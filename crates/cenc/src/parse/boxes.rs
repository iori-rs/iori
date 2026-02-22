//! CENC-specific box parsers

use super::combinators::*;
use crate::types::{CbcPattern, SchemeType, Subsample};
use winnow::binary::{be_u8, be_u16, be_u32};
use winnow::combinator::repeat;
use winnow::error::{ContextError, ErrMode};
use winnow::stream::Partial;
use winnow::token::take;
use winnow::{ModalResult, Parser};

/// Track encryption information from tenc box
#[derive(Debug, Clone, PartialEq)]
pub struct TrackEncryptionInfo {
    /// Is this track protected (1 = protected, 0 = unprotected)
    pub is_protected: u8,
    /// Per-sample IV size in bytes
    pub iv_size: u8,
    /// Key ID (KID)
    pub kid: [u8; 16],
    /// Scheme type (cenc, cens, cbc1, cbcs)
    pub scheme: SchemeType,
    /// CBC pattern (only for cbcs/cbc1)
    pub pattern: Option<CbcPattern>,
    /// Constant IV (only for tenc version 1 with iv_size == 0)
    pub constant_iv: Option<[u8; 16]>,
}

/// Parse tenc box (Track Encryption Box)
///
/// Version 0:
/// - reserved (3 bytes)
/// - is_protected (1 byte)
/// - iv_size (1 byte)
/// - kid[16]
///
/// Version 1 adds:
/// - crypt_byte_block (1 byte) - only if scheme is cbc1 or cbcs
/// - skip_byte_block (1 byte) - only if scheme is cbc1 or cbcs
/// - constant_iv[16] - only if iv_size == 0
pub fn parse_tenc(
    input: &mut Partial<&[u8]>,
    version: u8,
    scheme: SchemeType,
) -> ModalResult<TrackEncryptionInfo> {
    // Skip reserved bytes
    take(3usize).void().parse_next(input)?;

    // Common fields
    let is_protected = be_u8.parse_next(input)?;
    let iv_size = be_u8.parse_next(input)?;
    let kid: [u8; 16] = array.parse_next(input)?;

    // Version 1 adds pattern and constant IV
    let pattern = if version >= 1 && matches!(scheme, SchemeType::Cbc1 | SchemeType::Cbcs) {
        let crypt_byte_block = be_u8.parse_next(input)?;
        let skip_byte_block = be_u8.parse_next(input)?;
        Some(CbcPattern {
            crypt_byte_block,
            skip_byte_block,
        })
    } else {
        None
    };

    let constant_iv = if version >= 1 && iv_size == 0 {
        Some(array.parse_next(input)?)
    } else {
        None
    };

    Ok(TrackEncryptionInfo {
        is_protected,
        iv_size,
        kid,
        scheme,
        pattern,
        constant_iv,
    })
}

/// Sample encryption entry from senc box
#[derive(Debug, Clone, PartialEq)]
pub struct SampleEncryptionEntry {
    /// Initialization vector
    pub iv: [u8; 16],
    /// Subsample encryption information (clear/encrypted byte pairs)
    pub subsamples: Vec<Subsample>,
}

/// Parse senc box entries
///
/// Structure:
/// - For each sample:
///   - IV (iv_size bytes, padded to 16 with zeros)
///   - If UseSubSampleEncryption flag set:
///     - subsample_count (u16)
///     - For each subsample:
///       - clear_bytes (u16)
///       - encrypted_bytes (u32)
pub fn parse_senc_entries(
    input: &mut Partial<&[u8]>,
    sample_count: u32,
    iv_size: u8,
    flags: u32,
) -> ModalResult<Vec<SampleEncryptionEntry>> {
    const USE_SUBSAMPLE_ENCRYPTION: u32 = 0x02;
    let use_subsamples = (flags & USE_SUBSAMPLE_ENCRYPTION) != 0;

    repeat(
        sample_count as usize,
        move |input: &mut Partial<&[u8]>| -> ModalResult<SampleEncryptionEntry> {
            // Read IV (iv_size bytes, pad to 16)
            let mut iv = [0u8; 16];
            let iv_bytes: Vec<u8> = repeat(iv_size as usize, be_u8).parse_next(input)?;
            iv[..iv_size as usize].copy_from_slice(&iv_bytes);

            // Read subsamples if flag is set
            let subsamples = if use_subsamples {
                let subsample_count = be_u16.parse_next(input)?;
                repeat(
                    subsample_count as usize,
                    |input: &mut Partial<&[u8]>| -> ModalResult<Subsample> {
                        let clear_bytes = be_u16.parse_next(input)?;
                        let encrypted_bytes = be_u32.parse_next(input)?;
                        Ok(Subsample {
                            clear_bytes,
                            encrypted_bytes,
                        })
                    },
                )
                .parse_next(input)?
            } else {
                Vec::new()
            };

            Ok(SampleEncryptionEntry { iv, subsamples })
        },
    )
    .parse_next(input)
}

/// Sample auxiliary information sizes
#[derive(Debug, Clone, PartialEq)]
pub struct SampleAuxInfo {
    /// Default size (if all samples have same size)
    pub default_size: u8,
    /// Per-sample sizes (empty if default_size != 0)
    pub sizes: Vec<u8>,
}

/// Parse saiz box (Sample Auxiliary Information Sizes Box)
///
/// Structure:
/// - version (1 byte) + flags (3 bytes) [already parsed]
/// - If flags & 1:
///   - aux_info_type (u32)
///   - aux_info_type_parameter (u32)
/// - default_sample_info_size (u8)
/// - sample_count (u32)
/// - If default_sample_info_size == 0:
///   - sample_info_size[sample_count] (u8 each)
pub fn parse_saiz(input: &mut Partial<&[u8]>, flags: u32) -> ModalResult<SampleAuxInfo> {
    // Skip aux_info_type and parameter if present
    if (flags & 0x01) != 0 {
        take(8usize).void().parse_next(input)?;
    }

    let default_size = be_u8.parse_next(input)?;
    let sample_count = be_u32.parse_next(input)?;

    let sizes = if default_size == 0 {
        repeat(sample_count as usize, be_u8).parse_next(input)?
    } else {
        Vec::new()
    };

    Ok(SampleAuxInfo {
        default_size,
        sizes,
    })
}

/// Sample auxiliary information offsets
#[derive(Debug, Clone, PartialEq)]
pub struct SampleAuxOffsets {
    /// Offsets to auxiliary data
    pub offsets: Vec<u64>,
}

/// Parse saio box (Sample Auxiliary Information Offsets Box)
///
/// Structure:
/// - version (1 byte) + flags (3 bytes) [already parsed]
/// - If flags & 1:
///   - aux_info_type (u32)
///   - aux_info_type_parameter (u32)
/// - entry_count (u32)
/// - offset[entry_count] (u32 if version 0, u64 if version 1)
pub fn parse_saio(
    input: &mut Partial<&[u8]>,
    version: u8,
    flags: u32,
) -> ModalResult<SampleAuxOffsets> {
    // Skip aux_info_type and parameter if present
    if (flags & 0x01) != 0 {
        take(8usize).void().parse_next(input)?;
    }

    let entry_count = be_u32.parse_next(input)?;

    let offsets = if version == 0 {
        repeat(entry_count as usize, be_u32)
            .map(|v: Vec<u32>| v.into_iter().map(|x| x as u64).collect())
            .parse_next(input)?
    } else {
        repeat(entry_count as usize, winnow::binary::be_u64).parse_next(input)?
    };

    Ok(SampleAuxOffsets { offsets })
}

/// Parse schm box (Scheme Type Box)
///
/// Structure:
/// - version (1 byte) + flags (3 bytes) [already parsed]
/// - scheme_type (4 bytes) - e.g., "cenc", "cens", "cbc1", "cbcs"
/// - scheme_version (u32)
/// - scheme_uri (optional, if flags & 1)
pub fn parse_schm(input: &mut Partial<&[u8]>) -> ModalResult<SchemeType> {
    let scheme_bytes: [u8; 4] = array.parse_next(input)?;

    SchemeType::from_bytes(scheme_bytes).ok_or_else(|| ErrMode::Cut(ContextError::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tenc_v0() {
        let data = [
            0x00, 0x00, 0x00, // reserved
            0x01, // is_protected
            0x10, // iv_size = 16
            // kid (16 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut input = Partial::new(&data[..]);
        let tenc = parse_tenc(&mut input, 0, SchemeType::Cenc).unwrap();

        assert_eq!(tenc.is_protected, 1);
        assert_eq!(tenc.iv_size, 16);
        assert_eq!(
            tenc.kid,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert_eq!(tenc.scheme, SchemeType::Cenc);
        assert_eq!(tenc.pattern, None);
        assert_eq!(tenc.constant_iv, None);
    }

    #[test]
    fn test_parse_tenc_v1_with_pattern() {
        let data = [
            0x00, 0x00, 0x00, // reserved
            0x01, // is_protected
            0x08, // iv_size = 8
            // kid (16 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, // crypt_byte_block
            0x09, // skip_byte_block
        ];
        let mut input = Partial::new(&data[..]);
        let tenc = parse_tenc(&mut input, 1, SchemeType::Cbcs).unwrap();

        assert_eq!(tenc.is_protected, 1);
        assert_eq!(tenc.iv_size, 8);
        assert_eq!(
            tenc.pattern,
            Some(CbcPattern {
                crypt_byte_block: 1,
                skip_byte_block: 9
            })
        );
        assert_eq!(tenc.constant_iv, None);
    }

    #[test]
    fn test_parse_senc_entries() {
        let data = [
            // Sample 1
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // IV (8 bytes)
            0x00, 0x02, // subsample_count = 2
            0x00, 0x10, // clear_bytes = 16
            0x00, 0x00, 0x00, 0x20, // encrypted_bytes = 32
            0x00, 0x08, // clear_bytes = 8
            0x00, 0x00, 0x00, 0x40, // encrypted_bytes = 64
            // Sample 2
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // IV (8 bytes)
            0x00, 0x01, // subsample_count = 1
            0x00, 0x0c, // clear_bytes = 12
            0x00, 0x00, 0x00, 0x30, // encrypted_bytes = 48
        ];
        let mut input = Partial::new(&data[..]);
        let entries = parse_senc_entries(&mut input, 2, 8, 0x02).unwrap();

        assert_eq!(entries.len(), 2);

        // Sample 1
        assert_eq!(
            entries[0].iv[..8],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(entries[0].subsamples.len(), 2);
        assert_eq!(entries[0].subsamples[0].clear_bytes, 16);
        assert_eq!(entries[0].subsamples[0].encrypted_bytes, 32);

        // Sample 2
        assert_eq!(
            entries[1].iv[..8],
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
        assert_eq!(entries[1].subsamples.len(), 1);
        assert_eq!(entries[1].subsamples[0].clear_bytes, 12);
        assert_eq!(entries[1].subsamples[0].encrypted_bytes, 48);
    }

    #[test]
    fn test_parse_saiz() {
        let data = [
            0x00, // default_size = 0 (per-sample sizes follow)
            0x00, 0x00, 0x00, 0x03, // sample_count = 3
            0x10, 0x18, 0x20, // sizes = [16, 24, 32]
        ];
        let mut input = Partial::new(&data[..]);
        let saiz = parse_saiz(&mut input, 0).unwrap();

        assert_eq!(saiz.default_size, 0);
        assert_eq!(saiz.sizes, vec![16, 24, 32]);
    }

    #[test]
    fn test_parse_saio_v0() {
        let data = [
            0x00, 0x00, 0x00, 0x02, // entry_count = 2
            0x00, 0x00, 0x10, 0x00, // offset 1 = 4096
            0x00, 0x00, 0x20, 0x00, // offset 2 = 8192
        ];
        let mut input = Partial::new(&data[..]);
        let saio = parse_saio(&mut input, 0, 0).unwrap();

        assert_eq!(saio.offsets, vec![4096, 8192]);
    }

    #[test]
    fn test_parse_schm() {
        let data = *b"cenc";
        let mut input = Partial::new(&data[..]);
        let scheme = parse_schm(&mut input).unwrap();

        assert_eq!(scheme, SchemeType::Cenc);
    }
}
