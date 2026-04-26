//! CENC-specific box parsers

use crate::types::{CbcPattern, SchemeType, Subsample};
use winnow::binary::{be_u8, be_u16, be_u32};
use winnow::combinator::repeat;
use winnow::stream::Partial;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
