use crate::errors::{CencError, Result};
use crate::types::{CbcPattern, SchemeType, Subsample};
use shiguredo_mp4::boxes::{SampleEntry, UnknownBox};
use shiguredo_mp4::{BoxHeader, BoxType, Decode, FullBoxHeader};

const BOX_PSSH: BoxType = BoxType::Normal(*b"pssh");
const BOX_SINF: BoxType = BoxType::Normal(*b"sinf");
const BOX_SCHI: BoxType = BoxType::Normal(*b"schi");
const BOX_SCHM: BoxType = BoxType::Normal(*b"schm");
const BOX_TENC: BoxType = BoxType::Normal(*b"tenc");
const BOX_FRMA: BoxType = BoxType::Normal(*b"frma");
const BOX_SENC: BoxType = BoxType::Normal(*b"senc");
const BOX_SBGP: BoxType = BoxType::Normal(*b"sbgp");
const BOX_SGPD: BoxType = BoxType::Normal(*b"sgpd");
const BOX_SAIZ: BoxType = BoxType::Normal(*b"saiz");
const BOX_SAIO: BoxType = BoxType::Normal(*b"saio");
const BOX_ENCV: BoxType = BoxType::Normal(*b"encv");
const BOX_ENCA: BoxType = BoxType::Normal(*b"enca");

const CENC_AUX_INFO_TYPES: [BoxType; 4] = [
    SchemeType::Cenc.box_type(),
    SchemeType::Cbc1.box_type(),
    SchemeType::Cens.box_type(),
    SchemeType::Cbcs.box_type(),
];
const SENC_FLAG_OVERRIDE_TRACK_ENCRYPTION: usize = 0;
const SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION: usize = 1;
const SENC_SUPPORTED_FLAGS: u32 =
    (1 << SENC_FLAG_OVERRIDE_TRACK_ENCRYPTION) | (1 << SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION);
const AUX_INFO_TYPE_PRESENT_FLAG: usize = 0;
const AUX_INFO_TYPE_UNSPECIFIED: BoxType = BoxType::Normal([0; 4]);
const GROUPING_TYPE_SEIG: BoxType = BoxType::Normal(*b"seig");

const VISUAL_SAMPLE_ENTRY_SIZE: usize = 78;
const AUDIO_SAMPLE_ENTRY_SIZE: usize = 28;

pub(crate) struct PsshBox;

impl PsshBox {
    pub(crate) const TYPE: BoxType = BOX_PSSH;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginalFormatBox {
    pub(crate) original_format: BoxType,
}

impl OriginalFormatBox {
    pub(crate) const TYPE: BoxType = BOX_FRMA;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(payload);
        Ok(Self {
            original_format: reader.read_box_type()?,
        })
    }
}

pub(crate) struct EncryptedVideoSampleEntryBox;

impl EncryptedVideoSampleEntryBox {
    pub(crate) const TYPE: BoxType = BOX_ENCV;
    pub(crate) const BASE_SIZE: usize = VISUAL_SAMPLE_ENTRY_SIZE;
}

pub(crate) struct EncryptedAudioSampleEntryBox;

impl EncryptedAudioSampleEntryBox {
    pub(crate) const TYPE: BoxType = BOX_ENCA;
    pub(crate) const BASE_SIZE: usize = AUDIO_SAMPLE_ENTRY_SIZE;
}

// ---------------------------------------------------------------------------
// ByteReader — cursor-based binary reader
// ---------------------------------------------------------------------------

pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        u8::decode_at(self.data, &mut self.pos).map_err(Into::into)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        u16::decode_at(self.data, &mut self.pos).map_err(Into::into)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        u32::decode_at(self.data, &mut self.pos).map_err(Into::into)
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        u64::decode_at(self.data, &mut self.pos).map_err(Into::into)
    }

    pub(crate) fn read_type(&mut self) -> Result<[u8; 4]> {
        <[u8; 4]>::decode_at(self.data, &mut self.pos).map_err(Into::into)
    }

    pub(crate) fn read_box_type(&mut self) -> Result<BoxType> {
        Ok(BoxType::Normal(self.read_type()?))
    }

    pub(crate) fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.remaining() < len {
            return Err(CencError::InvalidSenc("unexpected end of data".into()));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub(crate) fn read_full_box_header(&mut self) -> Result<FullBoxHeader> {
        FullBoxHeader::decode_at(self.data, &mut self.pos).map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// ChildBox — lightweight view of a child box within a payload
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ChildBox<'a> {
    box_type: BoxType,
    payload: &'a [u8],
}

impl ChildBox<'_> {
    fn parse_children<'a>(payload: &'a [u8]) -> Result<Vec<ChildBox<'a>>> {
        RawMp4Box::parse_range(payload, 0, payload.len(), 0)?
            .into_iter()
            .map(|box_item| {
                let start = box_item.start + box_item.header_size;
                let end = box_item.start + box_item.size;
                Ok(ChildBox {
                    box_type: box_item.box_type,
                    payload: &payload[start..end],
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// RawMp4Box — lightweight top-level box descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub(crate) struct RawMp4Box {
    pub(crate) box_type: BoxType,
    pub(crate) start: usize,
    pub(crate) size: usize,
    pub(crate) header_size: usize,
}

impl RawMp4Box {
    pub(crate) fn parse_all(buf: &[u8], base_offset: usize) -> Result<Vec<Self>> {
        Self::parse_range(buf, 0, buf.len(), base_offset)
    }

    pub(crate) fn parse_range(
        buf: &[u8],
        start: usize,
        end: usize,
        base_offset: usize,
    ) -> Result<Vec<Self>> {
        let mut boxes = Vec::new();
        let mut offset = start;
        while offset < end {
            let (header, header_size) = BoxHeader::decode(&buf[offset..])?;
            let mut size = usize::try_from(header.box_size.get())
                .map_err(|_| CencError::InvalidSenc("box size overflow".to_string()))?;
            if size == 0 {
                size = end - offset;
            }
            if size < header_size || offset + size > end {
                return Err(CencError::InvalidSenc("invalid box size".to_string()));
            }
            let box_type = match header.box_type {
                BoxType::Normal(_) => header.box_type,
                BoxType::Uuid(_) => {
                    offset += size;
                    continue;
                }
            };
            boxes.push(RawMp4Box {
                box_type,
                start: base_offset + offset,
                size,
                header_size,
            });
            offset += size;
        }
        Ok(boxes)
    }
}

pub(crate) fn find_unknown_box<'a>(
    boxes: impl Iterator<Item = &'a UnknownBox>,
    box_type: BoxType,
) -> Option<&'a UnknownBox> {
    boxes
        .into_iter()
        .find(|box_item| box_item.box_type == box_type)
}

pub(crate) fn parse_first_matching_unknown_box<'a, T>(
    boxes: impl Iterator<Item = &'a UnknownBox>,
    box_type: BoxType,
    mut parse_payload: impl FnMut(&'a [u8]) -> Result<Option<T>>,
) -> Result<Option<T>> {
    boxes
        .into_iter()
        .filter(|box_item| box_item.box_type == box_type)
        .find_map(|box_item| parse_payload(&box_item.payload).transpose())
        .transpose()
}

// ---------------------------------------------------------------------------
// SampleEncryptionEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SampleEncryptionEntry {
    pub(crate) iv: [u8; 16],
    pub(crate) subsamples: Vec<Subsample>,
}

/// Parsed `senc` SampleEncryptionBox payload.
///
/// The box contains one entry per encrypted sample. It may also carry
/// track-encryption override parameters when flag `0x000001` is set.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SampleEncryptionBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) entries: Vec<SampleEncryptionEntry>,
    pub(crate) override_parameters: Option<TrackEncryptionOverride>,
}

/// Track-encryption override parameters carried by `senc` flag `0x000001`.
///
/// The override metadata is serialized before `sample_count`. For MPEG `cenc`,
/// `AlgorithmID == 0` marks the samples as not encrypted, while
/// `AlgorithmID == 1` keeps AES-CTR encryption active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrackEncryptionOverride {
    pub(crate) algorithm_id: [u8; 3],
    pub(crate) iv_size: u8,
    pub(crate) kid: [u8; 16],
}

impl SampleEncryptionBox {
    pub(crate) const TYPE: BoxType = BOX_SENC;

    pub(crate) fn override_kid(&self) -> Option<[u8; 16]> {
        self.override_parameters.map(|parameters| parameters.kid)
    }

    pub(crate) fn overrides_to_clear_samples(&self) -> bool {
        self.override_parameters
            .is_some_and(|parameters| parameters.algorithm_id == [0, 0, 0])
    }
}

impl SampleEncryptionBox {
    /// Parse a `senc` box payload into per-sample encryption entries.
    ///
    /// SampleEncryptionBox flags used by CENC, paraphrased:
    /// - `0x000001`: the box carries `AlgorithmID`, `IV_size`, and `KID`
    ///   values that override the track-level defaults for these samples.
    /// - `0x000002`: each sample entry carries a subsample table.
    ///
    /// Other flags alter the payload layout and are not accepted here.
    ///
    /// Each sample contributes an IV unless the track metadata selected a
    /// constant IV. When the subsample flag is absent, the sample is
    /// represented by an empty subsample vector and later treated as one fully
    /// protected range.
    #[cfg(test)]
    pub(crate) fn parse_senc(
        payload: &[u8],
        iv_size: u8,
        constant_iv: Option<[u8; 16]>,
    ) -> Result<SampleEncryptionBox> {
        Self::parse_senc_with_iv_info(payload, iv_size, constant_iv, None)
    }

    pub(crate) fn parse_senc_with_iv_info(
        payload: &[u8],
        iv_size: u8,
        constant_iv: Option<[u8; 16]>,
        per_sample_iv_info: Option<&[(u8, Option<[u8; 16]>)]>,
    ) -> Result<SampleEncryptionBox> {
        if payload.len() < 8 {
            return Err(CencError::InvalidSenc("senc too short".to_string()));
        }
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        if full_box_header.version != 0 {
            return Err(CencError::InvalidSenc(format!(
                "unsupported senc version {}",
                full_box_header.version
            )));
        }
        let flags = full_box_header.flags.get();
        let has_override = full_box_header
            .flags
            .is_set(SENC_FLAG_OVERRIDE_TRACK_ENCRYPTION);
        let has_subsamples = full_box_header
            .flags
            .is_set(SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION);
        if flags & !SENC_SUPPORTED_FLAGS != 0 {
            return Err(CencError::InvalidSenc(format!(
                "unsupported senc flags: {flags:#x}"
            )));
        }

        let override_parameters = if has_override {
            let algorithm_id: [u8; 3] = reader.read_exact(3)?.try_into().map_err(|_| {
                CencError::InvalidSenc("track encryption override truncated".to_string())
            })?;
            validate_senc_override_algorithm_id(algorithm_id)?;
            let override_iv_size = reader.read_u8()?;
            validate_iv_size(override_iv_size, "senc override")?;
            let kid_bytes = reader.read_exact(16)?;
            let mut kid = [0u8; 16];
            kid.copy_from_slice(kid_bytes);
            Some(TrackEncryptionOverride {
                algorithm_id,
                iv_size: override_iv_size,
                kid,
            })
        } else {
            None
        };
        let override_iv_size = override_parameters
            .map(|parameters| parameters.iv_size)
            .unwrap_or(iv_size);
        let sample_count = reader.read_u32()?;
        if let Some(per_sample_iv_info) = per_sample_iv_info
            && per_sample_iv_info.len() != sample_count as usize
        {
            return Err(CencError::SampleCountMismatch {
                expected: sample_count,
                actual: per_sample_iv_info.len() as u32,
            });
        }
        let mut entries = Vec::with_capacity(sample_count as usize);
        for sample_index in 0..sample_count as usize {
            let (sample_iv_size, sample_constant_iv) = if override_parameters.is_some() {
                (override_iv_size, constant_iv)
            } else if let Some(per_sample_iv_info) = per_sample_iv_info {
                per_sample_iv_info[sample_index]
            } else {
                (override_iv_size, constant_iv)
            };
            let iv =
                SampleEncryptionEntry::read_iv(&mut reader, sample_iv_size, sample_constant_iv)?;
            let subsamples = if has_subsamples {
                SampleEncryptionEntry::read_subsamples(&mut reader)?
            } else {
                Vec::new()
            };
            entries.push(SampleEncryptionEntry { iv, subsamples });
        }
        Ok(SampleEncryptionBox {
            full_box_header,
            entries,
            override_parameters,
        })
    }
}

/// Validate the CENC AlgorithmID carried by a `senc` override header.
///
/// The override header can replace the track-level encryption parameters for
/// all samples described by the box. For the CENC decryptor, AlgorithmID `0`
/// means the listed samples are clear and AlgorithmID `1` means AES-CTR CENC.
/// Other algorithm IDs select algorithms outside the currently supported CENC
/// path, so accepting them would create decrypt jobs with the wrong cipher.
fn validate_senc_override_algorithm_id(algorithm_id: [u8; 3]) -> Result<()> {
    if matches!(algorithm_id, [0, 0, 0] | [0, 0, 1]) {
        Ok(())
    } else {
        Err(CencError::InvalidSenc(format!(
            "unsupported senc AlgorithmID {}",
            hex::encode(algorithm_id)
        )))
    }
}

impl SampleEncryptionEntry {
    /// Parse auxiliary sample info entries (from saiz/saio data).
    ///
    /// Auxiliary sample information stores the same per-sample IV and optional
    /// subsample table as `senc`, but the byte count for each entry comes from
    /// `saiz` and the table payload is located through `saio`. The parser
    /// therefore constrains each read to one `saiz` entry and rejects leftover
    /// bytes in that entry.
    #[cfg(test)]
    pub(crate) fn parse_sai(
        data: &[u8],
        sizes: &[u8],
        iv_size: u8,
        constant_iv: Option<[u8; 16]>,
    ) -> Result<Vec<Self>> {
        let mut offset = 0usize;
        let mut entries = Vec::with_capacity(sizes.len());
        for size in sizes {
            let size = *size as usize;
            if data.len() < offset + size {
                return Err(CencError::InvalidSenc("sai data truncated".to_string()));
            }
            entries.push(Self::parse_sai_entry(
                &data[offset..offset + size],
                iv_size,
                constant_iv,
            )?);
            offset += size;
        }
        Ok(entries)
    }

    pub(crate) fn parse_sai_entry(
        data: &[u8],
        iv_size: u8,
        constant_iv: Option<[u8; 16]>,
    ) -> Result<Self> {
        if data.is_empty() {
            return Err(CencError::InvalidSenc("empty sample info size".to_string()));
        }
        let mut reader = ByteReader::new(data);
        let iv = Self::read_iv(&mut reader, iv_size, constant_iv)?;
        let subsamples = if reader.remaining() > 0 {
            if reader.remaining() < 2 {
                return Err(CencError::InvalidSenc(
                    "subsample data truncated".to_string(),
                ));
            }
            let subs = Self::read_subsamples(&mut reader)?;
            if reader.remaining() != 0 {
                return Err(CencError::InvalidSenc("sai size mismatch".to_string()));
            }
            subs
        } else {
            Vec::new()
        };
        Ok(Self { iv, subsamples })
    }

    /// Read a sample IV according to the effective per-sample IV size.
    ///
    /// A zero per-sample IV size means samples do not carry IV bytes;
    /// decryption must use the constant IV from `tenc` or `seig` metadata.
    /// An 8-byte IV is the high half of the AES-CTR/CBC IV; the low half is
    /// zero-filled before the block counter is added.
    fn read_iv(
        reader: &mut ByteReader,
        iv_size: u8,
        constant_iv: Option<[u8; 16]>,
    ) -> Result<[u8; 16]> {
        if iv_size == 0 {
            return constant_iv.ok_or_else(|| {
                CencError::InvalidSenc("missing constant iv for iv_size=0".to_string())
            });
        }
        validate_iv_size(iv_size, "sample")?;
        let iv_len = iv_size as usize;
        let iv_bytes = reader.read_exact(iv_len)?;
        let mut iv_buf = [0u8; 16];
        iv_buf[..iv_len].copy_from_slice(iv_bytes);
        if iv_len == 8 {
            iv_buf[8..].fill(0);
        }
        Ok(iv_buf)
    }

    fn read_subsamples(reader: &mut ByteReader) -> Result<Vec<Subsample>> {
        let subsample_count = reader.read_u16()?;
        let mut subsamples = Vec::with_capacity(subsample_count as usize);
        for _ in 0..subsample_count {
            subsamples.push(Subsample {
                clear_bytes: reader.read_u16()?,
                encrypted_bytes: reader.read_u32()?,
            });
        }
        Ok(subsamples)
    }
}

#[derive(Debug)]
pub(crate) struct ProtectionSchemeInfoBox<'a> {
    children: Vec<ChildBox<'a>>,
}

impl<'a> ProtectionSchemeInfoBox<'a> {
    pub(crate) const TYPE: BoxType = BOX_SINF;

    fn decode_payload(payload: &'a [u8]) -> Result<Self> {
        Ok(Self {
            children: ChildBox::parse_children(payload)?,
        })
    }

    fn find(&self, box_type: BoxType) -> Option<&ChildBox<'a>> {
        self.children
            .iter()
            .find(|child| child.box_type == box_type)
    }
}

#[derive(Debug)]
pub(crate) struct SchemeInformationBox<'a> {
    children: Vec<ChildBox<'a>>,
}

impl<'a> SchemeInformationBox<'a> {
    pub(crate) const TYPE: BoxType = BOX_SCHI;

    fn decode_payload(payload: &'a [u8]) -> Result<Self> {
        Ok(Self {
            children: ChildBox::parse_children(payload)?,
        })
    }

    fn find(&self, box_type: BoxType) -> Option<&ChildBox<'a>> {
        self.children
            .iter()
            .find(|child| child.box_type == box_type)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchemeTypeBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) scheme_type: SchemeType,
    #[allow(dead_code)]
    pub(crate) scheme_version: u32,
}

impl SchemeTypeBox {
    pub(crate) const TYPE: BoxType = BOX_SCHM;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        let scheme_type_box = reader
            .read_box_type()
            .map_err(|_| CencError::InvalidTenc("schm too short".to_string()))?;
        let scheme_version = reader
            .read_u32()
            .map_err(|_| CencError::InvalidTenc("schm too short".to_string()))?;
        let scheme_type = SchemeType::from_box_type(scheme_type_box).ok_or_else(|| {
            CencError::UnsupportedScheme(
                String::from_utf8_lossy(scheme_type_box.as_bytes()).to_string(),
            )
        })?;
        Ok(Self {
            full_box_header,
            scheme_type,
            scheme_version,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TrackEncryptionBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) default_crypt_byte_block: Option<CbcPattern>,
    pub(crate) default_is_protected: bool,
    pub(crate) default_per_sample_iv_size: u8,
    pub(crate) default_kid: [u8; 16],
    pub(crate) default_constant_iv: Option<[u8; 16]>,
}

impl TrackEncryptionBox {
    pub(crate) const TYPE: BoxType = BOX_TENC;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() < 24 {
            return Err(CencError::InvalidTenc("tenc too short".to_string()));
        }
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        let version = full_box_header.version;

        if payload.len().saturating_sub(reader.pos) == 20 {
            // Some producers omit the reserved byte before isProtected in a
            // version-0 tenc payload. Accept that legacy layout only when the
            // remaining length uniquely matches the shortened form.
            let _ = reader.read_u8()?;
        }

        let (pattern, is_protected, iv_size) = if version == 0 {
            let _reserved = reader.read_u8()?;
            let is_protected = reader.read_u8()? != 0;
            let iv_size = reader.read_u8()?;
            (None, is_protected, iv_size)
        } else if version == 1 {
            let pattern_offset = reader.pos;
            if reader.remaining() >= 4 {
                let candidate_iv_size = reader.data[pattern_offset + 2];
                if !matches!(candidate_iv_size, 0 | 8 | 16)
                    && matches!(reader.data[pattern_offset + 3], 0 | 8 | 16)
                {
                    let _ = reader.read_u8()?;
                }
            }
            let byte = reader.read_u8()?;
            let pattern = CbcPattern {
                crypt_byte_block: byte >> 4,
                skip_byte_block: byte & 0x0f,
            };
            let is_protected = reader.read_u8()? != 0;
            let iv_size = reader.read_u8()?;
            (Some(pattern), is_protected, iv_size)
        } else {
            return Err(CencError::InvalidTenc(format!(
                "unsupported tenc version {version}"
            )));
        };
        if is_protected && !matches!(iv_size, 0 | 8 | 16) {
            return Err(CencError::InvalidTenc(format!(
                "unsupported iv_size {iv_size}"
            )));
        }

        let kid_bytes = reader
            .read_exact(16)
            .map_err(|_| CencError::InvalidTenc("missing default_kid".to_string()))?;
        let mut kid = [0u8; 16];
        kid.copy_from_slice(kid_bytes);

        let constant_iv = if is_protected && iv_size == 0 {
            let size = reader
                .read_u8()
                .map_err(|_| CencError::InvalidTenc("missing constant iv size".to_string()))?
                as usize;
            if size > 16 {
                return Err(CencError::InvalidTenc(format!(
                    "unsupported constant iv size {size}"
                )));
            }
            let iv_bytes = reader
                .read_exact(size)
                .map_err(|_| CencError::InvalidTenc("constant iv truncated".to_string()))?;
            let mut iv = [0u8; 16];
            iv[..size].copy_from_slice(iv_bytes);
            Some(iv)
        } else {
            None
        };

        Ok(Self {
            full_box_header,
            default_crypt_byte_block: pattern,
            default_is_protected: is_protected,
            default_per_sample_iv_size: iv_size,
            default_kid: kid,
            default_constant_iv: constant_iv,
        })
    }
}

// ---------------------------------------------------------------------------
// TrackEncryptionInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TrackEncryptionInfo {
    pub(crate) scheme: SchemeType,
    pub(crate) kid: [u8; 16],
    pub(crate) iv_size: u8,
    pub(crate) constant_iv: Option<[u8; 16]>,
    pub(crate) pattern: Option<CbcPattern>,
    pub(crate) is_protected: bool,
}

impl TrackEncryptionInfo {
    /// Build encryption info for each sample entry in an stsd box.
    pub(crate) fn from_sample_entries(entries: &[SampleEntry]) -> Result<Vec<Option<Self>>> {
        entries.iter().map(Self::parse_sample_entry).collect()
    }

    /// Parse CENC protection metadata from one sample entry.
    ///
    /// Protected sample entries either use encrypted wrapper formats
    /// (`encv`/`enca`) or keep the original codec sample entry with a
    /// ProtectionSchemeInfoBox (`sinf`) attached. Both carry the same scheme
    /// and track-encryption metadata.
    ///
    /// CMAF commonly uses the original codec type with appended `sinf`,
    /// especially for `cbcs`. Any known sample entry with `sinf` is therefore
    /// treated as protected rather than requiring an `encv`/`enca` wrapper.
    fn parse_sample_entry(entry: &SampleEntry) -> Result<Option<Self>> {
        if let SampleEntry::Unknown(unknown) = entry {
            if unknown.box_type != EncryptedVideoSampleEntryBox::TYPE
                && unknown.box_type != EncryptedAudioSampleEntryBox::TYPE
            {
                return Ok(None);
            }
            let BoxType::Normal(box_type) = unknown.box_type else {
                return Ok(None);
            };
            let base_size = if unknown.box_type == EncryptedVideoSampleEntryBox::TYPE {
                EncryptedVideoSampleEntryBox::BASE_SIZE
            } else {
                EncryptedAudioSampleEntryBox::BASE_SIZE
            };
            if unknown.payload.len() <= base_size {
                return Err(CencError::UnsupportedSampleEntry(
                    String::from_utf8_lossy(&box_type).to_string(),
                ));
            }
            let children = ChildBox::parse_children(&unknown.payload[base_size..])?;
            let sinf = children
                .iter()
                .find(|child| child.box_type == ProtectionSchemeInfoBox::TYPE)
                .ok_or(CencError::MissingSinf)?;
            return Ok(Some(Self::parse_sinf(sinf.payload)?));
        }

        for ub in unknown_boxes_from_sample_entry(entry) {
            if ub.box_type == ProtectionSchemeInfoBox::TYPE {
                return Ok(Some(Self::parse_sinf(&ub.payload)?));
            }
        }

        Ok(None)
    }

    fn parse_sinf(sinf_payload: &[u8]) -> Result<Self> {
        let sinf = ProtectionSchemeInfoBox::decode_payload(sinf_payload)?;
        let schm = sinf
            .find(SchemeTypeBox::TYPE)
            .ok_or(CencError::MissingSchm)?;
        let scheme = SchemeTypeBox::decode_payload(schm.payload)?.scheme_type;
        if scheme == SchemeType::Sve1 {
            return Err(CencError::UnsupportedContentSensitiveScheme(
                "sve1".to_string(),
            ));
        }
        let schi = sinf
            .find(SchemeInformationBox::TYPE)
            .ok_or(CencError::MissingTenc)?;
        let schi = SchemeInformationBox::decode_payload(schi.payload)?;
        let tenc = schi
            .find(TrackEncryptionBox::TYPE)
            .ok_or(CencError::MissingTenc)?;
        let tenc = TrackEncryptionBox::decode_payload(tenc.payload)?;
        Self::validate_scheme_tenc_version(scheme, tenc.full_box_header.version)?;
        let mut info = Self::from_tenc_box(tenc);
        info.scheme = scheme;
        Ok(info)
    }

    #[cfg(test)]
    fn parse_schm(payload: &[u8]) -> Result<SchemeType> {
        Ok(SchemeTypeBox::decode_payload(payload)?.scheme_type)
    }

    #[cfg(test)]
    fn parse_schm_for_test(payload: &[u8]) -> Result<SchemeType> {
        Self::parse_schm(payload)
    }

    fn validate_scheme_tenc_version(scheme: SchemeType, version: u8) -> Result<()> {
        let valid = match scheme {
            SchemeType::Cenc | SchemeType::Cbc1 | SchemeType::Sve1 => version == 0,
            SchemeType::Cens | SchemeType::Cbcs => version == 1,
        };
        if valid {
            Ok(())
        } else {
            Err(CencError::InvalidTenc(format!(
                "{scheme:?} requires tenc version {}, got {version}",
                match scheme {
                    SchemeType::Cenc | SchemeType::Cbc1 | SchemeType::Sve1 => 0,
                    SchemeType::Cens | SchemeType::Cbcs => 1,
                }
            )))
        }
    }

    /// Parse a TrackEncryptionBox (`tenc`) payload.
    ///
    /// Version 0 carries no pattern byte; default crypt/skip block counts are
    /// therefore absent. Version 1 prefixes the protection fields with one
    /// packed pattern byte: high nibble = `crypt_byte_block`, low nibble =
    /// `skip_byte_block`. The pattern is used only by pattern schemes
    /// (`cens` and `cbcs`).
    ///
    /// Protected tracks either carry 8- or 16-byte IVs per sample, or a zero
    /// IV size meaning that a constant IV follows `default_KID`. Constant IVs
    /// are copied into a 16-byte working IV and used for every sample unless
    /// sample-group metadata overrides them.
    #[cfg(test)]
    fn parse_tenc(payload: &[u8]) -> Result<Self> {
        Ok(Self::from_tenc_box(TrackEncryptionBox::decode_payload(
            payload,
        )?))
    }

    fn from_tenc_box(tenc: TrackEncryptionBox) -> Self {
        Self {
            scheme: SchemeType::Cenc,
            kid: tenc.default_kid,
            iv_size: tenc.default_per_sample_iv_size,
            constant_iv: tenc.default_constant_iv,
            pattern: tenc.default_crypt_byte_block,
            is_protected: tenc.default_is_protected,
        }
    }
}

/// Return the `unknown_boxes` slice from any known codec sample entry type.
fn unknown_boxes_from_sample_entry(entry: &SampleEntry) -> &[UnknownBox] {
    match entry {
        SampleEntry::Avc1(b) => &b.unknown_boxes,
        SampleEntry::Hev1(b) => &b.unknown_boxes,
        SampleEntry::Hvc1(b) => &b.unknown_boxes,
        SampleEntry::Vp08(b) => &b.unknown_boxes,
        SampleEntry::Vp09(b) => &b.unknown_boxes,
        SampleEntry::Av01(b) => &b.unknown_boxes,
        SampleEntry::Opus(b) => &b.unknown_boxes,
        SampleEntry::Mp4a(b) => &b.unknown_boxes,
        SampleEntry::Flac(b) => &b.unknown_boxes,
        SampleEntry::Unknown(_) => &[],
    }
}

/// Parse a SampleAuxiliaryInformationSizesBox (`saiz`) payload.
///
/// When flag `0x000001` is set, `aux_info_type` and
/// `aux_info_type_parameter` are present before the size table. A non-zero
/// `default_sample_info_size` applies to every sample; otherwise the box
/// carries one explicit size byte per sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SaizBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) aux_info: Option<(BoxType, u32)>,
    pub(crate) default_sample_info_size: u8,
    pub(crate) sample_count: u32,
    pub(crate) sample_info_sizes: Vec<u8>,
}

impl SaizBox {
    pub(crate) const TYPE: BoxType = BOX_SAIZ;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        let aux_info = if full_box_header.flags.is_set(AUX_INFO_TYPE_PRESENT_FLAG) {
            Some((reader.read_box_type()?, reader.read_u32()?))
        } else {
            None
        };
        let default_sample_info_size = reader.read_u8()?;
        let sample_count = reader.read_u32()?;
        let mut sample_info_sizes = Vec::with_capacity(sample_count as usize);
        if default_sample_info_size != 0 {
            sample_info_sizes.resize(sample_count as usize, default_sample_info_size);
        } else {
            let data = reader.read_exact(sample_count as usize)?;
            sample_info_sizes.extend_from_slice(data);
        }
        Ok(Self {
            full_box_header,
            aux_info,
            default_sample_info_size,
            sample_count,
            sample_info_sizes,
        })
    }

    fn is_cenc_aux_info(&self) -> bool {
        self.aux_info
            .map(|(aux_info_type, aux_info_type_parameter)| {
                is_cenc_aux_info(aux_info_type, aux_info_type_parameter)
            })
            .unwrap_or(true)
    }
}

pub(crate) fn parse_saiz(payload: &[u8]) -> Result<Option<Vec<u8>>> {
    let box_item = SaizBox::decode_payload(payload)?;
    if !box_item.is_cenc_aux_info() {
        return Ok(None);
    }
    Ok(Some(box_item.sample_info_sizes))
}

/// Parse a SampleAuxiliaryInformationOffsetsBox (`saio`) payload.
///
/// When flag `0x000001` is set, `aux_info_type` and
/// `aux_info_type_parameter` precede the offset table. Version 0 uses 32-bit
/// offsets; version 1 uses 64-bit offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SaioBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) aux_info: Option<(BoxType, u32)>,
    pub(crate) offsets: Vec<u64>,
}

impl SaioBox {
    pub(crate) const TYPE: BoxType = BOX_SAIO;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        let aux_info = if full_box_header.flags.is_set(AUX_INFO_TYPE_PRESENT_FLAG) {
            Some((reader.read_box_type()?, reader.read_u32()?))
        } else {
            None
        };
        let entry_count = reader.read_u32()? as usize;
        let mut offsets = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let value = if full_box_header.version == 0 {
                reader.read_u32()? as u64
            } else {
                reader.read_u64()?
            };
            offsets.push(value);
        }
        Ok(Self {
            full_box_header,
            aux_info,
            offsets,
        })
    }

    fn is_cenc_aux_info(&self) -> bool {
        self.aux_info
            .map(|(aux_info_type, aux_info_type_parameter)| {
                is_cenc_aux_info(aux_info_type, aux_info_type_parameter)
            })
            .unwrap_or(true)
    }
}

pub(crate) fn parse_saio(payload: &[u8]) -> Result<Option<Vec<u64>>> {
    let box_item = SaioBox::decode_payload(payload)?;
    if !box_item.is_cenc_aux_info() {
        return Ok(None);
    }
    Ok(Some(box_item.offsets))
}

fn is_cenc_aux_info(aux_info_type: BoxType, aux_info_type_parameter: u32) -> bool {
    if aux_info_type == AUX_INFO_TYPE_UNSPECIFIED {
        return true;
    }
    aux_info_type_parameter <= 1
        && CENC_AUX_INFO_TYPES
            .iter()
            .any(|box_type| aux_info_type == *box_type)
}

// ---------------------------------------------------------------------------
// SbgpEntry — sample-to-group mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SbgpEntry {
    pub(crate) sample_count: u32,
    /// 0 means "use track-level defaults", ≥1 is a 1-based index into the SGPD.
    pub(crate) group_description_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SbgpBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) grouping_type: BoxType,
    pub(crate) grouping_type_parameter: Option<u32>,
    pub(crate) entries: Vec<SbgpEntry>,
}

impl SbgpBox {
    pub(crate) const TYPE: BoxType = BOX_SBGP;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        if reader.remaining() < 4 {
            return Err(CencError::InvalidSenc("sbgp too short".to_string()));
        }
        let grouping_type = reader.read_box_type()?;
        let grouping_type_parameter = if full_box_header.version == 1 {
            Some(reader.read_u32()?)
        } else {
            None
        };
        let entry_count = reader.read_u32()? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(SbgpEntry {
                sample_count: reader.read_u32()?,
                group_description_index: reader.read_u32()?,
            });
        }
        Ok(Self {
            full_box_header,
            grouping_type,
            grouping_type_parameter,
            entries,
        })
    }

    fn is_seig(&self) -> bool {
        self.grouping_type == GROUPING_TYPE_SEIG
    }
}

impl SbgpEntry {
    /// Convert this entry's group description index into a zero-based SGPD index.
    ///
    /// Sample-to-group entries are 1-based indexes into SGPD. Some fragmented
    /// files use the high bits to signal fragment-local description indexes;
    /// the low 16 bits still carry the 1-based SGPD entry number.
    pub(crate) fn description_index(&self) -> Result<usize> {
        let raw = self.group_description_index;
        let one_based = if raw >= 0x10001 { raw & 0xFFFF } else { raw } as usize;
        one_based.checked_sub(1).ok_or_else(|| {
            CencError::InvalidSenc(
                "sbgp group_description_index fragment-local underflow".to_string(),
            )
        })
    }

    /// Parse an SBGP box payload.
    ///
    /// Returns `None` when `grouping_type != "seig"`. Version 1 inserts
    /// `grouping_type_parameter` between `grouping_type` and `entry_count`.
    pub(crate) fn parse_seig(payload: &[u8]) -> Result<Option<Vec<Self>>> {
        let box_item = SbgpBox::decode_payload(payload)?;
        if !box_item.is_seig() {
            return Ok(None);
        }
        Ok(Some(box_item.entries))
    }
}

// ---------------------------------------------------------------------------
// SeigEntry — sample group description entry
// ---------------------------------------------------------------------------

/// A single seig entry from an SGPD (SampleGroupDescription) box.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct SeigEntry {
    pub(crate) pattern: Option<CbcPattern>,
    pub(crate) is_protected: bool,
    #[allow(dead_code)]
    pub(crate) per_sample_iv_size: u8,
    pub(crate) kid: [u8; 16],
    pub(crate) constant_iv: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SgpdSeigBox {
    pub(crate) full_box_header: FullBoxHeader,
    pub(crate) default_length: u32,
    pub(crate) default_sample_description_index: Option<u32>,
    pub(crate) entries: Vec<SeigEntry>,
}

impl SgpdSeigBox {
    pub(crate) const TYPE: BoxType = BOX_SGPD;

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Option<Self>> {
        let mut reader = ByteReader::new(payload);
        let full_box_header = reader.read_full_box_header()?;
        if reader.remaining() < 4 {
            return Err(CencError::InvalidSenc("sgpd too short".to_string()));
        }
        let grouping_type = reader.read_box_type()?;
        if grouping_type != GROUPING_TYPE_SEIG {
            return Ok(None);
        }
        let default_length = if full_box_header.version == 1 {
            reader.read_u32()?
        } else {
            0u32
        };
        let default_sample_description_index = if full_box_header.version >= 2 {
            Some(reader.read_u32()?)
        } else {
            None
        };
        let entry_count = reader.read_u32()? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if full_box_header.version == 1 && default_length == 0 {
                let _ = reader.read_u32()?; // length_including_length_field
            }
            entries.push(SeigEntry::decode_payload(&mut reader)?);
        }
        Ok(Some(Self {
            full_box_header,
            default_length,
            default_sample_description_index,
            entries,
        }))
    }
}

impl SeigEntry {
    fn decode_payload(reader: &mut ByteReader) -> Result<Self> {
        let crypt_skip = reader.read_u8()?;
        let pattern = Some(CbcPattern {
            crypt_byte_block: crypt_skip >> 4,
            skip_byte_block: crypt_skip & 0x0f,
        });
        let _reserved = reader.read_u8()?;
        let is_protected = reader.read_u8()? != 0;
        let per_sample_iv_size = reader.read_u8()?;
        if is_protected && !matches!(per_sample_iv_size, 0 | 8 | 16) {
            return Err(CencError::InvalidSenc(format!(
                "unsupported seig per_sample_iv_size {per_sample_iv_size}"
            )));
        }
        let kid_bytes = reader.read_exact(16)?;
        let mut kid = [0u8; 16];
        kid.copy_from_slice(kid_bytes);
        let constant_iv = if is_protected && per_sample_iv_size == 0 {
            let constant_iv_size = reader.read_u8()? as usize;
            if constant_iv_size > 16 {
                return Err(CencError::InvalidSenc(format!(
                    "unsupported seig constant iv size {constant_iv_size}"
                )));
            }
            let iv_bytes = reader.read_exact(constant_iv_size)?;
            let mut iv = [0u8; 16];
            iv[..constant_iv_size].copy_from_slice(iv_bytes);
            Some(iv)
        } else {
            None
        };
        Ok(Self {
            pattern,
            is_protected,
            per_sample_iv_size,
            kid,
            constant_iv,
        })
    }

    /// Parse an SGPD box payload for seig entries.
    ///
    /// Returns `None` when `grouping_type != "seig"`. SGPD version 1 may use a
    /// common entry length; when that value is zero, each description starts
    /// with its own length field. Later SGPD versions insert
    /// `default_sample_description_index` before `entry_count`.
    ///
    /// A `seig` description can override default pattern, protection state, IV
    /// size, KID, and constant IV for the samples mapped to it by `sbgp`. The
    /// packed pattern byte uses the same high/low nibble layout as `tenc`
    /// version 1.
    pub(crate) fn parse_seig(payload: &[u8]) -> Result<Option<Vec<Self>>> {
        Ok(SgpdSeigBox::decode_payload(payload)?.map(|box_item| box_item.entries))
    }
}

impl TrackEncryptionInfo {
    pub(crate) fn effective_kid(
        &self,
        group: Option<SeigEntry>,
        senc_override_kid: Option<[u8; 16]>,
    ) -> [u8; 16] {
        group
            .map(|entry| entry.kid)
            .or(senc_override_kid)
            .unwrap_or(self.kid)
    }

    pub(crate) fn effective_iv(&self, group: Option<SeigEntry>, sample_iv: [u8; 16]) -> [u8; 16] {
        group
            .and_then(|entry| entry.constant_iv)
            .unwrap_or(sample_iv)
    }

    pub(crate) fn effective_iv_info(&self, group: Option<SeigEntry>) -> (u8, Option<[u8; 16]>) {
        group
            .map(|entry| (entry.per_sample_iv_size, entry.constant_iv))
            .unwrap_or((self.iv_size, self.constant_iv))
    }

    pub(crate) fn effective_pattern(&self, group: Option<SeigEntry>) -> Option<CbcPattern> {
        self.scheme
            .effective_pattern(group.and_then(|entry| entry.pattern).or(self.pattern))
    }
}

fn validate_iv_size(iv_size: u8, context: &str) -> Result<()> {
    if matches!(iv_size, 8 | 16) {
        return Ok(());
    }
    Err(CencError::InvalidSenc(format!(
        "unsupported {context} iv size {iv_size}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shiguredo_mp4::Encode;

    const SAMPLE_KID: [u8; 16] = [
        0x70, 0xB9, 0x90, 0xCE, 0xB0, 0x91, 0x31, 0x38, 0xB2, 0x95, 0x9F, 0x53, 0x28, 0x01, 0x49,
        0x98,
    ];
    const SAMPLE_CONSTANT_IV: [u8; 16] = [
        0x1F, 0x2D, 0xCC, 0xFC, 0xC9, 0xE9, 0x36, 0xF5, 0x7E, 0x63, 0xA7, 0x23, 0xDD, 0x47, 0x0A,
        0x7D,
    ];

    struct Mp4Syntax(Vec<u8>);

    impl Mp4Syntax {
        fn new() -> Self {
            Self(Vec::new())
        }

        fn full_box_header(&mut self, version: u8, flags: u32) {
            self.u8(version);
            self.u24(flags);
        }

        fn u8(&mut self, value: u8) {
            self.0.extend_from_slice(&value.encode_to_vec().unwrap());
        }

        fn u16(&mut self, value: u16) {
            self.0.extend_from_slice(&value.encode_to_vec().unwrap());
        }

        fn u24(&mut self, value: u32) {
            self.0.extend_from_slice(&value.to_be_bytes()[1..]);
        }

        fn u32(&mut self, value: u32) {
            self.0.extend_from_slice(&value.encode_to_vec().unwrap());
        }

        fn u64(&mut self, value: u64) {
            self.0.extend_from_slice(&value.encode_to_vec().unwrap());
        }

        fn bytes(&mut self, value: &[u8]) {
            self.0.extend_from_slice(&value.encode_to_vec().unwrap());
        }

        fn into_payload(self) -> Vec<u8> {
            self.0
        }
    }

    struct SencBoxSyntax {
        flags: u32,
        override_parameters: Option<TrackEncryptionOverride>,
        samples: Vec<SencSampleSyntax>,
    }

    struct SencSampleSyntax {
        iv: Vec<u8>,
        subsamples: Vec<Subsample>,
    }

    impl SencBoxSyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.full_box_header(0, self.flags);
            if let Some(parameters) = self.override_parameters {
                mp4.bytes(&parameters.algorithm_id);
                mp4.u8(parameters.iv_size);
                mp4.bytes(&parameters.kid);
            }
            mp4.u32(self.samples.len() as u32);
            for sample in &self.samples {
                mp4.bytes(&sample.iv);
                if self.flags & 0x000002 != 0 {
                    mp4.u16(sample.subsamples.len() as u16);
                    for subsample in &sample.subsamples {
                        mp4.u16(subsample.clear_bytes);
                        mp4.u32(subsample.encrypted_bytes);
                    }
                }
            }
            mp4.into_payload()
        }
    }

    struct SaiEntrySyntax {
        iv: Vec<u8>,
        subsamples: Option<Vec<Subsample>>,
        trailing_bytes: Vec<u8>,
    }

    impl SaiEntrySyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.bytes(&self.iv);
            if let Some(subsamples) = &self.subsamples {
                mp4.u16(subsamples.len() as u16);
                for subsample in subsamples {
                    mp4.u16(subsample.clear_bytes);
                    mp4.u32(subsample.encrypted_bytes);
                }
            }
            mp4.bytes(&self.trailing_bytes);
            mp4.into_payload()
        }
    }

    struct SaizBoxSyntax {
        aux_info: Option<(BoxType, u32)>,
        default_sample_info_size: u8,
        sample_count: u32,
        explicit_sample_info_sizes: Vec<u8>,
    }

    impl SaizBoxSyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.full_box_header(0, u32::from(self.aux_info.is_some()));
            if let Some((aux_info_type, aux_info_type_parameter)) = self.aux_info {
                mp4.bytes(aux_info_type.as_bytes());
                mp4.u32(aux_info_type_parameter);
            }
            mp4.u8(self.default_sample_info_size);
            mp4.u32(self.sample_count);
            if self.default_sample_info_size == 0 {
                mp4.bytes(&self.explicit_sample_info_sizes);
            }
            mp4.into_payload()
        }
    }

    struct SaioBoxSyntax {
        version: u8,
        aux_info: Option<(BoxType, u32)>,
        offsets: Vec<u64>,
    }

    impl SaioBoxSyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.full_box_header(self.version, u32::from(self.aux_info.is_some()));
            if let Some((aux_info_type, aux_info_type_parameter)) = self.aux_info {
                mp4.bytes(aux_info_type.as_bytes());
                mp4.u32(aux_info_type_parameter);
            }
            mp4.u32(self.offsets.len() as u32);
            for offset in &self.offsets {
                if self.version == 0 {
                    mp4.u32(*offset as u32);
                } else {
                    mp4.u64(*offset);
                }
            }
            mp4.into_payload()
        }
    }

    struct SbgpBoxSyntax {
        version: u8,
        grouping_type: BoxType,
        grouping_type_parameter: Option<u32>,
        entries: Vec<SbgpEntry>,
    }

    impl SbgpBoxSyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.full_box_header(self.version, 0);
            mp4.bytes(self.grouping_type.as_bytes());
            if let Some(parameter) = self.grouping_type_parameter {
                mp4.u32(parameter);
            }
            mp4.u32(self.entries.len() as u32);
            for entry in &self.entries {
                mp4.u32(entry.sample_count);
                mp4.u32(entry.group_description_index);
            }
            mp4.into_payload()
        }
    }

    struct SgpdBoxSyntax {
        version: u8,
        grouping_type: BoxType,
        default_length: Option<u32>,
        default_sample_description_index: Option<u32>,
        entries: Vec<SgpdSeigEntrySyntax>,
    }

    struct SgpdSeigEntrySyntax {
        length_including_length_field: Option<u32>,
        pattern: CbcPattern,
        is_protected: bool,
        per_sample_iv_size: u8,
        kid: [u8; 16],
        constant_iv: Option<Vec<u8>>,
    }

    impl SgpdBoxSyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.full_box_header(self.version, 0);
            mp4.bytes(self.grouping_type.as_bytes());
            if let Some(default_length) = self.default_length {
                mp4.u32(default_length);
            }
            if let Some(index) = self.default_sample_description_index {
                mp4.u32(index);
            }
            mp4.u32(self.entries.len() as u32);
            for entry in &self.entries {
                if let Some(length) = entry.length_including_length_field {
                    mp4.u32(length);
                }
                mp4.u8((entry.pattern.crypt_byte_block << 4) | entry.pattern.skip_byte_block);
                mp4.u8(0); // reserved
                mp4.u8(u8::from(entry.is_protected));
                mp4.u8(entry.per_sample_iv_size);
                mp4.bytes(&entry.kid);
                if let Some(constant_iv) = &entry.constant_iv {
                    mp4.u8(constant_iv.len() as u8);
                    mp4.bytes(constant_iv);
                }
            }
            mp4.into_payload()
        }
    }

    struct TencBoxSyntax {
        version: u8,
        pattern: Option<CbcPattern>,
        is_protected: bool,
        iv_size: u8,
        kid: [u8; 16],
        constant_iv: Option<Vec<u8>>,
    }

    impl TencBoxSyntax {
        fn payload(&self) -> Vec<u8> {
            let mut mp4 = Mp4Syntax::new();
            mp4.full_box_header(self.version, 0);
            if let Some(pattern) = self.pattern {
                mp4.u8((pattern.crypt_byte_block << 4) | pattern.skip_byte_block);
            } else {
                mp4.u8(0); // reserved
            }
            mp4.u8(u8::from(self.is_protected));
            mp4.u8(self.iv_size);
            mp4.bytes(&self.kid);
            if let Some(constant_iv) = &self.constant_iv {
                mp4.u8(constant_iv.len() as u8);
                mp4.bytes(constant_iv);
            }
            mp4.into_payload()
        }
    }

    fn sgpd_version_1_constant_iv_payload() -> Vec<u8> {
        SgpdBoxSyntax {
            version: 1,
            grouping_type: GROUPING_TYPE_SEIG,
            default_length: Some(37),
            default_sample_description_index: None,
            entries: vec![SgpdSeigEntrySyntax {
                length_including_length_field: None,
                pattern: CbcPattern {
                    crypt_byte_block: 0,
                    skip_byte_block: 0,
                },
                is_protected: true,
                per_sample_iv_size: 0,
                kid: SAMPLE_KID,
                constant_iv: Some(SAMPLE_CONSTANT_IV.to_vec()),
            }],
        }
        .payload()
    }

    #[test]
    fn test_parse_sgpd_seig() {
        let payload = sgpd_version_1_constant_iv_payload();
        let entries = SeigEntry::parse_seig(&payload).unwrap().unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(e.is_protected);
        assert_eq!(e.per_sample_iv_size, 0);
        assert_eq!(e.kid, SAMPLE_KID);
        assert_eq!(e.constant_iv, Some(SAMPLE_CONSTANT_IV));
    }

    #[test]
    fn test_parse_sgpd_seig_wrong_grouping_type() {
        let payload = SgpdBoxSyntax {
            version: 1,
            grouping_type: BoxType::Normal(*b"maif"),
            default_length: Some(37),
            default_sample_description_index: None,
            entries: vec![SgpdSeigEntrySyntax {
                length_including_length_field: None,
                pattern: CbcPattern {
                    crypt_byte_block: 0,
                    skip_byte_block: 0,
                },
                is_protected: true,
                per_sample_iv_size: 0,
                kid: SAMPLE_KID,
                constant_iv: Some(SAMPLE_CONSTANT_IV.to_vec()),
            }],
        }
        .payload();

        assert!(SeigEntry::parse_seig(&payload).unwrap().is_none());
    }

    #[test]
    fn parse_schm_recognizes_sve1_scheme_type() {
        let mut payload = Mp4Syntax::new();
        payload.full_box_header(0, 0);
        payload.bytes(b"sve1");
        payload.u32(0x0001_0000);

        assert_eq!(
            TrackEncryptionInfo::parse_schm_for_test(&payload.into_payload()).unwrap(),
            SchemeType::Sve1
        );
    }

    #[test]
    fn validate_scheme_tenc_version_enforces_scheme_rules() {
        assert!(TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Cenc, 0).is_ok());
        assert!(TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Cbc1, 0).is_ok());
        assert!(TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Cens, 1).is_ok());
        assert!(TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Cbcs, 1).is_ok());
        assert!(TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Sve1, 0).is_ok());

        assert!(matches!(
            TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Cenc, 1),
            Err(CencError::InvalidTenc(_))
        ));
        assert!(matches!(
            TrackEncryptionInfo::validate_scheme_tenc_version(SchemeType::Cbcs, 0),
            Err(CencError::InvalidTenc(_))
        ));
    }

    #[test]
    fn parse_senc_supports_track_encryption_override() {
        let payload = SencBoxSyntax {
            flags: 0x000001,
            override_parameters: Some(TrackEncryptionOverride {
                algorithm_id: [0, 0, 1],
                iv_size: 8,
                kid: SAMPLE_KID,
            }),
            samples: vec![SencSampleSyntax {
                iv: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                subsamples: Vec::new(),
            }],
        }
        .payload();

        let parsed = SampleEncryptionBox::parse_senc(&payload, 16, None).unwrap();

        assert_eq!(parsed.override_kid(), Some(SAMPLE_KID));
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(
            parsed.entries[0].iv,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn parse_senc_detects_algorithm_override_to_clear_samples() {
        let payload = SencBoxSyntax {
            flags: 0x000001,
            override_parameters: Some(TrackEncryptionOverride {
                algorithm_id: [0, 0, 0],
                iv_size: 8,
                kid: SAMPLE_KID,
            }),
            samples: vec![SencSampleSyntax {
                iv: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                subsamples: Vec::new(),
            }],
        }
        .payload();

        let parsed = SampleEncryptionBox::parse_senc(&payload, 16, None).unwrap();

        assert!(parsed.overrides_to_clear_samples());
    }

    #[test]
    fn parse_senc_rejects_unsupported_algorithm_override() {
        let payload = SencBoxSyntax {
            flags: 0x000001,
            override_parameters: Some(TrackEncryptionOverride {
                algorithm_id: [0, 0, 2],
                iv_size: 8,
                kid: SAMPLE_KID,
            }),
            samples: vec![SencSampleSyntax {
                iv: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                subsamples: Vec::new(),
            }],
        }
        .payload();

        let err = SampleEncryptionBox::parse_senc(&payload, 16, None).unwrap_err();

        assert!(matches!(err, CencError::InvalidSenc(message) if message.contains("AlgorithmID")));
    }

    /// `senc` entries use the effective IV size selected by track metadata or
    /// by the optional override header.
    ///
    /// When that IV size is zero, the sample entry does not carry IV bytes.
    /// The decryptor must use the constant IV supplied by the effective track
    /// encryption metadata and then immediately continue with the optional
    /// subsample table when flag `0x000002` is set.
    #[test]
    fn parse_senc_uses_constant_iv_when_effective_iv_size_is_zero() {
        let constant_iv = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ];
        let payload = SencBoxSyntax {
            flags: 0x000002,
            override_parameters: None,
            samples: vec![SencSampleSyntax {
                iv: Vec::new(),
                subsamples: vec![Subsample {
                    clear_bytes: 3,
                    encrypted_bytes: 29,
                }],
            }],
        }
        .payload();

        let parsed = SampleEncryptionBox::parse_senc(&payload, 0, Some(constant_iv)).unwrap();

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].iv, constant_iv);
        assert_eq!(
            parsed.entries[0].subsamples,
            vec![Subsample {
                clear_bytes: 3,
                encrypted_bytes: 29,
            }]
        );
    }

    #[test]
    fn parse_senc_uses_per_sample_iv_size_overrides() {
        let payload = SencBoxSyntax {
            flags: 0,
            override_parameters: None,
            samples: vec![
                SencSampleSyntax {
                    iv: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                    subsamples: Vec::new(),
                },
                SencSampleSyntax {
                    iv: vec![
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                        0x0d, 0x0e, 0x0f, 0x10,
                    ],
                    subsamples: Vec::new(),
                },
            ],
        }
        .payload();
        let iv_info = [(8, None), (16, None)];

        let parsed =
            SampleEncryptionBox::parse_senc_with_iv_info(&payload, 16, None, Some(&iv_info))
                .unwrap();

        assert_eq!(
            parsed.entries[0].iv,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(
            parsed.entries[1].iv,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ]
        );
    }

    /// Only the two CENC-defined `senc` flags are accepted here.
    ///
    /// Other flag bits change the serialized layout or semantics. Accepting
    /// them would let the parser read later fields at the wrong byte offsets,
    /// so unsupported bits must be rejected before sample entries are read.
    #[test]
    fn parse_senc_rejects_unknown_flags() {
        let payload = SencBoxSyntax {
            flags: 0x000004,
            override_parameters: None,
            samples: Vec::new(),
        }
        .payload();

        assert!(matches!(
            SampleEncryptionBox::parse_senc(&payload, 16, None),
            Err(CencError::InvalidSenc(_))
        ));
    }

    /// SAI entries referenced by `saiz`/`saio` are length-delimited per sample.
    ///
    /// The entry size includes exactly one IV plus an optional subsample table.
    /// If a size leaves unread bytes after parsing that entry, the metadata is
    /// malformed because the next sample would start at an ambiguous offset.
    #[test]
    fn parse_sai_rejects_leftover_bytes_inside_entry_size() {
        let entry = SaiEntrySyntax {
            iv: vec![0x11; 16],
            subsamples: Some(Vec::new()),
            trailing_bytes: vec![0xff],
        }
        .payload();

        assert!(matches!(
            SampleEncryptionEntry::parse_sai(&entry, &[entry.len() as u8], 16, None),
            Err(CencError::InvalidSenc(_))
        ));
    }

    /// `saiz` may either carry one default auxiliary-info size or an explicit
    /// size byte for every sample.
    ///
    /// When flag `0x000001` is set, `aux_info_type` and
    /// `aux_info_type_parameter` are present before the size fields and must be
    /// skipped before reading `default_sample_info_size` and `sample_count`.
    #[test]
    fn parse_saiz_handles_aux_info_type_and_default_size() {
        for scheme in CENC_AUX_INFO_TYPES {
            let payload = SaizBoxSyntax {
                aux_info: Some((scheme, 0)),
                default_sample_info_size: 16,
                sample_count: 3,
                explicit_sample_info_sizes: Vec::new(),
            }
            .payload();

            assert_eq!(parse_saiz(&payload).unwrap(), Some(vec![16, 16, 16]));
        }
    }

    /// `saiz` explicit sizes are used when the default size is zero.
    ///
    /// In that form the box carries exactly `sample_count` one-byte sizes after
    /// the count field. The parser must not synthesize a default or ignore the
    /// explicit table.
    #[test]
    fn parse_saiz_handles_explicit_size_table() {
        let payload = SaizBoxSyntax {
            aux_info: None,
            default_sample_info_size: 0,
            sample_count: 4,
            explicit_sample_info_sizes: vec![8, 16, 0, 24],
        }
        .payload();

        assert_eq!(parse_saiz(&payload).unwrap(), Some(vec![8, 16, 0, 24]));
    }

    /// `saio` version 1 stores 64-bit offsets.
    ///
    /// As with `saiz`, flag `0x000001` inserts `aux_info_type` and
    /// `aux_info_type_parameter` before the offset count. The parser must skip
    /// those fields and then read each version-1 offset as a 64-bit value.
    #[test]
    fn parse_saio_handles_aux_info_type_and_64_bit_offsets() {
        for scheme in CENC_AUX_INFO_TYPES {
            let payload = SaioBoxSyntax {
                version: 1,
                aux_info: Some((scheme, 1)),
                offsets: vec![0x0000_0001_0000_0002, 0x0000_0003_0000_0004],
            }
            .payload();

            assert_eq!(
                parse_saio(&payload).unwrap().unwrap(),
                vec![0x0000_0001_0000_0002, 0x0000_0003_0000_0004]
            );
        }
    }

    /// `saiz` boxes with an explicit non-CENC auxiliary information type do
    /// not describe common-encryption sample metadata.
    ///
    /// A demuxer may carry several auxiliary information streams. The CENC
    /// parser must ignore size tables for other streams instead of treating
    /// them as IV and subsample sizes.
    #[test]
    fn parse_saiz_ignores_non_cenc_aux_info_type() {
        let payload = SaizBoxSyntax {
            aux_info: Some((BoxType::Normal(*b"gps "), 0)),
            default_sample_info_size: 16,
            sample_count: 1,
            explicit_sample_info_sizes: Vec::new(),
        }
        .payload();

        assert_eq!(parse_saiz(&payload).unwrap(), None);
    }

    /// `saio` boxes are subject to the same CENC auxiliary-information filter
    /// as `saiz`.
    ///
    /// Offsets for a different auxiliary information stream must not be used
    /// as CENC IV/subsample offsets.
    #[test]
    fn parse_saio_ignores_non_cenc_aux_info_type() {
        let payload = SaioBoxSyntax {
            version: 0,
            aux_info: Some((BoxType::Normal(*b"gps "), 0)),
            offsets: vec![32],
        }
        .payload();

        assert_eq!(parse_saio(&payload).unwrap(), None);
    }

    /// CENC SAI references allow only aux info parameters 0 and 1.
    ///
    /// A matching protection-scheme type with another parameter is a different
    /// auxiliary information stream and must not be consumed as IV/subsample
    /// data.
    #[test]
    fn parse_saiz_ignores_cenc_aux_info_with_unsupported_parameter() {
        let payload = SaizBoxSyntax {
            aux_info: Some((SchemeType::Cbcs.box_type(), 2)),
            default_sample_info_size: 16,
            sample_count: 1,
            explicit_sample_info_sizes: Vec::new(),
        }
        .payload();

        assert_eq!(parse_saiz(&payload).unwrap(), None);
    }

    /// `sbgp` version 1 inserts a grouping type parameter before entry count.
    ///
    /// For `seig` mappings, each entry gives a run length and a description
    /// index. Index zero means track defaults; non-zero values select an SGPD
    /// entry. Fragment-local indexes may use high bits, but the low 16 bits
    /// still carry the 1-based SGPD entry number used by this parser.
    #[test]
    fn parse_sbgp_version_1_and_fragment_local_description_index() {
        let payload = SbgpBoxSyntax {
            version: 1,
            grouping_type: GROUPING_TYPE_SEIG,
            grouping_type_parameter: Some(7),
            entries: vec![
                SbgpEntry {
                    sample_count: 5,
                    group_description_index: 0,
                },
                SbgpEntry {
                    sample_count: 3,
                    group_description_index: 0x0001_0002,
                },
            ],
        }
        .payload();

        let entries = SbgpEntry::parse_seig(&payload).unwrap().unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sample_count, 5);
        assert_eq!(entries[0].group_description_index, 0);
        assert_eq!(entries[1].sample_count, 3);
        assert_eq!(entries[1].description_index().unwrap(), 1);
    }

    /// SGPD version 2 inserts `default_sample_description_index` before
    /// `entry_count`.
    ///
    /// The CENC `seig` description then carries packed pattern values,
    /// protection state, per-sample IV size, KID, and, only when the IV size is
    /// zero for a protected entry, a constant IV. When `per_sample_iv_size` is
    /// non-zero, no constant IV bytes follow the KID.
    #[test]
    fn parse_sgpd_version_2_without_constant_iv_for_per_sample_iv() {
        let payload = SgpdBoxSyntax {
            version: 2,
            grouping_type: GROUPING_TYPE_SEIG,
            default_length: None,
            default_sample_description_index: Some(1),
            entries: vec![SgpdSeigEntrySyntax {
                length_including_length_field: None,
                pattern: CbcPattern {
                    crypt_byte_block: 2,
                    skip_byte_block: 1,
                },
                is_protected: true,
                per_sample_iv_size: 8,
                kid: [0x44; 16],
                constant_iv: None,
            }],
        }
        .payload();

        let entries = SeigEntry::parse_seig(&payload).unwrap().unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].pattern,
            Some(CbcPattern {
                crypt_byte_block: 2,
                skip_byte_block: 1,
            })
        );
        assert!(entries[0].is_protected);
        assert_eq!(entries[0].per_sample_iv_size, 8);
        assert_eq!(entries[0].constant_iv, None);
    }

    #[test]
    fn parse_tenc_rejects_constant_iv_longer_than_aes_block() {
        let payload = TencBoxSyntax {
            version: 0,
            pattern: None,
            is_protected: true,
            iv_size: 0,
            kid: [0; 16],
            constant_iv: Some(vec![0; 17]),
        }
        .payload();

        assert!(matches!(
            TrackEncryptionInfo::parse_tenc(&payload),
            Err(CencError::InvalidTenc(_))
        ));
    }

    #[test]
    fn parse_sgpd_rejects_constant_iv_longer_than_aes_block() {
        let payload = SgpdBoxSyntax {
            version: 1,
            grouping_type: GROUPING_TYPE_SEIG,
            default_length: Some(38),
            default_sample_description_index: None,
            entries: vec![SgpdSeigEntrySyntax {
                length_including_length_field: None,
                pattern: CbcPattern {
                    crypt_byte_block: 0,
                    skip_byte_block: 0,
                },
                is_protected: true,
                per_sample_iv_size: 0,
                kid: SAMPLE_KID,
                constant_iv: Some(vec![0; 17]),
            }],
        }
        .payload();

        assert!(matches!(
            SeigEntry::parse_seig(&payload),
            Err(CencError::InvalidSenc(_))
        ));
    }
}
