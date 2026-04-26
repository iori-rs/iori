use crate::errors::{CencError, Result};
use crate::types::{CbcPattern, SchemeType, Subsample};
use shiguredo_mp4::boxes::{SampleEntry, UnknownBox};
use shiguredo_mp4::{BoxHeader, BoxType, Decode};

pub(crate) const BOX_SINF: [u8; 4] = *b"sinf";
pub(crate) const BOX_SCHI: [u8; 4] = *b"schi";
pub(crate) const BOX_SCHM: [u8; 4] = *b"schm";
pub(crate) const BOX_TENC: [u8; 4] = *b"tenc";
pub(crate) const BOX_SENC: [u8; 4] = *b"senc";
pub(crate) const BOX_SBGP: [u8; 4] = *b"sbgp";
pub(crate) const BOX_SGPD: [u8; 4] = *b"sgpd";
pub(crate) const BOX_ENCV: [u8; 4] = *b"encv";
pub(crate) const BOX_ENCA: [u8; 4] = *b"enca";

const VISUAL_SAMPLE_ENTRY_SIZE: usize = 78;
const AUDIO_SAMPLE_ENTRY_SIZE: usize = 28;

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
        if self.remaining() < 1 {
            return Err(CencError::InvalidSenc("u8 truncated".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(CencError::InvalidSenc("u16 truncated".into()));
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(CencError::InvalidSenc("u32 truncated".into()));
        }
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(CencError::InvalidSenc("u64 truncated".into()));
        }
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub(crate) fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.remaining() < len {
            return Err(CencError::InvalidSenc("unexpected end of data".into()));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
}

// ---------------------------------------------------------------------------
// FullBoxHeader
// ---------------------------------------------------------------------------

pub(crate) struct FullBoxHeader {
    pub(crate) version: u8,
    pub(crate) flags: u32,
}

impl FullBoxHeader {
    pub(crate) fn parse(reader: &mut ByteReader) -> Result<Self> {
        let version = reader.read_u8()?;
        let b1 = reader.read_u8()?;
        let b2 = reader.read_u8()?;
        let b3 = reader.read_u8()?;
        let flags = ((b1 as u32) << 16) | ((b2 as u32) << 8) | b3 as u32;
        Ok(Self { version, flags })
    }
}

// ---------------------------------------------------------------------------
// ChildBox — lightweight view of a child box within a payload
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ChildBox<'a> {
    box_type: [u8; 4],
    payload: &'a [u8],
}

impl ChildBox<'_> {
    fn parse_children<'a>(payload: &'a [u8]) -> Result<Vec<ChildBox<'a>>> {
        let mut boxes = Vec::new();
        let mut offset = 0usize;
        while offset < payload.len() {
            let (header, header_size) = BoxHeader::decode(&payload[offset..])?;
            let mut box_size = usize::try_from(header.box_size.get())
                .map_err(|_| CencError::InvalidSenc("box size overflow".to_string()))?;
            if box_size == 0 {
                box_size = payload.len() - offset;
            }
            if box_size < header_size || offset + box_size > payload.len() {
                return Err(CencError::InvalidSenc("invalid child box size".to_string()));
            }
            let start = offset + header_size;
            let end = offset + box_size;
            let box_type = match header.box_type {
                BoxType::Normal(ty) => ty,
                BoxType::Uuid(_) => {
                    offset += box_size;
                    continue;
                }
            };
            boxes.push(ChildBox {
                box_type,
                payload: &payload[start..end],
            });
            offset += box_size;
        }
        Ok(boxes)
    }
}

// ---------------------------------------------------------------------------
// RawMp4Box — lightweight top-level box descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct RawMp4Box {
    pub(crate) box_type: [u8; 4],
    pub(crate) start: usize,
    pub(crate) size: usize,
}

impl RawMp4Box {
    pub(crate) fn parse_all(buf: &[u8], base_offset: usize) -> Result<Vec<Self>> {
        let mut boxes = Vec::new();
        let mut offset = 0usize;
        while offset < buf.len() {
            let (header, header_size) = BoxHeader::decode(&buf[offset..])?;
            let mut size = usize::try_from(header.box_size.get())
                .map_err(|_| CencError::InvalidSenc("box size overflow".to_string()))?;
            if size == 0 {
                size = buf.len() - offset;
            }
            if size < header_size || offset + size > buf.len() {
                return Err(CencError::InvalidSenc("invalid box size".to_string()));
            }
            let box_type = match header.box_type {
                BoxType::Normal(ty) => ty,
                BoxType::Uuid(_) => {
                    offset += size;
                    continue;
                }
            };
            boxes.push(RawMp4Box {
                box_type,
                start: base_offset + offset,
                size,
            });
            offset += size;
        }
        Ok(boxes)
    }
}

// ---------------------------------------------------------------------------
// SampleEncryptionEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SampleEncryptionEntry {
    pub(crate) iv: [u8; 16],
    pub(crate) subsamples: Vec<Subsample>,
}

impl SampleEncryptionEntry {
    /// Parse a `senc` box payload into per-sample encryption entries.
    pub(crate) fn parse_senc(
        payload: &[u8],
        iv_size: u8,
        constant_iv: Option<[u8; 16]>,
    ) -> Result<Vec<Self>> {
        if payload.len() < 8 {
            return Err(CencError::InvalidSenc("senc too short".to_string()));
        }
        let version = payload[0];
        if version != 0 {
            return Err(CencError::InvalidSenc(format!(
                "unsupported senc version {version}"
            )));
        }
        let flags =
            ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | payload[3] as u32;
        let has_subsamples = (flags & 0x000002) != 0;
        if flags & !0x000002 != 0 {
            return Err(CencError::InvalidSenc(format!(
                "unsupported senc flags: {flags:#x}"
            )));
        }

        let mut reader = ByteReader::new(&payload[4..]);
        let sample_count = reader.read_u32()?;
        let mut entries = Vec::with_capacity(sample_count as usize);
        for _ in 0..sample_count {
            let iv = Self::read_iv(&mut reader, iv_size, constant_iv)?;
            let subsamples = if has_subsamples {
                Self::read_subsamples(&mut reader)?
            } else {
                Vec::new()
            };
            entries.push(Self { iv, subsamples });
        }
        Ok(entries)
    }

    /// Parse auxiliary sample info entries (from saiz/saio data).
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
            if size == 0 {
                return Err(CencError::InvalidSenc("empty sample info size".to_string()));
            }
            if data.len() < offset + size {
                return Err(CencError::InvalidSenc("sai data truncated".to_string()));
            }
            let mut reader = ByteReader::new(&data[offset..offset + size]);
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
            entries.push(Self { iv, subsamples });
            offset += size;
        }
        Ok(entries)
    }

    fn read_iv(reader: &mut ByteReader, iv_size: u8, constant_iv: Option<[u8; 16]>) -> Result<[u8; 16]> {
        if iv_size == 0 {
            return constant_iv.ok_or_else(|| {
                CencError::InvalidSenc("missing constant iv for iv_size=0".to_string())
            });
        }
        let iv_len = iv_size as usize;
        if iv_len > 16 {
            return Err(CencError::InvalidSenc(format!(
                "unsupported iv size {iv_len}"
            )));
        }
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
    pub(crate) fn from_sample_entries(
        entries: &[SampleEntry],
    ) -> Result<Vec<Option<Self>>> {
        entries.iter().map(Self::parse_sample_entry).collect()
    }

    fn parse_sample_entry(entry: &SampleEntry) -> Result<Option<Self>> {
        // Standard CENC path: encv/enca box stored as SampleEntry::Unknown.
        if let SampleEntry::Unknown(unknown) = entry {
            let BoxType::Normal(box_type) = unknown.box_type else {
                return Ok(None);
            };
            if box_type != BOX_ENCV && box_type != BOX_ENCA {
                return Ok(None);
            }
            let base_size = if box_type == BOX_ENCV {
                VISUAL_SAMPLE_ENTRY_SIZE
            } else {
                AUDIO_SAMPLE_ENTRY_SIZE
            };
            if unknown.payload.len() <= base_size {
                return Err(CencError::UnsupportedSampleEntry(
                    String::from_utf8_lossy(&box_type).to_string(),
                ));
            }
            let children = ChildBox::parse_children(&unknown.payload[base_size..])?;
            let sinf = children
                .iter()
                .find(|child| child.box_type == BOX_SINF)
                .ok_or(CencError::MissingSinf)?;
            return Ok(Some(Self::parse_sinf(sinf.payload)?));
        }

        // CMAF cbcs path: known codec type with sinf appended.
        for ub in unknown_boxes_from_sample_entry(entry) {
            if ub.box_type == BoxType::Normal(BOX_SINF) {
                return Ok(Some(Self::parse_sinf(&ub.payload)?));
            }
        }

        Ok(None)
    }

    fn parse_sinf(sinf_payload: &[u8]) -> Result<Self> {
        let sinf_children = ChildBox::parse_children(sinf_payload)?;
        let schm = sinf_children
            .iter()
            .find(|child| child.box_type == BOX_SCHM)
            .ok_or(CencError::MissingSchm)?;
        let scheme = Self::parse_schm(schm.payload)?;
        let schi = sinf_children
            .iter()
            .find(|child| child.box_type == BOX_SCHI)
            .ok_or(CencError::MissingTenc)?;
        let schi_children = ChildBox::parse_children(schi.payload)?;
        let tenc = schi_children
            .iter()
            .find(|child| child.box_type == BOX_TENC)
            .ok_or(CencError::MissingTenc)?;
        let mut info = Self::parse_tenc(tenc.payload)?;
        info.scheme = scheme;
        Ok(info)
    }

    fn parse_schm(payload: &[u8]) -> Result<SchemeType> {
        if payload.len() < 12 {
            return Err(CencError::InvalidTenc("schm too short".to_string()));
        }
        let scheme_type = [payload[4], payload[5], payload[6], payload[7]];
        SchemeType::from_bytes(scheme_type).ok_or_else(|| {
            CencError::UnsupportedScheme(String::from_utf8_lossy(&scheme_type).to_string())
        })
    }

    fn parse_tenc(payload: &[u8]) -> Result<Self> {
        if payload.len() < 24 {
            return Err(CencError::InvalidTenc("tenc too short".to_string()));
        }
        let version = payload[0];
        let mut offset = 4;
        if payload.len().saturating_sub(offset) == 20 {
            offset += 1;
        }
        let (pattern, is_protected, iv_size) = if version == 0 {
            let _reserved = payload[offset];
            offset += 1;
            let is_protected = payload[offset] != 0;
            offset += 1;
            let iv_size = payload[offset];
            offset += 1;
            (None, is_protected, iv_size)
        } else if version == 1 {
            let mut pattern_offset = offset;
            if payload.len().saturating_sub(pattern_offset) >= 4 {
                let candidate_iv_size = payload[pattern_offset + 2];
                if !matches!(candidate_iv_size, 0 | 8 | 16)
                    && matches!(payload[pattern_offset + 3], 0 | 8 | 16)
                {
                    pattern_offset += 1;
                }
            }
            let byte = payload[pattern_offset];
            pattern_offset += 1;
            let pattern = CbcPattern {
                crypt_byte_block: byte >> 4,
                skip_byte_block: byte & 0x0f,
            };
            let is_protected = payload[pattern_offset] != 0;
            pattern_offset += 1;
            let iv_size = payload[pattern_offset];
            pattern_offset += 1;
            offset = pattern_offset;
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

        if payload.len() < offset + 16 {
            return Err(CencError::InvalidTenc("missing default_kid".to_string()));
        }
        let mut kid = [0u8; 16];
        kid.copy_from_slice(&payload[offset..offset + 16]);
        offset += 16;

        let constant_iv = if is_protected && iv_size == 0 {
            if payload.len() < offset + 1 {
                return Err(CencError::InvalidTenc(
                    "missing constant iv size".to_string(),
                ));
            }
            let size = payload[offset] as usize;
            offset += 1;
            if payload.len() < offset + size {
                return Err(CencError::InvalidTenc("constant iv truncated".to_string()));
            }
            let mut iv = [0u8; 16];
            iv[..size].copy_from_slice(&payload[offset..offset + size]);
            Some(iv)
        } else {
            None
        };

        Ok(Self {
            scheme: SchemeType::Cenc,
            kid,
            iv_size,
            constant_iv,
            pattern,
            is_protected,
        })
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

// ---------------------------------------------------------------------------
// saiz / saio helpers (payload-level parsing, used only from fmp4)
// ---------------------------------------------------------------------------

pub(crate) fn parse_saiz(payload: &[u8]) -> Result<Vec<u8>> {
    let mut reader = ByteReader::new(payload);
    let header = FullBoxHeader::parse(&mut reader)?;
    if header.flags & 0x000001 != 0 {
        let _ = reader.read_u32()?;
        let _ = reader.read_u32()?;
    }
    let default_size = reader.read_u8()?;
    let sample_count = reader.read_u32()? as usize;
    let mut sizes = Vec::with_capacity(sample_count);
    if default_size != 0 {
        sizes.resize(sample_count, default_size);
    } else {
        let data = reader.read_exact(sample_count)?;
        sizes.extend_from_slice(data);
    }
    Ok(sizes)
}

pub(crate) fn parse_saio(payload: &[u8]) -> Result<Vec<u64>> {
    let mut reader = ByteReader::new(payload);
    let header = FullBoxHeader::parse(&mut reader)?;
    if header.flags & 0x000001 != 0 {
        let _ = reader.read_u32()?;
        let _ = reader.read_u32()?;
    }
    let entry_count = reader.read_u32()? as usize;
    let mut offsets = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let value = if header.version == 0 {
            reader.read_u32()? as u64
        } else {
            reader.read_u64()?
        };
        offsets.push(value);
    }
    Ok(offsets)
}

// ---------------------------------------------------------------------------
// is_seig_grouping_box — predicate on external type
// ---------------------------------------------------------------------------

pub(crate) fn is_seig_grouping_box(b: &UnknownBox) -> bool {
    match b.box_type {
        BoxType::Normal(BOX_SBGP) | BoxType::Normal(BOX_SGPD) => {
            b.payload.len() >= 8 && &b.payload[4..8] == b"seig"
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// SbgpEntry — sample-to-group mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub(crate) struct SbgpEntry {
    pub(crate) sample_count: u32,
    /// 0 means "use track-level defaults", ≥1 is a 1-based index into the SGPD.
    pub(crate) group_description_index: u32,
}

impl SbgpEntry {
    /// Parse an SBGP box payload. Returns `None` when `grouping_type != "seig"`.
    pub(crate) fn parse_seig(payload: &[u8]) -> Result<Option<Vec<Self>>> {
        let mut reader = ByteReader::new(payload);
        let header = FullBoxHeader::parse(&mut reader)?;
        if reader.remaining() < 4 {
            return Err(CencError::InvalidSenc("sbgp too short".to_string()));
        }
        let grouping_type = reader.read_exact(4)?;
        if grouping_type != b"seig" {
            return Ok(None);
        }
        if header.version == 1 {
            let _ = reader.read_u32()?; // grouping_type_parameter
        }
        let entry_count = reader.read_u32()? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(Self {
                sample_count: reader.read_u32()?,
                group_description_index: reader.read_u32()?,
            });
        }
        Ok(Some(entries))
    }
}

// ---------------------------------------------------------------------------
// SeigEntry — sample group description entry
// ---------------------------------------------------------------------------

/// A single seig entry from an SGPD (SampleGroupDescription) box.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SeigEntry {
    pub(crate) pattern: Option<CbcPattern>,
    pub(crate) is_protected: bool,
    #[allow(dead_code)]
    pub(crate) per_sample_iv_size: u8,
    pub(crate) kid: [u8; 16],
    pub(crate) constant_iv: Option<[u8; 16]>,
}

impl SeigEntry {
    /// Parse an SGPD box payload for seig entries. Returns `None` when `grouping_type != "seig"`.
    pub(crate) fn parse_seig(payload: &[u8]) -> Result<Option<Vec<Self>>> {
        let mut reader = ByteReader::new(payload);
        let header = FullBoxHeader::parse(&mut reader)?;
        if reader.remaining() < 4 {
            return Err(CencError::InvalidSenc("sgpd too short".to_string()));
        }
        let grouping_type = reader.read_exact(4)?;
        if grouping_type != b"seig" {
            return Ok(None);
        }
        let default_length = if header.version == 1 {
            reader.read_u32()?
        } else {
            0u32
        };
        if header.version >= 2 {
            let _ = reader.read_u32()?; // default_sample_description_index
        }
        let entry_count = reader.read_u32()? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if header.version == 1 && default_length == 0 {
                let _ = reader.read_u32()?; // length_including_length_field
            }
            let crypt_skip = reader.read_u8()?;
            let pattern = Some(CbcPattern {
                crypt_byte_block: crypt_skip >> 4,
                skip_byte_block: crypt_skip & 0x0f,
            });
            let _reserved = reader.read_u8()?;
            let is_protected = reader.read_u8()? != 0;
            let per_sample_iv_size = reader.read_u8()?;
            let kid_bytes = reader.read_exact(16)?;
            let mut kid = [0u8; 16];
            kid.copy_from_slice(kid_bytes);
            let constant_iv = if is_protected && per_sample_iv_size == 0 {
                let constant_iv_size = reader.read_u8()? as usize;
                let iv_bytes = reader.read_exact(constant_iv_size)?;
                let mut iv = [0u8; 16];
                iv[..constant_iv_size].copy_from_slice(iv_bytes);
                Some(iv)
            } else {
                None
            };
            entries.push(Self {
                pattern,
                is_protected,
                per_sample_iv_size,
                kid,
                constant_iv,
            });
        }
        Ok(Some(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SGPD_SEIG_BOX: &[u8] = &[
        0x00, 0x00, 0x00, 0x3D, 0x73, 0x67, 0x70, 0x64,
        0x01, 0x00, 0x00, 0x00,
        0x73, 0x65, 0x69, 0x67,
        0x00, 0x00, 0x00, 0x25,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x00,
        0x70, 0xB9, 0x90, 0xCE, 0xB0, 0x91, 0x31, 0x38,
        0xB2, 0x95, 0x9F, 0x53, 0x28, 0x01, 0x49, 0x98, 0x10,
        0x1F, 0x2D, 0xCC, 0xFC, 0xC9, 0xE9, 0x36, 0xF5,
        0x7E, 0x63, 0xA7, 0x23, 0xDD, 0x47, 0x0A, 0x7D,
    ];

    #[test]
    fn test_parse_sgpd_seig() {
        let payload = &SGPD_SEIG_BOX[8..];
        let entries = SeigEntry::parse_seig(payload).unwrap().unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(e.is_protected);
        assert_eq!(e.per_sample_iv_size, 0);
        assert_eq!(
            e.kid,
            [
                0x70, 0xB9, 0x90, 0xCE, 0xB0, 0x91, 0x31, 0x38, 0xB2, 0x95, 0x9F, 0x53, 0x28,
                0x01, 0x49, 0x98,
            ]
        );
        assert_eq!(
            e.constant_iv,
            Some([
                0x1F, 0x2D, 0xCC, 0xFC, 0xC9, 0xE9, 0x36, 0xF5, 0x7E, 0x63, 0xA7, 0x23, 0xDD,
                0x47, 0x0A, 0x7D,
            ])
        );
    }

    #[test]
    fn test_parse_sgpd_seig_wrong_grouping_type() {
        let mut payload = SGPD_SEIG_BOX[8..].to_vec();
        payload[4..8].copy_from_slice(b"maif");
        assert!(SeigEntry::parse_seig(&payload).unwrap().is_none());
    }
}
