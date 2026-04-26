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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SampleEncryptionEntry {
    pub(crate) iv: [u8; 16],
    pub(crate) subsamples: Vec<Subsample>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TrackEncryptionInfo {
    pub(crate) scheme: SchemeType,
    pub(crate) kid: [u8; 16],
    pub(crate) iv_size: u8,
    pub(crate) constant_iv: Option<[u8; 16]>,
    pub(crate) pattern: Option<CbcPattern>,
    pub(crate) is_protected: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RawMp4Box {
    pub(crate) box_type: [u8; 4],
    pub(crate) start: usize,
    pub(crate) size: usize,
}

#[derive(Debug)]
struct ChildBox<'a> {
    box_type: [u8; 4],
    payload: &'a [u8],
}

pub(crate) fn parse_mp4_boxes(buf: &[u8], base_offset: usize) -> Result<Vec<RawMp4Box>> {
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

pub(crate) fn build_entry_encryption_info(
    entries: &[SampleEntry],
) -> Result<Vec<Option<TrackEncryptionInfo>>> {
    let mut infos = Vec::with_capacity(entries.len());
    for entry in entries {
        infos.push(parse_sample_entry_encryption(entry)?);
    }
    Ok(infos)
}

fn parse_sample_entry_encryption(entry: &SampleEntry) -> Result<Option<TrackEncryptionInfo>> {
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
        let children = read_child_boxes(&unknown.payload[base_size..])?;
        let sinf = children
            .iter()
            .find(|child| child.box_type == BOX_SINF)
            .ok_or(CencError::MissingSinf)?;
        return Ok(Some(parse_sinf_payload(sinf.payload)?));
    }

    // CMAF cbcs path: known codec type (avc1, hvc1, mp4a, …) with sinf appended as a
    // child box rather than being wrapped in encv/enca.
    for ub in unknown_boxes_from_sample_entry(entry) {
        if ub.box_type == BoxType::Normal(BOX_SINF) {
            return Ok(Some(parse_sinf_payload(&ub.payload)?));
        }
    }

    Ok(None)
}

/// Parse a `sinf` box payload into [`TrackEncryptionInfo`].
fn parse_sinf_payload(sinf_payload: &[u8]) -> Result<TrackEncryptionInfo> {
    let sinf_children = read_child_boxes(sinf_payload)?;
    let schm = sinf_children
        .iter()
        .find(|child| child.box_type == BOX_SCHM)
        .ok_or(CencError::MissingSchm)?;
    let scheme = parse_schm(schm.payload)?;
    let schi = sinf_children
        .iter()
        .find(|child| child.box_type == BOX_SCHI)
        .ok_or(CencError::MissingTenc)?;
    let schi_children = read_child_boxes(schi.payload)?;
    let tenc = schi_children
        .iter()
        .find(|child| child.box_type == BOX_TENC)
        .ok_or(CencError::MissingTenc)?;
    let mut info = parse_tenc(tenc.payload)?;
    info.scheme = scheme;
    Ok(info)
}

/// Return the `unknown_boxes` slice from any known codec sample entry type.
///
/// All codec box types produced by shiguredo-mp4 store unrecognised child boxes
/// (including `sinf` in CMAF-style cbcs files) in `unknown_boxes`.
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

fn parse_schm(payload: &[u8]) -> Result<SchemeType> {
    if payload.len() < 12 {
        return Err(CencError::InvalidTenc("schm too short".to_string()));
    }
    let scheme_type = [payload[4], payload[5], payload[6], payload[7]];
    SchemeType::from_bytes(scheme_type).ok_or_else(|| {
        CencError::UnsupportedScheme(String::from_utf8_lossy(&scheme_type).to_string())
    })
}

fn parse_tenc(payload: &[u8]) -> Result<TrackEncryptionInfo> {
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

    Ok(TrackEncryptionInfo {
        scheme: SchemeType::Cenc,
        kid,
        iv_size,
        constant_iv,
        pattern,
        is_protected,
    })
}

pub(crate) fn parse_senc(
    payload: &[u8],
    iv_size: u8,
    constant_iv: Option<[u8; 16]>,
) -> Result<Vec<SampleEncryptionEntry>> {
    if payload.len() < 8 {
        return Err(CencError::InvalidSenc("senc too short".to_string()));
    }
    let version = payload[0];
    if version != 0 {
        return Err(CencError::InvalidSenc(format!(
            "unsupported senc version {version}"
        )));
    }
    let flags = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | payload[3] as u32;
    let has_subsamples = (flags & 0x000002) != 0;
    if flags & !0x000002 != 0 {
        return Err(CencError::InvalidSenc(format!(
            "unsupported senc flags: {flags:#x}"
        )));
    }

    let mut offset = 4;
    let sample_count = read_u32(payload, &mut offset)?;
    let mut entries = Vec::with_capacity(sample_count as usize);
    for _ in 0..sample_count {
        let iv = if iv_size == 0 {
            constant_iv.ok_or_else(|| {
                CencError::InvalidSenc("missing constant iv for iv_size=0".to_string())
            })?
        } else {
            let iv_len = iv_size as usize;
            if iv_len > 16 {
                return Err(CencError::InvalidSenc(format!(
                    "unsupported iv size {iv_len}"
                )));
            }
            if payload.len() < offset + iv_len {
                return Err(CencError::InvalidSenc("iv truncated".to_string()));
            }
            let mut iv_buf = [0u8; 16];
            iv_buf[..iv_len].copy_from_slice(&payload[offset..offset + iv_len]);
            offset += iv_len;
            if iv_len == 8 {
                // Pad 64-bit IV with zeros to build a 128-bit counter block.
                iv_buf[8..].fill(0);
            }
            iv_buf
        };
        let mut subsamples = Vec::new();
        if has_subsamples {
            let subsample_count = read_u16(payload, &mut offset)?;
            for _ in 0..subsample_count {
                let clear_bytes = read_u16(payload, &mut offset)?;
                let encrypted_bytes = read_u32(payload, &mut offset)?;
                subsamples.push(Subsample {
                    clear_bytes,
                    encrypted_bytes,
                });
            }
        }
        entries.push(SampleEncryptionEntry { iv, subsamples });
    }
    Ok(entries)
}

pub(crate) fn parse_saiz(payload: &[u8]) -> Result<Vec<u8>> {
    let (_version, flags, mut offset) = read_full_box_header(payload)?;
    if flags & 0x000001 != 0 {
        let _ = read_u32(payload, &mut offset)?;
        let _ = read_u32(payload, &mut offset)?;
    }
    let default_size = read_u8(payload, &mut offset)?;
    let sample_count = read_u32(payload, &mut offset)? as usize;
    let mut sizes = Vec::with_capacity(sample_count);
    if default_size != 0 {
        sizes.resize(sample_count, default_size);
    } else {
        if payload.len() < offset + sample_count {
            return Err(CencError::InvalidSenc("saiz truncated".to_string()));
        }
        sizes.extend_from_slice(&payload[offset..offset + sample_count]);
    }
    Ok(sizes)
}

pub(crate) fn parse_saio(payload: &[u8]) -> Result<Vec<u64>> {
    let (version, flags, mut offset) = read_full_box_header(payload)?;
    if flags & 0x000001 != 0 {
        let _ = read_u32(payload, &mut offset)?;
        let _ = read_u32(payload, &mut offset)?;
    }
    let entry_count = read_u32(payload, &mut offset)? as usize;
    let mut offsets = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let value = if version == 0 {
            read_u32(payload, &mut offset)? as u64
        } else {
            read_u64(payload, &mut offset)?
        };
        offsets.push(value);
    }
    Ok(offsets)
}

pub(crate) fn parse_sai_entries(
    data: &[u8],
    sizes: &[u8],
    iv_size: u8,
    constant_iv: Option<[u8; 16]>,
) -> Result<Vec<SampleEncryptionEntry>> {
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
        let mut entry_offset = offset;
        let iv = if iv_size == 0 {
            constant_iv.ok_or_else(|| {
                CencError::InvalidSenc("missing constant iv for iv_size=0".to_string())
            })?
        } else {
            let iv_len = iv_size as usize;
            if iv_len > 16 || size < iv_len {
                return Err(CencError::InvalidSenc("invalid iv size".to_string()));
            }
            let mut iv_buf = [0u8; 16];
            iv_buf[..iv_len].copy_from_slice(&data[entry_offset..entry_offset + iv_len]);
            entry_offset += iv_len;
            if iv_len == 8 {
                iv_buf[8..].fill(0);
            }
            iv_buf
        };
        let mut subsamples = Vec::new();
        let remaining = offset + size - entry_offset;
        if remaining > 0 {
            if remaining < 2 {
                return Err(CencError::InvalidSenc(
                    "subsample data truncated".to_string(),
                ));
            }
            let subsample_count = read_u16(data, &mut entry_offset)? as usize;
            for _ in 0..subsample_count {
                let clear_bytes = read_u16(data, &mut entry_offset)?;
                let encrypted_bytes = read_u32(data, &mut entry_offset)?;
                subsamples.push(Subsample {
                    clear_bytes,
                    encrypted_bytes,
                });
            }
            if entry_offset != offset + size {
                return Err(CencError::InvalidSenc("sai size mismatch".to_string()));
            }
        }
        entries.push(SampleEncryptionEntry { iv, subsamples });
        offset += size;
    }
    Ok(entries)
}

pub(crate) fn read_full_box_header(payload: &[u8]) -> Result<(u8, u32, usize)> {
    if payload.len() < 4 {
        return Err(CencError::InvalidSenc(
            "full box header truncated".to_string(),
        ));
    }
    let version = payload[0];
    let flags = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | payload[3] as u32;
    Ok((version, flags, 4))
}

fn read_child_boxes(payload: &[u8]) -> Result<Vec<ChildBox<'_>>> {
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

pub(crate) fn read_u16(buf: &[u8], offset: &mut usize) -> Result<u16> {
    if buf.len() < *offset + 2 {
        return Err(CencError::InvalidSenc("u16 truncated".to_string()));
    }
    let value = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

pub(crate) fn read_u8(buf: &[u8], offset: &mut usize) -> Result<u8> {
    if buf.len() <= *offset {
        return Err(CencError::InvalidSenc("u8 truncated".to_string()));
    }
    let value = buf[*offset];
    *offset += 1;
    Ok(value)
}

pub(crate) fn read_u32(buf: &[u8], offset: &mut usize) -> Result<u32> {
    if buf.len() < *offset + 4 {
        return Err(CencError::InvalidSenc("u32 truncated".to_string()));
    }
    let value = u32::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}

pub(crate) fn read_u64(buf: &[u8], offset: &mut usize) -> Result<u64> {
    if buf.len() < *offset + 8 {
        return Err(CencError::InvalidSenc("u64 truncated".to_string()));
    }
    let value = u64::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
        buf[*offset + 4],
        buf[*offset + 5],
        buf[*offset + 6],
        buf[*offset + 7],
    ]);
    *offset += 8;
    Ok(value)
}

pub(crate) fn is_seig_grouping_box(b: &UnknownBox) -> bool {
    match b.box_type {
        BoxType::Normal(BOX_SBGP) | BoxType::Normal(BOX_SGPD) => {
            b.payload.len() >= 8 && &b.payload[4..8] == b"seig"
        }
        _ => false,
    }
}

/// Entry from an SBGP (SampleToGroup) box that maps a run of samples to a group.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SbgpEntry {
    pub(crate) sample_count: u32,
    /// 0 means "use track-level defaults", ≥1 is a 1-based index into the SGPD.
    pub(crate) group_description_index: u32,
}

/// A single seig entry from an SGPD (SampleGroupDescription) box.
///
/// The on-disk layout mirrors a tenc v1 payload:
/// `[ crypt<<4 | skip ] [ reserved ] [ is_protected ] [ per_sample_iv_size ] [ KID×16 ]`
/// followed by `[ constant_iv_size ] [ constant_iv×N ]` when
/// `is_protected == 1 && per_sample_iv_size == 0`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SeigEntry {
    pub(crate) pattern: Option<CbcPattern>,
    pub(crate) is_protected: bool,
    pub(crate) per_sample_iv_size: u8,
    pub(crate) kid: [u8; 16],
    /// Present when `is_protected && per_sample_iv_size == 0` (cbcs constant-IV mode).
    pub(crate) constant_iv: Option<[u8; 16]>,
}

/// Parse an SBGP box payload. Returns `None` when `grouping_type != "seig"`.
pub(crate) fn parse_sbgp_seig(payload: &[u8]) -> Result<Option<Vec<SbgpEntry>>> {
    let (version, _flags, mut offset) = read_full_box_header(payload)?;
    if payload.len() < offset + 4 {
        return Err(CencError::InvalidSenc("sbgp too short".to_string()));
    }
    if &payload[offset..offset + 4] != b"seig" {
        return Ok(None);
    }
    offset += 4;
    if version == 1 {
        // grouping_type_parameter
        let _ = read_u32(payload, &mut offset)?;
    }
    let entry_count = read_u32(payload, &mut offset)? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let sample_count = read_u32(payload, &mut offset)?;
        let group_description_index = read_u32(payload, &mut offset)?;
        entries.push(SbgpEntry {
            sample_count,
            group_description_index,
        });
    }
    Ok(Some(entries))
}

/// Parse an SGPD box payload for seig entries. Returns `None` when `grouping_type != "seig"`.
pub(crate) fn parse_sgpd_seig(payload: &[u8]) -> Result<Option<Vec<SeigEntry>>> {
    let (version, _flags, mut offset) = read_full_box_header(payload)?;
    if payload.len() < offset + 4 {
        return Err(CencError::InvalidSenc("sgpd too short".to_string()));
    }
    if &payload[offset..offset + 4] != b"seig" {
        return Ok(None);
    }
    offset += 4;
    let default_length = if version == 1 {
        read_u32(payload, &mut offset)?
    } else {
        0u32
    };
    if version >= 2 {
        let _ = read_u32(payload, &mut offset)?; // default_sample_description_index
    }
    let entry_count = read_u32(payload, &mut offset)? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        if version == 1 && default_length == 0 {
            let _ = read_u32(payload, &mut offset)?; // length_including_length_field
        }
        // seig entry layout (mirrors tenc v1):
        //   byte 0: (crypt_byte_block << 4) | skip_byte_block
        //   byte 1: reserved
        //   byte 2: is_protected (1 = encrypted)
        //   byte 3: per_sample_iv_size
        //   bytes 4-19: KID
        //   if is_protected && per_sample_iv_size == 0:
        //     byte 20: constant_iv_size
        //     bytes 21+: constant_iv
        let crypt_skip = read_u8(payload, &mut offset)?;
        let pattern = Some(CbcPattern {
            crypt_byte_block: crypt_skip >> 4,
            skip_byte_block: crypt_skip & 0x0f,
        });
        let _reserved = read_u8(payload, &mut offset)?;
        let is_protected = read_u8(payload, &mut offset)? != 0;
        let per_sample_iv_size = read_u8(payload, &mut offset)?;
        if payload.len() < offset + 16 {
            return Err(CencError::InvalidSenc(
                "sgpd seig entry truncated".to_string(),
            ));
        }
        let mut kid = [0u8; 16];
        kid.copy_from_slice(&payload[offset..offset + 16]);
        offset += 16;
        let constant_iv = if is_protected && per_sample_iv_size == 0 {
            let constant_iv_size = read_u8(payload, &mut offset)? as usize;
            if payload.len() < offset + constant_iv_size {
                return Err(CencError::InvalidSenc(
                    "sgpd seig constant_iv truncated".to_string(),
                ));
            }
            let mut iv = [0u8; 16];
            iv[..constant_iv_size].copy_from_slice(&payload[offset..offset + constant_iv_size]);
            offset += constant_iv_size;
            Some(iv)
        } else {
            None
        };
        entries.push(SeigEntry {
            pattern,
            is_protected,
            per_sample_iv_size,
            kid,
            constant_iv,
        });
    }
    Ok(Some(entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes of a real SGPD seig box (61 bytes total, 8-byte box header + 53-byte payload)
    /// from a cbcs-encrypted fMP4 segment.
    ///
    /// Parsed layout:
    ///   version=1, flags=0, grouping_type="seig"
    ///   default_length=37, entry_count=1
    ///   entry: crypt_skip=0x00, reserved=0x00, is_protected=0x01, per_sample_iv_size=0x00
    ///   KID = 70B990CEB091313 8B2959F53280149 98
    ///   constant_iv_size=16, constant_iv = 1F2DCCFCC9E936F57E63A723DD470A7D
    const SGPD_SEIG_BOX: &[u8] = &[
        0x00, 0x00, 0x00, 0x3D, 0x73, 0x67, 0x70, 0x64, // box header: size=61, type="sgpd"
        0x01, 0x00, 0x00, 0x00, // version=1, flags=0
        0x73, 0x65, 0x69, 0x67, // grouping_type="seig"
        0x00, 0x00, 0x00, 0x25, // default_length=37
        0x00, 0x00, 0x00, 0x01, // entry_count=1
        // entry (37 bytes):
        0x00, 0x00, 0x01, 0x00, // crypt_skip, reserved, is_protected=1, per_sample_iv_size=0
        0x70, 0xB9, 0x90, 0xCE, 0xB0, 0x91, 0x31, 0x38, // KID (16 bytes)
        0xB2, 0x95, 0x9F, 0x53, 0x28, 0x01, 0x49, 0x98, 0x10, // constant_iv_size=16
        0x1F, 0x2D, 0xCC, 0xFC, 0xC9, 0xE9, 0x36, 0xF5, // constant_iv (16 bytes)
        0x7E, 0x63, 0xA7, 0x23, 0xDD, 0x47, 0x0A, 0x7D,
    ];

    #[test]
    fn test_parse_sgpd_seig() {
        // Strip the 8-byte box header; parse_sgpd_seig takes the payload only.
        let payload = &SGPD_SEIG_BOX[8..];
        let entries = parse_sgpd_seig(payload).unwrap().unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(e.is_protected);
        assert_eq!(e.per_sample_iv_size, 0);
        assert_eq!(
            e.kid,
            [
                0x70, 0xB9, 0x90, 0xCE, 0xB0, 0x91, 0x31, 0x38, 0xB2, 0x95, 0x9F, 0x53, 0x28, 0x01,
                0x49, 0x98,
            ]
        );
        assert_eq!(
            e.constant_iv,
            Some([
                0x1F, 0x2D, 0xCC, 0xFC, 0xC9, 0xE9, 0x36, 0xF5, 0x7E, 0x63, 0xA7, 0x23, 0xDD, 0x47,
                0x0A, 0x7D,
            ])
        );
    }

    #[test]
    fn test_parse_sgpd_seig_wrong_grouping_type() {
        let mut payload = SGPD_SEIG_BOX[8..].to_vec();
        // Replace "seig" with "maif" at offset 4 of the payload (bytes 12-15 of the box).
        payload[4..8].copy_from_slice(b"maif");
        assert!(parse_sgpd_seig(&payload).unwrap().is_none());
    }
}
