use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    BOX_MOOF, BOX_SAIO, BOX_SAIZ, BOX_SENC, BOX_TFHD, BOX_TRUN, TrackEncryptionInfo, find_mp4_box,
    parse_moof_box, parse_mp4_boxes, parse_sai_entries, parse_saio, parse_saiz, parse_senc,
    read_full_box_header, read_i32, read_u32, read_u64,
};
use crate::jobs::get_track_map;
use crate::types::{DecryptJob, ParsedCenc, SchemeType};
use shiguredo_mp4::boxes::MoovBox;
use std::collections::HashMap;

pub(crate) fn parse_decrypt_jobs_fmp4(input: &[u8], moov: &MoovBox) -> Result<ParsedCenc> {
    let track_map = get_track_map(moov)?;
    let mut track_lookup: HashMap<u32, Vec<Option<TrackEncryptionInfo>>> = HashMap::new();
    for (track_id, infos) in track_map {
        track_lookup.insert(track_id, infos);
    }

    let top_boxes = parse_mp4_boxes(input, 0)?;
    let mut jobs = Vec::new();

    for moof in top_boxes.iter().filter(|b| b.box_type == BOX_MOOF) {
        let moof_box = parse_moof_box(moof)?;
        for traf in &moof_box.traf_boxes {
            let traf_children = parse_mp4_boxes(traf.payload, traf.payload_start)?;
            let tfhd = find_mp4_box(&traf_children, BOX_TFHD);
            let Some(tfhd) = tfhd else {
                continue;
            };
            let tfhd_info = parse_tfhd(tfhd.payload)?;
            let Some(entry_infos) = track_lookup.get(&tfhd_info.track_id) else {
                continue;
            };
            let sample_description_index = tfhd_info.sample_description_index.unwrap_or(1);
            let entry_index = sample_description_index as usize - 1;
            let Some(info) = entry_infos.get(entry_index).and_then(|info| info.as_ref()) else {
                continue;
            };
            if !info.is_protected {
                continue;
            }

            let mut sample_offsets = Vec::new();
            let mut sample_sizes = Vec::new();
            for trun in traf_children.iter().filter(|b| b.box_type == BOX_TRUN) {
                let trun_info = parse_trun(trun.payload, tfhd_info.default_sample_size)?;
                let base_offset = if let Some(offset) = trun_info.data_offset {
                    let offset = i64::from(offset);
                    if offset < 0 {
                        return Err(CencError::OutOfBounds);
                    }
                    moof_box.start as u64 + offset as u64
                } else if let Some(base) = tfhd_info.base_data_offset {
                    base
                } else {
                    moof_box.start as u64 + moof_box.size as u64
                };
                let mut current = base_offset;
                for size in &trun_info.sample_sizes {
                    sample_offsets.push(current);
                    sample_sizes.push(*size);
                    current += *size as u64;
                }
            }

            if sample_sizes.is_empty() {
                continue;
            }

            let senc_box = find_mp4_box(&traf_children, BOX_SENC)
                .or_else(|| find_mp4_box(&moof_box.unknown_boxes, BOX_SENC));
            let entries = if let Some(senc) = senc_box {
                parse_senc(senc.payload, info.iv_size, info.constant_iv)?
            } else {
                let saiz = find_mp4_box(&traf_children, BOX_SAIZ)
                    .or_else(|| find_mp4_box(&moof_box.unknown_boxes, BOX_SAIZ))
                    .ok_or(CencError::MissingSenc)?;
                let saio = find_mp4_box(&traf_children, BOX_SAIO)
                    .or_else(|| find_mp4_box(&moof_box.unknown_boxes, BOX_SAIO))
                    .ok_or(CencError::MissingSenc)?;
                let sizes = parse_saiz(saiz.payload)?;
                let offsets = parse_saio(saio.payload)?;
                if offsets.is_empty() {
                    return Err(CencError::MissingSenc);
                }
                if sizes.len() != sample_sizes.len() {
                    return Err(CencError::SampleCountMismatch {
                        expected: sample_sizes.len() as u32,
                        actual: sizes.len() as u32,
                    });
                }
                let aux_offset = moof_box.start + offsets[0] as usize;
                if aux_offset >= input.len() {
                    return Err(CencError::OutOfBounds);
                }
                parse_sai_entries(&input[aux_offset..], &sizes, info.iv_size, info.constant_iv)?
            };

            if entries.len() != sample_sizes.len() {
                return Err(CencError::SampleCountMismatch {
                    expected: sample_sizes.len() as u32,
                    actual: entries.len() as u32,
                });
            }

            let pattern = match info.scheme {
                SchemeType::Cens | SchemeType::Cbcs => info.pattern,
                SchemeType::Cenc | SchemeType::Cbc1 => None,
            };
            for ((offset, size), entry) in sample_offsets
                .into_iter()
                .zip(sample_sizes.into_iter())
                .zip(entries.into_iter())
            {
                jobs.push(DecryptJob {
                    offset,
                    size,
                    iv: entry.iv,
                    subsamples: entry.subsamples,
                    scheme: info.scheme,
                    pattern,
                    kid: info.kid,
                });
            }
        }
    }

    if jobs.is_empty() {
        return Err(CencError::FragmentedMp4Unsupported);
    }

    Ok(ParsedCenc { jobs })
}

#[derive(Debug, Clone, Copy)]
struct TfhdInfo {
    track_id: u32,
    base_data_offset: Option<u64>,
    sample_description_index: Option<u32>,
    default_sample_size: Option<u32>,
}

#[derive(Debug, Clone)]
struct TrunInfo {
    data_offset: Option<i32>,
    sample_sizes: Vec<u32>,
}

fn parse_tfhd(payload: &[u8]) -> Result<TfhdInfo> {
    let (version, flags, mut offset) = read_full_box_header(payload)?;
    if version != 0 {
        return Err(CencError::InvalidSenc(
            "unsupported tfhd version".to_string(),
        ));
    }
    let track_id = read_u32(payload, &mut offset)?;
    let base_data_offset = if flags & 0x000001 != 0 {
        let value = read_u64(payload, &mut offset)?;
        Some(value)
    } else {
        None
    };
    let sample_description_index = if flags & 0x000002 != 0 {
        Some(read_u32(payload, &mut offset)?)
    } else {
        None
    };
    if flags & 0x000008 != 0 {
        let _ = read_u32(payload, &mut offset)?;
    }
    let default_sample_size = if flags & 0x000010 != 0 {
        Some(read_u32(payload, &mut offset)?)
    } else {
        None
    };
    Ok(TfhdInfo {
        track_id,
        base_data_offset,
        sample_description_index,
        default_sample_size,
    })
}

fn parse_trun(payload: &[u8], default_sample_size: Option<u32>) -> Result<TrunInfo> {
    let (version, flags, mut offset) = read_full_box_header(payload)?;
    if version > 1 {
        return Err(CencError::InvalidSenc(
            "unsupported trun version".to_string(),
        ));
    }
    let sample_count = read_u32(payload, &mut offset)? as usize;
    let data_offset = if flags & 0x000001 != 0 {
        Some(read_i32(payload, &mut offset)?)
    } else {
        None
    };
    if flags & 0x000004 != 0 {
        let _ = read_u32(payload, &mut offset)?;
    }
    let has_duration = flags & 0x000100 != 0;
    let has_size = flags & 0x000200 != 0;
    let has_flags = flags & 0x000400 != 0;
    let has_cto = flags & 0x000800 != 0;
    let mut sample_sizes = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        if has_duration {
            let _ = read_u32(payload, &mut offset)?;
        }
        if has_size {
            sample_sizes.push(read_u32(payload, &mut offset)?);
        } else {
            let size = default_sample_size
                .ok_or_else(|| CencError::InvalidSenc("missing default sample size".to_string()))?;
            sample_sizes.push(size);
        }
        if has_flags {
            let _ = read_u32(payload, &mut offset)?;
        }
        if has_cto {
            if version == 0 {
                let _ = read_u32(payload, &mut offset)?;
            } else {
                let _ = read_i32(payload, &mut offset)?;
            }
        }
    }
    Ok(TrunInfo {
        data_offset,
        sample_sizes,
    })
}
