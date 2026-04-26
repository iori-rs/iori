use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    BOX_SBGP, BOX_SENC, BOX_SGPD, SampleEncryptionEntry, SeigEntry, TrackEncryptionInfo,
    parse_mp4_boxes, parse_sai_entries, parse_saio, parse_saiz, parse_sbgp_seig, parse_senc,
    parse_sgpd_seig,
};
use crate::jobs::get_track_map;
use crate::types::{DecryptJob, ParsedCenc, SchemeType};
use shiguredo_mp4::boxes::{MoofBox, MoovBox, UnknownBox};
use shiguredo_mp4::{BoxType, Decode};
use std::collections::HashMap;

fn find_unknown_box(boxes: &[UnknownBox], box_type: [u8; 4]) -> Option<&UnknownBox> {
    boxes
        .iter()
        .find(|b| b.box_type == BoxType::Normal(box_type))
}

/// Build per-sample encryption entries from sbgp/sgpd seig boxes.
///
/// Used when `senc.sample_count == 0`: the constant IV per sample is stored in the
/// SGPD seig group entry that each sample is mapped to via SBGP.
fn build_sample_group_entries(
    traf_unknown: &[UnknownBox],
    moof_unknown: &[UnknownBox],
    sample_count: usize,
    track_info: &TrackEncryptionInfo,
) -> Result<Vec<SampleEncryptionEntry>> {
    let sbgp = traf_unknown
        .iter()
        .chain(moof_unknown.iter())
        .filter(|b| b.box_type == BoxType::Normal(BOX_SBGP))
        .find_map(|b| parse_sbgp_seig(&b.payload).ok().flatten())
        .ok_or(CencError::MissingSenc)?;

    let sgpd = traf_unknown
        .iter()
        .chain(moof_unknown.iter())
        .filter(|b| b.box_type == BoxType::Normal(BOX_SGPD))
        .find_map(|b| parse_sgpd_seig(&b.payload).ok().flatten())
        .ok_or(CencError::MissingSenc)?;

    let mut entries = Vec::with_capacity(sample_count);
    let mut remaining = sample_count;

    for sbgp_entry in &sbgp {
        let count = (sbgp_entry.sample_count as usize).min(remaining);
        for _ in 0..count {
            let iv = if sbgp_entry.group_description_index == 0 {
                // Not mapped to any group — use track-level constant IV.
                track_info.constant_iv.ok_or_else(|| {
                    CencError::InvalidSenc(
                        "sbgp group_description_index=0 but no track-level constant IV".to_string(),
                    )
                })?
            } else {
                // ISO 14496-12 §8.9.2: group_description_index >= 0x10001 means a
                // fragment-local SGPD reference; the 1-based entry index is in the
                // lower 16 bits.  Values 1–0x10000 are moov-level (also 1-based).
                // Both cases result in a 0-based index into the SGPD we already found.
                let raw = sbgp_entry.group_description_index;
                let one_based = if raw >= 0x10001 { raw & 0xFFFF } else { raw } as usize;
                let idx = one_based.checked_sub(1).ok_or_else(|| {
                    CencError::InvalidSenc(
                        "sbgp group_description_index fragment-local underflow".to_string(),
                    )
                })?;
                let seig = sgpd.get(idx).ok_or_else(|| {
                    CencError::InvalidSenc("invalid sbgp group_description_index".to_string())
                })?;
                if !seig.is_protected {
                    // Sample group marks this run as clear — skip it entirely.
                    continue;
                }
                seig.constant_iv.ok_or_else(|| {
                    CencError::InvalidSenc(
                        "sgpd seig entry has no constant IV (per_sample_iv_size != 0)".to_string(),
                    )
                })?
            };
            entries.push(SampleEncryptionEntry {
                iv,
                subsamples: Vec::new(),
            });
        }
        remaining -= count;
        if remaining == 0 {
            break;
        }
    }

    Ok(entries)
}

fn sample_group_overrides(
    traf_unknown: &[UnknownBox],
    moof_unknown: &[UnknownBox],
    sample_count: usize,
) -> Result<Vec<Option<SeigEntry>>> {
    let Some(sbgp) = traf_unknown
        .iter()
        .chain(moof_unknown.iter())
        .filter(|b| b.box_type == BoxType::Normal(BOX_SBGP))
        .find_map(|b| parse_sbgp_seig(&b.payload).ok().flatten())
    else {
        return Ok(vec![None; sample_count]);
    };

    let sgpd = traf_unknown
        .iter()
        .chain(moof_unknown.iter())
        .filter(|b| b.box_type == BoxType::Normal(BOX_SGPD))
        .find_map(|b| parse_sgpd_seig(&b.payload).ok().flatten())
        .ok_or(CencError::MissingSenc)?;

    let mut overrides = Vec::with_capacity(sample_count);
    let mut remaining = sample_count;
    for sbgp_entry in &sbgp {
        let count = (sbgp_entry.sample_count as usize).min(remaining);
        let override_entry = if sbgp_entry.group_description_index == 0 {
            None
        } else {
            let raw = sbgp_entry.group_description_index;
            let one_based = if raw >= 0x10001 { raw & 0xFFFF } else { raw } as usize;
            let idx = one_based.checked_sub(1).ok_or_else(|| {
                CencError::InvalidSenc(
                    "sbgp group_description_index fragment-local underflow".to_string(),
                )
            })?;
            Some(*sgpd.get(idx).ok_or_else(|| {
                CencError::InvalidSenc("invalid sbgp group_description_index".to_string())
            })?)
        };
        overrides.extend(std::iter::repeat_n(override_entry, count));
        remaining -= count;
        if remaining == 0 {
            break;
        }
    }
    overrides.resize(sample_count, None);
    Ok(overrides)
}

pub(crate) fn parse_decrypt_jobs_fmp4(input: &[u8], moov: &MoovBox) -> Result<ParsedCenc> {
    let track_map = get_track_map(moov)?;
    let mut track_lookup: HashMap<u32, Vec<Option<TrackEncryptionInfo>>> = HashMap::new();
    for (track_id, infos) in track_map {
        track_lookup.insert(track_id, infos);
    }

    let top_boxes = parse_mp4_boxes(input, 0)?;
    let mut jobs = Vec::new();

    for raw_moof in top_boxes.iter().filter(|b| b.box_type == *b"moof") {
        let (moof, _) = MoofBox::decode(&input[raw_moof.start..raw_moof.start + raw_moof.size])?;
        let moof_start = raw_moof.start;
        let moof_size = raw_moof.size;

        for traf in &moof.traf_boxes {
            let tfhd = &traf.tfhd_box;
            let Some(entry_infos) = track_lookup.get(&tfhd.track_id) else {
                continue;
            };
            let sample_description_index = tfhd.sample_description_index.unwrap_or(1);
            let entry_index = sample_description_index as usize - 1;
            let Some(info) = entry_infos.get(entry_index).and_then(|info| info.as_ref()) else {
                continue;
            };
            if !info.is_protected {
                continue;
            }

            let mut sample_offsets = Vec::new();
            let mut sample_sizes = Vec::new();
            for trun in &traf.trun_boxes {
                let base_offset = if let Some(data_offset) = trun.data_offset {
                    let offset = data_offset as i64;
                    if offset < 0 {
                        return Err(CencError::OutOfBounds);
                    }
                    moof_start as u64 + offset as u64
                } else if let Some(base) = tfhd.base_data_offset {
                    base
                } else {
                    moof_start as u64 + moof_size as u64
                };
                let mut current = base_offset;
                for sample in &trun.samples {
                    let size = sample
                        .size
                        .or(tfhd.default_sample_size)
                        .ok_or_else(|| CencError::InvalidSenc("missing sample size".to_string()))?;
                    sample_offsets.push(current);
                    sample_sizes.push(size);
                    current += size as u64;
                }
            }

            if sample_sizes.is_empty() {
                continue;
            }

            let group_overrides = sample_group_overrides(
                &traf.unknown_boxes,
                &moof.unknown_boxes,
                sample_sizes.len(),
            )?;

            let senc_box = find_unknown_box(&traf.unknown_boxes, BOX_SENC)
                .or_else(|| find_unknown_box(&moof.unknown_boxes, BOX_SENC));
            let entries = 'entries: {
                // Prefer senc when it has sample entries.
                if let Some(senc) = senc_box {
                    let parsed = parse_senc(&senc.payload, info.iv_size, info.constant_iv)?;
                    if !parsed.is_empty() {
                        break 'entries parsed;
                    }
                    // senc.sample_count == 0: fall through to sample group encryption.
                }

                // Try saiz/saio auxiliary info.
                let saiz = find_unknown_box(&traf.unknown_boxes, *b"saiz")
                    .or_else(|| find_unknown_box(&moof.unknown_boxes, *b"saiz"));
                let saio = find_unknown_box(&traf.unknown_boxes, *b"saio")
                    .or_else(|| find_unknown_box(&moof.unknown_boxes, *b"saio"));
                if let (Some(saiz), Some(saio)) = (saiz, saio) {
                    let sizes = parse_saiz(&saiz.payload)?;
                    let offsets = parse_saio(&saio.payload)?;
                    if offsets.is_empty() {
                        return Err(CencError::MissingSenc);
                    }
                    if sizes.len() != sample_sizes.len() {
                        return Err(CencError::SampleCountMismatch {
                            expected: sample_sizes.len() as u32,
                            actual: sizes.len() as u32,
                        });
                    }
                    let aux_offset = moof_start + offsets[0] as usize;
                    if aux_offset >= input.len() {
                        return Err(CencError::OutOfBounds);
                    }
                    break 'entries parse_sai_entries(
                        &input[aux_offset..],
                        &sizes,
                        info.iv_size,
                        info.constant_iv,
                    )?;
                }

                // Fall back to cbcs sample group encryption (sbgp/sgpd seig).
                build_sample_group_entries(
                    &traf.unknown_boxes,
                    &moof.unknown_boxes,
                    sample_sizes.len(),
                    info,
                )?
            };

            if entries.len() != sample_sizes.len() {
                return Err(CencError::SampleCountMismatch {
                    expected: sample_sizes.len() as u32,
                    actual: entries.len() as u32,
                });
            }

            for (((offset, size), entry), group_override) in sample_offsets
                .into_iter()
                .zip(sample_sizes.into_iter())
                .zip(entries.into_iter())
                .zip(group_overrides.into_iter())
            {
                if matches!(group_override, Some(group) if !group.is_protected) {
                    continue;
                }
                let pattern = match info.scheme {
                    SchemeType::Cens | SchemeType::Cbcs => group_override
                        .and_then(|group| group.pattern)
                        .or(info.pattern),
                    SchemeType::Cenc | SchemeType::Cbc1 => None,
                };
                let kid = group_override.map(|group| group.kid).unwrap_or(info.kid);
                let iv = group_override
                    .and_then(|group| group.constant_iv)
                    .unwrap_or(entry.iv);
                jobs.push(DecryptJob {
                    offset,
                    size,
                    iv,
                    subsamples: entry.subsamples,
                    scheme: info.scheme,
                    pattern,
                    kid,
                });
            }
        }
    }

    Ok(ParsedCenc { jobs })
}
