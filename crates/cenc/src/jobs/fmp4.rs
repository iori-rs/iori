use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    BOX_SENC, TrackEncryptionInfo, parse_mp4_boxes, parse_sai_entries, parse_saio, parse_saiz,
    parse_senc,
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

            let senc_box = find_unknown_box(&traf.unknown_boxes, BOX_SENC)
                .or_else(|| find_unknown_box(&moof.unknown_boxes, BOX_SENC));
            let entries = if let Some(senc) = senc_box {
                parse_senc(&senc.payload, info.iv_size, info.constant_iv)?
            } else {
                let saiz = find_unknown_box(&traf.unknown_boxes, *b"saiz")
                    .or_else(|| find_unknown_box(&moof.unknown_boxes, *b"saiz"))
                    .ok_or(CencError::MissingSenc)?;
                let saio = find_unknown_box(&traf.unknown_boxes, *b"saio")
                    .or_else(|| find_unknown_box(&moof.unknown_boxes, *b"saio"))
                    .ok_or(CencError::MissingSenc)?;
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
