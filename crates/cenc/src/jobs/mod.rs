mod boxes;
mod fmp4;
mod non_fmp4;

use crate::errors::{CencError, Result};
use crate::jobs::boxes::{TrackEncryptionInfo, build_entry_encryption_info, parse_mp4_boxes};
use crate::types::{KeyMap, ParsedCenc};
use shiguredo_mp4::Decode;
use shiguredo_mp4::boxes::MoovBox;
use std::collections::HashMap;

use crate::jobs::fmp4::parse_decrypt_jobs_fmp4;
use crate::jobs::non_fmp4::parse_decrypt_jobs_non_fmp4;

pub fn parse_decrypt_jobs(input: &[u8]) -> Result<ParsedCenc> {
    let top_boxes = parse_mp4_boxes(input, 0)?;
    let has_moof = top_boxes
        .iter()
        .any(|box_item| box_item.box_type == *b"moof");
    let has_mdat = top_boxes
        .iter()
        .any(|box_item| box_item.box_type == *b"mdat");
    let moov = parse_moov_box(input, &top_boxes)?;

    if has_moof {
        let moov = moov.ok_or(CencError::MissingInitialSegment)?;
        return parse_decrypt_jobs_fmp4(input, &moov);
    }

    let moov = moov.ok_or(CencError::MissingMoov)?;

    // Init segment: moov only, no mdat and no moof.
    // Nothing to decrypt; normalize_decrypted_fmp4 (called by decrypt_in_place) will
    // rewrite the sample-entry metadata (encv/enca → original codec type, etc.).
    if !has_mdat {
        return Ok(ParsedCenc { jobs: vec![] });
    }

    parse_decrypt_jobs_non_fmp4(&moov)
}

pub fn parse_decrypt_jobs_with_initial_segment(
    input: &[u8],
    initial_segment: &[u8],
) -> Result<ParsedCenc> {
    let init_boxes = parse_mp4_boxes(initial_segment, 0)?;
    let moov = parse_moov_box(initial_segment, &init_boxes)?
        .ok_or(CencError::InitialSegmentMissingMoov)?;
    let track_map = get_track_map(&moov)?;
    if !track_map.iter().any(|(_, infos)| {
        infos
            .iter()
            .any(|info| info.as_ref().is_some_and(|info| info.is_protected))
    }) {
        return Err(CencError::InitialSegmentMissingEncryptionInfo);
    }

    parse_decrypt_jobs_fmp4(input, &moov)
}

fn parse_moov_box(
    input: &[u8],
    boxes: &[crate::jobs::boxes::RawMp4Box],
) -> Result<Option<MoovBox>> {
    let Some(raw_moov) = boxes.iter().find(|box_item| box_item.box_type == *b"moov") else {
        return Ok(None);
    };
    let (moov, _) = MoovBox::decode(&input[raw_moov.start..raw_moov.start + raw_moov.size])?;
    Ok(Some(moov))
}

pub(crate) fn get_track_map(
    moov: &MoovBox,
) -> Result<Vec<(u32, Vec<Option<TrackEncryptionInfo>>)>> {
    let mut track_map = Vec::new();
    for trak in &moov.trak_boxes {
        let track_id = trak.tkhd_box.track_id;
        let entry_infos =
            build_entry_encryption_info(&trak.mdia_box.minf_box.stbl_box.stsd_box.entries)?;
        if entry_infos.iter().any(|info| info.is_some()) {
            track_map.push((track_id, entry_infos));
        }
    }
    Ok(track_map)
}

pub(crate) fn parse_key_map(keys: &HashMap<String, String>) -> Result<KeyMap> {
    let mut map = HashMap::new();
    for (kid, key) in keys {
        let kid_bytes = parse_hex_16(kid)?;
        let key_bytes = parse_hex_16(key)?;
        map.insert(kid_bytes, key_bytes);
    }
    Ok(map)
}

fn parse_hex_16(hex_str: &str) -> Result<[u8; 16]> {
    let cleaned = hex_str.replace('-', "");
    let bytes = hex::decode(&cleaned).map_err(|_| CencError::InvalidKeyHex(hex_str.to_string()))?;
    if bytes.len() != 16 {
        return Err(CencError::InvalidKeyLength(bytes.len()));
    }
    Ok(bytes.try_into().unwrap())
}
