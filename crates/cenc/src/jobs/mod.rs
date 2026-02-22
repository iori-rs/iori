mod boxes;
mod fmp4;
mod non_fmp4;

use crate::errors::{CencError, Result};
use crate::jobs::boxes::{build_entry_encryption_info, TrackEncryptionInfo};
use crate::types::{KeyMap, ParsedCenc};
use shiguredo_mp4::{Decode, Mp4File};
use shiguredo_mp4::boxes::{MoovBox, RootBox};
use std::collections::HashMap;

use crate::jobs::fmp4::parse_decrypt_jobs_fmp4;
use crate::jobs::non_fmp4::parse_decrypt_jobs_non_fmp4;

pub fn parse_decrypt_jobs(input: &[u8]) -> Result<ParsedCenc> {
    let (mp4, _) = Mp4File::<RootBox>::decode(input)?;
    let has_moof = mp4.boxes.iter().any(|box_item| {
        matches!(box_item, RootBox::Moof(_))
    });

    let moov = mp4
        .boxes
        .iter()
        .find_map(|box_item| {
            if let RootBox::Moov(moov) = box_item {
                Some(moov)
            } else {
                None
            }
        })
        .ok_or(CencError::MissingMoov)?;

    if has_moof {
        return parse_decrypt_jobs_fmp4(input, moov);
    }

    parse_decrypt_jobs_non_fmp4(moov)
}

pub(crate) fn get_track_map(moov: &MoovBox) -> Result<Vec<(u32, Vec<Option<TrackEncryptionInfo>>)>> {
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
    let bytes =
        hex::decode(&cleaned).map_err(|_| CencError::InvalidKeyHex(hex_str.to_string()))?;
    if bytes.len() != 16 {
        return Err(CencError::InvalidKeyLength(bytes.len()));
    }
    Ok(bytes.try_into().unwrap())
}
