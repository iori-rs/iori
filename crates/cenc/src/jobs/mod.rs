pub(crate) mod boxes;
mod fmp4;
mod non_fmp4;

use crate::errors::{CencError, Result};
use crate::jobs::boxes::{RawMp4Box, TrackEncryptionInfo};
use crate::types::ParsedCenc;
use shiguredo_mp4::Decode;
use shiguredo_mp4::boxes::MoovBox;

use crate::jobs::fmp4::parse_decrypt_jobs_fmp4;
use crate::jobs::non_fmp4::parse_decrypt_jobs_non_fmp4;

impl ParsedCenc {
    /// Parse CENC encryption metadata from an MP4 buffer.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let top_boxes = RawMp4Box::parse_all(input, 0)?;
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
        if !has_mdat {
            return Ok(ParsedCenc { jobs: vec![] });
        }

        parse_decrypt_jobs_non_fmp4(&moov)
    }

    /// Parse CENC encryption metadata from a media segment, using a separate
    /// initialization segment that contains the moov box.
    pub fn parse_with_init(input: &[u8], initial_segment: &[u8]) -> Result<Self> {
        let init_boxes = RawMp4Box::parse_all(initial_segment, 0)?;
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
}

fn parse_moov_box(input: &[u8], boxes: &[RawMp4Box]) -> Result<Option<MoovBox>> {
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
        let entry_infos = TrackEncryptionInfo::from_sample_entries(
            &trak.mdia_box.minf_box.stbl_box.stsd_box.entries,
        )?;
        if entry_infos.iter().any(|info| info.is_some()) {
            track_map.push((track_id, entry_infos));
        }
    }
    Ok(track_map)
}
