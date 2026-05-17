pub(crate) mod boxes;
mod fmp4;
mod non_fmp4;

use crate::errors::{CencError, Result};
use crate::jobs::boxes::{RawMp4Box, TrackEncryptionInfo};
use crate::types::ParsedCenc;
use shiguredo_mp4::BoxType;
use shiguredo_mp4::Decode;
use shiguredo_mp4::boxes::{MdatBox, MoofBox, MoovBox};

use crate::jobs::fmp4::parse_decrypt_jobs_fmp4;
use crate::jobs::non_fmp4::parse_decrypt_jobs_non_fmp4;

struct Mp4Context<'a> {
    input: &'a [u8],
    top_boxes: Vec<RawMp4Box>,
}

impl<'a> Mp4Context<'a> {
    fn parse(input: &'a [u8]) -> Result<Self> {
        let top_boxes = RawMp4Box::parse_all(input, 0)?;
        Ok(Self { input, top_boxes })
    }

    fn has_box(&self, box_type: BoxType) -> bool {
        self.top_boxes
            .iter()
            .any(|box_item| box_item.box_type == box_type)
    }

    fn moov(&self) -> Result<Option<MoovBox>> {
        let Some(raw_moov) = self
            .top_boxes
            .iter()
            .find(|box_item| box_item.box_type == MoovBox::TYPE)
        else {
            return Ok(None);
        };
        let (moov, _) =
            MoovBox::decode(&self.input[raw_moov.start..raw_moov.start + raw_moov.size])?;
        Ok(Some(moov))
    }
}

struct TrackEncryptionMap(Vec<(u32, Vec<Option<TrackEncryptionInfo>>)>);

impl TrackEncryptionMap {
    fn from_moov(moov: &MoovBox) -> Result<Self> {
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
        Ok(Self(track_map))
    }

    fn has_protected_track(&self) -> bool {
        self.0.iter().any(|(_, infos)| {
            infos
                .iter()
                .any(|info| info.as_ref().is_some_and(|info| info.is_protected))
        })
    }

    fn into_inner(self) -> Vec<(u32, Vec<Option<TrackEncryptionInfo>>)> {
        self.0
    }
}

impl ParsedCenc {
    /// Parse CENC encryption metadata from an MP4 buffer.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let context = Mp4Context::parse(input)?;
        let moov = context.moov()?;

        if context.has_box(MoofBox::TYPE) {
            let moov = moov.ok_or(CencError::MissingInitialSegment)?;
            return parse_decrypt_jobs_fmp4(input, &moov);
        }

        let moov = moov.ok_or(CencError::MissingMoov)?;

        // Init segment: moov only, no mdat and no moof.
        if !context.has_box(MdatBox::TYPE) {
            return Ok(ParsedCenc { jobs: vec![] });
        }

        parse_decrypt_jobs_non_fmp4(&moov)
    }

    /// Parse CENC encryption metadata from a media segment, using a separate
    /// initialization segment that contains the moov box.
    pub fn parse_with_init(input: &[u8], initial_segment: &[u8]) -> Result<Self> {
        let init_context = Mp4Context::parse(initial_segment)?;
        let moov = init_context
            .moov()?
            .ok_or(CencError::InitialSegmentMissingMoov)?;
        if !TrackEncryptionMap::from_moov(&moov)?.has_protected_track() {
            return Err(CencError::InitialSegmentMissingEncryptionInfo);
        }

        parse_decrypt_jobs_fmp4(input, &moov)
    }
}

pub(crate) fn get_track_map(
    moov: &MoovBox,
) -> Result<Vec<(u32, Vec<Option<TrackEncryptionInfo>>)>> {
    Ok(TrackEncryptionMap::from_moov(moov)?.into_inner())
}
