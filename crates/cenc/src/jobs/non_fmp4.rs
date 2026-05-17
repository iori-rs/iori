use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    BOX_SENC, SampleEncryptionBox, TrackEncryptionInfo, is_seig_grouping_box,
};
use crate::types::{DecryptJob, ParsedCenc};
use shiguredo_mp4::BoxType;
use shiguredo_mp4::aux::SampleTableAccessor;
use shiguredo_mp4::boxes::MoovBox;

/// Parse CENC decrypt jobs from a non-fragmented MP4 `moov`.
///
/// Non-fragmented files keep sample layout in the regular sample tables. The
/// `stbl`-level `senc` box contributes IV/subsample data in sample order, so
/// its entry count must match the sample table count.
pub(crate) fn parse_decrypt_jobs_non_fmp4(moov: &MoovBox) -> Result<ParsedCenc> {
    let mut jobs = Vec::new();
    for trak in &moov.trak_boxes {
        let stbl = &trak.mdia_box.minf_box.stbl_box;
        let entry_infos = TrackEncryptionInfo::from_sample_entries(&stbl.stsd_box.entries)?;
        if !entry_infos.iter().any(|info| info.is_some()) {
            continue;
        }
        if stbl.unknown_boxes.iter().any(is_seig_grouping_box) {
            return Err(CencError::UnsupportedSampleGroups);
        }
        let senc = stbl
            .unknown_boxes
            .iter()
            .find(|b| matches!(b.box_type, BoxType::Normal(BOX_SENC)))
            .ok_or(CencError::MissingSenc)?;

        let sample_table = SampleTableAccessor::new(stbl)?;
        let track_iv_size = entry_infos
            .iter()
            .filter_map(|info| info.as_ref().map(|info| info.iv_size))
            .next()
            .unwrap_or(0);
        let track_constant_iv = entry_infos
            .iter()
            .filter_map(|info| info.as_ref().and_then(|info| info.constant_iv))
            .next();
        let senc_info =
            SampleEncryptionBox::parse_senc(&senc.payload, track_iv_size, track_constant_iv)?;
        if senc_info.overrides_to_clear_samples() {
            continue;
        }
        let senc_override_kid = senc_info.override_kid();
        let senc_entries = senc_info.entries;

        let expected = sample_table.sample_count();
        if senc_entries.len() as u32 != expected {
            return Err(CencError::SampleCountMismatch {
                expected,
                actual: senc_entries.len() as u32,
            });
        }

        for sample in sample_table.samples() {
            let index = sample.index().get() as usize - 1;
            let entry_index = sample.chunk().sample_entry_index();
            let Some(info) = entry_infos.get(entry_index).and_then(|info| info.as_ref()) else {
                continue;
            };
            if !info.is_protected {
                continue;
            }

            let senc_entry = &senc_entries[index];
            jobs.push(DecryptJob {
                offset: sample.data_offset(),
                size: sample.data_size(),
                iv: senc_entry.iv,
                subsamples: senc_entry.subsamples.clone(),
                scheme: info.scheme,
                pattern: info.effective_pattern(None),
                kid: info.effective_kid(None, senc_override_kid),
            });
        }
    }

    Ok(ParsedCenc { jobs })
}
