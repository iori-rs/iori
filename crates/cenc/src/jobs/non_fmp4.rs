use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    SampleEncryptionBox, SbgpBox, SbgpEntry, SeigEntry, SgpdSeigBox, TrackEncryptionInfo,
    find_unknown_box, parse_first_matching_unknown_box,
};
use crate::types::{DecryptJob, ParsedCenc};
use shiguredo_mp4::aux::SampleTableAccessor;
use shiguredo_mp4::boxes::MoovBox;
use shiguredo_mp4::boxes::UnknownBox;

struct NonFragmentedSample {
    index: usize,
    entry_index: usize,
    offset: u64,
    size: u32,
}

struct NonFragmentedSampleGroups {
    sbgp: Vec<SbgpEntry>,
    sgpd: Vec<SeigEntry>,
}

impl NonFragmentedSampleGroups {
    fn parse_optional(boxes: &[UnknownBox]) -> Result<Option<Self>> {
        let Some(sbgp) =
            parse_first_matching_unknown_box(boxes.iter(), SbgpBox::TYPE, SbgpEntry::parse_seig)?
        else {
            return Ok(None);
        };
        let sgpd = parse_first_matching_unknown_box(
            boxes.iter(),
            SgpdSeigBox::TYPE,
            SeigEntry::parse_seig,
        )?
        .ok_or(CencError::MissingSenc)?;
        Ok(Some(Self { sbgp, sgpd }))
    }

    fn overrides(&self, sample_count: usize) -> Result<Vec<Option<SeigEntry>>> {
        let mut overrides = Vec::with_capacity(sample_count);
        let mut remaining = sample_count;
        for sbgp_entry in &self.sbgp {
            let count = (sbgp_entry.sample_count as usize).min(remaining);
            let override_entry = if sbgp_entry.group_description_index == 0 {
                None
            } else {
                let idx = sbgp_entry.description_index()?;
                Some(*self.sgpd.get(idx).ok_or_else(|| {
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
}

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
        let senc = find_unknown_box(stbl.unknown_boxes.iter(), SampleEncryptionBox::TYPE)
            .ok_or(CencError::MissingSenc)?;

        let sample_table = SampleTableAccessor::new(stbl)?;
        let expected = sample_table.sample_count();
        let samples = sample_table
            .samples()
            .map(|sample| NonFragmentedSample {
                index: sample.index().get() as usize - 1,
                entry_index: sample.chunk().sample_entry_index(),
                offset: sample.data_offset(),
                size: sample.data_size(),
            })
            .collect::<Vec<_>>();
        let sample_groups = NonFragmentedSampleGroups::parse_optional(&stbl.unknown_boxes)?;
        let group_overrides = sample_groups
            .as_ref()
            .map(|groups| groups.overrides(expected as usize))
            .transpose()?
            .unwrap_or_else(|| vec![None; expected as usize]);
        let iv_info = samples
            .iter()
            .map(|sample| {
                entry_infos
                    .get(sample.entry_index)
                    .and_then(|info| info.as_ref())
                    .map(|info| info.effective_iv_info(group_overrides[sample.index]))
                    .unwrap_or((0, None))
            })
            .collect::<Vec<_>>();
        let (track_iv_size, track_constant_iv) = entry_infos
            .iter()
            .filter_map(|info| info.as_ref())
            .map(|info| (info.iv_size, info.constant_iv))
            .next()
            .unwrap_or((0, None));
        let senc_info = SampleEncryptionBox::parse_senc_with_iv_info(
            &senc.payload,
            track_iv_size,
            track_constant_iv,
            Some(&iv_info),
        )?;
        if senc_info.overrides_to_clear_samples() {
            continue;
        }
        let senc_override_kid = senc_info.override_kid();
        let senc_entries = senc_info.entries;

        if senc_entries.len() as u32 != expected {
            return Err(CencError::SampleCountMismatch {
                expected,
                actual: senc_entries.len() as u32,
            });
        }

        for sample in samples {
            let Some(info) = entry_infos
                .get(sample.entry_index)
                .and_then(|info| info.as_ref())
            else {
                continue;
            };
            if !info.is_protected {
                continue;
            }
            let group_override = group_overrides[sample.index];
            if matches!(group_override, Some(entry) if !entry.is_protected) {
                continue;
            }

            let senc_entry = &senc_entries[sample.index];
            jobs.push(DecryptJob {
                track_id: Some(trak.tkhd_box.track_id),
                offset: sample.offset,
                size: sample.size,
                iv: info.effective_iv(group_override, senc_entry.iv),
                subsamples: senc_entry.subsamples.clone(),
                scheme: info.scheme,
                pattern: info.effective_pattern(group_override),
                kid: info.effective_kid(group_override, senc_override_kid),
            });
        }
    }

    Ok(ParsedCenc { jobs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CbcPattern;

    #[test]
    fn seig_overrides_keep_sample_positions() {
        let groups = NonFragmentedSampleGroups {
            sbgp: vec![
                SbgpEntry {
                    sample_count: 1,
                    group_description_index: 1,
                },
                SbgpEntry {
                    sample_count: 1,
                    group_description_index: 0,
                },
            ],
            sgpd: vec![SeigEntry {
                pattern: Some(CbcPattern {
                    crypt_byte_block: 1,
                    skip_byte_block: 9,
                }),
                is_protected: false,
                per_sample_iv_size: 0,
                kid: [0; 16],
                constant_iv: None,
            }],
        };

        let overrides = groups.overrides(3).unwrap();

        assert!(matches!(overrides[0], Some(entry) if !entry.is_protected));
        assert!(overrides[1].is_none());
        assert!(overrides[2].is_none());
    }
}
