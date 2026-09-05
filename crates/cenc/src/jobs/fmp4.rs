use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    RawMp4Box, SampleEncryptionBox, SampleEncryptionEntry, SbgpBox, SbgpEntry, SeigEntry,
    SgpdSeigBox, TrackEncryptionInfo, find_unknown_box, parse_first_matching_unknown_box,
    resolve_seig_overrides, select_cenc_auxiliary,
};
use crate::types::{CbcPattern, DecryptJob, ParsedCenc};
use shiguredo_mp4::boxes::{MdatBox, MoofBox, MoovBox, UnknownBox};
use shiguredo_mp4::{BoxType, Decode};
use std::collections::HashMap;

struct UnknownBoxes<'a> {
    traf: &'a [UnknownBox],
    moof: &'a [UnknownBox],
}

impl<'a> UnknownBoxes<'a> {
    fn new(traf: &'a [UnknownBox], moof: &'a [UnknownBox]) -> Self {
        Self { traf, moof }
    }

    fn find(&self, box_type: BoxType) -> Option<&'a UnknownBox> {
        find_unknown_box(self.iter(), box_type)
    }

    fn parse_seig_sbgp(&self) -> Result<Option<Vec<SbgpEntry>>> {
        parse_first_matching_unknown_box(self.traf.iter(), SbgpBox::TYPE, SbgpEntry::parse_seig)
    }

    fn parse_seig_sgpd(&self) -> Result<Option<SgpdSeigBox>> {
        parse_first_matching_unknown_box(
            self.traf.iter(),
            SgpdSeigBox::TYPE,
            SgpdSeigBox::decode_payload,
        )
    }

    fn iter(&self) -> impl Iterator<Item = &'a UnknownBox> {
        self.traf.iter().chain(self.moof.iter())
    }
}

struct FragmentSamples {
    offsets: Vec<u64>,
    sizes: Vec<u32>,
    trun_sample_counts: Vec<usize>,
    end: u64,
}

impl FragmentSamples {
    fn collect(
        traf: &shiguredo_mp4::boxes::TrafBox,
        base_offset: u64,
        default_sample_size: Option<u32>,
    ) -> Result<Self> {
        let tfhd = &traf.tfhd_box;
        let mut offsets = Vec::new();
        let mut sizes = Vec::new();
        let mut trun_sample_counts = Vec::new();
        let mut current = base_offset;
        for trun in &traf.trun_boxes {
            trun_sample_counts.push(trun.samples.len());
            if let Some(data_offset) = trun.data_offset {
                current = base_offset
                    .checked_add_signed(i64::from(data_offset))
                    .ok_or(CencError::OutOfBounds)?;
            }
            for sample in &trun.samples {
                let size = sample
                    .size
                    .or(tfhd.default_sample_size)
                    .or(default_sample_size)
                    .ok_or_else(|| CencError::InvalidSenc("missing sample size".to_string()))?;
                offsets.push(current);
                sizes.push(size);
                current = current
                    .checked_add(u64::from(size))
                    .ok_or(CencError::OutOfBounds)?;
            }
        }
        Ok(Self {
            offsets,
            sizes,
            trun_sample_counts,
            end: current,
        })
    }

    fn is_empty(&self) -> bool {
        self.sizes.is_empty()
    }

    fn len(&self) -> usize {
        self.sizes.len()
    }

    fn trun_sample_counts(&self) -> &[usize] {
        &self.trun_sample_counts
    }

    fn into_iter(self) -> impl Iterator<Item = (u64, u32)> {
        self.offsets.into_iter().zip(self.sizes)
    }
}

enum GroupSampleEncryption {
    Clear,
    Encrypted(SampleEncryptionEntry),
}

fn constant_iv_samples(
    track: &TrackEncryptionInfo,
    groups: &[Option<SeigEntry>],
) -> Result<Vec<GroupSampleEncryption>> {
    groups
        .iter()
        .copied()
        .map(|group| {
            if !group.map_or(track.is_protected, |entry| entry.is_protected) {
                return Ok(GroupSampleEncryption::Clear);
            }
            let (iv_size, iv) = track.effective_iv_info(group);
            if iv_size != 0 {
                return Err(CencError::MissingSenc);
            }
            Ok(GroupSampleEncryption::Encrypted(SampleEncryptionEntry {
                iv: iv.ok_or(CencError::MissingSenc)?,
                subsamples: Vec::new(),
            }))
        })
        .collect()
}

#[derive(Debug, Clone)]
struct EffectiveSampleEncryption {
    kid: [u8; 16],
    iv: [u8; 16],
    pattern: Option<CbcPattern>,
}

impl EffectiveSampleEncryption {
    /// Resolve the effective encryption parameters for one media sample.
    ///
    /// Effective KID/IV precedence: sample-group overrides win, then `senc`
    /// track-encryption override KID, then track defaults. For IV, `seig`
    /// `constant_IV` overrides the per-sample IV.
    fn from_metadata(
        track: &TrackEncryptionInfo,
        group: Option<SeigEntry>,
        sample: &SampleEncryptionEntry,
        senc_override_kid: Option<[u8; 16]>,
        senc_overrides_to_clear: bool,
    ) -> Option<Self> {
        if senc_overrides_to_clear {
            return None;
        }
        if !group.map_or(track.is_protected, |entry| entry.is_protected) {
            return None;
        }
        Some(Self {
            kid: track.effective_kid(group, senc_override_kid),
            iv: track.effective_iv(group, sample.iv),
            pattern: track.effective_pattern(group),
        })
    }

    fn into_decrypt_job(
        self,
        track_id: u32,
        track: &TrackEncryptionInfo,
        sample: SampleEncryptionEntry,
        offset: u64,
        size: u32,
    ) -> DecryptJob {
        DecryptJob {
            track_id: Some(track_id),
            offset,
            size,
            iv: self.iv,
            subsamples: sample.subsamples,
            scheme: track.scheme,
            pattern: self.pattern,
            kid: self.kid,
        }
    }
}

fn parse_auxiliary_sample_entries(
    input: &[u8],
    base: usize,
    offsets: &[u64],
    sizes: &[u8],
    trun_sample_counts: &[usize],
    track_info: &TrackEncryptionInfo,
    group_overrides: &[Option<SeigEntry>],
) -> Option<Vec<SampleEncryptionEntry>> {
    if (offsets.len() != 1 && offsets.len() != trun_sample_counts.len())
        || offsets.is_empty()
        || sizes.len() != trun_sample_counts.iter().sum::<usize>()
    {
        return None;
    }
    if sizes.len() != group_overrides.len() {
        return None;
    }

    if offsets.len() == 1 {
        let aux_offset = checked_aux_offset(base, offsets[0], input.len())?;
        return parse_auxiliary_sample_entries_at(
            &input[aux_offset..],
            sizes,
            track_info,
            group_overrides,
        );
    }

    let mut entries = Vec::with_capacity(sizes.len());
    let mut size_offset = 0usize;
    for (trun_index, sample_count) in trun_sample_counts.iter().copied().enumerate() {
        if sample_count == 0 {
            continue;
        }
        let aux_offset = checked_aux_offset(base, *offsets.get(trun_index)?, input.len())?;
        let end = size_offset.checked_add(sample_count)?;
        let trun_sizes = sizes.get(size_offset..end)?;
        let trun_groups = group_overrides.get(size_offset..end)?;
        let mut trun_entries = parse_auxiliary_sample_entries_at(
            &input[aux_offset..],
            trun_sizes,
            track_info,
            trun_groups,
        )?;
        entries.append(&mut trun_entries);
        size_offset = end;
    }

    (entries.len() == sizes.len()).then_some(entries)
}

fn parse_auxiliary_sample_entries_at(
    data: &[u8],
    sizes: &[u8],
    track_info: &TrackEncryptionInfo,
    group_overrides: &[Option<SeigEntry>],
) -> Option<Vec<SampleEncryptionEntry>> {
    let mut entries = Vec::with_capacity(sizes.len());
    let mut offset = 0usize;
    for (size, group) in sizes.iter().copied().zip(group_overrides.iter().copied()) {
        let size = size as usize;
        let end = offset.checked_add(size)?;
        let entry_data = data.get(offset..end)?;
        let (iv_size, constant_iv) = track_info.effective_iv_info(group);
        let entry =
            SampleEncryptionEntry::parse_sai_entry(entry_data, iv_size, constant_iv).ok()?;
        entries.push(entry);
        offset = end;
    }
    Some(entries)
}

fn checked_aux_offset(input_base: usize, relative_offset: u64, input_len: usize) -> Option<usize> {
    let relative_offset = usize::try_from(relative_offset).ok()?;
    let offset = input_base.checked_add(relative_offset)?;
    (offset <= input_len).then_some(offset)
}

/// Parse CENC decrypt jobs from fragmented MP4 media.
///
/// Per-fragment encryption data is resolved like Bento4: auxiliary info
/// referenced by `saiz`/`saio` is tried first, invalid auxiliary layouts fall
/// back to `senc`. Effective track/group constant IVs need no auxiliary table.
pub(crate) fn parse_decrypt_jobs_fmp4(input: &[u8], moov: &MoovBox) -> Result<ParsedCenc> {
    let track_map = super::get_track_map(moov)?;
    let mut track_lookup: HashMap<u32, Vec<Option<TrackEncryptionInfo>>> = HashMap::new();
    for (track_id, infos) in track_map {
        track_lookup.insert(track_id, infos);
    }

    let top_boxes = RawMp4Box::parse_all(input, 0)?;
    let mut jobs = Vec::new();

    for raw_moof in top_boxes
        .iter()
        .filter(|box_item| box_item.is_type(MoofBox::TYPE))
    {
        let (moof, _) = MoofBox::decode(&input[raw_moof.start..raw_moof.end()])?;
        let moof_start = raw_moof.start;
        let mut preceding_traf_end = moof_start as u64;

        for traf in &moof.traf_boxes {
            let unknown_boxes = UnknownBoxes::new(&traf.unknown_boxes, &moof.unknown_boxes);
            let tfhd = &traf.tfhd_box;
            let trex = moov.mvex_box.as_ref().and_then(|mvex| {
                mvex.trex_boxes
                    .iter()
                    .find(|trex| trex.track_id == tfhd.track_id)
            });
            let base = tfhd.base_data_offset.unwrap_or({
                if tfhd.default_base_is_moof {
                    moof_start as u64
                } else {
                    preceding_traf_end
                }
            });
            let samples =
                FragmentSamples::collect(traf, base, trex.map(|trex| trex.default_sample_size))?;
            preceding_traf_end = samples.end;
            let Some(entry_infos) = track_lookup.get(&tfhd.track_id) else {
                continue;
            };
            let sample_description_index = tfhd
                .sample_description_index
                .or(trex.map(|trex| trex.default_sample_description_index))
                .unwrap_or(1);
            let entry_index = sample_description_index
                .checked_sub(1)
                .ok_or_else(|| CencError::InvalidSenc("sample description index is zero".into()))?
                as usize;
            let Some(info) = entry_infos.get(entry_index).and_then(|info| info.as_ref()) else {
                continue;
            };
            if samples.is_empty() {
                continue;
            }

            let sample_count = samples.len();
            let track = moov
                .trak_boxes
                .iter()
                .find(|track| track.tkhd_box.track_id == tfhd.track_id);
            let track_sgpd = track
                .map(|track| {
                    parse_first_matching_unknown_box(
                        track.mdia_box.minf_box.stbl_box.unknown_boxes.iter(),
                        SgpdSeigBox::TYPE,
                        SgpdSeigBox::decode_payload,
                    )
                })
                .transpose()?
                .flatten();
            let fragment_sgpd = unknown_boxes.parse_seig_sgpd()?;
            let sbgp = unknown_boxes.parse_seig_sbgp()?;
            let group_overrides = resolve_seig_overrides(
                sbgp.as_deref(),
                track_sgpd.as_ref(),
                fragment_sgpd.as_ref(),
                sample_count,
            )?;

            let senc_box = unknown_boxes.find(SampleEncryptionBox::TYPE);
            let (entries, senc_override_kid, senc_overrides_to_clear) = 'entries: {
                let auxiliary = select_cenc_auxiliary(unknown_boxes.iter());
                let has_auxiliary_metadata = !matches!(&auxiliary, Ok(None));
                if let Ok(Some((sizes, offsets))) = auxiliary
                    && let Some(entries) = parse_auxiliary_sample_entries(
                        input,
                        usize::try_from(base).map_err(|_| CencError::OutOfBounds)?,
                        &offsets,
                        &sizes,
                        samples.trun_sample_counts(),
                        info,
                        &group_overrides,
                    )
                {
                    debug_assert_eq!(entries.len(), sample_count);
                    let samples = entries
                        .into_iter()
                        .map(GroupSampleEncryption::Encrypted)
                        .collect();
                    break 'entries (samples, None, false);
                }

                if let Some(senc) = senc_box {
                    let iv_info = group_overrides
                        .iter()
                        .copied()
                        .map(|group| info.effective_iv_info(group))
                        .collect::<Vec<_>>();
                    let parsed = SampleEncryptionBox::parse_senc_with_iv_info(
                        &senc.payload,
                        info.iv_size,
                        info.constant_iv,
                        Some(&iv_info),
                    )?;
                    if !parsed.entries.is_empty() {
                        let override_kid = parsed.override_kid();
                        let overrides_to_clear = parsed.overrides_to_clear_samples();
                        let samples = parsed
                            .entries
                            .into_iter()
                            .map(GroupSampleEncryption::Encrypted)
                            .collect();
                        break 'entries (samples, override_kid, overrides_to_clear);
                    }
                }

                if has_auxiliary_metadata {
                    return Err(CencError::InvalidSenc(
                        "invalid or incomplete auxiliary encryption information".into(),
                    ));
                }
                (constant_iv_samples(info, &group_overrides)?, None, false)
            };

            if entries.len() != sample_count {
                return Err(CencError::SampleCountMismatch {
                    expected: sample_count as u32,
                    actual: entries.len() as u32,
                });
            }

            for (((offset, size), sample_encryption), group_override) in
                samples.into_iter().zip(entries).zip(group_overrides)
            {
                let GroupSampleEncryption::Encrypted(entry) = sample_encryption else {
                    continue;
                };
                let Some(effective) = EffectiveSampleEncryption::from_metadata(
                    info,
                    group_override,
                    &entry,
                    senc_override_kid,
                    senc_overrides_to_clear,
                ) else {
                    continue;
                };
                let end = offset
                    .checked_add(u64::from(size))
                    .ok_or(CencError::OutOfBounds)?;
                if !top_boxes.iter().any(|raw| {
                    raw.is_type(MdatBox::TYPE)
                        && offset >= (raw.start + raw.header_size) as u64
                        && end <= raw.end() as u64
                }) {
                    return Err(CencError::OutOfBounds);
                }
                jobs.push(effective.into_decrypt_job(tfhd.track_id, info, entry, offset, size));
            }
        }
    }

    Ok(ParsedCenc { jobs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SchemeType;

    fn track_with_iv_size(iv_size: u8) -> TrackEncryptionInfo {
        TrackEncryptionInfo {
            scheme: SchemeType::Cenc,
            kid: [1; 16],
            iv_size,
            constant_iv: None,
            pattern: None,
            is_protected: true,
        }
    }

    #[test]
    fn auxiliary_sample_entries_use_single_saio_offset_as_contiguous_table() {
        let mut input = vec![0u8; 80];
        input[20..28].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        input[28..36].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);

        let track = track_with_iv_size(8);
        let groups = vec![None, None];
        let entries =
            parse_auxiliary_sample_entries(&input, 10, &[10], &[8, 8], &[1, 1], &track, &groups)
                .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].iv,
            [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            entries[1].iv,
            [9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn auxiliary_sample_entries_use_one_saio_offset_per_trun_when_present() {
        let mut input = vec![0u8; 120];
        input[20..28].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        input[60..68].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
        input[68..76].copy_from_slice(&[17, 18, 19, 20, 21, 22, 23, 24]);

        let track = track_with_iv_size(8);
        let groups = vec![None, None, None];
        let entries = parse_auxiliary_sample_entries(
            &input,
            10,
            &[10, 50],
            &[8, 8, 8],
            &[1, 2],
            &track,
            &groups,
        )
        .unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0].iv,
            [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            entries[1].iv,
            [9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            entries[2].iv,
            [17, 18, 19, 20, 21, 22, 23, 24, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn auxiliary_sample_entries_use_seig_iv_size_overrides() {
        let mut input = vec![0u8; 80];
        input[20..28].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        input[28..44].copy_from_slice(&[
            9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        ]);
        let track = track_with_iv_size(16);
        let groups = vec![
            Some(SeigEntry {
                pattern: None,
                is_protected: true,
                per_sample_iv_size: 8,
                kid: [1; 16],
                constant_iv: None,
            }),
            None,
        ];

        let entries =
            parse_auxiliary_sample_entries(&input, 10, &[10], &[8, 16], &[2], &track, &groups)
                .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].iv,
            [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            entries[1].iv,
            [
                9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24
            ]
        );
    }

    #[test]
    fn effective_sample_encryption_skips_senc_algorithm_zero() {
        let track = TrackEncryptionInfo {
            scheme: SchemeType::Cenc,
            kid: [1; 16],
            iv_size: 8,
            constant_iv: None,
            pattern: None,
            is_protected: true,
        };
        let sample = SampleEncryptionEntry {
            iv: [2; 16],
            subsamples: Vec::new(),
        };

        let effective =
            EffectiveSampleEncryption::from_metadata(&track, None, &sample, Some([3; 16]), true);

        assert!(effective.is_none());
    }

    #[test]
    fn constant_iv_fallback_respects_clear_and_protected_defaults() {
        let mut track = track_with_iv_size(0);
        track.constant_iv = Some([7; 16]);
        assert!(matches!(
            constant_iv_samples(&track, &[None]).unwrap()[0],
            GroupSampleEncryption::Encrypted(_)
        ));
        track.is_protected = false;
        assert!(matches!(
            constant_iv_samples(&track, &[None]).unwrap()[0],
            GroupSampleEncryption::Clear
        ));
        let protected = SeigEntry {
            pattern: None,
            is_protected: true,
            per_sample_iv_size: 0,
            kid: [9; 16],
            constant_iv: Some([3; 16]),
        };
        let samples = constant_iv_samples(&track, &[None, Some(protected)]).unwrap();
        assert!(matches!(samples[0], GroupSampleEncryption::Clear));
        assert!(
            matches!(&samples[1], GroupSampleEncryption::Encrypted(entry) if entry.iv == [3; 16])
        );
    }
    fn sample_runs(offsets: &[Option<i32>], size: Option<u32>) -> shiguredo_mp4::boxes::TrafBox {
        use shiguredo_mp4::boxes::{TfhdBox, TrafBox, TrunBox, TrunSample};
        TrafBox {
            tfhd_box: TfhdBox {
                track_id: 1,
                base_data_offset: None,
                sample_description_index: None,
                default_sample_duration: None,
                default_sample_size: None,
                default_sample_flags: None,
                duration_is_empty: false,
                default_base_is_moof: false,
            },
            tfdt_box: None,
            unknown_boxes: vec![],
            trun_boxes: offsets
                .iter()
                .map(|offset| TrunBox {
                    data_offset: *offset,
                    first_sample_flags: None,
                    samples: vec![TrunSample {
                        duration: None,
                        size,
                        flags: None,
                        composition_time_offset: None,
                    }],
                })
                .collect(),
        }
    }

    #[test]
    fn fragment_offsets_use_signed_base_and_continue_previous_run() {
        let traf = sample_runs(&[Some(-32), None, Some(16), None], Some(16));
        let samples = FragmentSamples::collect(&traf, 100, None).unwrap();
        assert_eq!(samples.offsets, [68, 84, 116, 132]);
        assert_eq!(samples.end, 148);
        assert!(FragmentSamples::collect(&traf, 20, None).is_err());
    }

    #[test]
    fn fragment_sizes_inherit_trex_after_trun_and_tfhd() {
        let mut traf = sample_runs(&[Some(0), None], None);
        let samples = FragmentSamples::collect(&traf, 100, Some(12)).unwrap();
        assert_eq!(samples.sizes, [12, 12]);
        assert_eq!(samples.offsets, [100, 112]);
        traf.tfhd_box.default_sample_size = Some(8);
        traf.trun_boxes[0].samples[0].size = Some(4);
        let samples = FragmentSamples::collect(&traf, 100, Some(12)).unwrap();
        assert_eq!(samples.sizes, [4, 8]);
        assert_eq!(samples.offsets, [100, 104]);
    }

    #[test]
    fn effective_protection_is_decided_after_group_override() {
        let mut track = track_with_iv_size(0);
        track.is_protected = false;
        let sample = SampleEncryptionEntry {
            iv: [1; 16],
            subsamples: vec![],
        };
        assert!(
            EffectiveSampleEncryption::from_metadata(&track, None, &sample, None, false).is_none()
        );
        let group = SeigEntry {
            pattern: None,
            is_protected: true,
            per_sample_iv_size: 0,
            kid: [3; 16],
            constant_iv: Some([5; 16]),
        };
        let effective =
            EffectiveSampleEncryption::from_metadata(&track, Some(group), &sample, None, false)
                .unwrap();
        assert_eq!(effective.kid, [3; 16]);
        assert_eq!(effective.iv, [5; 16]);
    }
    #[test]
    fn auxiliary_offsets_require_one_table_or_exactly_one_per_run() {
        let track = track_with_iv_size(8);
        assert!(
            parse_auxiliary_sample_entries(
                &[0; 64],
                0,
                &[0, 8, 16],
                &[8, 8],
                &[1, 1],
                &track,
                &[None, None]
            )
            .is_none()
        );
        assert!(
            parse_auxiliary_sample_entries(
                &[0; 64],
                0,
                &[0, 8],
                &[8, 8, 8],
                &[1, 1, 1],
                &track,
                &[None, None, None]
            )
            .is_none()
        );
    }

    #[test]
    fn zero_length_auxiliary_records_accept_end_of_input() {
        let mut track = track_with_iv_size(0);
        track.constant_iv = Some([3; 16]);
        let entries =
            parse_auxiliary_sample_entries(&[0; 16], 8, &[8], &[0], &[1], &track, &[None]).unwrap();
        assert_eq!(entries[0].iv, [3; 16]);
        assert!(
            parse_auxiliary_sample_entries(&[0; 16], 8, &[9], &[0], &[1], &track, &[None])
                .is_none()
        );
    }
}
