use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    BOX_SBGP, BOX_SENC, BOX_SGPD, RawMp4Box, SampleEncryptionBox, SampleEncryptionEntry, SbgpEntry,
    SeigEntry, TrackEncryptionInfo, parse_saio, parse_saiz,
};
use crate::types::{CbcPattern, DecryptJob, ParsedCenc};
use shiguredo_mp4::boxes::{MoofBox, MoovBox, UnknownBox};
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

    fn find(&self, box_type: [u8; 4]) -> Option<&'a UnknownBox> {
        self.traf
            .iter()
            .chain(self.moof.iter())
            .find(|b| b.box_type == BoxType::Normal(box_type))
    }

    fn parse_seig_sbgp(&self) -> Result<Option<Vec<SbgpEntry>>> {
        self.traf
            .iter()
            .chain(self.moof.iter())
            .filter(|b| b.box_type == BoxType::Normal(BOX_SBGP))
            .find_map(|b| SbgpEntry::parse_seig(&b.payload).transpose())
            .transpose()
    }

    fn parse_seig_sgpd(&self) -> Result<Option<Vec<SeigEntry>>> {
        self.traf
            .iter()
            .chain(self.moof.iter())
            .filter(|b| b.box_type == BoxType::Normal(BOX_SGPD))
            .find_map(|b| SeigEntry::parse_seig(&b.payload).transpose())
            .transpose()
    }

    fn parse_cenc_saiz(&self) -> Result<Option<Vec<u8>>> {
        for box_item in self
            .traf
            .iter()
            .chain(self.moof.iter())
            .filter(|b| b.box_type == BoxType::Normal(*b"saiz"))
        {
            if let Some(sizes) = parse_saiz(&box_item.payload)? {
                return Ok(Some(sizes));
            }
        }
        Ok(None)
    }

    fn parse_cenc_saio(&self) -> Result<Option<Vec<u64>>> {
        for box_item in self
            .traf
            .iter()
            .chain(self.moof.iter())
            .filter(|b| b.box_type == BoxType::Normal(*b"saio"))
        {
            if let Some(offsets) = parse_saio(&box_item.payload)? {
                return Ok(Some(offsets));
            }
        }
        Ok(None)
    }
}

struct FragmentSamples {
    offsets: Vec<u64>,
    sizes: Vec<u32>,
    trun_sample_counts: Vec<usize>,
}

impl FragmentSamples {
    fn collect(
        traf: &shiguredo_mp4::boxes::TrafBox,
        moof_start: usize,
        moof_size: usize,
    ) -> Result<Self> {
        let tfhd = &traf.tfhd_box;
        let mut offsets = Vec::new();
        let mut sizes = Vec::new();
        let mut trun_sample_counts = Vec::new();
        for trun in &traf.trun_boxes {
            trun_sample_counts.push(trun.samples.len());
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
                offsets.push(current);
                sizes.push(size);
                current += size as u64;
            }
        }
        Ok(Self {
            offsets,
            sizes,
            trun_sample_counts,
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

struct SeigSampleGroups {
    sbgp: Vec<SbgpEntry>,
    sgpd: Vec<SeigEntry>,
}

/// Per-sample protection state expanded from `sbgp`/`sgpd`.
///
/// CENC sample groups are run-length metadata over the media samples. Each
/// mapped sample still occupies one position in decode order, even when its
/// `seig` description marks it unprotected. Keeping clear samples as explicit
/// entries preserves the one-to-one relationship between sample indexes and
/// sample-group indexes.
enum GroupSampleEncryption {
    /// The sample group description says this sample is not encrypted.
    Clear,
    /// The sample is encrypted and the group supplies the sample encryption
    /// parameters that are otherwise carried by `senc` or `saiz`/`saio`.
    Encrypted(SampleEncryptionEntry),
}

impl SeigSampleGroups {
    fn parse(required_boxes: &UnknownBoxes) -> Result<Self> {
        let sbgp = required_boxes
            .parse_seig_sbgp()?
            .ok_or(CencError::MissingSenc)?;
        let sgpd = required_boxes
            .parse_seig_sgpd()?
            .ok_or(CencError::MissingSenc)?;
        Ok(Self { sbgp, sgpd })
    }

    fn parse_optional(boxes: &UnknownBoxes) -> Result<Option<Self>> {
        let Some(sbgp) = boxes.parse_seig_sbgp()? else {
            return Ok(None);
        };
        let sgpd = boxes.parse_seig_sgpd()?.ok_or(CencError::MissingSenc)?;
        Ok(Some(Self { sbgp, sgpd }))
    }

    /// Build per-sample protection states from `sbgp`/`sgpd` `seig` boxes.
    ///
    /// If no `senc` or `saiz`/`saio` data exists, protected samples may still
    /// be described by a `seig` sample group. In that layout the group supplies
    /// a constant IV and there is no per-sample subsample table. Unprotected
    /// group descriptions are retained as clear samples instead of being
    /// omitted, because omitting them would shift every later sample's
    /// encryption metadata to the wrong media sample.
    fn build_samples(
        &self,
        sample_count: usize,
        track_info: &TrackEncryptionInfo,
    ) -> Result<Vec<GroupSampleEncryption>> {
        let mut samples = Vec::with_capacity(sample_count);
        let mut remaining = sample_count;

        for sbgp_entry in &self.sbgp {
            let count = (sbgp_entry.sample_count as usize).min(remaining);
            for _ in 0..count {
                let state = if sbgp_entry.group_description_index == 0 {
                    let iv = track_info.constant_iv.ok_or_else(|| {
                        CencError::InvalidSenc(
                            "sbgp group_description_index=0 but no track-level constant IV"
                                .to_string(),
                        )
                    })?;
                    GroupSampleEncryption::Encrypted(SampleEncryptionEntry {
                        iv,
                        subsamples: Vec::new(),
                    })
                } else {
                    let idx = sbgp_entry.description_index()?;
                    let seig = self.sgpd.get(idx).ok_or_else(|| {
                        CencError::InvalidSenc("invalid sbgp group_description_index".to_string())
                    })?;
                    if !seig.is_protected {
                        GroupSampleEncryption::Clear
                    } else {
                        let iv = seig.constant_iv.ok_or_else(|| {
                            CencError::InvalidSenc(
                                "sgpd seig entry has no constant IV (per_sample_iv_size != 0)"
                                    .to_string(),
                            )
                        })?;
                        GroupSampleEncryption::Encrypted(SampleEncryptionEntry {
                            iv,
                            subsamples: Vec::new(),
                        })
                    }
                };
                samples.push(state);
            }
            remaining -= count;
            if remaining == 0 {
                break;
            }
        }

        Ok(samples)
    }

    /// Expand sample-group overrides to one optional `seig` entry per sample.
    ///
    /// `sbgp` maps runs of samples to `sgpd` descriptions. A zero description
    /// index means "use the track defaults"; a non-zero index overrides
    /// selected track encryption fields for that run.
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
        if matches!(group, Some(entry) if !entry.is_protected) {
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
    moof_start: usize,
    offsets: &[u64],
    sizes: &[u8],
    trun_sample_counts: &[usize],
    track_info: &TrackEncryptionInfo,
    group_overrides: &[Option<SeigEntry>],
) -> Option<Vec<SampleEncryptionEntry>> {
    if offsets.is_empty() || sizes.len() != trun_sample_counts.iter().sum::<usize>() {
        return None;
    }
    if sizes.len() != group_overrides.len() {
        return None;
    }

    if offsets.len() == 1 {
        let aux_offset = checked_aux_offset(moof_start, offsets[0], input.len())?;
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
        let aux_offset = checked_aux_offset(moof_start, *offsets.get(trun_index)?, input.len())?;
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
    (offset < input_len).then_some(offset)
}

/// Parse CENC decrypt jobs from fragmented MP4 media.
///
/// Per-fragment encryption data is resolved like Bento4: auxiliary info
/// referenced by `saiz`/`saio` is tried first, invalid auxiliary layouts fall
/// back to `senc`, and `seig` sample groups are used when neither table exists.
pub(crate) fn parse_decrypt_jobs_fmp4(input: &[u8], moov: &MoovBox) -> Result<ParsedCenc> {
    let track_map = super::get_track_map(moov)?;
    let mut track_lookup: HashMap<u32, Vec<Option<TrackEncryptionInfo>>> = HashMap::new();
    for (track_id, infos) in track_map {
        track_lookup.insert(track_id, infos);
    }

    let top_boxes = RawMp4Box::parse_all(input, 0)?;
    let mut jobs = Vec::new();

    for raw_moof in top_boxes.iter().filter(|b| b.box_type == *b"moof") {
        let (moof, _) = MoofBox::decode(&input[raw_moof.start..raw_moof.start + raw_moof.size])?;
        let moof_start = raw_moof.start;
        let moof_size = raw_moof.size;

        for traf in &moof.traf_boxes {
            let unknown_boxes = UnknownBoxes::new(&traf.unknown_boxes, &moof.unknown_boxes);
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

            let samples = FragmentSamples::collect(traf, moof_start, moof_size)?;
            if samples.is_empty() {
                continue;
            }

            let sample_count = samples.len();
            let sample_groups = SeigSampleGroups::parse_optional(&unknown_boxes)?;
            let group_overrides = sample_groups
                .as_ref()
                .map(|groups| groups.overrides(sample_count))
                .transpose()?
                .unwrap_or_else(|| vec![None; sample_count]);

            let senc_box = unknown_boxes.find(BOX_SENC);
            let (entries, senc_override_kid, senc_overrides_to_clear) = 'entries: {
                let sizes = unknown_boxes.parse_cenc_saiz()?;
                let offsets = unknown_boxes.parse_cenc_saio()?;
                if let (Some(sizes), Some(offsets)) = (sizes, offsets)
                    && let Some(entries) = parse_auxiliary_sample_entries(
                        input,
                        moof_start,
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

                (
                    SeigSampleGroups::parse(&unknown_boxes)?.build_samples(sample_count, info)?,
                    None,
                    false,
                )
            };

            if entries.len() != sample_count {
                return Err(CencError::SampleCountMismatch {
                    expected: sample_count as u32,
                    actual: entries.len() as u32,
                });
            }

            for (((offset, size), sample_encryption), group_override) in samples
                .into_iter()
                .zip(entries.into_iter())
                .zip(group_overrides.into_iter())
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
    fn seig_sample_groups_keep_unprotected_samples_in_position() {
        let groups = SeigSampleGroups {
            sbgp: vec![
                SbgpEntry {
                    sample_count: 1,
                    group_description_index: 1,
                },
                SbgpEntry {
                    sample_count: 1,
                    group_description_index: 2,
                },
            ],
            sgpd: vec![
                SeigEntry {
                    pattern: None,
                    is_protected: false,
                    per_sample_iv_size: 0,
                    kid: [0; 16],
                    constant_iv: None,
                },
                SeigEntry {
                    pattern: None,
                    is_protected: true,
                    per_sample_iv_size: 0,
                    kid: [9; 16],
                    constant_iv: Some([7; 16]),
                },
            ],
        };
        let track = TrackEncryptionInfo {
            scheme: SchemeType::Cenc,
            kid: [1; 16],
            iv_size: 0,
            constant_iv: None,
            pattern: None,
            is_protected: true,
        };

        let samples = groups.build_samples(2, &track).unwrap();

        assert!(matches!(samples[0], GroupSampleEncryption::Clear));
        match &samples[1] {
            GroupSampleEncryption::Encrypted(entry) => assert_eq!(entry.iv, [7; 16]),
            GroupSampleEncryption::Clear => panic!("second sample should be encrypted"),
        }
    }
}
