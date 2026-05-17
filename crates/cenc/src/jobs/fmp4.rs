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
                offsets.push(current);
                sizes.push(size);
                current += size as u64;
            }
        }
        Ok(Self { offsets, sizes })
    }

    fn is_empty(&self) -> bool {
        self.sizes.is_empty()
    }

    fn len(&self) -> usize {
        self.sizes.len()
    }

    fn into_iter(self) -> impl Iterator<Item = (u64, u32)> {
        self.offsets.into_iter().zip(self.sizes)
    }
}

struct SeigSampleGroups {
    sbgp: Vec<SbgpEntry>,
    sgpd: Vec<SeigEntry>,
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

    /// Build per-sample encryption entries from `sbgp`/`sgpd` `seig` boxes.
    ///
    /// If no `senc` or `saiz`/`saio` data exists, protected samples may still
    /// be described by a `seig` sample group. In that layout the group supplies
    /// a constant IV and there is no per-sample subsample table.
    fn build_entries(
        &self,
        sample_count: usize,
        track_info: &TrackEncryptionInfo,
    ) -> Result<Vec<SampleEncryptionEntry>> {
        let mut entries = Vec::with_capacity(sample_count);
        let mut remaining = sample_count;

        for sbgp_entry in &self.sbgp {
            let count = (sbgp_entry.sample_count as usize).min(remaining);
            for _ in 0..count {
                let iv = if sbgp_entry.group_description_index == 0 {
                    track_info.constant_iv.ok_or_else(|| {
                        CencError::InvalidSenc(
                            "sbgp group_description_index=0 but no track-level constant IV"
                                .to_string(),
                        )
                    })?
                } else {
                    let idx = sbgp_entry.description_index()?;
                    let seig = self.sgpd.get(idx).ok_or_else(|| {
                        CencError::InvalidSenc("invalid sbgp group_description_index".to_string())
                    })?;
                    if !seig.is_protected {
                        continue;
                    }
                    seig.constant_iv.ok_or_else(|| {
                        CencError::InvalidSenc(
                            "sgpd seig entry has no constant IV (per_sample_iv_size != 0)"
                                .to_string(),
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
    ) -> Option<Self> {
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
        track: &TrackEncryptionInfo,
        sample: SampleEncryptionEntry,
        offset: u64,
        size: u32,
    ) -> DecryptJob {
        DecryptJob {
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

/// Parse CENC decrypt jobs from fragmented MP4 media.
///
/// Per-fragment encryption data is resolved in spec order: `senc` first when
/// present and non-empty, then auxiliary info referenced by `saiz`/`saio`, and
/// finally `seig` sample groups.
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
            let (entries, senc_override_kid) = 'entries: {
                let sizes = unknown_boxes.parse_cenc_saiz()?;
                let offsets = unknown_boxes.parse_cenc_saio()?;
                if let (Some(sizes), Some(offsets)) = (sizes, offsets)
                    && !offsets.is_empty()
                    && sizes.len() == sample_count
                {
                    let aux_offset = moof_start + offsets[0] as usize;
                    if aux_offset < input.len()
                        && let Ok(entries) = SampleEncryptionEntry::parse_sai(
                            &input[aux_offset..],
                            &sizes,
                            info.iv_size,
                            info.constant_iv,
                        )
                    {
                        break 'entries (entries, None);
                    }
                }

                if let Some(senc) = senc_box {
                    let parsed = SampleEncryptionBox::parse_senc(
                        &senc.payload,
                        info.iv_size,
                        info.constant_iv,
                    )?;
                    if !parsed.entries.is_empty() {
                        let override_kid = parsed.override_kid();
                        break 'entries (parsed.entries, override_kid);
                    }
                }

                (
                    SeigSampleGroups::parse(&unknown_boxes)?.build_entries(sample_count, info)?,
                    None,
                )
            };

            if entries.len() != sample_count {
                return Err(CencError::SampleCountMismatch {
                    expected: sample_count as u32,
                    actual: entries.len() as u32,
                });
            }

            for (((offset, size), entry), group_override) in samples
                .into_iter()
                .zip(entries.into_iter())
                .zip(group_overrides.into_iter())
            {
                let Some(effective) = EffectiveSampleEncryption::from_metadata(
                    info,
                    group_override,
                    &entry,
                    senc_override_kid,
                ) else {
                    continue;
                };
                jobs.push(effective.into_decrypt_job(info, entry, offset, size));
            }
        }
    }

    Ok(ParsedCenc { jobs })
}
