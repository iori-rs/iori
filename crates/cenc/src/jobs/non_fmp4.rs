use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    RawMp4Box, SampleEncryptionBox, SampleEncryptionEntry, SbgpBox, SbgpEntry, SgpdSeigBox,
    TrackEncryptionInfo, find_unknown_box, parse_first_matching_unknown_box,
    resolve_seig_overrides, select_cenc_auxiliary,
};
use crate::types::{DecryptJob, ParsedCenc};
use shiguredo_mp4::aux::SampleTableAccessor;
use shiguredo_mp4::boxes::MoovBox;

struct NonFragmentedSample {
    index: usize,
    entry_index: usize,
    chunk_index: u32,
    offset: u64,
    size: u32,
}

/// Parse CENC decrypt jobs from a non-fragmented MP4 `moov`.
///
/// Sample layout comes from the regular sample tables; encryption records
/// come from `senc`, matching `saiz`/`saio` tables, or effective constant-IV
/// defaults. Group protection overrides are resolved before choosing records.
pub(crate) fn parse_decrypt_jobs_non_fmp4(input: &[u8], moov: &MoovBox) -> Result<ParsedCenc> {
    let media_ranges = RawMp4Box::parse_all(input, 0)?
        .into_iter()
        .filter(|item| item.is_type(shiguredo_mp4::boxes::MdatBox::TYPE))
        .map(|item| ((item.start + item.header_size) as u64, item.end() as u64))
        .collect::<Vec<_>>();
    let mut jobs = Vec::new();
    for trak in &moov.trak_boxes {
        let stbl = &trak.mdia_box.minf_box.stbl_box;
        let entry_infos = TrackEncryptionInfo::from_sample_entries(&stbl.stsd_box.entries)?;
        if !entry_infos.iter().any(|info| info.is_some()) {
            continue;
        }
        let senc = find_unknown_box(stbl.unknown_boxes.iter(), SampleEncryptionBox::TYPE);

        let sample_table = SampleTableAccessor::new(stbl)?;
        let expected = sample_table.sample_count();
        let samples = sample_table
            .samples()
            .map(|sample| NonFragmentedSample {
                index: sample.index().get() as usize - 1,
                entry_index: sample.chunk().sample_entry_index(),
                chunk_index: sample.chunk().index().get(),
                offset: sample.data_offset(),
                size: sample.data_size(),
            })
            .collect::<Vec<_>>();
        let sbgp = parse_first_matching_unknown_box(
            stbl.unknown_boxes.iter(),
            SbgpBox::TYPE,
            SbgpEntry::parse_seig,
        )?;
        let sgpd = parse_first_matching_unknown_box(
            stbl.unknown_boxes.iter(),
            SgpdSeigBox::TYPE,
            SgpdSeigBox::decode_payload,
        )?;
        let group_overrides =
            resolve_seig_overrides(sbgp.as_deref(), sgpd.as_ref(), None, expected as usize)?;
        let iv_info = samples
            .iter()
            .map(|sample| {
                entry_infos
                    .get(sample.entry_index)
                    .and_then(|info| info.as_ref())
                    .map(|info| {
                        if group_overrides[sample.index]
                            .map(|g| g.is_protected)
                            .unwrap_or(info.is_protected)
                        {
                            info.effective_iv_info(group_overrides[sample.index])
                        } else {
                            (0, Some([0; 16]))
                        }
                    })
                    .unwrap_or((0, Some([0; 16])))
            })
            .collect::<Vec<_>>();
        let (track_iv_size, track_constant_iv) = entry_infos
            .iter()
            .filter_map(|info| info.as_ref())
            .map(|info| (info.iv_size, info.constant_iv))
            .next()
            .unwrap_or((0, None));
        let (senc_entries, senc_override_kid) = if let Some(senc) = senc {
            let senc_info = SampleEncryptionBox::parse_senc_with_iv_info(
                &senc.payload,
                track_iv_size,
                track_constant_iv,
                Some(&iv_info),
            )?;
            if senc_info.overrides_to_clear_samples() {
                continue;
            }
            let kid = senc_info.override_kid();
            (senc_info.entries, kid)
        } else {
            let entries = match select_cenc_auxiliary(stbl.unknown_boxes.iter(), samples.len())? {
                Some((sizes, offsets)) => {
                    parse_auxiliary_entries(input, &samples, &sizes, &offsets, &iv_info)?
                }
                None => iv_info
                    .iter()
                    .map(|(size, iv)| {
                        if *size != 0 {
                            return Err(CencError::MissingSenc);
                        }
                        Ok(SampleEncryptionEntry {
                            iv: iv.ok_or(CencError::MissingSenc)?,
                            subsamples: vec![],
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            };
            (entries, None)
        };

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
            let group_override = group_overrides[sample.index];
            if !group_override
                .map(|entry| entry.is_protected)
                .unwrap_or(info.is_protected)
            {
                continue;
            }

            let end = sample
                .offset
                .checked_add(sample.size as u64)
                .ok_or(CencError::OutOfBounds)?;
            if !media_ranges
                .iter()
                .any(|&(start, limit)| sample.offset >= start && end <= limit)
            {
                return Err(CencError::OutOfBounds);
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

/// Non-fragmented SAIO offsets are absolute file offsets, with one table or
/// one table per chunk. SAIZ sizes remain in sample order.
fn parse_auxiliary_entries(
    input: &[u8],
    samples: &[NonFragmentedSample],
    sizes: &[u8],
    offsets: &[u64],
    iv_info: &[(u8, Option<[u8; 16]>)],
) -> Result<Vec<SampleEncryptionEntry>> {
    if sizes.len() != samples.len() || iv_info.len() != samples.len() {
        return Err(CencError::InvalidSenc(
            "auxiliary sample count mismatch".into(),
        ));
    }
    let chunk_count = samples
        .iter()
        .enumerate()
        .filter(|(i, s)| *i == 0 || samples[*i - 1].chunk_index != s.chunk_index)
        .count();
    if offsets.len() != 1 && offsets.len() != chunk_count {
        return Err(CencError::InvalidSenc(
            "saio offset count must be one or match chunks".into(),
        ));
    }
    let mut entries = Vec::with_capacity(samples.len());
    let mut cursor = 0usize;
    let mut chunk = 0usize;
    for (i, sample) in samples.iter().enumerate() {
        if i == 0 || samples[i - 1].chunk_index != sample.chunk_index {
            if i > 0 {
                chunk += 1;
            }
            if i == 0 || offsets.len() > 1 {
                cursor = usize::try_from(offsets[if offsets.len() == 1 { 0 } else { chunk }])
                    .map_err(|_| CencError::OutOfBounds)?;
            }
        }
        let end = cursor
            .checked_add(sizes[i] as usize)
            .ok_or(CencError::OutOfBounds)?;
        let bytes = input.get(cursor..end).ok_or(CencError::OutOfBounds)?;
        entries.push(SampleEncryptionEntry::parse_sai_entry(
            bytes,
            iv_info[i].0,
            iv_info[i].1,
        )?);
        cursor = end;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auxiliary_offsets_are_absolute_and_follow_chunks() {
        let samples = vec![
            NonFragmentedSample {
                index: 0,
                entry_index: 0,
                chunk_index: 100,
                offset: 100,
                size: 16,
            },
            NonFragmentedSample {
                index: 1,
                entry_index: 0,
                chunk_index: 100,
                offset: 116,
                size: 16,
            },
            NonFragmentedSample {
                index: 2,
                entry_index: 0,
                chunk_index: 200,
                offset: 200,
                size: 16,
            },
        ];
        let mut input = vec![0; 80];
        input[8..16].fill(1);
        input[16..24].fill(2);
        input[64..72].fill(3);
        let entries =
            parse_auxiliary_entries(&input, &samples, &[8; 3], &[8, 64], &[(8, None); 3]).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.iv[0]).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        input[24..32].fill(4);
        let entries =
            parse_auxiliary_entries(&input, &samples, &[8; 3], &[8], &[(8, None); 3]).unwrap();
        assert_eq!(entries[2].iv[0], 4);
        assert!(
            parse_auxiliary_entries(&input, &samples, &[8; 3], &[75], &[(8, None); 3]).is_err()
        );
    }

    #[test]
    fn zero_length_auxiliary_entries_use_constant_iv() {
        let samples = vec![NonFragmentedSample {
            index: 0,
            entry_index: 0,
            chunk_index: 0,
            offset: 0,
            size: 16,
        }];
        let entries =
            parse_auxiliary_entries(&[], &samples, &[0], &[0], &[(0, Some([7; 16]))]).unwrap();
        assert_eq!(entries[0].iv, [7; 16]);
        assert!(parse_auxiliary_entries(&[], &samples, &[0], &[0], &[(8, None)]).is_err());
    }
}
