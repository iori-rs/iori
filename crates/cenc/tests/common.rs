use shiguredo_mp4::{BoxHeader, Decode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxLayout {
    pub typ: [u8; 4],
    pub start: usize,
    pub size: usize,
    pub header_size: usize,
}

#[allow(dead_code)]
pub fn top_level_box_layout(data: &[u8]) -> Option<Vec<BoxLayout>> {
    let mut boxes = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let (header, header_size) = BoxHeader::decode(&data[offset..]).ok()?;
        let mut box_size = usize::try_from(header.box_size.get()).ok()?;
        if box_size == 0 {
            box_size = data.len() - offset;
        }
        if box_size < header_size || offset + box_size > data.len() {
            return None;
        }
        if let shiguredo_mp4::BoxType::Normal(typ) = header.box_type {
            boxes.push(BoxLayout {
                typ,
                start: offset,
                size: box_size,
                header_size,
            });
        }
        offset += box_size;
    }
    Some(boxes)
}

#[allow(dead_code)]
pub fn find_top_level_box(data: &[u8], target: &[u8; 4]) -> Option<BoxLayout> {
    top_level_box_layout(data)?
        .into_iter()
        .find(|layout| &layout.typ == target)
}

#[allow(dead_code)]
pub fn read_mdat_payload(data: &[u8]) -> Option<Vec<u8>> {
    let mdat = find_top_level_box(data, b"mdat")?;
    let payload_start = mdat.start + mdat.header_size;
    let payload_end = mdat.start + mdat.size;
    Some(data[payload_start..payload_end].to_vec())
}

#[allow(dead_code)]
pub fn read_all_mdat_payloads(data: &[u8]) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    for mdat in top_level_box_layout(data)?
        .into_iter()
        .filter(|layout| layout.typ == *b"mdat")
    {
        let payload_start = mdat.start + mdat.header_size;
        let payload_end = mdat.start + mdat.size;
        payload.extend_from_slice(&data[payload_start..payload_end]);
    }
    Some(payload)
}

/// Bento4 encrypts the trailing partial block of unpatterned CENS audio as
/// ordinary CTR. ISO/IEC 23001-7:2023 sections 10.3 and 9.7 require it clear.
/// Verify the original fixture against its oracle everywhere except those
/// exact tails, then repair a copy of the fixture and verify all plaintext.
/// The stored fixtures and production decryptor are never adjusted for Bento4.
#[allow(dead_code)]
pub fn assert_bento4_decryption(
    encrypted: &[u8],
    oracle: &[u8],
    keys: &std::collections::HashMap<String, String>,
    context: &str,
) {
    use iori_cenc::{ParsedCenc, SchemeType, decrypt_mp4};
    use shiguredo_mp4::boxes::MoofBox;
    let layout = top_level_box_layout(encrypted).unwrap();
    let mdats: Vec<_> = layout.iter().filter(|b| b.typ == *b"mdat").collect();
    let expected = read_all_mdat_payloads(oracle).unwrap();
    let jobs = ParsedCenc::parse(encrypted).unwrap().jobs;
    let mut repaired = encrypted.to_vec();
    let mut legacy_expected = expected.clone();
    // Independently decoded trun/tfhd boundaries constrain every exception;
    // do not let a wrong decrypt-job range turn arbitrary mismatches into tails.
    let mut boundaries = Vec::new();
    for moof in layout.iter().filter(|b| b.typ == *b"moof") {
        let (decoded, _) = MoofBox::decode(&encrypted[moof.start..moof.start + moof.size]).unwrap();
        let mut preceding_end = moof.start as u64;
        for traf in decoded.traf_boxes {
            let base =
                traf.tfhd_box
                    .base_data_offset
                    .unwrap_or(if traf.tfhd_box.default_base_is_moof {
                        moof.start as u64
                    } else {
                        preceding_end
                    });
            let mut cursor = base;
            for trun in traf.trun_boxes {
                if let Some(offset) = trun.data_offset {
                    cursor = base.checked_add_signed(offset as i64).unwrap();
                }
                for sample in trun.samples {
                    let size = sample
                        .size
                        .or(traf.tfhd_box.default_sample_size)
                        .expect("fixture sample size");
                    boundaries.push((cursor, size));
                    cursor += size as u64;
                }
            }
            preceding_end = cursor;
        }
    }
    for job in jobs
        .iter()
        .filter(|j| j.scheme == SchemeType::Cens && j.pattern.is_none() && j.subsamples.is_empty())
    {
        assert!(
            boundaries.contains(&(job.offset, job.size)),
            "{context}: CENS sample boundary mismatch"
        );
        let tail_len = (job.size % 16) as usize;
        if tail_len == 0 {
            continue;
        }
        let start = job.offset as usize;
        let end = start.checked_add(job.size as usize).unwrap();
        let mut payload_base = 0usize;
        let mdat = mdats
            .iter()
            .find(|mdat| {
                let contains =
                    start >= mdat.start + mdat.header_size && end <= mdat.start + mdat.size;
                if !contains {
                    payload_base += mdat.size - mdat.header_size;
                }
                contains
            })
            .expect("CENS sample must be entirely inside mdat");
        let payload_end = payload_base + end - (mdat.start + mdat.header_size);
        let tail = payload_end - tail_len..payload_end;
        legacy_expected[tail.clone()].copy_from_slice(&encrypted[end - tail_len..end]);
        repaired[end - tail_len..end].copy_from_slice(&expected[tail]);
    }
    let mut decrypted = encrypted.to_vec();
    decrypt_mp4(&mut decrypted, keys).unwrap();
    let actual = read_all_mdat_payloads(&decrypted).unwrap();
    assert!(
        actual == legacy_expected,
        "{context}: mismatch outside legacy CENS tails at {:?}",
        actual
            .iter()
            .zip(&legacy_expected)
            .position(|(a, b)| a != b)
    );
    assert_eq!(decrypted.len(), encrypted.len(), "{context}: size changed");
    assert_eq!(
        top_level_box_layout(&decrypted),
        Some(layout.clone()),
        "{context}: layout changed"
    );
    decrypt_mp4(&mut repaired, keys).unwrap();
    let repaired_payload = read_all_mdat_payloads(&repaired).unwrap();
    assert!(
        repaired_payload == expected,
        "{context}: compliant fixture plaintext mismatch at {:?}",
        repaired_payload
            .iter()
            .zip(&expected)
            .position(|(a, b)| a != b)
    );
    assert_eq!(repaired.len(), encrypted.len());
    assert_eq!(top_level_box_layout(&repaired), Some(layout));
}
