//! Regression layouts for fragment defaults, offsets and sample groups.
mod common;
use iori_cenc::ParsedCenc;

fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(payload);
    out
}

fn init(clear: bool, sample_size: u32) -> Vec<u8> {
    let fixture = include_bytes!("fixtures/fmp4/cbcs.mp4");
    let moof = common::find_top_level_box(fixture, b"moof").unwrap();
    let mut bytes = fixture[..moof.start].to_vec();
    let tenc = bytes.windows(4).position(|s| s == b"tenc").unwrap();
    bytes[tenc + 10] = u8::from(!clear);
    let trex = bytes.windows(4).position(|s| s == b"trex").unwrap();
    bytes[trex + 20..trex + 24].copy_from_slice(&sample_size.to_be_bytes());
    bytes
}

fn traf(base: Option<u64>, relative_to_moof: bool, runs: &[Option<i32>], extra: &[u8]) -> Vec<u8> {
    let flags = u32::from(base.is_some()) | if relative_to_moof { 0x020000 } else { 0 };
    let mut tfhd = flags.to_be_bytes().to_vec();
    tfhd.extend_from_slice(&1u32.to_be_bytes());
    if let Some(base) = base {
        tfhd.extend_from_slice(&base.to_be_bytes());
    }
    let mut payload = boxed(b"tfhd", &tfhd);
    for offset in runs {
        let mut trun = u32::from(offset.is_some()).to_be_bytes().to_vec();
        trun.extend_from_slice(&1u32.to_be_bytes());
        if let Some(offset) = offset {
            trun.extend_from_slice(&offset.to_be_bytes());
        }
        payload.extend(boxed(b"trun", &trun));
    }
    payload.extend_from_slice(extra);
    boxed(b"traf", &payload)
}

fn moof(trafs: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = boxed(b"mfhd", &[0, 0, 0, 0, 0, 0, 0, 1]);
    for traf in trafs {
        payload.extend_from_slice(traf);
    }
    boxed(b"moof", &payload)
}

fn group(default: bool, index: u32) -> Vec<u8> {
    let mut entry = vec![0, 0x19, 1, 0];
    entry.extend_from_slice(&[9; 16]);
    entry.push(16);
    entry.extend_from_slice(&[7; 16]);
    let mut sgpd = vec![if default { 2 } else { 1 }, 0, 0, 0];
    sgpd.extend_from_slice(b"seig");
    sgpd.extend_from_slice(&(entry.len() as u32).to_be_bytes());
    if default {
        sgpd.extend_from_slice(&1u32.to_be_bytes());
    }
    sgpd.extend_from_slice(&1u32.to_be_bytes());
    sgpd.extend(entry);
    let mut result = boxed(b"sgpd", &sgpd);
    if !default {
        let mut sbgp = vec![0; 4];
        sbgp.extend_from_slice(b"seig");
        sbgp.extend_from_slice(&1u32.to_be_bytes());
        sbgp.extend_from_slice(&1u32.to_be_bytes());
        sbgp.extend_from_slice(&index.to_be_bytes());
        result.extend(boxed(b"sbgp", &sbgp));
    }
    result
}

#[test]
fn constant_iv_without_auxiliary_tables_and_trex_sizes() {
    let init = init(false, 16);
    let mut media = boxed(b"mdat", &[0; 32]);
    media.extend(moof(&[traf(Some(24), false, &[Some(-16), None], &[])]));
    let parsed = ParsedCenc::parse_with_init(&media, &init).unwrap();
    assert_eq!(
        parsed
            .jobs
            .iter()
            .map(|job| (job.offset, job.size))
            .collect::<Vec<_>>(),
        [(8, 16), (24, 16)]
    );
}

#[test]
fn later_implicit_traf_continues_at_previous_traf_end() {
    let init = init(false, 16);
    let mut media = boxed(b"mdat", &[0; 32]);
    media.extend(moof(&[
        traf(Some(8), false, &[None], &[]),
        traf(None, false, &[None], &[]),
    ]));
    let parsed = ParsedCenc::parse_with_init(&media, &init).unwrap();
    assert_eq!(
        parsed.jobs.iter().map(|job| job.offset).collect::<Vec<_>>(),
        [8, 24]
    );
}

#[test]
fn default_clear_init_accepts_protected_fragment_group_and_sgpd_default() {
    for extra in [group(false, 0x10001), group(true, 0)] {
        let init = init(true, 16);
        let mut media = boxed(b"mdat", &[0; 16]);
        media.extend(moof(&[traf(Some(8), false, &[None], &extra)]));
        let parsed = ParsedCenc::parse_with_init(&media, &init).unwrap();
        assert_eq!(parsed.jobs.len(), 1);
        assert_eq!(parsed.jobs[0].kid, [9; 16]);
        assert_eq!(parsed.jobs[0].iv, [7; 16]);
        let pattern = parsed.jobs[0].pattern.unwrap();
        assert_eq!((pattern.crypt_byte_block, pattern.skip_byte_block), (1, 9));
    }
}

#[test]
fn default_base_is_moof_uses_moof_start_and_rejects_header_addresses() {
    let init = init(false, 16);
    let mut media = boxed(b"mdat", &[0; 16]);
    media.extend(moof(&[traf(None, true, &[Some(-16)], &[])]));
    assert_eq!(
        ParsedCenc::parse_with_init(&media, &init).unwrap().jobs[0].offset,
        8
    );
    let invalid = moof(&[traf(Some(0), false, &[None], &[])]);
    assert!(ParsedCenc::parse_with_init(&invalid, &init).is_err());
}

fn rewrite_box(data: &[u8], target: &[u8; 4], edit: &impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    for layout in common::top_level_box_layout(data).unwrap() {
        let payload = &data[layout.start + layout.header_size..layout.start + layout.size];
        let updated = if &layout.typ == target {
            edit(payload)
        } else if [*b"moov", *b"trak", *b"mdia", *b"minf", *b"stbl", *b"mvex"].contains(&layout.typ)
        {
            rewrite_box(payload, target, edit)
        } else {
            payload.to_vec()
        };
        result.extend(boxed(&layout.typ, &updated));
    }
    result
}

#[test]
fn trex_selects_second_encryption_sample_description() {
    let init = rewrite_box(&init(false, 16), b"stsd", &|payload| {
        assert_eq!(u32::from_be_bytes(payload[4..8].try_into().unwrap()), 1);
        let mut entries = payload.to_vec();
        entries[4..8].copy_from_slice(&2u32.to_be_bytes());
        let tenc = entries.windows(4).position(|s| s == b"tenc").unwrap();
        entries[tenc + 10] = 0;
        entries.extend_from_slice(&payload[8..]);
        entries
    });
    let init = rewrite_box(&init, b"trex", &|payload| {
        let mut payload = payload.to_vec();
        payload[8..12].copy_from_slice(&2u32.to_be_bytes());
        payload
    });
    let mut media = boxed(b"mdat", &[0; 16]);
    media.extend(moof(&[traf(Some(8), false, &[None], &[])]));
    assert_eq!(
        ParsedCenc::parse_with_init(&media, &init)
            .unwrap()
            .jobs
            .len(),
        1
    );
}

#[test]
fn fragment_groups_resolve_track_and_local_namespaces_separately() {
    let track_group = group(true, 0);
    let init = rewrite_box(&init(false, 16), b"stbl", &|payload| {
        let mut payload = payload.to_vec();
        payload.extend_from_slice(&track_group);
        payload
    });
    for (index, expected) in [(1, [9; 16]), (0x10001, [6; 16])] {
        let mut extra = group(false, index);
        let kid = extra.windows(16).position(|s| s == [9; 16]).unwrap();
        extra[kid..kid + 16].fill(6);
        let mut media = boxed(b"mdat", &[0; 16]);
        media.extend(moof(&[traf(Some(8), false, &[None], &extra)]));
        let jobs = ParsedCenc::parse_with_init(&media, &init).unwrap().jobs;
        assert_eq!(jobs[0].kid, expected);
    }
    // A track default applies even with no fragment group boxes.
    let mut media = boxed(b"mdat", &[0; 16]);
    media.extend(moof(&[traf(Some(8), false, &[None], &[])]));
    assert_eq!(
        ParsedCenc::parse_with_init(&media, &init).unwrap().jobs[0].kid,
        [9; 16]
    );
}

#[test]
fn fragment_can_reference_track_group_without_local_description_table() {
    let track_group = group(true, 0);
    let init = rewrite_box(&init(false, 16), b"stbl", &|payload| {
        let mut payload = payload.to_vec();
        payload.extend_from_slice(&track_group);
        payload
    });
    let group_boxes = group(false, 1);
    let mapping = common::find_top_level_box(&group_boxes, b"sbgp").unwrap();
    let mut media = boxed(b"mdat", &[0; 16]);
    media.extend(moof(&[traf(
        Some(8),
        false,
        &[None],
        &group_boxes[mapping.start..],
    )]));
    assert_eq!(
        ParsedCenc::parse_with_init(&media, &init).unwrap().jobs[0].kid,
        [9; 16]
    );
}

#[test]
fn malformed_or_incomplete_auxiliary_metadata_never_falls_back_to_full_sample() {
    let init = init(false, 16);
    let mut saiz = vec![0; 4];
    saiz.push(8);
    saiz.extend_from_slice(&1u32.to_be_bytes());
    let saiz = boxed(b"saiz", &saiz);
    let mut saio = vec![0; 4];
    saio.extend_from_slice(&1u32.to_be_bytes());
    saio.extend_from_slice(&u32::MAX.to_be_bytes());
    let saio = boxed(b"saio", &saio);
    for extra in [saiz.clone(), saio.clone(), [saiz, saio].concat()] {
        let mut media = boxed(b"mdat", &[0; 16]);
        media.extend(moof(&[traf(Some(8), false, &[None], &extra)]));
        assert!(ParsedCenc::parse_with_init(&media, &init).is_err());
        // A valid senc still supplies the exact subsample table when auxiliary
        // offsets are unusable, instead of treating the entire sample as encrypted.
        let mut senc = vec![0, 0, 0, 2];
        senc.extend_from_slice(&1u32.to_be_bytes());
        senc.extend_from_slice(&1u16.to_be_bytes());
        senc.extend_from_slice(&8u16.to_be_bytes());
        senc.extend_from_slice(&8u32.to_be_bytes());
        let extra = [extra, boxed(b"senc", &senc)].concat();
        let mut media = boxed(b"mdat", &[0; 16]);
        media.extend(moof(&[traf(Some(8), false, &[None], &extra)]));
        let jobs = ParsedCenc::parse_with_init(&media, &init).unwrap().jobs;
        assert_eq!(jobs[0].subsamples[0].clear_bytes, 8);
        assert_eq!(jobs[0].subsamples[0].encrypted_bytes, 8);
    }
}
