//! Container metamorphic witnesses with frozen NIST AES-CBC sample bytes.
//! Expected sample coordinates are fixture-writer outputs, never decrypt jobs.
//! shiguredo supplies a container encoder; encryption expectations do not use
//! that library or production encryption/parsing helpers.
mod common;
use iori_cenc::{KeyMap, ParsedCenc};
use shiguredo_mp4::boxes::{MoovBox, StcoBox, StscEntry, StszBox, SttsEntry, UnknownBox};
use shiguredo_mp4::{Decode, Either, Encode};

const KID: [u8; 16] = [1; 16];
fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut data = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    data.extend_from_slice(kind);
    data.extend_from_slice(payload);
    data
}
fn unknown(kind: &[u8; 4], payload: &[u8]) -> UnknownBox {
    UnknownBox::decode(&boxed(kind, payload)).unwrap().0
}
fn sample(index: usize, encrypted: bool) -> Vec<u8> {
    let mut data = vec![0xa0 + index as u8, 0x40 + index as u8, 0x70 + index as u8];
    data.extend(bytes(if encrypted {
        "7649abac8119b246cee98e9b12e9197d"
    } else {
        "6bc1bee22e409f96e93d7e117393172a"
    }));
    data
}
fn movie(fragmented: bool, offsets: &[u32], extra: Vec<UnknownBox>) -> MoovBox {
    let fixture = include_bytes!("fixtures/fmp4/cbcs.mp4");
    let layout = common::find_top_level_box(fixture, b"moov").unwrap();
    let mut data = fixture[layout.start..layout.start + layout.size].to_vec();
    let tenc = data.windows(4).position(|v| v == b"tenc").unwrap();
    data[tenc + 12..tenc + 28].copy_from_slice(&KID);
    data[tenc + 29..tenc + 45].copy_from_slice(&bytes("000102030405060708090a0b0c0d0e0f"));
    let mut movie = MoovBox::decode(&data).unwrap().0;
    movie.trak_boxes.truncate(1);
    if fragmented {
        let trex = &mut movie.mvex_box.as_mut().unwrap().trex_boxes[0];
        trex.default_sample_size = 19;
    } else {
        movie.mvex_box = None;
    }
    let table = &mut movie.trak_boxes[0].mdia_box.minf_box.stbl_box;
    table.stts_box.entries = vec![SttsEntry {
        sample_count: offsets.len() as u32,
        sample_delta: 1,
    }];
    table.stsc_box.entries = if offsets.is_empty() {
        vec![]
    } else {
        vec![StscEntry {
            first_chunk: 1.try_into().unwrap(),
            sample_per_chunk: 1,
            sample_description_index: 1.try_into().unwrap(),
        }]
    };
    table.stsz_box = StszBox::Fixed {
        sample_size: 19.try_into().unwrap(),
        sample_count: offsets.len() as u32,
    };
    table.stco_or_co64_box = Either::A(StcoBox {
        chunk_offsets: offsets.to_vec(),
    });
    table.stss_box = None;
    table.ctts_box = None;
    table.unknown_boxes = extra;
    movie
}
fn record() -> Vec<u8> {
    vec![0, 1, 0, 3, 0, 0, 0, 16]
}
fn inline() -> Vec<UnknownBox> {
    let mut payload = vec![0, 0, 0, 2, 0, 0, 0, 3];
    payload.extend(record().repeat(3));
    vec![unknown(b"senc", &payload)]
}
fn auxiliary(offset: u64) -> Vec<UnknownBox> {
    let mut sizes = vec![0, 0, 0, 0, 8];
    sizes.extend_from_slice(&3u32.to_be_bytes());
    let mut offsets = vec![1, 0, 0, 0, 0, 0, 0, 1];
    offsets.extend_from_slice(&offset.to_be_bytes());
    vec![unknown(b"saiz", &sizes), unknown(b"saio", &offsets)]
}
fn data_layout(order: &[usize], padding: usize, separate_mdats: bool) -> (Vec<u8>, Vec<u32>) {
    let mut data = boxed(b"free", &vec![0x91; padding]);
    let mut positions = vec![0; 3];
    if separate_mdats {
        for index in order {
            positions[*index] = (data.len() + 8) as u32;
            data.extend(boxed(b"mdat", &sample(*index, true)));
            data.extend(boxed(b"free", &vec![0x72; padding]));
        }
    } else {
        let mut payload = vec![];
        for index in order {
            positions[*index] = (data.len() + 8 + payload.len()) as u32;
            payload.extend(sample(*index, true));
        }
        data.extend(boxed(b"mdat", &payload));
    }
    (data, positions)
}
fn fragment(offsets: &[u32], base: u64, extra: Vec<UnknownBox>, one_run: bool) -> Vec<u8> {
    let mut tfhd = vec![0, 0, 0, 1, 0, 0, 0, 1];
    tfhd.extend_from_slice(&base.to_be_bytes());
    let mut traf = boxed(b"tfhd", &tfhd);
    if one_run {
        let mut run = vec![0, 0, 0, 1, 0, 0, 0, 3];
        run.extend_from_slice(&((offsets[0] as i64 - base as i64) as i32).to_be_bytes());
        traf.extend(boxed(b"trun", &run));
    } else {
        for offset in offsets {
            let mut run = vec![0, 0, 0, 1, 0, 0, 0, 1];
            run.extend_from_slice(&((*offset as i64 - base as i64) as i32).to_be_bytes());
            traf.extend(boxed(b"trun", &run));
        }
    }
    for extra in extra {
        traf.extend(extra.encode_to_vec().unwrap());
    }
    let mut moof = boxed(b"mfhd", &[0, 0, 0, 0, 0, 0, 0, 1]);
    moof.extend(boxed(b"traf", &traf));
    boxed(b"moof", &moof)
}
fn check(mut file: Vec<u8>, positions: &[u32], parsed: ParsedCenc) -> Vec<Vec<u8>> {
    let before = file.clone();
    let layout = common::top_level_box_layout(&before).unwrap();
    let mut keys = KeyMap::new();
    keys.insert(
        KID,
        bytes("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap(),
    );
    parsed.decrypt_in_place(&mut file, &keys, 0).unwrap();
    assert_eq!(file.len(), before.len());
    assert_eq!(common::top_level_box_layout(&file).unwrap(), layout);
    let mut observed = vec![];
    for (index, position) in positions.iter().enumerate() {
        let start = *position as usize;
        let value = file[start..start + 19].to_vec();
        assert_eq!(value, sample(index, false));
        observed.push(value);
    }
    for b in layout {
        if b.typ == *b"free" {
            assert_eq!(
                &file[b.start..b.start + b.size],
                &before[b.start..b.start + b.size]
            );
        }
    }
    observed
}

#[test]
fn progressive_and_fragmented_inline_and_auxiliary_recover_identical_frozen_samples() {
    let mut reference = None;
    for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
        for padding in [0, 1, 31] {
            for separate_mdats in [false, true] {
                for external in [false, true] {
                    let (mut progressive, positions) = data_layout(&order, padding, separate_mdats);
                    let extra = if external {
                        let address = progressive.len() + 8;
                        progressive.extend(boxed(b"free", &record().repeat(3)));
                        auxiliary(address as u64)
                    } else {
                        inline()
                    };
                    progressive.extend(movie(false, &positions, extra).encode_to_vec().unwrap());
                    let parsed = ParsedCenc::parse(&progressive).unwrap();
                    let observed = check(progressive, &positions, parsed);
                    if let Some(reference) = &reference {
                        assert_eq!(&observed, reference);
                    } else {
                        reference = Some(observed);
                    }
                    for base_after_media in [false, true] {
                        let (mut media, positions) = data_layout(&order, padding, separate_mdats);
                        let base = if base_after_media {
                            media.len() as u64
                        } else {
                            0
                        };
                        let extra = if external {
                            let address = media.len() + 8;
                            media.extend(boxed(b"free", &record().repeat(3)));
                            auxiliary(address as u64 - base)
                        } else {
                            inline()
                        };
                        media.extend(fragment(&positions, base, extra, false));
                        let init = movie(true, &[], vec![]).encode_to_vec().unwrap();
                        let detached = ParsedCenc::parse_with_init(&media, &init).unwrap();
                        assert_eq!(
                            check(media.clone(), &positions, detached),
                            *reference.as_ref().unwrap()
                        );
                        media.extend(init);
                        let whole = ParsedCenc::parse(&media).unwrap();
                        assert_eq!(
                            check(media, &positions, whole),
                            *reference.as_ref().unwrap()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn one_trun_and_three_truns_have_the_same_plaintext_and_nonzero_window_offsets() {
    let init = movie(true, &[], vec![]).encode_to_vec().unwrap();
    for one_run in [false, true] {
        let (mut media, positions) = data_layout(&[0, 1, 2], 17, false);
        let base = media.len() as u64;
        media.extend(fragment(&positions, base, inline(), one_run));
        let parsed = ParsedCenc::parse_with_init(&media, &init).unwrap();
        check(media.clone(), &positions, parsed.clone());
        // Supported window API: decrypt only the contiguous mdat payload with
        // the same file-global jobs and its nonzero base_offset.
        let start = positions[0] as usize;
        let mut window = media[start..start + 57].to_vec();
        let mut keys = KeyMap::new();
        keys.insert(
            KID,
            bytes("2b7e151628aed2a6abf7158809cf4f3c")
                .try_into()
                .unwrap(),
        );
        parsed
            .decrypt_in_place(&mut window, &keys, start as u64)
            .unwrap();
        assert_eq!(
            window,
            [sample(0, false), sample(1, false), sample(2, false)].concat()
        );
    }
}

#[test]
fn clear_default_group_overrides_decrypt_distinct_keys_in_both_container_styles() {
    for fragmented in [false, true] {
        let mut descriptions = vec![1, 0, 0, 0, b's', b'e', b'i', b'g', 0, 0, 0, 0, 0, 0, 0, 3];
        for (protected, kid, iv) in [
            (false, KID, vec![]),
            (true, KID, bytes("000102030405060708090a0b0c0d0e0f")),
            (true, [2; 16], vec![0; 16]),
        ] {
            let mut entry = vec![0, 0x19, u8::from(protected), 0];
            entry.extend_from_slice(&kid);
            if protected {
                entry.push(16);
                entry.extend(iv);
            }
            descriptions.extend_from_slice(&(entry.len() as u32).to_be_bytes());
            descriptions.extend(entry);
        }
        let mut runs = vec![0, 0, 0, 0, b's', b'e', b'i', b'g', 0, 0, 0, 3];
        for index in 1..=3u32 {
            runs.extend_from_slice(&1u32.to_be_bytes());
            runs.extend_from_slice(&(index + if fragmented { 0x10000 } else { 0 }).to_be_bytes());
        }
        let groups = vec![unknown(b"sgpd", &descriptions), unknown(b"sbgp", &runs)];
        let mut payload = vec![0x11; 16];
        payload.extend(bytes("7649abac8119b246cee98e9b12e9197d"));
        // AES-128 zero-key/zero-IV CBC first block, independently frozen.
        payload.extend(bytes("66e94bd4ef8a2c3b884cfa59ca342b2e"));
        let mut data = boxed(b"mdat", &payload);
        let mut movie = if fragmented {
            movie(true, &[], vec![])
        } else {
            movie(false, &[8, 24, 40], groups.clone())
        };
        if fragmented {
            movie.mvex_box.as_mut().unwrap().trex_boxes[0].default_sample_size = 16;
            data.extend(fragment(&[8, 24, 40], 48, groups, false));
        } else {
            movie.trak_boxes[0].mdia_box.minf_box.stbl_box.stsz_box = StszBox::Fixed {
                sample_size: 16.try_into().unwrap(),
                sample_count: 3,
            };
        }
        let mut init = movie.encode_to_vec().unwrap();
        let tenc = init.windows(4).position(|v| v == b"tenc").unwrap();
        init[tenc + 10] = 0;
        let parsed = if fragmented {
            ParsedCenc::parse_with_init(&data, &init).unwrap()
        } else {
            data.extend(init);
            ParsedCenc::parse(&data).unwrap()
        };
        assert_eq!(
            parsed
                .jobs
                .iter()
                .map(|job| (job.offset, job.kid))
                .collect::<Vec<_>>(),
            [(24, KID), (40, [2; 16])]
        );
        let before = data.clone();
        let mut keys = KeyMap::new();
        keys.insert(
            KID,
            bytes("2b7e151628aed2a6abf7158809cf4f3c")
                .try_into()
                .unwrap(),
        );
        keys.insert([2; 16], [0; 16]);
        parsed.decrypt_in_place(&mut data, &keys, 0).unwrap();
        assert_eq!(&data[8..24], &[0x11; 16]);
        assert_eq!(&data[24..40], bytes("6bc1bee22e409f96e93d7e117393172a"));
        assert_eq!(&data[40..56], &[0; 16]);
        assert_eq!(data.len(), before.len());
        assert_eq!(
            common::top_level_box_layout(&data),
            common::top_level_box_layout(&before)
        );
    }
}

#[test]
fn missing_required_track_protection_fields_fail_before_decryption() {
    let init = movie(true, &[], vec![]).encode_to_vec().unwrap();
    let (mut media, positions) = data_layout(&[0, 1, 2], 0, false);
    media.extend(fragment(&positions, 0, inline(), false));
    for kind in [*b"schm", *b"schi", *b"tenc"] {
        let mut broken = init.clone();
        let position = broken.windows(4).position(|v| v == kind).unwrap();
        broken[position..position + 4].copy_from_slice(b"free");
        assert!(
            ParsedCenc::parse_with_init(&media, &broken).is_err(),
            "missing {kind:?}"
        );
    }
    let mut missing_tfhd = media.clone();
    let tfhd = missing_tfhd.windows(4).position(|v| v == b"tfhd").unwrap();
    missing_tfhd[tfhd..tfhd + 4].copy_from_slice(b"free");
    assert!(ParsedCenc::parse_with_init(&missing_tfhd, &init).is_err());
}
