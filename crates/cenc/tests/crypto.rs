mod common;
use common::read_mdat_payload;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use iori_cenc::{
    CbcPattern, CencError, DecryptJob, KeyMap, ParsedCenc, SchemeType, Subsample, decrypt_mp4,
    decrypt_mp4_with_initial_segment,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn find_box_start(data: &[u8], target: &[u8; 4]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + 8 <= data.len() {
        let size = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        if size < 8 || offset + size > data.len() {
            return None;
        }
        if &data[offset + 4..offset + 8] == target {
            return Some(offset);
        }
        offset += size;
    }
    None
}

const KID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

fn key_map() -> KeyMap {
    let mut map = KeyMap::new();
    map.insert(KID, KEY);
    map
}

fn decrypt_jobs(jobs: Vec<DecryptJob>) -> ParsedCenc {
    ParsedCenc { jobs }
}

#[test]
fn decrypt_cenc_roundtrip() {
    let plain = (0u8..128).collect::<Vec<_>>();
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: plain.len() as u32,
        iv: [0x10; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };

    let mut encrypted = plain.clone();
    decrypt_jobs(vec![job.clone()])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_prefers_track_id_key_before_kid_key() {
    let plain = (0u8..64).collect::<Vec<_>>();
    let job = DecryptJob {
        track_id: Some(7),
        offset: 0,
        size: plain.len() as u32,
        iv: [0x10; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };
    let mut keys = KeyMap::new();
    keys.insert_track(7, KEY);

    let mut encrypted = plain.clone();
    decrypt_jobs(vec![job.clone()])
        .decrypt_in_place(&mut encrypted, &keys, 0)
        .unwrap();
    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &keys, 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_cens_pattern_roundtrip() {
    let plain = (0u8..96).collect::<Vec<_>>();
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: plain.len() as u32,
        iv: [0x20; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cens,
        pattern: Some(CbcPattern {
            crypt_byte_block: 1,
            skip_byte_block: 2,
        }),
        kid: KID,
    };

    let mut encrypted = plain.clone();
    decrypt_jobs(vec![job.clone()])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_cbc1_roundtrip() {
    let plain = (0u8..64).collect::<Vec<_>>();
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: plain.len() as u32,
        iv: [0x33; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cbc1,
        pattern: None,
        kid: KID,
    };

    let mut encrypted = plain.clone();
    encrypt_cbc(&mut encrypted, job.pattern, job.iv);
    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_cbcs_pattern_with_subsamples() {
    let plain = (0u8..80).collect::<Vec<_>>();
    let subsamples = vec![
        Subsample {
            clear_bytes: 4,
            encrypted_bytes: 32,
        },
        Subsample {
            clear_bytes: 2,
            encrypted_bytes: 32,
        },
        Subsample {
            clear_bytes: 10,
            encrypted_bytes: 0,
        },
    ];
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: plain.len() as u32,
        iv: [0x44; 16],
        subsamples: subsamples.clone(),
        scheme: SchemeType::Cbcs,
        pattern: Some(CbcPattern {
            crypt_byte_block: 2,
            skip_byte_block: 1,
        }),
        kid: KID,
    };

    let mut encrypted = plain.clone();
    encrypt_cbc_with_subsamples(&mut encrypted, job.pattern, job.iv, &subsamples);
    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_keeps_trailing_bytes_after_subsample_table_clear() {
    let plain = (0u8..24).collect::<Vec<_>>();
    let subsamples = vec![Subsample {
        clear_bytes: 2,
        encrypted_bytes: 14,
    }];
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: plain.len() as u32,
        iv: [0x10; 16],
        subsamples: subsamples.clone(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };

    let mut encrypted = plain.clone();
    encrypt_ctr_continuous_with_subsamples(&mut encrypted, job.iv, &subsamples);
    assert_eq!(&plain[16..], &encrypted[16..]);

    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_cenc_keeps_ctr_keystream_position_across_subsamples() {
    let plain = (0u8..80).collect::<Vec<_>>();
    let subsamples = vec![
        Subsample {
            clear_bytes: 5,
            encrypted_bytes: 18,
        },
        Subsample {
            clear_bytes: 3,
            encrypted_bytes: 17,
        },
        Subsample {
            clear_bytes: 37,
            encrypted_bytes: 0,
        },
    ];
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: plain.len() as u32,
        iv: [0x55; 16],
        subsamples: subsamples.clone(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };

    let mut encrypted = plain.clone();
    encrypt_ctr_continuous_with_subsamples(&mut encrypted, job.iv, &subsamples);
    decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();

    assert_eq!(plain, encrypted);
}

fn encrypt_ctr_continuous_with_subsamples(data: &mut [u8], iv: [u8; 16], subsamples: &[Subsample]) {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let mut offset = 0usize;
    let mut encrypted_byte_offset = 0u64;
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        for byte in &mut data[offset..offset + subsample.encrypted_bytes as usize] {
            let block_index = encrypted_byte_offset / 16;
            let keystream_offset = (encrypted_byte_offset % 16) as usize;
            let mut counter_block = iv;
            let counter = u64::from_be_bytes(counter_block[8..].try_into().unwrap());
            counter_block[8..].copy_from_slice(&counter.wrapping_add(block_index).to_be_bytes());
            let mut keystream = GenericArray::clone_from_slice(&counter_block);
            cipher.encrypt_block(&mut keystream);
            *byte ^= keystream[keystream_offset];
            encrypted_byte_offset += 1;
        }
        offset += subsample.encrypted_bytes as usize;
    }
}

fn encrypt_cbc(data: &mut [u8], pattern: Option<CbcPattern>, iv: [u8; 16]) {
    encrypt_cbc_with_subsamples(
        data,
        pattern,
        iv,
        &[Subsample {
            clear_bytes: 0,
            encrypted_bytes: data.len() as u32,
        }],
    );
}

fn encrypt_cbc_with_subsamples(
    data: &mut [u8],
    pattern: Option<CbcPattern>,
    iv: [u8; 16],
    subsamples: &[Subsample],
) {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let (crypt_blocks, skip_blocks) = pattern
        .map(|p| (p.crypt_byte_block, p.skip_byte_block))
        .unwrap_or((0, 0));
    let cycle = crypt_blocks.saturating_add(skip_blocks);
    let mut offset = 0usize;
    let mut previous = iv;
    let mut block_index = 0u64;
    let patterned = pattern.is_some();
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        let encrypted_len = subsample.encrypted_bytes as usize;
        let end = offset + encrypted_len;
        if patterned {
            block_index = 0;
            previous = iv;
        }
        for chunk in data[offset..end].chunks_mut(16) {
            let should_crypt = if cycle == 0 {
                true
            } else {
                let pos = (block_index % cycle as u64) as u8;
                pos < crypt_blocks
            };
            block_index += 1;
            if !should_crypt {
                continue;
            }
            let mut block = GenericArray::clone_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= previous[i];
            }
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            previous.copy_from_slice(chunk);
        }
        offset = end;
    }
}

#[test]
fn decrypt_fmp4_fixtures_mdat_matches_plain() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fmp4");
    let plain = fs::read(base.join("plain.mp4")).unwrap();
    let plain_mdat = read_mdat_payload(&plain).unwrap();

    let keys = HashMap::from([(
        "00112233445566778899aabbccddeeff".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    )]);

    for name in ["cenc.mp4", "cens.mp4", "cbc1.mp4", "cbcs.mp4"] {
        let mut data = fs::read(base.join(name)).unwrap();
        decrypt_mp4(&mut data, &keys).unwrap();
        let decrypted_mdat = read_mdat_payload(&data).unwrap();
        assert_eq!(plain_mdat, decrypted_mdat, "mdat mismatch for {name}");
    }
}

#[test]
fn decrypt_fmp4_media_segment_with_initial_segment_reference() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fmp4");
    let plain = fs::read(base.join("plain.mp4")).unwrap();
    let encrypted = fs::read(base.join("cenc.mp4")).unwrap();
    let split = find_box_start(&encrypted, b"moof").unwrap();
    let plain_split = find_box_start(&plain, b"moof").unwrap();
    let plain_media = &plain[plain_split..];
    let init = &encrypted[..split];
    let encrypted_media = encrypted[split..].to_vec();

    let keys = HashMap::from([(
        "00112233445566778899aabbccddeeff".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    )]);

    let mut decrypted = encrypted_media.clone();
    decrypt_mp4_with_initial_segment(&mut decrypted, init, &keys).unwrap();

    assert_eq!(decrypted.len(), encrypted_media.len());
    assert_eq!(&decrypted[4..8], b"moof");
    assert_eq!(
        read_mdat_payload(plain_media).unwrap(),
        read_mdat_payload(&decrypted).unwrap()
    );

    assert!(matches!(
        decrypt_mp4(&mut encrypted_media.clone(), &keys),
        Err(CencError::MissingInitialSegment)
    ));

    assert!(matches!(
        decrypt_mp4_with_initial_segment(&mut encrypted_media.clone(), &[], &keys),
        Err(CencError::InitialSegmentMissingMoov)
    ));

    let styp = [0x00, 0x00, 0x00, 0x08, b's', b't', b'y', b'p'];
    let mut styp_prefixed_media = Vec::with_capacity(styp.len() + encrypted_media.len());
    styp_prefixed_media.extend_from_slice(&styp);
    styp_prefixed_media.extend_from_slice(&encrypted_media);

    let mut decrypted = styp_prefixed_media.clone();
    decrypt_mp4_with_initial_segment(&mut decrypted, init, &keys).unwrap();

    assert_eq!(decrypted.len(), styp_prefixed_media.len());
    assert_eq!(&decrypted[4..8], b"styp");
    assert_eq!(
        read_mdat_payload(plain_media).unwrap(),
        read_mdat_payload(&decrypted).unwrap()
    );
}

#[test]
fn decrypt_reports_missing_key_by_kid() {
    let mut encrypted = vec![0u8; 16];
    let job = DecryptJob {
        track_id: None,
        offset: 0,
        size: encrypted.len() as u32,
        iv: [0x10; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };

    let err = decrypt_jobs(vec![job])
        .decrypt_in_place(&mut encrypted, &KeyMap::new(), 0)
        .unwrap_err();

    assert!(matches!(err, CencError::MissingKey(kid) if kid == hex::encode(KID)));
}

#[test]
fn decrypt_rejects_jobs_outside_base_offset_window() {
    let mut encrypted = vec![0u8; 16];
    let job = DecryptJob {
        track_id: None,
        offset: 8,
        size: encrypted.len() as u32,
        iv: [0x10; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };

    assert!(matches!(
        decrypt_jobs(vec![job]).decrypt_in_place(&mut encrypted, &key_map(), 16),
        Err(CencError::OutOfBounds)
    ));
}
