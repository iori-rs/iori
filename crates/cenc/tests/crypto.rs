mod common;
use common::read_mdat_payload;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use iori_cenc::{
    CbcPattern, DecryptJob, KeyMap, SchemeType, Subsample, decrypt_in_place, decrypt_mp4,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const KID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

fn key_map() -> KeyMap {
    let mut map = HashMap::new();
    map.insert(KID, KEY);
    map
}

#[test]
fn decrypt_cenc_roundtrip() {
    let plain = (0u8..128).collect::<Vec<_>>();
    let job = DecryptJob {
        offset: 0,
        size: plain.len() as u32,
        iv: [0x10; 16],
        subsamples: Vec::new(),
        scheme: SchemeType::Cenc,
        pattern: None,
        kid: KID,
    };

    let mut encrypted = plain.clone();
    decrypt_in_place(&mut encrypted, std::slice::from_ref(&job), &key_map(), 0).unwrap();
    decrypt_in_place(&mut encrypted, &[job], &key_map(), 0).unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_cens_pattern_roundtrip() {
    let plain = (0u8..96).collect::<Vec<_>>();
    let job = DecryptJob {
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
    decrypt_in_place(&mut encrypted, std::slice::from_ref(&job), &key_map(), 0).unwrap();
    decrypt_in_place(&mut encrypted, &[job], &key_map(), 0).unwrap();

    assert_eq!(plain, encrypted);
}

#[test]
fn decrypt_cbc1_roundtrip() {
    let plain = (0u8..64).collect::<Vec<_>>();
    let job = DecryptJob {
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
    decrypt_in_place(&mut encrypted, &[job], &key_map(), 0).unwrap();

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
    ];
    let job = DecryptJob {
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
    decrypt_in_place(&mut encrypted, &[job], &key_map(), 0).unwrap();

    assert_eq!(plain, encrypted);
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
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        let encrypted_len = subsample.encrypted_bytes as usize;
        let end = offset + encrypted_len;
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
    const WRITE_DECRYPTED_FILES: bool = true;
    let plain = fs::read(base.join("plain.mp4")).unwrap();
    let plain_mdat = read_mdat_payload(&plain).unwrap();

    let keys = HashMap::from([(
        "00112233445566778899aabbccddeeff".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    )]);

    for name in ["cenc.mp4", "cens.mp4", "cbc1.mp4", "cbcs.mp4"] {
        let encrypted = fs::read(base.join(name)).unwrap();
        let decrypted = decrypt_mp4(encrypted, &keys).unwrap();
        if WRITE_DECRYPTED_FILES {
            let dec_name = name.replace(".mp4", "_dec.mp4");
            fs::write(base.join(dec_name), &decrypted).unwrap();
        }
        let decrypted_mdat = read_mdat_payload(&decrypted).unwrap();
        assert_eq!(plain_mdat, decrypted_mdat, "mdat mismatch for {name}");
    }
}
