//! Knowledge-derived mechanism tests K-01..K-09, separate from ISO eligibility.
//! Frozen AES vectors: NIST SP 800-38A F.2.1 and F.5.1,
//! https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
//! Pattern sweeps explicitly exercise a declared selection map. In particular,
//! 0:0 and 0:N are robustness interpretations, not claims of valid ISO metadata.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use iori_cenc::{CbcPattern, CencError, DecryptJob, KeyMap, ParsedCenc, SchemeType, Subsample};

const PLAIN: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"
);
const CTR: &str = concat!(
    "874d6191b620e3261bef6864990db6ce",
    "9806f66b7970fdff8617187bb9fffdff",
    "5ae4df3edbd5d35e5b4f09020db03eab",
    "1e031dda2fbe03d1792170a0f3009cee"
);
const CBC: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7"
);
const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const KID: [u8; 16] = [0x42; 16];

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn block(s: &str) -> [u8; 16] {
    bytes(s).try_into().unwrap()
}
fn keys() -> KeyMap {
    let mut keys = KeyMap::new();
    keys.insert(KID, block(KEY));
    keys
}
fn job(scheme: SchemeType, size: usize) -> DecryptJob {
    DecryptJob {
        track_id: None,
        offset: 0,
        size: size as u32,
        iv: block(if scheme.is_ctr() { CTR_IV } else { CBC_IV }),
        subsamples: vec![],
        scheme,
        pattern: None,
        kid: KID,
    }
}
fn decrypt(job: DecryptJob, data: &mut [u8]) {
    ParsedCenc { jobs: vec![job] }
        .decrypt_in_place(data, &keys(), 0)
        .unwrap();
}

// Encrypt a preselected, contiguous stream. This helper has no subsample or
// pattern knowledge: selection is constructed separately and scattered later.
fn stream_encrypt(plain: &[u8], scheme: SchemeType, iv: [u8; 16], key: [u8; 16]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut previous = iv;
    let mut result = Vec::with_capacity(plain.len());
    for (index, chunk) in plain.chunks(16).enumerate() {
        if scheme.is_ctr() {
            // Ordinary vectors never overflow the low word. Boundary behavior
            // has its own explicitly labeled interpretation test below.
            let counter = (u128::from_be_bytes(iv) + index as u128).to_be_bytes();
            let mut encrypted = GenericArray::clone_from_slice(&counter);
            cipher.encrypt_block(&mut encrypted);
            result.extend(chunk.iter().zip(encrypted).map(|(a, b)| a ^ b));
        } else {
            assert_eq!(chunk.len(), 16);
            let mut input = GenericArray::clone_from_slice(chunk);
            for (byte, prior) in input.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            cipher.encrypt_block(&mut input);
            previous.copy_from_slice(&input);
            result.extend_from_slice(&input);
        }
    }
    result
}

#[test]
fn nist_frozen_ctr_and_cbc_known_answers_anchor_reference_and_production() {
    for (scheme, frozen) in [(SchemeType::Cenc, CTR), (SchemeType::Cbc1, CBC)] {
        let job = job(scheme, 64);
        assert_eq!(
            stream_encrypt(&bytes(PLAIN), scheme, job.iv, block(KEY)),
            bytes(frozen)
        );
        let mut encrypted = bytes(frozen);
        decrypt(job, &mut encrypted);
        assert_eq!(encrypted, bytes(PLAIN));
    }
}

#[test]
fn k01_frozen_ctr_stream_survives_every_byte_subsample_split() {
    for split in 0..=64 {
        let mut encrypted = bytes(CTR);
        let mut expected = bytes(PLAIN);
        encrypted.splice(split..split, [0xca, 0xfe, 0xba]);
        expected.splice(split..split, [0xca, 0xfe, 0xba]);
        let mut job = job(SchemeType::Cenc, encrypted.len());
        job.subsamples = vec![
            Subsample {
                clear_bytes: 0,
                encrypted_bytes: split as u32,
            },
            Subsample {
                clear_bytes: 3,
                encrypted_bytes: (64 - split) as u32,
            },
        ];
        decrypt(job, &mut encrypted);
        assert_eq!(encrypted, expected, "split={split}");
    }
}

#[test]
fn k04_frozen_cbc_chain_crosses_clear_subsample_boundaries() {
    for split in [0, 16, 32, 48, 64] {
        let mut encrypted = bytes(CBC);
        let mut expected = bytes(PLAIN);
        encrypted.splice(split..split, [0x37; 7]);
        expected.splice(split..split, [0x37; 7]);
        let mut job = job(SchemeType::Cbc1, encrypted.len());
        job.subsamples = vec![
            Subsample {
                clear_bytes: 0,
                encrypted_bytes: split as u32,
            },
            Subsample {
                clear_bytes: 7,
                encrypted_bytes: (64 - split) as u32,
            },
        ];
        decrypt(job, &mut encrypted);
        assert_eq!(encrypted, expected, "split={split}");
    }
}

// Set construction instead of the implementation's mutable cycle cursor.
fn selected_positions(start: usize, blocks: usize, crypt: usize, skip: usize) -> Vec<usize> {
    let cycle = crypt + skip;
    let selected_blocks: Vec<_> = if cycle == 0 {
        (0..blocks).collect()
    } else {
        (0..blocks.div_ceil(cycle))
            .flat_map(|cycle_index| (0..crypt).map(move |within| cycle_index * cycle + within))
            .filter(|b| *b < blocks)
            .collect()
    };
    selected_blocks
        .into_iter()
        .flat_map(|b| start + b * 16..start + (b + 1) * 16)
        .collect()
}

#[test]
fn k03_k05_k07_all_256_patterns_all_tails_with_independent_selection_maps() {
    let mut tested = 0;
    for scheme in [SchemeType::Cens, SchemeType::Cbcs] {
        for crypt in 0..16 {
            for skip in 0..16 {
                for tail in 0..16 {
                    // zero, one, and multiple cycles; range two starts anew.
                    for blocks in [0, 1, 2 * (crypt + skip).max(1) + 1] {
                        let range_len = blocks * 16 + tail;
                        let size = 3 + range_len + 5 + range_len + 7;
                        let plain: Vec<u8> = (0..size).map(|i| (i * 37 + 11) as u8).collect();
                        let selections = [
                            selected_positions(3, blocks, crypt, skip),
                            selected_positions(3 + range_len + 5, blocks, crypt, skip),
                        ];
                        let mut encrypted = plain.clone();
                        let mut job = job(scheme, size);
                        job.pattern = Some(CbcPattern {
                            crypt_byte_block: crypt as u8,
                            skip_byte_block: skip as u8,
                        });
                        job.subsamples = vec![
                            Subsample {
                                clear_bytes: 3,
                                encrypted_bytes: range_len as u32,
                            },
                            Subsample {
                                clear_bytes: 5,
                                encrypted_bytes: range_len as u32,
                            },
                            Subsample {
                                clear_bytes: 7,
                                encrypted_bytes: 0,
                            },
                        ];
                        let streams = if scheme == SchemeType::Cens {
                            vec![selections.concat()]
                        } else {
                            selections.to_vec()
                        };
                        let mut selected = vec![false; size];
                        for positions in streams {
                            let gathered: Vec<_> = positions.iter().map(|p| plain[*p]).collect();
                            let ciphertext = stream_encrypt(&gathered, scheme, job.iv, block(KEY));
                            for (position, value) in positions.into_iter().zip(ciphertext) {
                                encrypted[position] = value;
                                selected[position] = true;
                            }
                        }
                        // Change every clear prefix, skip, and tail byte after
                        // encryption. It must neither chain nor consume CTR.
                        let mut expected = plain;
                        for i in 0..size {
                            if !selected[i] {
                                encrypted[i] ^= 0xa5;
                                expected[i] ^= 0xa5;
                            }
                        }
                        decrypt(job, &mut encrypted);
                        assert_eq!(
                            encrypted, expected,
                            "scheme={scheme:?}, pattern={crypt}:{skip}, blocks={blocks}, tail={tail}; zero crypt is robustness-only"
                        );
                        tested += 1;
                    }
                }
            }
        }
    }
    assert_eq!(tested, 2 * 256 * 16 * 3);
}

#[test]
fn k02_counter_carry_matches_frozen_nist_counter_inputs() {
    // NIST F.5.1 crosses ..feff -> ..ff00, probing byte carry.
    let mut encrypted = bytes(CTR);
    decrypt(job(SchemeType::Cenc, 64), &mut encrypted);
    assert_eq!(encrypted, bytes(PLAIN));
}

#[test]
fn k02_low_word_wrap_is_a_declared_robustness_interpretation() {
    // Low-64-bit modulo arithmetic is the current API interpretation, not an
    // assertion that counter exhaustion is permitted in a conforming file.
    let iv = block("123456789abcdef0fffffffffffffffe");
    let inputs = [
        block("123456789abcdef0fffffffffffffffe"),
        block("123456789abcdef0ffffffffffffffff"),
        block("123456789abcdef00000000000000000"),
    ];
    let cipher = Aes128::new(GenericArray::from_slice(&block(KEY)));
    let mut encrypted = Vec::new();
    for input in inputs {
        let mut stream = GenericArray::clone_from_slice(&input);
        cipher.encrypt_block(&mut stream);
        encrypted.extend_from_slice(&stream);
    }
    let mut job = job(SchemeType::Cenc, encrypted.len());
    job.iv = iv;
    decrypt(job, &mut encrypted);
    assert_eq!(encrypted, vec![0; 48]);
}

#[test]
fn k06_sample_state_resets_at_each_job_and_each_iv() {
    for scheme in [
        SchemeType::Cenc,
        SchemeType::Cens,
        SchemeType::Cbc1,
        SchemeType::Cbcs,
    ] {
        let mut jobs = vec![];
        let mut encrypted = vec![];
        for index in 0..3 {
            let mut job = job(scheme, 64);
            job.offset = index * 64;
            if index == 1 {
                job.iv[0] ^= 0x80;
            }
            encrypted.extend(stream_encrypt(&bytes(PLAIN), scheme, job.iv, block(KEY)));
            jobs.push(job);
        }
        ParsedCenc { jobs }
            .decrypt_in_place(&mut encrypted, &keys(), 0)
            .unwrap();
        assert_eq!(encrypted, bytes(PLAIN).repeat(3), "{scheme:?}");
    }
}

#[test]
fn k08_key_rotation_revisits_first_key_and_wrong_key_is_not_authenticated() {
    for scheme in [SchemeType::Cenc, SchemeType::Cbc1] {
        let mut jobs = vec![];
        let mut encrypted = vec![];
        let second_key = [0x91; 16];
        let mut keys = keys();
        keys.insert([0x43; 16], second_key);
        for index in 0..3 {
            let mut job = job(scheme, 64);
            job.offset = index * 64;
            let key = if index == 1 {
                job.kid = [0x43; 16];
                second_key
            } else {
                block(KEY)
            };
            encrypted.extend(stream_encrypt(&bytes(PLAIN), scheme, job.iv, key));
            jobs.push(job);
        }
        let parsed = ParsedCenc { jobs };
        let mut wrong = encrypted.clone();
        let mut wrong_keys = keys.clone();
        wrong_keys.insert([0x43; 16], block(KEY));
        parsed.decrypt_in_place(&mut wrong, &wrong_keys, 0).unwrap();
        assert_ne!(&wrong[64..128], &bytes(PLAIN));
        parsed.decrypt_in_place(&mut encrypted, &keys, 0).unwrap();
        assert_eq!(encrypted, bytes(PLAIN).repeat(3));
    }
}

#[test]
fn k09_missing_later_key_reports_kid_and_preserves_unprocessed_ciphertext() {
    // API behavior probe: decryption is incremental, not transactional. A
    // later failure leaves already decrypted samples changed.
    let first = job(SchemeType::Cenc, 64);
    let mut second = first.clone();
    second.offset = 64;
    second.kid = [0x99; 16];
    let mut data = bytes(CTR).repeat(2);
    let error = ParsedCenc {
        jobs: vec![first, second],
    }
    .decrypt_in_place(&mut data, &keys(), 0)
    .unwrap_err();
    assert!(matches!(error, CencError::MissingKey(kid) if kid == hex::encode([0x99;16])));
    assert_eq!(&data[..64], bytes(PLAIN));
    assert_eq!(&data[64..], bytes(CTR));
}

#[test]
fn k03_k04_frozen_pattern_trace_skips_blocks_and_restarts_ranges() {
    // Explicit byte coordinates: 1:1 selects blocks 0,2 in the first range
    // and block 0 in the second. The first range has a partial clear tail.
    // CENS consumes NIST blocks 0,1,2; CBCS restarts NIST CBC at the second
    // range, so its selected ciphertext is blocks 0,1,0.
    let positions = [3usize, 35, 61];
    for (scheme, frozen, indexes) in [
        (SchemeType::Cens, CTR, [0, 1, 2]),
        (SchemeType::Cbcs, CBC, [0, 1, 0]),
    ] {
        let mut encrypted = vec![0x55; 80];
        let mut expected = encrypted.clone();
        for (position, index) in positions.into_iter().zip(indexes) {
            encrypted[position..position + 16]
                .copy_from_slice(&bytes(frozen)[index * 16..(index + 1) * 16]);
            expected[position..position + 16]
                .copy_from_slice(&bytes(PLAIN)[index * 16..(index + 1) * 16]);
        }
        let mut job = job(scheme, 80);
        job.pattern = Some(CbcPattern {
            crypt_byte_block: 1,
            skip_byte_block: 1,
        });
        job.subsamples = vec![
            Subsample {
                clear_bytes: 3,
                encrypted_bytes: 51,
            },
            Subsample {
                clear_bytes: 7,
                encrypted_bytes: 19,
            },
        ];
        decrypt(job, &mut encrypted);
        assert_eq!(encrypted, expected, "{scheme:?}");
    }
}

#[test]
fn k07_unpatterned_all_partial_lengths_use_frozen_prefixes() {
    for size in 0..=64 {
        for (scheme, frozen) in [(SchemeType::Cenc, CTR), (SchemeType::Cbc1, CBC)] {
            let transformed_len = if scheme.is_ctr() {
                size
            } else {
                size / 16 * 16
            };
            let mut encrypted = bytes(frozen)[..transformed_len].to_vec();
            encrypted.extend_from_slice(&bytes(PLAIN)[transformed_len..size]);
            decrypt(job(scheme, size), &mut encrypted);
            assert_eq!(encrypted, bytes(PLAIN)[..size], "{scheme:?}, size={size}");
        }
    }
}

#[test]
fn k09_missing_first_key_does_not_mutate_sample() {
    let mut encrypted = bytes(CTR);
    let error = ParsedCenc {
        jobs: vec![job(SchemeType::Cenc, 64)],
    }
    .decrypt_in_place(&mut encrypted, &KeyMap::new(), 0)
    .unwrap_err();
    assert!(matches!(error, CencError::MissingKey(kid) if kid == hex::encode(KID)));
    assert_eq!(encrypted, bytes(CTR));
}
