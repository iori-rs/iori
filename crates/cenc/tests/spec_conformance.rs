//! CENC decryption conformance tests.
//!
//! These tests encode the normative behavior as small synthetic samples rather
//! than relying only on whole-file fixtures. Each test creates plaintext,
//! applies the corresponding encryption transform in the shape required by the
//! protection scheme, and then asserts that `iori-cenc` reverses that transform.
//!
//! The comments intentionally paraphrase the specification rules instead of
//! quoting them. They are written in the same level of detail as the rules the
//! implementation has to obey: which bytes are clear, which bytes are
//! protected, whether cipher state continues between subsamples, and how
//! pattern encryption advances.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use iori_cenc::{CbcPattern, DecryptJob, KeyMap, ParsedCenc, SchemeType, Subsample};

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

fn parsed(job: DecryptJob) -> ParsedCenc {
    ParsedCenc { jobs: vec![job] }
}

fn job(
    sample_len: usize,
    scheme: SchemeType,
    pattern: Option<CbcPattern>,
    subsamples: Vec<Subsample>,
) -> DecryptJob {
    DecryptJob {
        track_id: None,
        offset: 0,
        size: sample_len as u32,
        iv: [0x7a; 16],
        subsamples,
        scheme,
        pattern,
        kid: KID,
    }
}

/// For the `cenc` scheme, AES-CTR is applied to the concatenation of the
/// encrypted portions of a sample.
///
/// A subsample entry first skips `BytesOfClearData`, then protects
/// `BytesOfProtectedData`. Clear bytes are copied as-is and do not consume
/// counter-mode keystream. Protected bytes from later subsamples continue from
/// the next byte of the same CTR keystream used by earlier protected bytes in
/// the sample.
///
/// This test uses encrypted ranges whose lengths are not AES-block aligned so
/// a wrong implementation that restarts the counter at each subsample, or that
/// counts clear bytes as keystream bytes, will fail.
#[test]
fn cenc_ctr_subsamples_share_one_encrypted_byte_stream() {
    let plain = sample_bytes(83);
    let subsamples = vec![
        Subsample {
            clear_bytes: 5,
            encrypted_bytes: 21,
        },
        Subsample {
            clear_bytes: 7,
            encrypted_bytes: 18,
        },
        Subsample {
            clear_bytes: 32,
            encrypted_bytes: 0,
        },
    ];
    let job = job(plain.len(), SchemeType::Cenc, None, subsamples.clone());
    let mut encrypted = plain.clone();

    encrypt_ctr_continuous(&mut encrypted, job.iv, &subsamples);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// For the `cens` scheme, AES-CTR uses pattern encryption.
///
/// The pattern restarts at each protected subsample, while the CTR counter
/// continues across encrypted blocks. Skipped blocks do not consume keystream.
/// The first range ends after a crypt block; the next range must also begin
/// with a crypt block, using the next counter value.
#[test]
fn cens_ctr_pattern_restarts_across_subsamples_without_keystream_for_skips() {
    let plain = sample_bytes(114);
    let pattern = CbcPattern {
        crypt_byte_block: 1,
        skip_byte_block: 1,
    };
    let subsamples = vec![
        Subsample {
            clear_bytes: 3,
            encrypted_bytes: 16,
        },
        Subsample {
            clear_bytes: 17,
            encrypted_bytes: 64,
        },
    ];
    let job = job(
        plain.len(),
        SchemeType::Cens,
        Some(pattern),
        subsamples.clone(),
    );
    let mut encrypted = plain.clone();

    encrypt_ctr_pattern_subsamples(&mut encrypted, job.iv, pattern, &subsamples);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// CENS tails remain clear even in the crypt phase, and consume no counter.
/// Encrypt the selected complete blocks with the independent continuous CTR
/// helper so the expected ciphertext does not repeat the pattern algorithm.
#[test]
fn cens_partial_blocks_stay_clear_without_consuming_counter() {
    for pattern in [
        None,
        Some(CbcPattern {
            crypt_byte_block: 0,
            skip_byte_block: 0,
        }),
        Some(CbcPattern {
            crypt_byte_block: 2,
            skip_byte_block: 1,
        }),
    ] {
        for tail in 1..16 {
            let plain = sample_bytes(32 + tail);
            let subsamples = vec![
                Subsample {
                    clear_bytes: 0,
                    encrypted_bytes: (16 + tail) as u32,
                },
                Subsample {
                    clear_bytes: 0,
                    encrypted_bytes: 16,
                },
            ];
            let job = job(plain.len(), SchemeType::Cens, pattern, subsamples);
            let mut encrypted = plain.clone();
            encrypt_ctr_continuous(
                &mut encrypted,
                job.iv,
                &[
                    Subsample {
                        clear_bytes: 0,
                        encrypted_bytes: 16,
                    },
                    Subsample {
                        clear_bytes: tail as u16,
                        encrypted_bytes: 16,
                    },
                ],
            );
            parsed(job)
                .decrypt_in_place(&mut encrypted, &key_map(), 0)
                .unwrap();
            assert_eq!(plain, encrypted, "pattern={pattern:?}, tail={tail}");
        }
    }
}

#[test]
fn cbcs_zero_pattern_resets_chain_even_when_pattern_was_normalized_away() {
    for pattern in [
        None,
        Some(CbcPattern {
            crypt_byte_block: 0,
            skip_byte_block: 0,
        }),
    ] {
        let plain = sample_bytes(64);
        let subsamples = vec![
            Subsample {
                clear_bytes: 0,
                encrypted_bytes: 32,
            },
            Subsample {
                clear_bytes: 0,
                encrypted_bytes: 32,
            },
        ];
        let job = job(plain.len(), SchemeType::Cbcs, pattern, subsamples.clone());
        let mut encrypted = plain.clone();
        encrypt_cbc(&mut encrypted, job.iv, None, &subsamples, true);
        parsed(job)
            .decrypt_in_place(&mut encrypted, &key_map(), 0)
            .unwrap();
        assert_eq!(plain, encrypted);
    }
}

/// For the `cbc1` scheme, AES-CBC is applied without pattern encryption.
///
/// When subsample encryption is present, each protected range contributes its
/// complete AES blocks to one continuous CBC sequence for the sample. Clear
/// bytes separate protected ranges in the file layout, but they do not reset
/// the CBC chaining value. The first encrypted block uses the sample IV, and
/// each following encrypted block uses the previous ciphertext block as the
/// chaining value, even when that previous block came from another subsample.
///
/// This test makes the second subsample depend on the final ciphertext block of
/// the first subsample. An implementation that resets CBC per subsample would
/// decrypt the second protected range incorrectly.
#[test]
fn cbc1_subsamples_share_one_cbc_chain() {
    let plain = sample_bytes(74);
    let subsamples = vec![
        Subsample {
            clear_bytes: 4,
            encrypted_bytes: 32,
        },
        Subsample {
            clear_bytes: 6,
            encrypted_bytes: 32,
        },
    ];
    let job = job(plain.len(), SchemeType::Cbc1, None, subsamples.clone());
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, None, &subsamples, false);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// CBC-based CENC schemes operate only on complete AES blocks.
///
/// A protected byte count is allowed to include bytes after the final complete
/// 16-byte block. Those trailing bytes remain unchanged by CBC encryption and
/// decryption because there is no partial-block CBC transform in this scheme.
///
/// This test gives one subsample 35 protected bytes. Only the first 32 bytes
/// are encrypted as two AES-CBC blocks; the final three protected bytes are
/// carried through unchanged and must still match the original sample.
#[test]
fn cbc1_does_not_decrypt_partial_trailing_blocks() {
    let plain = sample_bytes(43);
    let subsamples = vec![Subsample {
        clear_bytes: 8,
        encrypted_bytes: 35,
    }];
    let job = job(plain.len(), SchemeType::Cbc1, None, subsamples.clone());
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, None, &subsamples, false);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// CBC partial-block handling is local to each protected subsample range.
///
/// If one protected range ends with bytes that do not make a complete AES
/// block, those bytes are left unchanged and are not used as CBC chaining
/// input. A following protected range still continues from the most recent
/// complete encrypted CBC block when the scheme is `cbc1`.
///
/// This test puts a partial protected tail before a later protected range. It
/// catches implementations that either try to decrypt the partial tail or use
/// those tail bytes as the previous CBC block for the next range.
#[test]
fn cbc1_partial_tail_does_not_affect_later_subsample_chain() {
    let plain = sample_bytes(78);
    let subsamples = vec![
        Subsample {
            clear_bytes: 4,
            encrypted_bytes: 35,
        },
        Subsample {
            clear_bytes: 7,
            encrypted_bytes: 32,
        },
    ];
    let job = job(plain.len(), SchemeType::Cbc1, None, subsamples.clone());
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, None, &subsamples, false);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// For the `cbcs` scheme, AES-CBC uses pattern encryption per protected range.
///
/// The crypt/skip pattern is counted in 16-byte blocks. Encrypted blocks update
/// the CBC chaining value; skipped blocks remain unchanged and do not become
/// the next chaining value. At the start of each protected subsample range, the
/// CBC chain is initialized from the sample IV and the pattern block count
/// starts again from zero.
///
/// This test uses two protected ranges and a 1:2 pattern. It proves both reset
/// requirements: the second range must start with a crypt block, and that crypt
/// block must be chained from the sample IV rather than from the first range.
#[test]
fn cbcs_resets_cbc_chain_and_pattern_for_each_subsample() {
    let plain = sample_bytes(136);
    let pattern = CbcPattern {
        crypt_byte_block: 1,
        skip_byte_block: 2,
    };
    let subsamples = vec![
        Subsample {
            clear_bytes: 8,
            encrypted_bytes: 48,
        },
        Subsample {
            clear_bytes: 16,
            encrypted_bytes: 48,
        },
        Subsample {
            clear_bytes: 16,
            encrypted_bytes: 0,
        },
    ];
    let job = job(
        plain.len(),
        SchemeType::Cbcs,
        Some(pattern),
        subsamples.clone(),
    );
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, Some(pattern), &subsamples, true);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// Skipped `cbcs` pattern blocks are not encrypted and do not update CBC state.
///
/// Pattern encryption chooses whether each complete 16-byte block is protected
/// or left clear. For CBC pattern schemes, only protected blocks participate in
/// the CBC chain. A skipped block remains byte-for-byte unchanged and must not
/// become the previous ciphertext block for the next protected block.
///
/// This test uses one protected range with a 1:1 pattern over three blocks:
/// block 0 is encrypted, block 1 is skipped, and block 2 is encrypted. Block 2
/// must be chained from block 0's ciphertext, not from the skipped block 1
/// bytes.
#[test]
fn cbcs_skipped_pattern_blocks_do_not_update_cbc_chain() {
    let plain = sample_bytes(48);
    let pattern = CbcPattern {
        crypt_byte_block: 1,
        skip_byte_block: 1,
    };
    let subsamples = vec![Subsample {
        clear_bytes: 0,
        encrypted_bytes: 48,
    }];
    let job = job(
        plain.len(),
        SchemeType::Cbcs,
        Some(pattern),
        subsamples.clone(),
    );
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, Some(pattern), &subsamples, true);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// A `cbcs` pattern with zero skipped blocks is still pattern encryption.
///
/// The 10:0 pattern is a common pattern value: every block is encrypted, but
/// the `cbcs` subsample rule still applies. Each protected range starts a fresh
/// CBC chain from the sample IV. Treating 10:0 as "no pattern" accidentally
/// turns `cbcs` into `cbc1` and carries CBC state across subsamples.
#[test]
fn cbcs_zero_skip_pattern_still_resets_each_subsample() {
    let plain = sample_bytes(72);
    let pattern = CbcPattern {
        crypt_byte_block: 10,
        skip_byte_block: 0,
    };
    let subsamples = vec![
        Subsample {
            clear_bytes: 4,
            encrypted_bytes: 32,
        },
        Subsample {
            clear_bytes: 4,
            encrypted_bytes: 32,
        },
    ];
    let job = job(
        plain.len(),
        SchemeType::Cbcs,
        Some(pattern),
        subsamples.clone(),
    );
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, Some(pattern), &subsamples, true);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// A `cbcs` pattern with zero encrypted blocks leaves every pattern block clear.
///
/// This is degenerate, but it follows directly from the pattern counts: zero
/// crypt blocks followed by skipped blocks means no complete block is protected.
/// It also protects against falling back to unpatterned CBC when only one of
/// the pattern counters is non-zero.
#[test]
fn cbcs_zero_crypt_pattern_leaves_blocks_clear() {
    let plain = sample_bytes(32);
    let pattern = CbcPattern {
        crypt_byte_block: 0,
        skip_byte_block: 10,
    };
    let subsamples = vec![Subsample {
        clear_bytes: 0,
        encrypted_bytes: 32,
    }];
    let job = job(
        plain.len(),
        SchemeType::Cbcs,
        Some(pattern),
        subsamples.clone(),
    );
    let mut encrypted = plain.clone();

    encrypt_cbc(&mut encrypted, job.iv, Some(pattern), &subsamples, true);
    assert_eq!(plain, encrypted);

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// If a sample has no subsample table, the whole sample is one protected
/// region.
///
/// In that layout there are no clear byte counts to apply. The parser and
/// decryptor must behave as if the sample had a single subsample entry with
/// zero clear bytes and protected byte count equal to the sample size.
///
/// This test leaves `subsamples` empty on the decrypt job and encrypts the
/// entire sample as one CTR stream.
#[test]
fn absent_subsample_table_means_whole_sample_is_encrypted() {
    let plain = sample_bytes(64);
    let job = job(plain.len(), SchemeType::Cenc, None, Vec::new());
    let mut encrypted = plain.clone();

    encrypt_ctr_continuous(
        &mut encrypted,
        job.iv,
        &[Subsample {
            clear_bytes: 0,
            encrypted_bytes: plain.len() as u32,
        }],
    );

    parsed(job)
        .decrypt_in_place(&mut encrypted, &key_map(), 0)
        .unwrap();
    assert_eq!(plain, encrypted);
}

/// Produce deterministic non-repeating test data.
///
/// The bytes are intentionally not all zero so mistakes in clear/protected
/// ranges, CBC chaining, or skipped pattern blocks are visible in equality
/// checks without needing external fixtures.
fn sample_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| index.wrapping_mul(37).wrapping_add(11) as u8)
        .collect()
}

/// Reference encryptor for unpatterned AES-CTR sample encryption.
///
/// The keystream byte offset advances only while processing protected bytes.
/// Clear portions move the file offset forward but leave the CTR byte position
/// unchanged, matching the rule that subsample clear data is outside the
/// encrypted byte stream.
fn encrypt_ctr_continuous(data: &mut [u8], iv: [u8; 16], subsamples: &[Subsample]) {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let mut offset = 0usize;
    let mut encrypted_byte_offset = 0u64;
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        for byte in &mut data[offset..offset + subsample.encrypted_bytes as usize] {
            let block_index = encrypted_byte_offset / 16;
            let keystream_offset = (encrypted_byte_offset % 16) as usize;
            let mut keystream = GenericArray::clone_from_slice(&ctr_block(iv, block_index));
            cipher.encrypt_block(&mut keystream);
            *byte ^= keystream[keystream_offset];
            encrypted_byte_offset += 1;
        }
        offset += subsample.encrypted_bytes as usize;
    }
}

/// Reference encryptor for AES-CTR pattern encryption.
///
/// The pattern block index restarts at each protected range in one sample.
/// Skip blocks leave bytes unchanged and do not consume CTR keystream, matching
/// the pattern stream-cipher behavior used by CENS.
fn encrypt_ctr_pattern_subsamples(
    data: &mut [u8],
    iv: [u8; 16],
    pattern: CbcPattern,
    subsamples: &[Subsample],
) {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let cycle = pattern.cycle_length();
    let mut offset = 0usize;
    let mut crypt_block_index = 0u64;
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        let encrypted_end = offset + subsample.encrypted_bytes as usize;
        let mut pattern_block_index = 0u64;
        while encrypted_end - offset >= 16 {
            let should_crypt = cycle == 0
                || ((pattern_block_index % cycle as u64) as u8) < pattern.crypt_byte_block;
            let block_len = usize::min(16, encrypted_end - offset);
            pattern_block_index += 1;
            if should_crypt {
                let mut keystream =
                    GenericArray::clone_from_slice(&ctr_block(iv, crypt_block_index));
                crypt_block_index += 1;
                cipher.encrypt_block(&mut keystream);
                for i in 0..block_len {
                    data[offset + i] ^= keystream[i];
                }
            }
            offset += block_len;
        }
        offset = encrypted_end;
    }
}

/// Build the AES-CTR input block for a sample IV and block index.
///
/// The low 64 bits are treated as the block counter and are incremented in
/// big-endian order. The high 64 bits remain the IV prefix selected from the
/// sample encryption metadata.
fn ctr_block(iv: [u8; 16], block_index: u64) -> [u8; 16] {
    let mut block = iv;
    let counter = u64::from_be_bytes(block[8..].try_into().unwrap());
    block[8..].copy_from_slice(&counter.wrapping_add(block_index).to_be_bytes());
    block
}

/// Reference encryptor for AES-CBC sample encryption.
///
/// With `reset_per_subsample = false`, the function models `cbc1`: all
/// complete encrypted blocks in the sample share one CBC chain. With
/// `reset_per_subsample = true`, it models `cbcs`: each protected subsample
/// range starts from the sample IV and from pattern block index zero.
///
/// Only complete 16-byte blocks are encrypted. Any remaining protected bytes at
/// the end of a range are left unchanged, matching the partial-block rule for
/// CBC-based CENC protection.
fn encrypt_cbc(
    data: &mut [u8],
    iv: [u8; 16],
    pattern: Option<CbcPattern>,
    subsamples: &[Subsample],
    reset_per_subsample: bool,
) {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let (crypt_blocks, skip_blocks) = pattern
        .map(|pattern| (pattern.crypt_byte_block, pattern.skip_byte_block))
        .unwrap_or((0, 0));
    let cycle = crypt_blocks.saturating_add(skip_blocks);
    let mut offset = 0usize;
    let mut previous = iv;
    let mut block_index = 0u64;

    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        if reset_per_subsample {
            previous = iv;
            block_index = 0;
        }
        let encrypted_len = subsample.encrypted_bytes as usize;
        let full_block_len = encrypted_len - encrypted_len % 16;
        let encrypted_end = offset + full_block_len;
        while encrypted_end - offset >= 16 {
            let should_crypt = cycle == 0 || ((block_index % cycle as u64) as u8) < crypt_blocks;
            block_index += 1;
            if should_crypt {
                let mut block = GenericArray::clone_from_slice(&data[offset..offset + 16]);
                for i in 0..16 {
                    block[i] ^= previous[i];
                }
                cipher.encrypt_block(&mut block);
                data[offset..offset + 16].copy_from_slice(&block);
                previous.copy_from_slice(&block);
            }
            offset += 16;
        }
        offset += encrypted_len - full_block_len;
    }
}
