use crate::cleanup::normalize_decrypted_fmp4;
use crate::errors::{CencError, Result};
use crate::types::{CbcPattern, DecryptJob, KeyMap, SchemeType, Subsample};
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

const AES_BLOCK_SIZE: usize = 16;

pub fn decrypt_in_place(
    data: &mut [u8],
    jobs: &[DecryptJob],
    keys: &KeyMap,
    base_offset: u64,
) -> Result<()> {
    for job in jobs {
        let key = keys
            .get(&job.kid)
            .ok_or_else(|| CencError::MissingKey(hex::encode(job.kid)))?;
        let job_start = job
            .offset
            .checked_sub(base_offset)
            .ok_or(CencError::OutOfBounds)?;
        let job_end = job_start + job.size as u64;
        if job_end > data.len() as u64 {
            return Err(CencError::OutOfBounds);
        }
        let start = job_start as usize;
        let end = job_end as usize;
        let sample = &mut data[start..end];
        decrypt_sample(sample, job, key)?;
    }
    normalize_decrypted_fmp4(data)?;
    Ok(())
}

fn decrypt_sample(sample: &mut [u8], job: &DecryptJob, key: &[u8; 16]) -> Result<()> {
    let subsamples = if job.subsamples.is_empty() {
        vec![Subsample {
            clear_bytes: 0,
            encrypted_bytes: sample.len() as u32,
        }]
    } else {
        job.subsamples.clone()
    };

    match job.scheme {
        SchemeType::Cenc | SchemeType::Cens => {
            decrypt_ctr(sample, key, job.iv, job.pattern, &subsamples)
        }
        SchemeType::Cbc1 | SchemeType::Cbcs => {
            decrypt_cbc(sample, key, job.iv, job.pattern, &subsamples)
        }
    }
}

fn decrypt_ctr(
    sample: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: Option<CbcPattern>,
    subsamples: &[Subsample],
) -> Result<()> {
    let mut offset = 0usize;
    let mut encrypted_block_index = 0u64;
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        let encrypted_len = subsample.encrypted_bytes as usize;
        let end = offset + encrypted_len;
        if end > sample.len() {
            return Err(CencError::OutOfBounds);
        }
        let segment = &mut sample[offset..end];
        encrypted_block_index = apply_ctr_pattern(segment, key, iv, pattern, encrypted_block_index);
        offset = end;
    }
    Ok(())
}

fn decrypt_cbc(
    sample: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: Option<CbcPattern>,
    subsamples: &[Subsample],
) -> Result<()> {
    let mut offset = 0usize;
    let mut previous = iv;
    let mut encrypted_block_index = 0u64;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        let encrypted_len = subsample.encrypted_bytes as usize;
        let remainder = encrypted_len % AES_BLOCK_SIZE;
        let decrypt_len = encrypted_len - remainder;
        let end = offset + encrypted_len;
        if end > sample.len() {
            return Err(CencError::OutOfBounds);
        }
        if decrypt_len > 0 {
            let segment = &mut sample[offset..offset + decrypt_len];
            let result =
                apply_cbc_pattern(segment, &cipher, previous, pattern, encrypted_block_index);
            previous = result.previous;
            encrypted_block_index = result.block_index;
        }
        offset = end;
    }
    Ok(())
}

fn apply_ctr_pattern(
    data: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: Option<CbcPattern>,
    mut block_index: u64,
) -> u64 {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let (crypt_blocks, skip_blocks) = pattern
        .map(|p| (p.crypt_byte_block, p.skip_byte_block))
        .unwrap_or((0, 0));
    let cycle = crypt_blocks.saturating_add(skip_blocks);
    let mut offset = 0usize;
    while offset < data.len() {
        let should_crypt = if cycle == 0 {
            true
        } else {
            let pos = (block_index % cycle as u64) as u8;
            pos < crypt_blocks
        };
        let counter_block = build_ctr_block(iv, block_index);
        block_index += 1;
        if should_crypt {
            let mut keystream = GenericArray::clone_from_slice(&counter_block);
            cipher.encrypt_block(&mut keystream);
            let block_len = usize::min(AES_BLOCK_SIZE, data.len() - offset);
            for i in 0..block_len {
                data[offset + i] ^= keystream[i];
            }
        }
        offset += AES_BLOCK_SIZE;
    }
    block_index
}

fn apply_cbc_pattern(
    data: &mut [u8],
    cipher: &Aes128,
    mut previous: [u8; 16],
    pattern: Option<CbcPattern>,
    mut block_index: u64,
) -> CbcResult {
    let (crypt_blocks, skip_blocks) = pattern
        .map(|p| (p.crypt_byte_block, p.skip_byte_block))
        .unwrap_or((0, 0));
    let cycle = crypt_blocks.saturating_add(skip_blocks);
    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
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
        let mut ciphertext = [0u8; AES_BLOCK_SIZE];
        ciphertext.copy_from_slice(chunk);
        let mut block = GenericArray::clone_from_slice(&ciphertext);
        cipher.decrypt_block(&mut block);
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] = block[i] ^ previous[i];
        }
        previous.copy_from_slice(&ciphertext);
    }
    CbcResult {
        previous,
        block_index,
    }
}

fn build_ctr_block(iv: [u8; 16], block_index: u64) -> [u8; 16] {
    let mut block = iv;
    let counter = u64::from_be_bytes(block[8..].try_into().unwrap());
    let next = counter.wrapping_add(block_index);
    block[8..].copy_from_slice(&next.to_be_bytes());
    block
}

#[derive(Debug)]
struct CbcResult {
    previous: [u8; 16],
    block_index: u64,
}
