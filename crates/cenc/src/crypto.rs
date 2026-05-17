use crate::cleanup::normalize_decrypted_fmp4;
use crate::errors::{CencError, Result};
use crate::types::{CbcPattern, CipherMode, DecryptJob, KeyMap, ParsedCenc, Subsample};
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

const AES_BLOCK_SIZE: usize = 16;

impl ParsedCenc {
    /// Decrypt all samples in `data` according to the parsed encryption metadata.
    pub fn decrypt_in_place(&self, data: &mut [u8], keys: &KeyMap, base_offset: u64) -> Result<()> {
        for job in &self.jobs {
            let key = keys
                .get_for_job(job)
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
            job.decrypt_sample(sample, key)?;
        }
        normalize_decrypted_fmp4(data)?;
        Ok(())
    }
}

impl DecryptJob {
    /// Decrypt one sample according to its scheme, IV, KID, optional pattern,
    /// and optional subsample table.
    ///
    /// CENC rule, paraphrased: when a sample has no subsample table, the
    /// entire sample is treated as one protected range. When a subsample table
    /// is present, each entry describes the next clear byte run followed by
    /// the next protected byte run. The described runs must not overrun the
    /// sample. Bytes that remain after the final entry are not part of a
    /// protected run and stay unchanged.
    pub(crate) fn decrypt_sample(&self, sample: &mut [u8], key: &[u8; 16]) -> Result<()> {
        let subsamples = if self.subsamples.is_empty() {
            vec![Subsample {
                clear_bytes: 0,
                encrypted_bytes: sample.len() as u32,
            }]
        } else {
            self.subsamples.clone()
        };
        validate_subsamples(sample.len(), &subsamples)?;

        match self.scheme.cipher_mode() {
            CipherMode::AesCtr => decrypt_ctr(sample, key, self.iv, self.pattern, &subsamples),
            CipherMode::AesCbc => decrypt_cbc(sample, key, self.iv, self.pattern, &subsamples),
        }
    }
}

fn validate_subsamples(sample_len: usize, subsamples: &[Subsample]) -> Result<()> {
    let mut offset = 0usize;
    for subsample in subsamples {
        offset = offset
            .checked_add(subsample.clear_bytes as usize)
            .ok_or(CencError::OutOfBounds)?;
        offset = offset
            .checked_add(subsample.encrypted_bytes as usize)
            .ok_or(CencError::OutOfBounds)?;
        if offset > sample_len {
            return Err(CencError::OutOfBounds);
        }
    }
    Ok(())
}

/// Decrypt AES-CTR sample data.
///
/// For `cenc`, AES-CTR is a byte stream over the concatenated protected bytes
/// in the sample. Clear ranges do not consume keystream, so the byte offset
/// advances only through encrypted bytes.
///
/// For `cens`, the crypt/skip pattern is one stream for the whole sample.
/// Clear subsample bytes are outside that stream. Skip blocks advance the
/// pattern position and remain unchanged, but they do not consume AES-CTR
/// keystream blocks because no cipher operation is performed for skipped
/// bytes.
fn decrypt_ctr(
    sample: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: Option<CbcPattern>,
    subsamples: &[Subsample],
) -> Result<()> {
    let mut offset = 0usize;
    let mut encrypted_byte_offset = 0u64;
    let mut pattern_state = CtrPatternState::default();
    for subsample in subsamples {
        offset += subsample.clear_bytes as usize;
        let encrypted_len = subsample.encrypted_bytes as usize;
        let end = offset + encrypted_len;
        if end > sample.len() {
            return Err(CencError::OutOfBounds);
        }
        let segment = &mut sample[offset..end];
        if let Some(pattern) = pattern {
            pattern_state = apply_ctr_pattern(segment, key, iv, pattern, pattern_state);
        } else {
            encrypted_byte_offset = apply_ctr_continuous(segment, key, iv, encrypted_byte_offset);
        }
        offset = end;
    }
    Ok(())
}

/// Decrypt AES-CBC sample data.
///
/// CBC-based CENC never decrypts a partial AES block. If a protected byte range
/// is not block-aligned, only complete leading blocks are decrypted and
/// trailing bytes remain unchanged in the sample.
///
/// For `cbcs`, pattern encryption is applied per subsample. Each protected
/// range starts a fresh CBC chain with the sample IV.
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
    let patterned = pattern.is_some();
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
            if patterned {
                previous = iv;
            }
            let segment = &mut sample[offset..offset + decrypt_len];
            let block_index = if patterned { 0 } else { encrypted_block_index };
            let result = apply_cbc_pattern(segment, &cipher, previous, pattern, block_index);
            previous = result.previous;
            encrypted_block_index = result.block_index;
        }
        offset = end;
    }
    Ok(())
}

/// Apply CTR crypt/skip pattern encryption to one protected byte range.
///
/// Pattern values count 16-byte blocks: crypt N blocks, then skip M blocks,
/// repeating. A zero-length cycle is treated as unpatterned encryption so old
/// or degenerate metadata still decrypts all blocks.
#[derive(Debug, Clone, Copy, Default)]
struct CtrPatternState {
    pattern_block_index: u64,
    crypt_block_index: u64,
}

fn apply_ctr_pattern(
    data: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: CbcPattern,
    mut state: CtrPatternState,
) -> CtrPatternState {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let cycle = pattern.cycle_length();
    let mut offset = 0usize;
    while offset < data.len() {
        let should_crypt = if cycle == 0 {
            true
        } else {
            let pos = (state.pattern_block_index % cycle as u64) as u8;
            pos < pattern.crypt_byte_block
        };
        let block_len = usize::min(AES_BLOCK_SIZE, data.len() - offset);
        state.pattern_block_index += 1;
        if should_crypt {
            let counter_block = build_ctr_block(iv, state.crypt_block_index);
            state.crypt_block_index += 1;
            let mut keystream = GenericArray::clone_from_slice(&counter_block);
            cipher.encrypt_block(&mut keystream);
            for i in 0..block_len {
                data[offset + i] ^= keystream[i];
            }
        }
        offset += AES_BLOCK_SIZE;
    }
    state
}

fn apply_ctr_continuous(
    data: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    mut byte_offset: u64,
) -> u64 {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut offset = 0usize;
    while offset < data.len() {
        let block_index = byte_offset / AES_BLOCK_SIZE as u64;
        let keystream_offset = (byte_offset % AES_BLOCK_SIZE as u64) as usize;
        let counter_block = build_ctr_block(iv, block_index);
        let mut keystream = GenericArray::clone_from_slice(&counter_block);
        cipher.encrypt_block(&mut keystream);
        let block_len = usize::min(AES_BLOCK_SIZE - keystream_offset, data.len() - offset);
        for i in 0..block_len {
            data[offset + i] ^= keystream[keystream_offset + i];
        }
        offset += block_len;
        byte_offset += block_len as u64;
    }
    byte_offset
}

/// Apply CBC crypt/skip pattern encryption to complete AES blocks.
///
/// CBC pattern encryption uses the same crypt/skip block cadence as CTR
/// pattern mode. Skipped blocks remain in the output unchanged and do not
/// update the CBC chaining value.
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
