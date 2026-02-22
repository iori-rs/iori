//! Streaming mdat decryption logic

use crate::error::{Result, V3Error};
use crate::parse::{FragmentMetadata, TrackMetadata};
use crate::types::{DecryptJob, KeyMap, Subsample};
use std::io::{Read, Write};

/// Decrypt mdat box content sample-by-sample in streaming fashion
///
/// This function processes the mdat content incrementally:
/// 1. Read one sample from input
/// 2. Decrypt it in-place using encryption metadata
/// 3. Write decrypted sample to output
/// 4. Repeat for all samples
///
/// Memory usage: O(largest_sample_size), not O(mdat_size)
pub fn decrypt_mdat<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    mdat_size: usize,
    fragment: &FragmentMetadata,
    track: &TrackMetadata,
    keys: &KeyMap,
) -> Result<()> {
    // Validate key exists
    let key = keys.get(&track.encryption_info.kid).ok_or_else(|| {
        V3Error::MissingKey(format!("No key for KID {:02x?}", track.encryption_info.kid))
    })?;

    // Validate sample counts match
    if fragment.sample_encryption.len() != fragment.sample_sizes.len() {
        return Err(V3Error::InvalidBoxStructure(format!(
            "Sample count mismatch: {} encryption entries but {} sample sizes",
            fragment.sample_encryption.len(),
            fragment.sample_sizes.len()
        )));
    }

    let mut total_processed = 0usize;

    // Process each sample
    for (i, &sample_size) in fragment.sample_sizes.iter().enumerate() {
        // Check bounds
        if total_processed + sample_size as usize > mdat_size {
            return Err(V3Error::InvalidBoxStructure(format!(
                "Sample {} size {} exceeds mdat bounds",
                i, sample_size
            )));
        }

        // Read sample from input
        let mut sample_data = vec![0u8; sample_size as usize];
        input.read_exact(&mut sample_data)?;

        // Get encryption info for this sample
        let enc_entry = &fragment.sample_encryption[i];

        // Build DecryptJob for this sample
        let job = DecryptJob {
            offset: 0, // In-memory offset (relative to sample buffer)
            size: sample_size,
            iv: enc_entry.iv,
            subsamples: enc_entry.subsamples.clone(),
            scheme: track.encryption_info.scheme,
            pattern: track.encryption_info.pattern,
            kid: track.encryption_info.kid,
        };

        // Decrypt sample in-place using existing crypto
        decrypt_sample_internal(&mut sample_data, &job, key)?;

        // Write decrypted sample to output
        output.write_all(&sample_data)?;

        total_processed += sample_size as usize;
    }

    // If there's remaining data in mdat (shouldn't happen with valid files),
    // just copy it through
    if total_processed < mdat_size {
        let remaining = mdat_size - total_processed;
        let mut buffer = vec![0u8; remaining.min(65536)];

        let mut copied = 0;
        while copied < remaining {
            let to_read = (remaining - copied).min(buffer.len());
            input.read_exact(&mut buffer[..to_read])?;
            output.write_all(&buffer[..to_read])?;
            copied += to_read;
        }
    }

    Ok(())
}

/// Internal function to decrypt a single sample
///
/// This is a wrapper around the crypto module's decrypt logic
/// Modified from crate::crypto::decrypt_sample to be standalone
fn decrypt_sample_internal(sample: &mut [u8], job: &DecryptJob, key: &[u8; 16]) -> Result<()> {
    // Handle empty subsamples - treat entire sample as encrypted
    let subsamples = if job.subsamples.is_empty() {
        vec![Subsample {
            clear_bytes: 0,
            encrypted_bytes: sample.len() as u32,
        }]
    } else {
        job.subsamples.clone()
    };

    // Call the appropriate decryption function based on scheme
    match job.scheme {
        crate::types::SchemeType::Cenc | crate::types::SchemeType::Cens => {
            decrypt_ctr(sample, key, job.iv, job.pattern, &subsamples)
        }
        crate::types::SchemeType::Cbc1 | crate::types::SchemeType::Cbcs => {
            decrypt_cbc(sample, key, job.iv, job.pattern, &subsamples)
        }
    }
}

/// CTR mode decryption (for CENC/CENS)
fn decrypt_ctr(
    sample: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: Option<crate::types::CbcPattern>,
    subsamples: &[Subsample],
) -> Result<()> {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};

    const AES_BLOCK_SIZE: usize = 16;

    let cipher = Aes128::new(aes::cipher::generic_array::GenericArray::from_slice(key));

    let (crypt_blocks, skip_blocks) = pattern
        .map(|p| (p.crypt_byte_block, p.skip_byte_block))
        .unwrap_or((0, 0));
    let cycle = crypt_blocks.saturating_add(skip_blocks);

    let mut offset = 0usize;
    let mut encrypted_block_index = 0u64;

    for subsample in subsamples {
        // Skip clear bytes
        offset += subsample.clear_bytes as usize;

        let encrypted_len = subsample.encrypted_bytes as usize;
        let end = offset + encrypted_len;

        if end > sample.len() {
            return Err(V3Error::CryptoError(crate::CencError::OutOfBounds));
        }

        let segment = &mut sample[offset..end];

        // Process encrypted segment block by block
        let mut seg_offset = 0usize;
        while seg_offset < segment.len() {
            let should_crypt = if cycle == 0 {
                true
            } else {
                let pos = (encrypted_block_index % cycle as u64) as u8;
                pos < crypt_blocks
            };

            // Build counter block
            let mut counter_block = iv;
            let counter = u64::from_be_bytes(counter_block[8..].try_into().unwrap());
            let next = counter.wrapping_add(encrypted_block_index);
            counter_block[8..].copy_from_slice(&next.to_be_bytes());

            encrypted_block_index += 1;

            if should_crypt {
                let mut keystream =
                    aes::cipher::generic_array::GenericArray::clone_from_slice(&counter_block);
                cipher.encrypt_block(&mut keystream);

                let block_len = usize::min(AES_BLOCK_SIZE, segment.len() - seg_offset);
                for i in 0..block_len {
                    segment[seg_offset + i] ^= keystream[i];
                }
            }

            seg_offset += AES_BLOCK_SIZE;
        }

        offset = end;
    }

    Ok(())
}

/// CBC mode decryption (for CBC1/CBCS)
fn decrypt_cbc(
    sample: &mut [u8],
    key: &[u8; 16],
    iv: [u8; 16],
    pattern: Option<crate::types::CbcPattern>,
    subsamples: &[Subsample],
) -> Result<()> {
    use aes::Aes128;
    use aes::cipher::{BlockDecrypt, KeyInit};

    const AES_BLOCK_SIZE: usize = 16;

    let cipher = Aes128::new(aes::cipher::generic_array::GenericArray::from_slice(key));

    let (crypt_blocks, skip_blocks) = pattern
        .map(|p| (p.crypt_byte_block, p.skip_byte_block))
        .unwrap_or((0, 0));
    let cycle = crypt_blocks.saturating_add(skip_blocks);

    let mut offset = 0usize;
    let mut previous = iv;
    let mut encrypted_block_index = 0u64;

    for subsample in subsamples {
        // Skip clear bytes
        offset += subsample.clear_bytes as usize;

        let encrypted_len = subsample.encrypted_bytes as usize;
        let remainder = encrypted_len % AES_BLOCK_SIZE;
        let decrypt_len = encrypted_len - remainder;
        let end = offset + encrypted_len;

        if end > sample.len() {
            return Err(V3Error::CryptoError(crate::CencError::OutOfBounds));
        }

        if decrypt_len > 0 {
            let segment = &mut sample[offset..offset + decrypt_len];

            // Process complete blocks
            for chunk in segment.chunks_mut(AES_BLOCK_SIZE) {
                let should_crypt = if cycle == 0 {
                    true
                } else {
                    let pos = (encrypted_block_index % cycle as u64) as u8;
                    pos < crypt_blocks
                };

                encrypted_block_index += 1;

                if !should_crypt {
                    continue;
                }

                let mut ciphertext = [0u8; AES_BLOCK_SIZE];
                ciphertext.copy_from_slice(chunk);

                let mut block =
                    aes::cipher::generic_array::GenericArray::clone_from_slice(&ciphertext);
                cipher.decrypt_block(&mut block);

                for i in 0..AES_BLOCK_SIZE {
                    chunk[i] = block[i] ^ previous[i];
                }

                previous.copy_from_slice(&ciphertext);
            }
        }

        offset = end;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{SampleEncryptionEntry, TrackEncryptionInfo};
    use crate::types::{CbcPattern, SchemeType};
    use std::io::Cursor;

    #[test]
    fn test_decrypt_sample_cenc_no_subsamples() {
        // Simple test: fully encrypted sample with CTR mode
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];

        // Create a sample with some data
        let mut sample_data = vec![0x42u8; 32]; // 2 AES blocks

        let job = DecryptJob {
            offset: 0,
            size: 32,
            iv,
            subsamples: vec![], // Empty = fully encrypted
            scheme: SchemeType::Cenc,
            pattern: None,
            kid: [0u8; 16],
        };

        // Decrypt should succeed
        let result = decrypt_sample_internal(&mut sample_data, &job, &key);
        assert!(result.is_ok());

        // Data should be modified (decrypted)
        assert_ne!(sample_data, vec![0x42u8; 32]);
    }

    #[test]
    fn test_decrypt_mdat_sample_count_mismatch() {
        let mut keys = std::collections::HashMap::new();
        keys.insert([0u8; 16], [1u8; 16]);

        let fragment = FragmentMetadata {
            track_id: 1,
            sample_encryption: vec![SampleEncryptionEntry {
                iv: [0u8; 16],
                subsamples: vec![],
            }],
            sample_sizes: vec![100, 200], // 2 sizes but only 1 encryption entry
            data_offset: 0,
        };

        let track = TrackMetadata {
            track_id: 1,
            encryption_info: TrackEncryptionInfo {
                is_protected: 1,
                iv_size: 16,
                kid: [0u8; 16],
                scheme: SchemeType::Cenc,
                pattern: None,
                constant_iv: None,
            },
        };

        let mut input = Cursor::new(vec![0u8; 300]);
        let mut output = Vec::new();

        let result = decrypt_mdat(&mut input, &mut output, 300, &fragment, &track, &keys);

        assert!(result.is_err());
    }
}
