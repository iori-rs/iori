//! Streaming mdat decryption logic

use crate::error::{Result, V3Error};
use crate::parse::{FragmentMetadata, TrackMetadata};
use crate::types::{DecryptJob, KeyMap};
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
    first_sample_offset: usize,
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

    if first_sample_offset > mdat_size {
        return Err(V3Error::InvalidBoxStructure(format!(
            "First sample offset {} exceeds mdat size {}",
            first_sample_offset, mdat_size
        )));
    }

    copy_passthrough(input, output, first_sample_offset)?;
    let mut total_processed = first_sample_offset;

    // Process each sample
    for (i, &sample_size) in fragment.sample_sizes.iter().enumerate() {
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
    copy_passthrough(input, output, mdat_size - total_processed)?;

    Ok(())
}

fn copy_passthrough<R: Read, W: Write>(input: &mut R, output: &mut W, size: usize) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let mut remaining = size;
    let mut buffer = vec![0u8; remaining.min(65536)];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len());
        input.read_exact(&mut buffer[..to_read])?;
        output.write_all(&buffer[..to_read])?;
        remaining -= to_read;
    }
    Ok(())
}

/// Internal function to decrypt a single sample
///
/// This is a wrapper around the crypto module's decrypt logic
/// Modified from crate::crypto::decrypt_sample to be standalone
fn decrypt_sample_internal(sample: &mut [u8], job: &DecryptJob, key: &[u8; 16]) -> Result<()> {
    crate::crypto::decrypt_sample(sample, job, key).map_err(V3Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::boxes::{SampleEncryptionEntry, TrackEncryptionInfo};
    use crate::types::SchemeType;
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

        let result = decrypt_mdat(&mut input, &mut output, 300, &fragment, &track, &keys, 0);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_mdat_preserves_prefix_before_first_sample() {
        let mut keys = std::collections::HashMap::new();
        keys.insert([0u8; 16], [1u8; 16]);

        let fragment = FragmentMetadata {
            track_id: 1,
            sample_encryption: vec![SampleEncryptionEntry {
                iv: [2u8; 16],
                subsamples: vec![],
            }],
            sample_sizes: vec![16],
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

        let prefix = vec![0xaau8; 4];
        let mut input = Cursor::new([prefix.as_slice(), &[0x42u8; 16]].concat());
        let mut output = Vec::new();

        decrypt_mdat(&mut input, &mut output, 20, &fragment, &track, &keys, 4).unwrap();

        assert_eq!(&output[..4], prefix.as_slice());
        assert_ne!(&output[4..], &[0x42u8; 16]);
    }
}
