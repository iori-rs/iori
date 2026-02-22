//! Decryption context for accumulating metadata during streaming

use crate::types::KeyMap;
use crate::error::{Result, V3Error};
use crate::parse::{FragmentMetadata, TrackMetadata};
use std::collections::HashMap;

/// Accumulates encryption metadata as we stream through the fMP4 file
#[derive(Debug)]
pub struct DecryptionContext {
    /// Track-level encryption metadata (from moov box)
    track_metadata: HashMap<u32, TrackMetadata>,

    /// Current fragment metadata (from most recent moof box)
    current_fragment: Option<FragmentMetadata>,

    /// Decryption keys (KID -> Key mapping)
    keys: KeyMap,
}

impl DecryptionContext {
    /// Create a new decryption context with the provided keys
    pub fn new(keys: KeyMap) -> Self {
        Self {
            track_metadata: HashMap::new(),
            current_fragment: None,
            keys,
        }
    }

    /// Set track metadata from moov box
    pub fn set_tracks(&mut self, tracks: Vec<TrackMetadata>) {
        for track in tracks {
            self.track_metadata.insert(track.track_id, track);
        }
    }

    /// Set current fragment metadata from moof box
    pub fn set_current_fragment(&mut self, fragment: FragmentMetadata) {
        self.current_fragment = Some(fragment);
    }

    /// Get current fragment metadata
    pub fn current_fragment(&self) -> Result<&FragmentMetadata> {
        self.current_fragment
            .as_ref()
            .ok_or_else(|| V3Error::MissingMetadata("No current fragment (moof before mdat)".to_string()))
    }

    /// Get track metadata by track ID
    pub fn track_metadata(&self, track_id: u32) -> Result<&TrackMetadata> {
        self.track_metadata
            .get(&track_id)
            .ok_or_else(|| V3Error::MissingMetadata(format!("No metadata for track {}", track_id)))
    }

    /// Get decryption keys
    pub fn keys(&self) -> &KeyMap {
        &self.keys
    }

    /// Clear current fragment after processing mdat
    pub fn clear_current_fragment(&mut self) {
        self.current_fragment = None;
    }

    /// Validate that we have all required keys for the current tracks
    pub fn validate_keys(&self) -> Result<()> {
        for (track_id, track) in &self.track_metadata {
            if !self.keys.contains_key(&track.encryption_info.kid) {
                return Err(V3Error::MissingKey(format!(
                    "No key for track {} with KID {:02x?}",
                    track_id, track.encryption_info.kid
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CbcPattern, SchemeType};
    use crate::parse::{SampleEncryptionEntry, TrackEncryptionInfo};

    #[test]
    fn test_context_set_and_get_tracks() {
        let mut ctx = DecryptionContext::new(HashMap::new());

        let track1 = TrackMetadata {
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

        ctx.set_tracks(vec![track1.clone()]);

        let retrieved = ctx.track_metadata(1).unwrap();
        assert_eq!(retrieved.track_id, 1);
    }

    #[test]
    fn test_context_fragment() {
        let mut ctx = DecryptionContext::new(HashMap::new());

        // Should error before fragment is set
        assert!(ctx.current_fragment().is_err());

        let fragment = FragmentMetadata {
            track_id: 1,
            sample_encryption: vec![],
            sample_sizes: vec![100, 200],
            data_offset: 4096,
        };

        ctx.set_current_fragment(fragment);

        let retrieved = ctx.current_fragment().unwrap();
        assert_eq!(retrieved.track_id, 1);
        assert_eq!(retrieved.data_offset, 4096);
    }

    #[test]
    fn test_context_validate_keys() {
        let kid = [1u8; 16];
        let key = [2u8; 16];

        let mut keys = HashMap::new();
        keys.insert(kid, key);

        let mut ctx = DecryptionContext::new(keys);

        let track = TrackMetadata {
            track_id: 1,
            encryption_info: TrackEncryptionInfo {
                is_protected: 1,
                iv_size: 16,
                kid,
                scheme: SchemeType::Cenc,
                pattern: None,
                constant_iv: None,
            },
        };

        ctx.set_tracks(vec![track]);

        // Should succeed - we have the key
        assert!(ctx.validate_keys().is_ok());
    }

    #[test]
    fn test_context_validate_keys_missing() {
        let ctx = DecryptionContext::new(HashMap::new());

        let track = TrackMetadata {
            track_id: 1,
            encryption_info: TrackEncryptionInfo {
                is_protected: 1,
                iv_size: 16,
                kid: [1u8; 16],
                scheme: SchemeType::Cenc,
                pattern: None,
                constant_iv: None,
            },
        };

        let mut ctx_with_track = DecryptionContext::new(HashMap::new());
        ctx_with_track.set_tracks(vec![track]);

        // Should fail - missing key
        assert!(ctx_with_track.validate_keys().is_err());
    }
}
