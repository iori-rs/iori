use std::collections::HashMap;

use crate::errors::{CencError, Result};
use shiguredo_mp4::BoxType;

/// Map from Key ID (KID) or track ID to 16-byte decryption keys.
#[derive(Debug, Clone)]
pub struct KeyMap {
    kids: HashMap<[u8; 16], [u8; 16]>,
    tracks: HashMap<u32, [u8; 16]>,
}

impl KeyMap {
    pub fn new() -> Self {
        Self {
            kids: HashMap::new(),
            tracks: HashMap::new(),
        }
    }

    pub fn get(&self, kid: &[u8; 16]) -> Option<&[u8; 16]> {
        self.kids.get(kid)
    }

    pub fn get_for_job(&self, job: &DecryptJob) -> Option<&[u8; 16]> {
        job.track_id
            .and_then(|track_id| self.tracks.get(&track_id))
            .or_else(|| self.kids.get(&job.kid))
    }

    pub fn insert(&mut self, kid: [u8; 16], key: [u8; 16]) {
        self.kids.insert(kid, key);
    }

    pub fn insert_track(&mut self, track_id: u32, key: [u8; 16]) {
        self.tracks.insert(track_id, key);
    }

    pub fn contains_key(&self, kid: &[u8; 16]) -> bool {
        self.kids.contains_key(kid)
    }

    /// Build a `KeyMap` from track-id-or-KID:key string pairs.
    ///
    /// The left side may be either a decimal track ID or a 128-bit KID encoded
    /// as hex. This mirrors Bento4's `mp4decrypt --key <id>:<k>` behavior:
    /// track IDs are tried before KID lookup when both are available.
    pub fn from_hex_pairs<I, K, V>(keys: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut map = Self::new();
        for (id, key) in keys {
            let key_bytes = parse_hex_16(key.as_ref())?;
            match parse_key_id(id.as_ref())? {
                KeyId::Kid(kid) => map.insert(kid, key_bytes),
                KeyId::Track(track_id) => map.insert_track(track_id, key_bytes),
            }
        }
        Ok(map)
    }
}

impl Default for KeyMap {
    fn default() -> Self {
        Self::new()
    }
}

enum KeyId {
    Kid([u8; 16]),
    Track(u32),
}

fn parse_key_id(id: &str) -> Result<KeyId> {
    let cleaned = id.replace('-', "");
    if cleaned.len() == 32 {
        return parse_hex_16(id).map(KeyId::Kid);
    }
    id.parse::<u32>()
        .map(KeyId::Track)
        .map_err(|_| CencError::InvalidKeyHex(id.to_string()))
}

fn parse_hex_16(hex_str: &str) -> Result<[u8; 16]> {
    let cleaned = hex_str.replace('-', "");
    if cleaned.len() != 32 {
        return Err(CencError::InvalidKeyLength(cleaned.len() / 2));
    }
    let mut bytes = [0u8; 16];
    hex::decode_to_slice(&cleaned, &mut bytes)
        .map_err(|_| CencError::InvalidKeyHex(hex_str.to_string()))?;
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeType {
    Cenc,
    Cens,
    Cbc1,
    Cbcs,
    Sve1,
}

impl SchemeType {
    pub(crate) const fn box_type(self) -> BoxType {
        match self {
            Self::Cenc => BoxType::Normal(*b"cenc"),
            Self::Cens => BoxType::Normal(*b"cens"),
            Self::Cbc1 => BoxType::Normal(*b"cbc1"),
            Self::Cbcs => BoxType::Normal(*b"cbcs"),
            Self::Sve1 => BoxType::Normal(*b"sve1"),
        }
    }

    pub(crate) fn from_box_type(box_type: BoxType) -> Option<Self> {
        match box_type {
            box_type if box_type == Self::Cenc.box_type() => Some(Self::Cenc),
            box_type if box_type == Self::Cens.box_type() => Some(Self::Cens),
            box_type if box_type == Self::Cbc1.box_type() => Some(Self::Cbc1),
            box_type if box_type == Self::Cbcs.box_type() => Some(Self::Cbcs),
            box_type if box_type == Self::Sve1.box_type() => Some(Self::Sve1),
            _ => None,
        }
    }

    pub fn is_ctr(&self) -> bool {
        matches!(self, Self::Cenc | Self::Cens | Self::Sve1)
    }

    pub fn is_cbc(&self) -> bool {
        matches!(self, Self::Cbc1 | Self::Cbcs)
    }

    pub(crate) fn cipher_mode(&self) -> CipherMode {
        match self {
            Self::Cenc | Self::Cens | Self::Sve1 => CipherMode::AesCtr,
            Self::Cbc1 | Self::Cbcs => CipherMode::AesCbc,
        }
    }

    pub(crate) fn uses_pattern_encryption(&self) -> bool {
        matches!(self, Self::Cens | Self::Cbcs)
    }

    pub(crate) fn effective_pattern(&self, pattern: Option<CbcPattern>) -> Option<CbcPattern> {
        self.uses_pattern_encryption()
            .then_some(pattern)
            .flatten()
            .filter(CbcPattern::is_active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherMode {
    AesCtr,
    AesCbc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CbcPattern {
    pub crypt_byte_block: u8,
    pub skip_byte_block: u8,
}

impl CbcPattern {
    pub fn cycle_length(&self) -> u8 {
        self.crypt_byte_block.saturating_add(self.skip_byte_block)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.crypt_byte_block != 0 || self.skip_byte_block != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsample {
    pub clear_bytes: u16,
    pub encrypted_bytes: u32,
}

#[derive(Debug, Clone)]
pub struct DecryptJob {
    pub track_id: Option<u32>,
    pub offset: u64,
    pub size: u32,
    pub iv: [u8; 16],
    pub subsamples: Vec<Subsample>,
    pub scheme: SchemeType,
    pub pattern: Option<CbcPattern>,
    pub kid: [u8; 16],
}

/// Parsed CENC encryption metadata containing per-sample decrypt jobs.
#[derive(Debug, Clone)]
pub struct ParsedCenc {
    pub jobs: Vec<DecryptJob>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_map_accepts_any_hex_pair_iterator() {
        let kid = "00112233-4455-6677-8899-aabbccddeeff";
        let key = "0123456789abcdef0123456789abcdef";

        let map = KeyMap::from_hex_pairs([(kid, key)]).unwrap();

        assert_eq!(
            map.get(&[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]),
            Some(&[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])
        );
    }

    #[test]
    fn key_map_accepts_decimal_track_id_keys() {
        let key = "0123456789abcdef0123456789abcdef";

        let map = KeyMap::from_hex_pairs([("7", key)]).unwrap();
        let job = DecryptJob {
            track_id: Some(7),
            offset: 0,
            size: 0,
            iv: [0; 16],
            subsamples: Vec::new(),
            scheme: SchemeType::Cenc,
            pattern: None,
            kid: [0xff; 16],
        };

        assert_eq!(
            map.get_for_job(&job),
            Some(&[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])
        );
    }

    #[test]
    fn key_map_rejects_invalid_key_material() {
        assert!(matches!(
            KeyMap::from_hex_pairs([("00112233445566778899aabbccddeeff", "abcd")]),
            Err(CencError::InvalidKeyLength(2))
        ));

        assert!(matches!(
            KeyMap::from_hex_pairs([(
                "00112233445566778899aabbccddeeff",
                "zz23456789abcdef0123456789abcdef"
            )]),
            Err(CencError::InvalidKeyHex(_))
        ));
    }

    #[test]
    fn pattern_encryption_is_active_when_either_crypt_or_skip_is_non_zero() {
        assert_eq!(
            SchemeType::Cbcs.effective_pattern(Some(CbcPattern {
                crypt_byte_block: 1,
                skip_byte_block: 9,
            })),
            Some(CbcPattern {
                crypt_byte_block: 1,
                skip_byte_block: 9,
            })
        );
        assert_eq!(
            SchemeType::Cbcs.effective_pattern(Some(CbcPattern {
                crypt_byte_block: 10,
                skip_byte_block: 0,
            })),
            Some(CbcPattern {
                crypt_byte_block: 10,
                skip_byte_block: 0,
            })
        );
        assert_eq!(
            SchemeType::Cbcs.effective_pattern(Some(CbcPattern {
                crypt_byte_block: 0,
                skip_byte_block: 9,
            })),
            Some(CbcPattern {
                crypt_byte_block: 0,
                skip_byte_block: 9,
            })
        );
        assert_eq!(
            SchemeType::Cbcs.effective_pattern(Some(CbcPattern {
                crypt_byte_block: 0,
                skip_byte_block: 0,
            })),
            None
        );
        assert_eq!(
            SchemeType::Cbc1.effective_pattern(Some(CbcPattern {
                crypt_byte_block: 1,
                skip_byte_block: 9,
            })),
            None
        );
        assert_eq!(
            SchemeType::Sve1.effective_pattern(Some(CbcPattern {
                crypt_byte_block: 1,
                skip_byte_block: 9,
            })),
            None
        );
    }
}
