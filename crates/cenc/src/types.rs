use std::collections::HashMap;

use crate::errors::{CencError, Result};

/// Map from Key ID (KID) to decryption key, both 16 bytes.
#[derive(Debug, Clone)]
pub struct KeyMap(HashMap<[u8; 16], [u8; 16]>);

impl KeyMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&self, kid: &[u8; 16]) -> Option<&[u8; 16]> {
        self.0.get(kid)
    }

    pub fn insert(&mut self, kid: [u8; 16], key: [u8; 16]) {
        self.0.insert(kid, key);
    }

    pub fn contains_key(&self, kid: &[u8; 16]) -> bool {
        self.0.contains_key(kid)
    }

    /// Build a `KeyMap` from hex-encoded KID:Key string pairs.
    pub fn from_hex_pairs<I, K, V>(keys: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut map = Self::new();
        for (kid, key) in keys {
            let kid_bytes = parse_hex_16(kid.as_ref())?;
            let key_bytes = parse_hex_16(key.as_ref())?;
            map.insert(kid_bytes, key_bytes);
        }
        Ok(map)
    }
}

impl Default for KeyMap {
    fn default() -> Self {
        Self::new()
    }
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
}

impl SchemeType {
    pub(crate) fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        match &bytes {
            b"cenc" => Some(Self::Cenc),
            b"cens" => Some(Self::Cens),
            b"cbc1" => Some(Self::Cbc1),
            b"cbcs" => Some(Self::Cbcs),
            _ => None,
        }
    }

    pub fn is_ctr(&self) -> bool {
        matches!(self, Self::Cenc | Self::Cens)
    }

    pub fn is_cbc(&self) -> bool {
        matches!(self, Self::Cbc1 | Self::Cbcs)
    }

    pub(crate) fn cipher_mode(&self) -> CipherMode {
        match self {
            Self::Cenc | Self::Cens => CipherMode::AesCtr,
            Self::Cbc1 | Self::Cbcs => CipherMode::AesCbc,
        }
    }

    pub(crate) fn uses_pattern_encryption(&self) -> bool {
        matches!(self, Self::Cens | Self::Cbcs)
    }

    pub(crate) fn effective_pattern(&self, pattern: Option<CbcPattern>) -> Option<CbcPattern> {
        self.uses_pattern_encryption().then_some(pattern).flatten()
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsample {
    pub clear_bytes: u16,
    pub encrypted_bytes: u32,
}

#[derive(Debug, Clone)]
pub struct DecryptJob {
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
}
