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
    pub fn from_hex_pairs(keys: &HashMap<String, String>) -> Result<Self> {
        let mut map = Self::new();
        for (kid, key) in keys {
            let kid_bytes = parse_hex_16(kid)?;
            let key_bytes = parse_hex_16(key)?;
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
    let bytes = hex::decode(&cleaned).map_err(|_| CencError::InvalidKeyHex(hex_str.to_string()))?;
    if bytes.len() != 16 {
        return Err(CencError::InvalidKeyLength(bytes.len()));
    }
    Ok(bytes.try_into().unwrap())
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
