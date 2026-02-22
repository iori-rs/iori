use std::collections::HashMap;

pub type KeyMap = HashMap<[u8; 16], [u8; 16]>;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CbcPattern {
    pub crypt_byte_block: u8,
    pub skip_byte_block: u8,
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

#[derive(Debug, Clone)]
pub struct ParsedCenc {
    pub jobs: Vec<DecryptJob>,
}
