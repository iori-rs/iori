use shiguredo_mp4::aux::SampleTableAccessorError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CencError {
    #[error("mp4 decode error: {0}")]
    Mp4Error(#[from] shiguredo_mp4::Error),
    #[error("sample table error: {0}")]
    SampleTableError(#[from] SampleTableAccessorError),
    #[error("missing moov box")]
    MissingMoov,
    #[error("fragmented mp4 is not supported yet")]
    FragmentedMp4Unsupported,
    #[error("missing sample encryption box (senc)")]
    MissingSenc,
    #[error("unsupported scheme type: {0}")]
    UnsupportedScheme(String),
    #[error("missing tenc box in encrypted sample entry")]
    MissingTenc,
    #[error("missing sinf box in encrypted sample entry")]
    MissingSinf,
    #[error("missing schm box in encrypted sample entry")]
    MissingSchm,
    #[error("unsupported sample entry type: {0}")]
    UnsupportedSampleEntry(String),
    #[error("invalid tenc payload: {0}")]
    InvalidTenc(String),
    #[error("invalid senc payload: {0}")]
    InvalidSenc(String),
    #[error("invalid key hex: {0}")]
    InvalidKeyHex(String),
    #[error("invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("missing key for kid {0}")]
    MissingKey(String),
    #[error("unsupported sample groups (sbgp/sgpd) are present")]
    UnsupportedSampleGroups,
    #[error("senc sample count mismatch: expected {expected}, got {actual}")]
    SampleCountMismatch { expected: u32, actual: u32 },
    #[error("cbc encrypted bytes must be multiple of 16, got {0}")]
    InvalidCbcLength(usize),
    #[error("data range out of bounds")]
    OutOfBounds,
    #[error("mp4 metadata cleanup failed: {0}")]
    MetadataCleanup(String),
}

pub type Result<T> = std::result::Result<T, CencError>;
