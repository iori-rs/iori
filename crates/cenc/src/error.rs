use std::fmt;

/// V3-specific errors for streaming CENC decryption
#[derive(Debug)]
pub enum V3Error {
    /// I/O error during reading or writing
    Io(std::io::Error),

    /// Unexpected end of file during parsing
    UnexpectedEof,

    /// Missing required metadata (e.g., tenc before mdat)
    MissingMetadata(String),

    /// Missing decryption key for a KID
    MissingKey(String),

    /// Invalid box structure or hierarchy
    InvalidBoxStructure(String),

    /// Unsupported feature or scheme
    UnsupportedFeature(String),

    /// Crypto operation error
    CryptoError(crate::CencError),
}

impl fmt::Display for V3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            V3Error::Io(e) => write!(f, "I/O error: {}", e),
            V3Error::UnexpectedEof => write!(f, "Unexpected end of file"),
            V3Error::MissingMetadata(msg) => write!(f, "Missing metadata: {}", msg),
            V3Error::MissingKey(msg) => write!(f, "Missing key: {}", msg),
            V3Error::InvalidBoxStructure(msg) => write!(f, "Invalid box structure: {}", msg),
            V3Error::UnsupportedFeature(msg) => write!(f, "Unsupported feature: {}", msg),
            V3Error::CryptoError(e) => write!(f, "Crypto error: {}", e),
        }
    }
}

impl std::error::Error for V3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            V3Error::Io(e) => Some(e),
            V3Error::CryptoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for V3Error {
    fn from(err: std::io::Error) -> Self {
        V3Error::Io(err)
    }
}

impl From<crate::CencError> for V3Error {
    fn from(err: crate::CencError) -> Self {
        V3Error::CryptoError(err)
    }
}

impl From<winnow::error::ErrMode<winnow::error::ContextError>> for V3Error {
    fn from(_: winnow::error::ErrMode<winnow::error::ContextError>) -> Self {
        V3Error::InvalidBoxStructure("Parse error".to_string())
    }
}

pub type Result<T> = std::result::Result<T, V3Error>;
