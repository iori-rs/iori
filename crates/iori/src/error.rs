use aes::cipher::block_padding::UnpadError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IoriError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::StatusCode),

    #[error("Manifest fetch error")]
    ManifestFetchError,

    #[error("Decryption key required")]
    DecryptionKeyRequired,

    #[error("Invalid hex key: {0}")]
    InvalidHexKey(String),

    #[error("Invalid binary key: {0:?}")]
    InvalidBinaryKey(Vec<u8>),

    #[error("mp4decrypt error: {0}")]
    Mp4DecryptError(#[from] mp4decrypt::Error),

    #[error("iori-ssa error: {0:?}")]
    IoriSsaError(#[from] iori_ssa::Error),

    #[error("Pkcs7 unpad error")]
    UnpadError(#[from] UnpadError),

    #[error("Invalid m3u8 file: {0}")]
    M3u8ParseError(String),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),

    #[error(transparent)]
    HexDecodeError(#[from] hex::FromHexError),

    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    // MPEG-DASH errors
    #[error(transparent)]
    MpdParseError(#[from] dash_mpd::DashMpdError),

    #[error("invalid mpd: {0}")]
    MpdParsing(String),

    #[error(transparent)]
    TimeDeltaOutOfRange(#[from] chrono::OutOfRangeError),

    #[error("Invalid timing schema: {0:?}")]
    InvalidTimingSchema(String),

    #[error(transparent)]
    MissingExecutable(#[from] which::Error),

    #[error("Can not set cache directory to an existing path: {0}")]
    CacheDirExists(std::path::PathBuf),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error("{0}")]
    CustomError(String),

    #[cfg(feature = "opendal")]
    #[error(transparent)]
    OpendalError(#[from] opendal::Error),

    #[error("No period found")]
    NoPeriodFound,

    #[error("No adaption set found")]
    NoAdaptationSetFound,

    #[error("No representation found")]
    NoRepresentationFound,

    #[error(transparent)]
    ChronoParseError(#[from] chrono::ParseError),

    #[error("Invalid date time: {0}")]
    DateTimeParsing(String),

    #[cfg(feature = "ffmpeg")]
    #[error(transparent)]
    RsmpegError(#[from] rsmpeg::error::RsmpegError),

    #[cfg(feature = "ffmpeg")]
    #[error(transparent)]
    InvalidTrackPath(#[from] std::ffi::NulError),

    #[cfg(feature = "ffmpeg")]
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
}

pub type IoriResult<T> = Result<T, IoriError>;
