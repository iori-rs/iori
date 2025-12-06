use iori::IoriError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FfmpegError {
    #[error(transparent)]
    Ffmpeg(#[from] rsmpeg::error::RsmpegError),
    #[error(transparent)]
    Nul(#[from] std::ffi::NulError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

impl From<FfmpegError> for IoriError {
    fn from(error: FfmpegError) -> Self {
        match error {
            FfmpegError::Ffmpeg(error) => IoriError::Custom(Box::new(error)),
            FfmpegError::Nul(error) => IoriError::Custom(Box::new(error)),
            FfmpegError::Join(error) => IoriError::Custom(Box::new(error)),
        }
    }
}
