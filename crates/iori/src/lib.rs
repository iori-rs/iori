pub mod cache;
pub mod decrypt;
pub mod download;
pub mod fetch;
pub mod merge;
pub mod raw;

pub mod dash;
pub mod hls;

pub(crate) mod util;
pub use crate::util::http::HttpClient;
pub use reqwest;
pub mod utils {
    pub use crate::util::detect_manifest_type;
    pub use crate::util::path::DuplicateOutputFileNamer;
}

mod segment;
pub use segment::*;
mod error;
pub use error::*;
pub use util::range::ByteRange;

/// ┌───────────────────────┐                ┌────────────────────┐
/// │                       │    Segment 1   │                    │
/// │                       ├────────────────►                    ├───┐
/// │                       │                │                    │   │fetch_segment
/// │                       │    Segment 2   │                    ◄───┘
/// │      M3U8 Time#1      ├────────────────►     Downloader     │
/// │                       │                │                    ├───┐
/// │                       │    Segment 3   │       [MPSC]       │   │fetch_segment
/// │                       ├────────────────►                    ◄───┘
/// │                       │                │                    │
/// └───────────────────────┘                │                    ├───┐
///                                          │                    │   │fetch_segment
/// ┌───────────────────────┐                │                    ◄───┘
/// │                       │       ...      │                    │
/// │                       ├────────────────►                    │
/// │                       │                │                    │
/// │      M3U8 Time#N      │                │                    │
/// │                       │                │                    │
/// │                       │                │                    │
/// │                       │  Segment Last  │                    │
/// │                       ├────────────────►                    │
/// └───────────────────────┘                └────────────────────┘
pub trait StreamingSource {
    type Segment: StreamingSegment + Send + 'static;

    fn fetch_info(
        &self,
    ) -> impl Future<
        Output = error::IoriResult<
            tokio::sync::mpsc::UnboundedReceiver<IoriResult<Vec<Self::Segment>>>,
        >,
    > + Send;

    fn fetch_segment<W>(
        &self,
        segment: &Self::Segment,
        writer: &mut W,
    ) -> impl Future<Output = IoriResult<()>> + Send
    where
        W: tokio::io::AsyncWrite + Unpin + Send + Sync + 'static;
}

pub trait StreamingSegment {
    /// Stream id
    fn stream_id(&self) -> u64;

    /// Sequence ID of the segment, starts from 0
    fn sequence(&self) -> u64;

    /// File name of the segment
    fn file_name(&self) -> &str;

    /// Optional initial segment data
    fn initial_segment(&self) -> InitialSegment {
        InitialSegment::None
    }

    /// Optional key for decryption
    fn key(&self) -> Option<std::sync::Arc<decrypt::IoriKey>>;

    fn r#type(&self) -> SegmentType;

    /// Format hint for the segment
    fn format(&self) -> SegmentFormat;
}
