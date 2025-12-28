pub mod cache;
pub mod decrypt;
pub mod download;
pub mod fetch;
pub mod merge;
pub mod raw;

pub mod dash;
pub mod hls;

pub(crate) mod util;
use crate::context::IoriContext;
pub use crate::util::http::IoriHttp;
pub use futures::Stream;
pub use reqwest;
pub mod utils {
    pub use crate::util::detect_manifest_type;
    pub use crate::util::path::DuplicateOutputFileNamer;
    pub use crate::util::path::sanitize;
}

pub mod context;

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
    type Segment: StreamingSegment + WriteSegment + Send + 'static;

    fn segments_stream(
        &self,
        context: &IoriContext,
    ) -> impl Future<Output = IoriResult<impl Stream<Item = IoriResult<Vec<Self::Segment>>>>>;
}

/// A segment of a streaming source
pub trait StreamingSegment {
    /// Stream id
    fn stream_id(&self) -> u64;

    /// Stream type
    fn stream_type(&self) -> StreamType;

    /// Sequence ID of the segment, starts from 0
    fn sequence(&self) -> u64;

    /// Part index of the segment. For segments without sub-parts or discontinuities,
    /// this defaults to 0.
    fn part_index(&self) -> u64 {
        0
    }

    /// File name of the segment
    fn file_name(&self) -> &str;

    /// Optional initial segment data
    fn initial_segment(&self) -> InitialSegment {
        InitialSegment::None
    }

    /// Optional key for decryption
    fn key(&self) -> Option<std::sync::Arc<decrypt::IoriKey>>;

    /// Optional duration of the segment
    fn duration(&self) -> Option<f64> {
        None
    }

    /// Format hint for the segment
    fn format(&self) -> SegmentFormat;
}

pub trait WriteSegment {
    fn write_segment<W>(
        &self,
        context: &IoriContext,
        writer: &mut W,
    ) -> impl Future<Output = IoriResult<()>> + Send
    where
        W: tokio::io::AsyncWrite + Unpin + Send;
}
