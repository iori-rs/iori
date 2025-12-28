use crate::{
    ByteRange, InitialSegment, RemoteStreamingSegment, SegmentFormat, StreamType, StreamingSegment,
    decrypt::IoriKey,
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct M3u8Segment {
    pub url: reqwest::Url,
    pub filename: String,

    pub key: Option<Arc<IoriKey>>,
    pub initial_segment: InitialSegment,

    pub byte_range: Option<ByteRange>,

    /// Stream id
    pub stream_id: u64,
    pub stream_type: Option<StreamType>,

    /// Sequence id allocated by the downloader, starts from 0
    pub sequence: u64,
    /// Media sequence id from the m3u8 file
    pub media_sequence: u64,

    pub part_index: u64,

    pub duration: f64,
    pub format: SegmentFormat,
}

impl StreamingSegment for M3u8Segment {
    fn stream_id(&self) -> u64 {
        self.stream_id
    }

    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn file_name(&self) -> &str {
        self.filename.as_str()
    }

    fn initial_segment(&self) -> InitialSegment {
        self.initial_segment.clone()
    }

    fn key(&self) -> Option<Arc<IoriKey>> {
        self.key.clone()
    }

    fn duration(&self) -> Option<f64> {
        Some(self.duration)
    }

    fn stream_type(&self) -> StreamType {
        self.stream_type.unwrap_or(StreamType::Video)
    }

    fn format(&self) -> SegmentFormat {
        self.format.clone()
    }

    fn part_index(&self) -> u64 {
        self.part_index
    }
}

impl RemoteStreamingSegment for M3u8Segment {
    fn url(&self) -> reqwest::Url {
        self.url.clone()
    }

    fn byte_range(&self) -> Option<ByteRange> {
        self.byte_range.clone()
    }
}
