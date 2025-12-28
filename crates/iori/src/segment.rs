use crate::{ByteRange, StreamingSegment, decrypt::IoriKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Default, PartialEq)]
pub enum InitialSegment {
    Encrypted(std::sync::Arc<Vec<u8>>),
    Clear(std::sync::Arc<Vec<u8>>),
    #[default]
    None,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum SegmentFormat {
    #[default]
    Mpeg2TS,
    Mp4,
    M4a,
    Cmfv,
    Cmfa,
    Aac,
    Raw(Option<String>),
    Other(String),
}

impl SegmentFormat {
    pub fn as_ext(&self) -> &str {
        match self {
            Self::Mpeg2TS => "ts",
            Self::Mp4 => "mp4",
            Self::M4a => "m4a",
            Self::Cmfv => "cmfv",
            Self::Cmfa => "cmfa",
            Self::Aac => "aac",
            Self::Raw(ext) => ext.as_deref().unwrap_or("raw"),
            Self::Other(ext) => ext.as_str(),
        }
    }

    pub fn from_filename(s: &str) -> Self {
        let (_, ext) = s.rsplit_once('.').unwrap_or(("", s));
        Self::from_ext(ext)
    }

    fn from_ext(ext: &str) -> Self {
        match ext {
            "ts" => Self::Mpeg2TS,
            "mp4" | "m4s" | "m4f" => Self::Mp4,
            "m4a" => Self::M4a,
            "cmfv" => Self::Cmfv,
            "cmfa" => Self::Cmfa,
            "aac" => Self::Aac,
            "txt" | "ass" | "srt" | "vtt" | "json" => Self::Raw(Some(ext.to_string())),
            _ => Self::Other(ext.to_string()),
        }
    }
}

impl FromStr for SegmentFormat {
    type Err = crate::IoriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_ext(s))
    }
}

#[derive(Clone, Default)]
pub struct SegmentInfo {
    pub stream_id: u64,
    pub stream_type: StreamType,
    pub sequence: u64,
    pub file_name: String,
    pub initial_segment: InitialSegment,
    pub key: Option<std::sync::Arc<IoriKey>>,
    pub duration: Option<f64>,
    pub format: SegmentFormat,
    pub part_index: u64,
}

impl<T> From<&T> for SegmentInfo
where
    T: StreamingSegment,
{
    fn from(segment: &T) -> Self {
        SegmentInfo {
            stream_id: segment.stream_id(),
            sequence: segment.sequence(),
            file_name: segment.file_name().to_string(),
            initial_segment: segment.initial_segment(),
            key: segment.key(),
            duration: segment.duration(),
            stream_type: segment.stream_type(),
            format: segment.format(),
            part_index: segment.part_index(),
        }
    }
}

impl StreamingSegment for Box<dyn StreamingSegment + Send + Sync + '_> {
    fn stream_id(&self) -> u64 {
        self.as_ref().stream_id()
    }

    fn sequence(&self) -> u64 {
        self.as_ref().sequence()
    }

    fn file_name(&self) -> &str {
        self.as_ref().file_name()
    }

    fn initial_segment(&self) -> InitialSegment {
        self.as_ref().initial_segment()
    }

    fn key(&self) -> Option<std::sync::Arc<IoriKey>> {
        self.as_ref().key()
    }

    fn duration(&self) -> Option<f64> {
        self.as_ref().duration()
    }

    fn stream_type(&self) -> StreamType {
        self.as_ref().stream_type()
    }

    fn format(&self) -> SegmentFormat {
        self.as_ref().format()
    }

    fn part_index(&self) -> u64 {
        self.as_ref().part_index()
    }
}

impl StreamingSegment for &Box<dyn StreamingSegment + Send + Sync + '_> {
    fn stream_id(&self) -> u64 {
        self.as_ref().stream_id()
    }

    fn sequence(&self) -> u64 {
        self.as_ref().sequence()
    }

    fn file_name(&self) -> &str {
        self.as_ref().file_name()
    }

    fn initial_segment(&self) -> InitialSegment {
        self.as_ref().initial_segment()
    }

    fn key(&self) -> Option<std::sync::Arc<IoriKey>> {
        self.as_ref().key()
    }

    fn duration(&self) -> Option<f64> {
        self.as_ref().duration()
    }

    fn stream_type(&self) -> StreamType {
        self.as_ref().stream_type()
    }

    fn format(&self) -> SegmentFormat {
        self.as_ref().format()
    }

    fn part_index(&self) -> u64 {
        self.as_ref().part_index()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum StreamType {
    #[default]
    Video,
    Audio,
    Subtitle,
    Unknown,
}

impl StreamType {
    pub fn from_mime_type(mime_type: Option<&str>) -> Self {
        let mime_type = mime_type.unwrap_or("video");

        if mime_type.starts_with("video") {
            Self::Video
        } else if mime_type.starts_with("audio") {
            Self::Audio
        } else if mime_type.starts_with("text") {
            Self::Subtitle
        } else {
            panic!("Unknown mime type: {}", mime_type);
        }
    }
}

pub trait RemoteStreamingSegment {
    fn url(&self) -> reqwest::Url;

    fn headers(&self) -> Option<reqwest::header::HeaderMap> {
        None
    }

    fn byte_range(&self) -> Option<ByteRange> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_format_from_filename() {
        assert_eq!(
            SegmentFormat::from_filename("test.ts"),
            SegmentFormat::Mpeg2TS
        );
        assert_eq!(SegmentFormat::from_filename("test.mp4"), SegmentFormat::Mp4);
        assert_eq!(SegmentFormat::from_filename("test.m4a"), SegmentFormat::M4a);
        assert_eq!(
            SegmentFormat::from_filename("test.cmfv"),
            SegmentFormat::Cmfv
        );
        assert_eq!(
            SegmentFormat::from_filename("test.cmfa"),
            SegmentFormat::Cmfa
        );
        assert_eq!(
            SegmentFormat::from_filename("test.txt"),
            SegmentFormat::Raw(Some("txt".to_string()))
        );
        assert_eq!(
            SegmentFormat::from_filename("test.unknown"),
            SegmentFormat::Other("unknown".to_string())
        );
    }

    #[test]
    fn test_segment_format_as_ext() {
        assert_eq!(SegmentFormat::Mpeg2TS.as_ext(), "ts");
        assert_eq!(SegmentFormat::Mp4.as_ext(), "mp4");
        assert_eq!(SegmentFormat::M4a.as_ext(), "m4a");
        assert_eq!(SegmentFormat::Cmfv.as_ext(), "cmfv");
        assert_eq!(SegmentFormat::Cmfa.as_ext(), "cmfa");
        assert_eq!(SegmentFormat::Raw(None).as_ext(), "raw");
        assert_eq!(SegmentFormat::Raw(Some("txt".to_string())).as_ext(), "txt");
        assert_eq!(
            SegmentFormat::Other("unknown".to_string()).as_ext(),
            "unknown"
        );
    }

    #[test]
    fn test_segment_type_from_mime_type() {
        assert_eq!(
            StreamType::from_mime_type(Some("video/mp4")),
            StreamType::Video
        );
        assert_eq!(
            StreamType::from_mime_type(Some("audio/mp4")),
            StreamType::Audio
        );
        assert_eq!(
            StreamType::from_mime_type(Some("text/vtt")),
            StreamType::Subtitle
        );
        assert_eq!(StreamType::from_mime_type(None), StreamType::Video);
    }
}
