use comparable::Comparable;
use quick_m3u8::tag::{DecimalResolution, hls};
use std::{borrow::Cow, ops::Deref};

#[derive(Debug, Clone, PartialEq, Comparable)]
pub enum Playlist {
    MasterPlaylist(MasterPlaylist),
    MediaPlaylist(MediaPlaylist),
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct MasterPlaylist {
    pub variants: Vec<VariantStream>,
    pub alternatives: Vec<AlternativeMedia>,
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct VariantStream {
    pub uri: String,
    pub bandwidth: u64,
    pub average_bandwidth: Option<u64>,
    pub resolution: Option<Resolution>,
    pub frame_rate: Option<F64>,
    pub audio: Option<String>,
    pub video: Option<String>,
}

impl<'a> From<(hls::StreamInf<'a>, Cow<'a, str>)> for VariantStream {
    fn from((value, uri): (hls::StreamInf<'a>, Cow<'a, str>)) -> Self {
        Self {
            uri: uri.to_string(),
            bandwidth: value.bandwidth(),
            average_bandwidth: value.average_bandwidth(),
            resolution: value.resolution().map(Resolution::from),
            frame_rate: value.frame_rate().map(F64::from),
            audio: value.audio().map(str::to_string),
            video: value.video().map(str::to_string),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Comparable)]
pub struct Resolution {
    pub width: u64,
    pub height: u64,
}

impl From<DecimalResolution> for Resolution {
    fn from(value: DecimalResolution) -> Self {
        Self {
            width: value.width,
            height: value.height,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct AlternativeMedia {
    pub group_id: String,
    pub media_type: AlternativeMediaType,
    pub name: String,
    pub uri: Option<String>,
    pub default: bool,
    pub autoselect: bool,
}

impl<'a> From<hls::Media<'a>> for AlternativeMedia {
    fn from(value: hls::Media<'a>) -> Self {
        Self {
            group_id: value.group_id().to_string(),
            media_type: match value.media_type() {
                hls::EnumeratedString::Known(value) => value.into(),
                hls::EnumeratedString::Unknown(value) => {
                    AlternativeMediaType::Other(value.to_string())
                }
            },
            name: value.name().to_string(),
            uri: value.uri().map(str::to_string),
            default: value.default(),
            autoselect: value.autoselect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Comparable)]
pub enum AlternativeMediaType {
    Audio,
    Video,
    Subtitles,
    ClosedCaptions,
    Other(String),
}

impl From<hls::MediaType> for AlternativeMediaType {
    fn from(value: hls::MediaType) -> Self {
        match value {
            hls::MediaType::Audio => Self::Audio,
            hls::MediaType::Video => Self::Video,
            hls::MediaType::Subtitles => Self::Subtitles,
            hls::MediaType::ClosedCaptions => Self::ClosedCaptions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct MediaPlaylist {
    pub media_sequence: u64,
    pub discontinuity_sequence: u64,
    pub segments: Vec<MediaSegment>,
    pub end_list: bool,
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct MediaSegment {
    pub uri: String,
    pub duration: F64,
    pub title: Option<String>,
    pub byte_range: Option<ByteRange>,
    pub key: Option<Key>,
    pub map: Option<Map>,
    pub part_index: u64,
}

impl<'a>
    From<(
        hls::Inf<'a>,
        Cow<'a, str>,
        Option<ByteRange>,
        Option<Key>,
        Option<Map>,
        u64,
    )> for MediaSegment
{
    fn from(
        (inf, uri, byte_range, key, map, part_index): (
            hls::Inf<'a>,
            Cow<'a, str>,
            Option<ByteRange>,
            Option<Key>,
            Option<Map>,
            u64,
        ),
    ) -> Self {
        Self {
            uri: uri.to_string(),
            duration: inf.duration().into(),
            title: match inf.title() {
                "" => None,
                title => Some(title.to_string()),
            },
            byte_range,
            key,
            map,
            part_index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Comparable)]
pub struct ByteRange {
    pub length: u64,
    pub offset: Option<u64>,
}

impl<'a> From<quick_m3u8::tag::hls::Byterange<'a>> for ByteRange {
    fn from(value: quick_m3u8::tag::hls::Byterange<'a>) -> Self {
        Self {
            length: value.length(),
            offset: value.offset(),
        }
    }
}

impl From<quick_m3u8::tag::hls::MapByterange> for ByteRange {
    fn from(value: quick_m3u8::tag::hls::MapByterange) -> Self {
        Self {
            length: value.length,
            offset: Some(value.offset),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct Map {
    pub uri: String,
    pub byte_range: Option<ByteRange>,
    pub encrypted: bool,
}

impl<'a> From<(hls::Map<'a>, &Option<Key>)> for Map {
    fn from((value, key): (hls::Map<'a>, &Option<Key>)) -> Self {
        Self {
            uri: value.uri().to_string(),
            byte_range: value.byterange().map(ByteRange::from),
            encrypted: key.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Comparable)]
pub struct Key {
    pub method: KeyMethod,
    pub uri: Option<String>,
    pub iv: Option<String>,
    pub key_format: KeyFormat,
    pub key_format_versions: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Comparable)]
pub enum KeyMethod {
    None,
    AES128,
    SampleAES,
    SampleAESCTR,
    SampleAesCenc,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Default, Comparable)]
pub enum KeyFormat {
    #[default]
    Identity,
    Other(String),
}

impl From<&str> for KeyFormat {
    fn from(value: &str) -> Self {
        if value == "identity" {
            Self::Identity
        } else {
            Self::Other(value.to_string())
        }
    }
}

impl From<String> for KeyFormat {
    fn from(value: String) -> Self {
        if value == "identity" {
            Self::Identity
        } else {
            Self::Other(value)
        }
    }
}

impl<'a> From<quick_m3u8::tag::hls::Key<'a>> for Key {
    fn from(value: quick_m3u8::tag::hls::Key) -> Self {
        let method = match value.method() {
            hls::EnumeratedString::Known(hls::Method::None) => KeyMethod::None,
            hls::EnumeratedString::Known(hls::Method::Aes128) => KeyMethod::AES128,
            hls::EnumeratedString::Known(hls::Method::SampleAes) => KeyMethod::SampleAES,
            hls::EnumeratedString::Known(hls::Method::SampleAesCtr) => KeyMethod::SampleAESCTR,
            hls::EnumeratedString::Unknown("SAMPLE-AES-CENC") => KeyMethod::SampleAesCenc,
            hls::EnumeratedString::Unknown(value) => KeyMethod::Other(value.to_string()),
        };

        Self {
            method,
            uri: value.uri().map(str::to_string),
            iv: value.iv().map(str::to_string),
            key_format: value.keyformat().into(),
            key_format_versions: value.keyformatversions().map(str::to_string),
        }
    }
}

impl std::fmt::Display for KeyMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyMethod::None => write!(f, "NONE"),
            KeyMethod::AES128 => write!(f, "AES-128"),
            KeyMethod::SampleAES => write!(f, "SAMPLE-AES"),
            KeyMethod::SampleAESCTR => write!(f, "SAMPLE-AES-CTR"),
            KeyMethod::SampleAesCenc => write!(f, "SAMPLE-AES-CENC"),
            KeyMethod::Other(name) => write!(f, "{name}"),
        }
    }
}

// TODO: Remove this once quick-m3u8 is well tested and stable
#[derive(Debug, Clone, Copy, PartialOrd)]
pub struct F64(f64);

impl PartialEq<F64> for F64 {
    fn eq(&self, other: &F64) -> bool {
        (self.0 - other.0).abs() < 0.1
    }
}

impl Eq for F64 {}

impl Deref for F64 {
    type Target = f64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<f64> for F64 {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl Comparable for F64 {
    type Desc = f64;

    fn describe(&self) -> Self::Desc {
        self.0
    }

    type Change = f64;

    fn comparison(&self, other: &Self) -> comparable::Changed<Self::Change> {
        let diff = (self.0 - other.0).abs();
        if diff < 0.1 {
            comparable::Changed::Unchanged
        } else {
            comparable::Changed::Changed(diff)
        }
    }
}
