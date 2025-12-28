use crate::{M3u8ParseError, models::*};

impl From<m3u8_rs::Playlist> for Playlist {
    fn from(value: m3u8_rs::Playlist) -> Self {
        match value {
            m3u8_rs::Playlist::MasterPlaylist(master) => Playlist::MasterPlaylist(master.into()),
            m3u8_rs::Playlist::MediaPlaylist(media) => Playlist::MediaPlaylist(media.into()),
        }
    }
}

impl From<m3u8_rs::MasterPlaylist> for MasterPlaylist {
    fn from(value: m3u8_rs::MasterPlaylist) -> Self {
        MasterPlaylist {
            variants: value
                .variants
                .into_iter()
                .map(VariantStream::from)
                .collect(),
            alternatives: value
                .alternatives
                .into_iter()
                .map(AlternativeMedia::from)
                .collect(),
        }
    }
}

impl From<m3u8_rs::VariantStream> for VariantStream {
    fn from(value: m3u8_rs::VariantStream) -> Self {
        VariantStream {
            uri: value.uri,
            bandwidth: value.bandwidth,
            average_bandwidth: value.average_bandwidth,
            resolution: value.resolution.map(Resolution::from),
            frame_rate: value.frame_rate.map(F64::from),
            audio: value.audio,
            video: value.video,
        }
    }
}

impl From<m3u8_rs::AlternativeMedia> for AlternativeMedia {
    fn from(value: m3u8_rs::AlternativeMedia) -> Self {
        AlternativeMedia {
            group_id: value.group_id,
            media_type: value.media_type.into(),
            name: value.name,
            uri: value.uri,
            default: value.default,
            autoselect: value.autoselect,
        }
    }
}

impl From<m3u8_rs::AlternativeMediaType> for AlternativeMediaType {
    fn from(value: m3u8_rs::AlternativeMediaType) -> Self {
        match value {
            m3u8_rs::AlternativeMediaType::Audio => AlternativeMediaType::Audio,
            m3u8_rs::AlternativeMediaType::Video => AlternativeMediaType::Video,
            m3u8_rs::AlternativeMediaType::Subtitles => AlternativeMediaType::Subtitles,
            m3u8_rs::AlternativeMediaType::ClosedCaptions => AlternativeMediaType::ClosedCaptions,
            m3u8_rs::AlternativeMediaType::Other(value) => AlternativeMediaType::Other(value),
        }
    }
}

impl From<m3u8_rs::Resolution> for Resolution {
    fn from(value: m3u8_rs::Resolution) -> Self {
        Resolution {
            width: value.width,
            height: value.height,
        }
    }
}

impl From<m3u8_rs::MediaPlaylist> for MediaPlaylist {
    fn from(value: m3u8_rs::MediaPlaylist) -> Self {
        let mut current_part_index = value.discontinuity_sequence;
        let mut segments = Vec::with_capacity(value.segments.len());

        for segment in value.segments {
            if segment.discontinuity {
                current_part_index += 1;
            }

            let segment: crate::models::MediaSegment = (segment, current_part_index).into();
            segments.push(segment);
        }

        MediaPlaylist {
            media_sequence: value.media_sequence,
            segments,
            end_list: value.end_list,
            discontinuity_sequence: value.discontinuity_sequence,
        }
    }
}

impl From<(m3u8_rs::MediaSegment, u64)> for MediaSegment {
    fn from((value, part_index): (m3u8_rs::MediaSegment, u64)) -> Self {
        MediaSegment {
            uri: value.uri,
            duration: (value.duration as f64).into(),
            title: value.title,
            byte_range: value.byte_range.map(ByteRange::from),
            key: value.key.map(Key::from),
            map: value.map.map(Map::from),
            part_index,
        }
    }
}

impl From<m3u8_rs::ByteRange> for ByteRange {
    fn from(value: m3u8_rs::ByteRange) -> Self {
        ByteRange {
            length: value.length,
            offset: value.offset,
        }
    }
}

impl From<m3u8_rs::Map> for Map {
    fn from(value: m3u8_rs::Map) -> Self {
        Map {
            uri: value.uri,
            byte_range: value.byte_range.map(ByteRange::from),
            encrypted: value.after_key,
        }
    }
}

impl From<m3u8_rs::Key> for Key {
    fn from(value: m3u8_rs::Key) -> Self {
        Key {
            method: value.method.into(),
            uri: value.uri,
            iv: value.iv,
            key_format: value.keyformat.map(KeyFormat::from).unwrap_or_default(),
            key_format_versions: value.keyformatversions,
        }
    }
}

impl From<m3u8_rs::KeyMethod> for KeyMethod {
    fn from(value: m3u8_rs::KeyMethod) -> Self {
        match value {
            m3u8_rs::KeyMethod::None => KeyMethod::None,
            m3u8_rs::KeyMethod::AES128 => KeyMethod::AES128,
            m3u8_rs::KeyMethod::SampleAES => KeyMethod::SampleAES,
            m3u8_rs::KeyMethod::Other(value) => match value.as_str() {
                "SAMPLE-AES-CTR" => KeyMethod::SampleAESCTR,
                "SAMPLE-AES-CENC" => KeyMethod::SampleAesCenc,
                _ => KeyMethod::Other(value),
            },
        }
    }
}

pub fn parse_playlist_res(input: &[u8]) -> Result<Playlist, M3u8ParseError> {
    let playlist = m3u8_rs::parse_playlist_res(input)
        .map_err(|e| M3u8ParseError::InvalidPlaylist(e.to_string()))?;
    Ok(playlist.into())
}
