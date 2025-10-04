use std::{
    hash::{Hash, Hasher},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use m3u8_rs::{AlternativeMedia, AlternativeMediaType, MediaPlaylist, Playlist};
use reqwest::Url;

use crate::{
    InitialSegment, SegmentFormat, SegmentType,
    decrypt::IoriKey,
    error::IoriResult,
    hls::{segment::M3u8Segment, utils::load_m3u8},
    util::http::HttpClient,
};

use super::utils::load_playlist_with_retry;

/// Core part to perform network operations
pub struct HlsMediaPlaylistSource {
    /// URL of the media playlist
    url: String,

    /// Stream ID
    stream_id: u64,
    /// Sequence number for segments retrived from the playlist
    sequence: AtomicU64,

    /// Override key
    key: Option<String>,
    /// Override segment type
    segment_type: Option<SegmentType>,

    client: HttpClient,
    initial_playlist: Option<MediaPlaylist>,
}

/// A source to fetch segments from a Media Playlist
///
/// > A Playlist is a Media Playlist if all URI lines in the Playlist
/// > identify Media Segments.
/// >
/// > [RFC8216 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8216#section-4.1)
///
/// The behavior of trying use [HlsPlaylistSource] to load a master playlist is undefined.
/// In current implementation, it will try to load the media playlist of the best quality.
/// But this may change in the future.
impl HlsMediaPlaylistSource {
    pub fn new(
        client: HttpClient,
        m3u8_url: String,
        initial_playlist: Option<MediaPlaylist>,
        key: Option<&str>,
        segment_type: Option<SegmentType>,
        stream_id: u64,
    ) -> Self {
        Self {
            url: m3u8_url,
            initial_playlist,
            key: key.map(str::to_string),

            sequence: AtomicU64::new(0),
            client,
            segment_type,
            stream_id,
        }
    }

    pub async fn load_segments(
        &mut self,
        latest_media_sequence: &Option<u64>,
        retry: u32,
    ) -> IoriResult<(Vec<M3u8Segment>, Url, MediaPlaylist)> {
        let (playlist_url, playlist) = if let Some(initial_playlist) = self.initial_playlist.take()
        {
            (Url::from_str(&self.url)?, initial_playlist)
        } else {
            load_m3u8(&self.client, Url::from_str(&self.url)?, retry).await?
        };

        let mut key = None;
        let mut initial_segment = InitialSegment::None;
        let mut next_range_start = 0;
        let mut segments = Vec::with_capacity(playlist.segments.len());
        for (i, segment) in playlist.segments.iter().enumerate() {
            if let Some(k) = &segment.key {
                key = IoriKey::from_key(
                    &self.client,
                    k,
                    &playlist_url,
                    playlist.media_sequence,
                    self.key.clone(),
                )
                .await?
                .map(Arc::new);
            }

            if let Some(m) = &segment.map {
                let url = playlist_url.join(&m.uri)?;

                let mut retries = retry;
                loop {
                    retries -= 1;

                    match self.load_bytes(url.clone()).await {
                        Ok(bytes) => {
                            initial_segment = if m.after_key {
                                InitialSegment::Encrypted(Arc::new(bytes))
                            } else {
                                InitialSegment::Clear(Arc::new(bytes))
                            };
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load bytes for initial segment {url}: {e}");
                            if retries == 0 {
                                return Err(e);
                            }
                        }
                    }
                }
            }

            let url = playlist_url.join(&segment.uri)?;
            // FIXME: filename may be too long
            let filename = url
                .path_segments()
                .and_then(|mut c| c.next_back())
                .map(|r| r.to_string())
                .unwrap_or_else(|| {
                    // 1. hash of file url
                    let mut hasher = std::hash::DefaultHasher::new();
                    url.hash(&mut hasher);
                    let value = hasher.finish();
                    let mut filename = format!("{value:016x}");

                    // 2. byte range
                    if let Some(byte_range) = &segment.byte_range {
                        filename.push_str(&format!("_{}", byte_range.length));
                        if let Some(offset) = byte_range.offset {
                            filename.push_str(&format!("_{}", offset));
                        }
                    }

                    filename
                });
            let format = SegmentFormat::from_filename(&filename);

            let media_sequence = playlist.media_sequence + i as u64;
            if let Some(latest_media_sequence) = latest_media_sequence
                && media_sequence <= *latest_media_sequence
            {
                continue;
            }

            let m3u8_segment = M3u8Segment {
                stream_id: self.stream_id,
                url,
                filename,
                key: key.clone(),
                initial_segment: initial_segment.clone(),
                sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
                media_sequence,
                byte_range: segment.byte_range.as_ref().map(|r| crate::ByteRange {
                    offset: r.offset.unwrap_or(next_range_start),
                    length: Some(r.length),
                }),
                duration: segment.duration,
                segment_type: self.segment_type,
                format,
            };
            segments.push(m3u8_segment);

            // [0-100)    -> 100@0  -> next_range_start  = 0 + 100 = 100
            // [100-120)  -> 20     -> next_range_start += 100 + 20 = 200
            if let Some(byte_range) = &segment.byte_range {
                if let Some(offset) = byte_range.offset {
                    next_range_start = offset + byte_range.length;
                } else {
                    next_range_start += byte_range.length;
                }
            }
        }

        Ok((segments, playlist_url, playlist))
    }

    async fn load_bytes(&self, url: Url) -> IoriResult<Vec<u8>> {
        Ok(self.client.get(url).send().await?.bytes().await?.to_vec())
    }
}

/// A source to fetch segments from a Master Playlist OR a Media Playlist
///
/// > A Playlist is a Master Playlist if all URI lines in the Playlist identify Media Playlists.
/// >
/// > [RFC8216 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8216#section-4.1)
///
/// It is recommended to always use [HlsPlaylistSource].
pub struct HlsPlaylistSource {
    url: Url,

    streams: Vec<HlsMediaPlaylistSource>,

    key: Option<String>,
    client: HttpClient,
}

impl HlsPlaylistSource {
    pub fn new(client: HttpClient, url: Url, key: Option<&str>) -> Self {
        Self {
            url,
            key: key.map(str::to_string),
            client,
            streams: Vec::new(),
        }
    }

    pub async fn load_streams(&mut self, retry: u32) -> IoriResult<Vec<Option<u64>>> {
        let playlist = load_playlist_with_retry(&self.client, &self.url, retry).await?;

        match playlist {
            Playlist::MasterPlaylist(mut pl) => {
                // Get the best variant
                let variants = &mut pl.variants;
                variants.sort_by(|a, b| {
                    // compare resolution first
                    if let (Some(a), Some(b)) = (a.resolution, b.resolution)
                        && a.width != b.width
                    {
                        return b.width.cmp(&a.width);
                    }

                    // compare framerate then
                    if let (Some(a), Some(b)) = (a.frame_rate, b.frame_rate) {
                        let a = a as u64;
                        let b = b as u64;
                        if a != b {
                            return b.cmp(&a);
                        }
                    }

                    // compare bandwidth finally
                    b.bandwidth.cmp(&a.bandwidth)
                });
                let variant = variants.first().expect("No variant found");
                let variant_url = self.url.join(&variant.uri)?;
                self.streams.push(HlsMediaPlaylistSource::new(
                    self.client.clone(),
                    variant_url.to_string(),
                    None,
                    self.key.as_deref(),
                    Some(SegmentType::Video),
                    0,
                ));

                fn load_variant<'a>(
                    group_id: &str,
                    media_type: AlternativeMediaType,
                    pl: &'a [AlternativeMedia],
                ) -> Option<&'a str> {
                    let alternatives: Vec<_> = pl
                        .iter()
                        .filter(|alternative| {
                            alternative.group_id == group_id && alternative.media_type == media_type
                        })
                        .collect();

                    let best = alternatives
                        .iter()
                        .find(|alternative| alternative.default && alternative.autoselect)
                        .or_else(|| alternatives.first());

                    best.and_then(|b| b.uri.as_deref())
                }

                // Load extra streams from the variant
                if let Some(group_id) = &variant.audio
                    && let Some(audio_url) =
                        load_variant(group_id, AlternativeMediaType::Audio, &pl.alternatives)
                {
                    let m3u8_url = self.url.join(audio_url)?.to_string();
                    if !self.streams.iter().any(|s| s.url == m3u8_url) {
                        self.streams.push(HlsMediaPlaylistSource::new(
                            self.client.clone(),
                            m3u8_url,
                            None,
                            self.key.as_deref(),
                            Some(SegmentType::Audio),
                            1,
                        ));
                    }
                }
                if let Some(group_id) = &variant.video
                    && let Some(video_url) =
                        load_variant(group_id, AlternativeMediaType::Video, &pl.alternatives)
                {
                    let m3u8_url = self.url.join(video_url)?.to_string();
                    if !self.streams.iter().any(|s| s.url == m3u8_url) {
                        self.streams.push(HlsMediaPlaylistSource::new(
                            self.client.clone(),
                            self.url.join(video_url)?.to_string(),
                            None,
                            self.key.as_deref(),
                            Some(SegmentType::Video),
                            2,
                        ));
                    }
                }
            }
            Playlist::MediaPlaylist(pl) => {
                self.streams.push(HlsMediaPlaylistSource::new(
                    self.client.clone(),
                    self.url.to_string(),
                    Some(pl),
                    self.key.as_deref(),
                    Some(SegmentType::Video),
                    0,
                ));
            }
        }
        Ok(vec![None; self.streams.len()])
    }

    pub async fn load_segments(
        &mut self,
        latest_media_sequences: &[Option<u64>],
        retry: u32,
    ) -> IoriResult<(Vec<Vec<M3u8Segment>>, bool /* is_end */)> {
        let mut segments = Vec::new();
        let mut is_end = true;
        for (stream, latest_media_sequence) in self.streams.iter_mut().zip(latest_media_sequences) {
            let (stream_segments, _, stream_playlist) =
                stream.load_segments(latest_media_sequence, retry).await?;
            segments.push(stream_segments);
            if !stream_playlist.end_list {
                is_end = false;
            }
        }

        Ok((segments, is_end))
    }
}
