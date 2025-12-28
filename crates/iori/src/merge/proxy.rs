use super::Merger;
use crate::{SegmentInfo, cache::CacheSource, error::IoriResult};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::RwLock;

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{Response, StatusCode, header},
    response::IntoResponse,
    routing::get,
};

/// ProxyMerger serves segments via an HTTP server with m3u8 playlists.
///
/// It starts an axum server that provides:
/// - m3u8 playlist endpoints (one per stream or a combined playlist)
/// - segment file endpoints
///
/// When the input stream finishes, it adds EXT-X-ENDLIST to the m3u8 manifest.
pub struct ProxyMerger {
    /// Segments organized by stream_id and sequence
    segments: Arc<RwLock<HashMap<u64 /* stream_id */, BTreeMap<u64 /* sequence */, SegmentInfo>>>>,
    /// Segment file paths for on-demand reading
    segment_paths: Arc<RwLock<HashMap<(u64 /* stream_id */, u64 /* sequence */), PathBuf>>>,
    /// Failed segments that should trigger discontinuity
    failed_segments: Arc<RwLock<std::collections::HashSet<(u64, u64)>>>,
    /// Whether the stream has finished
    finished: Arc<AtomicBool>,
    /// Server address to bind to
    addr: SocketAddr,
    /// Server handle
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyMerger {
    pub fn new(addr: SocketAddr) -> Self {
        let mut result = Self {
            segments: Arc::new(RwLock::new(HashMap::new())),
            segment_paths: Arc::new(RwLock::new(HashMap::new())),
            failed_segments: Arc::new(RwLock::new(HashSet::new())),
            finished: Arc::new(AtomicBool::new(false)),
            addr,
            server_handle: None,
        };

        result.start_server();
        result
    }

    fn start_server(&mut self) {
        let segments = self.segments.clone();
        let segment_paths = self.segment_paths.clone();
        let failed_segments = self.failed_segments.clone();
        let finished = self.finished.clone();
        let addr = self.addr;

        let app = Router::new()
            .route("/playlist.m3u8", get(serve_playlist))
            .route(
                "/stream/{stream_id}/playlist.m3u8",
                get(serve_stream_playlist),
            )
            .route("/segment/{stream_id}/{sequence}", get(serve_segment))
            .with_state(AppState {
                segments,
                segment_paths,
                failed_segments,
                finished,
            });

        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            tracing::info!("Proxy server listening on http://{}", addr);
            axum::serve(listener, app).await.unwrap();
        });

        self.server_handle = Some(handle);
    }
}

#[derive(Clone)]
struct AppState {
    segments: Arc<RwLock<HashMap<u64, BTreeMap<u64, SegmentInfo>>>>,
    segment_paths: Arc<RwLock<HashMap<(u64, u64), PathBuf>>>,
    failed_segments: Arc<RwLock<HashSet<(u64, u64)>>>,
    finished: Arc<AtomicBool>,
}

async fn serve_playlist(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let segments = state.segments.read().await;
    let failed_segments = state.failed_segments.read().await;
    let finished = state.finished.load(Ordering::Relaxed);

    // Get all stream IDs
    let stream_ids: Vec<u64> = segments.keys().copied().collect();

    if stream_ids.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    // If single stream, return its playlist directly
    if stream_ids.len() == 1 {
        let stream_id = stream_ids[0];
        let playlist =
            generate_media_playlist(&segments[&stream_id], &failed_segments, stream_id, finished);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
            .body(Body::from(playlist))
            .unwrap());
    }

    // Multiple streams: generate master playlist
    let mut master = String::new();
    master.push_str("#EXTM3U\n");
    master.push_str("#EXT-X-VERSION:3\n");

    for stream_id in stream_ids {
        // Determine stream type and attributes
        let stream_segments = &segments[&stream_id];
        if let Some(first_segment) = stream_segments.values().next() {
            match first_segment.stream_type {
                crate::StreamType::Video => {
                    master.push_str("#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080\n");
                }
                crate::StreamType::Audio => {
                    master.push_str(&format!(
                        r#"#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="Audio",DEFAULT=YES,URI="stream/{}/playlist.m3u8"\n"#,
                        stream_id
                    ));
                    continue;
                }
                _ => {}
            }
        }
        master.push_str(&format!("stream/{}/playlist.m3u8\n", stream_id));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
        .body(Body::from(master))
        .unwrap())
}

async fn serve_stream_playlist(
    State(state): State<AppState>,
    Path(stream_id): Path<u64>,
) -> Result<impl IntoResponse, StatusCode> {
    let segments = state.segments.read().await;
    let failed_segments = state.failed_segments.read().await;
    let finished = state.finished.load(Ordering::Relaxed);

    let stream_segments = segments.get(&stream_id).ok_or(StatusCode::NOT_FOUND)?;
    let playlist = generate_media_playlist(stream_segments, &failed_segments, stream_id, finished);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
        .body(Body::from(playlist))
        .unwrap())
}

fn generate_media_playlist(
    segments: &BTreeMap<u64, SegmentInfo>,
    failed_segments: &HashSet<(u64, u64)>,
    stream_id: u64,
    finished: bool,
) -> String {
    let mut playlist = String::new();
    playlist.push_str("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:3\n");
    playlist.push_str("#EXT-X-TARGETDURATION:10\n"); // TODO: validate whether this is correct
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");

    let mut prev_part_index: Option<u64> = None;
    let mut discontinuity_sequence = 0u64;

    for (sequence, segment) in segments.iter() {
        let current_failed = failed_segments.contains(&(stream_id, *sequence));

        // Mark discontinuity if:
        // 1. part_index changed
        if let Some(prev) = prev_part_index {
            if segment.part_index != prev {
                playlist.push_str("#EXT-X-DISCONTINUITY\n");
                discontinuity_sequence += 1;
            }
        }

        // Skip failed segments in the playlist output
        if !current_failed {
            // Add segment duration (default to 10 seconds if not available)
            playlist.push_str(&format!("#EXTINF:{},\n", segment.duration.unwrap_or(6.0)));

            // Add segment URL
            playlist.push_str(&format!("/segment/{}/{}\n", stream_id, sequence));
        }

        prev_part_index = Some(segment.part_index);
    }

    // Add discontinuity sequence at the beginning if there were any discontinuities
    if discontinuity_sequence > 0 {
        let header = format!("#EXT-X-DISCONTINUITY-SEQUENCE:{}\n", discontinuity_sequence);
        // Insert after version line
        let parts: Vec<&str> = playlist.split("#EXT-X-VERSION:3\n").collect();
        playlist = format!("{}#EXT-X-VERSION:3\n{}{}", parts[0], header, parts[1]);
    }

    // Add endlist tag if stream is finished
    if finished {
        playlist.push_str("#EXT-X-ENDLIST\n");
    }

    playlist
}

async fn serve_segment(
    State(state): State<AppState>,
    Path((stream_id, sequence)): Path<(u64, u64)>,
) -> Result<impl IntoResponse, StatusCode> {
    let segments = state.segments.read().await;
    let segment_paths = state.segment_paths.read().await;

    let stream_segments = segments.get(&stream_id).ok_or(StatusCode::NOT_FOUND)?;
    let segment = stream_segments
        .get(&sequence)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Get segment file path
    let path = segment_paths
        .get(&(stream_id, sequence))
        .ok_or(StatusCode::NOT_FOUND)?;

    // Read segment data from file on-demand
    let data = tokio::fs::read(path).await.map_err(|e| {
        tracing::error!("Failed to read segment file {}: {}", path.display(), e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Determine content type based on segment format
    let content_type = match segment.format {
        crate::SegmentFormat::Mpeg2TS => "video/mp2t",
        crate::SegmentFormat::Mp4 | crate::SegmentFormat::M4a => "video/mp4",
        crate::SegmentFormat::Aac => "audio/aac",
        _ => "application/octet-stream",
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(data))
        .unwrap())
}

impl Merger for ProxyMerger {
    type Result = ();

    async fn update(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        let stream_id = segment.stream_id;
        let sequence = segment.sequence;

        // Get segment file path from cache
        let path = cache.segment_path(&segment).await.ok_or_else(|| {
            crate::IoriError::IOError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Cache does not provide segment path",
            ))
        })?;

        // Store segment info
        self.segments
            .write()
            .await
            .entry(stream_id)
            .or_insert_with(BTreeMap::new)
            .insert(sequence, segment);

        // Store segment file path for on-demand reading
        self.segment_paths
            .write()
            .await
            .insert((stream_id, sequence), path);

        Ok(())
    }

    async fn fail(&mut self, segment: SegmentInfo, _cache: impl CacheSource) -> IoriResult<()> {
        let stream_id = segment.stream_id;
        let sequence = segment.sequence;

        tracing::warn!(
            "Segment {}/{} failed, marking as discontinued",
            stream_id,
            sequence
        );

        // Mark segment as failed to trigger discontinuity in playlist
        self.failed_segments
            .write()
            .await
            .insert((stream_id, sequence));

        // Still store segment info but without path
        self.segments
            .write()
            .await
            .entry(stream_id)
            .or_insert_with(BTreeMap::new)
            .insert(sequence, segment);

        Ok(())
    }

    async fn finish(&mut self, _cache: impl CacheSource) -> IoriResult<Self::Result> {
        // Mark stream as finished
        self.finished.store(true, Ordering::Relaxed);

        tracing::info!("Stream finished. Proxy server will stop running.");
        tracing::info!("Access playlist at http://{}/playlist.m3u8", self.addr);

        if let Some(handle) = self.server_handle.take() {
            // Wait for 1 minute before shutting down to allow clients to finish
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            handle.abort();
        }

        Ok(())
    }
}
