use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::{
    io::AsyncWrite,
    sync::{Mutex, mpsc},
};
use url::Url;

use crate::{
    StreamingSource,
    error::{IoriError, IoriResult},
    fetch::fetch_segment,
    hls::{segment::M3u8Segment, source::HlsPlaylistSource},
    util::{http::HttpClient, mix::VecMix},
};

pub struct HlsLiveSource {
    client: HttpClient,
    playlist: Arc<Mutex<HlsPlaylistSource>>,
    retry: u32,
    shaka_packager_command: Option<PathBuf>,
}

impl HlsLiveSource {
    pub fn new(
        client: HttpClient,
        m3u8_url: String,
        key: Option<&str>,
        shaka_packager_command: Option<PathBuf>,
    ) -> Self {
        Self {
            client: client.clone(),
            playlist: Arc::new(Mutex::new(HlsPlaylistSource::new(
                client,
                Url::parse(&m3u8_url).unwrap(),
                key,
            ))),
            shaka_packager_command,
            retry: 3,
        }
    }

    pub fn with_retry(mut self, retry: u32) -> Self {
        self.retry = retry;
        self
    }
}

impl StreamingSource for HlsLiveSource {
    type Segment = M3u8Segment;

    async fn fetch_info(
        &self,
    ) -> IoriResult<mpsc::UnboundedReceiver<IoriResult<Vec<Self::Segment>>>> {
        let mut latest_media_sequences =
            self.playlist.lock().await.load_streams(self.retry).await?;

        let (sender, receiver) = mpsc::unbounded_channel();

        let retry = self.retry;
        let playlist = self.playlist.clone();
        tokio::spawn(async move {
            loop {
                if sender.is_closed() {
                    break;
                }

                let before_load = tokio::time::Instant::now();
                let (segments, is_end) = match playlist
                    .lock()
                    .await
                    .load_segments(&latest_media_sequences, retry)
                    .await
                {
                    Ok(v) => v,
                    Err(IoriError::ManifestFetchError) => {
                        tracing::error!("Exceeded retry limit for fetching segments, exiting...");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch segments: {e}");
                        break;
                    }
                };

                let segments_average_duration = segments
                    .iter()
                    .map(|ss| {
                        let total_seconds = ss.iter().map(|s| s.duration).sum::<f32>();
                        let segments_count = ss.len() as f32;

                        if segments_count == 0. {
                            0
                        } else {
                            (total_seconds * 1000. / segments_count) as u64
                        }
                    })
                    .min()
                    .unwrap_or(5);

                for (segments, latest_media_sequence) in
                    segments.iter().zip(latest_media_sequences.iter_mut())
                {
                    *latest_media_sequence = segments
                        .last()
                        .map(|r| r.media_sequence)
                        .or(*latest_media_sequence);
                }

                let mixed_segments = segments.mix();
                if !mixed_segments.is_empty()
                    && let Err(e) = sender.send(Ok(mixed_segments))
                {
                    tracing::error!("Failed to send mixed segments: {e}");
                    break;
                }

                if is_end {
                    break;
                }

                // playlist does not end, wait for a while and fetch again
                let seconds_to_wait = segments_average_duration.clamp(1000, 5000);
                tokio::time::sleep_until(before_load + Duration::from_millis(seconds_to_wait))
                    .await;
            }
        });

        Ok(receiver)
    }

    async fn fetch_segment<W>(&self, segment: &Self::Segment, writer: &mut W) -> IoriResult<()>
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        fetch_segment(
            self.client.clone(),
            segment,
            writer,
            self.shaka_packager_command.clone(),
        )
        .await?;
        Ok(())
    }
}
