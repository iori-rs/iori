use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{io::AsyncWrite, sync::mpsc};
use url::Url;

use crate::{
    InitialSegment, SegmentType, StreamingSource, dash::segment::DashSegment, decrypt::IoriKey,
    error::IoriResult, fetch::fetch_segment, util::http::HttpClient,
};

use super::{template::Template, url::merge_baseurls};

// TODO: mark as deprecated
// #[deprecated(note = "Use `CommonDashLiveSource` instead")]
pub struct CommonDashArchiveSource {
    client: HttpClient,
    mpd: Url,
    key: Option<Arc<IoriKey>>,
    sequence: AtomicU64,
    shaka_packager_command: Option<PathBuf>,
}

impl CommonDashArchiveSource {
    pub fn new(
        client: HttpClient,
        mpd: String,
        key: Option<&str>,
        shaka_packager_command: Option<PathBuf>,
    ) -> IoriResult<Self> {
        let key = if let Some(k) = key {
            Some(Arc::new(IoriKey::clear_key(k)?))
        } else {
            None
        };

        Ok(Self {
            client,
            mpd: Url::parse(&mpd)?,
            key,
            sequence: AtomicU64::new(0),
            shaka_packager_command,
        })
    }
}

impl StreamingSource for CommonDashArchiveSource {
    type Segment = DashSegment;

    async fn fetch_info(
        &self,
    ) -> IoriResult<mpsc::UnboundedReceiver<IoriResult<Vec<Self::Segment>>>> {
        let (sender, receiver) = mpsc::unbounded_channel();

        let text = self
            .client
            .get(self.mpd.as_ref())
            .header("Accept", "application/dash+xml,video/vnd.mpeg.dash.mpd")
            .send()
            .await
            .expect("requesting MPD content")
            .text()
            .await
            .expect("fetching MPD content");
        let mpd = dash_mpd::parse(&text)?;

        let Some("static") = mpd.mpdtype.as_deref() else {
            panic!("only static MPD is supported");
        };

        let mut base_url = self.mpd.clone();
        if let Some(mpd_base_url) = mpd.base_url.first() {
            base_url = merge_baseurls(&base_url, &mpd_base_url.base)?;
        }

        for period in mpd.periods {
            let base_url = if let Some(mpd_base_url) = period.BaseURL.first() {
                Cow::Owned(merge_baseurls(&base_url, &mpd_base_url.base)?)
            } else {
                Cow::Borrowed(&base_url)
            };

            for adaptation in period.adaptations {
                let base_url = if let Some(mpd_base_url) = adaptation.BaseURL.first() {
                    Cow::Owned(merge_baseurls(&base_url, &mpd_base_url.base)?)
                } else {
                    base_url.clone()
                };

                let mime_type = adaptation.contentType.or(adaptation.mimeType);
                let frame_rate = adaptation.frameRate; // TODO: GetFrameRate

                let representation = adaptation
                    .representations
                    .into_iter()
                    // TODO: better representation select logic
                    .max_by_key(|r| r.bandwidth.unwrap_or(0))
                    .unwrap();

                let base_url = if let Some(mpd_base_url) = representation.BaseURL.first() {
                    Cow::Owned(merge_baseurls(&base_url, &mpd_base_url.base)?)
                } else {
                    base_url.clone()
                };

                let mime_type = mime_type
                    .clone() // TODO: do not clone here
                    .or(representation.contentType)
                    .or(representation.mimeType);

                let bandwidth = representation.bandwidth.unwrap_or(0);
                let codecs = representation
                    .codecs
                    .as_deref()
                    .or(adaptation.codecs.as_deref());
                let language = representation
                    .lang
                    .as_deref()
                    .or(adaptation.lang.as_deref());
                let frame_rate = frame_rate
                    .as_deref()
                    .or(representation.frameRate.as_deref());
                let resolution = representation
                    .width
                    .and_then(|w| representation.height.map(|h| (w, h)))
                    .map(|(w, h)| format!("{w}x{h}"));

                let mut template = Template::new();
                if let Some(representation_id) = representation.id {
                    template.insert(Template::REPRESENTATION_ID, representation_id);
                }
                template.insert(Template::BANDWIDTH, bandwidth.to_string());

                let mut segments = Vec::new();

                // 1. TODO: SegmentBase
                if let Some(segment_base) = representation.SegmentBase
                    && let Some(initialization) = segment_base.Initialization
                {
                    if let Some(source_url) = initialization.sourceURL {
                        // let url = base_url;
                        let init_url = base_url.join(&source_url)?;
                        let init_range = initialization.range.as_deref();

                        // TODO: set init
                    } else {
                        //
                    }
                }

                if let Some(segment_template) = representation
                    .SegmentTemplate
                    .or(adaptation.SegmentTemplate)
                {
                    let time_scale = segment_template.timescale.unwrap_or(1);
                    let initial_segment =
                        if let Some(initialization) = segment_template.initialization {
                            let initialization = template.resolve(&initialization);
                            let url = merge_baseurls(&base_url, &initialization)?;
                            let bytes = self.client.get(url).send().await?.bytes().await?.to_vec();
                            InitialSegment::Clear(Arc::new(bytes))
                        } else {
                            InitialSegment::None
                        };

                    if let Some(ref media_template) = segment_template.media {
                        let mut current_time = 0;
                        let mut segment_number = segment_template.startNumber.unwrap_or(1);

                        // SegmentTemplate + SegmentTimeline
                        if let Some(segment_timeline) = segment_template.SegmentTimeline {
                            for segment in segment_timeline.segments.iter() {
                                if let Some(t) = segment.t {
                                    current_time = t;
                                }

                                let duration = segment.d;
                                let repeat = segment.r.unwrap_or(0);
                                for _ in 0..(repeat + 1) {
                                    template
                                        .insert(Template::TIME, current_time.to_string())
                                        .insert(Template::NUMBER, segment_number.to_string());
                                    let filename = template.resolve(media_template);
                                    let url = merge_baseurls(&base_url, &filename)?;

                                    let segment = DashSegment {
                                        url,
                                        filename,
                                        r#type: SegmentType::from_mime_type(mime_type.as_deref()),
                                        initial_segment: initial_segment.clone(),
                                        key: self.key.clone(),
                                        sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
                                        stream_id: 0,
                                        byte_range: None,
                                        time: None,
                                    };
                                    segments.push(segment);

                                    segment_number += 1;
                                    current_time += duration;
                                }
                            }
                        } else if let Some(segment_duration) = segment_template.duration {
                            // SegmentTemplate + SegmentDuration
                            let total_segments = (period
                                .duration
                                .or(mpd.mediaPresentationDuration)
                                .expect("missing duration")
                                .as_secs() as f64
                                * time_scale as f64
                                / segment_duration)
                                .ceil() as u64;
                            for _ in 1..=total_segments {
                                template.insert(Template::NUMBER, segment_number.to_string());
                                let filename = template.resolve(media_template);
                                let url = merge_baseurls(&base_url, &filename)?;

                                let filename = url
                                    .path_segments()
                                    .and_then(|mut c| c.next_back())
                                    .map_or_else(|| "output.m4s".to_string(), |s| s.to_string());

                                let segment = DashSegment {
                                    url,
                                    filename,
                                    r#type: SegmentType::from_mime_type(mime_type.as_deref()),
                                    initial_segment: initial_segment.clone(),
                                    key: self.key.clone(),
                                    sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
                                    stream_id: 0,
                                    byte_range: None,
                                    time: None,
                                };
                                segments.push(segment);

                                segment_number += 1;
                            }
                        }
                    }

                    // segment.url =
                    //     merge_baseurls(&base_url, &resolve_url_template(&segment.url, &params))?;
                }

                sender.send(Ok(segments)).unwrap();
            }
        }

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
