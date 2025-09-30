use std::collections::BTreeMap;

use clap::Args;
use clap_handler::handler;
use reqwest::header::CONTENT_LENGTH;
use serde_json::Value;
use ssup::{
    Credential,
    upos::Upos,
    video::{Subtitle, Video},
};

use iori::{
    HttpClient, IoriError, IoriResult, RemoteStreamingSegment, SegmentInfo, StreamingSource,
    cache::{CacheSource, memory::MemoryCacheSource},
    download::ParallelDownloader,
    hls::{CommonM3u8ArchiveSource, segment::M3u8Segment},
    merge::Merger,
};
use tokio::io::AsyncReadExt;

#[derive(Args, Clone)]
pub struct UploadCommand {
    #[arg(short, long)]
    pub key: Option<String>,

    /// Video title
    #[arg(long)]
    pub title: String,

    /// Video description
    #[arg(long, default_value = "")]
    pub description: String,

    url: String,
}

async fn get_segment_sizes(source: &CommonM3u8ArchiveSource) -> IoriResult<BTreeMap<u64, u64>> {
    let mut receiver = source.fetch_info().await?;

    let mut result = BTreeMap::new();
    while let Some(segments_result) = receiver.recv().await {
        let segments = segments_result?;

        for segment in segments {
            let size = get_segment_size(&segment).await?;
            result.insert(segment.sequence, size);
        }
    }

    Ok(result)
}

async fn get_segment_size(segment: &M3u8Segment) -> IoriResult<u64> {
    let client = reqwest::Client::new();

    let mut request_builder = client.head(segment.url());

    if let Some(headers) = segment.headers() {
        for (key, value) in headers.iter() {
            request_builder = request_builder.header(key, value);
        }
    }

    let response = request_builder
        .send()
        .await
        .map_err(IoriError::RequestError)?;

    if !response.status().is_success() {
        return Err(IoriError::HttpError(response.status()));
    }

    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| {
            IoriError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to get Content-Length",
            ))
        })?;

    Ok(content_length)
}

pub struct BilibiliSubmitMerger {
    sizes: BTreeMap<u64, u64>,
    client: ssup::Client,
    upos: Upos,

    completed_segments: BTreeMap<u64, Value>,
    failed_segments: Vec<SegmentInfo>,

    video: Video,
}

impl BilibiliSubmitMerger {
    pub async fn new(video: Video, sizes: BTreeMap<u64, u64>) -> anyhow::Result<Self> {
        let credentials =
            serde_json::from_str::<Credential>(&std::fs::read_to_string("credentials.json")?)?;

        let client = ssup::Client::auto(credentials).await?;
        let bucket = client
            .upload_line()
            .pre_upload(&client, "output.ts", 100)
            .await?;
        let upos = Upos::from(bucket).await?;

        Ok(Self {
            sizes,
            client,
            upos,
            completed_segments: BTreeMap::new(),
            failed_segments: Vec::new(),
            video,
        })
    }

    pub fn offset(&self, sequence: u64) -> u64 {
        self.sizes
            .iter()
            .take_while(|(k, _)| k < &&sequence)
            .map(|(_, v)| v)
            .sum()
    }
}

impl Merger for BilibiliSubmitMerger {
    type Result = ();

    async fn update(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        let mut reader = cache.open_reader(&segment).await?;
        let mut chunk = Vec::new();
        reader.read_to_end(&mut chunk).await?;

        let current_chunk = segment.sequence as usize;
        let chunks_num = self.sizes.len();
        let start = 0;
        let total_size = self.sizes.values().sum::<u64>();

        let chunk = self
            .upos
            .upload_chunk(chunk.into(), current_chunk, chunks_num, start, total_size)
            .await
            .inspect_err(|e| {
                println!("分片 {} 上传失败: {}", segment.file_name, e);
            })
            .map_err(|e| IoriError::CustomError(e.to_string()))?;

        self.completed_segments.insert(segment.sequence, chunk);
        cache.invalidate(&segment).await?;
        Ok(())
    }

    async fn fail(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        cache.invalidate(&segment).await?;
        self.failed_segments.push(segment);
        Ok(())
    }

    async fn finish(&mut self, _cache: impl CacheSource) -> IoriResult<Self::Result> {
        println!("所有分片处理完成，正在提交投稿...");

        if !self.failed_segments.is_empty() {
            println!("警告: {} 个分片上传失败", self.failed_segments.len());
            for segment in &self.failed_segments {
                println!("  失败分片: {}", segment.file_name);
            }
        }

        let parts = self
            .completed_segments
            .clone()
            .into_values()
            .collect::<Vec<_>>();
        let video = self
            .upos
            .get_ret_video_info(&parts, "output.ts")
            .await
            .unwrap();

        self.video.videos = vec![video];
        self.client.submit(&self.video).await.unwrap();

        println!("投稿提交完成！");

        Ok(())
    }
}

#[handler(UploadCommand)]
async fn upload(me: UploadCommand) -> anyhow::Result<()> {
    let client = HttpClient::default();

    let source = CommonM3u8ArchiveSource::new(
        client.clone(),
        me.url.clone(),
        me.key.as_deref(),
        Default::default(),
        None,
    );

    let sizes = get_segment_sizes(&source).await?;
    let video = Video {
        copyright: 2,
        source: "internet".to_string(),
        tid: 6,
        cover: "".to_string(),
        title: me.title,
        desc_format_id: 0,
        desc: me.description.clone(),
        dynamic: me.description,
        subtitle: Subtitle {
            open: 0,
            lan: "".to_string(),
        },
        tag: "".to_string(),
        videos: vec![],
        display_time: None,
        open_subtitle: false,
    };
    let merger = BilibiliSubmitMerger::new(video, sizes).await?;
    ParallelDownloader::builder()
        .retries(3)
        .cache(MemoryCacheSource::new())
        .merger(merger)
        .download(source)
        .await?;

    Ok(())
}
