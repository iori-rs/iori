use super::inspect::{InspectorOptions, get_default_external_inspector};
use crate::{
    ShioriApp,
    commands::{ShioriArgs, update::check_update},
    i18n::ClapI18n,
    inspect::InspectPlaylist,
};
use clap::{Args, Parser};
use clap_handler::handler;
use fake_user_agent::get_chrome_rua;
use iori::{
    HttpClient,
    cache::{
        IoriCache,
        opendal::{Operator, services},
    },
    context::IoriContext,
    dash::live::CommonDashLiveSource,
    download::{ParallelDownloader, spawn_ctrlc_handler},
    hls::HlsLiveSource,
    merge::IoriMerger,
    raw::{HttpFileSource, RawDataSource, RawRemoteSegmentsSource},
    utils::{detect_manifest_type, sanitize},
};
use reqwest::{
    Client, IntoUrl,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use shiori_plugin::PlaylistType;
use std::{
    num::NonZeroU32,
    path::PathBuf,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

#[cfg(feature = "ffmpeg")]
type MergerType = iori_ffmpeg::FFmpegMerger;
#[cfg(not(feature = "ffmpeg"))]
type MergerType = iori::merge::auto::MkvmergeMerger;

#[derive(Parser, Clone, Default)]
#[clap(name = "download", visible_alias = "dl", short_flag = 'D')]
pub struct DownloadCommand<I>
where
    I: Args + Clone + Default + Send + Sync + 'static,
{
    #[clap(flatten)]
    pub http: HttpOptions,

    #[clap(flatten)]
    pub download: DownloadOptions,

    #[clap(flatten)]
    pub cache: CacheOptions,

    #[clap(flatten)]
    pub output: OutputOptions,

    #[clap(flatten)]
    pub decrypt: DecryptOptions,

    #[clap(skip)]
    pub extra: ExtraOptions,

    #[clap(short, long)]
    #[clap(about_ll = "download-wait")]
    pub wait: bool,

    #[clap(long = "experimental-ui", visible_alias = "tui")]
    #[clap(about_ll = "download-experimental-ui")]
    pub experimental_ui: bool,

    #[clap(flatten)]
    pub inspector_options: I,

    #[clap(about_ll = "download-url")]
    pub url: String,
}

impl<Ext> DownloadCommand<Ext>
where
    Ext: Args + Clone + Default + Send + Sync + 'static,
{
    pub async fn download(self, stop_signal: oneshot::Receiver<()>) -> anyhow::Result<()> {
        let app = ShioriApp::new(self.clone());
        let client = self.http.into_client(&self.url);
        let context = IoriContext {
            client,
            shaka_packager_command: self.decrypt.shaka_packager_command.clone().into(),
            manifest_retries: self.download.manifest_retries,
            segment_retries: self.download.segment_retries,
        };

        let playlist_type = match self.extra.playlist_type {
            Some(ty) => ty,
            None => detect_manifest_type(&self.url, &context.client)
                .await
                .map(|is_m3u8| {
                    if is_m3u8 {
                        PlaylistType::HLS
                    } else {
                        PlaylistType::DASH
                    }
                })?,
        };

        let downloader = ParallelDownloader::builder(context)
            .app(app)
            .concurrency(self.download.concurrency)
            .retries(self.download.segment_retries)
            .cache(self.cache.into_cache()?)
            .merger(self.output.into_merger()?)
            .stop_signal(stop_signal);

        match playlist_type {
            PlaylistType::HLS | PlaylistType::Unknown => {
                if matches!(playlist_type, PlaylistType::Unknown) {
                    log::warn!(
                        "Unknown playlist type detected, attempting to download as HLS playlist..."
                    );
                }

                let source = HlsLiveSource::new(self.url, self.decrypt.key.as_deref())?;
                downloader.download(source).await?;
            }
            PlaylistType::DASH => {
                let source = CommonDashLiveSource::new(
                    self.url.parse()?,
                    self.decrypt.key.as_deref(),
                    // self.decrypt.shaka_packager_command.clone(),
                )?;
                downloader.download(source).await?;
            }
            PlaylistType::RawData => {
                if let Some(initial_playlist_data) = self.extra.initial_playlist_data {
                    let source = RawDataSource::new(initial_playlist_data, self.url.clone());
                    downloader.download(source).await?;
                }
            }
            PlaylistType::Http => {
                let source = HttpFileSource::new(self.url, "raw".to_string());
                downloader.download(source).await?;
            }
            PlaylistType::RawRemoteSegments(segments) => {
                let source = RawRemoteSegmentsSource::new(segments);
                downloader.download(source).await?;
            }
        }

        Ok(())
    }

    fn merge(mut self, from: Self) -> Self {
        self.url = from.url;
        self.http.headers.extend(from.http.headers);
        self.http.cookies.extend(from.http.cookies);
        if self.decrypt.key.is_none() {
            self.decrypt.key = from.decrypt.key;
        }
        if self.output.output.is_none() {
            self.output.output = from.output.output;
        }
        self.extra = from.extra;

        self
    }
}

#[derive(Args, Clone, Debug)]
pub struct HttpOptions {
    #[clap(short = 'H', long = "header")]
    #[clap(about_ll = "download-http-headers")]
    pub headers: Vec<String>,

    #[clap(long = "cookie")]
    #[clap(about_ll = "download-http-cookies")]
    pub cookies: Vec<String>,

    #[clap(short, long, default_value = "10")]
    #[clap(about_ll = "download-http-timeout")]
    pub timeout: u64,

    #[clap(long, visible_alias = "http1")]
    #[clap(about_ll = "download-http-http1-only")]
    pub http1_only: bool,
}

impl HttpOptions {
    pub fn into_client(self, url: impl IntoUrl) -> HttpClient {
        let mut headers = HeaderMap::new();

        for header in &self.headers {
            let (key, value) = header.split_once(':').expect("Invalid header");
            headers.insert(
                HeaderName::from_str(key.trim()).expect("Invalid header name"),
                HeaderValue::from_str(value.trim()).expect("Invalid header value"),
            );
        }

        let mut builder = Client::builder()
            .default_headers(headers)
            .user_agent(get_chrome_rua())
            .timeout(Duration::from_secs(self.timeout))
            .danger_accept_invalid_certs(true);
        if self.http1_only {
            builder = builder.http1_only().http1_title_case_headers();
        }

        let client = HttpClient::new(builder);
        client.add_cookies(self.cookies, url);
        client
    }
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            cookies: Vec::new(),
            timeout: 10,
            http1_only: false,
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct DownloadOptions {
    #[clap(long, alias = "threads", default_value = "5")]
    #[clap(about_ll = "download-concurrency")]
    pub concurrency: NonZeroU32,

    #[clap(long, default_value = "5")]
    #[clap(about_ll = "download-segment-retries")]
    pub segment_retries: u32,

    #[clap(long, default_value = "3")]
    #[clap(about_ll = "download-manifest-retries")]
    pub manifest_retries: u32,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            concurrency: NonZeroU32::new(5).unwrap(),
            segment_retries: 5,
            manifest_retries: 3,
        }
    }
}

#[derive(Args, Clone, Debug, Default)]
pub struct CacheOptions {
    #[clap(short = 'm', long)]
    #[clap(about_ll = "download-cache-in-menory-cache")]
    pub in_memory_cache: bool,

    #[clap(long, env = "TEMP_DIR")]
    #[clap(about_ll = "download-cache-temp-dir")]
    pub temp_dir: Option<PathBuf>,

    #[clap(long)]
    #[clap(about_ll = "download-cache-cache-dir")]
    pub cache_dir: Option<PathBuf>,

    #[clap(long = "experimental-opendal")]
    pub opendal: bool,

    #[clap(long = "experimental-stream-dir-cache")]
    #[clap(about_ll = "download-cache-experimental-stream-dir-cache")]
    pub stream_dir_cache: bool,
}

impl CacheOptions {
    pub fn into_cache(self) -> anyhow::Result<IoriCache> {
        Ok(if self.in_memory_cache {
            IoriCache::memory()
        } else if let Some(cache_dir) = self.cache_dir {
            if self.stream_dir_cache {
                IoriCache::stream_dir_file(cache_dir)?
            } else {
                IoriCache::file(cache_dir)?
            }
        } else {
            let mut cache_dir = self
                .temp_dir
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(std::env::temp_dir);

            let started_at = SystemTime::now();
            let started_at = started_at.duration_since(UNIX_EPOCH).unwrap().as_millis();
            cache_dir.push(format!("shiori_{started_at}_{}", rand::random::<u8>()));

            if self.opendal {
                let cache_dir = cache_dir.to_str().expect("Invalid cache directory");
                let builder = services::Fs::default().root(cache_dir);
                let op = Operator::new(builder)?.finish();
                IoriCache::opendal(op, "shiori", true, None)
            } else if self.stream_dir_cache {
                IoriCache::stream_dir_file(cache_dir)?
            } else {
                IoriCache::file(cache_dir)?
            }
        })
    }
}

#[derive(Args, Clone, Debug, Default)]
pub struct DecryptOptions {
    #[clap(long = "key")]
    pub key: Option<String>,

    #[clap(long = "shaka-packager", visible_alias = "shaka")]
    pub shaka_packager_command: Option<PathBuf>,
}

#[derive(Clone, Default)]
pub struct ExtraOptions {
    /// Force Dash mode
    pub playlist_type: Option<PlaylistType>,
    pub initial_playlist_data: Option<String>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct OutputOptions {
    #[clap(flatten)]
    pub output_mode: OutputModeOptions,

    #[clap(short, long)]
    #[clap(about_ll = "download-output-output")]
    pub output: Option<PathBuf>,

    #[clap(long = "no-recycle", visible_aliases = ["keep-segments", "pipe-keep-segments"])]
    #[clap(default_value_t = true, action = clap::ArgAction::SetFalse)]
    #[clap(about_ll = "download-output-no-recycle")]
    pub recycle: bool,

    /// Proxy server bind address (default: 127.0.0.1:8080)
    #[clap(long, default_value = "127.0.0.1:8080")]
    pub proxy_addr: String,
}

#[derive(Args, Clone, Debug, Default)]
#[group(multiple = false)]
pub struct OutputModeOptions {
    #[clap(long)]
    #[clap(about_ll = "download-output-no-merge")]
    pub no_merge: bool,

    #[clap(long)]
    #[clap(about_ll = "download-output-concat")]
    pub concat: bool,

    #[clap(short = 'P', long)]
    #[clap(about_ll = "download-output-pipe")]
    pub pipe: bool,

    #[clap(short = 'M', long)]
    #[clap(about_ll = "download-output-pipe-mux")]
    pub pipe_mux: bool,

    #[clap(long)]
    #[clap(about_ll = "download-output-experimental-proxy")]
    pub proxy: bool,
}

impl OutputOptions {
    pub fn into_merger(self) -> anyhow::Result<IoriMerger<MergerType, MergerType>> {
        Ok(if self.output_mode.no_merge {
            IoriMerger::skip()
        } else if self.output_mode.proxy {
            let addr: std::net::SocketAddr =
                self.proxy_addr.parse().expect("Invalid proxy address");
            IoriMerger::proxy(addr)
        } else if self.output_mode.pipe || self.output_mode.pipe_mux {
            if self.output_mode.pipe_mux {
                IoriMerger::pipe_mux(self.output.unwrap_or("-".into()), self.recycle, None)
            } else if let Some(file) = self.output {
                IoriMerger::pipe_to_file(file, self.recycle)
            } else {
                IoriMerger::pipe(self.recycle)
            }
        } else if let Some(mut output) = self.output {
            if output.exists() {
                log::warn!("Output file exists. Will add suffix automatically.");
                let original_extension = output.extension();
                let new_extension = match original_extension {
                    Some(ext) => format!("{}.ts", ext.to_str().unwrap()),
                    None => "ts".to_string(),
                };
                output = output.with_extension(new_extension);
            }

            if self.output_mode.concat {
                IoriMerger::concat(output, self.recycle)
            } else {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "ffmpeg")] {
                        IoriMerger::auto(output, self.recycle, iori_ffmpeg::FFmpegMerger, iori_ffmpeg::FFmpegMerger)
                    } else {
                        IoriMerger::mkvmerge(output, self.recycle)
                    }
                }
            }
        } else {
            anyhow::bail!("Output file must be specified unless --pipe or --no-merge is used");
        })
    }
}

type ShioriDownloadCommand = DownloadCommand<InspectorOptions>;

#[handler(ShioriDownloadCommand)]
pub async fn download(me: ShioriDownloadCommand, shiori_args: ShioriArgs) -> anyhow::Result<()> {
    tracing::info!("Loading URL: {}", me.url);
    let (_, data) = get_default_external_inspector()
        .wait(me.wait)
        .inspect(&me.url, &me.inspector_options, |c| {
            tracing::warn!("Selecting inspector candidates is not implemented yet. Falling back to the first candidate.");
            c.into_iter().next().unwrap()
        })
        .await?;

    let playlist_downloads: Vec<ShioriDownloadCommand> =
        data.into_iter().map(|r| r.into()).collect();
    tracing::info!("Found {} playlist(s)", playlist_downloads.len());

    for playlist in playlist_downloads {
        let command: ShioriDownloadCommand = playlist;
        let cmd = me.clone().merge(command);
        cmd.download(spawn_ctrlc_handler()).await?;
    }

    // Check for update, but do not throw error if failed
    if shiori_args.update_check {
        _ = check_update().await;
    }
    Ok(())
}

impl<Ext> From<InspectPlaylist> for DownloadCommand<Ext>
where
    Ext: Args + Clone + Default + Send + Sync + 'static,
{
    fn from(data: InspectPlaylist) -> Self {
        Self {
            http: HttpOptions {
                headers: data.headers,
                cookies: data.cookies,
                ..Default::default()
            },
            decrypt: DecryptOptions {
                key: data.key,
                ..Default::default()
            },
            cache: CacheOptions {
                // Enable in-memory cache if the playlist is raw and has initial playlist data
                in_memory_cache: matches!(data.playlist_type, PlaylistType::RawData)
                    && data.initial_playlist_data.is_some(),
                ..Default::default()
            },
            extra: ExtraOptions {
                playlist_type: Some(data.playlist_type),
                initial_playlist_data: data.initial_playlist_data,
            },
            output: OutputOptions {
                output: data.title.map(|title| sanitize(&title).into()),
                output_mode: OutputModeOptions {
                    pipe_mux: data.streams_hint.unwrap_or(1) > 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            url: data.playlist_url,

            ..Default::default()
        }
    }
}
