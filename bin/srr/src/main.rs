use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
mod config;
mod webhook;

use config::Config;
use iori::{
    HttpClient,
    cache::{
        IoriCache,
        opendal::{Configurator, Operator},
    },
    context::IoriContext,
    download::ParallelDownloader,
    hls::HlsLiveSource,
    merge::IoriMerger,
};
use iori_showroom::{
    ShowRoomClient,
    model::{OnliveRoomInfo, RoomProfile},
};
use tokio::signal::unix::{SignalKind, signal};

use crate::{config::WebhookConfig, webhook::WebhookBody};

#[derive(Clone)]
struct MonitorConfig {
    room_slugs: Vec<String>,
    webhook: Option<WebhookConfig>,
}

struct ShowroomMonitor {
    config: Arc<Mutex<MonitorConfig>>,
    operator: Operator,
    onlive: Arc<Mutex<HashSet<String>>>,
}

impl ShowroomMonitor {
    fn new(
        room_slugs: Vec<String>,
        webhook: Option<WebhookConfig>,
        operator: Operator,
    ) -> Arc<Self> {
        Arc::new(Self {
            config: Arc::new(Mutex::new(MonitorConfig {
                room_slugs,
                webhook,
            })),
            operator,
            onlive: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn update_config(self: Arc<Self>, room_slugs: Vec<String>, webhook: Option<WebhookConfig>) {
        let mut config = self.config.lock().unwrap();
        config.room_slugs = room_slugs;
        config.webhook = webhook;

        log::info!("Updated existing monitoring job configuration");
    }

    fn start(self: Arc<Self>) {
        log::info!("Start monitoring online rooms");

        tokio::spawn(async move {
            loop {
                if let Err(e) = self.clone().scan().await {
                    log::error!("Failed to monitor online rooms: {e}");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    }

    async fn scan(self: Arc<Self>) -> anyhow::Result<()> {
        let client = ShowRoomClient::new(None).await?;

        let (room_slugs, webhook) = {
            let config = self.config.lock().unwrap();
            (config.room_slugs.clone(), config.webhook.clone())
        };

        let mut onlive_rooms: HashMap<_, _> = client
            .onlives()
            .await?
            .into_iter()
            .filter(|r| room_slugs.contains(&r.room_url_key))
            .map(|r| (r.room_url_key.clone(), r))
            .collect();
        log::debug!("Found {} online rooms", onlive_rooms.len());

        let mut recording_rooms = self.onlive.lock().unwrap();

        for room_slug in room_slugs {
            if recording_rooms.contains(&room_slug) {
                continue;
            }

            if let Some(room_info) = onlive_rooms.remove(&room_slug) {
                recording_rooms.insert(room_slug.clone());

                log::info!("Starting recording for room: {}", room_slug);
                let client = client.clone();
                let operator = self.operator.clone();
                let webhook = webhook.clone();
                let onlive_clone = self.onlive.clone();
                let room_slug_clone = room_slug.clone();

                tokio::spawn(async move {
                    let live_id = room_info.live_id;
                    let live_started_at = chrono::DateTime::from_timestamp(room_info.started_at, 0)
                        .unwrap()
                        .with_timezone(&chrono_tz::Asia::Tokyo)
                        .to_rfc3339();
                    let prefix = format!("{room_slug}/{live_id}_{live_started_at}");

                    let profile = RoomProfile {
                        room_name: room_info.main_name.clone(),
                        live_id,
                        current_live_started_at: room_info.started_at,
                    };
                    if let Some(webhook) = webhook.clone() {
                        let body = WebhookBody {
                            event: "start",
                            prefix: prefix.clone(),
                            profile: profile.clone(),
                        };
                        tokio::spawn(async move {
                            let client = HttpClient::default();
                            let _ = client.post(&webhook.url).json(&body).send().await;
                        });
                    }

                    // Start recording
                    if let Err(e) = record_room(client, room_info, prefix.clone(), operator).await {
                        log::error!("Failed to record room {}: {e}", room_slug_clone);
                    }

                    if let Some(webhook) = webhook {
                        let body = WebhookBody {
                            event: "end",
                            prefix: prefix.clone(),
                            profile,
                        };
                        tokio::spawn(async move {
                            let client = HttpClient::default();
                            let _ = client.post(webhook.url).json(&body).send().await;
                        });
                    }

                    // Remove from recording rooms
                    let mut onlive = onlive_clone.lock().unwrap();
                    onlive.remove(&room_slug_clone);
                });
            }
        }

        Ok(())
    }
}

async fn record_room(
    client: ShowRoomClient,
    room_info: OnliveRoomInfo,
    prefix: String,
    operator: Operator,
) -> anyhow::Result<()> {
    let room_id = room_info.room_id;
    let room_slug = &room_info.room_url_key;
    log::debug!("Recording room {room_slug}, id = {room_id}");

    let stream = client.live_streaming_url(room_id).await?;
    let Some(stream) = stream.best(false) else {
        log::warn!("No streaming URL available for room {room_slug}");
        return Ok(());
    };

    let live_id = room_info.live_id;
    log::info!("Start recording room {room_slug}, id = {room_id}, live_id = {live_id}");

    let client = HttpClient::default();
    let source = HlsLiveSource::new(stream.url.clone(), None)?;
    let cache = IoriCache::opendal(
        operator.clone(),
        prefix.clone(),
        false,
        Some("application/octet-stream".to_string()),
    );
    let merger = IoriMerger::<(), ()>::skip();
    let result = ParallelDownloader::builder(IoriContext {
        client,
        ..Default::default()
    })
    .app(())
    .cache(cache)
    .merger(merger)
    .ctrlc_handler()
    .download(source)
    .await;

    Ok(result?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .try_from_env()
                .unwrap_or_else(|_| {
                    "info,tokio_cron_scheduler=warn,iori::hls=warn,iori::download=warn".into()
                }),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::load()?;

    let operator = Operator::new(config.s3.into_builder())?.finish();
    let monitor = ShowroomMonitor::new(config.showroom.rooms, config.webhook, operator);
    monitor.clone().start();

    let mut sigusr1_stream = signal(SignalKind::user_defined1())?;
    let mut sigint_stream = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = sigusr1_stream.recv() => {
                log::warn!("SIGUSR1 received. Reloading config...");
                // SIGUSR1 received, reload config
                let config = Config::load()?;
                monitor.clone().update_config(
                    config.showroom.rooms,
                    config.webhook,
                );
                log::warn!("Config reloaded.");
            }
            _ = sigint_stream.recv() => {
                // SIGINT received, break the loop for graceful shutdown
                log::warn!("SIGINT received. Shutting down...");
                break;
            }
        }
    }

    Ok(())
}
