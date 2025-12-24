use std::str::FromStr;

use chrono::{DateTime, Utc};
use shiori_plugin::{iori::reqwest::ClientBuilder, *};

use iori_nicolive::{
    danmaku::{DanmakuClient, DanmakuList},
    model::{WatchMessageMessageServer, WatchMessageStream, WatchResponse},
    program::{NicoEmbeddedData, NivoServerResponse},
    watch::WatchClient,
};

pub struct NiconicoPlugin;

impl ShioriPlugin for NiconicoPlugin {
    fn name(&self) -> Cow<'static, str> {
        "niconico".into()
    }

    fn version(&self) -> Cow<'static, str> {
        "0.1.0".into()
    }

    fn description(&self) -> Option<Cow<'static, str>> {
        Some("Extracts Niconico live streams, timeshifts and videos.".into())
    }

    fn arguments(&self, command: &mut dyn InspectorCommand) {
        command.add_argument(
            "nico-user-session",
            Some("user_session"),
            "[Niconico] Your Niconico user session key.",
        );
        command.add_boolean_argument(
                "nico-download-danmaku",
                "[NicoLive] Download danmaku together with the video. This option is ignored if `--nico-danmaku-only` is set to true.",
            );
        command.add_boolean_argument(
            "nico-chase-play",
            "[NicoLive] Download an ongoing live from start.",
        );
        command.add_boolean_argument(
            "nico-reserve-timeshift",
            "[NicoLive] Whether to reserve a timeshift if not reserved.",
        );
        command.add_boolean_argument(
            "nico-danmaku-only",
            "[NicoLive] Only download danmaku without video.",
        );
    }

    fn register(&self, registry: &mut dyn InspectorRegistry) -> anyhow::Result<()> {
        registry.register_inspector(
            Regex::new(r"https://live\.nicovideo\.jp/watch/lv.*").unwrap(),
            Box::new(NicoLiveInspector),
            PriorityHint::Normal,
        );
        registry.register_inspector(
            Regex::new(r"https://www\.nicovideo\.jp/watch/(?:so|sm).*").unwrap(),
            Box::new(NicoVideoInspector),
            PriorityHint::Normal,
        );

        Ok(())
    }
}

struct NicoLiveInspector;

impl NicoLiveInspector {
    pub async fn download_danmaku(
        &self,
        builder: ClientBuilder,
        message_server: WatchMessageMessageServer,
        program_end_time: u64,
    ) -> anyhow::Result<DanmakuList> {
        let client = DanmakuClient::new(builder, message_server.view_uri).await?;
        let end_time = program_end_time + 30 * 60;
        let backward = client.get_backward_segment(end_time.to_string()).await?;
        let segment = backward
            .segment
            .ok_or_else(|| anyhow::anyhow!("No segment found in the backward segment"))?;
        let start_time = DateTime::<Utc>::from_str(&message_server.vpos_base_time)
            .map(|r| r.timestamp())
            .ok();

        let danmaku = client.recv_all(segment.uri, start_time).await?;
        Ok(danmaku)
    }
}

#[async_trait]
impl Inspect for NicoLiveInspector {
    fn name(&self) -> Cow<'static, str> {
        "nicolive".into()
    }

    async fn inspect(
        &self,
        context: &ShioriContext,
        url: &str,
        _captures: &Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let user_session = args.get_string("nico-user-session");
        let download_danmaku = args.get_boolean("nico-download-danmaku");
        let chase_play = args.get_boolean("nico-chase-play");
        let reserve_timeshift = args.get_boolean("nico-reserve-timeshift");
        let danmaku_only = args.get_boolean("nico-danmaku-only");

        let data = NicoEmbeddedData::new(
            context.http.builder(),
            url.to_string(),
            user_session.as_deref(),
        )
        .await?;
        let wss_url = if let Some(wss_url) = data.websocket_url() {
            wss_url
        } else if reserve_timeshift {
            data.timeshift_reserve().await?;
            let data = NicoEmbeddedData::new(
                context.http.builder(),
                url.to_string(),
                user_session.as_deref(),
            )
            .await?;
            data.websocket_url()
                .ok_or_else(|| anyhow::anyhow!("no websocket url"))?
        } else {
            anyhow::bail!("no websocket url");
        };

        let best_quality = data.best_quality()?;
        let download_danmaku = download_danmaku || danmaku_only;

        let watcher = WatchClient::new(context.http.builder(), &wss_url).await?;
        watcher.start_watching(&best_quality, chase_play).await?;

        let mut stream: Option<WatchMessageStream> = None;
        let mut message_server: Option<WatchMessageMessageServer> = None;
        loop {
            let msg = watcher.recv().await?;
            if let Some(WatchResponse::Stream(got_stream)) = msg {
                stream = Some(got_stream);
            } else if let Some(WatchResponse::MessageServer(got_message_server)) = msg {
                message_server = Some(got_message_server);
            }

            if stream.is_some() && (!download_danmaku || message_server.is_some()) {
                break;
            }
        }
        let stream = stream.unwrap();

        // keep seats
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = watcher.recv() => {
                        if let Err(e) = msg {
                            tracing::error!("{e:?}");
                            if let Err(e) = watcher
                                .reconnect(&wss_url, &best_quality, chase_play)
                                .await
                            {
                                tracing::error!("Failed to reconnect: {e:?}");
                                break;
                            }
                        }
                    }
                    _ = watcher.keep_seat() => (),
                }
            }
            tracing::info!("watcher disconnected");
        });

        let mut result = vec![];
        if !danmaku_only {
            result.push(InspectPlaylist {
                title: Some(data.program_title()),
                playlist_url: stream.uri,
                playlist_type: PlaylistType::HLS,
                cookies: stream.cookies.into_cookies(),
                streams_hint: Some(2),
                ..Default::default()
            });
        }

        if let Some(message_server) = message_server {
            let danmaku = self
                .download_danmaku(
                    context.http.builder(),
                    message_server,
                    data.program_end_time(),
                )
                .await?;
            result.push(InspectPlaylist {
                title: Some(data.program_title()),
                playlist_url: "danmaku.json".to_string(),
                playlist_type: PlaylistType::RawData,
                initial_playlist_data: Some(danmaku.to_json(true)?),
                ..Default::default()
            });
            match danmaku.to_ass() {
                Ok(ass_data) => {
                    result.push(InspectPlaylist {
                        title: Some(data.program_title()),
                        playlist_url: "danmaku.ass".to_string(),
                        playlist_type: PlaylistType::RawData,
                        initial_playlist_data: Some(ass_data),
                        ..Default::default()
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to generate ASS subtitle from danmaku: {e:?}");
                }
            }
        }

        Ok(InspectResult::Playlists(result))
    }
}

struct NicoVideoInspector;

#[async_trait]
impl Inspect for NicoVideoInspector {
    fn name(&self) -> Cow<'static, str> {
        "nicovideo".into()
    }

    async fn inspect(
        &self,
        context: &ShioriContext,
        url: &str,
        _captures: &Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let user_session = args.get_string("nico-user-session");
        let data =
            NivoServerResponse::new(context.http.builder(), url, user_session.as_deref()).await?;
        let (playlist_url, cookies) = data.playlist_url().await?;
        Ok(InspectResult::Playlists(vec![InspectPlaylist {
            title: data.program_title(),
            playlist_url,
            playlist_type: PlaylistType::HLS,
            headers: vec![format!("Cookie: {cookies}")],
            ..Default::default()
        }]))
    }
}
