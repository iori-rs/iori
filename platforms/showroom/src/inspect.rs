use std::borrow::Cow;

use shiori_plugin::*;

use crate::ShowRoomClient;

pub struct ShowroomPlugin;

impl ShioriPlugin for ShowroomPlugin {
    fn name(&self) -> Cow<'static, str> {
        "showroom".into()
    }

    fn version(&self) -> Cow<'static, str> {
        "0.1.0".into()
    }

    fn description(&self) -> Option<Cow<'static, str>> {
        Some("Extracts Showroom playlists from the given URL.".into())
    }

    fn arguments(&self, command: &mut dyn InspectorCommand) {
        command.add_argument(
            "showroom-user-session",
            Some("sr_id"),
            "[Showroom] Your Showroom user session key.",
        );
    }

    fn register(&self, registry: &mut dyn InspectorRegistry) -> anyhow::Result<()> {
        registry.register_inspector(
            Regex::new(r"https://www.showroom-live.com/r/(?<room_name>.*)").unwrap(),
            Box::new(ShowroomLiveInspector),
            PriorityHint::Normal,
        );
        registry.register_inspector(
            Regex::new(r"https://www.showroom-live.com/timeshift/(?<room_url_key>[^/]+)\/(?<view_url_key>.+)").unwrap(),
            Box::new(ShowroomTimeshiftInspector),
            PriorityHint::Normal,
        );

        Ok(())
    }
}

struct ShowroomLiveInspector;

#[async_trait]
impl Inspect for ShowroomLiveInspector {
    fn name(&self) -> Cow<'static, str> {
        "showroom-live".into()
    }

    async fn inspect(
        &self,
        _url: &str,
        captures: &regex::Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let client = ShowRoomClient::new(args.get_string("sr-id")).await?;

        let room_name = captures.name("room_name").unwrap();
        let room_id = match room_name.as_str().parse::<u64>() {
            Ok(room_id) => room_id,
            Err(_) => client.room_info(room_name.as_str()).await?.id,
        };

        let info = client.live_info(room_id).await?;
        if !info.is_living() {
            return Ok(InspectResult::None);
        }

        let streams = client.live_streaming_url(room_id).await?;
        let Some(stream) = streams.best(false) else {
            return Ok(InspectResult::None);
        };

        Ok(InspectResult::Playlist(InspectPlaylist {
            title: Some(info.room_name),
            playlist_url: stream.url.clone(),
            playlist_type: PlaylistType::HLS,
            ..Default::default()
        }))
    }
}

/// https://showroom-live.com/timeshift/stu48_8th_empathy_/k86763
struct ShowroomTimeshiftInspector;

#[async_trait]
impl Inspect for ShowroomTimeshiftInspector {
    fn name(&self) -> Cow<'static, str> {
        "showroom-timeshift".into()
    }

    async fn inspect(
        &self,
        _url: &str,
        captures: &regex::Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let client = ShowRoomClient::new(args.get_string("sr-id")).await?;

        let room_url_key = captures.name("room_url_key").unwrap();
        let view_url_key = captures.name("view_url_key").unwrap();
        let timeshift_info = client
            .timeshift_info(room_url_key.as_str(), view_url_key.as_str())
            .await?;
        let timeshift_streaming_url = client
            .timeshift_streaming_url(
                timeshift_info.timeshift.room_id,
                timeshift_info.timeshift.live_id,
            )
            .await?;
        let stream = timeshift_streaming_url.best();
        Ok(InspectResult::Playlist(InspectPlaylist {
            title: Some(timeshift_info.timeshift.title),
            playlist_url: stream.url().to_string(),
            playlist_type: PlaylistType::HLS,
            ..Default::default()
        }))
    }
}
