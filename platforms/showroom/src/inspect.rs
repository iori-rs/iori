use shiori_plugin::*;

use crate::ShowRoomClient;

pub struct ShowroomPlugin;

impl ShioriPlugin for ShowroomPlugin {
    fn name(&self) -> String {
        "showroom".to_string()
    }

    fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn description(&self) -> Option<String> {
        Some("Extracts Showroom playlists from the given URL.".to_string())
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
            Regex::new(r"https://www.showroom-live.com/r/.*").unwrap(),
            Box::new(ShowroomInspector),
            PriorityHint::Normal,
        );
        registry.register_inspector(
            Regex::new(r"https://www.showroom-live.com/timeshift/.*").unwrap(),
            Box::new(ShowroomInspector),
            PriorityHint::Normal,
        );

        Ok(())
    }
}

struct ShowroomInspector;

#[async_trait]
impl Inspect for ShowroomInspector {
    async fn inspect(
        &self,
        url: &str,
        _captures: &regex::Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let client = ShowRoomClient::new(args.get_string("sr-id")).await?;

        if url.contains("/r/") {
            let room_name = url.split("/r/").last().unwrap();
            let room_id = match room_name.parse::<u64>() {
                Ok(room_id) => room_id,
                Err(_) => client.room_info(room_name).await?.id,
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
        } else if url.contains("/timeshift/") {
            let parts: Vec<&str> = url.split("/").collect();
            let room_url_key = parts[parts.len() - 2];
            let view_url_key = parts[parts.len() - 1];
            let timeshift_info = client.timeshift_info(room_url_key, view_url_key).await?;
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
        } else {
            Ok(InspectResult::None)
        }
    }
}
