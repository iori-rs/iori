use anyhow::Context;
use shiori_plugin::*;

/// A plugin that provides a built-in inspector for HLS playlists.
pub struct HlsPlugin;

impl ShioriPlugin for HlsPlugin {
    fn name(&self) -> String {
        "hls".to_string()
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn description(&self) -> Option<String> {
        Some("A built-in inspector for HLS playlists (.m3u8)".to_string())
    }

    fn description_long(&self) -> Option<String> {
        Some("Inspects any URL ending in .m3u8 as an HLS playlist.".to_string())
    }

    fn register(&self, registry: &mut dyn InspectorRegistry) -> anyhow::Result<()> {
        registry.register_inspector(
            // This regex matches any URL that ends with .m3u8, ignoring query parameters or fragments.
            Regex::new(r"\.m3u8($|\?|#)").with_context(|| "Invalid m3u8 regex")?,
            Box::new(HlsInspector),
            // Set low priority to allow other more specific inspectors to take precedence.
            PriorityHint::Low,
        );
        Ok(())
    }
}

/// The inspector implementation for HLS.
struct HlsInspector;

#[async_trait]
impl Inspect for HlsInspector {
    /// The core inspection logic for HLS playlists.
    ///
    /// This inspector is very simple: it assumes any URL ending in `.m3u8` is a valid
    /// HLS playlist and immediately returns it.
    async fn inspect(
        &self,
        url: &str,
        _captures: &regex::Captures,
        _args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        Ok(InspectResult::Playlist(InspectPlaylist {
            playlist_url: url.to_string(),
            playlist_type: PlaylistType::HLS,
            ..Default::default()
        }))
    }
}
