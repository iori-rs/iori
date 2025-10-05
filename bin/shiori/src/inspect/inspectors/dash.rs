use std::borrow::Cow;

use anyhow::Context;

use shiori_plugin::*;

/// A plugin that provides a built-in inspector for MPEG-DASH manifests.
pub struct DashPlugin;

impl ShioriPlugin for DashPlugin {
    fn name(&self) -> Cow<'static, str> {
        "dash".into()
    }

    fn version(&self) -> Cow<'static, str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn description(&self) -> Option<Cow<'static, str>> {
        Some("A built-in inspector for MPEG-DASH manifests (.mpd)".into())
    }

    fn description_long(&self) -> Option<Cow<'static, str>> {
        Some("Inspects any URL ending in .mpd as a MPEG-DASH manifest.".into())
    }

    fn register(&self, registry: &mut dyn InspectorRegistry) -> anyhow::Result<()> {
        registry.register_inspector(
            // This regex matches any URL that ends with .mpd, ignoring query parameters or fragments.
            Regex::new(r"\.mpd($|\?|#)").with_context(|| "Invalid mpd regex")?,
            Box::new(DashInspector),
            // Set low priority to allow other more specific inspectors to take precedence.
            PriorityHint::Low,
        );
        Ok(())
    }
}

/// The inspector implementation for MPEG-DASH.
struct DashInspector;

#[async_trait]
impl Inspect for DashInspector {
    fn name(&self) -> Cow<'static, str> {
        "dash".into()
    }

    /// The core inspection logic for DASH manifests.
    ///
    /// This inspector is very simple: it assumes any URL ending in `.mpd` is a valid
    /// DASH playlist and immediately returns it.
    async fn inspect(
        &self,
        url: &str,
        _captures: &regex::Captures,
        _args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        Ok(InspectResult::Playlist(InspectPlaylist {
            playlist_url: url.to_string(),
            playlist_type: PlaylistType::DASH,
            ..Default::default()
        }))
    }
}
