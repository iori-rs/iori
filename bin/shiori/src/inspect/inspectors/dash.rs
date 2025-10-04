use anyhow::{Context, Ok};
use async_trait::async_trait;
use iori::PlaylistType;
use regex::Regex;

use shiori_plugin::*;

/// A plugin that provides a built-in inspector for MPEG-DASH manifests.
pub struct DashPlugin;

#[async_trait]
impl ShioriPlugin for DashPlugin {
    fn name(&self) -> String {
        "dash"
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> String {
        "A built-in inspector for MPEG-DASH manifests (.mpd)".to_string()
    }

    fn description_long(&self) -> String {
        Some("Inspects any URL ending in .mpd as a MPEG-DASH manifest.".to_string())
    }

    async fn register(
        &self,
        mut registry: impl Registry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        registry.register_inspector(
            // This regex matches any URL that ends with .mpd, ignoring query parameters or fragments.
            Regex::new(r"\.mpd($|\?|#)").with_context("Invalid mpd regex")?,
            Box::new(DashInspector),
            // Set low priority to allow other more specific inspectors to take precedence.
            PriorityHint::Low,
        );
        Ok(())
    }
}

/// The inspector implementation for MPEG-DASH.
pub struct DashInspector;

#[async_trait]
impl Inspect for DashInspector {
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
