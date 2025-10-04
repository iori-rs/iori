use crate::inspect::{Inspect, InspectResult};
use anyhow::Context;
use clap_handler::async_trait;
use reqwest::redirect::Policy;
use shiori_plugin::*;

pub struct ShortLinkPlugin;

impl ShioriPlugin for ShortLinkPlugin {
    fn name(&self) -> String {
        "redirect".to_string()
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn description(&self) -> Option<String> {
        Some("Redirects shortlinks to the original URL.".to_string())
    }

    fn register(&self, registry: &mut dyn InspectorRegistry) -> anyhow::Result<()> {
        registry.register_inspector(
            Regex::new(r#"^https://t.co/(?<id>.+)$"#).with_context(|| "Invalid t.co regex")?,
            Box::new(ShortLinkPlugin),
            PriorityHint::Normal,
        );

        Ok(())
    }
}

#[async_trait]
impl Inspect for ShortLinkPlugin {
    async fn inspect(
        &self,
        url: &str,
        _captures: &regex::Captures,
        _args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(Policy::none())
            .build()?;
        let response = client.head(url).send().await?;
        let location = response
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok());

        if let Some(location) = location {
            Ok(InspectResult::Redirect(location.to_string()))
        } else {
            Ok(InspectResult::None)
        }
    }
}
