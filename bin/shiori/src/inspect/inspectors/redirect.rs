use crate::inspect::{Inspect, InspectResult};
use clap_handler::async_trait;
use reqwest::redirect::Policy;
use shiori_plugin::*;

pub struct ShortLinkInspector;

impl ShioriPlugin for ShortLinkInspector {
    fn name(&self) -> String {
        "redirect".to_string()
    }

    fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn description(&self) -> String {
        Some("Redirects shortlinks to the original URL.".to_string())
    }

    async fn register(&self, registry: impl Registry) -> Result<(), Box<dyn std::error::Error>> {
        registry.register_inspector(
            Regex::new(r#"^https://t.co/(?<id>.+)$"#),
            ShortLinkInspector,
            PriorityHint::Normal,
        );
    }
}

#[async_trait]
impl Inspect for ShortLinkInspector {
    async fn inspect(
        &self,
        url: &str,
        captures: &regex::Captures,
        args: &dyn InspectorArguments,
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
