pub mod inspectors;

pub use shiori_plugin::*;
use std::{borrow::Cow, fmt::Write, sync::Arc, time::Duration};
use tokio::time::sleep;

use crate::commands::STYLES;

#[derive(Default)]
pub struct Inspectors {
    /// Whether to wait on found
    wait: Option<u64>,

    front: Vec<Box<dyn InspectorBuilder + Send + Sync + 'static>>,
    tail: Vec<Box<dyn InspectorBuilder + Send + Sync + 'static>>,
}

impl Inspectors {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add inspector to front queue
    pub fn add(&mut self, builder: impl InspectorBuilder + Send + Sync + 'static) -> &mut Self {
        self.front.push(Box::new(builder));
        self
    }

    pub fn push(&mut self, builder: impl InspectorBuilder + Send + Sync + 'static) -> &mut Self {
        self.tail.push(Box::new(builder));
        self
    }

    pub fn wait(mut self, value: bool) -> Self {
        self.wait = if value { Some(5) } else { None };
        self
    }

    pub fn wait_for(mut self, value: u64) -> Self {
        self.wait = Some(value);
        self
    }

    pub fn help(self) -> String {
        let mut is_first = true;

        let mut result = format!("{style}Inspectors:{style:#}\n", style = STYLES.get_header());

        let inspectors = self.front.iter().chain(self.tail.iter());
        for inspector in inspectors {
            if !is_first {
                result.push('\n');
            }
            is_first = false;

            writeln!(
                result,
                "  {style}{}:{style:#}\n",
                inspector.name(),
                style = STYLES.get_literal()
            )
            .unwarp();
            for line in inspector.help() {
                result.push_str(&" ".repeat(10));
                result.push_str(&line);
                result.push('\n');
            }
        }
        result
    }

    pub fn add_arguments(&self, command: &mut impl InspectorCommand) {
        for inspector in self.front.iter().chain(self.tail.iter()) {
            inspector.arguments(command);
        }
    }

    pub async fn inspect(
        self,
        url: &str,
        args: &dyn InspectorArguments,
        choose_candidate: fn(Vec<InspectCandidate>) -> InspectCandidate,
    ) -> anyhow::Result<(InspectorIdentifier, Vec<InspectPlaylist>)> {
        let inspectors = self
            .front
            .iter()
            .chain(self.tail.iter())
            .map(|b| b.build(args).map(|i| (b, i)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut registry = InspectRegistry::new();

        for (builder, inspector) in inspectors.iter() {
            inspector
                .register(Arc::new(builder.name()), &mut registry)
                .await?;
        }

        let mut url = Cow::Borrowed(url);

        loop {
            let result = registry.try_match(url.parse()?);
            let (inspector_id, result) = match result {
                MatchUriResult::Scheme((inspector, f), url) => (inspector, f(url).await.ok()),
                MatchUriResult::Http((inspector, f), uri_params, url) => {
                    (inspector, f(url, uri_params).await.ok())
                }
                MatchUriResult::NoMatch(_) => {
                    anyhow::bail!("No inspector matched")
                }
            };
            let inspector = inspectors
                .iter()
                .find(|i| i.0.name().as_str() == inspector_id.as_ref())
                .map(|e| &e.1)
                .unwrap();

            let result = handle_inspect_result(inspector.as_ref(), result, choose_candidate).await;
            match result {
                InspectBranch::Redirect(redirect_url) => {
                    url = Cow::Owned(redirect_url);
                }
                InspectBranch::Found(data) => return Ok((inspector_id.clone(), data)),
                InspectBranch::NotFound => {
                    if let Some(wait_time) = self.wait {
                        sleep(Duration::from_secs(wait_time)).await;
                    } else {
                        anyhow::bail!("Not found")
                    }
                }
            }
        }
    }
}

enum InspectBranch {
    Redirect(String),
    Found(Vec<InspectPlaylist>),
    NotFound,
}

#[async_recursion::async_recursion]
async fn handle_inspect_result(
    inspector: &dyn Inspect,
    result: Option<InspectResult>,
    choose_candidate: fn(Vec<InspectCandidate>) -> InspectCandidate,
) -> InspectBranch {
    match result {
        Some(InspectResult::Candidates(candidates)) => {
            let candidate = choose_candidate(candidates);
            let result = inspector
                .inspect_candidate(candidate)
                .await
                .inspect_err(|e| log::error!("Failed to inspect candidate: {:?}", e))
                .ok();
            handle_inspect_result(inspector, result, choose_candidate).await
        }
        Some(InspectResult::Playlist(data)) => InspectBranch::Found(vec![data]),
        Some(InspectResult::Playlists(data)) => InspectBranch::Found(data),
        Some(InspectResult::Redirect(redirect_url)) => InspectBranch::Redirect(redirect_url),
        Some(InspectResult::None) | None => InspectBranch::NotFound,
    }
}
