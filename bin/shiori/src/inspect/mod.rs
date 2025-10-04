pub mod inspectors;

pub use shiori_plugin::*;
use std::{borrow::Cow, time::Duration};
use tokio::time::sleep;

use crate::commands::STYLES;

#[derive(Default)]
pub struct PluginManager {
    /// Whether to wait on found
    wait: Option<u64>,

    plugins: Vec<Box<dyn ShioriPlugin + Send + Sync + 'static>>,
    inspectors: Vec<InspectorItem>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add inspector to front queue
    pub fn add(&mut self, plugin: impl ShioriPlugin + Send + Sync + 'static) -> &mut Self {
        // TODO: match the registered inspector with the plugin name
        plugin.register(self).unwrap();
        self.plugins.push(Box::new(plugin));

        self
    }

    fn sort(&mut self) {
        self.inspectors.sort_by_key(|item| item.priority);
        self.inspectors.reverse();
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

        let mut result = format!("{style}Plugins:{style:#}\n", style = STYLES.get_header());

        for plugin in self.plugins.iter() {
            if !is_first {
                result.push('\n');
            }
            is_first = false;

            result.push_str(&format!(
                "  {style}{}:{style:#}\n",
                plugin.name(),
                style = STYLES.get_literal()
            ));
            for line in plugin
                .description()
                .unwrap_or_else(|| "<No description>".to_string())
                .split('\n')
            {
                result.push_str(&" ".repeat(10));
                result.push_str(line);
                result.push('\n');
            }
            if let Some(long) = plugin.description_long() {
                for line in long.split('\n') {
                    result.push_str(&" ".repeat(10));
                    result.push_str(line);
                    result.push('\n');
                }
            }
        }
        result
    }

    pub fn add_arguments(&self, command: &mut impl InspectorCommand) {
        for plugin in self.plugins.iter() {
            plugin.arguments(command);
        }
    }

    pub async fn inspect(
        self,
        url: &str,
        args: &dyn InspectorArguments,
        choose_candidate: fn(Vec<InspectCandidate>) -> InspectCandidate,
    ) -> anyhow::Result<(String, Vec<InspectPlaylist>)> {
        let mut url = Cow::Borrowed(url);

        // As `InspectBranch::Redirect` exists, we need a loop
        let result = 'outer: loop {
            for item in self.inspectors.iter() {
                // If a regex matches, we try to inspect it
                if let Some(captures) = item.regex.captures(&url) {
                    let inspect_result = item
                        .inspector
                        .inspect(&url, &captures, args)
                        .await
                        .inspect_err(|e| log::error!("Failed to inspect {url}: {:?}", e))
                        .ok();
                    let inspect_branch = handle_inspect_result(
                        item.inspector.as_ref(),
                        inspect_result,
                        choose_candidate,
                    )
                    .await;
                    match inspect_branch {
                        InspectBranch::Redirect(redirect_url) => {
                            url = Cow::Owned(redirect_url);
                            continue 'outer;
                        }
                        InspectBranch::Found(data) => break 'outer ("todo".to_string(), data),
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

            anyhow::bail!("No inspector matched")
        };

        Ok(result)
    }
}

impl InspectorRegistry for PluginManager {
    fn register_inspector(
        &mut self,
        regex: Regex,
        inspector: Box<dyn Inspect>,
        priority_hint: PriorityHint,
    ) {
        self.inspectors.push(InspectorItem {
            regex,
            inspector,
            priority: priority_hint,
        });
        self.sort();
    }
}

struct InspectorItem {
    regex: Regex,
    inspector: Box<dyn Inspect + Send + Sync + 'static>,
    priority: PriorityHint,
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
