use std::borrow::Cow;

pub use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use iori;
pub use regex::Regex;

pub trait ShioriPlugin {
    /// Name of the plugin
    fn name(&self) -> Cow<'static, str>;

    /// Version of the plugin
    fn version(&self) -> Cow<'static, str>;

    /// Short description of the plugin
    fn description(&self) -> Option<Cow<'static, str>>;

    /// Detailed description message of the plugin
    fn description_long(&self) -> Option<Cow<'static, str>> {
        None
    }

    /// Define custom command-line arguments for the plugin.
    fn arguments(&self, _command: &mut dyn InspectorCommand) {}

    /// Register the plugin to the registry
    fn register(&self, registry: &mut dyn InspectorRegistry) -> anyhow::Result<()>;
}

/// A host-provided interface that allows a plugin to register its functionality.
pub trait InspectorRegistry {
    /// Register a normal inspector to the registry.
    fn register_inspector(
        &mut self,
        regex: Regex,
        inspector: Box<dyn Inspect>,
        priority_hint: PriorityHint,
    );
}

/// PriorityHint indicates the priority of an inspector.
#[derive(Debug, Clone, Copy)]
pub enum PriorityHint {
    /// Normal priority (0).
    Normal,
    /// High priority (100).
    High,
    /// Low priority (-100).
    Low,
    /// Custom priority.
    Custom(i32),
}

impl From<PriorityHint> for i32 {
    fn from(hint: PriorityHint) -> Self {
        match hint {
            PriorityHint::Normal => 0,
            PriorityHint::High => 100,
            PriorityHint::Low => -100,
            PriorityHint::Custom(v) => v,
        }
    }
}

impl From<i32> for PriorityHint {
    fn from(value: i32) -> Self {
        match value {
            0 => PriorityHint::Normal,
            100 => PriorityHint::High,
            -100 => PriorityHint::Low,
            v => PriorityHint::Custom(v),
        }
    }
}

impl PartialEq for PriorityHint {
    fn eq(&self, other: &Self) -> bool {
        i32::from(*self) == i32::from(*other)
    }
}

impl Eq for PriorityHint {}

impl PartialOrd for PriorityHint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityHint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        i32::from(*self).cmp(&i32::from(*other))
    }
}

/// Defines the core logic for inspecting a URL to find media information.
///
/// This trait should be implemented lazily. This means the constructor (e.g., `new()`)
/// should not perform any heavy work like network requests. Any expensive initialization
/// should be deferred to the `inspect` method itself to avoid slowing down application startup.
#[async_trait]
pub trait Inspect: Send + Sync {
    fn name(&self) -> Cow<'static, str>;

    /// Inspect the URL and return the result.
    ///
    /// This is the primary method of the trait. It is called by the host when a URL matches
    /// the `Regex` this inspector was registered with.
    ///
    /// # Arguments
    ///
    /// * `url`: The full URL string that was matched.
    /// * `captures`: The captures from the `Regex` match. This is useful for extracting
    ///   dynamic parts of the URL, such as video IDs.
    /// * `args`: An object providing access to the parsed values of any custom command-line
    ///   arguments defined by the plugin.
    ///
    /// # Returns
    ///
    /// An `anyhow::Result` containing an `InspectResult`, which can be a playlist, a list of
    /// candidates for further inspection, a redirect, or none.
    async fn inspect(
        &self,
        url: &str,
        captures: &regex::Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult>;

    /// Inspects a previously returned candidate to get the final playlist.
    ///
    /// If a prior call to `inspect` returned `InspectResult::Candidates`, the user may be
    /// prompted to choose one. This method is then called with the selected `InspectCandidate`
    /// to perform the final step of the inspection.
    ///
    /// # Arguments
    ///
    /// * `candidate`: The `InspectCandidate` chosen by the user.
    async fn inspect_candidate(
        &self,
        _candidate: InspectCandidate,
    ) -> anyhow::Result<InspectResult> {
        Ok(InspectResult::None)
    }
}

pub trait InspectorCommand {
    fn add_argument(
        &mut self,
        long: &'static str,
        value_name: Option<&'static str>,
        help: &'static str,
    );

    fn add_boolean_argument(&mut self, long: &'static str, help: &'static str);
}

pub trait InspectorArguments: Send + Sync {
    fn get_string(&self, argument: &'static str) -> Option<String>;
    fn get_boolean(&self, argument: &'static str) -> bool;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InspectResult {
    /// Found multiple available sources to choose
    Candidates(Vec<InspectCandidate>),
    /// Inspect data is found
    Playlist(InspectPlaylist),
    /// Multiple playlists are found and need to be downloaded
    Playlists(Vec<InspectPlaylist>),
    /// Redirect happens
    Redirect(String),
    /// Inspect data is not found
    None,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InspectCandidate {
    pub title: String,

    pub playlist_type: Option<PlaylistType>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct InspectPlaylist {
    /// Metadata of the resource
    pub title: Option<String>,

    /// URL of the playlist
    pub playlist_url: String,

    /// Type of the playlist
    pub playlist_type: PlaylistType,

    /// Key used to decrypt the media
    pub key: Option<String>,

    /// Headers to use when requesting
    pub headers: Vec<String>,

    /// Cookies to use when requesting
    pub cookies: Vec<String>,

    /// Initial data of the playlist
    ///
    /// Inspector may have already sent a request to the server, in which case we can reuse the data
    pub initial_playlist_data: Option<String>,

    /// Hints how many streams does this playlist contains.
    pub streams_hint: Option<u32>,
}

pub trait InspectorApp {
    fn choose_candidates(&self, candidates: Vec<InspectCandidate>) -> Vec<InspectCandidate>;
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub enum PlaylistType {
    /// HTTP Live Streaming
    HLS,
    /// Dynamic Adaptive Streaming over HTTP
    DASH,
    /// Raw data
    Raw(String),
    #[default]
    /// Unknown playlist type
    Unknown,
}
