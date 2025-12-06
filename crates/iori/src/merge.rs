mod auto;
mod concat;
mod pipe;
#[cfg(feature = "proxy")]
mod proxy;
mod skip;

pub use auto::{AutoMerger, MkvmergeMerger};
pub use concat::ConcatAfterMerger;
pub use pipe::PipeMerger;
#[cfg(feature = "proxy")]
pub use proxy::ProxyMerger;
pub use skip::SkipMerger;
use tokio::io::AsyncWrite;

use crate::{SegmentFormat, SegmentInfo, cache::CacheSource, error::IoriResult};
use std::path::{Path, PathBuf};

pub trait Merger {
    /// Result of the merge.
    type Result: Send + Sync + 'static;

    /// Add a segment to the merger.
    ///
    /// This method might not be called in order of segment sequence.
    /// Implementations should handle order of segments by calling
    /// [StreamingSegment::sequence].
    fn update(
        &mut self,
        segment: SegmentInfo,
        cache: impl CacheSource,
    ) -> impl Future<Output = IoriResult<()>> + Send;

    /// Tell the merger that a segment has failed to download.
    fn fail(
        &mut self,
        segment: SegmentInfo,
        cache: impl CacheSource,
    ) -> impl Future<Output = IoriResult<()>> + Send;

    fn finish(
        &mut self,
        cache: impl CacheSource,
    ) -> impl Future<Output = IoriResult<Self::Result>> + Send;
}

pub enum IoriMerger<C, M> {
    Pipe(PipeMerger),
    Skip(SkipMerger),
    Concat(ConcatAfterMerger),
    Auto(AutoMerger<C, M>),
    #[cfg(feature = "proxy")]
    Proxy(ProxyMerger),
}

impl<C, M> IoriMerger<C, M> {
    pub fn pipe(recycle: bool) -> Self {
        Self::Pipe(PipeMerger::stdout(recycle))
    }

    pub fn pipe_to_writer(
        writer: impl AsyncWrite + Unpin + Send + Sync + 'static,
        recycle: bool,
    ) -> Self {
        Self::Pipe(PipeMerger::writer(recycle, writer))
    }

    pub fn pipe_to_file(output_file: PathBuf, recycle: bool) -> Self {
        Self::Pipe(PipeMerger::file(recycle, output_file))
    }

    pub fn pipe_mux(output_file: PathBuf, recycle: bool, extra_commands: Option<String>) -> Self {
        Self::Pipe(PipeMerger::mux(recycle, output_file, extra_commands))
    }

    pub fn skip() -> Self {
        Self::Skip(SkipMerger)
    }

    pub fn concat(output_file: PathBuf, recycle: bool) -> Self {
        Self::Concat(ConcatAfterMerger::new(output_file, recycle))
    }

    #[cfg(feature = "proxy")]
    pub fn proxy(addr: std::net::SocketAddr) -> Self {
        Self::Proxy(ProxyMerger::new(addr))
    }
}

impl IoriMerger<MkvmergeMerger, MkvmergeMerger> {
    pub fn mkvmerge(output_file: PathBuf, recycle: bool) -> Self {
        Self::Auto(AutoMerger::mkvmerge(output_file, recycle))
    }
}

impl<C, M> IoriMerger<C, M> {
    pub fn auto(output_file: PathBuf, recycle: bool, concat_merger: C, merge_merger: M) -> Self {
        Self::Auto(AutoMerger::new(
            output_file,
            recycle,
            concat_merger,
            merge_merger,
        ))
    }
}

impl<C, M> Merger for IoriMerger<C, M>
where
    C: AutoMergerConcat + Send,
    M: AutoMergerMerge + Send,
{
    type Result = (); // TODO: merger might have different result types

    async fn update(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        match self {
            Self::Pipe(merger) => merger.update(segment, cache).await,
            Self::Skip(merger) => merger.update(segment, cache).await,
            Self::Concat(merger) => merger.update(segment, cache).await,
            Self::Auto(merger) => merger.update(segment, cache).await,
            #[cfg(feature = "proxy")]
            Self::Proxy(merger) => merger.update(segment, cache).await,
        }
    }

    async fn fail(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        match self {
            Self::Pipe(merger) => merger.fail(segment, cache).await,
            Self::Skip(merger) => merger.fail(segment, cache).await,
            Self::Concat(merger) => merger.fail(segment, cache).await,
            Self::Auto(merger) => merger.fail(segment, cache).await,
            #[cfg(feature = "proxy")]
            Self::Proxy(merger) => merger.fail(segment, cache).await,
        }
    }

    async fn finish(&mut self, cache: impl CacheSource) -> IoriResult<Self::Result> {
        match self {
            Self::Pipe(merger) => merger.finish(cache).await,
            Self::Skip(merger) => merger.finish(cache).await,
            Self::Concat(merger) => merger.finish(cache).await,
            Self::Auto(merger) => merger.finish(cache).await,
            #[cfg(feature = "proxy")]
            Self::Proxy(merger) => merger.finish(cache).await,
        }
    }
}

pub trait AutoMergerConcat {
    fn format(&self) -> SegmentFormat;

    fn concat<O>(
        &mut self,
        segments: &[&SegmentInfo],
        cache: &impl CacheSource,
        output_path: O,
    ) -> impl Future<Output = IoriResult<()>> + Send
    where
        O: AsRef<Path> + Send;
}

pub trait AutoMergerMerge {
    fn format(&self) -> SegmentFormat;

    fn merge<O>(
        &mut self,
        tracks: Vec<PathBuf>,
        output: O,
    ) -> impl Future<Output = IoriResult<()>> + Send
    where
        O: AsRef<Path> + Send;
}

impl AutoMergerConcat for () {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::Mpeg2TS
    }

    async fn concat<O>(&mut self, _: &[&SegmentInfo], _: &impl CacheSource, _: O) -> IoriResult<()>
    where
        O: AsRef<Path> + Send,
    {
        Ok(())
    }
}

impl AutoMergerMerge for () {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::Mpeg2TS
    }

    async fn merge<O>(&mut self, _: Vec<PathBuf>, _: O) -> IoriResult<()>
    where
        O: AsRef<Path> + Send,
    {
        Ok(())
    }
}
