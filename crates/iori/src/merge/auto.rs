use super::{AutoMergerConcat, AutoMergerMerge, Merger, concat::ConcatSegment};
use crate::{
    SegmentFormat, SegmentInfo, StreamType, cache::CacheSource, error::IoriResult,
    util::path::IoriPathExt,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tokio::{fs::File, io::BufWriter};

mod mkvmerge;
pub use mkvmerge::MkvmergeMerger;

/// AutoMerger is a merger that automatically chooses the best strategy to merge segments.
///
/// For MPEG-TS:
/// - It will use concat to merge segments.
/// - If there is only one track, the behavior is the same as [ConcatAfterMerger].
///
/// For other formats:
/// - It will use mkvmerge to merge segments.
///
/// If there are multiple tracks to merge, it will use mkvmerge to merge them.
/// If there are any missing segments, the merge will be skipped.
pub struct AutoMerger<C, M> {
    segments: HashMap<u64, Vec<ConcatSegment>>,

    /// Whether to recycle downloaded segments after merging.
    recycle: bool,

    has_failed: bool,

    /// Final output file path. It may not have an extension.
    output_file: PathBuf,
    /// A list of file extensions which should skip adding an auto extension.
    allowed_extensions: Vec<&'static str>,

    concat_merger: C,
    merge_merger: M,
}

impl<C, M> AutoMerger<C, M> {
    pub fn new(output_file: PathBuf, recycle: bool, concat_merger: C, merge_merger: M) -> Self {
        Self {
            segments: HashMap::new(),
            recycle,
            has_failed: false,

            output_file,
            allowed_extensions: vec!["mkv", "mp4", "ts"],
            concat_merger,
            merge_merger,
        }
    }
}

impl AutoMerger<MkvmergeMerger, MkvmergeMerger> {
    pub fn mkvmerge(output_file: PathBuf, recycle: bool) -> Self {
        Self::new(output_file, recycle, MkvmergeMerger, MkvmergeMerger)
    }
}

impl<C, M> Merger for AutoMerger<C, M>
where
    C: AutoMergerConcat + Send,
    M: AutoMergerMerge + Send,
{
    type Result = ();

    async fn update(&mut self, segment: SegmentInfo, _cache: impl CacheSource) -> IoriResult<()> {
        self.segments
            .entry(segment.stream_id)
            .or_default()
            .push(ConcatSegment {
                segment,
                success: true,
            });
        Ok(())
    }

    async fn fail(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        cache.invalidate(&segment).await?;
        self.segments
            .entry(segment.stream_id)
            .or_default()
            .push(ConcatSegment {
                segment,
                success: false,
            });
        self.has_failed = true;
        Ok(())
    }

    async fn finish(&mut self, cache: impl CacheSource) -> IoriResult<Self::Result> {
        tracing::info!("Merging chunks...");

        if self.has_failed {
            tracing::warn!("Some segments failed to download. Skipping merging.");
            if let Some(location) = cache.location_hint() {
                tracing::warn!("You can find the downloaded segments at {location}");
            }
            return Ok(());
        }

        let mut tracks = Vec::new();
        for (stream_id, segments) in self.segments.iter() {
            let mut segments: Vec<_> = segments.iter().map(|s| &s.segment).collect();

            let first_segment = segments[0];
            let mut output_path = self.output_file.to_owned();
            output_path.add_suffix(format!("{stream_id:02}"));
            output_path.set_extension(first_segment.format.as_ext());

            segments.sort_by(|a, b| a.sequence.cmp(&b.sequence));

            if output_path.exists() {
                let timestamp = chrono::Utc::now().timestamp();
                output_path.add_suffix(format!("{timestamp}"));
            }
            // TODO: if the file still exists, throw error

            let can_concat = segments.iter().all(|s| {
                matches!(
                    s.format,
                    SegmentFormat::Mpeg2TS | SegmentFormat::Aac | SegmentFormat::Raw(_)
                ) || matches!(s.stream_type, StreamType::Subtitle)
            });
            if can_concat {
                concat_merge(&segments, &cache, &output_path).await?;
            } else {
                output_path.set_extension(self.concat_merger.format().as_ext());
                self.concat_merger
                    .concat(&segments, &cache, &output_path)
                    .await?;
            }

            tracks.push(output_path);
        }

        tracing::info!("Merging streams...");

        let output_path = if tracks.len() == 1 {
            let track_format = tracks[0].extension().and_then(|e| e.to_str());
            let output = match track_format {
                Some(ext) => self
                    .output_file
                    .with_replaced_extension(ext, &self.allowed_extensions),
                None => self.output_file.clone(),
            }
            .sanitize()
            .deduplicate()?;
            tokio::fs::rename(&tracks[0], &output).await?;
            output
        } else {
            let output = self
                .output_file
                .with_replaced_extension(
                    self.merge_merger.format().as_ext(),
                    &self.allowed_extensions,
                )
                .sanitize()
                .deduplicate()?;
            self.merge_merger.merge(tracks, &output).await?;
            output
        };

        if self.recycle {
            tracing::info!("End of merging.");
            tracing::info!("Starting cleaning temporary files.");
            cache.clear().await?;
        }

        tracing::info!(
            "All finished. Please checkout your files at {}",
            output_path.display()
        );
        Ok(())
    }
}

#[allow(unused)]
async fn concat_merge<O>(
    segments: &[&SegmentInfo],
    cache: &impl CacheSource,
    output_path: O,
) -> IoriResult<()>
where
    O: AsRef<Path>,
{
    let output = File::create(output_path.as_ref()).await?;
    let mut output = BufWriter::new(output);
    for segment in segments {
        let mut reader = cache.open_reader(segment).await?;
        tokio::io::copy(&mut reader, &mut output).await?;
    }
    Ok(())
}
