use super::Merger;
use crate::{
    SegmentInfo,
    cache::CacheSource,
    error::IoriResult,
    util::path::{DuplicateOutputFileNamer, IoriPathExt},
};
use std::path::PathBuf;
use tokio::fs::File;

/// Concat all segments into a single file after all segments are downloaded.
pub struct ConcatAfterMerger {
    segments: Vec<ConcatSegment>,

    /// Final output file path.
    output_file: PathBuf,
    /// Whether to recycle downloaded segments after merging.
    recycle: bool,
}

impl ConcatAfterMerger {
    pub fn new(output_file: PathBuf, recycle: bool) -> Self {
        Self {
            segments: Vec::new(),
            output_file,
            recycle,
        }
    }
}

impl Merger for ConcatAfterMerger {
    type Result = ();

    async fn update(&mut self, segment: SegmentInfo, _cache: impl CacheSource) -> IoriResult<()> {
        self.segments.push(ConcatSegment {
            segment,
            success: true,
        });
        Ok(())
    }

    async fn fail(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        cache.invalidate(&segment).await?;
        self.segments.push(ConcatSegment {
            segment,
            success: false,
        });
        Ok(())
    }

    async fn finish(&mut self, cache: impl CacheSource) -> IoriResult<Self::Result> {
        tracing::info!("Merging chunks...");
        concat_merge(
            &mut self.segments,
            &cache,
            self.output_file.clone().sanitize().deduplicate()?,
        )
        .await?;

        if self.recycle {
            tracing::info!("End of merging.");
            tracing::info!("Starting cleaning temporary files.");
            cache.clear().await?;
        }

        tracing::info!(
            "All finished. Please checkout your files at {}",
            self.output_file.display()
        );
        Ok(())
    }
}

fn trim_end<T>(input: &[T], should_skip: fn(&T) -> bool) -> &[T] {
    let mut end = input.len();
    while end > 0 && should_skip(&input[end - 1]) {
        end -= 1;
    }
    &input[..end]
}

pub(crate) struct ConcatSegment {
    pub segment: SegmentInfo,
    pub success: bool,
}

async fn concat_merge(
    segments: &mut [ConcatSegment],
    cache: &impl CacheSource,
    output_path: PathBuf,
) -> IoriResult<()> {
    segments.sort_by(|a, b| {
        a.segment
            .part_index
            .cmp(&b.segment.part_index)
            .then(a.segment.sequence.cmp(&b.segment.sequence))
    });

    let mut namer = DuplicateOutputFileNamer::new(output_path.clone());
    let mut current_part_index: Option<u64> = None;
    let mut output: Option<File> = None;

    // We don't use trim_end here because we want to handle parts individually.
    // However, we should still skip trailing failed segments in each part.

    let mut part_start = 0;
    while part_start < segments.len() {
        let part_index = segments[part_start].segment.part_index;
        let mut part_end = part_start + 1;
        while part_end < segments.len() && segments[part_end].segment.part_index == part_index {
            part_end += 1;
        }

        let part_segments = &mut segments[part_start..part_end];
        let trimmed_part_segments = trim_end(part_segments, |s| !s.success);

        if !trimmed_part_segments.is_empty() {
            let path = if current_part_index.is_none() {
                output_path.clone()
            } else {
                namer.next_path()
            };

            let mut out = File::create(path).await?;
            for segment in trimmed_part_segments {
                if !segment.success {
                    out = File::create(namer.next_path()).await?;
                }

                let mut reader = cache.open_reader(&segment.segment).await?;
                tokio::io::copy(&mut reader, &mut out).await?;
            }
            current_part_index = Some(part_index);
        }

        part_start = part_end;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_trim_end() {
        let input = [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        let output = super::trim_end(&input, |&x| x == 0);
        assert_eq!(output, [1, 2, 3]);

        let input = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
        let output = super::trim_end(&input, |&x| x == 0);
        assert_eq!(output, input);

        let input = [1, 2, 3, 0, 0, 3, 0, 0, 0];
        let output = super::trim_end(&input, |&x| x == 0);
        assert_eq!(output, [1, 2, 3, 0, 0, 3]);
    }
}
