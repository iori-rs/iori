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
            let path = namer.next_path();

            let mut out = File::create(path).await?;
            for segment in trimmed_part_segments {
                if !segment.success {
                    out = File::create(namer.next_path()).await?;
                    continue;
                }

                let mut reader = cache.open_reader(&segment.segment).await?;
                tokio::io::copy(&mut reader, &mut out).await?;
            }
        }

        part_start = part_end;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::memory::MemoryCacheSource;
    use tokio::io::AsyncWriteExt;

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

    async fn create_segment(
        cache: &MemoryCacheSource,
        sequence: u64,
        part_index: u64,
        data: &[u8],
    ) -> ConcatSegment {
        let segment = SegmentInfo {
            sequence,
            part_index,
            ..Default::default()
        };
        let mut writer = cache.open_writer(&segment).await.unwrap().unwrap();
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();
        drop(writer);
        ConcatSegment {
            segment,
            success: true,
        }
    }

    #[tokio::test]
    async fn test_concat_merge_basic() {
        let cache = MemoryCacheSource::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.ts");

        let mut segments = vec![
            create_segment(&cache, 0, 0, b"part0_seq0").await,
            create_segment(&cache, 1, 0, b"part0_seq1").await,
        ];

        concat_merge(&mut segments, &cache, output_path.clone())
            .await
            .unwrap();

        // Give some time for the namer Drop to run if needed,
        // but here it's sync and should have run.
        let content = tokio::fs::read(&output_path).await.unwrap();
        assert_eq!(content, b"part0_seq0part0_seq1");
    }

    #[tokio::test]
    async fn test_concat_merge_discontinuity() {
        let cache = MemoryCacheSource::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.ts");

        let mut segments = vec![
            create_segment(&cache, 0, 0, b"part0_seq0").await,
            create_segment(&cache, 1, 0, b"part0_seq1").await,
            create_segment(&cache, 2, 1, b"part1_seq2").await,
            create_segment(&cache, 3, 1, b"part1_seq3").await,
        ];

        concat_merge(&mut segments, &cache, output_path.clone())
            .await
            .unwrap();

        // Check first part
        let output_path1 = temp_dir.path().join("output.1.ts");
        let content1 = tokio::fs::read(&output_path1).await.unwrap();
        assert_eq!(content1, b"part0_seq0part0_seq1");

        // Check second part
        let output_path2 = temp_dir.path().join("output.2.ts");
        let content2 = tokio::fs::read(&output_path2).await.unwrap();
        assert_eq!(content2, b"part1_seq2part1_seq3");
    }

    #[tokio::test]
    async fn test_concat_merge_failure() {
        let cache = MemoryCacheSource::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.ts");

        let mut segments = vec![
            create_segment(&cache, 0, 0, b"part0_seq0").await,
            ConcatSegment {
                segment: SegmentInfo {
                    sequence: 1,
                    part_index: 0,
                    ..Default::default()
                },
                success: false,
            },
            create_segment(&cache, 2, 0, b"part0_seq2").await,
        ];

        concat_merge(&mut segments, &cache, output_path.clone())
            .await
            .unwrap();

        // First part before failure
        let output_path1 = temp_dir.path().join("output.1.ts");
        let content1 = tokio::fs::read(&output_path1).await.unwrap();
        assert_eq!(content1, b"part0_seq0");

        // Second part after failure
        let output_path2 = temp_dir.path().join("output.2.ts");
        let content2 = tokio::fs::read(&output_path2).await.unwrap();
        assert_eq!(content2, b"part0_seq2");
    }

    #[tokio::test]
    async fn test_concat_merge_sorting() {
        let cache = MemoryCacheSource::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.ts");

        // Out of order segments
        let mut segments = vec![
            create_segment(&cache, 1, 0, b"part0_seq1").await,
            create_segment(&cache, 0, 0, b"part0_seq0").await,
            create_segment(&cache, 3, 1, b"part1_seq3").await,
            create_segment(&cache, 2, 1, b"part1_seq2").await,
        ];

        concat_merge(&mut segments, &cache, output_path.clone())
            .await
            .unwrap();

        let output_path1 = temp_dir.path().join("output.1.ts");
        let content1 = tokio::fs::read(&output_path1).await.unwrap();
        assert_eq!(content1, b"part0_seq0part0_seq1");

        let output_path2 = temp_dir.path().join("output.2.ts");
        let content2 = tokio::fs::read(&output_path2).await.unwrap();
        assert_eq!(content2, b"part1_seq2part1_seq3");
    }
}
