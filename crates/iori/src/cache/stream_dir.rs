use std::path::{Path, PathBuf};

use sanitize_filename_reader_friendly::sanitize;
use tokio::fs::File;

use crate::{
    IoriError, IoriResult, StreamType,
    cache::{CacheSource, CacheSourceReader, CacheSourceWriter},
    util::path::{IoriPathExt, SystemDotFiles},
};

const IGNORED_FILES: [&str; 2] = [
    ".directory", // KDE Dolphin
    ".DS_Store",  // macOS
];

/// [StreamDirCacheSource] is a cache source that stores the downloaded but not merged segments in a stream directory.
///
/// The cache directory is organized as follows:
///
/// ```text
/// cache_dir/
/// └── streams/
///     └── video_0/
///         └── 000000_filename.ts
///         └── 000001_filename.ts
///         └── ...
///         └── 999999_filename.ts
///     └── audio_1/
///         └── 000000_filename.ts
///         └── 000001_filename.ts
///         └── ...
///         └── 999999_filename.ts
/// ```
#[derive(Debug)]
pub struct StreamDirCacheSource {
    cache_dir: PathBuf,
}

impl StreamDirCacheSource {
    fn is_existing_stream_cache_dir(path: &Path) -> IoriResult<bool> {
        let mut streams_dir_exists = false;

        // Check if there are any files other than the `streams` directory
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if IGNORED_FILES.contains(&&*name) {
                continue;
            }
            if name == "streams" {
                streams_dir_exists = true;
                continue;
            }

            // For other files, return false
            return Ok(false);
        }

        if !streams_dir_exists {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn new(cache_dir: PathBuf) -> IoriResult<Self> {
        if cache_dir.exists() && !Self::is_existing_stream_cache_dir(&cache_dir)? {
            return Err(IoriError::CacheDirExists(cache_dir));
        }

        Ok(Self { cache_dir })
    }

    fn stream_dir(&self, stream_id: u64, stream_type: StreamType) -> PathBuf {
        let stream_type = match stream_type {
            StreamType::Video => "video",
            StreamType::Audio => "audio",
            StreamType::Subtitle => "subtitle",
            StreamType::Unknown => "unknown",
        };
        self.cache_dir
            .join("streams")
            .join(format!("{stream_id:02}_{stream_type}"))
    }

    fn segment_path<P>(&self, stream_dir: P, segment: &crate::SegmentInfo) -> PathBuf
    where
        P: AsRef<Path>,
    {
        let filename = sanitize(&segment.file_name);
        let sequence = segment.sequence;
        let filename = format!("{sequence:06}_{filename}");

        stream_dir.as_ref().join(filename)
    }
}

impl CacheSource for StreamDirCacheSource {
    async fn open_writer(
        &self,
        segment: &crate::SegmentInfo,
    ) -> IoriResult<Option<CacheSourceWriter>> {
        let stream_dir = self.stream_dir(segment.stream_id, segment.stream_type);
        if !stream_dir.exists() {
            tokio::fs::create_dir_all(&stream_dir).await?;
        }

        let path = self.segment_path(stream_dir, segment);
        if path.non_empty_file_exists() {
            tracing::warn!(
                stream_id = segment.stream_id,
                sequence = segment.sequence,
                "File {} already exists, ignoring.",
                path.display()
            );
            return Ok(None);
        }

        let file = File::create(path).await?;
        Ok(Some(Box::new(file)))
    }

    async fn open_reader(&self, segment: &crate::SegmentInfo) -> IoriResult<CacheSourceReader> {
        let stream_dir = self.stream_dir(segment.stream_id, segment.stream_type);
        let path = self.segment_path(stream_dir, segment);
        let file = File::open(path).await?;
        Ok(Box::new(file))
    }

    async fn segment_path(&self, segment: &crate::SegmentInfo) -> Option<PathBuf> {
        let stream_dir = self.stream_dir(segment.stream_id, segment.stream_type);
        Some(self.segment_path(stream_dir, segment))
    }

    async fn invalidate(&self, segment: &crate::SegmentInfo) -> IoriResult<()> {
        let stream_dir = self.stream_dir(segment.stream_id, segment.stream_type);
        let path = self.segment_path(stream_dir, segment);
        if path.exists() {
            tokio::fs::remove_file(path).await?;
        }
        Ok(())
    }

    async fn clear(&self) -> IoriResult<()> {
        // Remove streams first
        let streams_dir = self.cache_dir.join("streams");
        if streams_dir.exists() {
            tokio::fs::remove_dir_all(&streams_dir).await?;
        }

        // dot_clean for macOS
        SystemDotFiles::new(self.cache_dir.clone())
            .clean(true)
            .await?;

        // Then try to remove the cache directory but do not call it recursively
        if let Err(e) = tokio::fs::remove_dir(&self.cache_dir).await {
            tracing::warn!("Failed to remove cache directory: {e}");
        }
        Ok(())
    }

    fn location_hint(&self) -> Option<String> {
        Some(self.cache_dir.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SegmentInfo;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Global counter to ensure unique test directory names
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    // Generate a unique temporary directory name using process ID, timestamp, and atomic counter
    fn temp_test_dir() -> PathBuf {
        use std::time::SystemTime;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("iori_test_{pid}_{timestamp}_{counter}"))
    }

    fn create_test_segment(
        stream_id: u64,
        stream_type: StreamType,
        sequence: u64,
        file_name: &str,
    ) -> SegmentInfo {
        SegmentInfo {
            stream_id,
            stream_type,
            sequence,
            file_name: file_name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_stream_dir_cache_segment_path() {
        let cache_dir = PathBuf::from("/tmp/test_cache");
        let cache = StreamDirCacheSource {
            cache_dir: cache_dir.clone(),
        };

        let segment = create_test_segment(0, StreamType::Video, 5, "test.ts");
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        assert_eq!(stream_dir, cache_dir.join("streams").join("00_video"));

        let path = cache.segment_path(&stream_dir, &segment);
        assert_eq!(path, stream_dir.join("000005_test.ts"));

        // Test file name normalization with slashes
        let segment = create_test_segment(1, StreamType::Video, 123, "another/file.ts");
        let path = cache.segment_path(&stream_dir, &segment);
        assert_eq!(path, stream_dir.join("000123_another_file.ts"));
    }

    #[test]
    fn test_stream_dir_different_types() {
        let cache_dir = PathBuf::from("/tmp/test_cache");
        let cache = StreamDirCacheSource {
            cache_dir: cache_dir.clone(),
        };

        // Test video stream
        let segment = create_test_segment(0, StreamType::Video, 1, "video.ts");
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        assert_eq!(stream_dir, cache_dir.join("streams").join("00_video"));

        // Test audio stream
        let segment = create_test_segment(1, StreamType::Audio, 1, "audio.m4a");
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        assert_eq!(stream_dir, cache_dir.join("streams").join("01_audio"));

        // Test subtitle stream
        let segment = create_test_segment(2, StreamType::Subtitle, 1, "subtitle.vtt");
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        assert_eq!(stream_dir, cache_dir.join("streams").join("02_subtitle"));

        // Test unknown stream
        let segment = create_test_segment(3, StreamType::Unknown, 1, "unknown.dat");
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        assert_eq!(stream_dir, cache_dir.join("streams").join("03_unknown"));
    }

    #[tokio::test]
    async fn test_stream_dir_cache_new_with_existing_dir() {
        let temp_dir = temp_test_dir();
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let result = StreamDirCacheSource::new(temp_dir.clone());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IoriError::CacheDirExists(_)));

        // Cleanup
        tokio::fs::remove_dir_all(&temp_dir).await.unwrap();
    }

    #[tokio::test]
    async fn test_stream_dir_cache_write_read() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        let segment = create_test_segment(0, StreamType::Video, 42, "segment.ts");
        let test_data = b"test segment data";

        // Write data
        let mut writer = cache.open_writer(&segment).await?.unwrap();
        writer.write_all(test_data).await?;
        writer.shutdown().await?;
        drop(writer);

        // Verify stream directory was created
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        assert!(stream_dir.exists());

        // Read data back
        let mut reader = cache.open_reader(&segment).await?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        assert_eq!(data, test_data);

        // Cleanup
        tokio::fs::remove_dir_all(&temp_dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_duplicate_write() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        let segment = create_test_segment(0, StreamType::Video, 1, "test.ts");

        // First write
        let mut writer = cache.open_writer(&segment).await?.unwrap();
        writer.write_all(b"first").await?;
        writer.shutdown().await?;
        drop(writer);

        // Second write should return None (file already exists)
        let writer = cache.open_writer(&segment).await?;
        assert!(writer.is_none());

        // Cleanup
        tokio::fs::remove_dir_all(&temp_dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_multiple_streams() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        // Write video segment
        let video_segment = create_test_segment(0, StreamType::Video, 1, "video.ts");
        let mut writer = cache.open_writer(&video_segment).await?.unwrap();
        writer.write_all(b"video data").await?;
        writer.shutdown().await?;
        drop(writer);

        // Write audio segment
        let audio_segment = create_test_segment(1, StreamType::Audio, 1, "audio.m4a");
        let mut writer = cache.open_writer(&audio_segment).await?.unwrap();
        writer.write_all(b"audio data").await?;
        writer.shutdown().await?;
        drop(writer);

        // Verify both streams exist
        let video_dir = cache.stream_dir(video_segment.stream_id, video_segment.stream_type);
        let audio_dir = cache.stream_dir(audio_segment.stream_id, audio_segment.stream_type);
        assert!(video_dir.exists());
        assert!(audio_dir.exists());

        // Read video data
        let mut reader = cache.open_reader(&video_segment).await?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        assert_eq!(data, b"video data");

        // Read audio data
        let mut reader = cache.open_reader(&audio_segment).await?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        assert_eq!(data, b"audio data");

        // Cleanup
        tokio::fs::remove_dir_all(&temp_dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_segment_path_async() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        let segment = create_test_segment(0, StreamType::Video, 99, "test.ts");
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        let path = cache.segment_path(&stream_dir, &segment);

        let expected_path = temp_dir
            .join("streams")
            .join("00_video")
            .join("000099_test.ts");
        assert_eq!(path, expected_path);

        // Cleanup
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_invalidate() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        let segment = create_test_segment(0, StreamType::Video, 1, "test.ts");

        // Write data
        let mut writer = cache.open_writer(&segment).await?.unwrap();
        writer.write_all(b"test").await?;
        writer.shutdown().await?;
        drop(writer);

        // Verify file exists
        let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
        let path = cache.segment_path(&stream_dir, &segment);
        assert!(path.exists());

        // Invalidate
        cache.invalidate(&segment).await?;

        // Verify file is removed
        assert!(!path.exists());

        // Invalidating non-existent file should succeed
        cache.invalidate(&segment).await?;

        // Cleanup
        tokio::fs::remove_dir_all(&temp_dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_clear() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        // Write multiple segments
        let segment1 = create_test_segment(0, StreamType::Video, 1, "seg1.ts");
        let segment2 = create_test_segment(0, StreamType::Video, 2, "seg2.ts");
        let segment3 = create_test_segment(1, StreamType::Audio, 1, "seg3.m4a");

        for segment in [&segment1, &segment2, &segment3] {
            let mut writer = cache.open_writer(segment).await?.unwrap();
            writer.write_all(b"data").await?;
            writer.shutdown().await?;
            drop(writer);
        }

        // Verify streams directory exists
        let streams_dir = temp_dir.join("streams");
        assert!(streams_dir.exists());

        // Clear cache
        cache.clear().await?;

        // Verify streams directory is removed
        assert!(!streams_dir.exists());

        // Verify cache directory itself is also removed if it's empty
        // (It might not be removed if there are other files)

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_clear_with_os_files() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        // Create cache directory structure
        tokio::fs::create_dir_all(&temp_dir).await?;

        // Write a segment
        let segment = create_test_segment(0, StreamType::Video, 1, "test.ts");
        let mut writer = cache.open_writer(&segment).await?.unwrap();
        writer.write_all(b"data").await?;
        writer.shutdown().await?;
        drop(writer);

        // Create OS-specific files
        tokio::fs::write(temp_dir.join(".DS_Store"), b"macos").await?;
        tokio::fs::write(temp_dir.join(".directory"), b"kde").await?;

        // Clear cache
        cache.clear().await?;

        // Verify streams directory and OS files are removed
        assert!(!temp_dir.join("streams").exists());
        assert!(!temp_dir.join(".DS_Store").exists());
        assert!(!temp_dir.join(".directory").exists());

        Ok(())
    }

    #[test]
    fn test_stream_dir_cache_location_hint() {
        let cache_dir = PathBuf::from("/tmp/test_cache");
        let cache = StreamDirCacheSource {
            cache_dir: cache_dir.clone(),
        };

        let hint = cache.location_hint();
        assert!(hint.is_some());
        assert_eq!(hint.unwrap(), cache_dir.display().to_string());
    }

    #[tokio::test]
    async fn test_stream_dir_cache_filename_normalization() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        // Test various filename patterns that need normalization
        let test_cases = vec![
            ("simple.ts", "000001_simple.ts"),
            ("path/to/file.ts", "000001_path_to_file.ts"),
            (
                "nested/deep/path/file.ts",
                "000001_nested_deep_path_file.ts",
            ),
        ];

        for (input_name, expected_name) in test_cases {
            let segment = create_test_segment(0, StreamType::Video, 1, input_name);
            let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
            let path = cache.segment_path(&stream_dir, &segment);

            assert_eq!(path.file_name().unwrap().to_str().unwrap(), expected_name);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_dir_cache_sequence_padding() -> IoriResult<()> {
        let temp_dir = temp_test_dir();
        let cache = StreamDirCacheSource::new(temp_dir.clone())?;

        // Test sequence number padding
        let test_cases = vec![
            (0, "000000_test.ts"),
            (1, "000001_test.ts"),
            (99, "000099_test.ts"),
            (999, "000999_test.ts"),
            (9999, "009999_test.ts"),
            (99999, "099999_test.ts"),
            (999999, "999999_test.ts"),
        ];

        for (sequence, expected_name) in test_cases {
            let segment = create_test_segment(0, StreamType::Video, sequence, "test.ts");
            let stream_dir = cache.stream_dir(segment.stream_id, segment.stream_type);
            let path = cache.segment_path(&stream_dir, &segment);

            assert_eq!(path.file_name().unwrap().to_str().unwrap(), expected_name);
        }

        Ok(())
    }
}
