use crate::{
    IoriResult, SegmentFormat, SegmentInfo,
    cache::CacheSource,
    merge::{AutoMergerConcat, AutoMergerMerge},
};
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::process::Command;

pub struct MkvmergeMerger;

impl AutoMergerConcat for MkvmergeMerger {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::Other("mkv".to_string())
    }

    async fn concat<O>(
        &mut self,
        segments: &[&SegmentInfo],
        cache: &impl CacheSource,
        output_path: O,
    ) -> IoriResult<()>
    where
        O: AsRef<Path> + Send,
    {
        tracing::debug!("Concatenating with mkvmerge...");

        let mkvmerge = which::which("mkvmerge")?;

        let mut args = vec!["-q".to_string(), "[".to_string()];
        for segment in segments {
            let filename = cache.segment_path(segment).await.unwrap();
            args.push(filename.to_string_lossy().to_string());
        }
        args.push("]".to_string());
        args.push("-o".to_string());
        args.push(output_path.as_ref().to_string_lossy().to_string());

        let mut temp = tempfile::Builder::new().tempfile()?;
        let temp_path = temp.path().to_path_buf();
        temp.write_all(serde_json::to_string(&args)?.as_bytes())?;
        temp.flush()?;

        use tokio::io::{AsyncBufReadExt, BufReader};

        let mut child = Command::new(mkvmerge)
            .arg(format!("@{}", temp_path.to_string_lossy()))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // Capture and log stdout
        if let Some(stdout) = child.stdout.take() {
            let stdout_reader = BufReader::new(stdout);
            tokio::spawn(async move {
                let mut lines = stdout_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!("[mkvmerge] {}", line);
                }
            });
        }

        // Capture and log stderr
        if let Some(stderr) = child.stderr.take() {
            let stderr_reader = BufReader::new(stderr);
            tokio::spawn(async move {
                let mut lines = stderr_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::warn!("[mkvmerge] {}", line);
                }
            });
        }

        child.wait().await?;

        Ok(())
    }
}

impl AutoMergerMerge for MkvmergeMerger {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::Other("mkv".to_string())
    }

    async fn merge<O>(&mut self, tracks: Vec<PathBuf>, output: O) -> IoriResult<()>
    where
        O: AsRef<Path> + Send,
    {
        use tokio::io::{AsyncBufReadExt, BufReader};

        assert!(tracks.len() > 1);

        let mkvmerge = which::which("mkvmerge")?;
        let mut merge = Command::new(mkvmerge)
            .args(tracks.iter())
            .arg("-o")
            .arg(output.as_ref().with_extension("mkv"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // Capture and log stdout
        if let Some(stdout) = merge.stdout.take() {
            let stdout_reader = BufReader::new(stdout);
            tokio::spawn(async move {
                let mut lines = stdout_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!("[mkvmerge] {}", line);
                }
            });
        }

        // Capture and log stderr
        if let Some(stderr) = merge.stderr.take() {
            let stderr_reader = BufReader::new(stderr);
            tokio::spawn(async move {
                let mut lines = stderr_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::warn!("[mkvmerge] {}", line);
                }
            });
        }

        merge.wait().await?;

        // remove temporary files
        for track in tracks {
            tokio::fs::remove_file(track).await?;
        }

        Ok(())
    }
}
