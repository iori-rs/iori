use super::Merger;
use crate::{
    SegmentInfo, SegmentType,
    cache::CacheSource,
    error::IoriResult,
    util::{ordered_stream::OrderedStream, path::DuplicateOutputFileNamer},
};
use std::{path::PathBuf, pin::Pin, process::Stdio};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    process::Command,
    sync::mpsc,
    task::JoinHandle,
};

type SendSegment = (
    Pin<Box<dyn AsyncRead + Send + 'static>>,
    SegmentType,
    Pin<Box<dyn Future<Output = IoriResult<()>> + Send>>,
);

/// PipeMerger is a merger that pipes the segments directly to the output.
///
/// If there are any missing segments, it will skip them.
pub struct PipeMerger {
    recycle: bool,

    sender: Option<mpsc::UnboundedSender<(u64, u64, Option<SendSegment>)>>,
    future: Option<JoinHandle<()>>,
}

impl PipeMerger {
    pub fn stdout(recycle: bool) -> Self {
        Self::writer(recycle, tokio::io::stdout())
    }

    pub fn writer(
        recycle: bool,
        mut writer: impl AsyncWrite + Unpin + Send + Sync + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        let mut stream: OrderedStream<Option<SendSegment>> = OrderedStream::new(rx);
        let future = tokio::spawn(async move {
            while let Some((_, segment)) = stream.next().await {
                if let Some((mut reader, _type, invalidate)) = segment {
                    _ = tokio::io::copy(&mut reader, &mut writer).await;
                    if recycle {
                        _ = invalidate.await;
                    }
                }
            }
        });

        Self {
            recycle,

            sender: Some(tx),
            future: Some(future),
        }
    }

    pub fn file(recycle: bool, target_path: PathBuf) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        let mut stream: OrderedStream<Option<SendSegment>> = OrderedStream::new(rx);
        let future = tokio::spawn(async move {
            let mut namer = DuplicateOutputFileNamer::new(target_path.clone());
            let mut target = Some(
                tokio::fs::File::create(&target_path)
                    .await
                    .expect("Failed to create file"),
            );
            while let Some((_, segment)) = stream.next().await {
                if let Some((mut reader, _type, invalidate)) = segment {
                    if target.is_none() {
                        let file = tokio::fs::File::create(namer.next_path())
                            .await
                            .expect("Failed to create file");
                        target = Some(file);
                    }

                    if let Some(target) = &mut target {
                        _ = tokio::io::copy(&mut reader, target).await;
                    }
                    if recycle {
                        _ = invalidate.await;
                    }
                } else {
                    target = None;
                }
            }
        });

        Self {
            recycle,

            sender: Some(tx),
            future: Some(future),
        }
    }

    pub fn mux(recycle: bool, output: PathBuf, extra_command: Option<String>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        let mut stream: OrderedStream<Option<SendSegment>> = OrderedStream::new(rx);

        #[cfg(target_os = "windows")]
        let (mut audio_pipe, audio_receiver) = {
            let pipe_name = format!(r"\\.\pipe\iori-pipe-mux-audio-{}", rand::random::<u64>());
            let server = tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
                .unwrap();
            (server, pipe_name)
        };

        #[cfg(not(target_os = "windows"))]
        let (mut audio_pipe, audio_receiver) = {
            let (audio_pipe, audio_receiver) = tokio::net::unix::pipe::pipe().unwrap();
            let audio_receiver = audio_receiver.into_nonblocking_fd().unwrap();
            (audio_pipe, audio_receiver)
        };

        let future = tokio::spawn(async move {
            // TODO: maybe creating a new process might be better
            let mut video_pipe = tokio::spawn(async move {
                let mut command = Command::new("ffmpeg");
                command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());

                #[cfg(not(target_os = "windows"))]
                {
                    use command_fds::{CommandFdExt, FdMapping};
                    command
                        .fd_mappings(vec![FdMapping {
                            parent_fd: audio_receiver,
                            child_fd: 3,
                        }])
                        .unwrap();
                }

                command.args(["-y", "-fflags", "+genpts"]); // , "-loglevel", "quiet"

                if extra_command.is_some() {
                    command.arg("-re");
                }

                // video input: stdin
                command.args(["-i", "pipe:0"]);
                // audio input: mapped fd 3 or named pipe
                #[cfg(target_os = "windows")]
                command.args(["-i", &audio_receiver]);
                #[cfg(not(target_os = "windows"))]
                command.args(["-i", "pipe:3"]);

                #[rustfmt::skip]
                command.args([
                    "-map", "0",
                    "-map", "1",
                    "-strict", "unofficial",
                    "-c", "copy",
                    "-metadata", &format!(r#"date="{}""#, chrono::Utc::now().to_rfc3339()),
                    "-ignore_unknown",
                    "-copy_unknown",
                ]);

                if let Some(dest) = extra_command.and_then(|s| shlex::split(&s)) {
                    command.args(dest);
                } else {
                    command.args(["-f", "mpegts", "-shortest"]).arg(output);
                }

                let mut process = command.spawn().unwrap();
                let stdin = process.stdin.take().unwrap();
                tokio::spawn(async move {
                    process.wait().await.unwrap();
                });

                stdin
            })
            .await
            .unwrap();

            let (video_sender, mut video_receiver) = mpsc::unbounded_channel::<SendSegment>();
            let video_handle = tokio::spawn(async move {
                while let Some((mut reader, _, invalidate)) = video_receiver.recv().await {
                    tokio::io::copy(&mut reader, &mut video_pipe).await.unwrap();
                    if recycle {
                        invalidate.await.unwrap();
                    }
                }
            });

            let (audio_sender, mut audio_receiver) = mpsc::unbounded_channel::<SendSegment>();
            let audio_handle = tokio::spawn(async move {
                #[cfg(target_os = "windows")]
                audio_pipe.connect().await.unwrap();

                while let Some((mut reader, _, invalidate)) = audio_receiver.recv().await {
                    tokio::io::copy(&mut reader, &mut audio_pipe).await.unwrap();
                    if recycle {
                        invalidate.await.unwrap();
                    }
                }
            });

            while let Some((_, segment)) = stream.next().await {
                if let Some((reader, r#type, invalidate)) = segment {
                    match r#type {
                        SegmentType::Video => {
                            video_sender.send((reader, r#type, invalidate)).unwrap();
                        }
                        SegmentType::Audio => {
                            audio_sender.send((reader, r#type, invalidate)).unwrap();
                        }
                        SegmentType::Subtitle | SegmentType::Unknown => {
                            if recycle {
                                _ = invalidate.await;
                            }
                        }
                    }
                }
            }

            tracing::debug!("Waiting for video handler...");
            drop(video_sender);
            video_handle.await.unwrap();

            tracing::debug!("Waiting for audio handler...");
            drop(audio_sender);
            audio_handle.await.unwrap();
        });

        Self {
            recycle,

            sender: Some(tx),
            future: Some(future),
        }
    }

    fn send(&self, message: (u64, u64, Option<SendSegment>)) {
        if let Some(sender) = &self.sender {
            sender.send(message).expect("Failed to send segment");
        }
    }
}

impl Merger for PipeMerger {
    type Result = ();

    async fn update(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        let stream_id = segment.stream_id;
        let sequence = segment.sequence;
        let r#type = segment.r#type;
        let reader = cache.open_reader(&segment).await?;
        let invalidate = async move { cache.invalidate(&segment).await };

        self.send((
            stream_id,
            sequence,
            Some((Box::pin(reader), r#type, Box::pin(invalidate))),
        ));

        Ok(())
    }

    async fn fail(&mut self, segment: SegmentInfo, cache: impl CacheSource) -> IoriResult<()> {
        let stream_id = segment.stream_id;
        cache.invalidate(&segment).await?;

        self.send((stream_id, segment.sequence, None));

        Ok(())
    }

    async fn finish(&mut self, cache: impl CacheSource) -> IoriResult<Self::Result> {
        // drop the sender so that the future can finish
        drop(self.sender.take());

        self.future
            .take()
            .unwrap()
            .await
            .expect("Failed to join pipe");

        if self.recycle {
            cache.clear().await?;
        }

        Ok(())
    }
}
