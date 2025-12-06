use std::{
    ffi::CString,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rsmpeg::{
    UnsafeDerefMut,
    avformat::{
        AVFormatContextInput, AVFormatContextOutput, AVIOContextContainer, AVIOContextCustom,
        AVOutputFormat,
    },
    avutil::{AVDictionary, AVMem},
    ffi::{
        AV_LOG_DEBUG, AV_LOG_ERROR, AV_LOG_INFO, AV_LOG_WARNING, av_log_format_line2,
        av_log_set_callback,
    },
};
use tokio::io::AsyncReadExt;

mod error;

use iori::{
    IoriResult, SegmentFormat, SegmentInfo,
    cache::CacheSource,
    merge::{AutoMergerConcat, AutoMergerMerge},
};

use crate::error::FfmpegError;

// Reference: https://github.com/YeautyYE/ez-ffmpeg/blob/a249e8ad35196cdf345e3f3dc93c87cfb263bfef/src/core/mod.rs#L434-L463
#[cfg(any(
    all(
        not(target_arch = "aarch64"),
        not(target_arch = "powerpc"),
        not(target_arch = "s390x"),
        not(target_arch = "x86_64")
    ),
    all(target_arch = "aarch64", target_vendor = "apple"),
    target_family = "wasm",
    target_os = "uefi",
    windows,
))]
type VaListType = *mut ::std::os::raw::c_char;

#[cfg(all(target_arch = "x86_64", not(target_os = "uefi"), not(windows)))]
type VaListType = *mut rsmpeg::ffi::__va_list_tag;

#[cfg(all(
    target_arch = "aarch64",
    not(target_vendor = "apple"),
    not(target_os = "uefi"),
    not(windows),
))]
pub type VaListType = rsmpeg::ffi::__BindgenOpaqueArray<u64, 4>;

#[cfg(all(target_arch = "powerpc", not(target_os = "uefi"), not(windows)))]
pub type VaListType = *mut rsmpeg::ffi::__va_list_tag_powerpc;

#[cfg(target_arch = "s390x")]
pub type VaListType = *mut rsmpeg::ffi::__va_list_tag_s390x;

unsafe extern "C" fn ffmpeg_log_callback(
    ptr: *mut ::std::os::raw::c_void,
    level: ::std::os::raw::c_int,
    fmt: *const ::std::os::raw::c_char,
    vargs: VaListType,
) {
    if level > AV_LOG_DEBUG as i32 {
        return;
    }

    #[cfg(all(
        target_arch = "aarch64",
        not(target_vendor = "apple"),
        not(target_os = "uefi"),
        not(windows),
    ))]
    let mut buf = [0u8; 1024];

    #[cfg(not(all(
        target_arch = "aarch64",
        not(target_vendor = "apple"),
        not(target_os = "uefi"),
        not(windows),
    )))]
    let mut buf = [0i8; 1024];

    let mut print_prefix = 1;

    let buf_len = unsafe {
        av_log_format_line2(
            ptr,
            level,
            fmt,
            vargs,
            buf.as_mut_ptr(),
            buf.len() as i32,
            &mut print_prefix,
        )
    };

    if buf_len < 0 {
        tracing::error!("ffmpeg log callback error: {}", buf_len);
        return;
    }

    let data = &buf[..buf_len as usize];
    let data = unsafe { &*(data as *const _ as *const [u8]) };
    let data = String::from_utf8_lossy(data);
    let data = data.trim_end_matches(['\r', '\n', ' ']);
    if data.is_empty() {
        return;
    }

    let level = level as u32;
    if level <= AV_LOG_ERROR {
        tracing::error!("{data}");
    } else if level <= AV_LOG_WARNING {
        tracing::warn!("{data}");
    } else if level <= AV_LOG_INFO {
        tracing::info!("{data}");
    } else if level <= AV_LOG_DEBUG {
        tracing::debug!("{data}");
    }
}

pub struct FFmpegMerger;

impl AutoMergerConcat for FFmpegMerger {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::Mpeg2TS
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
        if segments.is_empty() {
            return Ok(());
        }

        unsafe {
            av_log_set_callback(Some(ffmpeg_log_callback));
        }

        let output_path = output_path.as_ref().to_path_buf();

        let output_file = File::create(&output_path)?;
        let (mut output_context, _) = open_output_context(output_file)?;
        output_context.set_oformat(
            AVOutputFormat::guess_format(Some(c"ts"), Some(c"output.ts"), None).unwrap(),
        );
        let mut output_set: bool = false;
        let mut output_header_written = false;

        for segment in segments {
            let mut input_context = {
                let mut reader = cache.open_reader(segment).await?;
                let mut input_data = Vec::new();
                reader.read_to_end(&mut input_data).await?;
                open_input_context(input_data)?
            };

            let mut total_stream_count = 0;
            let mut mapping = Vec::new();
            for input_stream in input_context.streams() {
                let codec_type = input_stream.codecpar().codec_type();
                if !codec_type.is_video() && !codec_type.is_audio() {
                    mapping.push(None);
                    continue;
                }

                if !output_set {
                    output_set = true;

                    let mut output_stream = output_context.new_stream();
                    let mut codecpar = input_stream.codecpar().clone();
                    {
                        let codecpar = unsafe { codecpar.deref_mut() };
                        let is_codec_invalid = codecpar.codec_tag.to_be_bytes().contains(&0);
                        if is_codec_invalid {
                            codecpar.codec_tag = 0;
                        }
                        if codec_type.is_audio() {
                            codecpar.frame_size = 1000;
                        }
                    }
                    output_stream.set_codecpar(codecpar);
                    output_stream.set_time_base(input_stream.time_base);
                }
                mapping.push(Some(total_stream_count));
                total_stream_count += 1;
            }

            if !output_header_written {
                output_header_written = true;
                let mut dict = Some(AVDictionary::new(c"analyzeduration", c"100M", 0).set(
                    c"probesize",
                    c"100M",
                    0,
                ));

                output_context
                    .write_header(&mut dict)
                    .map_err(FfmpegError::from)?;
            }

            while let Some(mut packet) = input_context.read_packet().map_err(FfmpegError::from)? {
                let input_stream_index = packet.stream_index as usize;
                let Some(output_stream_index) = mapping[input_stream_index] else {
                    continue;
                };

                let in_stream = &input_context.streams()[input_stream_index];
                let out_stream = &output_context.streams()[output_stream_index];

                packet.rescale_ts(in_stream.time_base, out_stream.time_base);
                packet.set_stream_index(output_stream_index as i32);
                packet.set_pos(-1);

                output_context
                    .interleaved_write_frame(&mut packet)
                    .map_err(FfmpegError::from)?;
            }

            drop(input_context);
        }

        output_context.write_trailer().map_err(FfmpegError::from)?;

        Ok(())
    }
}

impl AutoMergerMerge for FFmpegMerger {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::Mp4
    }

    async fn merge<O>(&mut self, tracks: Vec<PathBuf>, output: O) -> IoriResult<()>
    where
        O: AsRef<Path> + Send,
    {
        unsafe {
            av_log_set_callback(Some(ffmpeg_log_callback));
        }

        let output = output.as_ref().to_path_buf();
        let c_tracks = tracks
            .iter()
            .map(|track| CString::new(track.as_os_str().as_encoded_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(FfmpegError::from)?;

        tokio::task::spawn_blocking(move || -> IoriResult<()> {
            let c_output =
                CString::new(output.as_os_str().as_encoded_bytes()).map_err(FfmpegError::from)?;
            let mut output_format_context =
                AVFormatContextOutput::create(&c_output, None).map_err(FfmpegError::from)?;

            let mut input_contexts = vec![];
            for c_track in c_tracks {
                let mut input_options = Some(
                    AVDictionary::new(c"analyzeduration", c"100M", 0).set(c"probesize", c"100M", 0),
                );
                let input_context: AVFormatContextInput =
                    AVFormatContextInput::open(&c_track, None, &mut input_options)
                        .map_err(FfmpegError::from)?;
                input_contexts.push(input_context);
            }

            // [track][stream] -> output_stream_index
            let mut total_stream_count = 0;
            let mut stream_mapping = Vec::new();
            for input_context in &input_contexts {
                let mut mapping = Vec::new();
                for input_stream in input_context.streams() {
                    let codec_type = input_stream.codecpar().codec_type();
                    if !codec_type.is_video() && !codec_type.is_audio() {
                        mapping.push(None);
                        continue;
                    }

                    let mut output_stream = output_format_context.new_stream();
                    let mut codecpar = input_stream.codecpar().clone();
                    let is_codec_invalid = codecpar.codec_tag.to_be_bytes().contains(&0);
                    if is_codec_invalid {
                        let codecpar = unsafe { codecpar.deref_mut() };
                        codecpar.codec_tag = 0;
                    }
                    output_stream.codecpar_mut().copy(&codecpar);
                    mapping.push(Some(total_stream_count));
                    total_stream_count += 1;
                }
                stream_mapping.push(mapping);
            }

            let mut dict = Some(AVDictionary::new(c"analyzeduration", c"100M", 0).set(
                c"probesize",
                c"100M",
                0,
            ));
            output_format_context
                .write_header(&mut dict)
                .map_err(FfmpegError::from)?;

            for (input_context, mapping) in input_contexts.iter_mut().zip(stream_mapping) {
                while let Some(mut packet) =
                    input_context.read_packet().map_err(FfmpegError::from)?
                {
                    let input_stream_index = packet.stream_index as usize;
                    let Some(output_stream_index) = mapping[input_stream_index] else {
                        continue;
                    };

                    {
                        let output_stream = &output_format_context.streams()[output_stream_index];
                        let input_stream = &input_context.streams()[input_stream_index];

                        packet.rescale_ts(input_stream.time_base, output_stream.time_base);
                        packet.set_stream_index(output_stream_index as i32);
                        packet.set_pos(-1);
                    }

                    output_format_context
                        .interleaved_write_frame(&mut packet)
                        .map_err(FfmpegError::from)?;
                }
            }

            output_format_context
                .write_trailer()
                .map_err(FfmpegError::from)?;
            Ok(())
        })
        .await
        .map_err(FfmpegError::from)??;

        // remove temporary files
        for track in tracks {
            tokio::fs::remove_file(track).await?;
        }

        Ok(())
    }
}

fn open_input_context(input: Vec<u8>) -> IoriResult<AVFormatContextInput> {
    let mut current: usize = 0;

    let io_context = AVIOContextCustom::alloc_context(
        AVMem::new(4096),
        false,
        vec![],
        Some(Box::new(move |_, buf| {
            let right = input.len().min(current + buf.len());
            if right <= current {
                return rsmpeg::ffi::AVERROR_EOF;
            }
            let read_len = right - current;
            buf[0..read_len].copy_from_slice(&input[current..right]);
            current = right;
            read_len as i32
        })),
        None,
        None,
    );

    let input_format_context =
        AVFormatContextInput::from_io_context(AVIOContextContainer::Custom(io_context))
            .map_err(FfmpegError::from)?;
    Ok(input_format_context)
}

fn open_output_context<W>(writer: W) -> IoriResult<(AVFormatContextOutput, Arc<Mutex<W>>)>
where
    W: Write + Send + 'static,
{
    let writer = Arc::new(Mutex::new(writer));

    let writer_inner = writer.clone();
    let io_context = AVIOContextCustom::alloc_context(
        AVMem::new(4096),
        true,
        vec![],
        None,
        Some(Box::new(move |_, data| {
            if let Err(e) = writer_inner.lock().unwrap().write_all(data) {
                tracing::error!("write error: {}", e);
                return rsmpeg::ffi::AVERROR_EXTERNAL;
            }
            data.len() as i32
        })),
        None,
    );

    let output_format_context =
        AVFormatContextOutput::create(c"output.ts", Some(AVIOContextContainer::Custom(io_context)))
            .map_err(FfmpegError::from)?;
    Ok((output_format_context, writer))
}
