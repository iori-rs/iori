#!/bin/sh
#![allow(unused_attributes)] /*
OUT=/tmp/tmp && rustc "$0" -o ${OUT} && exec ${OUT} $@ || exit $? #*/

use std::fs;
use std::io::Result;
use std::process::Command;

fn main() -> Result<()> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "x86_64-apple-darwin".to_string());

    if fs::metadata("tmp").is_ok() {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        if target == "x86_64-pc-windows-gnu" {
            Command::new("./build/windows_ffmpeg_cross.rs").status()?;
        } else {
            Command::new("./build/linux_ffmpeg.rs").status()?;
        }
    }

    // Cross compile on macOS
    #[cfg(target_os = "macos")]
    {
        // FIXME: check current arch
        if target == "x86_64-apple-darwin" {
            Command::new("./build/macos_ffmpeg_cross.rs").status()?;
        } else {
            Command::new("./build/linux_ffmpeg.rs").status()?;
        }
    }

    Ok(())
}
