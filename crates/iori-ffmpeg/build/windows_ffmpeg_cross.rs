#!/bin/sh
#![allow(unused_attributes)] /*
OUT=/tmp/tmp && rustc "$0" -o ${OUT} && exec ${OUT} $@ || exit $? #*/

use std::fs;
use std::io::Result;
use std::path::PathBuf;
use std::process::Command;

fn mkdir(dir_name: &str) -> Result<()> {
    fs::create_dir(dir_name)
}

fn pwd() -> Result<PathBuf> {
    std::env::current_dir()
}

fn cd(dir_name: &str) -> Result<()> {
    std::env::set_current_dir(dir_name)
}

fn main() -> Result<()> {
    let _ = mkdir("tmp");

    cd("tmp")?;

    let tmp_path = pwd()?.to_string_lossy().to_string();
    let build_path = format!("{}/ffmpeg_build", tmp_path);
    let branch = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "release/7.1".to_string());
    let num_job = std::thread::available_parallelism().unwrap().get();

    if fs::metadata("ffmpeg").is_err() {
        Command::new("git")
            .arg("clone")
            .arg("--single-branch")
            .arg("--branch")
            .arg(&branch)
            .arg("--depth")
            .arg("1")
            .arg("https://github.com/ffmpeg/ffmpeg")
            .status()?;
    }

    cd("ffmpeg")?;

    Command::new("git")
        .arg("fetch")
        .arg("origin")
        .arg(&branch)
        .arg("--depth")
        .arg("1")
        .status()?;

    Command::new("git")
        .arg("checkout")
        .arg("FETCH_HEAD")
        .status()?;

    Command::new("./configure")
        .arg(format!("--prefix={}", build_path))
        // To workaround `https://github.com/larksuite/rsmpeg/pull/98#issuecomment-1467511193`
        .arg("--disable-decoder=exr,phm")
        .arg("--disable-programs")
        .arg("--disable-autodetect")
        .arg("--arch=x86_64")
        .arg("--target-os=mingw32")
        .arg("--cross-prefix=x86_64-w64-mingw32-")
        .arg("--pkg-config=pkg-config")
        .arg("--enable-static")
        .arg("--disable-shared")
        // https://github.com/elan-ev/static-ffmpeg/blob/ffb12599ea77149bb91d5ecb37304ee96a546c29/build_ffmpeg.sh#L494C24-L497
        .arg("--pkg-config-flags=--static")
        .arg("--extra-libs=-lstdc++")
        .arg("--extra-cflags=-static -static-libgcc")
        .arg("--extra-cxxflags=-static -static-libgcc -static-libstdc++")
        .arg("--extra-ldflags=-static -static-libgcc -static-libstdc++")
        .status()?;

    Command::new("make")
        .arg("-j")
        .arg(num_job.to_string())
        .status()?;

    Command::new("make").arg("install").status()?;

    cd("..")?;

    Ok(())
}
