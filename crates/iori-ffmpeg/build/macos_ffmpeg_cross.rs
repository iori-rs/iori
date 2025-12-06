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
    let arch = "x86_64";

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

    // Force x86_64 target flags so configure tests use the intended arch.
    Command::new("./configure")
        .arg(format!("--prefix={}", build_path))
        .arg("--enable-cross-compile")
        .arg("--target-os=darwin")
        .arg(format!("--arch={arch}"))
        .arg("--cc=clang")
        .arg("--cxx=clang++")
        .arg(format!("--extra-cflags=-arch {arch}"))
        .arg(format!("--extra-cxxflags=-arch {arch}"))
        .arg(format!("--extra-ldflags=-arch {arch}"))
        // To workaround `https://github.com/larksuite/rsmpeg/pull/98#issuecomment-1467511193`
        .arg("--disable-decoder=exr,phm")
        .arg("--disable-programs")
        .status()?;

    Command::new("make")
        .arg("-j")
        .arg(num_job.to_string())
        .status()?;

    Command::new("make").arg("install").status()?;

    cd("..")?;

    Ok(())
}
