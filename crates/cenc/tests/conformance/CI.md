# Running the gates

`.github/workflows/cenc-conformance.yml` runs the strict unit profile for CENC
changes on pushes and pull requests. It retains JSON, JUnit, and command logs
on success and failure. This job checks the regression suite and catalogue;
it does not assert complete Part 7 coverage or execute external decryptors.
It does not depend on the repository's unrelated FFmpeg build workflow.

Run the real-media comparisons separately with all required tools installed:

```sh
python3 crates/cenc/tests/conformance/run.py \
  --profile track-interop \
  --ffmpeg /absolute/path/to/ffmpeg \
  --mp4encrypt /absolute/path/to/mp4encrypt \
  --mp4decrypt /absolute/path/to/mp4decrypt \
  --mp4fragment /absolute/path/to/mp4fragment \
  --shaka /absolute/path/to/packager \
  --tool-lock /absolute/path/to/reviewed-tools.lock.json \
  --record-tools \
  --output target/cenc-interop-baseline
```

`--record-tools` explicitly establishes a platform-specific tool baseline.
Review and retain that lock with the report. For subsequent runs omit that
flag, reuse the same lock, and select a fresh output directory. Changed tool
hashes or version output then fail preflight. Missing tools are failures.
This records reproducibility evidence for the installed environment; it is
not a fully pinned OS, compiler, encoder, or container image. The unit CI's
Python/Rust actions are also version selectors, not immutable image digests.

External-interoperability CI is not configured by this workflow. A future
hosted job must install and verify platform-specific tool archives before
running the same command. Do not substitute a macOS tool lock for Linux.
The `full-part7` profile executes the available tests and reports unknown or
unimplemented coverage separately. Add `--require-complete` to enforce a
release gate that fails while the requirement source audit and unsupported
feature families remain open. Passing executed tests alone is not exhaustive
Part 7 compliance.
