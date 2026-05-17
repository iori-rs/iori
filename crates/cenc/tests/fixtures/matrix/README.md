# Encryption fixture matrix

`generate.sh` builds a local compatibility matrix from deterministic
audio and video sources:

- audio-only MP4
- video-only MP4
- audio+video MP4
- short and larger variants
- `MPEG-CENC`
- `MPEG-CENS`
- `MPEG-CBC1`
- `MPEG-CBCS`

The script writes generated media under `generated/`, which is ignored by git.
It also writes Bento4 `mp4decrypt` outputs as oracle files. The Rust matrix
test consumes the generated directory when it exists and otherwise skips. An
optional Shaka Packager differential test can also consume the same generated
fixtures when `SHAKA_PACKAGER` points to the `packager` executable.

Required tools:

- `ffmpeg`
- Bento4 `mp4fragment`
- Bento4 `mp4encrypt`
- Bento4 `mp4decrypt`
- Shaka Packager `packager` (optional, for `shaka_differential`)

Run:

```sh
crates/cenc/tests/fixtures/matrix/generate.sh
cargo test -p iori-cenc --test cenc_matrix
SHAKA_PACKAGER=/path/to/packager cargo test -p iori-cenc --test shaka_differential
```
