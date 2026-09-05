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

## Known Bento4 CENS audio discrepancy

The bundled Bento4 generator uses ordinary CTR for CENS audio with a 0:0
pattern, including its final partial block. Its decryptor reverses that
operation, so those oracle files are not a CENS conformance oracle for sample
tails. ISO/IEC 23001-7:2023 sections 10.3 and 9.7 require whole-block encryption
for non-NAL CENS samples and leave their final 0–15 bytes clear. See
[the specification, printed pages 24 and 27](https://previewnorm.com/iso/ISO%20IEC%2023001-7-2023%20PDF.pdf)
and [tracking issue #79](https://github.com/iori-rs/iori/issues/79).

The Rust comparison checks all plaintext bytes against Bento4 except these
precisely bounded legacy tails, which must remain identical to the encrypted
input. Independently decoded `trun`/`tfhd` sample boundaries constrain every
exception. It also replaces only those tails in an in-memory fixture copy
with known plaintext and verifies that this compliant input decrypts to the
entire plaintext oracle. Both passes check file length and box offsets.
Stored fixtures are not rewritten, and the production decryptor does not
emulate Bento4's tail encryption.
