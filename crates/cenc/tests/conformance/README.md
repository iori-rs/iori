# Executable CENC conformance and interoperability suite

The runner exercises `iori-cenc`, independent Python metadata/sample oracles,
Bento4 `mp4decrypt`, and Shaka Packager. It reports individual comparisons and
coverage gaps; successful execution is not a claim of complete ISO compliance.

## Run

Local tests require Python 3.10+ and Rust:

```sh
python3 crates/cenc/tests/conformance/run.py --profile unit
```

For real MP4 tests, install FFmpeg with AAC/libx264/libx265, and Bento4
`mp4encrypt`, `mp4decrypt`, `mp4fragment`. Install the checksum-verified Shaka
release with:

```sh
python3 crates/cenc/tests/conformance/setup_shaka.py
```

Run all core real-media comparisons and streaming cases:

```sh
python3 crates/cenc/tests/conformance/run.py \
  --profile track-interop --shaka target/cenc-tools/packager
```

The checked-in `tools.lock.json` records the macOS ARM64 baseline used during
implementation. On another platform, explicitly establish a separate lock:

```sh
python3 crates/cenc/tests/conformance/run.py \
  --profile track-interop --shaka /path/to/packager \
  --tool-lock target/my-tools.lock.json --record-tools
```

Review that lock, then omit `--record-tools` on subsequent runs. Executable
hashes and version output must match. This fingerprints installed binaries;
it does not pin every dynamically linked library or the operating system.
Known oracle deviations are only recognized for the measured binary hashes.
A different version that disagrees remains a failure until investigated.

Every run creates a fresh `target/cenc-conformance/<timestamp>` directory, or
uses a new `--output` path. Existing run directories are never overwritten.
Reports include `report.json`, `junit.xml`, `summary.md`, command arguments,
stdout/stderr, source sample manifests, encryption-range manifests and media.
Missing tools, empty inputs, unexpected tool failures and unreviewed mismatches
fail the run. Failed artifacts remain available.

`--quick` selects a smaller development matrix. `--profile compatibility`
selects the core oracle-deviation corpus. `--profile full-part7` executes the
available full corpus and publishes remaining gaps. Add `--require-complete`
to reject any unverified normative completeness; that gate currently fails by
design because the source audit and feature coverage remain incomplete.

## What is implemented

- Frozen NIST CTR/CBC vectors, counter/chaining traces, all 256 crypt/skip
  nibble pairs and all tail remainders: 24,576 pattern/tail checks.
- Public-parser malformed metadata, unsupported-feature responses, allocation
  bounds, group defaults and namespace tests.
- 180 frozen-plaintext decryption checks across equivalent progressive and
  fragmented layouts, run/chunk arrangements, padding and auxiliary storage.
- Independent MP4 extraction for ordinary progressive and fragmented tracks,
  including compact sizes, 64-bit addressing, signed offsets, timing/edit lists
  and explicit matching for otherwise ambiguous tracks.
- An independent single-key encryption-range oracle that checks clear bytes
  and identifies unsupported representations explicitly.
- Real AAC, AVC, HEVC and audio/video files produced by Bento4 and Shaka under
  all four track schemes; progressive CENC files produced by FFmpeg.
- Exact source-sample comparison, decoded video/PCM hashes, and iori-only
  recursive box-layout and clear-byte preservation checks in the core matrix.
- Selected-bit and XML/PSSH reference mechanisms, explicitly distinguished
  from product feature support.
- Runner/comparator fault injection, a traceability catalogue and a separate
  unit CI workflow. External-tool CI is not yet provisioned; see [CI.md](CI.md).

The original environment-dependent Rust differential wrappers are now
explicitly ignored by default and fail when deliberately invoked without their
requirements. The new runner provides the required external comparisons;
legacy whole-mdat wrappers do not define its verdicts.

## Interpretation of external results

`pass` means the declared exact comparisons executed successfully.
`known-oracle-deviation` and `tool-unsupported` retain evidence and appear as
skipped comparisons in JUnit, never as passing conformance tests. A case with
such results is `qualified`. Unknown deviations remain failures.

The measured Bento4 CENS audio behavior differs at partial audio block tails.
The compatibility checker verifies every other byte and metadata field; it
never repairs a normative input or silently ignores arbitrary differences.
The measured external tools also do not successfully decrypt some progressive
CENC layouts: unchanged ciphertext and explicit parser refusal are recorded
separately. See the run artifacts and `deviations.py` for exact predicates.

The normal runner returns success when all mandatory checks executed and only
reviewed deviations remain. Consumers requiring every external comparison to
pass must inspect the non-pass counts; `--require-complete` additionally gates
normative coverage. Reference-mechanism tests and predictable rejection of
unsupported 2023 formats do not establish implementation support.

## Coverage and limits

`families.csv`, `requirements.json` and `cases.json` retain 75 design families
and their decomposed engineering properties. `catalogue.py` validates mappings
and derives execution only from observed test/decoder results. Mapping several
requirements to a test does not create several independently executed tests.
No broad family receives complete credit from a representative regression.

The remaining item, multi-key, codec-sensitive and exact normative-validation
work is visible in `report.json`; the suite is not exhaustive Part 7 validation.
Some cases are knowledge-derived, and a complete authoritative source audit
is still needed for a verified normative denominator. This does not prevent
running the implemented cases.

Synthetic real media comes from FFmpeg lavfi sources and public test keys.
Its generation arguments and original samples are retained. Shaka/Bento4 IVs
are explicit in the core recipes; FFmpeg may generate IVs internally, so its
exact emitted artifacts and hashes are the replay evidence. Never assume a
recipe alone guarantees byte-identical encrypted files across environments.

For the complete design and interpretation decisions, see [DESIGN.md](DESIGN.md),
[KNOWLEDGE_CASES.md](KNOWLEDGE_CASES.md), and [INTERPRETATIONS.md](INTERPRETATIONS.md).

## Findings tracked by this suite

- [#81](https://github.com/iori-rs/iori/issues/81): metadata counts allocated
  memory before validation; fixed with bounded parsing and regression vectors.
- [#79](https://github.com/iori-rs/iori/issues/79): CENS audio-tail discrepancy.
- [#82](https://github.com/iori-rs/iori/issues/82): measured progressive-CENC
  limitations in the external decryptors.
- [#83](https://github.com/iori-rs/iori/issues/83): measured key-rotation
  limitations in the external decryptors.
