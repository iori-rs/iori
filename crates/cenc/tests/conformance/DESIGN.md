# ISO/IEC 23001-7:2023 test-suite design

Status: executable foundation implemented; see [README.md](README.md) for
commands, measured coverage and remaining gaps. This document retains the
complete target design; not every target family is implemented.

Companion artifacts: [proposed test families](families.csv) and
[source/interpretation register](INTERPRETATIONS.md), and
[knowledge-based test cases](KNOWLEDGE_CASES.md).

The objective is a traceable suite covering every applicable requirement in
the fourth edition, with independent cryptographic vectors and real MP4
decryption comparisons against Bento4 `mp4decrypt` and Shaka Packager.
Passing comparisons against those tools alone is not a conformance verdict.

## Source boundary and completion rule

Pin the baseline to ISO/IEC 23001-7:2023, edition 4, August 2023. Do not silently
include later amendments. The [ISO catalogue](https://www.iso.org/standard/84637.html)
identifies a 42-page standard. The publicly available
[working PDF](https://previewnorm.com/iso/ISO%20IEC%2023001-7-2023%20PDF.pdf)
ends on printed page 34, partway through Annex A. Its extraction also needs
visual verification around the scope and normative references.

Design and implementation can proceed using established cryptographic, MP4
and codec knowledge. Cases inferred this way carry `knowledge-derived`
provenance and an explicit expected property; source-verified requirements
carry their normative locator. Only the claim of exhaustive normative coverage
awaits a complete-source audit; that audit is not a prerequisite for building
or running the suite.
Do not redistribute the standard in the repository. Record an externally
provided source's edition, page count and SHA-256 in the release report.

The source audit must assign a stable requirement ID to every normative
condition, syntax-field restriction, conditional branch, table row and
normative reference used by Part 7. Keep SHOULD recommendations and optional
features visible. A clause heading is not a requirement and one test per
clause is insufficient. Annex examples are evidence, not replacements for
the normative algorithms.

For every requirement, record its actor (writer, reader, decryptor, manifest
consumer), applicability predicate, test instances and oracle. Conditions that
cannot be inferred from one file, such as cross-asset key/IV reuse, need a
corpus-level check. Writer requirements must not be invented as mandatory
decoder error behavior.

## Separate the verdicts

| Dimension | Values and meaning |
| --- | --- |
| Input classification | normative-valid, normative-invalid, legacy-compatibility, project-invariant |
| Implementation capability | supported, partial, unsupported, unverified |
| Execution | pass, fail, not-run, tool-unsupported, blocked-source, blocked-interpretation |
| Product profile | four track schemes; complete Part 7 including items, multi-key samples, sensitive encryption and XML |

A valid unsupported input can pass a safe-rejection test while remaining an
unsupported feature. It cannot turn the complete-Part-7 support indicator
green. A malformed input has a validity failure; its decoder expectation is
specified separately (defined error, tolerated behavior, or resource-safe
handling). Wrong AES keys need not produce an error because these schemes do
not authenticate plaintext; compare output to a known plaintext instead.

Release reports publish requirement enumeration completeness, execution
completeness, supported-feature coverage, compatibility results and external
tool results separately. Any missing source, unknown applicability, absent
required tool, unexecuted required case, or unresolved interpretation blocks
the corresponding full-coverage claim. Expected failures need an issue and
review date; an unexpected pass requires review rather than silently masking
a changed implementation.

## Current code and test gaps

The existing suite is a useful regression baseline, not the denominator for
the new suite. `DecryptJob` represents one key/IV per sample; `senc` parsing
accepts version zero; the parsed `sve1` path returns an unsupported error.
There is no dedicated encrypted-item or XML-conformance test module.

Current external tests return successfully when tools or generated media are
absent. The Shaka test skips audio/video files, uses duplicate key labels, and
compares concatenated `mdat` bytes even though remuxing can change interleaving.
The matrix is generated with Bento4 alone and has no locked tool manifest.
The BBB smoke test only establishes that payload bytes changed.

Reclassify tests with unaccounted sample bytes or partial protected ranges
where a scheme imposes alignment as robustness tests. Keep their regression
value, but add separate validity assertions and valid counterparts. Likewise,
generic accepted IV shapes do not establish that every scheme permits them.
The detailed fixture audit must examine all hand-built inputs before moving
them into the normative-valid corpus.

## Suite layers

| Layer | Responsibility | Oracle independent of iori |
| --- | --- | --- |
| Requirement catalogue | Enumerate source rules and applicability | Full-source review, versioned decisions |
| Primitive vectors | AES, counter/chaining state, pattern selection | Published AES known-answer vectors and a separately implemented reference |
| Binary syntax | Field order, versions, flags, lengths and associations | Literal bytes and independent field reader |
| Semantic validity | Cross-box and scheme restrictions | Rule engine separate from decrypt-job construction |
| Synthetic containers | Exact offsets, groups, auxiliary records, adversarial layouts | Independent writer plus expected sample table |
| Real media | Codec and muxer interactions | Original encoded sample bytes, two external decryptors |
| Robustness | Truncation, overflow, unsupported inputs, resource limits | No panic/hang/OOB write; declared error policy |
| Project contract | In-place output and selective metadata cleanup | Original recursive box layout and byte-range allowlist |

Keep encoder, metadata validator, sample extractor and production parser
independent. Production `ParsedCenc` output must not determine which mismatches
are allowed or which bytes count as encrypted. Use published AES vectors to
anchor the reference implementation before using it to generate new fixtures.

## Catalogue and generation model

`families.csv` lists the initial coverage inventory. It intentionally records
families, not a falsely exhaustive list of normative assertions. Implementation
expands each family into atomic `requirements.jsonl` records and deterministic
`cases.jsonl` records. Knowledge-derived records can be implemented now and
linked to precise normative requirements as verification progresses. Each case contains:

```json
{
  "id": "ctr-subsample-counter-continuation-iv8-two-ranges",
  "requirements": ["PART7-9.3-counter-continuity"],
  "classification": "normative-valid",
  "profile": "track-four-schemes",
  "capability": "supported",
  "fixture": "sha256:<content-hash>",
  "recipe": "recipes/ctr-subsamples.json",
  "seed": 1,
  "preconditions": ["independent-validator-pass"],
  "expectation": "exact-original-sample-bytes",
  "oracles": ["reference-aes", "original-clear-samples"],
  "external_expectations": {"bento4": "probe", "shaka": "probe"},
  "interpretations": []
}
```

This is a proposed schema, not a current executable case. Final records also
store clause/page/paragraph locators, target actor, source hash, build commit,
tool capability profile, and issue references. Unsupported cases remain in
the catalogue. Add a catalogue linter that rejects orphan requirements,
duplicate IDs, missing witnesses and cases labeled valid without validation.

Enumerate finite fields completely when cheap: pattern nibbles 0..15,
supported version/flag combinations, IV-width choices, key-index selection,
and protection transitions. Derive validity from the scheme before execution.
Exercise byte lengths 0, 1, 15, 16, 17, 31, 32, 33 and points immediately around
each pattern boundary. Include all tail remainders 0..15. Cross critical
dimensions exhaustively; use constrained pairwise generation only for
secondary interactions. Record which combinations it omits.

Counts and offsets use zero/one/multiple, maximum encodable values, overflow,
underflow, exact EOF and one-byte overruns. Simulate large address spaces in a
bounded reader rather than allocating multi-gigabyte media. Mutate one rule
at a time to make a negative case diagnostic. Run deterministic seeds on PRs;
archive shrinking results from longer property/fuzz runs as fixed regressions.

## Real MP4 corpus

Create redistributable deterministic source clips with known provenance:
AAC and a second supported audio codec; AVC baseline and high/CABAC; HEVC;
additional codecs only when their applicable signaling rules and tool support
are established. Use one-frame/one-sample, short multi-sample, and multi-fragment
clips. Include audio-only, video-only, audio/video, and mixed clear/protected
tracks. Use content with multiple NAL units and nontrivial slice headers.

Preserve original encoded samples before any encryption. Persist a manifest
of logical track identity, codec configuration, decode-order sample number,
DTS, CTS offset, duration, sample length and SHA-256. Keep exact bytes for small
vectors and hashes plus retrievable artifacts for larger media. Fix encoder
versions/options/thread counts; a recipe is reproducible only with its pinned
environment. A mismatch in source hash is a fixture-generation failure.

| Producer | Inputs to decryptors | Required comparisons |
| --- | --- | --- |
| Bento4 mp4encrypt | Supported schemes and container forms, one/many keys and tracks | iori and mp4decrypt and Shaka against original samples |
| Shaka Packager | Supported protection schemes, fragmentation, clear lead and rotation | iori and mp4decrypt and Shaka against original samples |
| Independent binary writer/reference cipher | Rare legal metadata and 2023 features tools cannot generate | iori against explicit expectations; probe both external tools |
| Single-rule mutations | Invalid/unsupported variants of the above | Validity classification and declared decoder behavior |

Do not assume every tool supports every scheme or layout. Lock a capability
table by exact binary version and probe it with tiny known fixtures. Unexpected
tool errors fail the run; known unsupported combinations are reported with
evidence and never counted as interoperability passes. Run all three decryptors
on every declared mutually supported cell. Tool agreement cannot override the
specification or the known source samples.

Cross schemes with fragmented and nonfragmented media where supported,
combined and separate init segments, multiple fragments/runs/chunks, clear lead
and selective groups, track-level and fragment-local group tables, per-sample
and constant IV configurations where valid, auxiliary records in different
allowed locations, subsamples, sample-description changes, and key rotation.
Include seeking/decryption of an isolated fragment with its proper init and
keys. Use distinct key values so incorrect key selection cannot pass.

For Shaka, explicitly set `--clear_lead 0` in fully protected recipes; use an
explicit nonzero value only in clear-lead cases. Assert that encrypted samples
actually exist so short all-clear output cannot pass as encryption coverage.
Use distinct key labels, explicit stream selection, and separate output paths
for each track of a multiplexed input. Treat test-only rotation recipes as
fixtures, not a production key-management model.

## Comparison algorithm

1. Validate the generated encrypted file independently and preserve it.
2. Clone the identical encrypted bytes for iori; feed the same asset/init/key
   mapping to both external decryptors. Capture argv, exit status, stdout,
   stderr, elapsed time and output hashes; enforce subprocess timeouts.
3. Extract samples independently from all outputs. Match tracks by the fixture
   manifest rather than output track IDs, which remuxers can change. Compare
   ordered encoded samples exactly, with timestamps represented as rational
   values when timescales differ. Explicitly account for edit lists and encoder
   priming; do not discard samples merely to align results.
4. If an oracle changes representation, use a named lossless canonicalizer
   with its own tests and store the original bytes too. Never silently strip
   NAL units or metadata to force a match. Codec parameter sets/configuration
   are part of the comparison contract.
5. Decode each result with a pinned software FFmpeg decoder and compare frame
   hashes/PCM to the source as a second check. Exact encoded samples remain
   the primary cryptographic oracle. Corrupt-header failure and unchanged
   ciphertext cannot pass merely because a decoder emitted some frames.
6. For iori only, compare file length and every recursive box start/size/order,
   exact media-byte changes, clear ranges, unrelated metadata, and expected
   signaling cleanup. External muxers are free to rewrite their box layout.

The existing Bento4 CENS audio-tail exception belongs in a versioned legacy
compatibility record. The normative lane uses conforming fixtures generated
independently. Never repair fixtures inside an ordinary oracle comparison or
derive exception ranges from the production decryptor. Any repaired derivative
must have a separate ID, recipe, hashes and explicit provenance.

## Runner, reproducibility and reporting

Proposed entry point: `python3 crates/cenc/tests/conformance/run.py --profile
<profile>`. The runner is implemented; see README.md for its current profiles and limits. Profiles are `unit`, `track-interop`,
`full-part7`, and `compatibility`. The `full-part7` execution profile runs all catalogued cases, including inferred
cases, without requiring the source audit to be complete. Missing required
fixtures or tools fail preflight. Its report separately sets
`normative_completeness=unverified` until source review is complete; a release
gate requesting verified full conformance fails on that status. Rust integration tests
that require external tools should use explicit ignored tests in ordinary
developer runs; the interop runner invokes them deliberately and enforces
preflight. There must be no silent successful return on a missing dependency.

Pin Bento4, Shaka, FFmpeg, Rust, the reference cipher and the sample extractor
in `tools.lock.json`: upstream URL, full source commit/submodules, build flags,
archive SHA-256, binary hashes and container image digest. Select versions
through a measured baseline, not mutable `latest` URLs. The official
[Bento4 downloads](https://www.bento4.com/downloads/) and
[Shaka releases](https://github.com/shaka-project/shaka-packager/releases)
are discovery sources; upgrades are dedicated baseline changes.

Generate into a new content-addressed directory and publish the manifest only
after validation completes. Preserve failing artifacts rather than deleting
the previous corpus at the start of a run. Cache by all recipe/source/tool
hashes. Keep tiny fixtures in Git; host larger immutable archives with checksums
and license records. Do not commit private source media, paid standards or DRM
secrets. All cryptographic keys in the corpus are explicitly public test keys.

Write JSON and JUnit results plus a readable coverage table. Each failure must
identify requirement/case, producer, decryptor, scheme, logical track, sample,
first differing byte, expected/actual digest and artifact paths. Log whether
an external comparison actually executed. Distinguish generator failure,
invalid-fixture failure, decryptor failure, oracle disagreement and source gap.

## CI and delivery order

PR checks run catalogue validation, primitive/binary vectors, the small real
corpus with both external tools, project invariants, formatting and lint.
Nightly checks run the larger codec/container cross-product and bounded fuzzing.
Release checks run the complete pinned corpus with no unapproved omissions,
including applicable 2023 feature profiles. Optional hardware playback may
provide additional compatibility evidence but is not the conformance oracle.

Deliver in independently reviewable steps:

1. Atomic requirement catalogue and interpretation log, with verified and
   knowledge-derived provenance. Continue complete-source verification in parallel.
2. Fixture-validity layer; reclassify existing tests and preserve regressions.
3. Independent AES vectors, binary writer, sample extractor and comparison tests.
4. Locked Bento4/Shaka real corpus and strict runner, including multitrack media.
5. Rare-layout, key-rotation, multi-key, item, XML and Annex A families; retain
   explicit unsupported results until the implementation supports them.
6. CI/reporting gates and review of the complete requirement-to-case mapping.

The design can be implemented now, including the knowledge-derived cases.
Full normative completeness is a separate review milestone; neither inferred
coverage nor safe rejection of unsupported features is a certification claim.

## Implementation references

- [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final): independent
  CTR/CBC algorithm vectors; adapt counter state rules only through separately
  checked Part 7 requirements.
- [Bento4 mp4encrypt](https://www.bento4.com/documentation/mp4encrypt/) and
  [mp4decrypt](https://www.bento4.com/documentation/mp4decrypt/): CLI recipes
  and detached-fragment handling.
- [Shaka CLI](https://shaka-project.github.io/shaka-packager/html/documentation.html):
  stream selection, raw-key configuration and explicit encryption settings.
- [Shaka raw-key provider](https://github.com/shaka-project/shaka-packager/blob/main/packager/media/base/raw_key_source.cc):
  source for investigating labels and deterministic test rotation; pin the
  implementation revision before deriving fixture recipes.
