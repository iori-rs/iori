# Local implementation baseline

Measured on macOS ARM64 with the executable identities in `tools.lock.json`.
This is a regression/interoperability result, not full Part 7 certification.

| Check | Result |
| --- | --- |
| Rust tests | 112 passed; 3 legacy external wrappers explicitly ignored |
| Python tests | 87 passed |
| Pattern/tail generated checks | 24,576 within the Rust tests |
| Equivalent-layout decryptions | 180 within the Rust tests |
| Core real-media cases | 35 |
| Additional streaming cases | 4 |
| Individual external comparisons | 129 executed: 115 pass, 6 known CENS-tail deviations, 8 tool-unsupported |
| Formatting / strict Clippy | Pass |
| Full normative coverage | Unverified; not claimed |

The core matrix uses AAC, AVC, HEVC and multiplexed audio/video; two encrypted
MP4 producers cover the four schemes, and FFmpeg adds progressive CENC.
Core exact passes also match decoded video/PCM hashes. Streaming tests cover
clear lead, detached complete/last fragments, and two-key rotation; those use
exact encoded samples and iori byte/layout checks without a secondary decode
hash assertion. Iori passes the conforming Shaka CENS audio and rotation cases.

Known deviations and tool-unsupported outcomes are separate from exact passes,
with version-bound predicates, original files and command logs retained.
No source file is silently repaired to make a differential comparison pass.

The coverage catalogue has 75 families: 56 have partial witnesses, 19 remain
unimplemented, and none is marked normatively complete. Several case mappings
can refer to one executable test; catalogue counts are not test execution counts.
Items, complete multi-key auxiliary formats, corpus-wide IV uniqueness, and
codec/Annex eligibility still need implementation or normative verification.

Reproduce with the README commands. A run's `report.json` and `junit.xml` are the
source of truth for its actual counts; this baseline does not imply that tools
missing from a later environment ran successfully.
