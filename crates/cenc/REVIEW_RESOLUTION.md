# PR #54 review resolution

This records the corrections to the review of commit `5458656`, including
inconsistencies found while implementing and testing those corrections. Each
row is implemented and has regression coverage. GitHub issues remain open
until the implementation is merged.

All decryption and metadata cleanup preserves input length, box order, and
downstream offsets. Encryption metadata is replaced in place with `free`
boxes; unrelated sample groups and auxiliary metadata are retained.

| Issue | Correction | Regression coverage |
| --- | --- | --- |
| [#64](https://github.com/iori-rs/iori/issues/64) | Restart CENS patterns per protected subsample; preserve the CTR counter | `spec_conformance::cens_ctr_pattern_restarts_across_subsamples_without_keystream_for_skips` |
| [#65](https://github.com/iori-rs/iori/issues/65) | Keep CENS partial blocks clear, without consuming counter values | `spec_conformance::cens_partial_blocks_stay_clear_without_consuming_counter` |
| [#66](https://github.com/iori-rs/iori/issues/66) | Decode the reserved byte before the seig pattern byte; correct builders | `boxes::seig_standard_bytes_preserve_pattern_and_default_index` |
| [#67](https://github.com/iori-rs/iori/issues/67) | Resolve signed offsets from effective bases and continue runs/trafs; reject sample addresses outside mdat in both container paths | Fragment layout tests and `nonfragmented_layouts::sample_tables_cannot_point_at_box_headers` |
| [#68](https://github.com/iori-rs/iori/issues/68) | Apply per-sample protection overrides to clear track defaults, including separate init segments | Clear-default tests in `fragment_layouts` and `nonfragmented_layouts` |
| [#69](https://github.com/iori-rs/iori/issues/69) | Inherit trex sample sizes and description indices | `fragment_layouts::constant_iv_without_auxiliary_tables_and_trex_sizes`, `trex_selects_second_encryption_sample_description` |
| [#70](https://github.com/iori-rs/iori/issues/70) | Resolve track and fragment group namespaces separately | `fragment_layouts::fragment_groups_resolve_track_and_local_namespaces_separately` and track-only group test |
| [#71](https://github.com/iori-rs/iori/issues/71) | Apply SGPD defaults without explicit sample assignments or SBGP | `boxes::seig_namespaces_and_unassigned_defaults_stay_distinct` and both container layout suites |
| [#72](https://github.com/iori-rs/iori/issues/72) | Accept constant-IV full-sample protection without per-sample metadata | Constant-IV tests in both container layout suites |
| [#73](https://github.com/iori-rs/iori/issues/73) | Read nonfragmented auxiliary records using absolute offsets and per-chunk tables | `nonfragmented_layouts::absolute_auxiliary_offset_supplies_per_sample_iv_without_senc`, `non_fmp4::auxiliary_offsets_are_absolute_and_follow_chunks` |
| [#74](https://github.com/iori-rs/iori/issues/74) | Reset CBCS chaining by scheme, including 0:0 patterns | `spec_conformance::cbcs_zero_pattern_resets_chain_even_when_pattern_was_normalized_away` |
| [#75](https://github.com/iori-rs/iori/issues/75) | Selectively clean encryption metadata in traf and stbl, preserving unrelated bytes and all boundaries | `cleanup::cleanup_preserves_unrelated_metadata_and_every_box_boundary` |
| [#76](https://github.com/iori-rs/iori/issues/76) | Read SGPD version-2 default_length and honor individual description lengths | `boxes::sgpd_variable_description_lengths_bound_each_entry` and version-2 tests |
| [#77](https://github.com/iori-rs/iori/issues/77) | Pair auxiliary streams by type/parameter; reject invalid records without valid senc fallback; accept empty constant-IV records | `boxes::auxiliary_pair_selection_keeps_stream_identifiers_together`, malformed auxiliary fragment test, zero-length record tests |
| [#78](https://github.com/iori-rs/iori/issues/78) | Validate 8- or 16-byte constant IVs consistently | `boxes::constant_iv_sizes_must_be_eight_or_sixteen_bytes` |
| [#79](https://github.com/iori-rs/iori/issues/79) | Explicitly reconcile legacy Bento4 CENS audio tail behavior with whole-block encryption | `common::assert_bento4_decryption`, used by the matrix and checked-in fixture tests |
| [#80](https://github.com/iori-rs/iori/issues/80) | Remove tenc reserved-byte heuristics and correct synthetic builders | `boxes::tenc_reserved_byte_is_present_for_clear_and_constant_iv_defaults` |

## Validation and limits

Run `cargo test -p iori-cenc`, `cargo fmt -p iori-cenc --check`, and
`cargo clippy -p iori-cenc --all-targets -- -D warnings`.
The suite contains 44 library tests and 40 integration test entry points.
The local generated matrix contains 24 audio/video/container combinations.
The Bento4 differential can be enabled with `BENTO4_MP4DECRYPT`; the Shaka
differential requires `SHAKA_PACKAGER` and otherwise returns without running
an external comparison.

The legacy Bento4 CENS audio fixtures encrypt partial tails. The fixture tests
check all other bytes against the oracle, verify those precise tails remain
unchanged, then check complete plaintext using a copy with corrected clear
tails. See [fixture provenance and rationale](tests/fixtures/matrix/README.md).

These tests establish regression coverage for the tracked corrections; they
are not a claim of complete ISO/IEC 23001-7:2023 certification. Existing legacy
senc algorithm-override handling remains covered by its dedicated tests.
