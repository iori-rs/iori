# Source and interpretation register

These are review questions, not amendments to ISO/IEC 23001-7:2023. Verify
them against a complete, authoritative copy before encoding strict verdicts.
Do not interpret an apparent editorial problem as permission to choose the
behavior of an existing tool. A resolution records the source locator,
decision, rationale, reviewer, affected case IDs and date.

| ID | Question | Suite treatment until resolved |
| --- | --- | --- |
| SRC-01 | Available working PDF ends during Annex A.1; subsequent normative tables are unavailable. Some extracted scope text is absent. | Proceed with knowledge-derived vectors and property tests; keep exact eligibility-table coverage unverified until source review. |
| INT-01 | Protected-only record wording in 7.2.1 appears internally inconsistent. | Preserve both readings as candidate expectations for senc version/count cases; no strict pass claim. |
| INT-02 | Zero-entry senc handling needs reconciliation between 7.2.1 and 7.2.3. | Distinguish absent records, empty box and malformed sample-count mismatch; review by version. |
| INT-03 | Item auxiliary box presence wording in 8.4 needs reconciliation with implicit auxiliary information. | Keep explicit/implicit item cases and annotate applicability rather than forcing every item to carry iaux. |
| INT-04 | CENS references to whole-block behavior and IV wording across 9.7 and 10.3 need a documented reading. | Audit algorithm geometry and scheme IV restrictions separately; do not inherit unrelated IV rules through a cross-reference. |
| INT-05 | Some pattern references appear to target the extractor subsection rather than 9.6. | Retain the original locator and separately record any corrected semantic target after source review. |

## Existing-test classification work

The following must be reviewed during implementation, before marking fixtures
normative-valid. Their current permissive behavior may remain valuable.

- Exact subsample coverage versus clear bytes left undescribed by the table.
- Primitive partial-tail handling versus scheme-specific protected-range
  alignment requirements.
- Generic IV length acceptance versus the IV requirements of a selected scheme.
- Zero patterns for different media categories.
- Synthetic tenc/seig versions versus all newly introduced 2023 formats.
- Unsupported-feature rejection versus positive support for items, multi-key
  samples and sensitive encryption.
- Legacy senc override semantics versus normative versions and flags.
- Tool-produced ciphertext versus independently validated conforming input.

No production behavior is changed by this design. A future implementation
change needs a valid witness, the applicable requirement, and a regression;
specification-invalid but tolerated fixtures remain in the compatibility lane.
