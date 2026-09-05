# Knowledge-derived test cases

These cases make the design implementable without waiting for the remaining
standard text. They derive from cryptography, binary-format testing and codec
engineering. They are proposed tests, not results. Their mathematical or
engineering properties are explicit; exact Part 7 field eligibility and
ambiguous normative decisions remain separately labeled.

Do not fabricate clause numbers or Annex table entries. For a case whose
expected result depends on an unverified rule, provide a named interpretation
or an explicit externally supplied selection map. Such a test validates the
mechanism under that map, not the correctness of the map itself.

## Concrete vectors and properties

| Case | Construction | Expected observation |
| --- | --- | --- |
| K-01 CTR continuity | Two exact-cover protected ranges separated by clear bytes; independently freeze cipher input/output for each block | Clear bytes consume no selected-byte keystream; output matches the frozen trace |
| K-02 Counter carry | Counter suffix near its arithmetic boundary; three independently computed blocks | Compare each cipher input to the declared counter model; tag the Part 7 wrap policy separately from AES correctness |
| K-03 Pattern state | 1:1, 1:9, 5:5 and boundary patterns; two protected ranges ending at different phases | Verify selected block indexes, range restart and counter consumption independently |
| K-04 CBC chaining | Distinct ciphertext blocks with a skipped block between selected blocks | Trace the previous ciphertext used at each selected block; a wrong skipped-block dependency changes the result |
| K-05 Clear-data independence | Change clear-prefix, skipped-block and clear-tail bytes separately | Protected output remains identical for a fixed selection map; changed clear bytes survive unchanged |
| K-06 Sample reset | Two identical samples using deliberately chosen IVs in an isolated test | Each sample follows its own initial state; no accidental state leak across samples |
| K-07 Every tail | Lengths 16n+r, r=0..15, at zero/one/multiple pattern cycles | Check the declared transform's full-block and tail policy; classify input validity independently |
| K-08 Key discrimination | Recognizable plaintext encrypted under two distinct keys; alternate selection and revisit the first key | Each range recovers its assigned plaintext; using only the first key fails |
| K-09 Missing later key | First sample key exists, later sample key absent | Defined key lookup failure, with mutation behavior checked against the documented API policy |
| K-10 Metadata equivalence | Encode one known sample map as senc and as matching auxiliary records | Same effective samples and plaintext; different file offsets do not affect cryptographic results |
| K-11 Layout equivalence | Reorder legal physical chunks, add free boxes and split equivalent runs; update offsets with an independent writer | Same logical sample sequence and bytes; original layout preserved within each iori output |
| K-12 Buffer windows | Whole-file parse/decrypt and supported init-plus-fragment or base-offset APIs over equivalent data | Same selected sample bytes; exact bounds at the beginning and end of each window |
| K-13 Group boundaries | Run counts 0,1,2; alternate clear/protected descriptions; repeat a KID after another key | No sample-index shift; protection and keys follow the explicit fixture map |
| K-14 Item isolation | Two items with different keys and multiple extents; unrelated item and shared properties | Each item's expected bytes are isolated; wrong association cannot decrypt the other item correctly |
| K-15 XML identity | Equivalent namespace prefixes and whitespace forms where permitted; deliberately different UUIDs | Canonical identity comparison preserves meaning without merging distinct IDs; lexical validity checked separately |

Use fixed vectors as well as generated cases. A round trip with the same
implementation is useful but insufficient: matching encoder/decoder mistakes
can cancel. Anchor AES against published known-answer vectors; keep container
generation and extraction independent of production decrypt jobs.

## Sensitive-encryption mechanism coverage

The incomplete Annex does not prevent testing bit selection, packing,
state management, inverse transformation and parser integration. It prevents
claiming that a provisional selection map contains every required syntax bit.

**Explicit selection-map harness.** Supply a fixture-side ordered list of
eligible bit positions, with syntax element, source byte/bit coordinate and
reason. Keep this map separate from the production parser. Test selected-bit
counts 0,1,7,8,9,127,128,129,255,256,257 and maps crossing byte, field and slice
boundaries. Freeze packed input, generated keystream, transformed selected
bits and reconstructed output. Check every unselected bit. Repeat with
multiple keys using a declared state model; do not guess state-reset rules.

**Codec witness corpus.** Construct small AVC CAVLC, AVC CABAC and HEVC streams
with intra/inter pictures, small/large residuals, positive/negative values,
short/long coded values and multiple slices. Candidate probes can include
coefficient-sign and motion-related syntax, but these are *candidates*, not an
assertion that the Annex selects those fields. Each confirmed eligibility rule
later acquires one activating witness and an adjacent non-activating witness.

**Entropy-parser checks.** Parse the original and encrypted streams with an
independent codec parser. Record field boundaries and coded lengths. For a
map intended to preserve syntax, encryption must leave the encrypted stream
parseable; decryption must recover the exact original compressed bytes.
Code-length-sensitive probes and CABAC context/bypass transitions help expose
unsafe selection maps. Reject a guessed map that breaks parsing rather than
treating the failure as a production-decryptor defect.

**Framing checks.** Exercise RBSP/EBSP conversion, emulation-prevention bytes,
NAL length prefixes, slice termination and HEVC entry-point boundaries.
Store both logical-bit and file-byte coordinates. Any allowed representation
change needs its own explicit rule and comparator. For iori, the in-place
length/offset requirement remains separately enforced.

**State reset probes.** Put identical eligible fields before and after a
slice, sample, key or IV transition. Compare against each explicitly proposed
state model until the normative one is verified. These are interpretation
tests, not multiple contradictory normative expectations.

This produces executable mechanism coverage now. Annex completeness later
requires replacing provisional eligibility maps with reviewed maps and
accounting for every actual table row and condition.

## Verify the test infrastructure itself

The comparator and runner can otherwise make a broken decryptor look correct.

- Renumber tracks and change legal interleaving in a known clear file: sample
  comparison must still pass while whole-file equality differs.
- Drop, duplicate, reorder or flip one sample: comparison must fail at the
  correct logical track/sample and retain the first differing byte.
- Corrupt auxiliary bytes while keeping media intact: metadata validity must
  fail even if a plaintext-only comparison would pass.
- Return unchanged ciphertext from a fake decryptor: the source-sample oracle
  must fail, including for very short clips.
- Supply an empty manifest, missing tool, crashing tool and hanging tool:
  none may produce a successful executed comparison.
- Make a fake oracle disagree in an undeclared byte range: the known-deviation
  mechanism must reject the mismatch.
- Change the generator seed, encoder build or recipe: stale cached artifacts
  must not be reused under the previous identity.
- Break one normative mapping while leaving its tests green: catalogue
  validation must detect the missing requirement link.

## Implementation priority

Implement K-01 through K-13 and the comparator/runner self-tests first, alongside
the real-media matrix. Implement item/XML and sensitive-mechanism fixtures next
even if the product currently rejects those features; report that rejection
as capability evidence rather than support. Refine source mappings in parallel.
No case is blocked merely because its clause locator is pending, provided its
expected property and provenance are explicit.
