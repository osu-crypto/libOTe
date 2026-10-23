# Sparse-DPF correction encoding

2026-09-07. Approved fix in `codex/dmpf-package`, following the activity-mask
fix. This is a separate setup-privacy issue (AUD-213).

## Disclosure and repair

Previously the sparse correction opened the full selected child sum sigma
and the two tag corrections. For reconstructed address bit a and child sums
z0,z1, the opening satisfied

```text
sigma = z[1-a]
tau0 = lsb(z0) xor a xor 1
tau1 = lsb(z1) xor a.
```

If tau0 differs from tau1, comparing lsb(sigma) against the two tags reveals
a. This occurs with probability 1/2 for independent uniform child sums,
including directly sampled roots under the ideal-randomness model. The
activity masks do not remove that algebraic relation.

`SparseDpf::reveal(sigma,tau,...)` now clears the low bit of every local
sigma share before copying it into the send buffer. It also clears the
reconstructed low bit. The transmitted block contains a 127-bit prefix
and a constant zero bit; both tag corrections are sent separately.
No selected low bit is opened.

Corrected tree seeds use the packed representation from the paper:

```text
CW[j] = prefix | block(0,tau[j])
correctedSeed = rawChild xor (parentTag * CW[j]).
```

The logical tag is the low bit of this corrected seed. `correctSeed` is a
small inline helper used in both the eight-node kernel and scalar tail.
The dense-to-sparse boundary likewise packs the separately supplied logical
tag into the seed's low bit. This does not resolve the separate distribution
question about the dense evaluator's exported value.

## Cached and immediate-payload outputs

Cached output now contains only the corrected 127-bit prefix, represented
by a block with low bit zero, plus a separate logical tag. Waterfall and
Reverse-Cuckoo already hash cached blocks into full-width values for each
expansion. Their loops, AES call counts, and OT consumption are unchanged.

The immediate-payload sparse API cannot use a zero-low-bit prefix directly
as a 128-bit mask: its opening would expose the payload's low bit. It now
converts the prefix with `AES_k(prefix) xor prefix`, under a dedicated public
leaf key distinct from the tree key, before forming the payload correction.
This adds one AES call per output leaf only for the immediate-payload API.
Its concrete security is part of the remaining ideal-cipher instantiation
argument, not a new claim that correctness tests prove privacy.

Singleton cached outputs now use the direct-output path, without accessing
unallocated immediate-payload buffers. Singleton and dense-direct leaves
follow the same prefix/output conventions.

## Cost, compatibility, and scope

- No additional OT, message round, or wire byte is required by this fix.
- No extra AES call is added to cached setup or repeated expansion.
- The batched tree kernel keeps its eight-node organization.
- Both peers must use the revised encoding for a new setup. Message lengths
  alone do not distinguish old and new implementations.
- The custom dense generator, its final single-round transform, and the
  public round-key schedule for reusable leaves are unchanged.
- No performance benchmark or MSVC build was run for this change.

## Tests

`SparseDpf_CorrectionEncoding_Test` inspects actual outgoing socket bytes,
checks both local-party choices, and exhaustively compares the opening laws
for two-bit child blocks. It also checks the packed correction helper.

`SparseDpf_InactiveLevel_Test` now checks the exact AES inputs/outputs in
one-, eight-, and thirteen-node kernels, zero-low-bit cached prefixes,
singleton/two-point/uneven supports, every supported active index, dense
depths 0/1/2/6, immediate payloads, cached seeds, and unchanged OT counts.

Run the focused multiplication, sparse-DPF, Waterfall, and Reverse-Cuckoo
suite with `bash analysis/run_sparse_dpf_mask_tests.sh` in WSL. The paper's
`experiments/test_sparse_dpf_correction_encoding.py` retains the historical
disclosure equations and checks the corrected abstract encoding independently.

Validation: all 17 focused WSL/GCC tests passed, including the expanded
singleton/two-point cases. All nine exact Python encoding tests passed.
`git diff --check` reported no whitespace errors.
