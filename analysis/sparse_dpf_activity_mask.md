# Sparse-DPF activity masking

2026-09-07. Implementation fix in the isolated `codex/dmpf-package` worktree.

## Discrepancy and correction

A public sparse tree may split at a level after its secret active path has
already reached a leaf. Every parent at that level is then off-path. The
parties expand equal corrected seeds, so both reconstructed child sums vanish.

Previously, `SparseDpf` masked only publicly empty levels. A publicly present
but inactive level therefore revealed a deterministic correction. For public
support `{0,1,4}` and active address `4`, the split of `{0,1}` exposed raw
sigma zero and tag corrections `(1,0)`.

The implementation now separates two fields:

- `mHasSplit`: a public scheduling flag. A level can be skipped only when
  no instance in the batch has a public split there.
- `mActivity`: a local XOR share of the tags of parents splitting at the
  level. Tags are taken after the parent's correction, before its children
  expand. Each parent contributes once, including at the dense/sparse boundary.

For each scheduled level, the parties compute
`[z] := [z] xor (1 xor [v]) * [r]`, where `v` is reconstructed activity and
`r` comprises two independently sampled 128-bit blocks. The multiplication
treats the two blocks as one 256-bit string. The activity bit is never opened
and does not control local branching or message lengths.

If `v=1`, the reconstructed child sums are unchanged. If `v=0`, they become
random masks. Both parties still apply the same correction to every off-path
parent with equal tags, so their corrected seeds remain equal. This implements
the paper's mask; it does not establish the separate concrete AES-generator
requirements from the reusable-DPF theorem.

## Cost and compatibility

Let `D=ceil(log2(domain))`, let `d` be the clamped dense-prefix depth, and let
`n` be the number of parallel sparse-DPF instances. The reserved random-OT
count **per direction** changes from `Dn` to `(d + 2(D-d))n`.
Each scheduled sparse level consumes `n` OTs per direction for masking and
`n` per direction for the existing correction selection. Entirely unused
public levels consume neither operation.

Thus the added operation costs two OTs total per instance and scheduled
sparse level, with 256-bit string payloads. It does not require four OTs for
the two child blocks. The current bit-times-string primitive sends one packed
choice-difference bit and one 256-bit correction per direction per row,
plus byte padding and socket framing. The tree's eight-node expansion kernel
is unchanged except for XOR accumulation of corrected tags. Mask buffers are
allocated once per setup and reused across levels; fully dense calls allocate
no mask rows. Cached expansion is unchanged.

Both peers must use the new provisioning count and message schedule. Do not
mix old and new peers or reuse a previously sized OT slice. Callers obtain
the new counts through `baseOtCount()`; dense and sparse slices are still
assigned by `setBaseOts()`.

The masking call uses the existing generic bit-times-string multiplication.
Its AES schedule and SIMD masks now have explicitly owned aligned storage.
Its OT-swap kernel is a non-inlined, non-coroutine helper with the original
eight-way unrolling. These are storage changes, not arithmetic or wire-format
changes to that primitive. The generic multiplication adds one owned scratch
allocation per call; no per-node tree allocation was introduced.

## Regression coverage

`SparseDpf_InactiveLevel_Test` checks:

- the actual 256-bit MPC mask for every activity-share pair, with 13 rows
  to cover byte packing and the SIMD tail;
- exact reconstruction of both masks at inactive rows and zero masks at
  active rows, using deterministic test coins;
- one OT per direction per row for the masking operation;
- corrected-tag accumulation for 1, 8, and 13 splitting nodes;
- the three-point witness and uneven trees below dense prefixes;
- every supported active index in those examples;
- value-producing and cached-seed output invariants;
- the changed reservation count, including a fully dense configuration;
- consumption of both mask and correction operations at the witness's two
  public split levels.

The focused runner also invokes existing multiplication, sparse-DPF,
Waterfall, and Reverse-Cuckoo integration tests. From a configured WSL build:

```sh
bash analysis/run_sparse_dpf_mask_tests.sh
```

Set `SPARSE_DPF_BUILD` to select another compatible Ninja build directory.
Use `-maskOnly` for the new regression alone. The runner links configured
test objects directly to avoid recreating the large aggregate test archive.
All 16 tests in the focused runner passed under WSL/GCC. The three-point
witness is exercised end to end for reconstruction, cached-leaf invariants,
and the mask/correction OT schedule. The separate MPC-mask test checks exact
mask reconstruction; it does not estimate a statistical distance from sampled
transcripts. No MSVC build or new performance benchmark was run in this pass.
