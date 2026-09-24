# DMPF package compatibility and release scope

This research package includes reusable Waterfall and Reverse-Cuckoo DMPFs.
It is not a claim of production security for every caller or parameter set.

## Upgrade both parties together

Reverse-Cuckoo setup now uses two serial privately controlled Waksman passes,
with an independently sampled uniform permutation for each set and party.
The composed permutation is retained across expansions. Setup also exchanges
independent seed contributions for every (set, partition), rather than
reusing each partition evaluator across the batch. This changes the setup
wire format and permutation preprocessing; upgrade both peers and rerun setup.
The seed exchange sends `16 * (1 + numSets * numPartitions)` bytes per party,
including the separate DPF root. Sparse-set construction streams one evaluator
at a time and retains the batched inner-product kernel. Repeated expansion
still uses the cached leaf seeds, but the shuffle now has two serial passes.
Historical timings do not measure these changes.

The sparse-DPF setup protocol now masks inactive levels and omits the
selected correction's low bit. The masking step changes the OT reservation
and consumption schedule. Recompute reservations through `baseOtCount()`;
do not reuse hard-coded counts or old preprocessing.

The correction encoding and AES schedules also change. Both peers must use
the same revision. Discard old cached DPF state and rerun setup; mixing peers
or cached state from different revisions is unsupported.

`RegularDpfKey` serialization now stores an additional 16-byte public tree
seed. Old serialized keys are incompatible. There is no format negotiation
or migration reader; regenerate keys using the new implementation. Applications
that persist keys should version their own containing format.

Standalone tree generation without a supplied public seed exchanges one
16-byte contribution in each direction. The DMPF wrappers derive their tree
seeds from existing setup coins, so this adds no DMPF messages or OTs.
Leaf expansion advances a public root deterministically and rekeys every
1,024 leaf positions. Internal-node schedules also limit a key to 1,024
distinct parent positions. These schedules are hardening, not a proof of
the inherited AES evaluator.

## Security and parameter boundaries

- Waterfall's generic simulation argument uses ideal subprotocols; the
  concrete AES realization has separate, explicitly conjectured requirements.
- `compact4N()` and `compact3N()` are profiles for 16 input rows, not generic
  parameter generators. Other sizes require their own routing-error analysis.
- Reverse Cuckoo leaks support information and requires the stated
  application-specific assumption. Do not use it as a generic private DMPF.
- Ring-LPN setup filters the analyzed Goldilocks profile: ring degree 2^20,
  four polynomials, and weight 16. Each party resamples its complete support
  tuple until at least 61 residues modulo 128 are occupied, counting each
  polynomial separately. The filter applies to both DMPF backends and both
  OLE/triple output modes, based on the rounded ring degree. Other fields,
  degrees, and noise dimensions retain unfiltered sampling; they have no
  security claim from this profile. Accepted supports persist across reuse.
- A complete application-level OLE simulation/composition argument remains
  separate from the DMPF proof. Historical timing tables predate the full
  set of mask, filtering, and AES changes; they are not current-release
  benchmarks.
- Ring-LPN tensor sampling retains uniform field coefficients, including
  zero, matching the paper's revised assumption. Correctness supports zero
  payloads; no zero rejection is required. Relative to independent nonzero sampling, the
  ideal uniform-field distributions differ by at most `2 * P * t * Q / q`
  over `Q` expansions. For the analyzed Goldilocks profile this is about
  `Q * 2^-57`; this accounting is separate from primitive-security losses.

## Validation

Release follow-up fixes the Silent OT/VOLE PPRF buffer sizing and gates the
GCC 13–16 ASan stack workaround. CI then passed the previously failing
`AnyField_F2Ole_Test`, but exposed a separate KOS-Dot scratch-alignment bug.
The transpose helper now uses 32-byte-aligned arrays in a non-inlined,
non-coroutine function. It adds no heap allocation or protocol change.
`DotExt_Kos_Check_Test` also checks the transpose against a scalar reference
for empty, partial, and full chunks, and rejects oversized chunks.
All five focused KOS-Dot tests pass with the test and protocol translation
units built under GCC 13 ASan with stack checks disabled. This focused runner
links existing non-ASan dependency archives; it does not replace full CI.
Cross-platform validation of this follow-up is still pending; earlier failed
Ubuntu runs skipped the source-tree and installed-consumer checks.

The exact-permutation/per-list-seed update passes the 24-suite focused WSL/GCC
runner at defaults and at domain 4097 with 16 points, three sets, four
expansions, and either two or three partitions. The registered sparse-set
regression checks per-instance evaluator indexing against scalar hashing,
including empty and fully loaded buckets. The four-suite Ring-LPN runner
passes with `-trials 2` (support filter, audit, stationary reuse, and OLE).
Seven Python hash-conditioning checks pass. These are local regression tests,
not new benchmarks or a completed cross-platform CI run.

The registered unit tests include the correction-encoding and inactive-level
regressions, both rekeying schedules, and Waterfall/Reverse-Cuckoo integration.
Enable `ENABLE_SPARSE_DPF`, or use the existing `ENABLE_ALL_OT` CI configuration.
The focused WSL runner is `bash analysis/run_sparse_dpf_mask_tests.sh` after
configuring a compatible Ninja build; `SPARSE_DPF_BUILD` selects its directory.

The exact hash-conditioning checks use only the Python standard library:

```sh
python -m unittest analysis.test_rev_cuckoo_hash_conditioning
```

Do not run two benchmarks concurrently. Record the tested commit, build
configuration, hardware, and raw output when refreshing performance results.
