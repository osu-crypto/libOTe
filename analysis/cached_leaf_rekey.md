# Cached-leaf rekeying

Implemented on 2026-09-07 in `CachedDpfExpansion.h`. This changes reusable
leaf conversion for Rev-Cuckoo, Waterfall, and Waterfall's cached value scatter.
Internal tree expansion and the immediate-payload SparseDPF API are unchanged.

## Schedule

Both parties already know the same public seed from setup. The root helper
derives separate roots for Rev-Cuckoo (purpose 0), Waterfall columns (purpose 1),
and Waterfall scatter (purpose 2). It evaluates AES under the setup seed at
`block(purpose, 0x4450464c524f4f54)`. No new communication is required.

For one expansion call, let `R` be the current root and `j` the zero-based
leaf ordinal after flattening the public rows in their stored order.
The conversion key is
`AES_R(block(j / 1024, 0x4450464c43484e4b))`, using integer division.
The leaf mask remains `AES_key(seed) XOR seed`, followed by the coefficient
conversion and the party's sign. The next call's root is
`AES_R(block(0, 0x4450464c4e455854))`.

Each chunk covers at most 1,024 leaves, continuing across short or empty rows.
The last chunk can be partial. An empty call advances the root without using
a chunk key. Within one call, distinct chunk keys and the next root are
distinct because their inputs to the same AES permutation are distinct.
This does not establish independence across calls or setups.

The public order is shared by both parties; matching off-path seeds therefore
receive the same key. Internal-node recomputation order does not enter this
schedule. The stored roots and output shares change relative to older builds;
both peers must update together. The API and message sizes are unchanged.

## Execution and scope

AES key setup stays outside the existing eight-lane inner loops. The AES
chains now use `hashBlocks<8>` before the unrolled coefficient conversion.
No per-leaf key selection, extra heap allocation, or threading is introduced.
A non-inlined, non-coroutine helper owns the AES schedules. Waterfall scatter uses the
same helper, removing its duplicate conversion loop and coroutine-local AES.

For L cached leaves, the change adds ceil(L / 1024) AES encryptions and key
expansions to the previous per-call work. Setup also derives the purpose roots
locally. There are no added OTs, payload bits, or protocol rounds.

Rekeying limits repeated leaf evaluations under a chunk key. It does not
repair collisions or leakage during tree setup and does not prove the
custom dense generator or the reusable leaf evaluator secure.

## Validation

All 18 focused WSL/GCC tests passed after the final batching change, both
with defaults and with `-domain 1024` to cross chunk boundaries in the
Rev-Cuckoo end-to-end fixture. No native MSVC validation was run in this pass.

`CachedDpf_LeafRekey_Test` compares both parties' output values and row sums
against an independent scalar schedule. It covers three calls, empty rows,
1,023/1,024/1,025-leaf boundaries, cross-row boundaries, and partial SIMD batches.
It exercises integer, GF(2^128), and four-word array coefficient contexts.
The end-to-end tests also check setup-root agreement and purpose separation.

Run correctness tests with `analysis/run_sparse_dpf_mask_tests.sh` under WSL.
Run the sequential kernel comparison with
`analysis/run_cached_leaf_rekey_benchmark.sh`; never overlap benchmarks.
The benchmark contains the pre-rekey kernel from commit
`b2e9b7b5c5ab60adf800ba56b087c0d1b4330812` as its baseline.
It measures cached conversion only, not complete DMPF expansion or networking.

Local sequential measurements used WSL Ubuntu 24.04, GCC with the configured
`-O2` AES-NI/AVX2 flags, and an Intel i7-13700H. Each entry is a median of
20 samples after four warmups, alternating old/new execution order.
Large profiles use N = 2^20 and 64/320 near-equal rows; scatter profiles
use 16 rows of 64/320 leaves. Values are unsigned 64-bit integers.
These are synthetic row shapes, not sampled placements or end-to-end timings.
The baseline uses the old common leaf kernel, including for the scatter shapes;
it does not reproduce the old separate Waterfall scatter loop.

| Shape | Party | Old ns/leaf | New ns/leaf | Change |
| --- | ---: | ---: | ---: | ---: |
| 4N | 0 | 3.8932 | 3.4866 | -10.44% |
| 4N | 1 | 5.0286 | 3.2575 | -35.22% |
| 3N | 0 | 3.5399 | 3.3051 | -6.63% |
| 3N | 1 | 4.9345 | 3.3760 | -31.58% |
| scatter64 | 0 | 3.5082 | 3.2299 | -7.93% |
| scatter64 | 1 | 4.7146 | 3.2542 | -30.98% |
| scatter320 | 0 | 3.4381 | 3.0830 | -10.33% |
| scatter320 | 1 | 4.4264 | 2.9233 | -33.96% |

An initial chunk-only change was slower on the sign-negating path. Explicit
eight-block AES batching removed that regression. The table compares the
combined rekeying/batching change against the old kernel; it does not isolate
the cost of rekeying alone. CPU frequency and scheduling varied between local
runs, so use these results as a regression check, not a portable speed claim.

Next paper pass: describe the public leaf ordinal as part of the concrete
leaf-evaluator context, alongside the expansion call and purpose. The ideal
functionality does not change. Internal-node rekeying remains deferred.
