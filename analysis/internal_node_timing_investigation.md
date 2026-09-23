# Internal rekeying: investigation of expansion timings

2026-09-07. The earlier separate-executable measurements reported a 3--7%
Waterfall 3N slowdown and roughly 5% Rev-Cuckoo slowdown after internal-node
rekeying. Internal-node expansion runs during setup, not reusable expansion.
The question was whether those timings reflected a new online cost.

## Conclusion

The earlier slowdown does not reproduce under tighter controls. The same
frozen binaries, pinned to WSL CPU 0 and warmed up before comparison, reverse
the sign of the measured difference. A separate one-executable experiment
leaves a 1--2% difference, within the scale of observed run variation.
These results do not establish exact zero overhead or a speedup. They do
not support treating the earlier 5--7% figures as an intrinsic rekeying cost.

Execution conditions are the leading explanation. CPU scheduling/frequency,
memory placement, and executable layout have not been isolated individually.
WSL affinity constrains a guest CPU; it does not lock a physical core or its
frequency. No hardware-counter diagnosis was performed.

No production C++ or protocol changes were made in this investigation.

## 1. Instruction comparison

Both cached-leaf kernel instantiations in the frozen binaries have identical
instruction sequences after normalizing addresses and RIP-relative offsets.
Their instruction counts are 833 and 834. The surrounding coroutine code
has changed object offsets and executable placement. Thus this comparison
establishes unchanged leaf arithmetic, not an identical complete executable.

## 2. One executable, selectable setup generator

`internal_node_probe.cpp` substitutes a diagnostic tree-hash adapter before
including the production DPF headers. It selects either the previous fixed
AES key or the new counter schedule during setup. Both modes retain the new
object layout, public seed plumbing, and sparse chunk traversal. This is a
controlled generator comparison, not a reconstruction of the old setup binary.
Both modes call the same online code, with deterministic fixture coins and
indices. Their cached seed values differ, as expected.

The fixture uses t=16, N=2^20, one set, additive u64 values, and preloaded
correlated OTs. Both parties run serially over LocalAsyncSocket. Each profile
first warms up one setup in each mode, then runs ABBA and BAAB. Each setup
performs four warmup expansions and 24 measured expansions. Every full output
is checked outside the timer. No benchmarks overlap.

Existing timer points separate local leaf conversion and local update/scatter
work. These intervals contain no suspension. Their two-party durations are
summed; the residual is total time minus those durations, not a sum of waiting
times. Rev-Cuckoo's leaf interval also includes small payload preparation.
Waterfall's residual includes its small value-scatter DPF.

The following values are means of four per-setup medians, in milliseconds.
Stage medians need not sum to the total median.

| Profile | Fixed total | Rekeyed total | Difference | Fixed / rekeyed leaves | Fixed / rekeyed update |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rev-Cuckoo 3N | 28.085 | 28.541 | +1.63% | 10.472 / 10.637 | 17.188 / 17.562 |
| Waterfall 3N | 35.055 | 35.672 | +1.76% | 10.552 / 10.931 | 24.186 / 24.387 |
| Waterfall 4N | 44.700 | 45.163 | +1.04% | 14.119 / 14.121 | 30.559 / 30.626 |

Correction/scatter accounts for roughly 60--70% of expansion time. There is
no large new leaf-conversion cost in this experiment. The residual 1--2%
differences are not proved to be noise, but are smaller than run-to-run
variation. Raw results, including the excluded warmups, are in
`internal_node_probe_stages.csv`.

## 3. Frozen executables with CPU affinity

`run_internal_node_affinity.sh` reruns the original binaries with `taskset
-c 0`. It warms up each binary once, then runs ABBA and BAAB. Each process
retains the original three warmup expansions and fifteen measured expansions.
The following values are means of four per-process medians.

| Profile | Before (ms) | After (ms) | Difference |
| --- | ---: | ---: | ---: |
| Rev-Cuckoo 3N | 26.669 | 26.096 | -2.15% |
| Waterfall 3N | 35.916 | 35.406 | -1.42% |
| Waterfall 4N | 48.501 | 46.109 | -4.93% |

These are not claimed speedups. The reversal shows that the earlier slowdown
is not stable across benchmark conditions. Affinity and warmup were changed
together, and measurements occurred later; the experiment cannot attribute
the reversal solely to affinity. Communication and output correctness remain
unchanged. Raw results are in `internal_node_probe_affinity.csv`.

## 4. Identical-cache replay

The separate `layout` invocation copies one real Rev-Cuckoo cache into the
same allocated buffer at offsets 0, 64, 512, and 2048 bytes from a page-aligned
base. It keeps the output buffers fixed and resets the leaf PRG root for every
call. It alternates forward/reverse offset order for 32 repetitions, excluding
the first four. Copying and exact output comparisons are outside the timer.

Median leaf conversion times were 5.240, 5.164, 5.326, and 5.280 ms: a 3.15%
spread. All 128 replay outputs matched exactly. This demonstrates measured
sensitivity at the few-percent scale; it does not identify the original
allocation pattern as the cause, or isolate layout from all timer variation.
It measures one party's leaf conversion, not full expansion or update/scatter.
Raw results are in `internal_node_probe_layout.csv`.

## Reproduction and scope

Environment: WSL Ubuntu 24.04, GCC 13.3.0, configured `-O2`, AES-NI/AVX2,
Intel Core i7-13700H as reported by the guest. No real network latency or OT
preprocessing is included. The final stage suite checks 840 full expansions;
the affinity suite checks 540; the final layout invocation checks another
28 full expansions and 128 identical-cache replays. An earlier exploratory
stage/layout run preceded these recorded suites and is not used in the tables.

Binary SHA256 identifiers:

- Frozen before: `26fd9267e5ec491bf4a03b37cd932ffe1d1cf9835c2c93b112664e6cd931f112`.
- Frozen after: `aa8de0a79f6a63659e7a41f46b1bb56272b78ca00c1179491e7fd4849126700e`.
- Diagnostic: `5501b7b6129c87047cc4d783135fb2dd1697c73eac1eb23f977ae00a9b361d9c`.

Recommendation: retain internal rekeying and use affinity, explicit warmup,
and stage timings in future benchmarks. Return to the paper's concrete AES
description; do not change its performance claims based on these small local
timing differences. A precise microarchitectural attribution would require
further controlled hardware-counter measurements.
