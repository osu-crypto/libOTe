# Regular-noise Silent OT

The isolated regular-noise sender produces **89.05 million hashed OTs/s** at
K=2^18 with VAES and streaming output stores. It reuses the full precomputed
SPIN code: there is no heuristic permutation bank or per-batch code refresh.
The matched stationary rerun gives 84.47 million OTs/s.

## Timing contract

These are local sender computation times, not two-party network throughput.
Both noise modes start each batch with fresh base correlations already supplied.
Code setup, workspace/output allocation, base-correlation generation, transcript
draining, and network transport are outside timing. The timed interval contains
production `silentSendInplace` and `hash`: PPRF expansion, sums and padding,
SPIN compression, hashing both sender messages, and routine allocation and local
message enqueueing within those calls. Output consumption is timed only in the
explicit scan control below.

Regular noise expands the PPRF trees each batch. It does not cache leaf seeds.
The SPIN map, workspace, code seed, and descriptor remain unchanged between calls.
The configuration is semi-honest Silent OT, packed choices, MultType::Spin,
T128S19 with weight-five feedback, and SetupMode::Full.

| K | Input length N | Partitions | Leaves/tree | Fresh base OTs/batch | Padding |
|---|---:|---:|---:|---:|---:|
| 2^18 | 524288 | 128 | 4096 | 1536 | 0 |
| 2^20 | 2097152 | 128 | 16384 | 1792 | 0 |

Stationary K=2^18 instead has 312 trees of 1680 leaves, 128 padded coordinates,
about 8 MiB of cached leaf seeds, and 312 fresh base-VOLE correlations per batch.
It also includes the heuristic code refresh. Since generating these different
base-correlation inputs is excluded, the comparison does not establish which
complete protocol has lower total cost.

## Measurements

Ryzen 9 7950X, CPU 15, fixed requested 4.5 GHz, boost disabled. libOTe and
cryptoTools use GCC 13.4 Release with VAES; SPIN uses the same GCC 15.2 Zen 4
archive as the stationary campaign, with runtime-dispatched AVX-512 BCH kernels.
Each cell is the median of three process medians, each with five warmups and
101 timed batches. Store/read mode order reverses on the second repeat.
Every benchmark runs serially with all three shared locks held.

| Mode | Expansion ms | Compression ms | Hash ms | Total ms | Million OTs/s |
|---|---:|---:|---:|---:|---:|
| Regular K=2^18, cached stores | 1.034712 | 1.625526 | 0.405968 | 3.065705 | 85.51 |
| Regular K=2^18, streaming stores | 1.033269 | 1.481877 | 0.427648 | 2.943876 | 89.05 |
| Stationary K=2^18, cached stores | 0.946297 | 2.192504 | 0.426506 | 3.565437 | 73.52 |
| Stationary K=2^18, streaming stores | 0.919196 | 1.751430 | 0.427608 | 3.103495 | 84.47 |
| Regular K=2^20, cached stores | 4.102029 | 11.378306 | 2.012507 | 17.494576 | 59.94 |
| Regular K=2^20, streaming stores | 4.092581 | 11.351225 | 1.727856 | 17.185599 | 61.01 |

Stage medians need not sum to total medians. The regular K=2^18 streaming totals
are 2.975996, 2.943876, and 2.938326 ms across processes; K=2^20 totals are
17.224522, 17.185599, and 17.178356 ms. The stationary repeat reproduces the
paper's approximately 84.5-million-OT/s result.

The regular path spends slightly longer on expansion but less on compression
at K=2^18. This comparison changes tree geometry, resident memory, and routing
mode together; it does not isolate a single cause for the compression difference.
The K=2^20 integrated compression is about 11.35 ms, not the paper's 9.29 ms
standalone optimized-research encoder measurement. No encoder-only substitution
or matched speedup over the historical 47-million-OT/s run is claimed.

### Immediate sequential output read

This control scans every output byte after hashing. The total includes the scan
and its effect on the next batch's cache state, not a downstream protocol.

| Regular batch size | Cached total ms | Streaming total ms | Streaming million OTs/s |
|---|---:|---:|---:|
| K=2^18 | 3.420687 | 3.171221 | 82.66 |
| K=2^20 | 18.428109 | 17.971146 | 58.35 |

Streaming stores remain opt-in; no production default is changed by this benchmark.

## Correctness and reproduction

Each isolated run checks a complete two-party hashed-OT batch before releasing
the receiver's state. Separate paired runs verify every OT across five measured
batches and five warmups: regular K=2^18 with both store policies, regular K=2^20
with streaming stores, and stationary K=2^18 with streaming stores.
The regular runs verify fixed-code reuse; stationary runs verify cached-leaf reuse
and synchronized code refresh. SpinIntegration and SpinOptions pass in the same build.

```sh
cmake --build BUILD --target spin_stationary_bench
bash libOTe_Tests/run_spin_store_bench.sh \
  BUILD/libOTe_Tests/spin_stationary_bench RESULTS/k18 18 101 regular
bash libOTe_Tests/run_spin_store_bench.sh \
  BUILD/libOTe_Tests/spin_stationary_bench RESULTS/stationary-k18 18 101
bash libOTe_Tests/run_spin_store_bench.sh \
  BUILD/libOTe_Tests/spin_stationary_bench RESULTS/k20 20 101 regular
python3 libOTe_Tests/summarize_spin_noise_bench.py RESULTS
```

The shared executable keeps its historical name. `regular` changes the noise
model and setup mode, and records both explicitly in the output. The summarizer
checks geometry, lifecycle flags, sample counts, medians, and throughput arithmetic.
No raw samples are committed. Retained results are under
`/tmp/libote-spin-ssd-pq75QW/results/regular-20260923` on the measurement host.

| Measured snapshot item | SHA-256 |
|---|---|
| SpinStationaryBench.cpp | 47823a52f1c491e542ebbce525c611d3c6dee71afd9bdfd7d2d99e76c6e4ee61 |
| Summarizer | 7a883140ecb7b77db4c2818224d4cabbce0508b90dfeaaa5261cc7e4eb696199 |
| Benchmark executable | 589c2f646aaa3c64847c907563ebcc2530ab30340a97733695ae0f96aa693c09 |
| SPIN archive | ecbebbfa16d15b4b5460c8811053720d1dd534f2aa81ea5b82757bebd153f0d7 |

`summary.json` retains the SHA-256 of every raw run. The paper now leads with
the regular-noise result and keeps the stationary heuristic variant as a
separate operating mode.
