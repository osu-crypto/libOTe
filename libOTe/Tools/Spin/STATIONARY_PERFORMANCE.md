# Cached-leaf stationary Silent OT

The latest VAES and opt-in streaming-store results are in
[STREAMING_HASH.md](STREAMING_HASH.md): **3.101 ms**, or **84.54 million OTs/s**,
at K=2^18. The sections below retain the earlier AES-NI and VAES campaigns.

In the initial AES-NI campaign, the isolated sender takes **3.700 ms**, or **70.85 million
hashed random OTs/s**, on one Ryzen 9 7950X core. This measures the existing
libOTe stationary protocol path, not an encoder-only estimate.

| Sender stage | Median ms |
|---|---:|
| Fresh leaves from cached tree seeds, including sums and tail zeroing | 0.987 |
| SPIN compression, including fresh heuristic code refresh | 2.061 |
| AES hashing of both OT messages | 0.677 |
| Complete timed sender computation | 3.700 |

Each column is the median of three process medians; stage medians need not
sum to the total median. Total process medians were 3.563872, 3.699736, and
3.729021 ms (73.56, 70.85, and 70.30 million OTs/s).

## Timing contract

- Semi-honest stationary noise, `MultType::Spin`, packed receiver choices,
  K=262144 and N=524288, with T128S19 and `BankedHeuristic` refresh.
- 312 trees, each with 1680 leaves; 128 zero-padded coordinates.
  Cached leaf seeds occupy 8,386,560 bytes per party.
- Initial tree expansion, bank construction, workspace and output allocation
  are outside timing. Tree seeds are retained; each batch generates fresh leaves.
- Each batch consumes 312 fresh base-VOLE correlations, supplied outside timing.
  Their generation and base OT are not measured.
- Each batch advances the code seed and refreshes the heuristic SPIN instance.
  These instances do not inherit the uniform-setup distance certificate.
- Timing calls `silentSendInplace` followed by the production sender `hash`.
  It includes routine allocation and local message-enqueue overhead, but excludes
  socket flush/drain and network transport. This is local computation throughput.
- Five warmups, then 31 timed batches per process. Three processes run serially,
  pinned to CPU 15 at 4.5 GHz, boost disabled, holding all shared benchmark locks.
- libOTe/cryptoTools: GCC 13.4, Release, AES-NI and AVX2. SPIN: existing GCC 15.2
  Release library, Zen 4 tuning, runtime-dispatched AVX-512 BCH. GCC 15 crashes
  compiling libOTe's coroutines; no production workaround was added here.
  Installed coproto/macoro dependencies are reused.

## Validation and memory-pressure control

The harness initializes both real endpoints and checks every hashed OT in an
untimed batch. Sender-only mode then clears the receiver's cached leaves, code,
scratch and output buffers. Timed batches check reuse, counters and seed changes.

A separate `paired` run retains both endpoints but executes them serially. It
checks every hashed OT in every batch, synchronized seeds, and cached-tree reuse.
Its 31-batch medians were 5.343 ms sender and 5.097 ms receiver; sender compression
was 3.632 ms. This is a co-resident memory-pressure control, not the selected
isolated-party result. SpinIntegration and SpinOptions also passed before timing.

A separate standalone banked-encoder control using the same SPIN archive measured
1.731 ms including refresh (8.5 microseconds refresh). Protocol compression remains
slower at 2.061 ms. Releasing the receiver demonstrates sensitivity to co-resident
state, but does not fully isolate the remaining difference or its cache level.

The paper's ~47 million OTs/s used regular noise, K=2^20, and an older implementation;
it is not a matched comparison. The 185 million blocks/s figure is fixed-code
encoding only at K=2^18, excluding the AES passes and fresh-code refresh.

## Reproduction

```sh
cmake --build BUILD --target spin_stationary_bench
bash libOTe_Tests/run_spin_stationary_bench.sh \
  BUILD/libOTe_Tests/spin_stationary_bench OUTPUT_DIRECTORY 18 31
```

The target is opt-in, not a CTest benchmark. The runner takes all three shared
locks. The executable alone does not: never run it alongside another benchmark.
Its optional fourth argument `paired` retains and verifies both endpoints.
JSON includes every timed sample. No raw data is committed.

The measured snapshot is in `/tmp/libote-spin-ssd-pq75QW` on Peach.
SHA-256 identities:

| Item | SHA-256 |
|---|---|
| SpinStationaryBench.cpp | a0e5e70ff85ad690927ad3c6333c2a75dbf2e4b5eeebcfd083262a1aeea47bd2 |
| Benchmark executable | 7047ec94dbad7a5af8af0ca54bb6666fc379d14296361459f6a547fc6fa7bb8d |
| SPIN archive | ecbebbfa16d15b4b5460c8811053720d1dd534f2aa81ea5b82757bebd153f0d7 |
| Sender run 1 | f52bb3cfc5b67cfdee5da7df018201043603712786303fc5dc7d3ba9a53c8613 |
| Sender run 2 | 242033a02a7c236d9e6f342a40f3f15a31802fb27efff35594479737d49ed8d0 |
| Sender run 3 | f258a92ce70ce1b16697587c0a58056d4f866d40cb9cead0e86ca1fd0a76344a |
| Paired confirmation | ed90d96cf67bb8f83981f313afc771ff2dc15f10d41bb36e1fffecd3c6a17248 |

## VAES follow-up

An opt-in `ENABLE_VAES=ON` cryptoTools build uses 256-bit VAES. libOTe's sender
also packs complete 32-byte pairs and submits sixteen blocks per hash call.
This avoids narrow-store/wide-load stalls in the temporary hash buffer.
The OFF path retains its two eight-block AES calls. Outputs are unchanged.

A matched OFF/ON comparison used the same host, compiler, SPIN archive, geometry,
and timing boundaries above. Three processes per build ran in alternating order;
each used five warmups and 31 samples. These are medians of process medians:

| Sender stage, K=2^18 | AES-NI | VAES |
|---|---:|---:|
| Fresh leaves | 0.989 ms | 0.949 ms |
| Compression and refresh | 2.096 ms | 2.180 ms |
| Hash both messages | 0.677 ms | 0.440 ms |
| Total | 3.770 ms | 3.571 ms |
| Throughput | 69.54 million OTs/s | 73.41 million OTs/s |

Final process medians were 3.770/3.790/3.722 ms OFF and 3.571/3.590/3.520 ms ON.
An earlier matched comparison measured 3.708 to 3.415 ms. Compression varies
between runs; the approximately 0.24 ms reduction in final hashing is stable.
Stage medians need not add to the median total. A separate nine-sample paired
run verified all batches, synchronized refresh, and cached-leaf reuse.
Its co-resident sender/receiver medians were 5.111/5.308 ms; do not substitute
those memory-pressure results for the isolated sender comparison.

Isolated VAES kernels reach approximately 27–28 GB/s, roughly twice AES-NI and
95–99% of a measured round-only compute ceiling. See
`cryptoTools/benchmarks/VAES.md` for the kernel benchmark and build option.
Fresh-leaf generation has not achieved the same speedup as isolated hashing;
profiling that caller remains a possible next step.

The subsequent [compression diagnosis](COMPRESSION_DIAGNOSIS.md) isolates another
opportunity: writing OT output after each batch slows the next encode by roughly
0.5 ms. The subsequent [streaming-hash experiment](STREAMING_HASH.md) applies
non-temporal stores in the real sender hash. It reaches approximately 85 million
OTs/s at K=2^18, or 77 million including an immediate sequential output read.
The option remains disabled by default; the benefit depends on size and workload.
