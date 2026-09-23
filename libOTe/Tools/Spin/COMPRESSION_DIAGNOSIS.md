# Why compression rises from 1.4 ms to roughly 2.1 ms

The largest reproducible integration penalty comes from writing the previous
batch's OT output, not from regenerating the SPIN setup. Plain output writes
without AES reproduce the penalty. Non-temporal output stores recover most of
it in a diagnostic control. This strongly supports cache pollution as the cause.

## Matched encoder comparison

All cells use the same libOTe executable and imported SPIN archive, K=2^18,
T128S19, native 128-bit elements, and in-place transposed encoding. The host is
the Ryzen 7950X, CPU 15 fixed at 4.5 GHz, boost disabled. VAES is enabled.
libOTe uses GCC 13.4; the SPIN archive uses GCC 15.2 and the existing Zen 4 build.

The diagnostic changes the surrounding work, not the encoding implementation.
Each process discards fifteen warmups. The initial grid uses 51 measured calls;
the output-write controls use 101. Every cell has three serial process runs.
Entries below are medians of those process medians, in milliseconds.

| Code setup | Encoder alone | After production leaf generation | With leaf generation and subsequent OT hashing |
|---|---:|---:|---:|
| Full precomputed code | 1.464 | 1.644 | 2.167 |
| Frozen banked code | 1.595 | 1.701 | 2.128 |
| Fresh banked code | 1.617 | 1.783 | 2.217 |

These times exclude preparation and the surrounding work itself. Fresh banked
preparation costs another 0.0085–0.0090 ms. Unchanged-seed preparation is negligible.
The extra work of banked routing explains approximately 0.15 ms in the standalone
comparison. Refresh does not explain the integration gap.

The fixed-code result is close to the historical optimized 1.419 ms measurement,
though that measurement used a different executable. The earlier standalone
banked result of 1.731 ms is not a universal baseline: this controlled run gives
about 1.626 ms including refresh. Do not subtract historical cells as if every
build and surrounding memory access were identical.

## Isolating output traffic

All rows below use fresh banked codes and production leaf generation. Each
iteration generates leaves, prepares the code, times encoding, and then performs
the selected output action. Output actions affect the *next* timed encoding.

| Output action after encoding | Encoding ms | Output-action ms |
|---|---:|---:|
| None | 1.705 | negligible |
| Allocate the 8 MiB output buffer, but do not rewrite it | 1.700 | negligible |
| Write two copies of each encoded block, without AES | 2.207 | 0.227 |
| Production sender OT hashing | 2.212 | 0.443 |

A separate confirmation compared ordinary writes with non-temporal writes:

| Output action | Encoding ms | Output-action ms |
|---|---:|---:|
| Ordinary stores | 2.195 | 0.238 |
| Non-temporal stores, including an `sfence` | 1.800 | 0.295 |
| Production hashing | 2.207 | 0.444 |
| No output action | 1.730 | negligible |

The non-temporal control makes the output pass about 0.057 ms slower, but reduces
the next encode by about 0.395 ms. It therefore recovers approximately 0.34 ms
across those two stages. This control copies blocks; it does not implement an
alternative OT hash, so that saving is not yet a full-protocol result.

CPU 15 has a 32 MiB L3 cache domain. The input and encoder scratch each occupy
8 MiB, cached leaf seeds occupy almost 8 MiB, and the sender's OT output adds
another 8 MiB. Bank tables add further traffic. Some setup data is inactive in
the hot path, so these allocation sizes are not an exact cache-residency model.
The write controls establish the traffic effect without assuming that model.
We have not attributed every lost cycle to a particular cache level or miss type.

## Scope and next step

`SpinCompressionBench.cpp` uses synthetic cached seeds and the production
stationary leaf-expansion, SPIN adapter, and sender-hash routines. It bypasses
tree setup and does not establish valid OT correlations. The full protocol's
correctness tests remain separate. Both ordinary and non-temporal output-copy
controls check their final output outside the timed region.

This diagnostic itself did not change the production encoder or protocol.
The subsequent [streaming-hash experiment](STREAMING_HASH.md) tests non-temporal
stores in the real stationary sender and includes an immediate output scan.
That option remains disabled by default. Chunked processing is another option
if preserving output locality is important.

## Reproduction

```sh
cmake --build BUILD --target spin_compression_bench
bash libOTe_Tests/run_spin_compression_bench.sh \
  BUILD/libOTe_Tests/spin_compression_bench RESULTS_DIRECTORY 101
```

The runner holds the shared benchmark locks and executes all cells serially.
Raw measurements remain outside source control. The measured remote workspace
is `/tmp/libote-spin-ssd-pq75QW`; controls are under `results/compression/`.
