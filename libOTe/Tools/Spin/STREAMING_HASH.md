# Non-temporal sender hash output

At K=2^18, non-temporal output stores reduce measured stationary sender time
from 3.577 to 3.101 ms: 73.29 to 84.54 million hashed OTs/s. An immediate scan
of all output bytes reduces the gain, but does not eliminate it.

The implementation is opt-in. Existing calls retain normal cached stores:

```cpp
sender.hash(messages, ChoiceBitPacking::True);       // existing default
sender.hash(messages, ChoiceBitPacking::True, true); // streaming output
```

Call `silentSendInplace` first, as in the existing split encoding/hash flow.
The convenience `silentSend` call continues to use cached stores. The extra
argument changes memory stores, not the OT messages, code, or seed schedule.

The store policy selects a compile-time-specialized loop once per hash call.
There is no policy branch per block. On x86, streaming stores require only the
existing 16-byte alignment. An `sfence` completes them before the cached tail
and before return. Other platforms retain normal stores. SIMD scratch stays in
the ordinary hash function's stack frame, not a coroutine frame.

## Matched K=2^18 results

The host, compiler, stationary-code family, and exclusions match
[STATIONARY_PERFORMANCE.md](STATIONARY_PERFORMANCE.md). VAES is enabled.
Each mode has three independent processes, five warmups, and 101 timed batches.
All benchmarks run serially on CPU 15 at 4.5 GHz with the shared locks held.
The table gives medians of process medians.

| Sender stage | Cached stores | Streaming stores |
|---|---:|---:|
| Fresh leaves | 0.941 ms | 0.917 ms |
| Compression and refresh | 2.213 ms | 1.752 ms |
| Final hash, including stores and fence | 0.423 ms | 0.429 ms |
| Total | 3.577 ms | 3.101 ms |
| Throughput | 73.29 million OTs/s | 84.54 million OTs/s |

The gain is mainly in the next batch's compression, not in AES computation.
Streaming stores avoid filling the cache with the 8 MiB final output buffer.
This agrees with the earlier [write-only controls](COMPRESSION_DIAGNOSIS.md).
Stage medians need not sum to the median total.

Reversing the mode order in another three-process campaign gave 3.571 versus
3.069 ms, or 73.41 versus 85.42 million OTs/s. The benefit survives reversal.

## Immediate output consumption

The `consume` mode scans every output byte immediately after hashing and reduces
the bytes into a checksum. Both the scan and its effect on the next batch are
included. This is a sequential-read consumer, not a model of every application.

| Measurement | Cached stores | Streaming stores |
|---|---:|---:|
| Immediate scan | 0.113 ms | 0.188 ms |
| Total including scan | 3.884 ms | 3.425 ms |
| Throughput including scan | 67.49 million OTs/s | 76.55 million OTs/s |

The scan is slower after streaming stores because the output is less cache-resident.
Nevertheless, the complete repeated pipeline remains faster. Reversing mode order
gave 3.849 versus 3.393 ms. Real consumers can have different access patterns or
overwrite output, so these measurements do not justify a universal default.

## Other sizes and validation

Three-process checks with 31 measured batches, without the immediate scan:

| K | Cached total | Streaming total |
|---|---:|---:|
| 2^16 | 0.825 ms | 0.829 ms |
| 2^20 | 24.881 ms | 24.387 ms |

The K=2^20 cell uses the general banked route implementation. It is not the
paper's approximately 9.3 ms precomputed encoder. Its compression stage is about
18.7 ms and barely changes with store policy. That routing cost is separate work.

Focused tests compare both store modes with scalar AES for lengths 0–33, check
output guards, and deliberately use a 16-byte offset from 32-byte alignment.
GCC integration tests pass with VAES enabled and disabled; the MSVC Release
integration test also passes. Paired stationary runs
check every hashed OT across multiple refreshes, including an immediate-read run.
The paired measurements are correctness and co-resident-memory controls, not the
isolated-party performance numbers above.

## Reproduction

```sh
cmake --build BUILD --target spin_stationary_bench spin_integration_tests
ctest --test-dir BUILD -R 'SpinIntegration|SpinOptions' --output-on-failure
bash libOTe_Tests/run_spin_store_bench.sh \
  BUILD/libOTe_Tests/spin_stationary_bench OUTPUT_DIRECTORY 18 101
```

The runner compares all four store/read modes serially and reverses their order
on alternating processes. `run_spin_stationary_bench.sh` also forwards optional
`nt`, `consume`, and `paired` flags after the trial count. Raw samples remain
outside source control. Current evidence is under `results/nt/` in the remote
workspace `/tmp/libote-spin-ssd-pq75QW`.

Normal stores remain the default. Next, evaluate the streaming option in the
actual downstream consumer before selecting a default policy. Fresh-leaf
generation and the general banked route remain independent optimization targets.
