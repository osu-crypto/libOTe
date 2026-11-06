# LogVole

LogVole implements semi-honest chosen-input VOLE over a batching prime `p`.
The receiver chooses `x`, the sender chooses `Delta`, and the output satisfies
`a[i] = b[i] + x[i] * Delta mod p`. This implementation follows the Ring-LWE
construction of Lucien K. L. Ng, Peter Rindal and Akash Shah,
*LogVOLE: Succinct and Efficient Chosen-Input VOLE for ZK and Beyond*.

## Build

LogVole uses libOTe's C++20 toolchain, its pinned cryptoTools/coproto dependencies,
and stock Microsoft SEAL 4.1.1 (`SEAL::seal`). libOTe's normal `FETCH_AUTO` flow
fetches SEAL. An existing installation can be selected with `SEAL_DIR` and
`FETCH_SEAL=OFF`. HEXL and Python scientific packages are not required.

From the libOTe repository root:

```sh
git submodule update --init --recursive
python3 build.py --all --boost --sodium --par=8 -DENABLE_LOGVOLE=ON
./out/build/linux/frontend/frontend_libOTe -u
```

`ENABLE_LOGVOLE=OFF` omits LogVole. CUDA is separately optional and defaults to
OFF. CUDA builds require CMake 3.18 or newer and a compatible CUDA/host compiler
pair. Select the architecture for your device, for example `90` for H100/H200:

```sh
python3 build.py --all --boost --sodium --par=8 \
    -DENABLE_LOGVOLE=ON -DENABLE_LOGVOLE_CUDA=ON \
    -DCMAKE_CUDA_ARCHITECTURES=90
```

The standard `CMAKE_CUDA_COMPILER`, `CMAKE_CUDA_HOST_COMPILER`, and
`CMAKE_CUDA_ARCHITECTURES` settings are respected. `LOGVOLE_CUDA_ARCH` is an
optional fallback when `CMAKE_CUDA_ARCHITECTURES` was not set. Installed CPU
packages do not require CUDA; installed CUDA packages discover CUDAToolkit for
their exported `CUDA::cudart` link dependency.

## Protocol modes and API

The public wrappers are `osuCrypto::LogVoleSender` and `LogVoleReceiver` in
`LogVole.h`. Construct each party with a `LogVoleOptions` value, use the actual
prime returned by `modulus()`, and then perform offline setup and online queries.

```cpp
osuCrypto::LogVoleOptions options;
options.mRequestSize = 1024;
options.mPlaintextModulusBits = 55;
options.mNumThreads = 4;
options.mUseGpu = false;
options.mSetting = osuCrypto::LogVole::CivoleSetting::GoldenSeed;
options.mMode = osuCrypto::LogVole::OnlineMode::Interactive;
osuCrypto::LogVoleSender sender(options);
osuCrypto::LogVoleReceiver receiver(options);
```

The constructor captures its options. There is no separate `configure` API or
implicit sizing from query buffers. Default-constructed or cleared parties are
empty move targets; construct a new party to select a new configuration.
Tuning, transport, and experimental controls live under `options.mAdvanced`.
Resource owners capture the shared `LogVoleExecutionOptions` base (backend and
tuning), allowing reuse across protocol sizes without retaining protocol state.
Both peers must use the same setting, online mode, and updated wire format.
The added mode metadata changes setup framing from the upstream base revision.

| Setting | Online mode | CPU | CUDA |
| --- | --- | --- | --- |
| `CivoleSetting::GoldenSeed` | `OnlineMode::Interactive` (default) | Yes | Yes |
| `CivoleSetting::NoGoldenSeed` | `OnlineMode::Interactive` | Yes | Yes |
| `CivoleSetting::NoGoldenSeed` | `OnlineMode::NonInteractive` | Yes | Yes |

Non-interactive mode requires NoGoldenSeed. Its fixed parameters choose a 52-bit
plaintext prime. GoldenSeed with non-interactive mode is rejected.

For interactive use, run `sender.offline(delta, senderPrng, senderSocket)` with
`receiver.offline(receiverSocket)`, then run
`sender.send(keys, senderPrng, senderSocket)` with
`receiver.receive(x, macs, receiverPrng, receiverSocket)`.
Offline setup is reusable; sequential online calls consume distinct session IDs.
Wrappers are move-only to prevent accidental copying of live session state.

In non-interactive mode the sender can finish offline setup into a
`coproto::BufferingSocket` and publish its outbound bytes before a receiver exists.
The receiver imports those public-key bytes during offline setup. It can then
finish each online query locally, producing MACs and one outbound message without
receiving a sender reply. The sender later processes that message to obtain keys.
Use distinct session IDs across clients sharing a public key. The regression
test `LogVole_Civole_NonInteractivePublicKeyAndSequentialQueries` demonstrates
this deferred lifecycle and rejects replay.

CUDA applications set `options.mUseGpu = true` and pass
those options to the sender and receiver constructors.
Check `LogVole::gpu::enabled(options)` when GPU execution
is required. The default is CPU; each party can select its backend independently.
Optional diagnostics are constructor settings as well:
`options.mAdvanced.mHostStepProfile` enables host-step timing (default false).
The context owns the timing table; CPU contexts, GPU resources, and deferred
message decoders reuse that owner's table. `sender.hostProfiler()` and
`receiver.hostProfiler()` expose their tables (null when disabled); snapshot or
reset them between completed queries. Reporting occurs when the last profiler
owner is released.
`options.mCpuBenchmark` optionally borrows caller-owned CPU diagnostic counters
(default null). Keep them alive through all work, including deferred
materialization. Worker calls pass their own instrumentation state explicitly;
nested work reuses its calling worker's state. No benchmark TLS is used.
Reset counters only after all users have joined. The existing worker-slot
budget, pools, and worker-cap TLS are unchanged.
`options.mAdvanced.mStreams.mDebug` enables CUDA decline/error logging and
synchronized region timing; `mProtocol.mRootProfile` enables root timing;
`mKernels.mNoGoldH200InverseOpTrace` traces the selected inverse operations.
All three default to false.

Set `mKeepOutputOnDevice` to keep outputs in device memory;
`outputDevice()` and `outputDeviceCount()` expose the resulting device token.
The receiver can also supply its own input token through `mInputDevice`.
The two parties retain separate protocol state and communicate through coproto
socket messages.

`LogVoleGarbled.h` provides three-component additive 128-bit garbled labels.
`LogVoleZk.h` provides multiplication-circuit and matrix-product checks on top of
the correlations. Proof wrappers capture VOLE settings in their constructors;
`prepare(statement)` prepares a statement using those settings and at least
`options.mRequestSize` VOLE outputs. Garbled wrappers interpret `mRequestSize`
as the number of labels and use the selected setting's audited modulus width.
Neither API changes the underlying semi-honest VOLE threat
model. Garbled labels are additive field tuples, not XOR/free-XOR blocks.

Matrix checks follow the public-product workload in Section 12.2 and Table 6
of the October 17 paper: every one of the `n*n` length-`n` inner products is
evaluated directly. Independent per-entry coefficients batch those equations;
there is no Freivalds-style matrix projection. CPU checking packs B's columns
contiguously and accumulates exact products in bounded 128-bit chunks,
reducing once per chunk. It dispatches to AVX-512 IFMA on compatible CPUs for
51- and 54-bit fields, with an exact scalar fallback. Set
`mCpuVectorMatMul = false` in `LogVoleZkOptions` to exercise that fallback. Unweighted inner products
are reused across repetitions, giving CPU work `O(n^3 + repetitions*n^2)`;
CUDA currently performs `O(repetitions*n^3)` work. The private VOLE input
contains A, B, then one fresh mask per repetition, totaling `2*n*n + repetitions` entries.

The application supplies the expected public C explicitly to
`ZkMatMulVerifier::verify(publicProduct, prng, socket)`. The verifier validates
and snapshots its `n*n` canonical field elements before the online exchange.
`zkMatMulWitness` returns the private witness and public product separately;
`zkMatMulFillProduct` and its CUDA counterpart also have separate product
outputs. Product generation belongs to statement preparation, outside proof
timing. Public C is common input and is not transmitted inside the proof.

Matrix checks send one 16-byte response per repetition.
`ZkMatMulProver::mLastProofs` and
`ZkMatMulVerifier::mLastValues` expose every equation; the singular diagnostic
members expose the first. Low-level callers use the vector overloads of
`zkMatMulProverResponse` and `zkMatMulVerifierValue`, then `zkMatMulAccept`.
The verifier-value functions require the public product immediately after the
key span. Challenges contain `repetitions*n*n` coefficients.
The scalar overloads accept one repetition. Both peers must use the updated
layout and direct inner-product algorithm. Each equation receives its own fresh mask.

Independent repetitions prevent residuals from cancelling across equations.
Their residual batching error is at most `(1/p)^repetitions`, but all equations
share the same base-field `Delta`; this does not amplify authentication beyond
the field-size limit or change the underlying semi-honest threat model.

## Examples and correctness tests

```sh
B=./out/build/linux/frontend/frontend_libOTe
$B -logvole -n 65539 -t 2
$B -logvole -n 65539 -t 2 -noninteractive 1
$B -logvole -n 65539 -t 2 -nogold 1
# The same three examples accept -gpu 1 in a CUDA build.
$B -logvole -n 65539 -t 2 -gpu 1
$B -logvole -n 65539 -t 2 -noninteractive 1 -gpu 1

$B -u LogVole
$B -u LogVole -gpu 1
$B -u
```

The local example verifies every output against the VOLE relation. libOTe's
usual `-r` and `-ip` options run separate roles using coproto Boost sockets.
The mode tests exercise partial CRT batches, repeated queries, moved sessions,
and GPU output tokens. They fail if `-gpu 1` cannot produce device outputs.

Standalone CUDA arithmetic checks are built independently:

```sh
cmake -S libOTe_Tests/LogVole/tests/cuda -B out/build/logvole-cuda-tests \
    -DCMAKE_CUDA_ARCHITECTURES=90
cmake --build out/build/logvole-cuda-tests --parallel 8
ctest --test-dir out/build/logvole-cuda-tests --output-on-failure
```

The source extraction includes library code, public examples, correctness tests,
and build integration. Research drivers, parameter-search scripts, datasets,
plots, profiling outputs, and benchmark results are excluded.

## Refactoring backlog

### Ownership and execution inventory — 2026-11-06

This inventory describes the working tree at `d2266368`, including uncommitted
changes. A migrated synchronous wrapper is not a completed async migration.
The original 216-declaration globals snapshot remains in the local review
artifacts; the current scan finds **28 runtime global/static/TLS declarations**.
Counts cover source branches on both platforms, not fields within objects or
template instantiations. Compile-time constants and the five literal CUDA
tables are excluded. The scanned LogVole library, tests, and frontend example
contain no environment reads.

| Step | Current status |
| --- | --- |
| Explicit CPU capabilities, settings, and context-owned host/root profiling | Committed; residual capability caches are listed below. |
| Explicit CPU benchmark state; benchmark TLS removed | Committed (`49a1e92e`). |
| Async in-place LHE, explicit executor and buffers | Committed (`305f7a26`); legacy overloads deprecated. |
| Standalone sender expansion using async LHE | Committed (`cbe43e90`). |
| Async truncated LENC, including fused subtraction | Committed (`42e5c113`); legacy overloads deprecated. |
| Standalone receiver expansion using async LHE/LENC | Reviewed and committed (`d2266368`). Full-digit LENC retains its synchronous arithmetic. Existing state-owned mask storage remains leased across awaits without holding a mutex. |
| Sender pinning evidence moved onto sender state | Present in working tree, uncommitted; separate CUDA allocation evidence remains global. |
| Offline setup migration | Uncommitted intermediate `CpuRowScratch::runBulk` implementation; still needs the explicit executor/buffer call-site pattern. |
| macoro `bulk_chunked` and `bulk` delegation | Uncommitted in the separate `out/macoro` checkout, with regression tests. |

#### Remaining runtime globals

| Group | Count | Exact remaining objects | Intended owner/change |
| --- | ---: | --- | --- |
| Protocol run/role | 2 | `gProtocolCacheRunCounter`, `tProtocolCacheScope` in `LogVoleRuntime.h` | Explicit session/cache identity and role passed down the stack. |
| Worker budget | 2 | `gParallelWorkerSlotsInUse`, `tParallelWorkerCap` in `LogVoleParallel.h` | Caller-supplied compute resource and explicit chunk allowance; remove the ambient scheduler after caller migration. |
| Statistics | 5 | `RingOpsStats::resetEpoch`, `globalRingOpsStats`, `globalTimingStats`, `tlsRingOpsStats`; `regions()::r` in `cuda/LogVoleGpuProtocol.cpp` | Owned diagnostics and per-chunk pending counters. |
| CUDA allocation evidence | 2 | `rootCudaWireEvidenceMutex`, `lastRootCudaWireEvidence` in `LogVoleEncoding.cpp` | Caller/actor-owned evidence sink. |
| Capability/compatibility caches | 4 | `defaultPublicSenderCt2PrefetchLevels()::h200`, `available()::ok`, `gaussianTransformHostCompatible()::{recognized, arithmeticCompatible}` | Capture once in the appropriate CPU/GPU resource owner. |
| CUDA error/name storage | 4 | `gLastError`, `gLastWhere`, `gpuDeviceName()::name`, `gpuLastErrorOk()::buf` in `cuda/LogVoleGpuKernels.cu` | Execution-owned error state and owned name/message storage. |
| CUDA attribute initialization | 7 | `gSharedConfigured`, `gPointwisePseudo55TreeSharedConfigured`, `gPointwisePseudo55TreeWarpSharedConfigured`, `gPointwisePseudo55TreeProductWarpSharedConfigured`, `gPointwisePseudo55TreeProductWarpVectorSharedConfigured`, `gPointwisePseudo55SparseSharedConfigured`, `gNttInversePostWarpStages05SharedConfigured` | Owned device preparation; consider only a justified CUDA initialization guard as an exception. |
| Empty sentinel/CLI tags | 2 | `getRingHostModuli()::empty`, `logvoleTags` in `frontend/ExampleLogVole.cpp` | Context-owned empty storage/view and local or compile-time CLI tags. |

The declaration-level scan with source locations is in the local artifacts
`out/review/logvole-globals-inventory-current.{txt,json}`. The older files
without `-current` are historical, not the remaining-work list.

#### Remaining scheduling migration

There are **20 `detail::runParallelTasks` call sites** in library `.cpp` files:
`LogVole.cpp` (2), `LogVoleCore.cpp` (4), `LogVoleEncoding.cpp` (2),
`LogVoleLenc.cpp` (1), `LogVoleLhe.cpp` (1), `LogVoleRingReceiver.cpp` (2),
`LogVoleShrinkExpand.cpp` (2), `LogVoleZk.cpp` (5), and
`cuda/LogVoleGpuBackend.cpp` (1). These are call sites, not independent algorithms.

Separately, **22 offline setup sites** use the intermediate
`setupScratch.runBulk`: Core (7), LENC (6), LHE (5), Ring (4).
Five additional executor `runBulk` sites remain in ZK (3), legacy LHE (1),
and legacy LENC (1). They still reach the blocking `CpuExecutor::runBulkChunked`
adapter. Direct `sync_wait` expressions remain in `LogVoleCpuExecutor.h` and
`cuda/LogVoleGpuBackend.cpp`; deleting just those expressions is not a migration.

Receiver review validation: the Windows build and four end-to-end tests passed
in 0.57 seconds, including fused/separate evaluation, one-worker execution,
exact legacy agreement, and unchanged output on failure. Checks verify reuse
of LHE/LENC storage and reacquisition of the same mask allocation after both
success and failure. The preceding five-test run also covered the LENC kernel
matrix (7.36 seconds). This migration has not been revalidated on WSL or CUDA
execution.

Next steps, in order:

1. Migrate the root receiver expansion in `finalizeRootOnlineReceiverImpl`
   (`LogVoleCore.cpp`) and its `LogVoleRingReceiver::onlineImpl` call boundary.
   Thread the caller's executor and prepared buffers through the online API;
   await the single expansion, preserving root state publication and GPU paths.
   Deprecate the synchronous entry point while other callers migrate.
2. Migrate intermediate receiver expansion (`LogVoleRingReceiver.cpp`, the
   `wDoublePrime` loop). Its callbacks will await, so synchronous `bulk_chunked`
   is not the outer algorithm. Discuss a bounded set of partition tasks joined
   with `when_all_scope`: one exclusive buffer set per partition, sequential
   chunks within each partition, and no nested worker multiplication. Child
   inputs and outputs must remain owned until the join completes. Keep row
   parallelism for the single-chunk case. Sender seed evaluation is a subsequent
   step; preserve its early-rejection and accepted-cache behavior.
3. Migrate coherent groups of remaining setup/proof/codec loops using direct
   `bulk_chunked` where appropriate. Discuss a different algorithm first if a
   loop does not fit. Retire `CpuRowScratch` scheduling and legacy overloads
   when their callers are gone.
4. Remove the remaining global groups above in separate ownership changes.
   Small independent groups need not wait for all scheduling work to finish.

The object-owned `ShrinkExpandScratch` leases and GPU worker maps are not
globals. Redesigning them is separate work, not a prerequisite for eliminating
the remaining ambient state. Socket detached-send semantics remain out of scope.
Use fast focused tests per coherent step; broader cross-platform/leak checks
belong at milestones. No benchmarks are needed for this migration.

### Deferred option cleanup

- Prune transport/encoding optionality after the ownership refactor. Audit the
  18 switches under `mAdvanced.mTransport`: retain only controls justified by a
  concrete caller requirement or measured supported-platform tradeoff. Make
  established ownership/move and endian-safe codec paths standard; use the
  configured thread count for parallel work. Remove unneeded experimental
  root-pinning/allocation variants and their alternative implementations, not
  just their flags. Preserve required portability, allocation-failure fallback,
  protocol bytes, and structured lifetimes. Do not assume every current default
  is universally fastest; record the reason for each retained control.
