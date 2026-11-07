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
`sender.send(executor, buffers, keys, senderPrng, senderSocket)` with
`receiver.receive(executor, receiverLheBuffers, receiverLencBuffers, x, macs, receiverPrng, receiverSocket)`.
For CPU execution, keep an application-owned `macoro::thread_pool` running and
prepare one `LheDecryptBuffer` per allowed partition. Size each
`buffer.mProduct.mCoeffs` to `ringPolyCoeffCount(sender.mParams.mLogVole.mShrinkExpand.mRing)`.
Pass the same pool and buffers to sequential sends; both must outlive the awaited
operation. GPU execution accepts an idle pool and empty buffers. The garbled
sender and ZK verifier APIs take these same explicit resources.
The receiver uses separate LHE products and LENC pointer buffers. After offline,
reserve both `mCiphertexts` and `mNodes` to the maximum of
`2 * max(rootLeftLevels, shrinkExpandLevels) * (tau + 1)` across its recursion
levels, and size each LHE product for the common ring. The example prepares these
buffers once. Sender and receiver may share an executor, including a single
worker, but concurrent operations must have disjoint buffers. No pool or buffer
owner is installed inside the protocol; each started operation must finish before
the caller reuses or destroys its resources.
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

Estimated overall completion: **77%** of the agreed ownership/globals refactor,
including remaining scheduling, cleanup and cross-platform/leak validation.
This is a rough work estimate, not a declaration count.

This inventory describes the committed tree. A migrated synchronous wrapper
is not a completed async migration.
The original 216-declaration globals snapshot remains in the local review
artifacts; the current scan finds **26 runtime global/static/TLS declarations**.
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
| Root receiver finalization and key-derivation prefix | Committed in `d9faba17`; async LHE/LENC with caller-owned buffers, owned response before lazy start, and unchanged root/output publication. |
| Intermediate receiver expansion | Committed in `fce0002d`; bounded partition tasks joined by `when_all_scope`, exclusive LHE/LENC buffers per partition, sequential chunks, and row parallelism for a single chunk. The legacy CPU entry point is removed; the GPU fallback remains. |
| Intermediate receiver shrink | Committed in `b792a035`; direct `bulk_chunked` on the caller executor, unchanged arithmetic/padding, exclusive output ranges, and inline execution for one partition. Per-partition benchmark state is allocated only for parallel work. |
| Intermediate receiver denoise | Committed in `216ef876`; direct async `bulk_chunked`, one shared recovery-data preparation, unchanged unrolled row kernel, and alias-safe output publication. Legacy synchronous entry point is deprecated. |
| Empty-moduli sentinel and CLI tags | Removed in `dd980823`; a borrowed modulus span and function-local tags replace the globals. |
| Sender pinning evidence moved onto sender state | Reviewed and committed. `LogVoleSender::mRootWirePin` owns the result; low-level callers pass an exclusive reference. Shared evidence/mutex and snapshot API removed. Separate CUDA allocation evidence remains global. |
| Offline setup migration | Twenty former setup sites now await direct `bulk_chunked` with caller executor and exclusive status storage, wired through public sender/verifier APIs. Sequential phases reuse the storage; one chunk runs inline. Sampling order and arithmetic batching are preserved. Synchronous GPU lazy materialization retains the legacy adapter. |
| Online receiver zeta | CPU digest preparation awaits direct `bulk_chunked` with caller executor and exclusive `RootZetaBuffer` storage, threaded through public receiver/garbled/prover APIs. Each chunk reuses multiprecision scratch and an AES PRNG buffer. Protocol range count still determines seed layout; buffer count only bounds execution. GPU sampling/fallback remains synchronous and unchanged. |
| Receiver input wrapping | CPU CI-VOLE input wrapping awaits direct `bulk_chunked` using caller-owned `ZpEncodeBuffer` storage. Each chunk reuses slots and SEAL plaintext storage; the encoding/lifting arithmetic is shared with the legacy entry point. Public receiver, garbled receiver, and prover APIs pass the buffers through. GPU wrapping/fallback remains unchanged. |
| CPU output unwrapping | Sender key release and receiver MAC output await direct `bulk_chunked` using caller-owned `ZpDecodeBuffer` storage. Each chunk reuses plaintext, slots, canonical residues and composition storage; one shared synchronous numerical kernel preserves the legacy arithmetic. Public sender/receiver, garbled and proof wrappers pass resources through. GPU/fallback and staged diagnostic release retain the synchronous API. |
| macoro `bulk_chunked` and `bulk` delegation | Reviewed and committed as `76f1b70` in `out/macoro`. One execution engine for chunk and item callbacks; focused bulk/executor/join tests pass (18 tests, 0.23 seconds on Windows). |
| macoro bounded async `all_of` | Reviewed and committed as `9114af8` in `out/macoro`. One shared allocation plus one reusable native coroutine bridge per async partition; no synthetic-frame ABI dependency. All started predicates join and clean up before completion. |
| Async sender seed evaluation | Explicit-executor `LogVoleRingSender::online` and `senderPrecompute` now await root LHE, recursive expansion/denoise, and bounded `all_of` validation. Early rejection joins started work before retry; focused tests compare early/full seeds, outputs, caches and PRNG order. Higher-level senders and ZK verifiers now pass these resources through. Synchronous CPU entry points are removed; the legacy evaluator is restricted to GPU sessions, including its existing host fallback. |
| Higher-level receiver resource wiring | Public receiver, garbled receiver, CI-VOLE and ZK prover APIs pass executor/LHE/LENC buffers through. Deprecated synchronous CPU online/finalization entry points are removed. Ring scopes are captured before lazy start and no TLS guard crosses the added await. GPU finalization/fallback remains private. |

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

The declaration-level scan with source locations is in the local artifacts
`out/review/logvole-globals-inventory-current.{txt,json}`. The older files
without `-current` are historical, not the remaining-work list.

#### Remaining scheduling migration

There are **20 `detail::runParallelTasks` call sites** in library `.cpp` files:
`LogVole.cpp` (2), `LogVoleCore.cpp` (4), `LogVoleEncoding.cpp` (2),
`LogVoleLenc.cpp` (1), `LogVoleLhe.cpp` (1), `LogVoleRingReceiver.cpp` (2),
`LogVoleShrinkExpand.cpp` (2), `LogVoleZk.cpp` (5), and
`cuda/LogVoleGpuBackend.cpp` (1). These are call sites, not independent algorithms.
The synchronous input-wrapping and output-unwrapping sites now serve
GPU/fallback and diagnostic callers; production CPU paths use explicit-resource
async overloads. The staged synchronous `civoleSenderReleaseK` API remains legacy.
Setup message/state copying and codec parallelism are GPU-gated; leave those
alone while GPU migration is deferred. Their CPU paths already copy inline.

Of the original **22 `setupScratch.runBulk` sites**, 20 offline sampling and
assembly sites now use direct async `bulk_chunked`; CPU online receiver zeta
also uses it. Three calls to `setupScratch.runBulk` remain: legacy zeta sampling
for GPU/fallback callers, synchronous GPU lazy root-error expansion, and a named
legacy seed-replay helper used only by that GPU lazy getter. CPU finalization's
exceptional seed-only replay retains its existing inline, one-worker fallback.
The getter uses `std::call_once` and
cannot await; changing that boundary is separate from CPU offline setup.
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

Root review and intermediate expansion validation: Windows build passed. Root
reuse/lifetime regressions and the recursive VOLE relation passed in 4.22 seconds;
a two-thread run with separate arithmetic passed in 0.42 seconds. Recursive tests
verify unchanged LHE/LENC allocations with three buffers and one/two executor
threads. GPU execution and WSL were not rerun for this step.

Denoise exactness/aliasing and controller-on-single-worker tests passed in
0.71 seconds. After the global removals, NTT, denoise, and recursive relation
checks passed in 0.67 seconds. The LogVole target and changed frontend object
compile on Windows; the full frontend target encounters unrelated DPF/Waterfall
test compilation errors in this configuration. No WSL/GPU execution rerun.

Previous sender migration validation: Windows CPU tests compared the two entry points,
seed/PRNG progression, cache reuse and malformed-root failure with early checking
on/off and worker allowances 1, 2 and 4. Both protocol controllers and their workers
share a single executor thread with disjoint reusable buffers. These checks passed
in 7.48 seconds; a two-thread separate-arithmetic run passed in 0.45 seconds.
CUDA-enabled compilation passed; GPU execution and WSL were not rerun.
The local build needs `-DMACORO_GIT_TAG=codex/macoro-scope-lifetime` (or the
corresponding published revision): coproto's dependency fetch otherwise checks out
its older macoro revision, which lacks these algorithms.

Higher-level sender migration also closes the GoldenSeed response boundary: it
now awaits seed evaluation before encoding the response; PublicSeed still defers
expansion until after sending. The earlier socket tests did not expose this gap
because GoldenSeed preparation still took the synchronous path. There is now one
CPU seed-evaluation implementation, reached through the explicit-resource API.
The synchronous evaluator remains private to GPU sessions for their existing
backend/fallback behavior. Other legacy setup, receiver and codec scheduling is
outside this step.

Validation for this step: the CUDA-enabled Windows test target and the public
example compile. Three focused core tests pass in 11.83 seconds (early/full
rejection and PRNG parity, cache/failure behavior, root reuse and single-thread
execution). Two-query public GoldenSeed and NoGoldenSeed runs pass in 5.1 and
41.3 seconds with stable caller buffer storage. The combined 60-second budget
expired during the non-interactive case; its one-query rerun passes in 29.4
seconds. No GPU runtime or WSL rerun, and no benchmarks.

Receiver wiring validation: the CUDA-enabled Windows test target and example
compile. Recursive VOLE, root reuse/failure handling, and two public GoldenSeed
queries pass in 25.59 seconds combined. Both public controllers and their workers
share one executor thread; LHE and LENC storage stays stable, and LENC pointer
lists are empty after each query. One 16-value non-interactive PublicSeed query
passes in 33.16 seconds. No GPU runtime, WSL rerun, or benchmarks in this step.
The working-tree reversion of the previously committed async receiver shrink and
denoise blocks was removed so the mandatory-executor path retains those phases.

Sender pinning evidence review: the worker joins before its evidence is published
and before reserved storage is destroyed. Windows CUDA-enabled compilation passes;
CPU checks for lazy start, failure reset, independent evidence, move and clear pass
in 3.33 seconds. GPU registration execution and WSL were not rerun. This finalizes
an existing working-tree change; the working-tree inventory still has 26 runtime
declarations because it already excluded these two globals.

Working-tree reconciliation: the remaining offline setup changes and their
regressions are committed together. Restored the already-committed sender
expansion scope capture before lazy task start. CUDA-enabled Windows compilation
and the example object pass; four focused tests pass in 3.60 seconds, covering
serial/parallel setup agreement, exact PRNG progression, reusable executor,
worker allowances, failure cleanup, recursive VOLE and early/full seed checking.
No WSL or GPU runtime rerun. Overall completion remains 71% because this closes
commit debt for work already counted rather than completing another migration.

Offline async setup validation: the CUDA-enabled Windows test target and
example object compile. Four CPU tests pass in 33.94 seconds, covering exact
serial/parallel sampling and PRNG progression, lazy start, worker allowances,
failure/output preservation, workspace reuse, recursive VOLE, and both public
controllers sharing one executor thread with their workers. The full LENC
parameter matrix accounts for 30 seconds; use `-lvFactoryFast 1` for subsequent
focused runs. The small CUDA LENC smoke passes in 12.13 seconds; the resident
Gaussian parity test skips because this compiler/libm combination is not
recognized for exact transformation. WSL and leak validation were not rerun.
Setup options and legacy cache identity are captured by value before lazy
execution; borrowed operands and status storage live until completion. No TLS
scope guard crosses an added await. This batch changes scheduling ownership,
so the remaining runtime-global declaration count is still 26.

Online zeta validation: CUDA-enabled Windows compilation and the public example
pass. Four focused CPU tests pass in 7.66 seconds, including two public queries
with stable scratch/PRNG allocations and controller/worker execution on one pool
thread. The sampler regression checks exact legacy agreement at 1, 63, 65, 127
and 208 bits, forced rejection, serial/seeded parent-PRNG progression, allowances
1/2/3, a worker cap, lazy start, and unchanged output on invalid seed shape.
A two-thread recursive protocol run also passes in 0.45 seconds.
No GPU runtime, WSL, leak checks, or benchmarks were run for this CPU-only step.

Input-wrapping validation: CUDA-enabled Windows compilation and the public
example pass. The focused encoder regression and two public GoldenSeed queries
pass in 4.14 seconds; the encoder also passes on two workers in 0.05 seconds.
Checks cover exact legacy agreement, both lifting modes, partial-batch padding,
empty input, invalid padding/buffer rejection, lazy start, worker limits, and
stable slot/plaintext/output allocations. One chunk completes on an executor
with no threads. The public query test verifies scratch reuse across queries
while both controllers and their workers share one pool thread. No GPU runtime,
WSL, leak checks, or benchmarks were run for this step.

Output-unwrapping validation: CUDA-enabled Windows compilation and the public
example object pass (67.05 seconds). The focused decoder regression and two
public GoldenSeed queries pass in 3.97 seconds; the decoder also passes with two
executor threads in 0.10 seconds. Checks use original scalar labels as an exact
roundtrip oracle, with scaled/unscaled decoding, noncanonical residues,
optimized/scalar dispatch, empty/full/partial batches, allowances 1/2/3,
plaintext/slot/canonical/composition/output allocation reuse, invalid
count/shape/buffer rejection, an explicit worker cap, and an idle executor's
inline single-chunk path. The public queries run controllers and workers on one
pool thread and verify stable pre-sized sender/receiver plaintext and slot
allocations across both queries. No GPU runtime, WSL, leak checks, or benchmarks
were run.

Next steps, in order:

1. Migrate remaining CPU proof loops using direct
   `bulk_chunked` where appropriate. Discuss a different algorithm first if a
   loop does not fit. Retire `CpuRowScratch` scheduling and legacy overloads
   when their callers are gone.
2. Remove the remaining global groups above in separate ownership changes.
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
