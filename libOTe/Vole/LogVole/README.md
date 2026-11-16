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

The agreed CPU phase is **100% complete and validated** by the focused Windows
functional and Linux host-LSan gates below. The GPU phase remains deferred with
**21 runtime global/static/TLS declarations**. The earlier **98% overall** figure
is a historical rough work estimate, not a claim that the full globals refactor
is complete or a declaration count.

This inventory describes the committed tree. A migrated synchronous wrapper
is not a completed async migration.
The original 216-declaration globals snapshot remains in the local review
artifacts; the current inventory contains **21 runtime global/static/TLS declarations**.
Counts cover source branches on both platforms, not fields within objects or
template instantiations. Compile-time constants and the five literal CUDA
tables are excluded. The scanned LogVole library, tests, and frontend example
contain no environment reads.

| Step | Current status |
| --- | --- |
| Explicit CPU capabilities, settings, and context-owned host/root profiling | Committed; residual capability caches are listed below. |
| Explicit CPU benchmark state; benchmark TLS removed | Committed (`49a1e92e`). |
| Async in-place LHE, explicit executor and buffers | Committed (`305f7a26`); normal synchronous overloads retired, internal GPU compatibility retained. |
| Standalone sender expansion using async LHE | Committed (`cbe43e90`). |
| Async truncated LENC, including fused subtraction | Committed (`42e5c113`); normal synchronous overloads retired, internal GPU compatibility retained. |
| Standalone receiver expansion using async LHE/LENC | Reviewed and committed (`d2266368`). Full-digit LENC retains its synchronous arithmetic. Existing state-owned mask storage remains leased across awaits without holding a mutex. |
| Root receiver finalization and key-derivation prefix | Committed in `d9faba17`; async LHE/LENC with caller-owned buffers, owned response before lazy start, and unchanged root/output publication. |
| Intermediate receiver expansion | Committed in `fce0002d`; bounded partition tasks joined by `when_all_scope`, exclusive LHE/LENC buffers per partition, sequential chunks, and row parallelism for a single chunk. The legacy CPU entry point is removed; the GPU fallback remains. |
| Intermediate receiver shrink | Committed in `b792a035`; direct `bulk_chunked` on the caller executor, unchanged arithmetic/padding, exclusive output ranges, and inline execution for one partition. Per-partition benchmark state is allocated only for parallel work. |
| Intermediate receiver denoise | Committed in `216ef876`; direct async `bulk_chunked`, one shared recovery-data preparation, unchanged unrolled row kernel, and alias-safe output publication. Normal synchronous entry point retired; root recovery shares the serial arithmetic core. |
| Empty-moduli sentinel and CLI tags | Removed in `dd980823`; a borrowed modulus span and function-local tags replace the globals. |
| Sender pinning evidence moved onto sender state | Reviewed and committed. `LogVoleSender::mRootWirePin` owns the result; low-level callers pass an exclusive reference. Shared pin evidence/mutex removed. CUDA allocation evidence now has an explicit shared sink retained by its sender and active wire allocation. |
| Offline setup migration | Twenty former setup sites now await direct `bulk_chunked` with caller executor and exclusive status storage, wired through public sender/verifier APIs. Sequential phases reuse the storage; one chunk runs inline. Sampling order and arithmetic batching are preserved. Synchronous GPU lazy materialization retains the legacy adapter. |
| Online receiver zeta | CPU digest preparation awaits direct `bulk_chunked` with caller executor and exclusive `RootZetaBuffer` storage, threaded through public receiver/garbled/prover APIs. Each chunk reuses multiprecision scratch and an AES PRNG buffer. Protocol range count still determines seed layout; buffer count only bounds execution. GPU sampling/fallback remains synchronous and unchanged. |
| Receiver input wrapping | CPU CI-VOLE input wrapping awaits direct `bulk_chunked` using caller-owned `ZpEncodeBuffer` storage. Each chunk reuses slots and SEAL plaintext storage; the encoding/lifting arithmetic is shared with the legacy entry point. Public receiver, garbled receiver, and prover APIs pass the buffers through. GPU wrapping/fallback remains unchanged. |
| CPU output unwrapping | Sender key release and receiver MAC output await direct `bulk_chunked` using caller-owned `ZpDecodeBuffer` storage. Each chunk reuses plaintext, slots, canonical residues and composition storage; one shared synchronous numerical kernel preserves the legacy arithmetic. Public sender/receiver, garbled and proof wrappers pass resources through. GPU/fallback and staged diagnostic release retain the synchronous API. |
| Multiplication proof CPU execution | Public CPU prover response/verifier checks await direct `bulk_chunked` on the caller executor. `ZkMulCpuWorkspace` preallocates numerical locals/task outputs and captures its worker budget without creating a pool. The async witness API joins each independent layer, retaining scalar dependent-layer order. Shared synchronous kernels preserve arithmetic, original prover partitions, verifier task slots, reduction order and PRNG draws. Legacy diagnostics/GPU fallback lazily construct their private executor; matrix proof loops are separate remaining work. |
| Matrix proof CPU execution | CPU prover/verifier paths await direct `bulk_chunked` with role-specific numerical workspaces prepared before proofs. Prover stores four n^2-word arrays; verifier stores two, plus O(chunks + repetitions) locals/output staging. Noncanonical copies remain lazy. Transpose tiling, unweighted inner products, original row/weighted-sum partitions and ordered reductions are unchanged. GPU-selected public objects keep CPU workspaces empty until an actual host proof is needed. Host fallback lazily prepares the existing member workspace, reuses it on later checks, and awaits the same primary CPU algorithm on the caller executor; device-only failures remain fatal. Standalone async product/witness APIs use exclusive caller byte-status storage. |
| Identity service, stage one | `ProtocolCacheService` owns the atomic allocator; shared factories and GPU execution/setup owners retain/inject it. Cheap host-only IDs contain service identity plus numeric value, and cache/retained comparisons preserve affinity. Owned operation contexts and retained records keep service lifetime; lookups/copies of ID views do not increment shared ownership. The global allocator is removed. The compatibility identity TLS is now removed; constructors and preparation accept explicit configure views, and query-SID numeric bindings are unchanged. |
| Resource construction boundary | Ring/CRT factory and GPU setup/execution constructors no longer inherit identity service from ambient scope. Existing phase/default-factory entry callers explicitly forward their compatibility service; supplied owners remain unchanged. Nullable raw setup creation receives its fallback service explicitly, with no extra service ownership work when execution already exists. Factory core role/run selection is now explicit; compatibility defaults at unmigrated caller boundaries and remaining operation transport still use identity TLS. |
| Factory context forwarding | Ring/CRT factory make, native combined setup/certificate admission, and CRT host materialization receive explicit cheap scope views. Factory cache role/service selection and native bundle owner checks use that view; no current-scope read or guard remains in these cores. Existing public entry signatures have a trailing compatibility default evaluated at unmigrated caller boundaries. No operation identity is stored on shared math/context records; exact retained-record selection keeps its fixed-owner contract. |
| Public operands and retention context | LHE/LENC public-cache creation, lookup and host materialization forward explicit views through nonce-derived uniform batches and GPU retained-owner registration/validation/materialization. Existing owned setup contexts supply these views before suspension; service ownership is retained once per entry/owner. CPU-only decryption/evaluation workers use supplied operands only, so their two unnecessary identity capture/guard pairs are removed. A remains run-keyed; CPU B retains its same-role run-zero sharing convention. |
| Private GPU provenance context | Root/top private uniform sampling, compact root-error ownership, delta/seed-label/repetition validation, and first-query ownership checks take cheap explicit caller views. Retained owners keep their service once; online first-query admission stays in that retained service domain. The identity-free allocation worker no longer installs a scope guard. Transitional defaults remain at unmigrated callers; lazy host materializer caller-role checks still require explicit-interface plumbing. |
| Lazy sender host context | Seed-label lazy host access and `hostS` accept explicit caller views. Sender materializers preserve first-materialization Receiver rejection inside `call_once`; retained-device checks use the original producer identity, while fallback callbacks, CRT host/wrap helpers and repetition construction forward caller context. Top-sk1 explicit materialization also separates caller admission from producer validation. Three owner guards are removed; identity-free root/error replay interfaces remain unchanged. |
| Reusable GPU offline mirrors | Sender/receiver cache preparation forwards an explicit borrowed identity through context creation, retained-public validation, copies and host-retention lookup. Recursive Core setup forwards its captured scope. Sender retained operands preserve their original offline run. Three TLS guards are removed; compatibility defaults and receiver Ct1 lazy materialization remain. No kernel or numerical changes. |
| Receiver resident Ct1 and lazy snapshots | Explicit receiver finalization scope reaches context/public-operand acquisition, retained validation, cache construction and producer owners. Original caller-role context/eager-cache selection and Receiver-only retained regions are preserved. Lazy public owners pass their owned scope directly. Ct1 snapshot/NTT and pipelined copy are identity-free, so their redundant guards are removed without new parameters. Generic legacy parallel helpers still carry compatibility scope; copy workers use an empty owned context. No scheduling or numerical changes. |
| GPU backend cold setup ownership | Dynamic coefficient/plaintext selectors and nullable raw-ring setup accept an explicit fallback service; production execution owners bypass compatibility defaults. `GpuRing::get(ctx)` obtains a missing setup service from its owned factory, and prefetch workers use their copied context without identity capture. Backend implementation has no direct ambient identity reads/guards; temporary external defaults and the retained-record bind boundary remain. Role/raw cache keys and warm reuse are unchanged. |
| GPU geometry and retained randomizer identity | Geometry keys hash the explicit operation role; shrink/expand and setup assembler entry points forward borrowed views through cache/token admission and retained copies. LENC randomizers preserve producer-role admission across runs, and seed-label/private metadata keeps its exact existing run rules. Existing owned setup/online callers forward their contexts; public compatibility defaults remain for other callers. No numerical, kernel or scheduling changes. |
| Receiver offline transport context | Both receiver offline coroutines own the captured operation scope before lazy start and pass explicit views through recursive, shrink/expand and root finalization. Four direct guards are removed, including the two that previously spanned socket awaits; transport frame allocation and byte decoders remain identity-free. Existing wire/lazy allocation owners are retained. Sender offline setup and remaining online caller capture remain separate work. |
| Key derivation and configured receiver setup | Sender/receiver key-derive coroutines capture owned scope before lazy start; only response processing/finalization receive views for fallback ring construction. Request packing and transport remain identity-free. Public receiver offline captures and forwards the exact caller run through CI-VOLE metadata/context, Ring setup and first-query owner sealing; canonical zero is preserved, never replaced by the configure ID. Four guards are removed. |
| Async LHE/LENC sender setup kernels | Existing owned setup scopes now feed private-token admission and lazy seed-label fallback explicitly. Fifteen entry/worker guards and their suspend/resume transport are removed; arithmetic chunks remain identity-free. Public A/B, sampler and GPU assembly calls keep explicit context; numeric lazy producer owners retain existing ownership. Core/ShrinkExpand phase closure remains separate. |
| ShrinkExpand sender orchestration | Owned phase scopes replace six guards in ShrinkExpand setup and Core public setup forwarders. Fixed private-key admission still checks the original caller role before Sender normalization. Context/public-token creation, full-digit nullable-B fallback, top-key sampling and temporary GPU sampler owners receive explicit views; scalar arithmetic samplers remain identity-free. Online phase closure remains separate work. |
| Core recursive/root sender setup | Root error sampling, TopCt assembly, root offline preparation and recursive sender setup use their existing owned phase scope explicitly. Eleven entry/chunk guards are removed; private delta/top/root metadata, B/BStar caches/fetches and uncaptured batch samplers preserve original role/run admission and ownership. Internal defaults are required at migrated helpers; encoder tensor access remains identity-free. |
| Identity-free compact and host Root samplers | Seven Ring entry/chunk guards are removed. Three compact sampler APIs and both host-only Root sampler overloads no longer accept unused protocol scope; they borrow numeric context, buffers and executor until joined. Resident Root metadata creation still receives owned identity. Service-lifetime regression now exercises actual LHE public-A cache ownership. |
| Sender entry, delta and offline wire ownership | Public/CI-VOLE/Ring sender entry points capture owned caller context before lazy start. A zero incoming sender run still allocates fresh from its resource service; qualified service affinity and explicit sender-owner override are preserved. Delta wrapping forwards views into cold plaintext tables. Eight guards are removed from setup/wire workers and encoders; explicit run IDs, wire allocators, RootWirePin and joined workers retain exact services. Send ownership/order is unchanged. |
| Online ShrinkExpand leaves and host materialization | Sender/receiver expansion and tree preparation forward explicit caller views; async expansion owns context before lazy start, preserving Receiver-only normalization. Host materialization keeps its original role subregions and caller admission. Nullable-A synchronous LHE receives a view; in-place async LHE remains identity-free. Ten guards are removed, including numeric denoise transport. Parent online orchestration remains next. |
| macoro `bulk_chunked` and `bulk` delegation | Reviewed and committed as `76f1b70` in `out/macoro`. One execution engine for chunk and item callbacks; focused bulk/executor/join tests pass (18 tests, 0.23 seconds on Windows). |
| macoro bounded async `all_of` | Reviewed and committed as `9114af8` in `out/macoro`. One shared allocation plus one reusable native coroutine bridge per async partition; no synthetic-frame ABI dependency. All started predicates join and clean up before completion. |
| Async sender seed evaluation | Explicit-executor `LogVoleRingSender::online` and `senderPrecompute` now await root LHE, recursive expansion/denoise, and bounded `all_of` validation. Early rejection joins started work before retry; focused tests compare early/full seeds, outputs, caches and PRNG order. Higher-level senders and ZK verifiers now pass these resources through. Synchronous CPU entry points are removed; the legacy evaluator is restricted to GPU sessions, including its existing host fallback. |
| Higher-level receiver resource wiring | Public receiver, garbled receiver, CI-VOLE and ZK prover APIs pass executor/LHE/LENC buffers through. Deprecated synchronous CPU online/finalization entry points are removed. Ring scopes are captured before lazy start and no TLS guard crosses the added await. GPU finalization/fallback remains private. |

Reusable-mirror validation: the CUDA-enabled Windows test target and frontend
example object compile (66.4 seconds). Three focused CPU tests pass in 3.29
seconds; private metadata and lazy-context GPU tests pass in 1.22 seconds,
including explicit context under unrelated ambience, sender offline-run reuse,
and receiver foreign-run rejection before cache publication. No benchmarks or
WSL validation in this step.


Receiver-Ct1 validation: CUDA-enabled Windows test target and frontend example
object compile (68.46 seconds; test-only correction rebuild 15.37 seconds).
Three focused CPU tests pass in 3.28 seconds; private metadata and lazy-context
GPU tests pass in 2.36 seconds. The receiver regression encodes actual sender
state, imports its derived parameters, and checks first resident Ct1 snapshot
against CPU NTT under a foreign service/role, forced pipelined copying and
repeated snapshot/public-owner reuse. An initial test used original rather than
derived truncated parameters and correctly failed validation; corrected before
the passing run. Seven direct guards are removed; generic parallel helper
transport remains. No benchmarks or WSL validation in this step.

Backend cold-setup validation: Windows CUDA-enabled test target and frontend
example compile (65.21 seconds). Three CPU checks pass in 3.16 seconds; two
GPU identity/lazy-context checks pass in 2.51 seconds, including explicit
null-execution selector/raw owners and cold prefetch/get reuse under unrelated
ambience. No benchmarks or WSL run.

Geometry/randomizer validation: Windows CUDA-enabled test target and frontend
example compile (69.84 seconds). Two GPU identity checks pass in 2.56 seconds,
including explicit randomizer role admission across runs and a real shrink
mirror rebuild under foreign ambience. Two-query 16-value GoldenSeed GPU online
smoke passes in 0.80 seconds; three CPU checks pass in 3.20 seconds. No
benchmarks or WSL run. Compatibility transport still keeps the runtime global
count at 25; the 85% headline is an approximate overall work estimate.

Receiver-offline validation: Windows CUDA-enabled target and frontend example
compile (66.82 seconds); three CPU checks pass in 3.20 seconds, two GPU identity
checks in 3.12 seconds, and the two-query GoldenSeed GPU smoke in 2.35 seconds.
The lazy-start regression drops external service owners, suspends before frame
arrival under unrelated ambience, and verifies unchanged TLS, retained exact
service, Receiver state role and exact Ct1 output. No benchmarks or WSL run.

Key-derive/configured-receiver validation: Windows CUDA-enabled target and
frontend example compile (77.04 seconds). Three key-derive checks pass in 0.24
seconds, including construction-time service retention and unchanged TLS across
paired socket suspension, exact outputs and oversized-frame rejection. Three
CPU checks pass in 3.18 seconds; GPU identity/lazy-context and two-query GoldenSeed
smoke pass in 3.28 seconds. No benchmarks or WSL run.

Setup-kernel validation: Windows CUDA-enabled target and frontend example
compile (23.72 seconds). Three CPU checks pass in 3.32 seconds, including lazy
LHE/LENC setup under unrelated ambience with exact outputs/PRNG progression and
unchanged executor TLS. GPU identity/lazy-context and two-query GoldenSeed smoke
pass in 3.34 seconds. No benchmarks or WSL run.

Sender-orchestration validation: Windows CUDA-enabled target and frontend
example verification pass (final incremental build 7.92 seconds). Four CPU
checks pass in 3.31 seconds, including standalone lazy ShrinkExpand state/message
agreement, exact PRNG progression and full-digit LENC shape/determinism. GPU
identity/lazy-context and two-query GoldenSeed smoke pass in 3.25 seconds. No
benchmarks or WSL run.

Core sender-setup validation: Windows CUDA-enabled target and frontend example
verification pass (28.65 seconds). Three CPU checks pass in 3.28 seconds; GPU
identity/lazy-context and two-query GoldenSeed smoke pass in 3.45 seconds.
The Core transport fixture captures a Sender task before lazy start, executes
under Receiver ambience and verifies unchanged TLS plus existing exact-output
checks. No benchmarks or WSL run. The approximate overall estimate is 86%;
25 runtime declarations remain while the compatibility bridge is present.

Identity transport is explicit throughout setup, online Core/controllers,
materialization and construction. Public defaults are canonical-zero views;
owned asynchronous scopes retain their exact service before lazy start. The
identity getter, guards and TLS compatibility transport are removed. Synchronous
helpers borrow views, and numeric pool/row workers carry no identity context.
Constructors/prepare accept an explicit configure view; supplied factories remain
authoritative and reject a foreign nonzero service. Query scopes still qualify
the SID through their state factory, and zero sender-offline scopes still allocate
a fresh run. The remaining runtime declaration count is 24.

Numeric-sampler validation: Windows CUDA-enabled target and frontend example
verification pass (78.51 seconds). Three CPU checks pass in 3.35 seconds,
including exact sampling/PRNG/failure behavior and the LHE task-to-cache service
lifetime regression. GPU identity/lazy-context, two-query GoldenSeed smoke and
Gaussian prefix parity pass in 4.03 seconds (four tests). No benchmarks or WSL run.

Sender-entry/wire validation: Windows CUDA-enabled target and frontend example
verification pass (83.57 seconds). Four CPU checks pass in 3.63 seconds,
including recursive wire/evidence handling and two-query GoldenSeed. GPU
identity/lazy-context and two-query GoldenSeed pass in 3.29 seconds. Mode checks
prove foreign-service lazy capture rejects before PRNG use, canonical-zero
capture allocates the sender run from its configured service, and GPU execution
under third-service Receiver ambience leaves TLS unchanged. CPU mode operations
also run on the shared executor. No benchmarks, large reservation tests or WSL
run. The approximate overall estimate is 87%; 25 runtime declarations remain.

Online-leaf validation: Windows CUDA-enabled target and frontend example pass
(79.14 seconds). Four CPU checks pass in 6.39 seconds, including fused/separate
expansion equality; GPU identity, explicit materialization admission/output and
two-query GoldenSeed checks pass in 3.42 seconds. No benchmarks or WSL run.

Identity-closure validation: CUDA-enabled Windows library, tests and frontend
example build pass. Five CPU identity/setup/two-query/seeded-ZK checks pass in
11.41 seconds; three GPU identity/lazy/two-query checks pass in 2.36 seconds.
Native parity/rollback passes in 2.83 seconds with the bounded factory option;
production configure/fresh-run checks pass standalone in 25.67 seconds. Both
Root prefetch/hash CLI checks pass in 4.52 seconds. Six low-level key-derive,
party-cache, scalar-lifetime and public-retention checks pass in 12.64 seconds.
Retired identity getter,
guard, setter and TLS names have no source/test/frontend references. No
benchmarks, WSL matrix or leak validation was run in this batch. Earlier
validation entries above and below record historical migration checkpoints.

#### Remaining runtime globals

| Group | Count | Exact remaining objects | Intended owner/change |
| --- | ---: | --- | --- |
| Protocol run/role | 0 | None | Instance-owned services allocate qualified IDs; explicit operation contexts carry role/run identity and retain service lifetime. |
| Worker budget | 0 | None | Caller executors and explicit chunk allowances schedule primary async work. Synchronous GPU host work borrows exclusive, reusable CPU scratch from its operation/state owner. |
| Statistics | 0 | None | Optional execution-options sinks collect CPU and GPU counters/timings; per-chunk pending counters retain batching. Callers join work before reading/resetting sinks and keep sinks alive through context/stream teardown. GPU region timing totals belong to each `GpuStream`. |
| CUDA allocation evidence | 0 | None | Sender-owned shared sink; active wire blocks retain it through completion and release it before entering the reuse cache. CPU offline resets only its supplied owner. |
| Capability/compatibility caches | 0 | None | Device availability is captured at factory construction and forwarded to contexts and resource domains. Explicit standalone GPU owners discover once; `available()` is an uncached cold query. Gaussian compiler/libm facts belong to `GpuExecutionContext`, borrowed by its streams; direct streams own their cache inline. FP environment checks remain per-use. The legacy device-zero H200 prefetch flag belongs to `GpuExecutionContext`. |
| CUDA error/name storage | 0 | None | Kernel API failures throw owned error messages; device descriptions return owned strings. |
| CUDA attribute initialization | 0 | None | Seven lazy readiness flags belong to `GpuRing`/`GpuPlainNtt`; launch views borrow their owners' lifetime. |

Each stream reports its nonzero upload, kernel and download timing totals when
its owner is released, after draining queued work. Disabled region tracing adds no
allocation, synchronization or clock reads. The execution context captures
the existing device-zero H200 prefetch decision once, preserving that policy.

The main CUDA kernel API reports unexpected failures by throwing
`std::runtime_error` with the operation, numeric CUDA code, and CUDA message.
The allocator reports CUDA out-of-memory failures as `std::bad_alloc`, which
optional allocation paths catch to retain their fallback. Unsupported shapes
and invalid input still return `false`; benign host-registration declines keep
the unpinned fallback. Cleanup that cannot establish required completion fails
closed during destruction. This change does not migrate the separate CUDA ZK
kernel error policy.

Validation: the Windows build completed in 442.81 seconds, including the
focused tests, lifecycle target, and frontend object. All six GPU tests passed
with zero skips in 1.17 seconds; `GpuImmediateErrors` completed in 332 ms.
The lifecycle target was built but not executed. No leak validation,
benchmarks, or Linux validation was run for this change. The patch remains
uncommitted for review.

The declaration-level scan with source locations is in the local artifacts
`out/review/logvole-globals-inventory-current.{txt,json}`. The older files
without `-current` are historical, not the remaining-work list.

#### Remaining scheduling migration

The ambient scheduler and its global worker counter/TLS cap have been removed;
no library or test calls `runParallelTasks`. CPU proof phases and online kernels
await the caller executor with explicit numerical buffers and chunk allowances.
Synchronous GPU host numerical paths borrow exclusive state-owned
`CpuRowScratch` leases and reuse the existing bulk execution algorithm. An
explicit inner allowance of one prevents nested chunk pools. A failed item stops
its chunk; independent chunks still join before failure is returned. Golden-seed
validation retains its shared rejection flags and early skips.

GPU matmul host proofs use the primary async algorithm on the caller executor.
Their existing member numerical workspace is prepared only when an actual host
proof is required and reused on later checks. Successful device execution keeps
that workspace empty, and device-only failures remain fatal.

Setup message copying awaits direct `bulk_chunked` on the caller executor.
Synchronous setup-state copies and codecs borrow explicit operation/state
scratch. GPU D2H materialization borrows lazy execution-owned transfer scratch;
all host copy chunks join before pinned staging is reused. Serial work creates
no pool or partition-storage allocation. No scheduler resource is discovered
from thread history or a process-global budget.

The existing synchronous execution adapter in `CpuExecutor` remains for these
synchronous boundaries; primary async callers do not use it. Its macoro bulk
operation joins all borrowed work before returning, including on exceptions.

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

Multiplication-proof validation: CUDA-enabled Windows library/tests and public
example object build pass (initial code build 26.99 seconds, final test-only
incremental build 9.00 seconds). The async arithmetic/witness regression,
prepared execution lifetime regression and focused two-query GoldenSeed
multiplication protocol pass in 3.84 seconds; the async regression also passes
with two executor threads in 0.06 seconds. Checks use independent scalar witness
and proof-polynomial oracles; optimized/scalar settings; dependent/independent
layers; exact PRNG progression and invalid-layer failure state; repeated
workspace/output reuse; one/three requested workers; a one-worker cap accumulating
three original prover partitions; invalid shape/span rejection; and inline
execution without pool threads. The bundled `FreshMaskCpu` test exceeded a
60-second limit after the two arithmetic/lifetime tests had passed; it includes
six multiplication/matrix configurations and was not counted as completed
coverage. No GPU runtime, WSL, leak checks, or benchmarks were run.

Matrix-proof validation: CUDA-enabled Windows library/tests and public example
object build pass (27.96 seconds). The independent arithmetic regression and
focused two-query, three-repetition GoldenSeed matrix protocol pass in 4.64
seconds; the regression also passes with two executor threads in 0.04 seconds.
Checks cover scalar/vector settings, reused workspaces across two moduli and
challenges, noncanonical lazy-copy paths, requested three chunks under one/three
worker caps, independent scalar witness/product/proof oracles, PRNG progression,
output allocation reuse, invalid shape/challenge/buffer rejection without
publication, and an idle executor's inline path. GPU-selected public-object
preparation confirms both CPU workspaces remain empty, without GPU computation.
No broad matrix suite, GPU computation, WSL, leak checks, or benchmarks were run.

CPU callsite audit after matrix migration: the frontend has no multiplication or
matrix witness-generation or staged-key-release calls. These standalone
synchronous APIs remain legacy diagnostics/GPU fallback, alongside their async
alternatives. The synchronous rounding validators and `findGoldenSeed` are used
by GPU-gated legacy sender evaluation or exposed as diagnostic helpers; normal
CPU candidate evaluation calls its polynomial predicates directly under async
execution. Ordinary CPU root-key recovery now calls `detail::denoiseCombSerial`
directly, sharing the numerical preparation and row kernel with async denoise
and preserving the nonempty task-metrics scope. The internal GPU compatibility
denoise retains its existing serial/parallel execution behavior. Remaining CPU
cleanup covers diagnostic statistics defaults and synchronous diagnostic
scheduling. The explicit internal GPU compatibility boundary retains its
existing fallback scheduling and diagnostics; worker-budget globals still
support that legacy adapter. Protocol run/role identity is already explicit.

Final inline denoise cleanup: CUDA-enabled Windows library/tests/example-object
build passes in 27.13 seconds. Existing integer-rounding denoise and root-online
local-relation tests pass in 2.97 seconds. The direct requested-worker-one branch
preserves numerical order, publication and task metrics; the old serial adapter
had no separate statistics flush, so no flush semantics change. Globals remain
26 declarations and physical `runParallelTasks` sites remain 20; the normal
CPU root-key path now bypasses that adapter. No further ownership redesign was
implemented at this boundary.

Identity service stage one retains allocator lifetime explicitly in factories,
GPU setup/execution owners, public-cache entries, GPU retained public operands,
DeviceBatch provenance, native setup bundles, first-query plans, lazy host
materializers, setup-wire allocators/blocks/evidence and preregistration worker
captures. Borrowed ID views require one of these owners (or an owned operation
context) through use; numeric `configureCacheRunId()` is diagnostic projection,
while `configureCacheIdentity()` preserves service affinity. IDs are host-only;
no wire formats, CUDA kernel arguments or numerical kernels changed.

Identity-service validation: CUDA-enabled Windows library/test/example-object
build passes (66.91 seconds; final test-only incremental build 19.69 seconds).
The new service identity regression and existing two-query GoldenSeed CPU
protocol pass in 4.03 seconds. Coverage includes equal numeric IDs from separate
services with distinct cache keys, role separation, shared-service allocation,
concurrent allocation, retained/moved owner lifetime, canonical zero, cross-service
factory/execution admission rejection, and both synthetic and real sampling
lazy-task ownership after the caller's service/scope disappear. Completed task
frames intentionally retain their context until destroyed. No GPU computation,
WSL, broad suite or benchmarks were run for this stage.

Resource-construction validation: CUDA-enabled Windows library/tests and public
example object build pass in 66.11 seconds. The identity/lifetime regression and
two-query GoldenSeed CPU protocol pass in 4.07 seconds. New assertions construct
Ring/CRT factories and GPU setup/execution resources under an ambient sender
scope and confirm they allocate independent services unless explicitly supplied.
Default phase/factory entrypoints still select the expected sender role and
service by explicitly forwarding compatibility data. No GPU computation,
benchmarks, broad suite or statistics/worker-TLS changes were made. Remaining
runtime-global count stays 25; identity compatibility TLS is not yet removed.

Factory-forwarding validation: CUDA-enabled Windows library/tests and public
example object build pass in 60.92 seconds. Identity/lifetime, host backend-owner
metadata, and two-query GoldenSeed CPU protocol tests pass in 4.99 seconds. The
identity test selects explicit Receiver records under ambient Sender, reuses the
same ring/CRT cached records under an unrelated ambient service, checks combined
setup forwarding, and rejects foreign explicit services without changing output.
CRT affinity is checked before cache lookup, including cache hits. No GPU
computation, numerical/kernel changes, broad suite or benchmarks were needed.
Remaining runtime-global count is 25; identity TLS is still present at callers.

Public-cache validation: CUDA-enabled Windows library/tests/example-object build
passes in 88.98 seconds; final regression-TU rebuild passes in 19.18 seconds.
Identity/cache/lifetime, existing offline-setup execution, and two-query
GoldenSeed CPU protocol tests pass in 4.02 seconds. Explicit Receiver cache
access ignores contradictory ambient Sender services, reuses identical snapshots
for the same context, preserves A run partitioning and B host-only run-zero
sharing, and preserves exact sampled coefficients and role partitions. Existing
lazy sampler ownership checks continue to pass. No numerical/CUDA kernel,
PRNG-order, cache eviction/partitioning or exact retained-record behavior changed.
No GPU computation, broad suite, benchmarks, statistics or worker-TLS migration
was performed. Estimate stays 84%; runtime-global count stays 25.

Private-provenance validation: CUDA-enabled Windows library/tests/example object
build passes; the final corrected test-TU/link takes 20.13 seconds. Identity,
lazy setup lifetime and two-query CPU smoke pass in 4.05 seconds. The small GPU
private metadata regression passes in 2.10 seconds: explicit Sender scope wins
under an unrelated Receiver ambient scope, root secrets retain the existing
cross-run caller-role convention, top secrets retain strict run matching, and
repetition/root-error metadata reject wrong roles/runs. No numerical/kernel,
PRNG, cache partition, query-SID numeric binding or scheduling changes were made.
The first-query allocation worker retains its plan/service through its existing
joined lifetime without installing identity TLS. Its online run must belong to
the plan's retained service, preventing an unowned foreign-service ID escaping.
Canonical-zero offline IDs remain zero. Because that sentinel carries no service,
the plan retains the selected context's factory service, or its explicit GPU
setup/execution service when no factory exists; missing ownership rejects the
plan before its worker starts. This preserves same-service online admission
without allocating a replacement run ID or changing cache keys/numeric SID checks.

Remaining compatibility boundary: GPUProtocol.cpp has 14 current-scope reads
(including four transitional helper defaults), down from 38, and six guards,
down from seven. Ring.cpp has one transitional default read, down from four,
and seven existing setup/worker guards. New public trailing defaults still read
TLS at unmigrated upper callers; no removal of the identity TLS global is claimed.
GPU lazy host materializers and receiver/tree operation wrappers still validate
caller role and need an explicit caller-context interface; their existing guards
remain. Upper protocol/configuration/offline/online scopes, legacy synchronous
LHE/LENC tree/digest callers and remaining defaults are still transport boundaries.
The service and shared math records contain no mutable current-session state.
Estimate stays 84%; runtime-global count stays 25.

Lazy-host validation: Windows library/tests/example-object build passes; final
regression TU/link takes 23.90 seconds. The new N1024 production lazy seed-label
regression and existing small private-metadata GPU test pass in 2.34 seconds.
An explicit Receiver fails first materialization under Sender ambience; retry
with explicit Sender succeeds under Receiver ambience, matches CPU host-wrap
and repetition coefficients, and reuses the completed snapshot. Existing
identity/lifetime/offline-setup/two-query CPU tests pass in 3.96 seconds.
The role check remains inside `call_once`, preserving prior completed-snapshot
behavior. Failed device materialization falls back through the existing callback
with the caller view; no producer identity is substituted for caller admission.
No extra callback abstraction, scheduling, PRNG, arithmetic or kernel change.

This batch reduces Core.cpp current reads 13 to 10 and guards 29 to 26;
LogVole.cpp reads 13 to 12; Backend.cpp reads seven to five. GPUProtocol.cpp
remains at 14 reads/six guards: its first-query wrap default was removed, while
unmigrated plaintext-table callers temporarily use a new helper default.
Plaintext-table constructors now receive the explicit forwarded view. Remaining
receiver Ct1 lazy download/pipelined-copy and reusable device-cache wrappers
still have guards, as do upper phase operations. Randomizer device admission
and geometry-index cache role lookup also still acquire caller role through TLS.
Next: thread explicit context through those GPU wrappers/download boundaries,
then through upper protocol callers and remove compatibility defaults/TLS.
Estimate remains 84%, with 25 runtime globals pending the final TLS deletion.

Identity forwarding is complete, including construction/preparation, online
controllers, private metadata admission, and test helpers. Admission APIs require
explicit caller views; owned asynchronous scopes retain the exact service before
lazy start. Configure/offline run identity and qualified query-SID binding remain
distinct. Statistics and worker-budget TLS remain separate work.

Next steps, in order:

The caller-executor ZK witness/proof workspaces now prepare the explicitly
requested number of logical task slots, independent of hardware concurrency and
optional benchmark limits. Zero selects one task. Matrix-product calls reject
insufficient caller result slots before changing the output; they no longer
silently reduce the task count. The fixed caller executor may have fewer threads
than logical tasks. Reused arithmetic buffers and serial inline execution are
preserved. This is the first explicit-task-count scheduling step: the synchronous
witness compatibility overload still owns its legacy executor, and the shared
legacy/GPU scheduler still retains worker globals/TLS. No GPU scheduling changed.
The inventory remains 24 runtime declarations and the estimate remains 89%.
The Windows targeted build and frontend object compile pass in 81.96 seconds.
Five focused CPU checks pass in 0.23 seconds with one executor thread, including
three logical tasks, rejection, joins and reuse; CPU interactive golden passes
in 4.11 seconds. No benchmarks or GPU execution checks were run for this step.

The grouped follow-up removes diagnostic limits from existing asynchronous CPU
CRT wrapping/decoding, compact error sampling/replay, root-zeta, and independent
LENC/LHE setup phases. Explicit requested counts select tasks, bounded by useful
work; zero selects one. Insufficient caller storage rejects before PRNG or output
changes. Root-zeta retains its explicit seed layout. Sender seed evaluation uses
the supplied buffer span as its task allowance and forwards exclusive subspans
to nested work. Sequential shared-PRNG phases remain sequential by algorithm.
GPU-enabled compatibility caps and synchronous legacy schedulers remain; the
runtime declaration inventory remains 24 and the completion estimate remains 89%.
The Windows build completed with one incremental finish (182.13 seconds) after
the initial 240-second runner limit; all library and frontend objects had already
compiled without errors. Four focused CPU checks pass in 0.30 seconds with one
executor thread, including three logical tasks, sampler/CRT rejection, unchanged
PRNG progression, buffer reuse and joined failures. Small CPU interactive golden
passes in 3.91 seconds. No benchmarks or GPU execution checks were run.

The synchronous witness caller audit found only test fixtures and reference
oracles, with no production/frontend callers. The scalar witness entry point now
evaluates inline with the same independent-layer diagnostics and PRNG draws.
The threaded and prepared synchronous witness overloads and their hardware/
diagnostic worker policy are retired; CPU witness regression callers use the
existing caller-executor/workspace operation. Scalar GPU-reference fixtures are
unchanged. The workspace's legacy executor remains for GPU proof-response/value
fallbacks. This retires test-only witness scheduling policy, not a production
migration or a runtime-global declaration; the inventory remains 24 (89%).
The targeted Windows build/frontend target passes in 45.82 seconds. Three focused
witness/lifetime/proof checks pass in 0.31 seconds on one executor thread with up
to four logical tasks, including dependent layers, integer/PRNG oracles and
rejection parity. The small CPU asynchronous multiplication protocol passes in
5.57 seconds. No benchmarks or GPU execution checks were run.

The asynchronous CPU LHE statistics pilot accepts optional borrowed totals in
`LogVoleExecutionOptions::mRingOpsStats`; null disables ring-operation counting
for that path. Synchronous transform/chunk scopes own fixed pending counters and
flush before suspension or completion, including exceptional exits. No pending
sink remains in reusable arithmetic buffers. The same concrete collector backs
the legacy TLS compatibility path with the existing 256-count threshold. Reset
epochs now belong to each totals instance, so reset invalidates stale pending
counts independently, including destructor flush. Totals must outlive pending
collectors; reset/read follow joined producers. Context options copy the borrowed
selection; no numerical cache keys depend on it. GPU sources and timing remain
unchanged. Only the static reset epoch is retired: 23 runtime declarations remain
and the completion estimate stays 89%.
The single targeted Windows build/frontend target passes in 112.93 seconds.
Two focused LHE/fused regressions pass in 5.97 seconds, covering exact owned/null
counts, independent reset epochs, threshold/destructor flushing and compatibility
totals. Small CPU interactive golden passes in 3.92 seconds. No benchmarks or GPU
execution checks were run.

Asynchronous CPU truncated LENC evaluation now uses the same per-chunk pending
collector through leaf evaluation, the batched dyadic inner product and inverse
NTT. Ordinary coefficient/NTT evaluation and fused NTT subtraction explicitly
forward the selected owner or null; no collector or borrowed sink is retained in
reusable pointer lists. The existing 32-term arithmetic batches are unchanged.
Legacy scratch partitions retain their flush guard; non-scratch synchronous
evaluation flushes the caller at phase completion after temporary workers join.
No GPU source, scheduling or timing changes are included. This forwarding step
removes no declaration: the inventory remains 23 and the estimate remains 89%.
The Windows build/frontend target passes after an unchanged incremental retry
(82.97 seconds) of a transient MSVC C1090/PDB24 failure in `CpuScratch.cpp`.
Two focused LENC/LHE checks pass in 7.40 seconds, including exact independent
owner/null counts, all three output modes, three tasks on one worker and buffer
reuse. Small CPU interactive golden passes in 4.22 seconds. No benchmarks or GPU
execution checks were run.

The grouped setup-statistics pass forwards explicit pending counters through Ring
arithmetic, transforms, gadget operations and uniform/error sampling into live
CPU LHE/LENC setup and root setup/digest scopes. Public polynomial caches count
only actual generation; cache hits do not replay counts. Deferred host transforms
create their collector when materialization runs from the retained context's
borrowed totals selection. Synchronous chunk/serial scopes flush before joining
or suspension, and cached records never retain a pending pointer. GPU-compatible
paths retain their legacy selection; scheduling, PRNG order, arithmetic batching
and timing are unchanged. Standalone legacy APIs and later online arithmetic
families remain separate work. This forwarding pass removes no declarations:
the inventory remains 23 and the estimate advances to 90%.
The single combined Windows build/frontend target passes in 110.44 seconds.
Three focused CPU setup/LENC/LHE checks pass in 8.65 seconds, including exact
owned/null totals, cache generation/hits, unchanged PRNG progression and reuse.
Small CPU interactive golden passes in 5.13 seconds. The dedicated
`Core_RootOnlineLocalFlow` check passes in 2.62 seconds and directly exercises root
offline setup, receiver transforms and `prepareRootDigestReceiver`. No benchmarks
or GPU execution checks were run. Remaining active online receiver arithmetic,
timing ownership and legacy public surfaces require separate audits.

The CPU online statistics pass now forwards the selected borrowed totals or null
through Core root responses, sender seed evaluation, receiver root finalization,
ShrinkExpand expansion, LHE apply/derive/hash, nontruncated LENC evaluation and
recursive receiver shrink/aggregation. Each synchronous CPU phase owns its
pending collector and flushes before suspension or completion. The audit also
fixed the missed serial CPU Ct1 forward-transform loop in receiver offline
finalization. GPU-compatible/deprecated callers retain legacy defaults; GPU
sources, arithmetic, PRNG order, buffers, batching, scheduling and timing are
unchanged. No declarations are removed: the inventory remains 23 and the
estimate advances to 91%.
The combined Windows library/test/frontend build passes in 119.18 seconds.
The enhanced two-query root reuse check passes in 3.91 seconds, with independent
sender/receiver owners, a null reference receiver, producing-worker TLS flushes,
unchanged exact outputs and reusable allocations. Three CPU setup/LENC/LHE
regressions pass in 5.93 seconds; small two-query CPU interactive golden passes
in 4.41 seconds. The N1024 two-level socket fixture initially timed out because
it requested four tasks with three result/arithmetic slots after the earlier
strict admission change. Giving that fixture four exclusive slots preserves its
four-task seed layout. Its final test-TU/link rebuild passes in 30.24 seconds;
recursive relation and buffer reuse pass with one physical worker (0.51 seconds)
and two workers with alternate CPU options (0.40 seconds). No benchmarks or GPU
execution checks were run. Timing ownership, legacy public surfaces and final
cross-platform validation remain separate work.

CPU timing now accepts optional borrowed `TimingStats*` totals in
`LogVoleExecutionOptions::mTimingStats`. Null disables collection without clock
reads. CPU uniform samplers, wrap/unwrap, sender seed search and attempt counts,
root serialization/host phases, and sender/receiver transport waits select those
totals explicitly. Frame receive timing still covers only a successfully
received header; payload reception and decode remain outside that interval.
Bare key-derive APIs accept an optional borrowed timing pointer. Totals must
outlive their operations, including deferred work, and reads/reset follow joins.
GPU-selected contexts and legacy defaults retain global timing; CUDA sources,
arithmetic, PRNG order, batching and scheduling are unchanged.
The end-to-end check exposed a CPU root-operand preparation probe entering a
CUDA helper whose legacy timer started before its disabled-backend rejection.
The Core wrapper now rejects CPU execution before that helper, preserving its
false result and empty device output while avoiding those clock reads and
possible global writes. No declarations are removed: 23 remain and the overall
estimate advances to 92%. Active CPU timing paths are explicit; legacy public
statistics/default surfaces and GPU diagnostics still need their separate audit.
The combined Windows library/test/frontend targets pass after a serialized
incremental retry (39.78 seconds) following an MSVC compiler heap resource error
in an unchanged test translation unit. The final Core guard rebuild/link passes
in 17.22 seconds. Timer/transport ownership, two-query root reuse and N1024
recursive socket checks pass together in 4.40 seconds. The timer test verifies
independent/reset owners, disabled timers, role-specific waits and exclusion of
a controlled payload delay. Small two-query CPU interactive golden passes with
owned totals (4.24 seconds) and null totals (4.43 seconds); both preserve all 31
global timing fields, arithmetic and reusable storage. Sender seed-attempt
counts provide deterministic ownership evidence without duration thresholds in
the protocol checks. No benchmarks, GPU execution or WSL checks were run.

The grouped public-statistics pass changes 37 default collector arguments in
Ring/LHE/LENC/Core APIs to null. Omitting those arguments now disables counting;
callers requesting totals supply an explicitly borrowed `PendingRingOpsStats*`.
Every existing library caller of the initial 35 declarations already forwards
its selection explicitly. Header/inline and frontend/example audits found no
additional callers. The sender socket expansion round now forwards its selected
collector through both full and truncated key derivation, closing the two
remaining active CPU omissions in this batch. Its synchronous collector scope
ends before the next suspension. GPU-selected execution retains its explicit
legacy collector; no CUDA implementation, arithmetic, scheduling, PRNG order or
buffer layout changes are included.
The existing coproto fixture repeats full/truncated socket expansion with owned
and null sender totals on reused resources. It checks the exact key-derivation
multiplication contribution and unchanged legacy totals after caller/worker
flushes; each fixture has one physical executor worker. Existing LHE/LENC legacy
count assertions retain their internal explicit compatibility selection.
No global declaration is removed: the inventory remains 23 and the overall
estimate remains 92%. Public CPU compatibility is still incomplete: standalone
key-derive processing/finalization, root inner-product and synchronous seed-search
helpers, deprecated synchronous evaluation/decryption/expansion, and GPU setup/
lazy-host fallbacks retain legacy defaults or internal selections. Standalone
key-derive contexts have no supplied statistics owner yet; preserving their
counts requires explicit boundary plumbing rather than silently disabling them.
The ambient legacy worker scheduler and its blocking adapters remain separate
debt. These public CPU surfaces prevent claiming complete CPU global/TLS removal.
The single serialized Windows library/test/frontend-object build passes in
308.97 seconds. Five focused coproto ownership/reuse and LHE/LENC legacy-count
checks pass in 6.03 seconds; small two-query CPU interactive golden passes in
3.86 seconds. No benchmarks, GPU execution or WSL checks were run. Next: group
remaining standalone CPU diagnostic-boundary migration before another shared-
header build, preserving explicit legacy selections at deferred GPU boundaries.

The standalone CPU diagnostic-boundary pass adds an optional borrowed
`RingOpsStats*` after timing on sender/receiver key-derive coroutines. Their
synchronous processing/finalization accepts an explicit pending collector;
collectors leave scope before socket suspension. Root inner-product selects its
context owner, and synchronous golden-seed search accepts borrowed totals and
forwards its pending collector through setup, sampling and subtraction. Null
disables collection. Standalone frame receives now default to disabled timing;
production callers already select their timing explicitly. GPU key-derive and
root inner-product retain their explicit legacy diagnostic selections. No CUDA
implementation, scheduling, PRNG order, batching or buffer layout changes are
included. Golden-seed sampling remains serial despite its requested-worker
argument; candidate validation still uses its existing uncounted parallel work.
The declaration inventory remains 23 and the overall estimate advances to 93%.
Deprecated synchronous evaluation/decryption/expansion, GPU setup/lazy-host
fallback diagnostics, and ambient scheduling/blocking adapters remain open.
The serialized combined Windows library/test/frontend-object build first
regenerated 140 targets after Ninja reported an old build-log version. Its
600.02-second wrapper timed out after target 112; process checks confirmed all
build children had ended before continuation. The incremental continuation
passes in 235.50 seconds. Eight focused CPU key-derive core/socket, metadata and
oversized-frame rejection, root inner-product and golden-search checks pass in
1.89 seconds. They verify owned/null totals, exact key-derive counts, legacy
isolation and unchanged arithmetic; golden search also preserves output and
PRNG continuation. Small two-query CPU interactive golden passes in 5.17 seconds.
No benchmarks, GPU execution or WSL checks were run. Next: group the remaining
legacy synchronous CPU diagnostic surfaces, then address caller-owned scheduling
and matching buffers without changing deterministic task/seed layouts.

CPU synchronous-interface retirement: the twelve declarations listed above are
removed from normal headers. Existing async root finalization is available to
staged CPU callers with explicit executor/LHE/LENC buffers and a mutable response;
validation precedes seed/skPrime consumption. The shared async root-key phase
borrows the production context, preserving one context construction and the
existing arithmetic, batching, seed progression and explicit pending statistics.
GPU compatibility implementations remain internal, and their migration is deferred;
no CUDA implementation file or GPU scheduling policy changed. Targeted GPU
interface plumbing is authorized when it helps CPU cleanup or the later GPU pass;
GPU arithmetic and scheduling redesign remain deferred. Other synchronous
CPU diagnostic surfaces remain in golden validation/search, wrapping/unwrapping,
staged key release and ZK helpers. Worker-budget globals and blocking adapters
remain for those diagnostic and GPU boundaries. The inventory stays at **23
runtime declarations** and **20 physical `runParallelTasks` sites**; the approximate
overall migration estimate advances to **94%**.

The serialized CUDA-enabled Windows library/test/public-example-object build
passes in 410.97 seconds. Focused CPU groups cover independent LHE/LENC arithmetic
and integer-denoise oracles, LENC domains/reuse/admission/singleton cases, full and
truncated shrink-expand with sockets, root local flow/relation/reuse and two-level
local/socket relations, plus a small two-query interactive GoldenSeed run. The
first twelve-test kernel group passed eleven tests and exposed an existing test
fixture requesting four encoder chunks with only three result slots. A helper-local
four-slot array fixes that admission mismatch; its test-only rebuild passes in
10.50 seconds and isolated rerun in 0.45 seconds. All **25 distinct affected CPU
checks pass**: the other kernel checks took 8.23 seconds including the initial
failure, seven shrink-expand checks 0.88 seconds, five root checks 9.91 seconds,
and two-query GoldenSeed 4.02 seconds. No GPU execution, WSL, broad suite, leak
checks or benchmarks were run. Next: remove remaining CPU TLS diagnostic defaults
with explicit pending collectors, then finish the remaining diagnostic scheduler
boundaries while preserving GPU compatibility behavior.

The remaining implicit ring-statistics defaults are now explicit: 33 public
collector arguments default to null, and 31 private helper collectors are
required arguments. Context-owning CPU digest, socket shrink, root setup/noise
and lazy-host replay boundaries select their borrowed owner or null. The two
context-free seed-label decomposition/sampling helpers accept an optional
pending collector so explicit compatibility callers can retain their counts.
GPU compatibility entrypoints explicitly select legacy collectors; parallel
callbacks acquire them on their executing thread. Four calls in
`cuda/LogVoleGpuProtocol.cpp` now pass the existing legacy collector explicitly;
GPU arithmetic, scheduling, PRNG order and batching are unchanged.
Generic `CpuRowScratch` execution no longer flushes ring diagnostics. Counted
compact-noise replay owns one CPU collector per existing chunk, with a guarded
legacy flush only for GPU execution; uncounted callbacks need no flush. CPU
phases therefore leave unrelated pending legacy work untouched. The focused
statistics test covers omitted public arguments, an unflushed legacy sentinel,
configured/null digest owners, and serial/parallel compatibility counts using
CPU arithmetic. The combined serialized Windows library/test/frontend-object
build passes in 726.92 seconds. Four defaults/sentinel/setup and LHE/LENC
ownership checks pass in 9.08 seconds (the new compatibility/sentinel test takes
42 ms); eight root/local/reuse/recursive and socket checks pass in 15.37 seconds;
eight standalone key-derive/error, inner-product and golden-search checks pass
in 1.65 seconds. Small two-query CPU interactive golden passes in 5.84 seconds.
The source audit finds no remaining implicit TLS collector defaults. Explicit
legacy collectors remain in the GPU compatibility and lazy-host fallback
boundaries; those compatibility entrypoints can still execute CPU arithmetic.
The inventory remains 23 runtime-global declarations for retained GPU/legacy
work, and the rough overall estimate advances to 95%. Scheduling cleanup and
Linux/LSAN validation remain pending. No benchmarks, GPU execution tests or WSL
checks were run. Next: retire remaining synchronous ZK scheduling interfaces using
their existing async workspaces, then finish golden/reference and staged key
release boundaries.

ZK synchronous-interface retirement removes eight normal CPU interfaces using
the existing async workspace APIs. Four unused synchronous definitions are deleted:
matrix product/witness and scalar matrix prover/verifier wrappers. Four required
GPU host-fallback definitions remain internal, each reached by one production
caller behind its existing GPU guard. The multiplication workspace grants private
access through two narrow detail friends; no accessor or execution wrapper is
added. Fixed arithmetic partitions, reduction order, challenge/RNG progression,
workspace layouts and GPU scheduling are unchanged. Serial multiplication witness
and matrix witness-input helpers remain ordinary arithmetic. The inventory stays
at **23 runtime-global declarations**; deleting the unused product scheduler
reduces physical `runParallelTasks` sites from 20 to **19**. The rough overall
completion estimate advances to **96%**.

The serialized CUDA-enabled Windows library/test/public-example-object build
passes in 240.14 seconds. Four CPU workspace/lifetime/reference/async proof checks
pass in 0.35 seconds; matrix independent repetitions/reconfiguration pass in
18.63 seconds; both async proof protocols pass in 8.54 seconds. Fresh-mask CPU
coverage retains all six GoldenSeed/NoGoldenSeed and multiplication/matrix-one-
repetition/matrix-three-repetition cases. Its existing `lvFactoryFast` test mode
now selects two queries and two logical workers while default/GPU coverage remains
unchanged. The original 60-second aggregate run timed out without an assertion
failure. Temporary stage markers showed all three GoldenSeed cases finishing in
about 11.3 seconds and NoGoldenSeed cases taking roughly 21 seconds each, with
progress through configure, offline and each query. After removing the markers,
the final test-only rebuild passes in 11.22 seconds and the complete fresh-mask
check passes in **72.79 seconds** under a measured 100-second bound. All **nine
focused CPU checks pass**. No GPU execution tests, benchmarks, WSL or host-leak
checks were run. Next: retire the public synchronous `sampleRootZeta` and
`sampleRootZetaFromTaskSeeds` interfaces (production CPU already uses async), then
close synchronous wrapping/unwrapping, staged key release and golden/reference
scheduling boundaries. Follow with the Windows/WSL ownership and host-leak
milestone gate.

CRT/staged-release retirement removes the normal synchronous wrap/unwrap
interfaces and converts `civoleSenderReleaseK` to an explicit-executor task with
caller-owned decode buffers. CPU tests reuse those existing async algorithms;
the input-wrap oracle still encodes each ring independently with `wrapZpBatchCrt`,
and scalar-capability decode plus known labels remains the output oracle.
Mixed GPU/lightweight tests select the internal compatibility implementations
explicitly. No arithmetic, batching, GPU scheduling or cache generation is added.
A real small GoldenSeed offline/root exchange establishes the staged key cache;
the new test checks cold SID establishment, empty/insufficient decode buffers,
unchanged cache/unused SID/output on admission failure, scalar output agreement,
metadata and used-SID publication exactly once, replay rejection and cached PRNG
stability.

The serialized CUDA-enabled Windows library/test/public-example-object build
passes in **278.18 seconds**. All **nine focused CPU checks pass**: staged release
1.94 seconds; async wrapping/unwrapping and leaf decoder/product checks 31.20
seconds; root reuse/SID validation 7.74 seconds; small GoldenSeed/noninteractive
mode checks 19.38 seconds. The large hardcoded noninteractive public-key test and
heavy GPU/lightweight context matrix were compiled, without running them. No GPU
execution tests, benchmarks, WSL or host-leak checks were run. The inventory stays
at **23 runtime-global declarations** and **19 physical legacy parallel sites**;
the rough overall completion estimate remains **96%**.

Remaining CPU closure includes golden/reference scheduling and the shared CUDA
allocation-evidence reset still reached
by CPU offline start. Windows/WSL ownership and host-leak milestone validation
remain pending. Validation also depends on the local macoro coroutine/bulk and
lifetime changes: publishing/pinning that dependency revision and verifying a clean
dependency fetch remain final integration work.

Golden validation/search now exposes three explicit-executor task interfaces
with a caller-supplied partition count. One shared CPU validator uses indexed
`all_of` with a sized `std::views::iota` descriptor; it no longer borrows unrelated
LHE scratch. Null diagnostics adds no task/clock scopes. Enabled diagnostics uses
immovable per-partition telemetry values with lazy timing/task scopes, destroyed
before partition completion. Two synchronous validator bodies remain internal for
four GPU fallback calls; no synchronous search copy remains. Candidate rejection
is distinct from operation failure, and invalid/zero-task admission leaves outputs
unchanged. Search retains serial sampling/subtraction, one 16-byte seed per
completed attempt, the 100-attempt limit and publication only on acceptance.
Explicit statistics collectors flush before each validation await. No arithmetic,
seed layout, GPU scheduling or dependency publishing changes are included.

The initial serialized Windows library/test/public-example-object build passes in
280.93 seconds. Validation/search/totals/PRNG-continuation/telemetry checks pass in
1.68 seconds; the plaintext-product check passes in 2.42 seconds; small two-query
CPU GoldenSeed passes in 3.86 seconds. Early/full evaluation initially hit the
60-second cap because its existing socket helper supplied three zeta buffers to
the four-task case. The receiver's admission failure left its peer awaiting the
missing message. The helper now sizes only zeta storage to the maximum declared
receiver-chain task count, retaining the intentional three-slot LHE/LENC allowance.
No socket/cancellation machinery changed. The fixture/header-documentation rebuild
passes in 369.06 seconds and the complete one/two/four-task early/full comparison
passes in **4.84 seconds**. All **six focused CPU checks pass**. No GPU execution,
benchmarks, WSL or host-leak validation ran. The rough completion estimate advances
to **97%**; the retained runtime-global inventory and physical GPU compatibility
scheduler sites are unchanged. Remaining closure includes the shared CUDA evidence
owner/reset still reached by CPU offline setup, Windows/WSL ownership and host-leak
checks, and clean dependency integration/publishing of the local macoro revision.

Root CUDA allocation evidence is now explicitly owned. High-level senders retain
one reusable shared sink; low-level offline callers supply an owner captured by
value through completion. Reset/note/snapshot operations select that sink and its
qualified run ID. Active wire allocations retain the sink; completion checks the
live in-range block and matching run, and release drops ownership before block
reuse. The shared mutex/snapshot globals are removed, including the reset formerly
reached by CPU offline start. Pool-to-evidence is the only nested lock order.
Existing GPU allocation/download behavior is unchanged.

The serialized CUDA-enabled Windows library/test/public-example-object build
passes in **417.90 seconds**. Five registered CPU checks pass: the new host-pool
owner/run/completion/reuse/lifetime regression (0.14 seconds), pinned-wire ownership
and two-level protocol/isolation (0.56 seconds), the actual grouped message-round-
trip registration `Encoding_AllMessageRoundTrips` (0.69 seconds), and small two-query
GoldenSeed with sender-owner move/clear checks (4.18 seconds). The initial round-
trip leaf name was not a registration; its grouped registration was then run
explicitly. No GPU execution, benchmarks, WSL or host-leak checks ran. Removing the
two evidence globals reduces the runtime inventory from **23 to 21 declarations**;
the approximate overall estimate advances to **98%**. Remaining milestone work is
Windows/WSL ownership and host-leak validation, the deferred GPU/legacy global
ownership work listed above, and clean macoro dependency integration/pinning. No
dependency publication is included.

1. Migrate the remaining CPU scheduling paths to caller-supplied fixed executors,
   explicit task counts and matching buffers, then move pending diagnostics into their
   operation/resource owners. Retire `CpuRowScratch` scheduling and legacy
   overloads when their GPU/fallback/diagnostic callers are gone; do not treat
   physical legacy sites as unmigrated production CPU phases.
2. Remove the remaining global groups above in separate ownership changes.
   Small independent groups need not wait for all scheduling work to finish.

The object-owned `ShrinkExpandScratch` leases and GPU worker maps are not
globals. Redesigning them is separate work, not a prerequisite for eliminating
the remaining ambient state. Socket detached-send semantics remain out of scope.
Use fast focused tests per coherent step; broader cross-platform/leak checks
belong at milestones. No benchmarks are needed for this migration.

Zeta interface retirement removes the normal synchronous `sampleRootZeta` and
`sampleRootZetaFromTaskSeeds` APIs. GPU compatibility retains their exact bodies;
the exceptional CPU seed-only finalization replay also uses that shared kernel
with one worker, inline without a pool. Ordinary CPU callers use the existing
async executor and prepared zeta buffers. Tests retain independent scalar draws,
serial compatibility seed replay, exact parent PRNG continuation, all five wide
sampler widths, rejection, resource admission and reuse checks.

The resumed serialized Windows library/test/public-example-object build passes
in **179.70 seconds** against local macoro **`3f3de08`**. All **four focused CPU
checks pass in 4.22 seconds**: root-zeta shape/bounds, offline setup execution,
root state reuse across queries, and failure joining children. The dependency
revision remains local and was not published. No GPU execution, benchmarks, WSL
or host-leak checks were run. The estimate remains **96%**; golden/reference
scheduling, allocation-evidence ownership and final milestone validation remain.
### CPU ownership and host-leak milestone

The current source checkpoint `58ed36fd` passes the Windows functional gates
recorded above and a fresh Ubuntu 24.04/GCC 13 C++20 build with standalone
LeakSanitizer. The initial `/mnt/c` build was interrupted, then deliberately
stopped during its continuation after measured Plan9 filesystem stalls. An exact
source/cryptoTools snapshot (checksum comparison found no differences), reviewed
Linux dependencies, install files and CUDA toolkit were copied to native ext4;
no previous build objects were reused. Native configure passed in **10.02 seconds**
and the two-worker build passed in **546.89 seconds**.

The executable loads `liblsan`; an intentional unreachable 137-byte allocation
reported one leak and exited **23**. With
`LSAN_OPTIONS=exitcode=23:leak_check_at_exit=1` and no suppressions, all **22
registered CPU checks passed**, each process exiting zero without a leak report:

| Focused group | Checks | Seconds |
| --- | ---: | ---: |
| Evidence ownership, explicit statistics/timing, identity, setup/lifetime/join | 7 | 0.22 |
| Async LHE/LENC, CRT wrapping/decoding and ZK workspaces | 7 | 0.42 |
| Root-zeta/reuse, golden validation/search, staged release and recursive setup | 6 | 14.21 |
| Small two-query GoldenSeed and noninteractive modes | 2 | 8.17 |

The isolated native macoro build also passes its seven focused `all_of`
lifetime/allocation checks under the same LSan settings (28.48-second build;
CTest 0.03 seconds, exit zero with no leak report).

This gate covers unreachable host allocations at process exit. It is not an
AddressSanitizer check, a native Windows leak check, or a GPU memory/leak test.
CUDA was compiled and linked because the focused target requires it; these
checks selected CPU execution only. No benchmarks or broad GPU fixtures ran.
The normal CPU resource/diagnostic ownership milestone is validated. The source
audit found no environment reads, `__int128` arithmetic, hidden executor creation
or internal blocking waits on normal CPU paths; the retained one-worker seed
replay runs inline. Explicit GPU compatibility/diagnostic APIs can still execute
host arithmetic and retain their deferred ambient behavior. **21
GPU/explicit-compatibility global declarations** remain deferred. Validation
requires the reviewed local macoro revision
`feea851f3bda2bdc80993252144fd38a46acca85`, pinned explicitly during configure;
it was not published, so this does not establish clean-clone reproducibility.
Detailed configure/build/control and per-group logs are retained in ignored
`out/review/cpu-owned-*` artifacts. The native executable remains under
`/root/logvole-cpu-lsan-58ed36fd` in the Ubuntu 24.04 WSL distro.

### Production option cleanup

The first production cleanup removes five baseline selectors: the three CPU
kernel switches and the two memcpy codec switches. Established optimized paths
are standard. The endian-safe fallback, alias handling, and general APIs remain;
this changes neither protocol bytes nor arithmetic.

The transport cleanup makes owned setup/root sends and root-message moves
standard, preserving the existing GPU-only eligibility for moving received
offline state. It removes the disabled root pin-overlap and CUDA-owned/early
allocation experiments and their evidence plumbing. Codec workers use the
configured thread count under the existing GPU eligibility policy. Eligible
little-endian GPU transport receives retain encoded tensors; CPU and other
endian hosts retain eager decoding. Direct decode APIs remain eager. The root
digest hash follows the existing deferred transport schedule, while direct/Core
callers retain their eager default. Protocol bytes and arithmetic are unchanged.

Only three wire-memory controls remain under `mAdvanced.mTransport`: `mPinned`
selects host registration, `mDirectDownload` permits device downloads into wire
storage, and `mHugePages` permits huge-page advice for large eligible buffers.
These control supported allocation/transfer tradeoffs. Ordinary wire-pool
pinning, allocation-failure fallback, and direct transfers remain; none of these
controls changes protocol bytes.

The top-level CPU cleanup removes partial-root geometry support and the early
golden-check override. Production root geometry remains required. Early golden
checking follows its existing automatic one-to-four-worker eligibility policy;
the full path remains where that policy requires it. Together, these cleanups
remove 20 selectors: 15 transport selectors, three CPU-kernel selectors, and two
top-level selectors. Broader GPU option cleanup remains separate.

The first GPU cleanup batch removes six unused kernel selectors: four H200
sampler selectors and two rejection selectors, plus their validation/equality
plumbing. Repository-wide searches found no consumers outside the options
header. Active kernel options, dispatch, and arithmetic remain unchanged.

The isolated GPU experiments are removed: eight protocol selectors for Root
direct upload, host-key residency/preupload, the operand-residency alias, GPU
digest hashing, CT2 prefix caching, and receiver shrink tiling/count, plus the
Root digest warp kernel selector. Established upload, host digest, prefix upload,
and single-stream shrink paths remain. SK/DPrime residency and fresh device-key
sampling retain their existing controls. This source cleanup changes neither
protocol bytes nor kernel arithmetic. Validation: the Windows CUDA test target
and frontend object build passed, and all eight focused GPU tests passed with
zero skips in 18.43 seconds; the leak-check script passed Python syntax checking.

Each GPU ring/plaintext-table owner now owns its seven lazy kernel-attribute
readiness flags; launch views borrow that state with the device tables. Warm
dispatch reads one atomic flag; cold initialization locks, checks the captured
device, and publishes readiness only after success, allowing retries on failure.
Views retain the existing matching-device/primary-context/stream lifetime contract;
device reset invalidates their owning tables and initialization state together.

Validation: the serialized Windows VS 14.50 CUDA build and frontend example
compilation passed. The five focused GPU checks (kernel options, two-tile parity,
NTT round trip, memory-pool lifecycle, and party-cache separation) passed with
`-gpu 1 -lvFactoryFast 1`: five passed, zero skipped; no benchmarks were run.

The hi208 GPU cleanup fixes the established Garner-14, fold-3, schedule-0 paths
and removes their three selectors and unused alternatives. Prepared constants
retain the 80-double table; missing constants retain the former Garner-4
fallback. The existing geometry, modulus, and hardware eligibility gates remain.

Validation: the serialized Windows VS 14.50 CUDA test target and frontend object
build passed, and an isolated SM90 kernel-object compile passed. Six focused
checks passed with zero skips in 6.56 seconds using `-gpu 1 -lvFactoryFast 1`,
including exact CPU-oracle hi208 parity with prepared and missing-table views.
The local RTX 4060 exercised general dispatch; H200 runtime paths were not
executed. No benchmarks were run.

The H200 pointwise cleanup removes the arithmetic and thread-count selectors,
retaining arithmetic mode 3 with 256 threads for the four established indexed
inner-product operations. Hardware, modulus, flag, and alias eligibility gates,
the nullable reciprocal table, and general fallbacks remain unchanged. The
broader pseudo55 selector remains outside this batch.

Validation: the serialized Windows VS 14.50 CUDA test target and frontend object
build and isolated SM90 kernel-object compile passed. Four focused checks passed
with zero skips in 11.69 seconds using `-gpu 1 -lvFactoryFast 1`. Direct scalar
CPU-oracle checks cover all four operations, a general indexed fallback,
canonical operands, noncanonical 52-bit-shape operands, and missing constants.
The local RTX 4060 did not execute H200 runtime paths; no benchmarks were run.

The H200 accumulator cleanup removes six tuning selectors and their unused
alternatives. The established packed-pointer, explicit carry/borrow, load-3 path
and independent non-pseudo52 Barrett path remain, with automatic tile counts and
the existing geometry, modulus, and hardware gates.

Validation: the Windows VS 14.50 CUDA test target and frontend object build
passed with two build workers, and the isolated SM90 kernel-object compile
passed. Two focused checks passed with zero skips in 11.59 seconds using
`-gpu 1 -lvFactoryFast 1`. The direct sixteen-output scalar CPU-oracle case covers
both retained accumulator paths on supported H200 hardware. The local RTX 4060
verified admission decline and the protocol fallback; it did not execute the
H200 fused oracle. No benchmarks were run.

The outer-reuse cleanup removes the default-disabled H200 selector and its ten
experimental variants. Active pseudo55 row-reuse paths, their caller APIs, and
the indexed-product fallback remain unchanged.

Validation: the Windows VS 14.50 CUDA test target and frontend object build and
isolated SM90 kernel-object compile passed. Two focused checks passed with zero
skips in 11.58 seconds using `-gpu 1 -lvFactoryFast 1`. H200 runtime execution
was unavailable locally. No benchmarks were run.

The H200 forward NTT cleanup fixes the production FP52 schedule for in-place,
plain-broadcast, and centered-limb inputs, removing three tuning selectors and
opt-in forward root packing. Inverse root packing remains enabled by the
`mNoGoldH200InversePackedRoots` boolean, with inverse tables and fallbacks intact.
The 16384/rho8 setup arenas shrink by 1 MiB each; other raw geometries retain
their existing metadata headroom.

Validation: the Windows VS 14.50 CUDA test target and frontend object build and
isolated SM90 compile passed; all three retained FP52 input-mode symbols were
verified in the SM90 object. Three focused checks passed with zero skips in
15.10 seconds using `-gpu 1 -lvFactoryFast 1`. The RTX 4060 ran in-place,
out-of-place, and centered generic parity against CPU transforms. The 16384
plain-broadcast path correctly declined locally; its direct parity and the FP52
batch-threshold cases require H200 hardware and were not executed. No benchmarks
were run.

The inverse FP52 cleanup removes nine tuning selectors, unused schedules, and
the single-tile FP52 family. Four production two-tile variants remain: narrow
1024-thread cache-stage-1 kernels with packed or unpacked roots, and wide
512-thread cache-stage-2 kernels with packed interleaved prefetch or unpacked
roots. Admission retains the 64-block or twice-SM-count rule, runtime pre/post
operations, nullable inverse roots, and the existing generic and integer paths.

Validation: the Windows VS 14.50 CUDA test target and frontend object build and
isolated SM90 compile passed; all four retained kernel entry symbols were
verified in the SM90 object. Three focused checks passed with zero skips in
16.64 seconds using `-gpu 1 -lvFactoryFast 1`. Local RTX 4060 tests checked generic
inverse results against CPU transforms with runtime operations and native/null
root views. H200-only threshold cases were added but were not executed locally.
No benchmarks were run.

The integer H200 NTT cleanup removes seven tuning selectors while retaining
paired 512-thread large-batch forward paths, the 1024-thread small plain-broadcast
path, and aligned direct/paired versus unaligned shared-input inverse paths.
Generic transforms, FP52 schedules, and their eligibility gates remain intact.

Validation: the Windows VS 14.50 CUDA test target and frontend object build and
isolated SM90 compile passed. Six retained integer kernel entries and the FP52
entries were verified in the SM90 object. Three focused checks passed with zero
skips in 20.72 seconds using `-gpu 1 -lvFactoryFast 1`. The RTX 4060 executed
53-bit generic forward/centered CPU-oracle parity and inverse Add/Negate parity
with aligned, one-word-shifted data, and one-word-shifted pre-input views.
H200 integer execution and the 16384 plain-broadcast path remain conditional
and were not executed locally. No benchmarks were run.

The log13 cleanup removes three default-disabled experiments: forward direct
store, centered diagonal identity, and small inverse direct store. Their
exclusive template arms and attribute setup are removed. Default small inverse
dispatch and the active inverse direct-store paths remain unchanged.

Validation: the Windows VS 14.50 CUDA test target and frontend object build and
isolated SM90 compile passed. Retained generic forward and H200 kernel entries
were verified in the SM90 object. Three focused checks passed with zero skips
in 19.61 seconds using `-gpu 1 -lvFactoryFast 1`. H200 runtime execution remains
untested locally. No benchmarks were run.

The log13 forward cleanup fixes five fusion choices to their production defaults
and removes three exclusive alternative kernels. Required non-1024-thread,
generic-geometry, and H200 paths remain unchanged. Direct coverage now checks
in-place, out-of-place, plain-broadcast, centered-limb, and single-limb gather
entries against CPU transforms, including permutations and centering boundaries.

Validation: the five-entry CPU-oracle test passed on the RTX 4060 before pruning.
The final Windows VS 14.50 CUDA test target and frontend object build and isolated
SM90 compile passed, with retained kernel entries verified in the SM90 object.
Four focused checks passed with zero skips in 20.17 seconds using
`-gpu 1 -lvFactoryFast 1`, including the same direct oracle after pruning.
H200 runtime execution remains untested locally. No benchmarks were run.

The ordinary log13 inverse cleanup fixes five fusion controls to their
production defaults and removes three unreachable fixed-kernel instantiations.
Both alpha schedule families, the 256-block threshold, runtime operations,
non-simple indexing, and common-thread/geometry fallbacks remain intact.

Validation: the new direct CPU-oracle test passed on the RTX 4060 before and
after pruning at 63, 64, and 65 polynomials, with indexed inputs, Add/Sub pre-ops,
and Add/Negate/ReverseSub post-ops across both schedule families. The final
Windows VS 14.50 CUDA test target and frontend object build and isolated SM90
compile passed; six hot and eleven fixed inverse entries were verified in the
SM90 object. Four focused checks passed with zero skips in 29.68 seconds using
`-gpu 1 -lvFactoryFast 1`. H200 runtime remains untested locally. No benchmarks
were run.

The log13 tree inverse cleanup removes four dispatch switches and the exclusive
rollback kernels and initialization state. Five production kernels remain:
pseudo55 alpha-two vector/scalar product paths, the other-alpha warp path, and
simple/non-simple generic fused-first-stage paths. Admission and alignment
fallbacks remain unchanged.

Validation: the direct five-kernel CPU oracle passed on the RTX 4060 before
pruning in 4.31 seconds. The final Windows VS 14.50 CUDA test target and frontend
object build and isolated SM90 compile passed; all five retained tree entries
and absence of the removed rollback entries were verified in the SM90 object.
Three focused checks passed with zero skips in 57.70 seconds using
`-gpu 1 -lvFactoryFast 1`, including the direct oracle after pruning. These are
correctness checks, with no performance claim. H200 runtime remains untested
locally. No benchmarks were run.

Scatter and sparse NTT dispatch now follow their established defaults without
the two local selector switches. Functional admission checks and protocol
controls remain unchanged. Direct coverage checks fixed and generic scatter,
single-limb output, partial plain/garbled labels, and both NoZero arithmetic
paths with the mandatory sparse gadget consumer; complementary zero/sentinel
limbs and packed digits are checked explicitly.

Validation: both direct CPU-oracle tests passed on the RTX 4060 before pruning.
The final Windows VS 14.50 CUDA test target and frontend object build and isolated
SM90 compile passed, with retained scatter, sparse, tree, and H200 entries
verified in the SM90 object. Four focused checks passed with zero skips in
30.59 seconds using `-gpu 1 -lvFactoryFast 1`. H200 runtime remains untested
locally. No benchmarks were run.

Common NTT dispatch now uses the established transform widths, inverse block
threshold, and hardware-selected H200 paths without eight tuning controls.
Functional geometry, alignment, modulus, and resource fallbacks remain intact.
Scale/round arithmetic controls remain available; direct scale/NTT/gather
coverage checks their retained paths against the public CPU unwrap operation,
including partial two-chunk output and slot-map availability.

Validation: the scale-gather oracle passed on the RTX 4060 before pruning. The
final Windows VS 14.50 CUDA test target and frontend object build and isolated
SM90 compile passed, with retained NTT entries verified in the SM90 object.
Nine focused checks passed with zero skips in 51.23 seconds using
`-gpu 1 -lvFactoryFast 1`. H200 runtime remains untested locally. No benchmarks
were run.

Shared log13 NTT dispatch now follows its production specialization, indexing,
vector-load, inverse specialization, and direct-store defaults without five
selector switches. Required generic geometries, runtime operations, alignment
fallbacks, sparse zero/NoZero contracts, and table ownership remain intact.

Validation: the final Windows VS 14.50 CUDA test target and frontend object
build and isolated SM90 compile passed. Retained NTT families and absence of
obsolete alternatives were verified in the SM90 object. All nine focused NTT
checks passed with zero skips in 55.80 seconds using `-gpu 1 -lvFactoryFast 1`.
The goal-scope audit found no remaining implementation work for this cleanup.
H200 runtime remains untested locally. No benchmarks were run.
