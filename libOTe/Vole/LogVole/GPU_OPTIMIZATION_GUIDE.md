# LogVole GPU optimization guide

Start with the kernel that runs for the workload you want to improve. Trace the public operation through `cuda/LogVoleGpuProtocol.cpp` and the launch function in `cuda/LogVoleGpuKernels.cu`. Record the ring geometry, modulus bounds, layout, aliasing, available tables, and selected device. A test can pass through a fallback, so include evidence of which kernel ran.

The protocol uses polynomials of degree less than `N` over an RNS basis of `rho` moduli. A batch in the coefficient domain stores data in polynomial, limb, and coefficient order, with the coefficient index contiguous. NTT views also carry representation and ordering assumptions. Verify the layout at both the producer and consumer before changing how a kernel loads or stores it.

## Hardware and dispatch

Build for architecture 89 on an RTX 4090 or RTX 4060, and for architecture 90 on an H200. The H200-specific routes require the device name to contain `H200`, compute capability major version 9, and at least 128 KiB of opt-in shared memory per block. `prepareKernelDispatch` captures those facts in the ring's launch view. Use an actual H200 to exercise those routes. H100 and other SM90 devices can validate compilation and generic CUDA paths.

| Operation | Production routes and tests |
| --- | --- |
| GoldenSeed transforms and indexed arithmetic | The `N=8192`, `rho=4` routes include fused forward and inverse operations, sparse inputs, scatters, and tree evaluation. The pseudo55 arithmetic requires each modulus to lie strictly between `2^55 - 2^21` and `2^55`. The outer product reuses rows at widths 8 and 16 with either pseudo55 or general reduction. Widths 32, 64, and 128 require pseudo55. Keep the general transform and modular arithmetic for other admissible views. |
| H200 forward NTT | `log14H200Shape` requires `N=16384`, `logN=14`, and `rho=8`. The FP52 path has distinct in-place, centered-limb, and plain-broadcast input modes. Keep the paired integer schedules and the small plain-broadcast route. Check `launchNttForward*` for the batch, modulus, and input-view predicates for each entry point. |
| H200 inverse NTT | The two-tile FP52 specialization requires moduli strictly between `2^51` and `2^52` and no fused inner product. Below twice the SM count, the narrow route requires at least 64 polynomial-limb blocks and uses 1024 threads. The wide route uses 512 threads. Test both with packed roots and a view without packed roots. Keep runtime pre/post operations and the integer paths for aligned and unaligned inputs. |
| H200 expansion accumulator | The specialized route requires 16 rows per chunk, eight tree terms, and a nonzero output count divisible by 16 and at most 65535. Its structural bound is `q < 2^60` for each modulus `q`. The packed pseudo52 path requires every `q` to lie strictly between `2^52 - 2^24` and `2^52`. The specialized Barrett route covers the remaining admitted moduli. Keep the automatic tile count and the generic accumulator. |
| Gadget decomposition and pointwise products | Prepared constants enable specialized arithmetic. Exercise views with and without those constants using the actual modulus metadata. Keep bit-width and canonicality admission checks at the dispatch boundary. |

Run the direct tests listed in `libOTe_Tests/LogVole_Tests.h`. Start with `NttTwoTileInPlaceParity`, `AccumulatorParity`, `GadgetParity`, `PointwiseOuterParity`, and the relevant `NttLog13*` tests. For H200 inverse selection, use the existing `mNoGoldH200InverseOpTrace` diagnostic or inspect kernel names in a separate CUDA trace. Record the observed kernel for each hardware-specific case. A standalone SM90 object establishes compile coverage.

The recursive sparse leaf path commits to a sparse consumer. Before launching `tryLaunchNttInverseRecursiveLeafSparseNegateNoZero`, the caller checks `canLaunchGadgetDecomposeHi110RecursiveLeafSparsePair`. The producer leaves the complementary limbs unwritten. After this producer runs, the paired sparse consumer is mandatory and its launch failure must propagate. A dense consumer would read the unwritten limbs. `NttLog13SparseParity` checks the active limbs, preserves sentinels in the complementary limbs, and compares the paired decomposition with its CRT reference.

The remaining kernel options cover diagnostics, data layout, and optional dispatch or cache policy. `mNoGoldH200InverseOpTrace` enables inverse operation diagnostics. `mNoGoldH200InversePackedRoots` controls allocation and use of packed inverse roots. `mFusedIp` selects an inner-product fusion path and affects protocol dispatch. The H200 root L2 policy uses `mNoGoldH200RootL2Mode` for direction, `mRootL2MiB` for set-aside size, and `mRootL2HitPercent` for the access-policy hint. Device support and table availability still determine whether persistence applies.

## Exact sampling

Seed derivation and sampling are part of the reproducible protocol computation. Use the same fixed seed and public inputs when comparing coefficient vectors or protocol bytes. Preserve every domain label, field width, byte order, counter, and acceptance condition.

- **CT2.** The 16-byte seed route hashes the session identifier, row count, 64-bit instance index, seed length, digest hash, and seed bytes under the CT2 instance label. Each polynomial then hashes its instance seed, domain tag, row index, ring degree, and modulus count. The resulting 128-bit block keys AES. Four counter blocks, numbered zero through three, produce the eight words of the SEAL seed. The split path expands keys with 32 threads per block and encrypts with 128. The shared S-box path requires a positive multiple of 32 polynomials. Other totals use the ordinary encryption path. `GpuCt2SeedAesParity` checks 31, 32, and 33 polynomials against a CPU oracle, plus 16- and 17-byte seed inputs at the sampler interface.
- **Root zeta.** Each polynomial is split into ranges of `ceil(N/rangesPerPoly)` coefficients. Each range has a separate PRNG seed and ends at the polynomial boundary if needed. Both GPU sampling kernels use 256 threads per block. The GoldenSeed path draws 111 bits from one AES counter per candidate. The NoGoldenSeed path draws 209 bits from two consecutive counters per candidate. Each rejects the all-ones field and subtracts `2^g - 1` from accepted values, where `g` is 110 or 208. Reduce that signed integer canonically in each limb. If a candidate is rejected, repair begins at the first rejected candidate, consumes entire candidates in counter order, and overwrites the range suffix. `RootZetaParity` compares both shapes against a CPU oracle, including forced rejection of candidate zero in task zero.
- **Uniform sampler.** Let `M = 2^64 - 1` and let `q` be the limb modulus. Keep the existing CPU and CUDA SEAL compatibility threshold `M - (M mod q) - 1`. Reject draws at or above the threshold. Keep the AES PRNG seed domain and consume retries in order. Uniform repair uses per-operation epochs. Root zeta repair stores a coefficient index in separate scratch.

Build oracle values through an independent CPU path. `buildHashedCt2` can dispatch batched polynomial derivation to CUDA if the context allows GPU use. Explicitly disable GPU in the CPU reference context and assert that CUDA is disabled before deriving expected output. Check exact coefficient and wire parity wherever the optimized operation contributes to serialization.

## CUDA ownership and performance

- Keep allocation ownership with the execution context and its stream. Reuse the stream's existing seed, key, and rejection scratch after its earlier consumers in stream order. A consumer on another stream needs its existing event or completion dependency.
- Keep pinned host staging alive until the copy finishes. Preserve the stream drain on failure paths that can reuse staging. Keep borrowed views within the lifetime of their owning tables and use them with the matching CUDA device.
- Keep readiness flags with the table owner and publish readiness after successful initialization. Keep per-run diagnostics and options on their existing owners. Ambient globals, TLS, and environment-controlled dispatch break that ownership model.
- Preserve fixed tile widths, explicit batching, unrolled loops, arithmetic order, and alignment contracts in hot kernels. Prefer compile-time configuration. Keep stack-sensitive SIMD work in a synchronous helper outside coroutine frames. Retain ownership across every suspension.
- Resolve the ordered ring moduli directly for seed-budget validation. The public budget checks use the modulus values and do not need SEAL transform tables. For receiver BStar verification, derive the expected batch with `actualNtt = true` and compare the canonical words before admitting root state. The legacy `deriveUniformPolyBatchFromNonceNtt` wrapper passes `actualNtt = false`. Use the explicit NTT flag for canonical BStar validation.
- Measure the changed kernel's registers, spills, shared memory, and memory traffic when those resources explain a timing change. For an end-to-end change, also measure copy traffic and stream overlap. Profile separately from timing.

Change one kernel or dispatch decision per experiment. Keep the reference revision available in Git and use separate builds for the two revisions. Run the independent CPU oracle and the protocol test that exercises the call site before timing the experiment. Restore the reference implementation through Git if the experiment fails. A temporary nondefault kernel selector adds another dispatch path to validate.

The code and tests here establish implementation parity under existing parameters. Route changes to the mathematical noise assumptions, parameter bounds, or ZK proof to the protocol authors for review.

## Revision and timing protocol

`b80413b5` is the original implementation reference for the full before/after comparison. Build it from unchanged source on Linux. On Windows, apply the [baseline compatibility patch](../../../libOTe_Tests/LogVole/original_b80413b5_windows_compat.patch) and add `-Xcompiler=/Zc:preprocessor` to the original CUDA build flags. `ff8a006a` is the reference for the pruning-only comparison beginning at `101fe736`. Record both full revision SHAs, use separate build directories, and match the toolchains, target architecture, and build configuration for each pair.

First validate both revisions with their available direct and protocol tests. Run the common workload with the same mode, size, thread count, and input controls. The local frontend verifies every VOLE output. A representative GPU workload is `frontend_libOTe -logvole -n 65539 -t 2 -gpu 1`. Add `-nogold 1` for interactive NoGoldenSeed or `-noninteractive 1` for noninteractive NoGoldenSeed.

Warm up each binary. Run one benchmark at a time across all devices and operating system environments. Alternate the two revisions in a balanced order such as A, B, B, A. Record the command, exit status, wall time, protocol phase timings when available, GPU model and UUID, driver and toolchain versions, and clock or power settings. Retain the raw samples with the median and range for each GPU and workload. Use uninstrumented runs for timing and separate runs for CUDA traces or Compute Sanitizer.

## Hardware handoff

On each host, record the OS and GPU, build both revisions, run direct and protocol checks, and run the applicable leak checks. Capture a separate trace for the H200 cases to establish dispatch. Start serial A/B runs after the checks pass.

| Environment | Report |
| --- | --- |
| Windows SM89 and Linux SM89 | Build, direct arithmetic tests, protocol tests, and strict CUDA leak checks. Name the device for each run. A 4060 and a 4090 produce separate timing records. |
| SM90 compilation | Compiler result and architecture. Include kernel symbol inspection if available. |
| Actual H200 runtime | Exact arithmetic and protocol tests, observed H200 kernel names, strict CUDA leak checks, and serial timings. Mark the runtime fields pending until they have been collected on the device. |

[GPU validation commands](GPU_VALIDATION.md) and [the serial A/B runner](../../../libOTe_Tests/LogVole/run_gpu_ab.py) accompany this guide.
