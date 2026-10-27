# LogVole Fixed Audit Issues

This record preserves the June 2026 completed-fix history and the subsequent
implementation corrections, paper alignment and CPU optimization. Each entry
records an implemented correction and its validation. Test names refer to the
registered suites in
[`LogVole_Tests.h`](../../../libOTe_Tests/LogVole_Tests.h).

## June 2026 completed corrections

### LV-AUDIT-001: Secret/noise randomness derived from public seeds

Secret-key, encryption-randomness and error sampling draw from `PRNG&` at the
point of use. SEAL samplers receive a full `seal::prng_seed_type`. Public
ciphertext material uses separate SID/digest/instance domain derivation.

The sampler/API review and passing LogVole tests cover the active paths in
`LogVoleRing`, `LogVoleLenc`, `LogVoleLhe`, `LogVoleCore` and
`LogVoleShrinkExpand`.

### LV-AUDIT-002: Public ciphertext-mask domain separation

`deriveSeedInstanceBlock(...)` absorbs public seed bytes, SID, digest, instance
index and fallback nonce/domain material before expansion to a full SEAL seed.
Recursive sender and receiver paths pass their instance indices explicitly.

`LogVole_LheOps_HashedCt2Deterministic` checks reproducibility and separation
when the domain inputs change.

### LV-AUDIT-003: Structural/debug test gating

Structural and longer audit tests are gated by
`ENABLE_LOGVOLE_EXTENDED_TESTS`. The default suite retains the normal protocol
regressions. The default suite and extended-test build were validated.

Files: `cmake/buildOptions.cmake`, `cmake/buildOptions.cmake.in`,
`libOTe_Tests/CMakeLists.txt` and the LogVole test registry.

### LV-AUDIT-005: Double CRT lift in recursive sender input

The recursive `gamma == tau` sender input isolates the selected RNS limb
without applying a second CRT lift. Receiver-side unbundling retains its
required one-limb lift, matching the LENC/denoise representation.

Regressions: `LogVole_Core_RepOfflineSenderInputGammaTauUnbundlesResidues` and
`LogVole_Core_RecursiveLiftOracleKeepsSenderResiduesUnscaled`. The extended
`LogVole_Core_GdecompHiUnbundleLiftsOneLimbPerOutput` covers the receiver
convention.

### LV-AUDIT-006: Golden-seed candidate domain parity

Candidate generation passes the same `mu` domain material to
`deriveSeedInstanceBlock(...)` as online `buildHashedCt2(...)` reconstruction.
The recursive candidate search and online mask derivation therefore agree.

The extended `LogVole_Core_GoldenSeedFindAndValidateCandidate` regression
reconstructs the accepted candidate with `seedLabelSampleCt2FromSeed(...)`
and checks it against the stored sampled mask.

### LV-AUDIT-009: Public-seed Gaussian noise helper removal

The unused `addGaussianNoise(...)` helper was deleted. Active noise paths use
`addPolyError(..., PRNG&, ...)` or `sampleErrorPolyNtt(...)`.

Source scans found no remaining declaration, definition or call to
`addGaussianNoise` under the LogVole library; the LogVole tests passed after
removal.

### LV-AUDIT-010: Root randomizer width follows the gadget base

`rootRandomizerWidth(...)` derives the leftover-hash slack from the gadget
base and ring degree. The default parameters retain width three, while smaller
gadget bases receive additional randomizer columns. Metadata validation and
setup/digest paths use the same calculation.

`LogVole_Core_RootRandomizerWidthTracksGadgetBase` checks the default width
and the increase for smaller gadget bases.

### LV-AUDIT-013: Seed-byte and nonce domain-separation coverage

The default `LogVole_LheOps_HashedCt2Deterministic` regression changes seed
bytes in `buildHashedCt2(...)` and the fallback nonce / `mu` in
`deriveSeedInstanceBlock(...)`, in addition to SID, digest and instance-index
checks. Changing either added domain input changes the derived material.

### LV-AUDIT-021: Dead sampling tags and duplicate noise-budget state

Removed the six unused LENC/LHE/seed domain constants, the ignored
`sampleUniformBatch` `domainTag` parameter and its caller arguments, and the
unused `computeBaseNoiseFloor` / `mEffectiveNoiseBound` path.

Source scans confirm those symbols are absent and `sampleUniformBatch` takes
only its context, count and PRNG. Live secret/noise sampling remains
PRNG-based; the active noise gate is `estimateNoiseBoundLog2`.

### LV-AUDIT-022: Out-of-range wide-integer shift

The June 5 correction makes `wideU64OneShift` return zero for `bit >= 128`
before evaluating a native shift, preventing a shift count of 64 or more.

`LogVole_Core_WideU64OneShiftBounds` covers `0, 63, 64, 127, 128, 255`.

## Earlier follow-up corrections

### LV-AUDIT-026: Peer-input bounds and label-count overflow

The completed changes were:

- June 5: `zpRingLabelCount` uses
  `count / slots + (count % slots != 0)`, avoiding an overflowing numerator.
- August 24: both `recvFrame` implementations check a protocol-derived maximum
  before allocating a peer-advertised payload.
- August 25: `civoleReceiverOffline` checks the peer's fixed-size label-count
  metadata against the agreed local output length before CRT construction or
  setup.

Regressions: `LogVole_Core_ZpRingLabelCountCeilNoOverflow`,
`LogVole_KeyDeriveCoproto_OversizedFramesRejectedBeforeAllocation` and
`LogVole_Civole_RejectsPeerOfflineWidth`.

Files: `LogVole.cpp`, `LogVoleRingSender.cpp` and `LogVoleRingReceiver.cpp`.

### LV-AUDIT-029: Intermediate sender online caches

The accepted recursive branch in `evaluateSenderSeedCandidate` stores
`finalTbk` in `state.mPrecomputedTbk` before returning the evaluation output.
Every intermediate level therefore has the cache needed during sender unwind.

`LogVole_Core_ThreeLevelOfflineReuseAndInvalidWidth` runs a three-level online
query and checks top-level and intermediate caches.

## October 2026 implementation corrections

| Item | Implemented correction | Regression |
| --- | --- | --- |
| LV-AUDIT-030: matrix repetition cancellation | Verify every equation independently, refresh a separate mask per equation, reject repeated statements through singular helpers, and sample matrix coefficients by exact rejection sampling. | `LogVole_Zk_MatMulIndependentRepetitions`, `LogVole_Zk_FreshMaskCpu`, `LogVole_Zk_FreshMaskGpu` |
| LV-AUDIT-031: stale GPU matrix allocations after configure | Reset cached device state and check dimensions, repetitions and challenge sizes before device writes. | `LogVole_Zk_MatMulReconfigure` |
| LV-AUDIT-032: rejected host input consumes a SID | Advance the wrapper SID after low-level input validation; retain consumed SIDs after later failures. | `LogVole_Civole_RejectedHostInputPreservesSid` |
| LV-AUDIT-033: direct root API reuses old sender keys | Clear recursive expansion caches for a fresh root request while retaining idempotent precompute reuse within that request. | `LogVole_Core_RootOnlineStateReuseAcrossQueries` |
| LV-AUDIT-034: singleton LENC tree lacks a randomizer layer | Pad to two leaves, reject explicit width one, and match offline wire bounds to the padding. | `LogVole_LencOps_SingletonPaddingAndRelation`, `LogVole_Encoding_SingletonOfflinePayloadBound` |
| LV-AUDIT-035: completed scalar upload retains a destroyed stream | Publish synchronized uploads without a producer-stream dependency. | `LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch` |
| LV-AUDIT-036: scalar upload allocates on the preceding role's stream | Select the destination stream before allocating reusable storage. | `LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch` |
| LV-AUDIT-037: matrix statement and work differ from the paper | Check every length-`n` inner product with application-supplied public C and independent coefficients. | `LogVole_Zk_MatMulIndependentRepetitions`, `LogVole_Zk_MatMulReconfigure` |

The audit-correction measurements and validation provenance are preserved in
`result/data/audit_fixes/`, with derived tables in
`result/figures/audit_fixes/`.

## LV-AUDIT-030: Independent matrix equations and fresh masks

Previously, summing repetition residuals allowed opposite errors to cancel.
`zkMatMulAccept` now checks every nonempty, matching proof/value pair
independently. Singular response/value helpers reject statements with more
than one repetition. Each repetition reserves its own mask, and each query
samples fresh masks from the receiver PRNG. Matrix coefficients use exact
rejection sampling in the field.

`LogVole_Zk_MatMulIndependentRepetitions` constructs opposite nonzero residuals
whose sum is zero and requires rejection. `LogVole_Zk_FreshMaskCpu` and
`LogVole_Zk_FreshMaskGpu` check actual masks across three queries and every
repetition, including resident MAC/key relations on CUDA.

## LV-AUDIT-031: Matrix device-state reconfiguration

Cached device allocations could retain the preceding statement's dimensions
or repetition count. Both matrix wrappers now reset their cached device state
on `configure`. Device entry points check dimensions, repetitions and challenge
sizes before writing outputs.

`LogVole_Zk_MatMulReconfigure` grows the statement from dimension one to four
with three repetitions, then to dimension 257 on CUDA. It checks public C in
valid, corrupted and restored states, followed by exact host/device proof
comparison. Dimension 257 crosses both kernel thread and cell-grid strides.

## LV-AUDIT-032: Receiver SID handling after rejected input

The receiver previously advanced its wrapper SID before validating the input.
It now reserves the candidate SID and advances it after the existing low-level
input check accepts the query. A later failure preserves consumption when the
low-level state has already recorded that SID. The final implementation uses
the existing validation pass, avoiding a duplicate full-input scan.

`LogVole_Civole_RejectedHostInputPreservesSid` submits noncanonical input,
then completes two valid queries. It also forces a closed-transport failure
and checks that the already-consumed SID cannot be reused.

## LV-AUDIT-033: Fresh keys for repeated direct root queries

A fresh root request could reuse recursive expansion keys from the preceding
query. `clearSenderExpansionCaches` now clears the GoldenSeed and host/device
precomputed-key state recursively before publishing a fresh root response.
Precompute calls within the same request retain their idempotent reuse.

`LogVole_Core_RootOnlineStateReuseAcrossQueries` runs two direct root queries,
checks every returned field VOLE relation, and verifies repeated precompute
calls within each request.

## LV-AUDIT-034: Singleton LENC padding and offline wire bounds

An unpadded one-leaf tree had no randomizer layer. Automatic padding now uses
at least two leaves, and explicitly requesting width one is rejected. Offline
message bounds use the same padded dimensions as the encoded payload.

`LogVole_LencOps_SingletonPaddingAndRelation` covers full and truncated
encodings, a nonempty randomizer, explicit-width rejection and the relation
`eval = r*d - s*x`. `LogVole_Encoding_SingletonOfflinePayloadBound` encodes,
checks the actual wire bound, decodes and finalizes the singleton payload.

## LV-AUDIT-035 and LV-AUDIT-036: Scalar-upload stream ownership

A synchronized upload could retain a stream handle owned by a worker that had
already exited. Reusing storage after changing protocol roles could also
allocate on the preceding role's stream. `uploadScalars` now selects the
current role's stream before resizing storage, synchronizes the host-to-device
copy, and publishes completed data without a producer-stream dependency.

`LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch` fetches data after the
upload worker and its stream have been destroyed. It also performs eight
sender/receiver storage handoffs with pending prior writes, checking stream
selection and every copied value.

## LV-AUDIT-037: Public-product matrix correction and CPU optimization

CPU and CUDA now follow Section 12.2 and Table 6 of the October 17 paper:
all `n*n` length-`n` inner products are evaluated directly. Each output entry
has an independent field coefficient per repetition. The verifier validates
and snapshots application-supplied public C before the online exchange. Its
per-entry term is `sum_k K[A_ik]*K[B_kj] - C_ij*Delta^2`.

The private VOLE layout contains A, B and one fresh mask per repetition,
totaling `2*n*n + repetitions` entries. Proof responses contain 16 bytes per
repetition, and every equation is checked separately.

Regressions cover malformed statements/challenges, public-C rejection,
independent batching, fresh masks, reconfiguration, and exact CPU/CUDA proof
equality, including dimension 257. Boundary checks cover maximal matrix
inputs at dimensions 1024/1025, alternate moduli and a public-C error confined
to the last output cell.

The completed CPU optimization packs columns and accumulates exact products
in bounded integer chunks. Runtime AVX-512 IFMA dispatch accelerates supported
fields; an exact scalar fallback remains available. Unweighted terms are
computed once and reused across repetitions, giving CPU work
`O(n^3 + repetitions*n^2)`. The benchmark uses separate pinned completion
executors and exact label requests.

Recorded validation passed 123 LogVole tests on both CPU models, with 15
CUDA-only skips. The CUDA-enabled suite passed 136 tests on H100, with two
existing Gaussian compatibility skips. Matched first-query measurements on
Xeon 6972P and Xeon Gold 6226 are documented in
[the CPU matrix optimization notes](../../../docs/logvole_integration.md#cpu-matrix-optimization)
and `result/data/matrix_cpu_optimization/`.

The matched benchmark uses dimension 1024, one repetition and one physical
CPU core per party, with a fresh setup and first query for each sample. Setup
and public-product preparation are outside the online timer; online VOLE
generation and proof acceptance are inside it. The same corrected harness is
used before and after, with three paired seeds and alternating process order.

| CPU | Before online median | After online median | Speedup |
| --- | ---: | ---: | ---: |
| Xeon 6972P | 33.838 s | 3.804 s | 8.90x |
| Xeon Gold 6226 | 54.769 s | 7.741 s | 7.08x |

These are local `LocalAsyncSocket` measurements with one thread per party.
The label request is exactly `2*n*n + repetitions`, or 2,097,153 at dimension
1024 with one repetition. Every returned VOLE relation is checked outside the
timer. Source, hardware, affinity, commands and artifact hashes are preserved
with the linked measurements.

## Leaf golden-seed final-output rounding correction

The final recursion level previously reused the intermediate `Q/q_j`
predicate, which could accept a coefficient near a final-output rounding
boundary. The final predicate now checks the full CRT fraction of `p*V/Q`.
Intermediate levels retain their per-limb predicate and padded-sample checks;
the final level checks its logical output prefix.

CPU checking retains vectorized arithmetic and early rejection. CUDA uses
Shoup multiplication with four- and eight-limb specializations. Eager,
deferred and root-only paths use the corrected final predicate, and deferred
validation preserves any earlier rejection. Constant construction uses the
validated primes directly, avoiding repeated modulus/primality setup.

Boundary and decoder-threshold regressions are retained. CUDA coverage checks
host/device agreement for four, five and eight limbs, unused padding and
failure-flag accumulation.

## Plaintext-product lift margin correction

The actual CI-VOLE wrapping path multiplies `floor(Q/p)*Delta` by plaintext
coefficient `x`. The unreduced integer product `M=Delta*x` can reach `(p-1)^2`.
The shared CPU/CUDA margin now uses `p*(B+p^2)/Q` in place of `p*(B+p)/Q`,
retaining upward numerical slack and reciprocal-error allowances.

`LogVole_Core_LeafGoldenSeedChecksPlaintextProduct` exercises wrapping, ring
multiplication and decoding with `Delta=x=p-1`. It rejects a constructed key
that produces a decoder mismatch even at zero noise, and checks accepted
candidates on both sides of the boundary with zero and extremal noise signs.
CUDA exercises the same candidates through eager and deferred validation.

The regression failed with the previous margin and passes with the corrected
bound. Recorded validation passed 123 CPU LogVole tests with 15 CUDA-only
skips, and 136 H200 tests with two existing Gaussian compatibility skips.
Leaf tests also passed with scalar CPU checking and eager CUDA validation
selected explicitly. Detailed equations, validation and the leaf-rounding
before/after measurements are in
[the leaf golden-seed correction](../../../docs/leaf_golden_seed_fix.md).
