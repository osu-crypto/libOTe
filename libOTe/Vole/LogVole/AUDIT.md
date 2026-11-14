# LogVole Audit Record

This record preserves the June 2026 completed-fix history and the subsequent
implementation corrections, paper alignment and CPU optimization. The open
review questions below are separate from the completed corrections, whose entries
record implemented changes and validation. Test names refer to the
registered suites in
[`LogVole_Tests.h`](../../../libOTe_Tests/LogVole_Tests.h).

## Open questions for Lucien: paper and noise alignment (2026-11-13)

Status: **OPEN; review requested, no sampler or protocol change proposed.**
This comparison uses implementation revision `54f79490` and paper revision
`78878ea` in the local `logVole` paper repository (`C:/Users/peter/repo/logVole`).
Paper paths below refer to that revision and the active `p.tex` input tree.

### Concrete integer-noise distribution and security parameters

The paper's `prelims-app.tex:114` defines the discrete Gaussian with mass
proportional to `exp(-pi*k^2/s^2)`. Lines 162–165 discuss clipping that discrete
distribution and bound the resulting statistical distance. The concrete
[`samplePolyNormal`](LogVoleRing.cpp) instead uses SEAL 4.1.1's clipped
continuous-normal distribution and converts each result to an integer by
truncation toward zero. The
[`CUDA Gaussian transform`](cuda/LogVoleGpuGaussianKernels.cu) preserves this
conversion. Ordinary setup supplies `sigma = 3.19*sqrt(tau)` for LacE noise
and `3.19*sqrt(widthPadded)` for LHE noise in
[`LogVoleShrinkExpand.cpp`](LogVoleShrinkExpand.cpp); root setup has analogous
choices in [`LogVoleCore.cpp`](LogVoleCore.cpp).

For illustration, continuous standard deviation `3.19*sqrt(2) = 4.511...`
becomes approximately `4.132` after integer truncation. Its zero probability
is approximately `0.175424`, whereas a discrete Gaussian with the matched
continuous width `s = sigma*sqrt(2*pi)` has zero probability approximately
`0.088431`. This difference is a distribution and parameter-alignment issue;
the zero-probability difference is not a security-loss estimate or evidence
of a break. Ordinary LWE security can tolerate a range of error distributions,
but that robustness does not by itself identify which concrete parameters and
leaky-LWE assumptions cover this sampler.

These are three separate choices: instantiating random streams with an AES
PRG, clipping Gaussian tails, and discretizing a continuous Gaussian by
integer truncation. The paper's negligible tail-clipping lemma addresses the
second choice for its stated discrete distribution, not the third choice.

**Question for Lucien:** Is the implemented integer-noise distribution covered
by suitable RLWE and adaptive error-leakage RLWE assumptions at the actual
standard deviations and parameter sets? Please identify the matching
assumptions or reduction and the security estimates for those parameters, or
specify what distribution/parameter alignment is required.

### Fresh hiding noise in the proof and hash-derived corrections

The paper's `proofsh-trunc.tex:575–578` and `:666` invoke fresh hiding noise
from `overline chi_LacE`. Its error-leakage experiments in
`prelims-app.tex:116–159` likewise include fresh masking noise, and
`alg/golden-seed.tex:45–50` gives a hiding-noise width that depends on the
reuse bound `T`. However, `alg/shrinkexpand-trunc.tex:36–40` specifies
hash-derived correction ciphertexts directly. The corresponding concrete
paths, `prepareSenderExpansion` and `finishReceiverExpansion` in
[`LogVoleShrinkExpand.cpp`](LogVoleShrinkExpand.cpp), derive those corrections,
subtract the LacE evaluation and combine the ciphertext terms without an
explicit fresh Gaussian hiding-noise draw. Root-response `kPrime` sampling
in [`LogVoleCore.cpp`](LogVoleCore.cpp) is uniform sampling. The public noise
budget estimator's leaky-LWE width calculations alone do not establish a
distributional correspondence for these executed paths.

**Question for Lucien:** What distributional or simulation argument connects
the hash-derived corrections, including golden-seed conditioning, to the
proof's fresh `overline chi_LacE`-masked leakage? Please map that argument to
the concrete setup widths, reuse bound and online sampling paths. The paper
algorithm and implementation both use hash-derived corrections here, so this
is an open proof/instantiation question rather than a demonstrated omission
from an otherwise matching implementation.

### Paper erratum: golden-seed acceptance inequality

In `alg/golden-seed.tex:26–27`, `e` is centered modulo the component's scale
gap `delta`, but the pseudocode rejects when `|e| > B`. To match the good
interval in `lower-golden.tex:57`, a robust sufficient acceptance condition is
`|e_i| + B < delta_i/2` for every component; reject if any component satisfies
`|e_i| + B >= delta_i/2`. Equality may be allowed only with a stated
rounding-tie convention and corresponding noise-bound assumptions.
The implementation's boundary-distance predicate
in [`LogVoleCore.cpp`](LogVoleCore.cpp) follows the prose's intended interval;
this erratum does not call for a runtime predicate change. This comparison
does not certify all fixed-point or reciprocal-error boundary cases.

### Opened-setup ZK proof questions (2026-11-14)

Status: **OPEN; deferred for Lucien's review, no changes proposed now.**
These questions use paper `e569700` and code `920658e4`; earlier entries retain
their stated provenance.

**Simulator.** `zk-proof.tex:78-91` samples honest verifier setup, commits before
opening, then samples correlated final values after `Delta`.
**Question for Lucien:** What is the complete simulator for an actual malicious
verifier, including consistent commitment openings and abort behavior? This is a
proof-completion question, not an attack claim or proposed protocol change.

**Commitments.** `zkp.tex:75-77` lists binding; `zk-proof.tex:91` invokes hiding.
**Question for Lucien:** Which exact commitment properties does the completed
simulator require, and how should the theorem state them?

**Public `B*`.** `Digest-Properties.tex:34,68-69` uses a uniformly sampled matrix;
the implementation uses fixed public AES expansion. The admission guard prevents
substitution but does not prove an expansion assumption. **Question for Lucien:**
Which explicit setup, random-oracle, or other assumption covers this instantiation?
The statistical uniform-matrix theorem alone does not supply that argument.

## Paper's opened fresh-setup ZK route

Status: **NOT IMPLEMENTED.** The existing ZK wrappers use semi-honest VOLE.
This section records paper revision `e569700`: `zkp.tex`, `alg/it-mac-zk.tex`,
and `zk-proof.tex`. The prover is the VOLE receiver; the verifier is the sender.

The verifier samples `Delta` and sends a fresh setup transcript `T_set`.
The prover extends its witness-derived circuit trace with fresh sacrificed
RLC coordinates `u_t` and the fresh IT-MAC masking coordinate `V1*`.
The parties run chosen-input VOLE on this extended input `x'`, giving the
prover labels `m_i` and the verifier keys `k_i`. After receiving the verifier's
random-linear-check (RLC) challenges, the prover commits to the masked answers
`u'_t = u_t + sum_i chi_i^(t)*x_i`. Gate batching uses coefficients derived
from `H(T_set, C_rlc, transcript)`. The prover then commits to the final
IT-MAC values `(Vhat_1, Vhat_2)`.

Only then does the verifier disclose `Delta`, its setup coins, and all `k_i`.
The prover recomputes `T_set` from `Delta` and the disclosed coins, rejecting a
mismatch. It also checks `m_i = k_i + x'_i*Delta` for every extended coordinate,
including all `u_t` and `V1*`. After these checks succeed, it opens both
commitments. The verifier checks the RLC identities and
`Uhat = Vhat_2 + Vhat_1*Delta`, accepting only if all checks pass.
These are checks on the actual extended input; the algorithm does not prescribe
online-sender replay or an audit over all possible receiver inputs.
The setup is fresh for each proof and single use because `Delta` is revealed.

The deferred proof and public-matrix questions are recorded in the Lucien
review section above. RLC-based extraction and the alternative digest-knowledge
assumption in `zkp.tex` remain distinct knowledge-soundness routes.

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
