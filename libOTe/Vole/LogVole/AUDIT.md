# LogVole Audit Tracker

This file tracks security- and correctness-relevant audit items for the
LogVole port. It is intentionally implementation-facing: each item should say
what the concern is, what evidence we have, and what would close it.

Date opened: 2026-06-04

Status legend:

- `fixed`: code has been changed and normal LogVole tests pass.
- `open`: needs a code change, paper check, or targeted test.
- `watch`: not currently considered a bug, but worth preserving in tests or
  review notes.

## LV-AUDIT-001: Secret/noise randomness must not come from public seeds

Status: fixed

Concern:

The original port carried deterministic sampling roots in protocol parameters.
That made secret-key, encryption randomness, and error sampling look derivable
from serialized or fixed configuration material. For LWE/RLWE ciphertexts, the
sender-side secret/noise randomness must not be recoverable by the receiver.

Current state:

Secret/noise sampling now draws directly from `PRNG&` at the point of use.
SEAL samplers receive a full `seal::prng_seed_type`, not a reduced 64-bit seed.
Public deterministic ciphertext material is derived through a random-oracle/AES
seed from the SID, digest, instance index, and domain material.

Relevant files:

- `LogVoleRing.h`
- `LogVoleRing.cpp`
- `LogVoleLenc.cpp`
- `LogVoleLhe.cpp`
- `LogVoleCore.cpp`
- `LogVoleShrinkExpand.cpp`

Closure evidence:

- Normal LogVole tests pass.
- Extended-test build compiles.
- Repository scan finds no remaining LogVole uses of `random_device`,
  `sysRandomSeed`, old `noiseSeed` naming, or raw `{ u64, 0 }` SEAL seeds.

Regression tests to keep:

- Search/grep based review is useful here because this is an API-use invariant.
- Any future deterministic sampler should make public-vs-secret randomness
  explicit in its name and signature.

## LV-AUDIT-002: Public ciphertext masks must be derived from digest and SID

Status: fixed

Concern:

The TeX states that ciphertext masks derived during the online phase should be
a function of the receiver digest and the session id. The earlier port routed
some sampling through small nonces or cached seed roots, which made the domain
separation too implicit and too easy to misuse.

Current state:

`deriveSeedInstanceBlock(...)` derives the public deterministic seed from:

- public seed material,
- SID,
- digest,
- instance index,
- optional fallback nonce/domain material.

The generated block is expanded into a full SEAL seed before uniform sampling.

Relevant files:

- `LogVoleRing.h`
- `LogVoleRing.cpp`
- `LogVoleLhe.cpp`
- `LogVoleCore.cpp`
- `LogVoleRingSender.cpp`
- `LogVoleRingReceiver.cpp`
- `LogVoleShrinkExpand.cpp`

Closure evidence:

- Normal LogVole tests pass.
- Recursive sender/receiver paths pass instance indices explicitly instead of
  reusing an unrelated derived nonce.

Regression tests to keep:

- SID reuse and sequential-SID tests.
- A future targeted test should prove that changing SID or digest changes the
  derived ct2 masks while identical `(seed, sid, digest, instance)` tuples
  reproduce exactly.

## LV-AUDIT-003: No-noise or paper/debug variants must not be generally exposed

Status: fixed

Concern:

Several audit/debug tests exercise no-noise or structural-only variants. These
are useful when comparing algebra, but they should not be part of the normal
test surface or exposed as a production mode.

Current state:

Longer and more structural LogVole tests are behind
`ENABLE_LOGVOLE_EXTENDED_TESTS`. The default test set stays smaller and focused
on normal protocol behavior.

Relevant files:

- `cmake/buildOptions.cmake`
- `cmake/buildOptions.cmake.in`
- `libOTe_Tests/CMakeLists.txt`
- `libOTe_Tests/LogVole_Tests.h`
- `libOTe_Tests/UnitTests.cpp`

Closure evidence:

- Default LogVole suite passes with the option off.
- Extended test registry compiles with the option on.

Regression tests to keep:

- CI should continue running the default LogVole suite.
- Extended tests can be run during local audit passes or before risky algebra
  changes.

## LV-AUDIT-004: Root-level `r1` distribution in the truncated root wrapper

Status: watch

Concern:

The full-gadget root-wrapper algorithm in `alg/rootdigest.tex` describes
`\bb r_{\rt}^{(1)}` as sampled uniformly from `R_q^{tau rho}`. The implemented
clean-ot path and this port use the one-digit truncated LENC/LHE variant. In
that variant, the transported LENC masks are sampled from the small/error
distribution `D`, and the truncation correctness proof explicitly relies on
that smallness to bound the dropped low-gadget-digit terms.

Current state:

The current port intentionally matches clean-ot behavior for the truncated root
wrapper by using `sampleRootErrorBatch(...)` for root `r1`.

Relevant files:

- `LogVoleCore.cpp`
- `LogVoleCore.h`
- `LogVoleLenc.cpp`
- TeX: `alg/rootdigest.tex`
- TeX: `alg/lenc-trunc.tex`
- TeX: `alg/shrinkexpand-trunc.tex`
- TeX: `app-trunc.tex`
- TeX: `proofsh-trunc.tex`
- clean-ot reference: `native/loglabel/src/protocol/trunclabel_protocol.cpp`

Evidence:

- `alg/rootdigest.tex` is written in the full-gadget style and samples
  `\bb r_{\rt}^{(1)} <- R_q^{tau rho}`.
- `alg/lenc-trunc.tex` samples `\bb r^{(0)}, ..., \bb r^{ell-1}` from `D`.
- `alg/shrinkexpand-trunc.tex` calls `lenctrunc.enc(s)` and then encrypts the
  returned `r` with `lhetrunc.enc_1(r)`.
- `app-trunc.tex` states that the truncated variant publishes `ct_1^hi` and
  `lacct^hi` using masks sampled from the LENC error distribution `D`, and the
  bound includes `ng max(D)` dropped-digit terms.
- `proofsh-trunc.tex` says the change
  `r, r^(1), ..., r^(ell-1) <- D` is handled by the truncated LENC proof
  because these values are the row secrets in the laconic ciphertext hybrids.
- clean-ot samples the root-wrapper `r1` through `sample_root_error_batch(...)`.
- This port's `lencEncTrunc(...)` samples its internal `rLayers` with
  `sampleErrorPolyNtt(...)`; the root wrapper separately samples its top
  `r1` with the same small/error path so the special top row follows the same
  truncated contract.
- Switching root `r1` to uniform caused multiple normal correctness tests to
  fail, consistent with the dropped low-gadget-digit term becoming too large.

What would close it:

- Lucian confirms that the randomized-root wrapper in the optimized protocol is
  meant to inherit the truncated LENC mask distribution, or
- the TeX adds an explicit truncated-root-wrapper algorithm/remark replacing
  the full-gadget root `r1 <- R_q` line with `r1 <- D` for the truncated
  variant.

Recommended targeted test:

- A small root-only truncated algebra test that computes the dropped low-digit
  error independently and verifies that it is bounded when `r1 <- D`.
- A negative extended test, kept out of normal CI, can demonstrate that using a
  uniform `r1` violates the truncation noise budget for ordinary parameters.

## LV-AUDIT-005: Double CRT lift in recursive digest/key handling

Status: fixed

Concern:

The receiver-side digest unbundle currently multiplies each RNS limb by the CRT
lift factor `q / q_j`. The sender-side recursive offline input also applies the
same lift convention to the retained limb. That gives an extra uncompensated
lift factor in the recursive `gamma == tau` path.

Lucian's concern:

Lucian confirmed that clean-ot has the same issue. The receiver-side lift is
accounted for by the LENC leaf scaling/de-lift and denoise path. The
sender-side lift in `rep_offline_sender_input` is not matched for the
recursive `gamma == tau` branch, giving an unintended extra factor. The issue
was mostly invisible because the default recursive tests used `tau_hi == 1`.

Current state:

The receiver-side unbundle still lifts one limb, matching the current
LENC/denoise representation. The sender-side recursive input no longer applies
the CRT lift in the `gamma == tau` branch; it isolates the selected RNS limb and
leaves that residue unscaled.

Relevant files:

- `LogVoleCore.cpp`
  - `seedLabelGadgetDecomposeHiAndUnbundle(...)`
  - `seedLabelRepOfflineSenderInput(...)`
- `LogVoleShrinkExpand.cpp`
  - `shrinkExpandDenoiseComb(...)`
- `libOTe_Tests/LogVole/tests/test_core.cpp`
- `libOTe_Tests/LogVole_Tests.h`
- clean-ot reference: `goldlabel_backend_seal.cpp`

Evidence:

- clean-ot applies the lift in both analogous places.
- Removing the receiver-side lift breaks the root relation immediately,
  including the `tau_hi == 1` path.
- Removing the sender-side recursive lift keeps the protocol tests passing and
  matches Lucian's assessment that the sender recursive lift was unmatched.
- A default regression test now checks that
  `seedLabelRepOfflineSenderInput(..., gamma == tau, ...)` unbundles residues
  without CRT scaling.

What would close it:

- Normal LogVole tests pass after the fix.
- Extended-test build compiles after the fix.

Regression tests to keep:

- `LogVole_Core_RepOfflineSenderInputGammaTauUnbundlesResidues`.
- `LogVole_Core_GdecompHiUnbundleLiftsOneLimbPerOutput`, kept as an extended
  implementation-shape test for the receiver-side convention.

## LV-AUDIT-006: Golden-seed search domain parity

Status: fixed

Concern:

The clean-ot implementation searches for sender seed candidates with recursive
validation. The port should preserve that behavior closely because it affects
performance and correctness margins. The port must also derive candidate ct2
masks with the same public domain tuple used by online reconstruction.

Current state:

The current port contains recursive golden-seed candidate machinery and was
audited against clean-ot's structure. Randomness feeding that machinery uses
public seed material and digest/SID domain separation. Candidate generation now
passes the same `mu` domain material into `deriveSeedInstanceBlock(...)` as
`buildHashedCt2(...)`, so `findGoldenSeed(...)` and online ct2 reconstruction
agree.

Relevant files:

- `LogVoleCore.cpp`
- clean-ot reference: `goldlabel_protocol.cpp`

Closure evidence:

- Extended `LogVole_Core_GoldenSeedFindAndValidateCandidate` reconstructs the
  accepted candidate through `seedLabelSampleCt2FromSeed(...)` and checks it
  against the stored `mTbkPerSampledPoly`.
- Extended LogVole suite passes.

Regression tests to keep:

- `LogVole_Core_GoldenSeedFindAndValidateCandidate`.
- A future stress test can still force multiple candidate attempts and check
  recursive parent validity under larger instance counts.

## LV-AUDIT-007: Tests can pass while algebra/noise representation is wrong

Status: open

Concern:

Several current tests compute expected values by using the same implementation
helpers as the protocol. That is useful for regression testing, but it can miss
representation mistakes where both the implementation and expected path share
the same bug.

Current state:

Normal tests are good smoke/regression coverage, but not sufficient for the
paper-vs-implementation audit.

Relevant files:

- `libOTe_Tests/LogVole/tests/test_core.cpp`
- `libOTe_Tests/LogVole/tests/test_shrinkexpand.cpp`
- `libOTe_Tests/LogVole/tests/test_lhe.cpp`
- `libOTe_Tests/LogVole/tests/test_lenc.cpp`

What would close it:

- Add a small number of independent paper-oracle tests for the root relation,
  one recursive level, SID-derived mask domain separation, and CRT recombine
  behavior.

Recommended targeted tests:

- Independent root relation test.
- Independent recursive one-level relation test with `rho > 1`.
- Noise-margin test for the possible double-lift issue.
- SID/digest domain separation test for public deterministic masks.

## LV-AUDIT-008: Wide 64-bit arithmetic portability

Status: watch

Concern:

The current port uses a local wide-64 helper instead of Boost or compiler-only
`uint128_t` API exposure. This should stay narrow and removable. Boost must not
become a LogVole dependency except where libOTe already uses Boost through
coproto/asio.

Current state:

The LogVole code should not introduce a hard Boost dependency. The wide-64
helper should remain an internal arithmetic detail only.

Relevant files:

- `LogVoleRing.h`
- `LogVoleRing.cpp`

What would close it:

- Windows build passes.
- Scan confirms no new non-asio Boost includes under `libOTe/Vole/LogVole`.

## LV-AUDIT-009: Dead-but-live `addGaussianNoise` draws Gaussian noise from a public seed

Status: fixed

Concern:

`addGaussianNoise(poly, sigma, maxDev, u64 seed, u64 streamId, ctx)` produces a
clipped-Gaussian error deterministically from a *public* random-oracle
derivation — the same family used for `ct2` / public-polynomial derivation. The
plain `u64 seed` and `streamId` flow through the public path, so any error
produced by this function is fully recoverable by anyone who knows
`(seed, streamId)`. The function is currently dead (zero call sites), but it
sits next to `addPolyError(..., PRNG&, ...)` with a near-identical signature.
If a future edit wires an LWE/LacE/LHE error through `addGaussianNoise` with a
public/serializable seed, the receiver could subtract the known error and
recover the masked LWE secret / Delta — a Critical break. This is exactly the
secret-from-public-seed mistake LV-AUDIT-001 was created to prevent.

Current state:

Deleted. Active noise paths use `addPolyError(..., PRNG&, ...)` or
`sampleErrorPolyNtt(...)`.

Relevant files:

- Active (correct) noise paths: `LogVoleLenc.cpp:495,1088,1499`,
  `LogVoleLhe.cpp:246`, `LogVoleCore.cpp:897`
- clean-ot reference: uses PRNG-based error injection for all LWE/LacE/LHE
  errors; no public-seed Gaussian error path is wired in
- TeX: `lhe-trunc.tex:20,31` (E1,E2 <- Dbar must be secret);
  `lenc-trunc.tex` / `app-trunc.tex` (masks/errors from D);
  `golden-seed.tex` (only ct2, NOT errors, are hash-derived)

Evidence:

- Grep confirms no remaining `addGaussianNoise` declaration, definition, or call
  site under `libOTe/Vole/LogVole`.

What would close it:

- Normal LogVole tests pass after deletion.

Recommended targeted test:

- Extend the LV-AUDIT-001 regression scan to assert no LogVole error/secret path
  calls `addGaussianNoise`.

## LV-AUDIT-010: Root randomizer width does not scale with the gadget base `g`

Status: fixed

Concern:

The randomized root digest `d'_rt = B_1 . gdecompHi(y_L) + B* . zeta` is the
sender's only view of the receiver input `x`. Its statistical hiding
(SD <= 2^-statsec) requires randomizer width `m = tau + s` with
`s >= (2*statsec + log2 n + O(1)) / log2 g`. The implementation hard-codes
`m = max(3, tau+1)` (i.e. `s = 1` for `tau >= 2`) with no dependence on `g` or
`n`. For default eval params (`g = 2^110, n = 8192, statsec = 40, tau = 2`) this
yields `SD <= sqrt(n) . g^-1/2 = 2^-48.5 < 2^-40` (correct). But the required
slack grows as `1/log2 g`: for a custom config with a smaller gadget base
(e.g. `gadgetLogBase = 30`), `s = 1` yields `SD ~ sqrt(8192) . 2^-15 = 2^-8.5`,
far above `2^-40`, so `d'_rt` would leak partial statistical information about
`y_L` (hence `x`) to a semi-honest sender.

Current state:

`rootRandomizerWidth(...)` now computes the leftover-hash slack from the gadget
base and ring degree:
`m = tau + max(1, ceil((2*statsec + ceil(log2 n) + 1) / log2 g))`, with
`statsec = 40`. For the default eval params (`g = 2^110, n = 8192, tau = 2`)
this preserves the old width `m = 3`; small-`g` direct `Params` configurations
now receive additional randomizer columns.

Relevant files:

- `LogVoleCore.cpp` (`rootRandomizerWidth(...)`, metadata validation,
  setup/finalize/digest paths)
- `libOTe_Tests/LogVole/tests/test_core.cpp`
- clean-ot reference: `trunclabel_protocol.cpp:58-60`
  (`root_randomizer_width` identical)
- TeX: `Digest-Properties.tex` lem:randrootdigest-hiding-main
  (`m = tau + Theta((statsec+log n)/log g)`) and thm:rootdigest-lhl-inst
  (`s >= (2*statsec + log2 n + O(1))/log2 g`); concrete instantiation
  `Digest-Properties.tex:126-142`

Evidence:

- The old constant encoded only the `n=8192 / g=2^110` working point.
- `LogVole_Core_RootRandomizerWidthTracksGadgetBase` checks that the default
  width remains 3 and that a smaller gadget base increases the width.

What would close it:

- Normal and extended LogVole tests pass after the width change.

Recommended targeted test:

- A parameterized hiding test that, for a small-`g` config, asserts the chosen
  randomizer width satisfies the lemma's `SD <= 2^-statsec` bound (or that
  validation rejects the config).

## LV-AUDIT-011: Paper's `chi_lenc` eval-error smudging is realized via random-oracle ct2 masking

Status: watch

Concern:

The paper's truncated LacE simulation (lem:lenchi-sim, adaptive
error-leakage Ring-LWE) and the correctness proof add an explicit smudging-noise
term `lerr ~ chi_lenc` whose magnitude scales with `sqrt(T)` (the number of
evaluations reusing the same `lacct`), to statistically hide the LacE
evaluation-error leakage `e_lenc = Z*E` observable in the low bits of `tbm`
across queries. The implementation samples no such eval-time noise. Hiding is
instead provided structurally by `ct2 = H(seed, sid, digest, instance)`, a fresh
uniformly-random ring element per query that masks the residual via
`-a*tbkPrime + ct2` in `tbm` (the sender's `tbk` shares the same `ct2`). For
distinct digests/instances, `ct2` differs and the uniform difference perfectly
masks any error-difference — arguably stronger than the paper's statistical
`chi_lenc`. The noise budget still conservatively reserves room for
`max chi_lenc`.

Current state:

No eval-time `chi_lenc` term at any noise site; hiding is the RO-derived ct2.
Matches clean-ot exactly. No concrete attack identified. The residual risk is
only a reuse path letting two protocol-useful evaluations share the same `ct2`
with different secret-bearing error leakage the uniform mask does not cover —
that case is supposed to be ruled out by golden-seed binding plus the
near-collision SIS premise (a different worker's scope).

Relevant files:

- `LogVoleLhe.cpp:415` (`buildHashedCt2`: ct2 = uniform RO-derived)
- `LogVoleShrinkExpand.cpp:850-857` (`tbm = decPartial - eval + ct2`)
- clean-ot reference: `shrinkexpand_protocol.cpp` (no chi/smudging/hiding noise
  sites; noise only in lenc_ops/lhe_ops/ring_ops/root error)
- TeX: `golden-seed.tex:50` (`max chi_lenc := sqrt(lambda)*sbar_LacE`,
  `sbar ~ sqrt(T)`); `proofcor.tex:100` (`lerr <- chi_lenc^mu`);
  `proofsh-trunc.tex` lem:lenchi-sim; `app-trunc.tex`
  eq:trunc-rounding-condition

Evidence:

- The eval-time noise term is absent; the budget term in
  `estimateNoiseBoundLog2` still scales with `sqrt(2mT)`, so the budget reserves
  `max chi_lenc` room even though the noise is never added.

What would close it:

- Confirm with the authors/simulation-proof auditor that the truncated
  semi-honest proof can be discharged using fresh RO-derived ct2 masking in lieu
  of the explicit `chi_lenc` smudging term (i.e. the proofsh-trunc hybrids using
  `lenctrunc.Sim` go through when the per-query randomness is the RO ct2 rather
  than added Gaussian). If so, add a paper remark that the implementation
  realizes `chi_lenc` via the random oracle ct2. If not, add the
  `sqrt(T)`-scaled hiding noise to the expand message.

Recommended targeted test:

- (Corroborating) the ct2 domain-separation oracle of LV-AUDIT-013 confirms that
  distinct queries get distinct ct2 masks, which is the structural premise of
  this argument.

## LV-AUDIT-012: No independent truncated-LENC/root eval-relation test; integration bound omits `max(Dbar)`; LV-AUDIT-004 status drift

Status: open

Concern:

The truncated-LENC unit tests provide no independent check of the truncated eval
relation `phi[ind] ~ r[ind]*high_g(d) - s[ind]*x[ind] + e_drop` (with the
dropped-digit term), unlike the full-gadget path which has a genuine
first-principles oracle. The truncated eval algebra is only exercised end-to-end
via the ShrinkExpand coproto test, whose residual bound check uses an analytic
expression that *omits the `max(Dbar)` factor* from `app-trunc.tex` (it passes
empirically because centered `low_g <= g/2` and masks are small, but the
asserted bound is not the proven one). This is the LV-AUDIT-007 concern
specialized to the truncated LENC/root path (distinct from the dismissed
r1-distribution finding — here the gap is tracking + coverage, not the mask
distribution). Separately, the audit brief described LV-AUDIT-004 as `open`
while this worktree's tracker marks it `watch`; reconcile.

Current state:

Truncated LENC tests check only shape/determinism/tree-vs-x/mu-reject/leaf-path.
The integration residual bound is looser/differently-shaped than the paper bound.

Relevant files:

- `AUDIT.md:137` (LV-AUDIT-004 `Status: watch`) and `AUDIT.md:196-201`
  (recommended root-only truncated algebra test NOT yet implemented)
- `test_lenc.cpp:207-436` (5 truncated LENC tests; none checks the eval relation)
- `test_lenc.cpp:123-156` (`LogVole_LencOps_EvalMatchesRmulDigestMinusSmulX` —
  the full-gadget first-principles oracle that the truncated path lacks)
- `test_shrinkexpand_coproto.cpp:264-268` (residual bound uses analytic
  `2^(gadgetLogBase + log2 n + log2 pathLen) * 4`, OMITS the `max(Dbar)` factor)
- TeX: `app-trunc.tex:60-91` (lem:trunc-lhe-product) and `:122-153`
  (lem:trunc-lenc-path) — the bounds a targeted test should empirically confirm

Evidence:

- The full-gadget oracle exists but has no truncated counterpart; the only
  truncated coverage is end-to-end with a non-paper bound.

What would close it:

- Add an independent truncated-LENC eval test mirroring
  `EvalMatchesRmulDigestMinusSmulX` that recomputes
  `r[i]*high_g(d) - s[i]*x[i]` from first principles and asserts the residual is
  `<= n*g*max(Dbar)*(1 + log2 mu)`.
- Add the root-only truncated algebra test of `AUDIT.md:196-201`.
- Reconcile the LV-AUDIT-004 status between the brief and this tracker.

Recommended targeted test:

- `LogVole_Oracle_RootEvalRelationFromFirstPrinciples`: runs the full
  SetupRoot/online root path (`buildRootTopCt` + `lheEnc1Trunc` +
  `deriveSkxTrunc` + `shrinkExpandExpand{Sender,Receiver}`), computes the
  expected `s_i * x_i` from an independently-built sender key (replicate `sk1`
  and unbundle per-limb by hand, NOT via `seedLabelRepOfflineSenderInput`), and
  checks the centered residual against a from-scratch budget that *explicitly
  measures and includes* `max(Dbar)` as the actual centered-inf-norm of the
  receiver inputs `x` (closing the omitted-factor gap).

## LV-AUDIT-013: In-CI ct2 domain-separation test omits the seed-bytes and `fallbackNonce(mu)` dimensions

Status: fixed

Concern:

`golden-seed` correctness/security rests on every component of
`(seed, sid, digest, instance, mu)` changing the derived ct2. The CI test
already covers reproducibility plus separation under changing `sid`, `digest`,
and `instanceIdx` (more than the AUDIT.md `open` status for LV-AUDIT-007
implies). However, `deriveSeedInstanceBlock` also hashes the raw seed bytes and
the `fallbackNonce` (mu), and neither dimension is exercised — the test never
changes the seed or `fallbackNonce` while holding the rest fixed. A future
refactor that accidentally drops the seed from the hash transcript would pass CI.

Current state:

The default `LogVole_LheOps_HashedCt2Deterministic` test now covers seed-byte
separation in `buildHashedCt2(...)` and fallback nonce / `mu` separation in
`deriveSeedInstanceBlock(...)`, in addition to the previous SID, digest, and
instance-index checks.

Relevant files:

- `test_lhe.cpp` (`LogVole_LheOps_HashedCt2Deterministic`)
- `LogVoleRing.cpp:495-523` (`deriveSeedInstanceBlock` hashes raw seed bytes at
  `:513-516` and fallbackNonce at `:507`)
- `test_core.cpp:719-736`
  (`SeedLabelSampleCt2FromSeedDeterministic` is sid-only, extended-suite only)
- TeX: `golden-seed.tex:16` (`seed := H(id, d_rt, krt, q)`) and `:24`
  (`ct = hashct(id, seed, j, i, d_rt)`)

Evidence:

- Test coverage confirms changing seed bytes changes `ct2`, and changing the
  fallback nonce / `mu` changes the derived seed block.

What would close it:

- Normal LogVole tests pass with the additional domain-separation assertions.

Recommended targeted test:

- `LogVole_Oracle_Ct2PublicMaskDomainSeparationFull`: derives the
  reproduce/differ contract from the random-oracle definition (collision IFF
  every absorbed field is identical) and asserts independent separation for each
  of seed-bytes (single-byte flip), sid, digest (one coeff), instanceIdx, and
  fallbackNonce/mu — isolating the nonce at the block level via
  `deriveSeedInstanceBlock` + `deriveUniformPolyBatchFromSeed` so the separation
  is proven to come from the absorbed nonce, not the output count.

## LV-AUDIT-014: Reported off-by-one in `sampleRootZeta` randomizer range (likely already resolved)

Status: watch

Concern:

A source finding reported that `sampleRootZeta` produces a per-coefficient zeta
support of `[-(G-1), G-2]` (where `G = 2^gadgetLogBase`), i.e. `2G-2` distinct
values missing `+(G-1)`, slightly asymmetric and non-uniform versus the paper's
required `||zeta||_inf < G` (support `{-(G-1), ..., G-1}`, `2G-1` values). If
present, this would be a negligible statistical-distance perturbation for the
smudging argument at `G = 2^110` (one missing positive value out of ~`2G`),
with no binding/correctness impact.

Current state:

A direct re-read of the current code does NOT reproduce the reported off-by-one.
With `eta = 2^gadgetLogBase - 1`, `sampleBits = gadgetLogBase + 1`, and the
rejection loop discarding only the single all-ones value
`sampleMask = 2^(gadgetLogBase+1) - 1`, the accepted `raw` ranges over
`[0, 2*G - 2]`. The negative branch (`raw <= eta`) yields magnitudes
`[0, G-1]` (values `{-(G-1), ..., 0}`); the positive branch (`raw > eta`,
i.e. `raw in [G, 2G-2]`) yields magnitudes `raw - eta in [1, G-1]`
(values `{1, ..., G-1}`). The union is the *full symmetric* interval
`{-(G-1), ..., G-1}`, all `2G-1` values, with `+(G-1)` present. So the support
appears correct and symmetric in the current revision; the finding may reflect
an earlier version or a different rejection bound. Kept as `watch` so nothing is
silently lost and so a future change to the rejection bound is re-checked.
`||zeta||_inf < G` holds either way, so there is no security or correctness
concern at the eval working point. The underlying `wideU64` arithmetic
(`OneShift(gadgetLogBase)`, `Mask(gadgetLogBase+1)`, `Sub`, `Mod`) is correct and
UB-free at the guarded range `gadgetLogBase <= 127`.

Relevant files:

- `LogVoleCore.cpp:927-947` (eta/sampleBits/sampleMask and the
  negative/positive magnitude mapping — re-read confirms full symmetric support)
- `LogVoleCore.cpp:920-923` (`gadgetLogBase == 0 || gadgetLogBase > 127 -> false`
  guard)
- clean-ot reference: `trunclabel_shared_ops.cpp` / rootdigest sampling
  (cross-check intended `||zeta|| < g` range)
- TeX: `rootdigest.tex` (`zeta_rt` from `{zeta : ||zeta||_inf < g}`);
  `ringlabel-online.tex:18`

Evidence:

- Re-derivation from `LogVoleCore.cpp:927-947`: positive-branch maximum magnitude
  `= raw_max - eta = (2G-2) - (G-1) = G-1`, so `+(G-1)` IS reachable and the
  support is symmetric — contradicting the reported `[-(G-1), G-2]`.

What would close it:

- Confirm with the original finder which revision exhibited the asymmetric
  support, or accept that the current code already samples the full symmetric
  `(-G, G)` and close the item.

Recommended targeted test:

- A small unit test at a tiny `gadgetLogBase` (e.g. 3) that enumerates the zeta
  support over many draws and asserts it equals `{-(G-1), ..., G-1}` symmetric,
  pinning the boundary for any future change to the rejection bound.

## LV-AUDIT-015: Public CRS polynomials (`B*`, LHE `a`, LacE `b0/b1`) are derived from fixed compile-time constants and reused across all sessions (intended CRS model)

Status: watch

Concern:

`buildLhePublicANttImpl` (`a`), `buildLencPublicBNttImpl` (`b0, b1`), and the
root randomizer matrix `B*` are all derived from hard-coded nonce/domain
constants via `deriveUniformPolyFromNonceNtt` (RO-expanded) and process-cached
keyed only on ring params. None depends on `sid`/`digest`/any per-session value,
so identical `a/b0/b1/B*` are reused for every session and recursion instance.
A reviewer could mistake this fixed-constant derivation for a missing
per-session randomization, or "fix" it by sampling a public value from a secret
PRNG (which would break sender/receiver agreement). For `B*` specifically, the
derivation uses a fixed nonce with NO sid/PRNG/per-session salt, yet `B*` is
still transmitted in the offline message and validated/used by the receiver.

Current state:

This matches the paper's CRS model. The paper treats `a` (lhe-trunc.tex setup)
and the LacE node keys / `B*` (rootdigest.tex SetupRoot) as public CRS-style
parameters; RLWE/Ring-SIS hardness holds for any fixed public matrix, even
adversarially-known. The root-digest hiding lemma is a leftover-hash-lemma
stated for any *fixed* uniformly-distributed `B*` independent of zeta; a
Blake2-of-fixed-nonce output is indistinguishable from uniform in the ROM (where
the semi-honest proof lives), and zeta is freshly sampled from the per-session
secret PRNG, so published `d'_rt` differs per session. Reuse does not weaken the
SIS/binding side (Ring-SIS is defined w.r.t. a single fixed public matrix). The
only thing lost relative to the paper is per-session freshness of `B*`, which
the hiding/binding arguments do not rely on. Note `ct2` IS correctly
domain-separated by `(seed, sid, digest, instanceIdx)` — the contrast is
intentional.

Relevant files:

- `LogVoleLhe.cpp:76` (`a <- nonce 0xA11ACE5E`), `:79-101` (process-cached, keyed
  only on ring params)
- `LogVoleLenc.cpp:131` (`b0, b1 <- nonce 0xC0DEC0DE`), `:166-185` (cached)
- `LogVoleCore.cpp:1077-1081`
  (`publicBStarNtt[idx] = deriveUniformPolyFromNonceNtt(ctx,
  0x52544E43524F4F54 'RTNCROOT', 0xB57A52, idx)` — fixed nonce, NO sid/PRNG);
  still transmitted/stored/validated at `LogVoleCore.cpp:1190-1191,1214` and used
  by the receiver at `prepareRootDigestReceiver:1339`; zeta_rt freshly sampled
  from the secret PRNG at `LogVoleCore.cpp:913-962`
- clean-ot reference: loglabel lhe/lenc backends build public `a/b` from a fixed
  derivation; `trunclabel_protocol.cpp` + `goldlabel_protocol.cpp` root setup use
  the same deterministic public `B*`
- TeX: `lhe-trunc.tex:5-12` (`a <- R_q^w` in setup); `rootdigest.tex:9,15`
  (public node key `(b1, b2)` and `B* <- R_q^{1xm}` sampled in SetupRoot);
  `Digest-Properties.tex:53-142` lem:randrootdigest-hiding-main /
  thm:rootdigest-lhl-inst (LHL stated for each fixed `B*`)

Evidence:

- All three public matrices are RO-expanded from compile-time constants and
  cached on ring params only; none takes a per-session input.
- The receiver consumes the *transmitted* `B*`
  (`message.mPublicBStarNtt`), so the S->R structure is faithful even though the
  generation is deterministic — sampling `B*` from a secret PRNG without
  transmitting it would break cross-party agreement.

What would close it:

- No change required for the semi-honest build. Optionally add one-line code
  comments at `LogVoleLhe.cpp:76`, `LogVoleLenc.cpp:131`, and
  `LogVoleCore.cpp:1080` stating that `a/b0/b1/B*` are intentional fixed public
  CRS values (public RLWE/Ajtai matrix), that session-independence is by design,
  and that the hiding lemma conditions on a fixed uniform `B*` with entropy from
  the secret per-session zeta.
- If the malicious-secure variant is ever implemented, re-confirm the
  near-collision Ring-SIS argument (`proofsh-trunc.tex:278-281`) is content with
  a globally-reused `B*`.

Recommended targeted test:

- None required. A code comment guards against a future "add sid to the public
  matrix" misedit that would break sender/receiver agreement.

## LV-AUDIT-016: Golden seed is drawn fresh from the sender PRNG instead of `H(id, d'_rt, k'_rt, counter)` (distributionally equivalent for semi-honest)

Status: watch

Concern:

The paper derives each candidate seed deterministically through the random
oracle as `seed = H(id, d_rt, k'_rt, q)` and rejection-samples by bumping the
counter `q`. The implementation instead draws a fresh 16-byte (= lambda-bit)
seed directly from the sender's real PRNG on each of up to 100 attempts and
accepts the first whose hashed correction ciphertexts pass the good-interval
predicate (`validateGoldenSeedCandidate`). The accepted-seed marginal
distribution is identical in both cases (a uniform draw from the "golden" set
defined by the public good-interval predicate), and the acceptance predicate
depends only on values a corrupt-receiver simulator can reproduce. In the paper
the seed is unpredictable because it depends on the sender's secret `k'_rt`; in
the impl it is unpredictable because it is the sender's private PRNG output — in
both cases it is the sender's secret choice, independent of `sk1`, revealed only
at online time. The released seed only enables `ct2 = H_ct(seed, ...)`
reconstruction and does not encode the LWE secret.

Current state:

No leakage and no security impact for the interactive mode realized here.
Worth recording because (a) the seed is not bound to `(id, d'_rt, k'_rt)`, so it
is not reproducible/deterministic the way the paper specifies, and (b) the
non-interactive mode of `ringlabel-online.tex` (deriving
`(sk'_rt, seed) = H(id, d'_rt)`) is not implemented.

Relevant files:

- `LogVoleCore.cpp:2894-2895` and `:1659-1681`
  (`AlignedUnVec<u8> seed(16); prng.get(seed.data(), seed.size());` accept first
  candidate passing `validateGoldenSeedCandidate`); candidates derived via
  `deriveSeedInstanceBlock(seed, sid, digest, instanceIdx, mu)`; seed released at
  online time in `RootResponseMessage.mSeed` (`LogVoleCore.cpp:1418`) /
  `SenderOnlineOutput.mSeed`
- clean-ot reference: `goldlabel_protocol.cpp:314,:391` (FindGoldenSeed candidate
  generation / golden-seed grinding wrapper)
- TeX: `golden-seed.tex:16` (`seed := H(id, d_rt, k_rt, q)`);
  `ringlabel-online.tex:27` (`seed := FindGoldenSeed(id, k'_rt, d'_rt)`);
  `lower-golden.tex:147-149` (predicate exposes only ct validity)

Evidence:

- The seed is a real PRNG draw, not a hash of secret-dependent material; the
  acceptance predicate is public and reproducible by a simulator.

What would close it:

- No change required for security. If exact paper conformance / determinism is
  desired, derive the candidate seed via the RO as
  `H(id, d'_rt, k'_rt, counter)`; otherwise document that the implemented variant
  is the interactive mode with an independently-sampled golden seed,
  distributionally equivalent for semi-honest security.

Recommended targeted test:

- None required (the live ct2 parity is covered by LV-AUDIT-025).

## LV-AUDIT-017: Truncated gadget path uses centered (signed) representation; paper notation specifies non-centered `gdecomp`

Status: watch

Concern:

For the truncated internal path the port computes `gdecompHi` via a *centered*
base-`g` decomposition: digits land in `(-g/2, g/2]` (stored as `-d mod q_j` when
negative, with borrow propagation). `notation.tex:68` defines `gdecomp` with
non-centered digits in `[0, g)`. A future reader comparing line-by-line to
`notation.tex` could "fix" it to non-centered, enlarging `low_g(d)` up to `g`
and eroding the truncation margin.

Current state:

Verified numerically (50k trials at default `digitBits = 110 / q ~ 2^220`, 20k at
a generic `q`) that the centered full decomposition reconstructs exactly and that
`gdecompHi(startLevel = 1)` yields `high_g(d)` with the dropped digit bounded by
`|low_g(d)| <= g/2` — *strictly tighter* than the paper's `<= g` bound, so the
truncation noise bound (`~ n*g*max(Dbar)`) is respected with margin. keygen and
apply both use the identical centered decomposition, so the LHE/LENC inner
products stay consistent. Matches clean-ot. The divergence is purely
representational.

Relevant files:

- `LogVoleRing.cpp:999` (`gadgetDecomposeBitsRangeCentered`) and `:331-414`
  (`centeredDecomposeSlow`)
- Call sites: `LogVoleLhe.cpp:374,558`; `LogVoleLenc.cpp:390`;
  `LogVoleCore.cpp:582,1297,2555`
- clean-ot reference: `ring_ops.cpp` (centered/signed-digit decomposition for the
  truncated `gdecompHi` path)
- TeX: `notation.tex:68` (`gdecomp`: `||x||_inf < g`, `x.g = x`) and `:70`
  (`gadgetHi`/`gdecompHi`, `low_g`/`high_g`); `app-trunc.tex`
  (`||low_g(d)||_inf <= g`)

Evidence:

- Centered digits are within (in fact tighter than) the paper's stated bound, so
  correctness/noise budgets are preserved.

What would close it:

- Document in code/AUDIT.md that the truncated gadget intentionally uses a
  centered (signed) representation, tighter than the paper's non-centered
  `gdecomp`, and that this matches clean-ot. Optionally add a remark in the TeX
  truncated section.

Recommended targeted test:

- `LogVole_Oracle_CrtComposeZpLabelRoundTrip` and
  `LogVole_Oracle_TruncatedDropDigitNoiseMargin` both pin the centered
  representation: they recompose centered AND non-centered decompositions and
  assert both equal the same Z_p label while asserting at least one per-digit
  residue differs, making a silent change of representation detectable.

## LV-AUDIT-018: LHE encryption noise sigma is scaled by `sqrt(lacct width)`, diverging from the paper's fixed `s=8` per-entry sampling

Status: watch

Concern:

The paper specifies the LHE error matrix `E_1` is sampled entrywise from a fixed
error distribution `oD` (Gaussian width `s = 8`, `sigma ~ 3.19`). The
implementation instead samples `E_1` with per-coefficient std-dev
`lheSigma = 3.19 * sqrt(widthPadded)`, inflating the encryption (flooding) noise
proportionally to the LacE aggregation width rather than keeping it at fixed
`oD`. The reference clean-ot does exactly the same (with a comment that it is
intentional — "keep the flooding noise proportional to the active aggregation
width instead of tying it directly to q"). This is a deliberate design choice not
reflected in the literal `lhe-trunc.tex` pseudocode.

Current state:

No correctness or security break observed: larger encryption noise is
conservative for hiding and is absorbed by the rounding/denoise margin; the
clipped-Gaussian bounds every coefficient by `+-sqrt(128)*lheSigma` so the
`e_lhe` term feeding eq:trunc-rounding-condition stays finite. The only risk is
inconsistency between the proven `B_lhe` (if computed with fixed `s=8`) and the
implemented `sqrt(width)`-scaled noise (a noise-budget reconciliation —
see LV-AUDIT-019).

Relevant files:

- `LogVoleShrinkExpand.cpp:497-498` (`lheSigma = computeSigma(sqrt(widthPadded))`)
  and `:195-198` (`computeSigma = kNoiseStdS * factor`, `kNoiseStdS = 3.19` at
  `:18`)
- clean-ot reference: `shrinkexpand_backend_seal.cpp:429`
  (`compute_sigma(params, sqrt(lacct.width_padded))`) and `:114-121`
  (`compute_sigma`) — with an intentional comment
- TeX: `lhe-trunc.tex:20` (`E_1 <- oD^{wxtau'}`); `app-trunc.tex:60-91`
  lem:trunc-lhe-product and `:293-305` eq:trunc-rounding-condition; setup brief
  `EstimateNoiseBound` with `s_LacE = s_LHE = 8`

Evidence:

- The sigma factor is literally `sqrt(widthPadded)`, matching clean-ot's
  `compute_sigma(params, sqrt(width))`.

What would close it:

- Confirm with the authors that the `sqrt(width)`-scaled LHE/LENC flooding noise
  is intended and that `EstimateNoiseBound`/`B_lhe` in the eval set was derived
  with this scaling (not fixed `s=8`). If so, add a one-line remark in
  `lhe-trunc.tex` / the noise section that the implemented `oD` width grows with
  the aggregation width.

Recommended targeted test:

- The noise-margin oracle `LogVole_Oracle_TruncatedDropDigitNoiseMargin` checks
  the residual against a from-scratch budget; cross-check against the
  noise-budget reconciliation in LV-AUDIT-019.

## LV-AUDIT-019: Truncation noise margin omits the `sqrt(lambda)` factor of `max(Dbar)` in `estimateNoiseBoundLog2`

Status: watch

Concern:

The paper truncation margin is `n*g*max(Dbar)*(1 + log2 mu)` with
`max(Dbar) = sqrt(lambda)*s`. The implemented `log2Trunc` term uses `s` without
the `sqrt(lambda)` factor, undercounting the truncation term by ~11x. Identical
to clean-ot. Distinct from the runtime clamp issue (LV-AUDIT-020, a separate
`sqrt(2pi)` factor on the actual sampled errors): this is purely the analytic
estimator term.

Current state:

Negligible: the truncation term is dominated by `B_lenc + B_lhe`; changing it
stays far below the `delta_j > 2B` rounding gap.

Relevant files:

- `LogVoleCore.cpp:205-209` (the `log2Trunc` term)
- clean-ot reference: `goldlabel_backend_seal.cpp:206-207` (identical)
- TeX: `app-trunc.tex`; `golden-seed.tex:50` (paper margin
  `n*g*max(Dbar)*(1 + log2 mu)`, `max(Dbar) = sqrt(lambda)*s`)

Evidence:

- The estimator term carries `s` but not `sqrt(lambda)`, an ~11x undercount of a
  term that is already dominated.

What would close it:

- Multiply the truncation term by `sqrt(lambda)` for fidelity with the paper
  bound; coordinate with clean-ot.

Recommended targeted test:

- `LogVole_Oracle_TruncatedDropDigitNoiseMargin` builds a from-scratch margin
  that explicitly includes `sqrt(lambda)*max(Dbar)` (measuring the actual dropped
  digit norm), catching this omission.

## LV-AUDIT-020: Gaussian error clamp at `sqrt(lambda)*sigma` is tighter than the paper's `max(Dbar)` coefficient bound (benign, conservative)

Status: watch

Concern:

The implementation clamps each Gaussian error coefficient at
`maxDev = sqrt(lambda)*sigma ~ 11.31*sigma`. The paper's coefficient bound
`max(Dbar)` used in the dropped-digit analysis is
`sqrt(lambda)*s = sqrt(lambda)*sqrt(2pi)*sigma ~ 28.36*sigma` (a factor
`sqrt(2pi)` larger). The implementation thus clamps ~`sqrt(2pi)`x tighter. This
is the runtime-sampling clamp, distinct from the analytic-estimator undercount in
LV-AUDIT-019.

Current state:

Benign and conservative: actual sampled errors (and hence the dropped-digit term
`r*low_g(d)`) are smaller than the paper's bound, improving correctness margin.
Per-coordinate tail mass removed at `11.31 sigma` is `erfc(11.31/sqrt2) ~ 2^-96`;
aggregate statistical distance from the untruncated Gaussian stays below `2^-46`
even for `2^50` sampled coefficients, below the statistical security parameter
(40). No security or correctness degradation.

Relevant files:

- `LogVoleCore.cpp:657-661` (`rootNoiseMaxDeviation = sqrt(128)*sigma` —
  confirmed by direct read)
- `LogVoleRing.cpp:1411` (`ClippedNormalDistribution(0, sigma, maxDev)`)
- `LogVoleShrinkExpand.cpp:449,498` (`lencMaxDev/lheMaxDev = sqrt(128)*sigma`)
- TeX: `golden-seed.tex:50,55` (TinyLabels: `max Dbar = sqrt(lambda)*s`,
  `s = sigma*sqrt(2pi)`); `prelims-app.tex:160` (lem:trunc-gaussian-close:
  truncated vs untruncated Gaussian `2^-lambda` close)

Evidence:

- The clamp constant is `sqrt(128)*sigma`, a factor `sqrt(2pi)` below the
  paper's `max(Dbar)`.

What would close it:

- No change required. Optionally document that the implementation's effective
  `max(Dbar)` clamp is `sqrt(lambda)*sigma` (not `sqrt(lambda)*s`), explaining why
  the runtime dropped-digit term is below the paper's analytic `n*g*max(Dbar)`
  bound.

Recommended targeted test:

- `LogVole_Oracle_TruncatedDropDigitNoiseMargin` part (A) measures the actual
  centered-inf-norm of impl high digits and asserts the centered bound
  `<= 2^(g-1)` is tight while the paper's `2^g` also holds — recording which
  bound binds.

## LV-AUDIT-021: Dead domain-separation constants, an ignored `domainTag`, and a vestigial second noise-budget path

Status: fixed

Update:

The dead domain constants, ignored `sampleUniformBatch` `domainTag`, and
vestigial `computeBaseNoiseFloor` / `mEffectiveNoiseBound` path have been
removed.

The historical concern text below records what was removed.

Concern:

Three related dead/misleading artifacts that could each invite a future
crypto-code footgun of the secret-from-public-seed family (the LV-AUDIT-001
family):

1. Six domain-separation constants are defined exactly once and referenced
   nowhere — `kLencRDomain`, `kLencCtNoiseDomain`, `kLencTruncRDomain`,
   `kLencTruncCtNoiseDomain` (`LogVoleLenc.cpp:16-19`), `kLheNoiseDomain`
   (`LogVoleLhe.cpp:16`), and `kSeedBytesDomain` (`LogVoleRing.cpp:28`). They are
   vestigial from the pre-LV-AUDIT-001 design in which secret noise was derived
   from public domain tags; that design was correctly replaced by direct PRNG
   sampling, but the constants were left behind. A developer could wire one of
   these dead tags into a sampler believing it provides separation.

2. `sampleUniformBatch` takes a `domainTag` argument and explicitly discards it
   (`(void)domainTag`); callers pass mnemonic tags (`0x5254534B 'RTSK'` at
   `LogVoleCore.cpp:1096`, `0xA002` at `LogVoleShrinkExpand.cpp:434`) that look
   like separators but contribute nothing — the actual separation is by
   sequential PRNG draw order.

3. A second noise-budget function `computeBaseNoiseFloor` hardcodes
   `T = 32768` and `L = 10`, and its result is stored in
   `ShrinkExpand{Sender,Receiver}State.mEffectiveNoiseBound`, which is only ever
   assigned — never read by any rejection or validation logic. The live budget is
   `estimateNoiseBoundLog2`, which derives `T` from params.

Current state:

No functional or security bug today: the unused constants are inert, the ignored
`domainTag` does not affect output (PRNG sequential draws are correctly ordered),
and the hardcoded-`T` budget gates nothing. Pure maintenance/clarity hazard:
if a future change wires `mEffectiveNoiseBound` into the noise rejection while
still hardcoding `T = 32768`, the budget would be under-provisioned for VOLE sizes
with reuse count `T > 32768` (`totalLabels > 32768*n*mu ~ 2^32`), causing silent
decryption failures.

Relevant files:

- `LogVoleLenc.cpp:16-19`, `LogVoleLhe.cpp:16`, `LogVoleRing.cpp:28` (six dead
  constants — each confirmed to appear only at its definition by repo-wide grep)
- `LogVoleShrinkExpand.cpp:392-394` (`sampleUniformBatch` takes `domainTag` then
  `(void)domainTag`); callers at `LogVoleCore.cpp:1096`,
  `LogVoleShrinkExpand.cpp:434`
- `LogVoleShrinkExpand.cpp:145-193` (`computeBaseNoiseFloor`: hardcoded
  `T = 32768.0`, `L = 10.0`); `:422,574` (`mEffectiveNoiseBound` assigned);
  `LogVoleTypes.h:142,155` (storage); only equality-checked in
  `test_shrinkexpand.cpp:498-499` / `test_shrinkexpand_coproto.cpp:337-338` —
  never read for a decision (confirmed by grep)
- Live secret-sampling paths correctly draw from `PRNG&`:
  `sampleErrorPolyNtt`, `addPolyError`, `sampleUniformPoly`
  (`LogVoleLenc.cpp:486-499,1029,1403`; `LogVoleLhe.cpp:246`;
  `LogVoleCore.cpp:897`)
- The live noise gate is `estimateNoiseBoundLog2` (`LogVoleCore.cpp:155`), which
  derives `T` from params (`estimateReuseCountLog2`)
- clean-ot reference: `lhe_ops.cpp:22` derives a per-(row,col) domain-separated
  noise seed via `derive_noise_seed(..., k_lhe_noise_domain, ...)` at `:317-322` —
  the PORT kept `kLheNoiseDomain` but draws noise directly from `PRNG&` (the
  refactor artifact intended by LV-AUDIT-001)
- TeX: `app-trunc.tex:8-9` (masks/errors must be secret); `lenc-trunc.tex:22-25`;
  `golden-seed.tex` (`EstimateNoiseBound` is the live budget)

Evidence:

- Grep confirms each constant appears only at definition; `mEffectiveNoiseBound`
  is only assigned and test-compared; `sampleUniformBatch` discards its tag.

What would close it:

- Delete the six unused constants (`LogVoleLenc.cpp:16-19`, `LogVoleLhe.cpp:16`,
  `LogVoleRing.cpp:28`).
- Either remove the `domainTag` parameter from `sampleUniformBatch` and its two
  call sites, or actually fold it into the seal seed so it provides the
  separation its name implies.
- Either remove the dead `computeBaseNoiseFloor`/`mEffectiveNoiseBound` path, or
  unify it with `estimateNoiseBoundLog2` (single source of truth that derives `T`
  from parameters). If kept, comment that it is not the live noise gate.
- (If exact cross-validation against clean-ot's noise stream is later desired,
  restore explicit per-stream seed derivation for `kLheNoiseDomain` instead of
  deleting it.)

Recommended targeted test:

- Extend the LV-AUDIT-001 grep-based regression to flag any new use of the
  removed constants or any read of `mEffectiveNoiseBound` in a rejection path.

## LV-AUDIT-022: `wideU64OneShift` has latent shift-by->=64 UB for `bit >= 128`

Status: fixed

Update 2026-06-05:

`wideU64OneShift` now returns zero for `bit >= 128` before evaluating the
native shift. The default test `LogVole_Core_WideU64OneShiftBounds` covers
`0, 63, 64, 127, 128, 255`, pinning both boundary behavior and the saturation
case.

Concern:

`wideU64OneShift(bit)` for `bit` in `[64, 127]` computes `u64(1) << (bit-64)`
(shift `0..63`, well-defined). For `bit >= 128` the shift amount `bit-64 >= 64`
is C++ undefined behavior, silently producing a wrong 128-bit value rather than
asserting. The helper is unguarded and relies entirely on each caller's bounds
check. `wideU64Mask` is fine — its `bits >= 128` branch returns all-ones before
any shift.

Current state:

No current path reaches the UB. All reachable call sites pass the constant 127 or
`gadgetLogBase`, and `sampleRootZeta` hard-guards
`gadgetLogBase == 0 || gadgetLogBase > 127 -> return false`, so `bit <= 127`
today; `sampleBits = gadgetLogBase + 1 <= 128` which `wideU64Mask` handles.
Verified correct for `bit = 0/1/62/63/64/65/126/127` against exact 128-bit
values. Latent footgun only.

Relevant files:

- `LogVoleArithmetic.h:30-33` (`wideU64OneShift`: `bit >= 64` path computes
  `u64(1) << (bit-64)` -> UB when `bit >= 128`) and `:35-54` (`wideU64Mask`
  routes `bits >= 128` to all-ones, safe)
- Reachable call sites: `LogVole.cpp:798` (const 127); `LogVoleCore.cpp:2762,927`;
  `LogVoleShrinkExpand.cpp:969` (const 127 or guarded `gadgetLogBase <= 127`)
- Sole variable feeder is `gadgetLogBase`, hard-guarded in `sampleRootZeta`
  (`LogVoleCore.cpp:920`)
- clean-ot reference: `trunclabel_protocol.cpp:462-470` (identical `<= 127` guard
  and the same native-shift UB risk)
- TeX: n/a (`rootdigest.tex:34-43` only constrains `||zeta|| < g`)

Evidence:

- Direct read of `LogVoleArithmetic.h:30-33` confirms the `bit >= 64` branch
  shifts by `bit-64` with no internal clamp; safety depends on the
  `sampleRootZeta` guard.

## LV-AUDIT-023: No independent test of the `gdecompHi` high-part identity or the Z_p CRT wrap/unwrap round-trip

Status: open

Concern:

The only standard centered-gadget test verifies
`gadgetDecomposeBitsRangeCentered(startLevel = 0, full)` round-trips to the
original. The protocol instead relies on `startLevel = 1` (`gdecompHi`) producing
`high_g(d)` such that `g_hi^T . gdecompHi(d) = d - low_g(d)`; this identity is
never checked in isolation. Likewise the Z_p CRT wrap (lift by `floor(q/p)`) and
unwrap (scale-and-round) are only validated indirectly through the multi-second
end-to-end Civole tests, not as a standalone encode->decode oracle. Both
confirmed correct via numerical models, but in-tree coverage shares the
LV-AUDIT-007 weakness (no paper-oracle for the exact identities the protocol
depends on).

Current state:

No bug present, but a future regression in `centeredDecomposeSlow`'s borrow/sign
logic or in `unwrapRingLabelsCrt`'s fractional accumulation could pass the
existing standard suite. The `startLevel = 0` roundtrip test does not exercise
the dropped-low-digit semantics.

Relevant files:

- `test_ring_ops.cpp:123-141`
  (`CenteredGadgetDecomposeRecomposeBits` tests ONLY `startLevel = 0` full
  roundtrip)
- `test_encoding.cpp` covers only message serialization
- The Z_p wrap->unwrap path is exercised only end-to-end via `test_civole.cpp`
- TeX: `proofcor.tex:53,132` (`sk_x = d.sk_1 + k` relation that `gdecompHi` must
  preserve)

Evidence:

- The standard suite checks only the `startLevel = 0` full roundtrip; the
  `startLevel = 1` high-part identity and the Z_p CRT round-trip have no isolated
  oracle.

What would close it:

- Add two small independent tests:
  (1) recompose `g_hi` powers (`g^1..g^{tau-1}`) over the `startLevel = 1`
  centered digits and assert it equals `d` minus a residue with
  `|coeff| <= g/2` (i.e. equals `high_g(d)`);
  (2) a standalone `wrapZp*Crt -> unwrapRingLabelsCrt(scaleAndRound = true)`
  round-trip over random `Z_p` vectors (and with bounded injected noise
  `|e| < delta/2`) asserting exact recovery, computed without reusing protocol
  helpers for the expected value.

Recommended targeted test:

- `LogVole_Oracle_RecursiveGdecompHiIdentityRhoGt1` (CRT-composes the digest,
  centers, drops low `g` bits via integer shift, and checks the per-limb unbundled
  high-part output equals the from-scratch high part at `rho > 1`) and
  `LogVole_Oracle_CrtComposeZpLabelRoundTrip` (hand Garner/CRT compose plus an
  in-test modexp recompose, asserting `recompose(decompose(p)) == p` for both
  centered and non-centered, and a small-value CRT round-trip).

## LV-AUDIT-024: Verified-correct truncated LHE algebra — `r.high_g(d)` recovery and `r*d` cancellation (positive coverage record)

Status: watch

Concern:

Positive coverage record (not a defect), retained so a future refactor does not
silently break the verified truncated LHE algebra. First-principles derivation:
`enc_1Trunc` gives `ct_1[t][u] = a[t]s_1[u] + r[t]g^{u+1} + E_1[t][u]`.
`lheApplyCt1Trunc` computes
`ct_res[t] = sum_u ct_1[t][u] * g_hi^{-1}(d)[u]
= a[t](s_1^T g_hi^{-1}(d)) + r[t]*high_g(d) + E_1[t].g_hi^{-1}(d)`.
`deriveSkxTrunc` gives `sk_x = s_1^T g_hi^{-1}(d) + tbk'` with the *identical*
centered decomposition, so `lheDec`'s
`m_res = ct_res - a.sk_x = r.high_g(d) + e_lhe + (ct_k - a.tbk')
= r.high_g(d) + e_lhe + tbk`. Subtracting LENC eval (which contains `+r*d` via
the shared mask `r`) telescopes to
`x(.)s + tbk - r.low_g(d) - e_drop + e_lhe - e_lenc`, exactly matching
`app-trunc.tex:264-281`. `low_g(d) = digit_0` bounded by `g/2` (impl, centered)
`<= g` (paper). All shapes use `tau' = tau-1`.

Current state:

Confirms LHE enc/dec algebra, linear-homomorphism, truncation handling,
decryption-recovers-linear-function, and LENC composition are correct under the
paper's truncated variant. Closes the C3 algebraic-correctness question
affirmatively and addresses the LV-AUDIT-007 trap for LHE (`test_lhe.cpp`
recomputes `high_g` via `recompute_trunc_high_part` rather than reusing the dec
path).

Relevant files:

- `LogVoleLhe.cpp:358-413` (`lheApplyCt1Trunc`), `:540-576` (`deriveSkxTrunc`),
  `:434-500` (`lheDec`), `:260-299` (`lheEnc1Trunc`)
- `LogVoleShrinkExpand.cpp:492,505` (shared `r` mask), `:763-806`
  (apply->dec->subtract eval)
- clean-ot reference: `lhe_ops.cpp:341-536`
  (`lhe_enc1_trunc`/`lhe_apply_ct1_trunc`), `:719-772` (`derive_skx_trunc`) —
  semantically identical to PORT
- TeX: `lhe-trunc.tex:16-55`; `shrinkexpand-trunc.tex:32-39`;
  `app-trunc.tex:30-116` (eq:trunc-ctres, eq:trunc-lhe-eval,
  lem:trunc-lhe-product), `:259-305`

Evidence:

- First-principles algebra above telescopes to the exact `app-trunc.tex` form;
  the existing `test_lhe.cpp` oracles recompute `high_g` independently of the dec
  path.

What would close it:

- No action. Retain `test_lhe.cpp`
  `LogVole_LheOps_Enc1ShapeDeterminismAndColumnDecrypt` and
  `_TruncApplyCt1AndDeriveSkxRelation` as genuine paper-oracle algebra checks.

Recommended targeted test:

- (Hardening) `LogVole_Oracle_TruncatedDropDigitNoiseMargin` part (B) asserts the
  noiseless truncated LHE eval+dec output equals `r*high_g(d)` (computed via an
  independent integer-shift oracle), confirming the `r*d` cancellation as a
  standing record.

## LV-AUDIT-025: LV-AUDIT-006 closure evidence used a test-only API, not the live golden-seed path (live parity independently confirmed)

Status: watch

Concern:

The functions named as LV-AUDIT-006 closure evidence
(`findGoldenSeed`/`seedLabelSampleCt2FromSeed`/`validateGoldenSeedSearch`/
`GoldenSeedSearchOutput`) are referenced only in `test_core.cpp` — they are
test-only helpers, not the live path. This is the LV-AUDIT-007 trap (closure
documented against a test helper rather than the production code).

Current state:

No correctness/security impact; live parity confirmed by reading the live path.
The live path is
`evaluateSenderSeedCandidate -> shrinkExpandExpandSender -> buildHashedCt2`,
accepted by `validateGoldenSeedCandidate` on the same `mTbk` the receiver
reconstructs. Both sides call
`buildHashedCt2(mu, seed, sid, d_prime_rt, nonce)` identically, so `ct_k`
cancels. Process/coverage risk only.

Relevant files:

- `LogVoleCore.cpp:2814,:2701`
  (`findGoldenSeed`/`seedLabelSampleCt2FromSeed`/`validateGoldenSeedSearch`/
  `GoldenSeedSearchOutput`, test-only) vs live `:1478,:1452,:2444`
- Receiver `LogVoleRingReceiver.cpp:503-504`; sender `:1607-1609`
- clean-ot reference: `goldlabel_protocol.cpp:314,:391`
- TeX: `golden-seed.tex:24-28`; `ringlabel-online.tex:84`

Evidence:

- The closure helpers appear only in tests; the live `buildHashedCt2` call is
  identical on both sides so `ct_k` cancels — live parity holds.

What would close it:

- Add a live-path regression test (drive the production golden-seed path and
  assert receiver/sender ct2 parity), or mark the helpers explicitly test-only.

Recommended targeted test:

- `LogVole_Oracle_RootEvalRelationFromFirstPrinciples` drives the live
  `shrinkExpandExpand{Sender,Receiver}` path end to end and checks the relation
  with an independent oracle, exercising the live ct2 cancellation rather than the
  test-only helper.

## LV-AUDIT-026: Untrusted-input hardening gaps in framing, label-count arithmetic, and SID tracking

Status: watch

Update 2026-06-05:

The `zpRingLabelCount` overflow path is fixed. It now computes ceiling division
as `zpLabelCount / slots + (zpLabelCount % slots != 0)`, avoiding the overflowing
`zpLabelCount + slots - 1` numerator. The default test
`LogVole_Core_ZpRingLabelCountCeilNoOverflow` covers ordinary boundaries and
`U64_MAX`.

Concern:

Three transport/robustness gaps against a non-honest peer or transport. All are
non-issues in the stated semi-honest threat model (both parties honest) but are
hardening gaps if the transport is untrusted:

1. **Length-prefixed allocation DoS.** `recvFrame` reads an 8-byte
   little-endian length header and immediately allocates `Buffer(size)` before the
   payload arrives. The only sanity check is `size > size_t::max`, a no-op on
   64-bit. A peer/MITM can announce a multi-GB/EB frame and force a large
   allocation / `bad_alloc`. No memory corruption (the buffer is sized to the
   header and `recv` fills exactly that), but the allocation attempt happens
   first.

2. **`u64` overflow in `zpRingLabelCount` (fixed).** `civoleReceiverOffline` reads
   `meta.mLabelCount` from the sender over the socket and feeds it to
   `zpRingLabelCount`, which computes `(zpLabelCount + slots - 1)/slots`. For
   `zpLabelCount` near `2^64` the numerator wraps, producing a small
   `packedWidth` while `mW/mTotalLabelCount` stays huge. Not exploitable as memory
   unsafety: the public `LogVoleReceiver::offline` rejects the mismatch via
   `state.mW != mRequestSize` (`LogVole.cpp:509-512`), and the low-level
   setX/unwrap paths are bounded (`LogVole.cpp:763`, `:1118`), so no OOB occurs —
   worst case is an internally-inconsistent state that fails later.

3. **Unbounded `mUsedSids` growth + SID `u64` wrap.** Every online call appends
   the SID to `mUsedSids` and never prunes; reuse detection is a linear
   `std::find`. `mNextSid` (u64) increments once per call; after `2^64` calls it
   wraps to 0, but a wrapped-to-already-used SID is still rejected by
   `containsSid` (defense in depth). The practical concern is monotonic memory
   growth and `O(n)` per-call reuse cost for very long-lived sessions
   (billions of calls — not reachable in any realistic deployment).

Current state:

No security break in the semi-honest model (the sender is honest, so the count
and frame sizes are correct; SID wrap is infeasible and safely caught).

Relevant files:

- `LogVoleRingReceiver.cpp:51-69` (and identical `LogVoleRingSender.cpp:51-69`):
  `recvFrame`
- `LogVole.cpp:575-583` (`zpRingLabelCount`), `:968-1010` (`civoleReceiverOffline`
  takes `meta.mLabelCount` from the wire), `:762-766` (`unwrapRingLabelsCrt` guard
  that contains it), `:509-512` (public `offline` mismatch rejection),
  `:1118` (`x.size() == state.mW` guard)
- `LogVole.cpp:411 & 540` (`mNextSid++`), `:232-239 & 1045-1047 & 1099-1101`
  (`mUsedSids.resize` + append), `:197-200` (`containsSid` linear scan)
- clean-ot reference: framing helpers use the same length-prefix pattern
- TeX: `func-civole.tex:12` (`w` is a public agreed parameter); framing is an
  implementation detail not specified in `alg/*.tex`

Evidence:

- `recvFrame` allocates from the header before `recv`; `zpRingLabelCount` no
  longer has the overflowing ceil-div; `mUsedSids` is append-only with a linear
  membership scan.

What would close it:

- Clamp the frame length to a protocol-derived maximum (a small multiple of the
  largest legitimate message size from the configured params) before allocating,
  and reject larger frames.
- Have `civoleReceiverOffline` validate `meta.mLabelCount` against an expected
  bound rather than trusting it unconditionally.
- Optional: replace `mUsedSids` with a hash set, or track a monotonic-SID
  high-water mark, if very high session counts on a single offline state are
  expected.

Recommended targeted test:

- A negative/robustness test feeding an oversized frame header and an
  out-of-range `meta.mLabelCount` and asserting graceful rejection rather than
  allocation/overflow (kept out of normal CI).

## LV-AUDIT-027: Wide-arithmetic precision and ring add/sub canonicalization hardening

Status: watch

Concern:

Two low-level arithmetic hardening gaps:

1. **`floorToWideU64` low-word precision on MSVC.** `floorToWideU64` splits a
   `long double` into hi/lo 64-bit words via `value/2^64` and
   `value - hi*2^64`. On MSVC `long double` is 64-bit (53-bit mantissa, same as
   `double`), so for inputs whose magnitude approaches `2^128` the residual cannot
   represent the low 64 bits exactly. In the only call site the argument is
   `exp2(marginExp)` with `marginExp = log2_B - log2_delta_j + 128` and
   `log2_B < log2_delta_j - 1`, so `marginExp < 127` and the value is well below
   `2^128`; the margin is used only for an inequality comparison, so a few ulps of
   low-bit imprecision are immaterial. No correctness impact in context.

2. **Ring add/sub do not reduce inputs mod q.** SEAL's
   `add_poly_coeffmod`/`sub_poly_coeffmod` assume both operands are already
   `< modulus`; `ringAddInplace`/`ringSubInplace` validate only the coefficient
   count and pass coefficients straight through. The dyadic-multiply path, by
   contrast, defensively applies `%mod` to each operand. So a poly carrying a
   coefficient `>= modulus` (e.g. a denormalized received NTT-form ciphertext not
   yet canonicalized) would produce an incorrect-but-bounded result when
   added/subtracted. No memory unsafety (lengths are validated; the result stays
   within the allocated buffer). Only triggers for inputs that violate the
   canonical-representation invariant, which honest transmitted ciphertexts do
   not.

Current state:

Neither has correctness impact for the current code paths and honest inputs.
Hardening gaps only.

Relevant files:

- `LogVoleArithmetic.h:176-194` (`floorToWideU64`); used at `LogVoleCore.cpp:339`
  (`mMargin`)
- `LogVoleRing.cpp:714-748` (`ringAddInplace`/`ringSubInplace` use
  `add_poly_coeffmod`/`sub_poly_coeffmod` directly) vs `:683-712`
  (`dyadicMultiplyAddNttInplace` reduces operands via `%mod`)
- clean-ot reference: `goldlabel_backend_seal.cpp:223-240` (`floor_to_u128`, same
  algorithm, on platforms where `long double` may be 80-bit)
- TeX: `app-trunc.tex` eq:trunc-rounding-condition (margin is a threshold,
  exactness of low bits not required); representation invariant otherwise
  unspecified

Evidence:

- `floorToWideU64` computes the low word via a `long double` subtraction;
  `ringAdd/ringSub` validate only shape (`validateShapeAgainstContext`) and do not
  reduce operands, unlike the multiply path.

What would close it:

- No change required for current usage of `floorToWideU64`. If it is ever reused
  for values near `2^128` where exact low bits matter, compute the low word with
  integer arithmetic. Optionally add a comment noting the MSVC long-double caveat.
- For consistency with the dyadic path and defense in depth, either canonicalize
  received ciphertext polynomials once on decode, or have `ringAdd`/`ringSub`
  assert/reduce operands `< modulus`. Document the canonical-input precondition.

Recommended targeted test:

- A unit test that adds/subtracts a deliberately denormalized poly (coefficient
  `>= modulus`) and asserts either correct reduction or an explicit precondition
  failure (after the canonicalization/assert is added).

## LV-AUDIT-028: Considered and dismissed this pass

The following candidate findings were investigated and **refuted** by the
adversarial verification panel. They are recorded here as watch items so the
analysis is not silently lost and so a future maintainer does not re-open them
without the empirical context.

### M1 (was High -> dropped): Recursive offline sender input omits the CRT scale `delta_j`

Claim: the `gamma == tau` branch of `seedLabelRepOfflineSenderInput`
(`LogVoleCore.cpp:2660-2698`) memsets the non-`j` limbs but does not multiply the
surviving limb `j` by `delta_j = q/q_j`, unlike the paper
(`ringlabel-offline.tex:21`, `proofcor.tex:15-16`) and clean-ot
(`goldlabel_backend_seal.cpp:793-802`), so for `tau_hi >= 2` the net product
loses one `delta_j` and yields silently-wrong VOLE output; AUDIT.md LV-AUDIT-005
was alleged to be factually wrong.

Why dismissed: REFUTED empirically by two independent reviewers. The PORT uses a
*relocated-lift convention*: the receiver `seedLabelGadgetDecomposeHiAndUnbundle`
applies `delta_j` (`LogVoleCore.cpp:2563-2596`), and the denoise comb divides out
exactly one `delta_j` (`LogVoleShrinkExpand.cpp:1056-1059`). Because the
digest-indexed pairing `d (.) sk_1` is bilinear, placing `delta_j` on the
receiver operand vs the sender operand gives the identical product
`delta_j*(d (.) sk_1)`, carrying exactly one `delta_j` into the one-`delta_j`
denoise — net-equivalent. clean-ot applies it on *both* operands, i.e. clean-ot
carries a latent *double* lift (invisible at `tau_hi == 1`); the PORT correctly
removed the redundant sender lift, so AUDIT.md LV-AUDIT-005's "fixed" rationale is
CORRECT. Decisive proof: reviewers built a from-scratch end-to-end CI-VOLE test at
`gadgetLogBase = 88` (`tau = 3, tau_hi = 2`) that genuinely exercises the
`gamma == tau` branch (asserted child `gamma == tau_hi == 2`) and checks
`m == x*Delta + k` against an independent oracle — it PASSED as shipped, and
FAILED with the recommended fix applied (max centered residual `~2^219`, the
signature of one extra uncompensated `delta_j`). Adopting the recommendation would
INTRODUCE a real double-lift bug. The two oracle unit tests
(`test_core.cpp:645-647,:701-716`) correctly lock in the unscaled value. A third
reviewer (paper-convention lens) maintained a residual Medium "latent
spec/reference divergence" view, but the two empirical reviewers (code-reading and
cryptographic-materiality lenses) both dropped it after running the test; the
verdict is drop. The only accurate residual point — no in-tree `tau_hi >= 2`
end-to-end test — is captured as LV-AUDIT-012 / LV-AUDIT-007.

### M2 (was Medium -> dropped): Truncated-root `r1` sampled from `Dbar` (not uniform), with an "unconfirmed" Gaussian-`r1` hiding lemma

Claim: the root-wrapper `r1` is sampled from the error distribution `Dbar`
(`LogVoleCore.cpp:1083-1094`) rather than uniform `R_q` per `rootdigest.tex:14-15`;
this is algebraically forced for the truncated variant and matches clean-ot, but
(a) the paper has no truncated-root-wrapper statement and (b) the hiding lemma
lem:randrootdigest-hiding-main is stated for uniform `r1`, so a Gaussian-`r1`
hiding argument is "unconfirmed" — held at Medium for that open question.

Why dismissed: REFUTED. The finding itself concedes there is no correctness or
security defect (Gaussian `r1` is the correct, algebraically-forced truncated
adaptation; the dropped-digit terms are exactly the `app-trunc.tex`
lem:trunc-lhe-product / lem:trunc-lenc-path bounds; recommendation is explicitly
"no code change required"). The Medium elevation rested solely on the alleged
"unconfirmed Gaussian-`r1` hiding lemma," which is a misreading:
lem:randrootdigest-hiding-main (`Digest-Properties.tex:52-64`) hides the published
*digest* `d'_rt` via the ring leftover-hash lemma using the receiver randomizer
`zeta` ("for every fixed `u`"), and does not involve the sender mask `r1` at all.
The Gaussian `r1` is a Ring-LWE row secret in the laconic top row, structurally
identical to the per-level masks `r^{(h)}`, and is discharged by the truncated
LacE simulation lem:lenchi-sim; `proofsh-trunc.tex:585-588` explicitly states the
change `r, r^{(1)}, ..., r^{(ell-1)} <- D` "is handled there, because these values
are the Ring-LWE row secrets in the laconic ciphertext hybrids." The composed
truncated SH theorem thm:trunc-sh-sec already covers the truncated root wrapper.
The residual editorial spec gap (no redrawn `rootdigest-trunc` figure) is exactly
the already-accepted LV-AUDIT-004 `watch`, which the finding agrees is accurate.
At most Info, already tracked; dropped as an independent item.

### M13 (was Medium -> dropped): Root-wrapper key replication neither isolates limbs nor applies `delta_t`

Claim: `replicateRootHiKeyByLimb` (`LogVoleCore.cpp:696-722`) copies the full RNS
poly `rho` times with no limb isolation and no `delta_t` lift, unlike the paper's
`hat_skr = transpose((skr_t*delta_t)_t)` (`rootdigest.tex:12-13`); held at Medium
on the premise that, like M1, the missing sender-side lift could compose
incorrectly at `tau_hi > 1` and that the only relation test checks an `s(x)x`
relation, not the full DerandRoot denoise+agg.

Why dismissed: REFUTED. Same relocated-lift convention as M1/LV-AUDIT-005, applied
to the root path: the sender `replicateRootHiKeyByLimb` does full-poly replicate
with no lift, and the receiver `seedLabelGadgetDecomposeHiAndUnbundle`
(`LogVoleCore.cpp:2536-2604`) applies BOTH per-limb isolation AND the
`delta_j = q/q_j` lift; the bilinear pairing makes the product identical, so the
unscaled sender replication is correct. The PORT matches clean-ot byte-for-byte
(`replicate_root_hi_key_by_limb` at `trunclabel_protocol.cpp:173-199` is
line-for-line identical, `(void)limb`, no lift; `gdecomp_hi_and_unbundle` at
`goldlabel_backend_seal.cpp:635-706` is identical with the explicit comment
"Canonical per-limb lift factor Delta_j = Q / q_j"). The finding's load-bearing
testability claim is false: `LogVole_Core_RootOnlineLocalRelation`
(`test_core.cpp:1131-1248`) runs at `tau_hi = 2, rho = 7` (the multi-digit AND
multi-limb regime), drives the FULL DerandRoot (`prepareRootResponseSender` +
`computeRootSenderKey` + `finalizeRootResponseReceiver`, both invoking
`denoiseAndAggRootKey` = `shrinkExpandDenoiseComb` then `seedLabelAgg` `tau -> 1`),
and asserts the end-to-end identity `m - k ~= s.x` — and it PASSES (standard,
~1.5 s). Also note the replication input is `mShrinkExpandState.mSk1` (the correct
SetupRoot left-LacE plaintext of width `tau_hi`), not a raw scalar. A
paper-full-variant vs implemented-truncated-variant convention mismatch that is
documented (LV-AUDIT-005), matches the reference, and is exercised end-to-end by a
passing standard relation test at `tau_hi > 1`. Dropped.

## LV-AUDIT-029: Depth-3 sender online cache was not populated on intermediate recursive levels

Status: fixed

Concern:

For recursive online runs with at least one non-root intermediate level, the
sender unwind expects every non-root level to have `mPrecomputedTbk` populated.
`evaluateSenderSeedCandidate` computed each intermediate level's accepted
`finalTbk`, but only returned it upward as `next.mTbk`; it did not cache that
same value on the intermediate `SenderState`. The sender online service then
aborted when unwinding through that level.

Fix:

The accepted recursive branch now stores `finalTbk` into
`state.mPrecomputedTbk` before moving it into the returned evaluation output.
The default test `LogVole_Core_ThreeLevelOfflineReuseAndInvalidWidth` now runs
three-level local online and asserts both the top-level and intermediate sender
precompute caches are populated.

Relevant files:

- `LogVoleCore.cpp` (`evaluateSenderSeedCandidate`, recursive branch)
- `LogVoleRingSender.cpp` (`senderOnlineService` unwind cache requirement)
- `test_core.cpp` (`LogVole_Core_ThreeLevelOfflineReuseAndInvalidWidth`)

## Next audit pass

Recommended next work items (incorporating the recommended oracle tests):

1. **Add the independent paper-oracle tests** (closing LV-AUDIT-007 and its
   specializations LV-AUDIT-012/-013/-017/-019/-020/-023/-024/-025):
   - `LogVole_Oracle_RootEvalRelationFromFirstPrinciples` — root relation with an
     independent sender key and a from-scratch budget that explicitly includes
     `max(Dbar)` (LV-AUDIT-012, -025).
   - `LogVole_Oracle_RecursiveGdecompHiIdentityRhoGt1` — `gdecompHi` high-part
     identity at `rho > 1`, pinning the centered representation (LV-AUDIT-017,
     -023).
   - `LogVole_Oracle_Ct2PublicMaskDomainSeparationFull` — ct2 separation across
     all of seed-bytes / sid / digest / instance / mu (LV-AUDIT-013, corroborates
     LV-AUDIT-011/-015).
   - `LogVole_Oracle_CrtComposeZpLabelRoundTrip` — Z_p CRT wrap/unwrap and
     gadget recompose round-trip, centered vs non-centered (LV-AUDIT-023, -017).
   - `LogVole_Oracle_TruncatedDropDigitNoiseMargin` — centered-digit norm bound,
     noiseless `r*high_g(d)` cancellation, and a margin that explicitly includes
     `sqrt(lambda)*max(Dbar)` (LV-AUDIT-019, -020, -024).
2. **Upstream a `tau_hi >= 2` end-to-end relation test** (e.g. `gadgetLogBase`
   small enough that `ceil(logQ/g) >= 3`) so the recursive sender-lift and
   root-key-replication branches — dead in CI today — are covered, preventing
   regression of the relocated-lift convention validated in LV-AUDIT-028
   (M1/M13).
3. **Reconcile LV-AUDIT-004 status** (`open` in the brief vs `watch` here) and
   add the root-only truncated `r1 <- D` algebra test it recommends.
4. **Author confirmations (paper-side, no code change):**
   - LV-AUDIT-011: confirm RO-ct2 masking discharges the truncated SH proof in
     lieu of explicit `chi_lenc` smudging.
   - LV-AUDIT-018 / LV-AUDIT-019: confirm `EstimateNoiseBound`/`B_lhe` were
     derived with the `sqrt(width)`-scaled LHE noise (not fixed `s=8`).
5. **LV-AUDIT-026, -027 (defensive hardening, lower priority):** add the
   `recvFrame` length clamp, bounded `meta.mLabelCount` validation, and the
   `ringAdd`/`ringSub` canonical-input precondition.
6. Re-run the default LogVole suite and the extended build after each batch of
   tests/cleanups lands.
