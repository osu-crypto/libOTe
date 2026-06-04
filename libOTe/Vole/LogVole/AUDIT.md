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

## Next audit pass

Recommended next work items:

1. Add the targeted extended test for LV-AUDIT-005 before changing the lift
   convention.
2. Add an independent root-only truncated-wrapper parity test for LV-AUDIT-004.
3. Re-run normal LogVole tests and the extended LogVole build after those tests
   are added.
4. Only then decide whether the receiver lift, sender lift, or denoise comb
   needs to change.
