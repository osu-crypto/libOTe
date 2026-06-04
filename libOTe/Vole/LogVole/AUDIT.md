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

## LV-AUDIT-005: Possible double CRT lift in recursive digest/key handling

Status: open

Concern:

The receiver-side digest unbundle currently multiplies each RNS limb by the CRT
lift factor `q / q_j`. The sender-side recursive offline input also applies the
same lift convention to the retained limb. Denoise/recombine appears to remove
one lift factor. This raises a paper-vs-implementation question: are both lifts
intentional representation choices, or is one extra?

Lucian's concern:

If the receiver lifts its input, then the receiver is multiplying a ciphertext
by a polynomial with large coefficients. That can overflow the intended noise
budget. Normal correctness tests passing does not rule this out because they
mostly test implementation self-consistency and use small/friendly inputs.

Current state:

The current port matches clean-ot's apparent convention. We have not changed it
while waiting for Lucian's read.

Relevant files:

- `LogVoleCore.cpp`
  - `seedLabelGadgetDecomposeHiAndUnbundle(...)`
  - `seedLabelRepOfflineSenderInput(...)`
- `LogVoleShrinkExpand.cpp`
  - `shrinkExpandDenoiseComb(...)`
- clean-ot reference: `goldlabel_backend_seal.cpp`

Evidence:

- clean-ot appears to apply the lift in both analogous places.
- Current tests pass, including recursive tests, but expected-value paths reuse
  implementation helpers and therefore do not independently validate the TeX
  representation.
- A dedicated structural test currently encodes the receiver-side lift
  convention; that test should be treated as implementation-observation, not as
  proof that the convention is correct.

What would close it:

- Lucian confirms that the receiver lift is intended and gives the exact noise
  argument, or
- a targeted test demonstrates that the residue-only receiver representation
  is the TeX-correct one and the current lifted version has inflated noise.

Recommended targeted test:

- Under `ENABLE_LOGVOLE_EXTENDED_TESTS`, construct one recursive level with
  `rho > 1`.
- Build receiver digest input in two ways:
  - current lifted RNS representation,
  - residue-only representation with no `q / q_j` multiplication.
- Compare both against an independent paper-style recombination/noise
  calculation that does not call `seedLabelGadgetDecomposeHiAndUnbundle(...)`
  or `seedLabelRepOfflineSenderInput(...)`.
- Include larger receiver coefficients, not just the small plaintext-like
  samples used by normal correctness tests.

## LV-AUDIT-006: Golden-seed search must match clean-ot performance semantics

Status: watch

Concern:

The clean-ot implementation searches for sender seed candidates with recursive
validation. The port should preserve that behavior closely because it affects
performance and correctness margins.

Current state:

The current port contains recursive golden-seed candidate machinery and was
audited against clean-ot's structure. Randomness feeding that machinery has been
changed to avoid small/public secret seeds, but the search shape should remain
mechanically close to clean-ot.

Relevant files:

- `LogVoleCore.cpp`
- clean-ot reference: `goldlabel_protocol.cpp`

What would close it:

- A focused clean-ot parity review of:
  - candidate ordering,
  - recursive parent checks,
  - chunk/instance indexing,
  - failure behavior,
  - communication accounting if we choose to expose it.

Recommended targeted test:

- A deterministic public-seed test that forces multiple candidate attempts and
  checks that accepted candidates match the recursive validity predicate.

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
