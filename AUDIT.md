# Security Audit Tracker

This file tracks accepted security findings for libOTe. Findings use stable,
zero-padded identifiers of the form `AUD-XXX`.

Status values:

- `open`: accepted finding that still needs a fix.
- `fixed`: a fix and its regression evidence have been recorded.
- `deferred`: accepted finding whose fix is intentionally postponed.

## AUD-001: Ring-LPN regular support can lose effective weight after factor folding

Status: deferred

Affected code:

- `libOTe/Triple/RingLpn/RingLpnTriple.h`, in the sparse-support sampling path.

Concern:

The current Ring-LPN parameters sample four regular sparse polynomials with 16
nonzero positions each. When the complete support is folded modulo the degree
of the smallest relevant 1-sparse factor, collisions can reduce its effective
weight below the intended security threshold.

For the current `(mNumPolys, mPolyWeight) = (4, 16)` parameter set, the proposed
acceptance condition folds each absolute position
`blockIdx * mBlockSize + offset` modulo 128, preserving the polynomial index,
and requires at least 61 distinct folded positions across the four
polynomials. The expected rejection-sampling acceptance probability is about
0.502.

Impact:

This is a parameter-soundness issue in the Ring-LPN assumption used by the
triple construction. Sampling a support with too many folded collisions may
reduce the effective noise weight and weaken the intended concrete security.
The precise security loss is not reproduced in this repository, so no numeric
severity is assigned here.

Resolution plan:

1. Make the relevant factor degree and minimum folded weight explicit Ring-LPN
   parameters.
2. Rejection-sample the complete regular support before committing to it.
3. Add a deterministic regression test that constructs collision-heavy
   candidates and verifies rejection at weights below the configured bound.
4. Reassess the concrete threshold when the supporting attack analysis is
   available.
