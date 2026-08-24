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

## AUD-002: KOS and IKNP receiver splitting derived incomplete child state

Status: fixed

Affected code:

- `libOTe/TwoChooseOne/Kos/KosOtExtReceiver.cpp`, in `splitBase()`.
- `libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h`, in `splitBase()`.

Concern:

`KosOtExtReceiver::splitBase()` allocated 128 child base-OT pairs but derived
only two pairs. The loop used the number of PRG banks instead of the number of
AES columns. The function passed 126 indeterminate pairs to the child receiver.

The IKNP sender had a second split-state error. Its move assignment replaced
the child's semi-honest mode with the malicious KOS default. The corresponding
IKNP receiver remained in semi-honest mode, so the peers expected different
message sizes.

Impact:

The public KOS and IKNP split APIs did not produce matching child extenders.
Applications that used these APIs could fail the protocol or derive incorrect
OT outputs. The multithreaded frontend uses this split path.

Resolution:

The KOS receiver now derives all 128 base-OT pairs. The IKNP sender now restores
semi-honest mode after deriving its child state.

Verification:

- `OtExt_Kos_Split_Test` runs 257 OTs through split KOS and IKNP children.
- Both child protocols produced the receiver-selected sender output.

## AUD-003: OT receivers accepted inconsistent choice and output lengths

Status: fixed

Affected code:

- `libOTe/TwoChooseOne/OTExtInterface.cpp`.
- KOS, KOS-Dot, and SoftSpoken receiver entry points.

Concern:

Receiver APIs require one choice bit for each output block. Several entry
points did not enforce this invariant. A mismatched caller could make an
adapter read beyond the logical choice vector. Malicious KOS could also write
beyond its retained transpose buffer or use uninitialized check data.

Impact:

Invalid local API input could cause memory-safety failures, protocol failure,
or output derived from unspecified choice bits. An application could expose
the failure to remote input if the peer controlled either requested length.

Resolution:

The shared chosen and correlated adapters now reject unequal lengths before
network activity. KOS, KOS-Dot, and both SoftSpoken receivers enforce the same
invariant for direct calls. Silent OT and the base-OT implementations already
performed this check.

Verification:

- `OtExt_InputValidation_Test` covers direct KOS and KOS-Dot calls.
- The test also covers the shared chosen-OT adapter.

## AUD-004: KOS-Dot accepted invalid base-OT dimensions

Status: fixed

Affected code:

- `libOTe/TwoChooseOne/KosDot/KosDotExtSender.cpp`, in `setBaseOts()`.
- `libOTe/TwoChooseOne/KosDot/KosDotExtReceiver.cpp`, in `setBaseOts()`.

Concern:

KOS-Dot declares a requirement of 168 base OTs. Both parties previously
accepted other dimensions. Invalid dimensions reached fixed-size operations
that assumed at least 128 columns and at most 256 choice bits.

Impact:

Invalid local API input could cause an unsigned-loop underflow, an out-of-bounds
base-key read, or an out-of-bounds matrix or stack write. Other invalid counts
could change the code parameters and invalidate the intended security level.

Resolution:

Both KOS-Dot parties now require exactly `baseOtCount()` base OTs. The sender
also requires the base-choice vector to have the same exact length.

Verification:

- `DotExt_Kos_BaseValidation_Test` rejects counts 0, 167, and 169.
- The test rejects unequal sender key and choice counts.
- The existing `DotExt_Kos_Test` passes with 168 base OTs.

## AUD-005: Malicious KOS dereferenced an end pointer for check-only blocks

Status: fixed

Affected code:

- `libOTe/TwoChooseOne/Kos/KosOtExtSender.cpp`, in the AES output-hash path.

Concern:

Malicious KOS appends a check-only block. When the requested OT count was zero
or divisible by 128, this block contained no caller outputs. The sender still
evaluated `mIter->data()` with `mIter == messages.end()` to construct an empty
span. This expression dereferenced a pointer that did not designate an object.

Impact:

The expression has undefined behavior under the C++ object model. Existing
optimized builds tolerated the expression, but compiler transformations or
runtime instrumentation could produce a failure.

Resolution:

The sender now skips AES hashing when the current block contains no caller
outputs. Pointer advancement remains unchanged for nonempty blocks.

Verification:

- `OtExt_Kos_BlockBoundary_Test` covers 0, 128, and 256 malicious KOS OTs.
- Existing KOS tests pass for AES, random-oracle, and Fiat-Shamir modes.

## AUD-006: IKNP NoHash overwrote earlier sender outputs

Status: fixed

Affected code:

- `libOTe/TwoChooseOne/Kos/KosOtExtSender.cpp`, in the output loop shared with
  IKNP.

Concern:

The sender rewound its output iterator before applying an optional hash. The
AES and random-oracle branches advanced the iterator after hashing, but the
NoHash branch did not. Each complete block after the first therefore
overwrote the first 128 sender outputs and left later outputs unwritten.

Impact:

IKNP with `HashType::NoHash` produced incorrect correlated OTs when the request
contained more than 128 outputs. The receiver and sender could disagree, and
the caller could observe output storage that the protocol had not initialized.

Resolution:

The NoHash branch now advances the output iterator by the number of outputs
written in the current block. The transpose and hashing kernels are unchanged.

Verification:

- `OtExt_NoHashMultiBlock_Test` covers 257 IKNP NoHash outputs and checks both
  receiver selection and the sender correlation.

## AUD-007: Split operations lost protocol type or configuration

Status: fixed

Affected code:

- KOS sender and receiver `splitBase()` implementations.
- IKNP sender and receiver `split()` implementations.
- KOS-Dot sender split and delta state.

Concern:

KOS children reverted to the default hash, Fiat-Shamir, and malicious-mode
settings. Type-erased IKNP splits inherited the KOS implementation and returned
KOS objects instead of IKNP objects. KOS-Dot children also lost an explicitly
configured correlation delta. A zero delta could not be distinguished from an
unset delta.

Impact:

Split peers could execute different protocol variants, return a different
concrete type than requested, or use a correlation that differed from the
parent configuration. These failures could cause protocol disagreement or
silently violate caller expectations.

Resolution:

KOS splits now copy all protocol settings. IKNP overrides the type-erased split
interface and restores semi-honest mode. KOS-Dot preserves both its delta and
an explicit set/unset flag, including for an explicitly selected zero delta.

Verification:

- `OtExt_SplitConfig_Test` checks KOS settings and runs 257 NoHash OTs through
  type-erased IKNP children.
- `DotExt_Kos_SplitDelta_Test` runs a split KOS-Dot instance with an explicit
  zero delta.

## AUD-008: The multithreaded frontend omitted the final OT range

Status: fixed

Affected code:

- `frontend/ExampleTwoChooseOne.cpp`, in sender and receiver work partitioning.

Concern:

The end boundary used the current thread index instead of the next thread
index. Thread zero therefore received an empty range, and no thread covered
the final partition.

Impact:

The multithreaded example executed fewer OTs than requested. Because the code
is an integration example, applications that copied its partitioning logic
could inherit the same omission.

Resolution:

Both roles now derive adjacent boundaries from `threadIndex` and
`threadIndex + 1`. Each rounded boundary is capped at the requested OT count,
so the ranges remain contiguous and the last range ends exactly at the
request size.

Verification:

- The complete frontend target builds with the corrected sender and receiver
  partitioning paths.

## AUD-009: KOS-Dot retained the legacy malicious consistency check

Status: fixed

Affected code:

- KOS-Dot sender and receiver consistency checks.
- The obsolete `NO_KOS_WARNING` build option.

Concern:

Ordinary KOS had adopted the newer packed-field consistency check, but KOS-Dot
still used the legacy polynomial check. The two implementations therefore did
not provide the same check structure despite relying on the same malicious OT
extension invariant.

Impact:

KOS-Dot continued to depend on the legacy check after the ordinary KOS path
had moved to the newer security analysis. The repository also exposed a
warning-suppression option even though no corresponding warning remained.

Resolution:

KOS-Dot now transposes each 128-row chunk and accumulates a GF(2^128) check for
each of its 168 base-OT columns. The receiver sends the 168 reduced column
checks and one reduced choice check. The sender verifies every column against
its base-choice bit before encoding outputs. The protocol retains 128
sacrificial rows and the existing commit-and-reveal challenge ordering. The
unused `NO_KOS_WARNING` option and generated define were removed.

Verification:

- `DotExt_Kos_Check_Test` checks all 168 equations and confirms that a modified
  raw row is rejected by the equations.
- `DotExt_Kos_Test` exercises the complete honest protocol with a nonzero
  configured delta.
- `DotExt_Kos_SplitDelta_Test` exercises the complete protocol with a zero
  configured delta.

## AUD-010: Disabled McRosRoy backends broke the default test build

Status: fixed

Affected code:

- `libOTe_Tests/BaseOT_Tests.cpp`, in adversarial McRosRoy helper templates.

Concern:

The adversarial helper templates were defined outside their feature guards.
Their bodies named Ristretto and Montgomery backend types even when the
corresponding protocol was disabled.

Impact:

The default test configuration could not compile unless optional McRosRoy
backends were enabled. This prevented the full regression suite from serving
as an audit gate for the enabled library configuration.

Resolution:

Each helper definition now uses the same feature guard as its backend and
callers.

Verification:

- The complete frontend and unit-test target builds with `ENABLE_MRR=OFF` and
  `ENABLE_MRR_TWIST=OFF`.

## AUD-011: Chosen NCO adapters accepted invalid message domains

Status: fixed

Affected code:

- `libOTe/NChooseOne/NcoOtExt.cpp`, in `sendChosen()` and `receiveChosen()`.
- The KKRT and OOS configuration interfaces.

Concern:

The chosen-message receiver did not require equal choice and output counts. It
also used each choice as a matrix column without checking the column range.
Both adapters accepted more messages than the configured NCO input domain.

The sender encodes each column index using the configured number of input bits.
When the message count exceeded that domain, distinct columns could receive
the same NCO encoding.

Impact:

Invalid dimensions could cause an out-of-bounds read from the choice vector or
the received message matrix. Reused encodings could also let a receiver decrypt
more than one chosen-message ciphertext with one NCO output.

Resolution:

The NCO interface now reports the exact configured input-bit count. The chosen
adapters reject empty message domains, unequal vectors, out-of-range choices,
and message counts larger than the configured domain. All checks occur before
network activity.

Verification:

- `NcoOt_ChosenValidation_Test` covers unequal vectors, out-of-range choices,
  and domains larger than the configured input space.
- `NcoOt_chosen` passes for a valid 256-message domain.

## AUD-012: NCO state and bounds checks were absent in release builds

Status: fixed

Affected code:

- KKRT and OOS sender `encode()` and `recvCorrection()` paths.
- KKRT and OOS receiver `encode()`, `zeroEncode()`, and `sendCorrection()`
  paths.

Concern:

Several checks were present only when `NDEBUG` was not defined. Release builds
therefore accepted OT indices outside initialized matrices, correction ranges
beyond allocated storage, duplicate receiver encodes, and corrections for
unencoded OTs.

Impact:

Invalid API calls could construct network receive spans beyond matrix storage
or access OT rows outside initialized state. Other invalid sequences could
produce incorrect corrections and violate the receiver workflow required by
the protocols.

Resolution:

The range and state checks now execute in all builds. Each receiver keeps one
byte of encode state per initialized OT. The arithmetic and transpose kernels
are unchanged. Correction counters advance only after the corresponding send
or receive completes successfully.

Verification:

- `NcoOt_StateValidation_Test` rejects missing corrections, oversized ranges,
  invalid OT indices, unencoded corrections, and duplicate encodes.
- Existing KKRT and OOS protocol tests pass in the release configuration.

## AUD-013: Moving an OOS receiver lost active protocol state

Status: fixed

Affected code:

- `libOTe/NChooseOne/Oos/OosNcoOtReceiver.h`, in move construction and move
  assignment.

Concern:

Move assignment omitted the correction index, configured input-bit count,
challenge seed, encode flags, and proof buffers. A move of an initialized
receiver therefore produced a destination with incomplete or indeterminate
state.

Impact:

Continuing the protocol with the destination could access the wrong correction
range, construct an incorrect malicious proof, or access storage outside the
active protocol state.

Resolution:

Move assignment now transfers every protocol field. It first completes any
pending operation owned by the destination. After transfer, it explicitly
clears every scalar, container, pointer, future, and proof buffer in the source
object.

Verification:

- `NcoOt_OosMove_Test` checks the complete destination state.
- The same test checks that the moved-from receiver has the default empty
  state.

## AUD-014: Silent OT splits discarded the configured security policy

Status: fixed

Affected code:

- `SilentOtExtSender::split()` and `SilentOtExtReceiver::split()`.
- Automatic configuration in the Silent OT sender and receiver.

Concern:

A split child received only the base state of the underlying SoftSpoken
extension. The child reverted to semi-honest security and the default noise,
compression, thread, and debugging settings.

Impact:

Splitting a malicious Silent OT extender silently disabled its malicious
consistency check. The child could also execute a different protocol variant
from the parent.

Resolution:

Each split now preserves the parent's security and algorithm policy. The child
remains unconfigured for an OT count. Automatic configuration uses the
preserved noise and compression settings when the child first executes.

Verification:

- `OtExt_Silent_AuditState_Test` checks both sender and receiver children after
  splitting malicious stationary instances with non-default settings.

## AUD-015: Rejected Silent OT base choices could leave usable partial state

Status: fixed

Affected code:

- `SilentOtExtReceiver::setBaseCors()` and `hasBaseCors()`.
- `RegularPprfReceiver::setChoiceBits()`.

Concern:

The receiver did not validate the number of base-OT choices before installing
PPRF state. A missing malicious-check suffix caused a later slice to fail after
the PPRF base had been installed. The readiness check ignored the missing
malicious and stationary components.

Impact:

A caller that caught the first exception could reuse an object that reported
complete base state. The next malicious check could index an empty choice
buffer.

Resolution:

The receiver validates every base-correlation dimension before mutation. Its
readiness check now covers the PPRF, malicious check, and both stationary VOLE
vectors. PPRF point encodings are also validated before active paths change.

Verification:

- `OtExt_Silent_AuditState_Test` supplies a malicious base-choice vector that
  omits the 128 check choices. The call fails without making the receiver ready.

## AUD-016: Silent VOLE checksum derandomization omitted the correlation

Status: fixed

Affected code:

- The external-base derandomization path in `SilentVoleSender::silentSendInplace()`.

Concern:

Let the receiver's coefficient correction be `diff = c' - c`. The sender must
adjust its base share by `diff * delta`. The implementation added `diff`
without multiplying by the sender's correlation `delta`.

Impact:

Malicious Silent VOLE with externally supplied base correlations failed its
consistency check except when the omitted multiplication had no effect.

Resolution:

The sender now multiplies the received coefficient correction by `delta`
before updating the final base share.

Verification:

- `Vole_Silent_malBase_test` runs malicious Silent VOLE with externally
  supplied base correlations for regular and stationary noise.

## AUD-017: Silent VOLE clear operations retained active state

Status: fixed

Affected code:

- `SilentVoleSender::clear()` and `SilentVoleReceiver::clear()`.

Concern:

Both clear operations reset their PPRF generators but retained a non-default
protocol state and configured dimensions. The sender also retained its base
VOLE share.

Impact:

A later execution observed `isConfigured() == true` and skipped configuration,
although the generator no longer had matching dimensions or base state.

Resolution:

Both clear operations now reset the state tag, dimensions, base correlations,
code seed, malicious-check state, and output buffers. The receiver's base type
also has a defined initial value.

Verification:

- `Vole_Silent_Clear_test` populates active sender and receiver state, clears
  both objects, and checks their complete inactive state.
