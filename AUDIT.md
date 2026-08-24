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
The direct stationary generator removes its base-VOLE choice suffix together
with the corresponding messages before installing the PPRF base state.

Verification:

- `OtExt_Silent_AuditState_Test` supplies a malicious base-choice vector that
  omits the 128 check choices. The call fails without making the receiver ready.
- `OtExt_Silent_baseOT_Test` generates stationary base correlations through
  both the direct base-OT and OT-extension paths.

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

## AUD-018: Optional base-OT receivers accepted mismatched output counts

Status: fixed

Affected code:

- `MasnyRindalKyber::receive()`.
- `INSECURE_MOCK_OT::receive()`.

Concern:

Each receiver used one caller-provided length to control the protocol and the
other length to access output or choice storage. Neither receiver required the
two lengths to agree.

Impact:

A mismatched local API call could read a choice bit or write an output block
outside the corresponding caller-provided range.

Resolution:

Both receivers now require equal choice and output counts before protocol I/O.

Verification:

- `Bot_MasnyRindal_Kyber_Test` rejects mismatched spans when Kyber OT is
  available.
- `Bot_Mock_Test` rejects mismatched spans without starting the mock protocol.

## AUD-019: Small-field VOLE advanced a null correction pointer

Status: fixed

Affected code:

- The low-field receiver kernel in `SmallFieldVole.cpp`.

Concern:

The loop advanced the optional correction pointer after every batch, including
when the pointer was null. Pointer arithmetic on a null pointer has undefined
behavior in C++.

Impact:

The ordinary receiver path without corrections executed undefined behavior.
An optimizing compiler could therefore miscompile the kernel even though the
advanced pointer was not dereferenced.

Resolution:

The kernel now advances the correction pointer only when corrections are
present. Its fixed-size batching and memory-access pattern are unchanged.

Verification:

- `Vole_SoftSpokenSmall_Test` exercises receiver generation without a
  correction.

## AUD-020: Small-field VOLE read past a nonmultiple-of-four input

Status: fixed

Affected code:

- `SmallFieldVoleReceiver::sharedFunctionXor()`.

Concern:

The implementation loaded four input elements per iteration even when fewer
than four logical VOLEs remained.

Impact:

A valid input span whose length was not divisible by four could be read past
its end. Values found there could also affect padded output blocks.

Resolution:

Complete groups still use the existing four-at-a-time kernel. A scalar tail
now handles the remaining zero to three logical VOLEs.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` supplies one declared input followed by
  nonzero sentinels and checks that only the logical output changes.

## AUD-021: Small-field VOLE span validation was debug-only

Status: fixed

Affected code:

- The span overloads of the small-field VOLE sender and receiver generation
  functions.
- The span overload of `SmallFieldVoleReceiver::sharedFunctionXor()`.

Concern:

Public span lengths were validated only when `NDEBUG` was absent. Release
builds passed invalid spans directly to raw-pointer kernels.

Impact:

An invalid local API call in a release build could cause an out-of-bounds read
or write instead of a deterministic exception.

Resolution:

The public span overloads now validate every required length in all builds.
The raw-pointer kernels and their hot loops are unchanged.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` checks every affected span dimension and
  is run in the release test configuration.

## AUD-022: External Silent OLE bases fixed the sender input share to zero

Status: fixed

Affected code:

- The sender path in `SilentOtTriple::setBaseOts()` and the OLE overload of
  `SilentOtTriple::expand()`.

Concern:

The external-base interface installed the Silent OT sender with correlation
`delta = 0`. The OLE expansion reused that value. Both sender hash inputs were
therefore equal, which made the sender's OLE input share identically zero.

Impact:

The generated values satisfied the tested OLE equation but were degenerate.
They did not have the randomness required from an OLE generator.

Resolution:

Each OLE expansion now samples a fresh sender correlation from its supplied
PRNG. This matches the existing triple path and works with generated or
externally installed base OTs.

Verification:

- `SilentOtTriple_ole_test` uses external base OTs and rejects an all-zero
  sender input share.

## AUD-023: Foleage retained consumed DPF and tensor base OTs

Status: fixed

Affected code:

- Base-OT installation and expansion in `FoleageTriple`.
- Base-OT installation in `TernaryDpf`.

Concern:

One Foleage expansion consumed every DPF base OT, but `hasBaseOts()` continued
to report available state. A second expansion indexed beyond the consumed DPF
vectors. Installing replacement bases appended tensor OTs and did not reset
the DPF index.

Impact:

Reusing an instance could read outside base-OT storage. It could also reuse
tensor masks derived from old OT keys.

Resolution:

Foleage now tracks one complete unused base-OT set. An expansion reserves that
set before protocol I/O and clears it on every exit path. Replacement tensor
bases overwrite prior values, and Ternary DPF installation resets its OT
index.

Verification:

- `foleage_F4ole_test` checks that a completed expansion clears every DPF and
  tensor base-OT container.
- `foleage_Audit_test` replaces an installed set and checks the tensor sizes
  and both DPF indices.

## AUD-024: Scalar Silent-triple SIMD fallbacks had different semantics

Status: fixed

Affected code:

- The non-SSE shuffle, 16-bit shift, and byte-mask helpers in
  `SilentOtTriple.cpp`.

Concern:

The scalar shuffle preserved most bytes that the SSE instruction zeroed. The
scalar byte-mask helper repeatedly read byte zero instead of each input byte.
The scalar shift also left-shifted signed 16-bit values.

Impact:

A build without SSE could generate incorrect OLEs and triples. The signed
shift also had undefined behavior.

Resolution:

The scalar helpers now implement the SSE operations with unsigned arithmetic.
The fixed-width compression structure is unchanged.

Verification:

- The existing Silent OLE and triple tests are run in a configuration with
  `ENABLE_SSE=OFF`.

## AUD-025: Foleage derived dimensions before validating its domain

Status: fixed

Affected code:

- `FoleageTriple::init()`.
- The `log3ceil()` and `ipow()` integer helpers.

Concern:

For a small domain, initialization subtracted a larger ternary depth from a
smaller one before checking the block size. The unsigned result wrapped.
Power-of-three calculations also lacked overflow checks.

Impact:

Invalid local parameters could produce wrapped dimensions, excessive work, or
an unbounded power-of-three search.

Resolution:

Initialization now validates the party, domain, sparse dimensions, coefficient
count, and `F3x32` capacity before constructing either DPF. The integer helpers
reject unrepresentable powers.

Verification:

- `foleage_Audit_test` rejects zero and undersized domains, an invalid party,
  and an input whose next power of three is not representable.

## AUD-026: Public Foleage arithmetic accepted undersized spans

Status: fixed

Affected code:

- The span overloads of `F4Multiply()`.
- `foleageFft()`.
- `FoleageTriple::tensor()`.

Concern:

The arithmetic helpers trusted explicit dimensions without comparing them to
their spans. The tensor function also multiplied unchecked dimensions and
accepted one fewer receiver choice than it accessed.

Impact:

Invalid local API inputs could cause out-of-bounds reads or writes.

Resolution:

The public helpers now validate their complete dimensions before entering the
arithmetic loops. Tensor input is limited to its implemented range and requires
the full base-OT count.

Verification:

- `foleage_Audit_test` rejects undersized multiplication and FFT spans.

## AUD-027: Default Silent-triple state was indeterminate

Status: fixed

Affected code:

- The `mN` member and public state checks in `SilentOtTriple`.

Concern:

A default-constructed object left `mN` uninitialized. Reading initialization
state or deriving output dimensions before `init()` therefore read an
indeterminate value.

Impact:

The default object had undefined state and could enter a dimension-dependent
path without configuration.

Resolution:

The default object now has `mN = 0`. Public setup and expansion operations
reject an uninitialized object, while readiness queries report inactive state.

Verification:

- `SilentOtTriple_Audit_test` checks the default initialization and base-OT
  state.

## AUD-028: Reused Regular-DPF keys retained old leaf programming

Status: fixed

Affected code:

- Static key generation and leaf deserialization in `RegularDpf`.

Concern:

Static key generation resized the correction matrices without clearing the
serialized leaf values. It then appended the new values. Reusing a key object
therefore produced a leaf buffer containing every prior generation.

Impact:

Expansion allocated one field element per tree but deserialized the complete
retained buffer. A reused key could overwrite the destination allocation.

Resolution:

Resizing a key without programmed leaves now clears its leaf buffer. Static
key generation consequently produces one canonical leaf buffer.

Verification:

- `Dpf_Audit_Test` generates twice into the same keys and checks the resulting
  leaf-buffer length.

## AUD-029: Regular-DPF expansion trusted inconsistent key dimensions

Status: fixed

Affected code:

- Static key generation and noninteractive expansion in `RegularDpf`.

Concern:

Expansion derived its tree count from one correction matrix. It did not check
the other matrix dimensions or the serialized leaf length. Static punctured
key generation also used the empty value count instead of the point count.

Impact:

An inconsistent key could cause out-of-bounds matrix access or an oversized
deserialization. Static punctured key generation silently omitted every tree.

Resolution:

Expansion now requires matching correction dimensions and either zero or one
serialized leaf value per tree. Static generation uses the point count and
rejects empty point sets, unsupported domains, and plaintext points outside
the domain.

Verification:

- `Dpf_Audit_Test` rejects short correction matrices and oversized leaf
  buffers. It also checks punctured key generation and point bounds.

## AUD-030: Direct Ternary-DPF reuse read consumed base OTs

Status: fixed

Affected code:

- Base-OT state and expansion in `TernaryDpf`.
- Base-OT readiness in `DpfMult`.

Concern:

Ternary expansion advanced its OT index without checking that a complete
unused set remained. A second direct expansion indexed beyond the installed
vectors. Readiness checks also treated exhausted OT vectors as available.

Impact:

Reusing a public DPF instance could cause out-of-bounds reads. A failed
protocol could leave partially consumed correlation state available to a
retry.

Resolution:

Ternary expansion now reserves one complete fresh set before protocol work.
It clears that set on every exit. DPF multiplier readiness now includes exact
vector dimensions and the current consumption index.

Verification:

- `TritDpf_Proto_Test` checks that expansion clears all Ternary base OTs and
  rejects a second expansion.
- The Foleage protocol tests pass with the strengthened Ternary lifecycle.

## AUD-031: Sparse-DPF expansion accepted a different tree count

Status: fixed

Affected code:

- Input validation in `SparseDpf::expand()`.

Concern:

Expansion compared the point count with the supplied sparse-set row count.
It did not compare either count with the tree count fixed by `init()`.

Impact:

Too few rows caused out-of-bounds access while initializing the trees. Extra
rows could index beyond the tree array during dense expansion.

Resolution:

The point count and sparse-set row count must now equal the initialized tree
count before allocation or protocol work.

Verification:

- `Dpf_Audit_Test` supplies fewer rows than the initialized tree count and
  checks rejection.

## AUD-032: Sparse-DPF set invariants were not enforced in release builds

Status: fixed

Affected code:

- Sparse-set validation and partitioning in `SparseDpf`.

Concern:

Empty, duplicate, unsorted, and out-of-domain sparse sets reached the tree
partitioner. Its principal safety checks were debug-only. A singleton set at
zero dense depth also passed an empty child to the partitioner.

Impact:

Invalid sets could underflow a bit index, violate the ordering precondition of
`upper_bound`, or index beyond a dense seed matrix.

Resolution:

Expansion now validates every public sparse set before allocation. The
partitioner rejects empty ranges and exhausted bit prefixes in every build.
The zero-dense-depth path handles a singleton directly.

Verification:

- `Dpf_Audit_Test` rejects each invalid set form and expands a singleton set
  at zero dense depth.

## AUD-033: Sum DMPF clear retained protocol and base-OT state

Status: fixed

Affected code:

- Initialization and `clear()` in `SumDmpf`.

Concern:

The clear operation removed only the point shares. The embedded Regular DPF,
its base OTs, dimensions, and readiness state remained active.

Impact:

An object reported cleared could retain secret correlation material and could
be reused under its prior configuration.

Resolution:

The clear operation now clears the embedded DPF and resets every configuration
field. Initialization also rejects a wrapped product of set dimensions and
removes point state from a prior configuration.

Verification:

- `Dpf_Audit_Test` installs base OTs, clears the Sum DMPF, and checks every
  protocol and configuration field.

## AUD-034: Regular PPRF trusted incomplete expansion state

Status: fixed

Affected code:

- Configuration, readiness, point recovery, and expansion in `RegularPprf`.

Concern:

Expansion indexed the base-OT matrices without verifying that they were set.
Receiver expansion and point recovery also indexed the active-path matrix
without verifying its dimensions. Reconfiguration removed the base OTs but
retained the prior active paths.

Impact:

An incomplete or reconfigured public PPRF object could access storage outside
its matrices or silently reuse punctures from a prior configuration.

Resolution:

Readiness now requires the exact sender or padded receiver base-OT dimensions.
Receiver point recovery and expansion require a complete active-path matrix.
Configuration clears old paths, and callback output requires an installed
callback before protocol work.

Verification:

- `Pprf_Audit_Test` checks stale choices, absent base state, and a missing
  callback.

## AUD-035: Failed PPRF expansion retained one-time base OTs

Status: fixed

Affected code:

- Sender and receiver expansion in `RegularPprf`.
- Initial expansion through `StationaryPprf`.

Concern:

Base OTs were cleared only after successful expansion. An eager expansion
could expose correction messages for one or more batches and then fail while
retaining every OT for a retry.

Impact:

Retrying the object could reuse masks already exposed on the wire. This reuse
violates the one-time correlation requirement and falls outside the PPRF
security argument.

Resolution:

Expansion performs all local preflight checks before reserving its base OTs.
Once reserved, the complete set is cleared on both successful and exceptional
exits. Stationary initial expansion inherits the same lifecycle from its
embedded Regular PPRF.

Verification:

- `Pprf_Audit_Test` checks that a preflight failure preserves unused OTs.
- The test checks that callback and malformed-message failures consume the
  reserved sender and receiver state.

## AUD-036: PPRF dimension arithmetic could wrap

Status: fixed

Affected code:

- PPRF configuration and output validation.
- Expansion-tree, correction-buffer, and temporary-leaf allocation.

Concern:

Configuration accepted zero point counts, depth-64 domains, and dimensions
whose products were not representable. Later code could divide by zero, shift
by 64, or allocate a wrapped buffer before writing the unwrapped logical
output.

Impact:

Invalid public dimensions could cause undefined behavior, undersized
allocations followed by out-of-bounds access, or excessive protocol work.

Resolution:

Shared PPRF validation now requires a nonzero point count and a tree depth
below 64. Checked addition, multiplication, and round-up helpers protect every
derived allocation and output dimension.

Verification:

- `Pprf_Audit_Test` rejects zero point counts, a depth-64 domain, and wrapped
  dimensions.

## AUD-037: Stationary PPRF omitted public vector validation

Status: fixed

Affected code:

- Sender and receiver expansion in `StationaryPprf`.

Concern:

Both parties wrote one output for every tree leaf without validating the
output length. The sender also read one programming value per tree without
validating the value count.

Impact:

An undersized public vector caused out-of-bounds reads or writes before the
stationary correlation was returned.

Resolution:

Stationary expansion now uses the shared output-format validator. The sender
also requires exactly one programming value per tree, and its serialized
message allocation uses checked arithmetic.

Verification:

- `Pprf_Audit_Test` rejects missing values and undersized stationary output.

## AUD-038: PPRF puncture sampling used biased 64-bit reduction

Status: fixed

Affected code:

- Active-point sampling in `RegularPprfReceiver`.

Concern:

The receiver sampled a 64-bit integer and reduced it modulo the domain. This
distribution is uniform only when the domain divides `2^64`, while the
syndrome-decoding analysis assumes uniform positions.

Impact:

The sampling distribution introduced a statistical deviation larger than the
intended statistical-security allowance for common non-power-of-two domains.

Resolution:

Each point is now obtained by reducing a full 128-bit PRNG sample modulo the
true domain. Configuration requires `domain * pointCount` to fit in 64 bits,
so the aggregate statistical distance over every sampled point is below
`2^-66`, exceeding the selected 40-bit statistical target. Native GCC, Clang,
and MSVC reductions have a portable fixed-work fallback.

Verification:

- `Pprf_Audit_Test` uses a reduction vector whose result depends on the high
  64-bit limb.
- Existing non-power-of-two PPRF tests pass with the new sampler.

## AUD-039: Stationary PPRF allowed puncture mutation after expansion

Status: fixed

Affected code:

- Choice installation and lifecycle reset in `StationaryPprfReceiver`.
- Lifecycle reset in `StationaryPprfSender`.

Concern:

The receiver could replace its active paths after the retained PPRF share had
been generated for the old paths. Receiver clear also retained the share and
both clear operations retained the expansion counter.

Impact:

Later stationary expansions could apply their correction at coordinates that
did not match the retained share and return an invalid correlation. Cleared
objects also retained active expansion material.

Resolution:

Nonempty choice updates are rejected after initial expansion. Empty base-state
updates are no-ops once expansion makes new base OTs unnecessary. Configure
and clear remove retained shares and reset the expansion counter on both
parties.

Verification:

- `Pprf_Audit_Test` completes an initial stationary expansion, rejects a later
  choice update, and checks complete sender and receiver clear state.
