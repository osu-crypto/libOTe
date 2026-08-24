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
invariant for direct calls. The lower-level Silent OT interface and the base-OT
implementations already performed this check. AUD-052 covers the chosen Silent
OT adapter.

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

## AUD-040: Kyber entropy fallback could overwrite its destination

Status: fixed

Affected code:

- `thirdparty/KyberOT/randombytes.c`, in `randombytes_kyber()`.

Concern:

After a partial `getrandom()` result, the function advanced its output pointer.
If a later call failed, the fallback received the original byte count at the
advanced pointer. The fallback could therefore write past the destination.

Impact:

The optional MR-Kyber backend could corrupt adjacent memory when the operating
system returned partial entropy and a later entropy request failed.

Resolution:

The fallback now receives only the unfilled suffix. A zero-byte system call
also enters the fallback instead of leaving the entropy loop without progress.

Verification:

- The Linux-only MR-Kyber entropy source compiles with the corrected remaining
  length and zero-progress branch.

## AUD-041: Unseeded SoftSpoken splitting read an invalid AES schedule

Status: fixed

Affected code:

- `AESStream::split()` and `AESRekeyManager::split()` in
  `SoftSpokenShOtExt.h`.

Concern:

An extender can be split after base OTs are installed but before the protocol
seed is exchanged. The split path evaluated the default-constructed AES
object, whose key schedule was not initialized, and marked the child stream as
seeded.

Impact:

Pre-expansion splitting read indeterminate state. This ordering is used by the
multithreaded frontend and could produce undefined behavior before the child
installed its protocol seed.

Resolution:

AES streams now expose their seeded state and reject direct unseeded splits.
The rekey manager preserves unseeded parent and child states without evaluating
AES.

Verification:

- `OtExt_SoftSpoken_AesState_Audit_Test` checks direct rejection and confirms
  that both managers remain unseeded.

## AUD-042: SoftSpoken rekey accounting omitted the triggering batch

Status: fixed

Affected code:

- `AESRekeyManager::useAES()` in `SoftSpokenShOtExt.h`.

Concern:

When a batch exceeded the remaining use allowance, the manager selected a new
key and reset its counter to zero. The current batch then used the new key but
was absent from that key's counter.

Impact:

Beyond an indivisible caller batch's own size, the key could process the next
1,024 secret blocks without rekeying. This weakened the configured computation
and security tradeoff.

Resolution:

The triggering batch becomes the new key's initial use count. An indivisible
batch larger than the nominal allowance retains its supported behavior: it gets
a fresh key to itself and forces another rekey before subsequent use. A checked
comparison avoids counter overflow.

Verification:

- `OtExt_SoftSpoken_AesState_Audit_Test` crosses two consecutive rekey
  boundaries and confirms that an oversized batch cannot accumulate later use
  on the same key.

## AUD-043: SoftSpoken splitting could resurrect an expired cached AES key

Status: fixed

Affected code:

- `AESStream::split()` and `AESRekeyManager::split()` in
  `SoftSpokenShOtExt.h`.

Concern:

`AESStream` caches eight derived keys. Splitting incremented the logical index
without invoking the cache-refill path. A split at index seven advanced the
parent to index eight but selected stale cache slot zero.

Impact:

The parent reused a key that had already reached its usage limit. Repeated
splits could bypass the rekey policy and extend the lifetime of expired keys.

Resolution:

Splitting now advances through `next()`, which refills the cache at its
boundary. The parent usage count resets because the parent also advances to a
fresh key.

Verification:

- `OtExt_SoftSpoken_AesState_Audit_Test` checks the index-seven split against
  independently derived key eight and exercises the parent usage limit after
  a seeded split.

## AUD-044: Moving a Subspace VOLE sender lost pending corrections

Status: fixed

Affected code:

- Move construction and move assignment in `SubspaceVoleSender`.

Concern:

The move operations transferred the code and base VOLE state but omitted the
pending message buffer. Move construction left the corrections in the source.
Move assignment also retained any stale corrections in the destination.

Impact:

A caller that moved the public low-level sender after generating corrections
could send an empty or cross-session transcript. The peer could then block,
reject the transcript, or use corrections from the wrong protocol state.

Resolution:

Both move operations now transfer the pending message buffer. The buffer move
also leaves the source container empty.

Verification:

- `OtExt_SoftSpoken_BufferState_Audit_Test` checks move construction and move
  assignment with nonempty source and destination buffers.

## AUD-045: TwoOneRTCR moves omitted their AES state

Status: fixed

Affected code:

- Move construction and move assignment in `TwoOneRTCR`.

Concern:

The custom move operations transferred the hash key and tweak state but did not
move the `AESRekeyManager` base. A move-constructed object therefore had no AES
key. A move-assigned object retained the destination's previous AES key.

Impact:

Continuing the hash through a moved object could evaluate unseeded AES state or
combine one session's tweak state with another session's AES key. The sender
and receiver would then derive inconsistent random-OT outputs.

Resolution:

The move operations now transfer the `AESRekeyManager` base before transferring
the hash and tweak state. The source manager becomes logically unseeded.

Verification:

- `OtExt_SoftSpoken_BufferState_Audit_Test` checks the AES key after move
  construction and move assignment. It also checks that both sources reject
  later AES use.

## AUD-046: Subspace VOLE receive validation was debug-only

Status: fixed

Affected code:

- Receive-buffer handling in `SubspaceVoleReceiver::recv()` and
  `SubspaceVoleReceiver::getMessage()`.

Concern:

Release builds omitted the checks for unread corrections and receive-buffer
bounds. The low-level interface could discard unread data or construct a span
outside the active buffer. Its size calculations also allowed unsigned wrap.

Impact:

Incorrect low-level batch accounting could produce invalid VOLE correlations
or an out-of-bounds span. The current high-level SoftSpoken loops provide
balanced sizes, so this issue required direct low-level misuse or corrupted
caller state.

Resolution:

The lifecycle and bounds checks now run in every build. Checked multiplication,
addition, and subtraction reject unrepresentable receive sizes without clearing
the active buffer.

Verification:

- `OtExt_SoftSpoken_BufferState_Audit_Test` rejects unread-buffer replacement,
  over-read, invalid padding, and wrapped receive dimensions.

## AUD-047: Empty malicious SoftSpoken calls desynchronized the parties

Status: fixed

Affected code:

- Input validation in `SoftSpokenMalOtReceiver::receive()`.

Concern:

The malicious sender rejected an empty OT request before protocol setup. The
receiver accepted the request and started base generation or expansion.

Impact:

An honest pair given empty inputs followed different protocol paths. The
receiver could consume persistent state before the sender closed the channel.

Resolution:

The receiver now rejects an empty request before base generation, seed
exchange, or counter advancement.

Verification:

- `OtExt_SoftSpoken_BufferState_Audit_Test` submits empty receiver inputs and
  checks that the receiver retains its initial protocol state.

## AUD-048: Subspace VOLE reservation multiplied by code length twice

Status: fixed

Affected code:

- Both overloads of `SubspaceVoleSender::reserveMessages()`.

Concern:

The two-argument overload converted random and chosen VOLE counts into message
blocks. The one-argument overload then multiplied that block count by the code
length again.

Impact:

For field size two and 4,096 chosen chunks, the sender reserved about 1 GiB for
an approximately 8 MiB correction buffer. Large, valid OT requests could cause
avoidable allocation failure or memory pressure.

Resolution:

The one-argument overload now treats its input as a block count. Both overloads
use checked arithmetic before reserving the exact block count plus temporary
padding.

Verification:

- `OtExt_SoftSpoken_BufferState_Audit_Test` checks the exact capacity for a
  chosen-VOLE reservation and rejects a wrapped reservation.

## AUD-049: Malicious SoftSpoken batching left its chunk count at zero

Status: fixed

Affected code:

- `SoftSpokenMalOtReceiver::runBatch()`.

Concern:

The receiver declared `numChunks` but never assigned the number of chunks. Its
initial reservation was always empty. After a communication boundary,
subtracting the processed count from zero wrapped to a large integer.

Impact:

The receiver repeatedly grew its first correction buffer. Later reservations
requested a complete communication window even when fewer chunks remained.
AUD-048 amplified the resulting memory cost.

Resolution:

The receiver now computes the chunk count from the input length before its
first reservation. The calculation avoids addition-based ceiling overflow.

Verification:

- Existing malicious SoftSpoken tests exercise the corrected batching path.
- The reservation checks in `OtExt_SoftSpoken_BufferState_Audit_Test` cover the
  shared correction-buffer accounting.

## AUD-050: Invalid Noisy VOLE calls consumed OT state before failing

Status: fixed

Affected code:

- Public `NoisyVoleSender::send()` and `NoisyVoleReceiver::receive()`
  overloads that generate their own OTs.

Concern:

The receiver generated OTs before checking that its input and output counts
matched or were nonzero. The sender also generated OTs before rejecting an
empty output batch. The lower-level overloads performed some checks only after
the outer overload had advanced the OT provider.

Impact:

Invalid local API input could consume one-time OT state without completing the
VOLE. Reusing either endpoint after the failure could desynchronize its OT
state from the peer.

Resolution:

Both public entry points now validate the batch and field dimensions before
invoking the OT provider. The lower-level overloads retain the same validation
for callers that supply OTs directly.

Verification:

- `Vole_Noisy_Audit_Test` submits empty and mismatched batches through the
  public overloads and confirms that the OT provider is not invoked.

## AUD-051: Noisy VOLE allocation dimensions could wrap

Status: fixed

Affected code:

- Message and serialization-buffer allocation in `NoisyVoleSender` and
  `NoisyVoleReceiver`.

Concern:

The implementations multiplied the field bit count, correlation count, and
serialized element size without bounding any term. A wrapped product could
allocate a buffer smaller than the subsequent loops expected.

Impact:

Ordinary `std::vector` inputs cannot reach the problematic sizes on current
machines. A custom vector-like input with an invalid logical size, or a future
large field context, could cause out-of-bounds access. This layer does not take
these dimensions from the peer.

Resolution:

The entry points now limit correlation counts to `u32`, and field bit and byte
sizes to `u16`. They also reject zero dimensions and inconsistent binary
decompositions. The allocation products are evaluated as `u64`; the individual
limits make their maximum product smaller than `2^64`.

Verification:

- `Vole_Noisy_Audit_Test` uses oversized vector-like inputs and confirms that
  both parties reject them before invoking the OT provider.
- Existing `Vole_Noisy_test` cases cover the accepted field contexts.

## AUD-052: Chosen Silent OT validated choices after consuming random OT state

Status: fixed

Affected code:

- `SilentOtExtReceiver::receive()`.

Concern:

The chosen-OT adapter first completed a random Silent OT using an internally
sized choice vector. It compared the caller's choice length only when XORing
the correction bits afterward. Regular-noise execution had already cleared
its one-time protocol state at that point.

Impact:

A mismatched local call consumed the receiver's Silent OT state and network
transcript before failing. The peer could retain the corresponding completed
sender state, leaving the endpoints inconsistent.

Resolution:

The chosen receiver now checks the caller's choice and output lengths before
configuration, base generation, expansion, or communication.

Verification:

- `OtExt_Silent_AuditState_Test` submits mismatched lengths and confirms that
  the receiver remains unconfigured.

## AUD-053: Syndrome-decoding configuration accepted unbounded dimensions

Status: fixed

Affected code:

- `syndromeDecodingConfigure()`.

Concern:

The configuration routine accepted arbitrary `u64` request sizes, security
parameters, and group bit counts. Derived rounding and dimension products
could therefore wrap before later allocations used the configuration.

Impact:

This was a local caller-size bug. Extreme inputs could produce a small,
internally inconsistent configuration and later cause protocol failure or an
out-of-bounds access. The protocol does not receive these values from its peer.

Resolution:

The routine now limits the security parameter to 1,024 bits, the request size
to `u32`, and the group bit count to `u16`. These limits cover the supported use
cases and keep every derived dimension representable as `u64`.

Verification:

- `Vole_Noisy_Audit_Test` checks each configuration limit independently.

## AUD-054: Silent OT clear operations retained active correlations

Status: fixed

Affected code:

- `SilentOtExtSender::clear()` and `SilentOtExtReceiver::clear()`.

Concern:

Each clear operation reset the request count before it tested
`isConfigured()`. The test was therefore false, and the operation never cleared
the selected PPRF generator. Both parties also retained base correlations,
malicious-check OTs, and encoding state.

Impact:

An explicit clear retained secret protocol material and did not restore the
documented empty state. A later successful configuration replaced the PPRF
generator, so the ordinary automatic execution path did not directly reuse the
retained PPRF OTs.

Resolution:

Both clear operations now reset the selected generator without consulting the
request count. They also remove every correlation and temporary buffer owned by
Silent OT and reset the code seed.

Verification:

- `OtExt_Silent_AuditState_Test` installs malicious stationary correlations,
  clears both parties, and checks the complete empty state.

## AUD-055: Failed Silent configuration could mix protocol states

Status: fixed

Affected code:

- Silent OT sender and receiver configuration.
- Silent VOLE sender and receiver configuration.

Concern:

Each configuration operation assigned public dimensions and security policy
before validating the requested compression and noise parameters. A rejected
reconfiguration could therefore retain the old generator while exposing new
dimensions or policy through the same object.

Impact:

A local caller that caught the configuration exception could continue with an
internally inconsistent object. Subsequent base-correlation accounting or
protocol execution could fail or use state associated with the previous
configuration.

Resolution:

Configuration now validates the noise model, syndrome-decoding parameters, and
PPRF dimensions before mutating the object. A successful reconfiguration
reconstructs the selected generator and discards correlations tied to the old
dimensions.

Verification:

- `OtExt_Silent_AuditState_Test` rejects invalid reconfiguration and checks
  that both Silent OT parties retain their complete prior state.
- `Vole_Silent_Clear_test` performs the same check for both Silent VOLE
  parties.

## AUD-056: GMW output mapping checked the wrong dimension

Status: fixed

Affected code:

- `Gmw::mapOutput()`.

Concern:

The output mapper checked whether the number of output wires was divisible by
the block size. It needed to check the byte count in each mapped row. For 129
parallel evaluations, a 17-byte row could therefore be accepted even though
the evaluator accesses two complete blocks, or 32 bytes, per row.

Impact:

An invalid local output view could make adjacent mapped rows overlap. Access to
the last row could continue beyond the caller's matrix allocation.

Resolution:

The mapper now applies the block-stride requirement to the column count, as the
corresponding input mapper does.

Verification:

- `Gmw_Audit_Test` rejects a 17-byte output row for 129 parallel evaluations.

## AUD-057: GMW retained consumed one-time OLE correlations

Status: fixed

Affected code:

- OLE handling in `Gmw::run()` and `Gmw::clear()`.

Concern:

`run()` advanced spans that referred to the member OLE vectors but never
changed the vectors themselves. `clear()` also retained both vectors.
Reinitializing the object could therefore evaluate another circuit with the
same OLE masks.

Impact:

For repeated evaluations, the other party could cancel a reused mask between
two protocol messages. The resulting value reveals the XOR of the corresponding
wire shares from those evaluations.

Resolution:

After local preflight succeeds, `run()` moves the complete OLE vectors into
coroutine-local storage and explicitly clears the member vectors. Every later
success or failure consumes that state. `clear()` also removes retained OLE
state.

Verification:

- `Gmw_Audit_Test` completes an evaluation and confirms that neither party
  retains its OLE vectors.
- The test also confirms that an explicit clear removes unconsumed OLE state.

## AUD-058: Missing GMW OLE correlations caused an infinite loop

Status: fixed

Affected code:

- OLE batching in `Gmw::run()`.

Concern:

For a nonlinear circuit without enough OLE blocks, the batching loop selected
zero correlations and did not advance its output index. The coroutine remained
in the local loop and never reached network communication or an error.

Impact:

An invalid local call could consume a worker indefinitely. The peer did not
control the OLE vector dimensions through the GMW protocol.

Resolution:

`run()` now requires the exact OLE block count before mapping finalization or
communication. GMW also bounds the evaluation count and nonlinear gate count
individually to keep the OLE count representable.

Verification:

- `Gmw_Audit_Test` confirms that a second nonlinear evaluation without fresh
  OLE correlations is rejected. It also checks both individual dimension
  limits.

## AUD-059: Log VOLE frame lengths permitted peer-driven allocation

Status: fixed

Affected code:

- Ring-protocol framing in `LogVoleRingSender` and `LogVoleRingReceiver`.

Concern:

Each receive operation allocated the peer-supplied 64-bit payload length before
parsing or validating the message. On 64-bit platforms, its only limit was
`size_t::max`.

Impact:

Even though Log VOLE assumes semi-honest parties, a malformed peer value could
trigger an enormous allocation attempt and terminate the process. Basic bounds
on values received from the peer are appropriate independently of the protocol
security model.

Resolution:

Each receive site now supplies a checked maximum derived from the local ring
parameters and the message type expected at that protocol step. The frame
header is rejected before payload allocation when it exceeds that bound.

Verification:

- `LogVole_KeyDeriveCoproto_OversizedFramesRejectedBeforeAllocation` exercises
  both framing implementations with a header one byte above the expected size.
- The complete Log VOLE suite exercises legitimate direct and recursive frames.

## AUD-060: LinearCode loaders accepted malformed dimensions and payloads

Status: fixed

Affected code:

- Text, binary-stream, and byte-buffer loading in `LinearCode`.

Concern:

The loaders trusted dimensions and stream reads. Release text parsing indexed
short rows without validation, and binary dimensions could be inconsistent,
truncated, or large enough to wrap derived sizes.

Impact:

Malformed local input could cause an out-of-bounds read, divide by zero,
integer wraparound, or excessive allocation. Protocol use normally loads
trusted embedded code descriptions.

Resolution:

The parser now limits plaintext dimensions to 512 bits and codewords to 65,536
bits. It validates all reads, text separators and bits, binary matrix shape,
payload completion, and trailing data. Parsing and table generation occur in a
temporary object and commit only after success.

Verification:

- `Tools_LinearCode_Audit_Test` covers short and malformed text, oversized
  dimensions, truncated and inconsistent binary input, and transactional
  failure.

## AUD-061: Linear-code span validation was debug-only

Status: fixed

Affected code:

- Span overloads in `GenericLinearCode` and `LinearCode`.

Concern:

Release builds omitted dimension and buffer-length checks before forwarding raw
pointers to the encoding implementation.

Impact:

An undersized local span could cause an out-of-bounds read or write. Existing
protocol callers ordinarily construct exact internal dimensions.

Resolution:

Span overloads now perform always-on dimension and buffer checks before entering
the encoding kernels. Raw pointer overloads remain the explicitly unchecked
buffer interface. No inner loop changed.

Verification:

- `Tools_LinearCode_Audit_Test` rejects undersized message and output spans in a
  Release build.

## AUD-062: LinearCode encode read uninitialized padding

Status: fixed

Affected code:

- The optimized byte encoder in `LinearCode`.

Concern:

The unrolled lookup kernels process input bytes in padded groups but copied only
the caller's logical bytes into their stack staging buffer. The final group
therefore used indeterminate bytes as lookup-table indices.

Impact:

The corresponding generator rows were zero, so the intended result was stable,
but the indeterminate reads were undefined behavior on valid code dimensions.

Resolution:

The encoder initializes only the unused tail of the final eight-byte group. The
unrolled kernels and their memory-access structure are unchanged.

Verification:

- `Tools_LinearCode_Audit_Test` compares encodings for several non-byte-aligned
  plaintext dimensions against a scalar generator-matrix oracle.

## AUD-063: Zero-length RepetitionCode underflowed its operations

Status: fixed

Affected code:

- Construction and encoding operations in `RepetitionCode`.
- Dimension arithmetic in `GenericLinearCode`.

Concern:

A zero-length code reported dimension one. Its codimension underflowed, and
syndrome encoding and decoding indexed element `n - 1`.

Impact:

An invalid local configuration could cause an out-of-bounds access. Ordinary
Subspace VOLE configurations use a nonzero repetition length.

Resolution:

The explicit zero-length constructor and every raw operation now reject the
unconfigured state. Generic wrappers also reject any code whose length is less
than its dimension before subtracting or dispatching.

Verification:

- `Tools_LinearCode_Audit_Test` checks explicit and default-constructed
  zero-length rejection.

## AUD-064: BlkAcc discarded its seeded accumulator permutations

Status: fixed

Affected code:

- Permutation handling in `Accumulator::dualEncode()` and
  `Accumulator::getMtx()`.
- The default BlkAcc compression path in Silent OT and Silent VOLE.

Concern:

`BlkAccCode` constructed each accumulator with a distinct permutation seed,
but `Accumulator` immediately reinitialized that permutation using its default
seed. Every accumulator round therefore used the same fixed permutation, and
the accumulator portion of the matrix did not change when the code seed
changed.

Impact:

The parties still computed correlated outputs, so ordinary relation tests did
not detect the issue. However, the implemented default compression matrix did
not have the independently seeded permutation structure on which its estimated
minimum distance and Silent-protocol security parameters are based.

Resolution:

`Accumulator` now preserves the initialized permutation supplied by its
caller. Beginning a `FeistelPerm` iteration still resets only its traversal
buffer; it does not regenerate its round keys. No permutation or accumulation
inner loop changed.

Verification:

- `BlkAccCode_Audit_Test` checks both power-of-two and arbitrary domains and
  confirms that encoding preserves the caller's Feistel round keys.
- The default Silent OT/VOLE and explicit BlkAcc protocol tests exercise the
  corrected matrix while checking the protocol relation.

## AUD-065: FeistelPerm's iterator never reached its end

Status: fixed

Affected code:

- `FeistelPerm::Iterator::operator++()`.

Concern:

Incrementing the iterator advanced the permutation buffer but did not advance
the index used by iterator comparison. A conventional loop that compared the
iterator with `end()` therefore never terminated.

Impact:

Use of the public iterator interface could loop indefinitely and continue
returning stale buffered indices. Internal encoding loops used an explicit
domain count and were not affected.

Resolution:

The iterator now advances its logical index together with the permutation
buffer. Feistel iterator indices are 64-bit so the endpoint of a full 32-bit
domain remains representable.

Verification:

- `Permutation_Audit_Test` iterates to `end()` and checks exact, unique
  coverage of a non-power-of-two domain.

## AUD-066: BlkAcc accepted unsupported dimensions

Status: fixed

Affected code:

- Configuration in `BlkAccCode`, `BlockDiagonal`, `Feistel2KPerm`, and
  `FeistelPerm`.

Concern:

Configuration accepted zero block sizes, undersized compression domains,
non-vector-aligned code sizes, and domains larger than the permutation index
type. These inputs failed only after initialization, divided by zero, or could
truncate permutation indices.

Impact:

An invalid local configuration could cause undefined behavior, excessive work,
or a late protocol failure. Normal Silent configuration selects supported
parameters, but the code classes are also public interfaces.

Resolution:

Initialization now individually requires nonzero message, code, and block
sizes; a code size at least twice the message size; eight-element code and
block granularity; a representable 32-bit permutation domain; and depth at
least three. `BlockDiagonal` and the permutation classes enforce their own
direct-construction invariants as well.

Verification:

- `BlkAccCode_Audit_Test` covers every rejected dimension class before running
  a valid non-power-of-two configuration.

## AUD-067: BlockDiagonal's SIMD tail crossed logical blocks

Status: fixed

Affected code:

- The eight-way kernel and matrix oracle in `BlockDiagonal`.

Concern:

For non-final logical blocks, the optimized loop processed eight inputs whenever
at least one remained. A short tail therefore incorporated columns belonging
to the following diagonal block. The matrix oracle also used floor division
where the encoder used ceiling division when the output size was not a block
multiple.

Impact:

Supported allocations remained in bounds, but some locally selected dimensions
produced an overlapping matrix rather than the intended block-diagonal code.
The encoder and its matrix oracle disagreed, so the stated code construction
and its distance analysis did not apply to those dimensions.

Resolution:

Each logical block now processes an aligned scalar prefix, unchanged eight-way
full chunks, and a scalar tail. Random-bit consumption remains sequential
across all three portions. The oracle now uses the same ceiling block count and
handles the empty matrix explicitly.

Verification:

- `BlkAccCode_Audit_Test` compares the optimized encoder with the sparse-matrix
  oracle for both an unaligned input partition and a partial final output
  block.

## AUD-068: Paired NTT spans could have different lengths

Status: fixed

Affected code:

- Recursive forward and inverse negacyclic NTT entry points.
- Reference matrix forward and inverse NTT entry points.

Concern:

These functions derived the transform size from one span and indexed the paired
span as though it had the same length.

Impact:

An undersized local input or output span could cause an out-of-bounds read or
write in Release builds. Ring-LPN callers construct equal internal spans.

Resolution:

Every paired-span entry point now requires equal lengths before transform
validation or indexing. The optimized in-place transform and all arithmetic
kernels are unchanged.

Verification:

- `Ntt_Audit_Test` supplies mismatched spans to all four paired-span APIs and
  requires an `invalid_argument` rejection.

## AUD-069: Tungsten dimensions could underflow permutation allocation

Status: fixed

Affected code:

- `TungstenCode::config()` and `TungstenPerm::init()`.

Concern:

Configuration subtracted the message size from the code size without first
establishing their order. It also accepted rates that the encoder later
rejected and permutation chunk counts larger than its 32-bit indices.

Impact:

An invalid local configuration could underflow into an enormous allocation
attempt, fail after partially changing object state, or truncate permutation
indices. Tungsten remains an explicitly experimental compression option.

Resolution:

Configuration now individually validates nonzero and chunk-aligned dimensions,
the implemented rate of at least two, and the permutation index domain before
allocation. It constructs the new permutation temporarily and commits all live
state only after successful initialization.

Verification:

- `TungstenCode_Audit_Test` covers reversed and unsupported dimensions, an
  oversized chunk domain, and transactional preservation of a prior valid
  configuration.

## AUD-070: ExConv dimensions could underflow accumulator indexing

Status: fixed

Affected code:

- `ExConvCode::config()` and `ExConvCode::accumulateFixed()`.

Concern:

The default code-size calculation could overflow, a systematic code could
subtract a larger message size, and an accumulator at least as large as its
working region underflowed the unchecked-loop boundary. An accumulator wider
than the fixed PRNG coefficient buffer also formed a pointer before that
buffer.

Impact:

Invalid use of the public code API could produce out-of-bounds reads and
writes. Protocol-selected ExConv7x24 and ExConv21x24 parameters were within the
supported domain.

Resolution:

Configuration now separately validates the default-size multiplication,
nonzero message size, systematic dimension ordering, accumulator working
region, and the 32768-bit coefficient-buffer limit. It configures a temporary
expander and commits state only after every check succeeds.

Verification:

- `ExConvCode_Audit_Test` covers every invalid dimension class and confirms
  that a rejected reconfiguration preserves prior live state.

## AUD-071: Expander configuration admitted zero moduli

Status: fixed

Affected code:

- `ExpanderCode::config()` as used by ExConv and EACode.

Concern:

Zero message or code sizes underflowed iterator probes, zero weight divided by
zero in regular mode, and a regular half-weight larger than the code size
produced a zero region modulus.

Impact:

Invalid local configuration could cause undefined behavior or division by
zero. Standard ExConv and EACode configurations use positive, supported
parameters.

Resolution:

The expander now individually requires positive dimensions and weight. A
regular expander additionally requires its regular half-weight to fit within
the code size. Validation precedes all state mutation.

Verification:

- `ExConvCode_Audit_Test` covers zero dimensions, zero weight, an oversized
  regular weight, and a valid tail-bearing regular expander.

## AUD-072: The regular expander matrix described a different code

Status: fixed

Affected code:

- `ExpanderCode::getMatrix()`.

Concern:

The encoder split its weight between separately seeded regular and uniform
edges, while the matrix helper generated every edge as regular from one seed.

Impact:

Protocol output was unaffected, but verbose weight diagnostics and any caller
using the helper as a code-analysis oracle observed the wrong matrix.

Resolution:

The helper now uses the encoder's exact regular/uniform split, seeds, region
width, batching order, and tail order. The optimized eight-way encoding loop
is unchanged.

Verification:

- `ExConvCode_Audit_Test` compares matrix-derived output with optimized integer
  encoding across both a full eight-row batch and a scalar tail.

## AUD-073: Quasi-cyclic configuration admitted unsafe dimensions

Status: fixed

Affected code:

- `QuasiCyclicCode::init2()` and `QuasiCyclicCode::dualEncode()`.

Concern:

Reversed dimensions underflowed the parity length, equal dimensions reached
FFT decoding without initializing the product polynomial, and polynomial or
transpose dimension products could wrap.

Impact:

Invalid use of the public code API could request enormous allocations or
reach undefined behavior. Silent protocol configuration uses an expanding
code with valid dimensions.

Resolution:

Initialization now requires a positive message size and a strictly larger code
size. It computes the prime and all polynomial dimensions in temporaries,
checks each product against its consumer's range, and commits state only after
validation succeeds.

Verification:

- The bitpolymul-enabled `ExConvCode_Audit_Test` rejects zero, equal, and
  reversed dimensions and checks transactional state preservation.
- Existing quasi-cyclic unit and Silent OT tests pass with bitpolymul enabled.

## AUD-074: Quasi-cyclic bit utilities accepted unsafe domains

Status: fixed

Affected code:

- `QuasiCyclicCode::bitShiftXor()` and `QuasiCyclicCode::modp()`.

Concern:

A shifted empty input underflowed `in.size() - 1` and could be read out of
bounds. A zero polynomial modulus divided by zero, and ceiling and span-length
arithmetic could wrap.

Impact:

Malformed direct calls to these public helpers could cause out-of-bounds reads
or arithmetic faults. Internal quasi-cyclic encoding supplied valid inputs.

Resolution:

The helpers reject missing shifted input and a zero modulus. Ceiling divisions
now use subtraction-based forms, input and output length products have explicit
bounds, and loop endpoints are formed from a checked remaining length.

Verification:

- The bitpolymul-enabled `ExConvCode_Audit_Test` covers empty shifted input and
  a zero modulus.
- Existing bit-shift and polynomial-reduction differential tests pass.

## AUD-075: Quasi-cyclic prime selection was randomized at 40-bit confidence

Status: fixed

Affected code:

- `isPrime()` and `nextPrime()` in `Tools.cpp`.

Concern:

Prime selection used 20 randomized Miller--Rabin trials with independently
seeded PRNGs. A composite could therefore be accepted with roughly 40-bit
confidence, potentially selecting different moduli at the two parties. The
modular products also wrapped above the 32-bit protocol range, and prime search
could wrap at the end of the 64-bit domain.

Impact:

The low-probability acceptance of a composite could invalidate the
quasi-cyclic algebraic assumptions or make the parties disagree. Direct
64-bit callers received unreliable primality answers for large candidates.

Resolution:

Primality testing now uses the deterministic seven-witness Miller--Rabin test
that is exact over the full 64-bit domain. Modular multiplication has an
ordinary fast path when the product fits and an overflow-safe double-and-add
path otherwise. Prime search advances over odd candidates and throws before
the domain can wrap; the legacy PRNG and round-count parameters remain only
for source compatibility.

Verification:

- `ExConvCode_Audit_Test` checks a strong pseudoprime, the largest 64-bit
  prime, `UINT64_MAX`, known next-prime output, and exhaustion at the domain
  boundary.

## AUD-076: Dynamic sparse-matrix mutations broke adjacency invariants

Status: fixed

Affected code:

- `DynSparseMtx` resizing, clearing, row operations, column selection, and
  `VecSortSet` erasure.

Concern:

Resize used its growth condition for the shrink cleanup loops. Growth could
remove reciprocal entries from existing columns, while shrink simply
discarded rows or columns that were still referenced from the opposite side.
The clear operations removed only the reciprocal entries and left the selected
set populated. Missing-set erasure and invalid public indices were assert-only
or unchecked.

Impact:

Direct mutation of a dynamic sparse matrix could silently corrupt its paired
row/column representation. Later mutation or conversion could erase unrelated
entries or access outside the row or column arrays.

Resolution:

Shrink now clears removed rows and columns in descending order, growth
preserves existing edges, and clear operations empty both sides. Public
mutation and selection indices are validated before mutation, self-row
addition clears the row, validation checks index domains before dereferencing,
and sorted-set erasure rejects a missing element.

Verification:

- `Mtx_Audit_Test` grows and shrinks a populated matrix, checks edge
  preservation and removal, clears a row, validates both adjacency views, and
  verifies transactional rejection of an invalid appended column.

## AUD-077: Sparse-matrix APIs trusted Release-disabled boundary assertions

Status: fixed

Affected code:

- `SparseMtx` initialization, vector multiplication, submatrices, column
  selection, concatenation, multiplication, addition, and coordinate lookup.

Concern:

Several public operations used assertions as their only dimension checks.
Short vectors, invalid column indices, or overflowing submatrix ranges could
therefore be indexed out of bounds in Release. Initialization terminated the
process with `abort()` for duplicate or out-of-range points.

Impact:

Malformed direct inputs, including dimensions derived from an external
message by a caller, could cause out-of-bounds access or process termination.

Resolution:

Each public operation now validates its own vector lengths, matrix dimensions,
indices, and subtraction-based submatrix ranges before entering its existing
loop. Initialization validates all points and reports malformed input with an
exception instead of aborting. Multiplication inner loops are unchanged.

Verification:

- `Mtx_Audit_Test` covers short multiplication input, invalid submatrices and
  selected columns, duplicate and out-of-range points, and mismatched matrix
  multiplication and addition.

## AUD-078: Dense-matrix operations admitted unsafe dimensions

Status: fixed

Affected code:

- `DenseMtx` resizing, selection, row swapping, multiplication, addition,
  inversion, and submatrix extraction.

Concern:

Row padding and storage products could wrap. Other public operations used
assertions or no checks for operand dimensions and requested ranges, permitting
out-of-bounds access in Release.

Impact:

Invalid direct use of the matrix API could allocate the wrong storage size or
read and write beyond an operand.

Resolution:

Resize individually checks row padding and the column-by-block-row product
before changing live dimensions. All compound operations validate dimensions
or indices once at their boundary. Dense bit-access and arithmetic inner loops
remain unchanged.

Verification:

- `Mtx_Audit_Test` covers overflowing resize, invalid selection and
  submatrices, nonsquare inversion, and mismatched addition and multiplication.

## AUD-079: Primitive-root validation skipped prime factors

Status: fixed

Affected code:

- `isPrimRootOfUnity()` and NTT root validation and precomputation.

Concern:

The primitivity loop omitted the first and last unique factors. In particular,
a power-of-two order has one factor and received no proper-order check, so an
order-two element could be accepted for a larger NTT. An empty factor list
underflowed the loop bound. Root precomputation also checked a root for twice
the actual output-span order; the incomplete validator had hidden that error.

Impact:

A caller-supplied nonprimitive root could produce a noninvertible or otherwise
incorrect transform while passing validation.

Resolution:

Validation reconstructs the order with checked products, handles order one,
and checks every unique prime factor. Recursive transforms validate
primitivity once at their outer entry, and precomputation consistently requires
a primitive root whose order equals the power-table span. Optimized
precomputed-twiddle inner loops are unchanged.

Verification:

- `Field_Audit_Test` rejects an order-two element as a primitive eighth root
  and accepts the primitive first root.
- `Ntt_Audit_Test` rejects the order-two element in both forward and inverse
  Release transforms; existing matrix, recursive, and batch NTT tests verify
  the corrected precomputation contract.

## AUD-080: Root generation could divide by zero or index past root tables

Status: fixed

Affected code:

- Generic, Fp31, and Goldilocks `primRootOfUnity()` implementations.

Concern:

The generic implementation accepted zero and orders that did not divide the
field multiplicative order. The specialized power-of-two implementations
shifted before bounding the logarithm and did not check their table indices.

Impact:

Invalid direct orders could cause division by zero, undefined shifts, return a
non-root, or read beyond a static root table.

Resolution:

The generic path requires a nonzero divisor of the multiplicative order. Fp31
and Goldilocks require a representable power of two and separately bound the
index by their respective root tables and field two-adicities.

Verification:

- `Field_Audit_Test` covers zero, a nondividing order, Fp31 order `2^28`, and
  Goldilocks order `2^33`.

## AUD-081: Fp exponent and zero-division semantics were incorrect

Status: fixed

Affected code:

- `Fp::pow()`, `Fp::inverse()`, and the division operators.

Concern:

Exponentiation reduced large exponents modulo the field order instead of the
multiplicative-group order, changing valid powers such as `a^(p+1)`. Inversion
of zero aborted in Debug but returned zero in Release, so Release division by
zero silently returned zero.

Impact:

Large-exponent field computations could return the wrong element, and division
by zero had build-dependent behavior that could hide invalid algebraic state.

Resolution:

Exponentiation now processes the supplied nonnegative exponent without the
incorrect reduction. `inverse(0)` consistently follows the vector-friendly
zero convention already used by Goldilocks, while `/` and `/=` explicitly
reject a zero divisor.

Verification:

- `Field_Audit_Test` checks `a^(p+1) = a^2`, the zero-inverse convention, and
  division-by-zero rejection.

## AUD-082: NTT size validation performed unsafe derived arithmetic

Status: fixed

Affected code:

- Recursive, iterative, matrix, precomputation, and twiddle-extraction NTT
  entry points.

Concern:

Zero lengths reached `log2ceil(0)`, a shift by 64, and `n - 1` allocation
arithmetic. Other paths formed a doubled root order before establishing a safe
size and did not consistently enforce the 32-bit bit-reversal index domain.

Impact:

Malformed direct calls could underflow allocations or invoke undefined shifts
before the transform rejected the input.

Resolution:

A shared entry check now requires a nonzero power-of-two size in the supported
32-bit index domain and bounds the doubled order before any derived arithmetic.
Size-one transforms return without calling zero-bit reversal. Arithmetic and
butterfly inner loops are unchanged.

Verification:

- `Ntt_Audit_Test` covers empty forward, inverse, matrix, precomputation, and
  twiddle calls, plus an extreme size outside the supported domain.
