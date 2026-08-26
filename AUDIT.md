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

## AUD-083: Sparse-matrix copies retained views into the source object

Status: fixed

Affected code:

- `SparseMtx` copy construction and copy assignment.

Concern:

The default copy operations independently copied the owned flat vectors and
the row and column spans. The copied spans therefore continued to reference
the source vectors rather than the copied storage.

Impact:

Copies aliased source mutations and became dangling views after the source was
destroyed, permitting use-after-free through ordinary value semantics.

Resolution:

Copy construction now copies the flat storage, verifies that every nonempty
source view is backed by that storage, and rebinds all destination views.
Copy assignment uses a checked temporary followed by move assignment.

Verification:

- `Mtx_Audit_Test` checks independent row and column addresses, copy
  assignment across source destruction, and rejection of an externally
  rebound view.

## AUD-084: Polynomial coefficient growth could wrap before resizing

Status: fixed

Affected code:

- `Poly::setCoeff()` and mutable `Poly::operator[]()`.

Concern:

Both entry points formed `index + 1` without first excluding the maximum
64-bit index. At `UINT64_MAX`, the requested size wrapped to zero and the
subsequent coefficient access was out of bounds.

Impact:

An invalid direct coefficient index could cause memory corruption without
first attempting an unrepresentably large allocation.

Resolution:

Each growth entry point now rejects addition overflow and indices beyond the
coefficient vector's individual maximum size before resizing.

Verification:

- `Poly_Audit_Test` checks both maximum-index mutation paths.

## AUD-085: Minimum-distance adapter used an unsafe fixed temporary file

Status: fixed

Affected code:

- `minDist()` and `minDist2()` in the LDPC utility layer.

Concern:

`minDist2()` truncated the fixed relative path `./deleteMe`, followed existing
links, and removed the file only on success. The Algo994 adapter continued
after a failed matrix parse with an uninitialized pointer and dimensions,
narrowed an unchecked thread count into `int`, and mutated backend globals
without synchronization.

Impact:

Calling the helper could clobber a file selected through the working
directory, leak temporary data, pass invalid state into the C backend, or race
with another call.

Resolution:

The adapter now serializes backend-global access, validates the thread count
and parsed dimensions, and stops immediately on parse failure. The matrix is
written to an exclusively created, unpredictable file in the system temporary
directory and removed by an RAII guard on every exit. Builds without Algo994
reject the operation before creating a file.

Verification:

- `Mtx_Audit_Test` verifies the feature-disabled early rejection. The
  Algo994-only code is compile-guarded because that optional backend is not
  present in the audited build configurations.

## AUD-086: Const dense-matrix operations could mutate their source

Status: fixed

Affected code:

- Dense bit and row accessors, `upperTriangular()`, and
  `gausianElimination()`.

Concern:

Const accessors returned mutable proxy objects. Both elimination methods used
those proxies to modify `*this` despite advertising a const, result-returning
interface. A matrix with rows but no columns was also indexed before its width
was checked.

Impact:

A nominally read-only calculation changed caller state and could race with
other readers. A zero-width direct input caused out-of-bounds access in
Release.

Resolution:

Const access now returns bit values and a read-only row view. Elimination is
performed on a local copy and handles zero width before indexing. Existing
elimination and row-arithmetic loops are unchanged.

Verification:

- `Mtx_Audit_Test` checks source preservation, the returned triangular and
  reduced matrices, const reads, and nonempty zero-width inputs.

## AUD-087: Combination utilities admitted invalid domains and overflow

Status: fixed

Affected code:

- `choose()`, `ithCombination()`, and `NChooseK`.

Concern:

Binomial coefficients were computed recursively with unchecked products.
Invalid combination sizes and indices were not rejected. Incrementing the
valid `k = 0` combination indexed an empty vector, and iterator exhaustion was
assertion-only.

Impact:

Malformed direct parameters could produce incorrect enumeration, division by
zero, out-of-bounds access, or assertion-dependent process termination.

Resolution:

Binomial coefficients now use reduced, overflow-checked multiplication.
Combination unranking validates its domain and uses bounded combinatorial
search. The iterator explicitly handles the empty combination and rejects
construction, increment, or dereference outside its range.

Verification:

- `Mtx_Audit_Test` checks known counts and enumeration, count overflow,
  invalid sizes and indices, empty-combination iteration, and exhausted
  iterator operations.

## AUD-088: Polynomial replacement and equality retained stale state

Status: fixed

Affected code:

- Span assignment, polynomial equality, addition, and multiplication.

Concern:

Assigning a shorter or empty coefficient span did not remove old high
coefficients. Comparing two empty zero polynomials indexed coefficient zero
and threw. Arithmetic could retain ineffective trailing zeros and terminate
under a Debug-only multiplication assertion.

Impact:

Reusing a polynomial could silently compute with stale coefficients, while
equivalent zero-padded representations behaved differently across operations
and build modes.

Resolution:

Span assignment now replaces the exact range through an alias-safe temporary.
Equality compares zero-extended coefficients, and algebraic results discard
ineffective trailing zeros. Multiplication derives checked output dimensions
from effective operand sizes while retaining its existing coefficient loops.

Verification:

- `Poly_Audit_Test` covers shorter, empty, and self-overlapping assignment;
  empty and padded-zero equality; cancellation; and multiplication of padded
  operands.

## AUD-089: Polynomial scalar division silently accepted zero

Status: fixed

Affected code:

- `Poly::operator/(const F&)`.

Concern:

Scalar division called `inverse()` directly. The field layer intentionally
defines `inverse(0)` as zero for vector-friendly inversion, so this bypassed
the strict zero check in field division.

Impact:

Dividing a polynomial by zero silently returned the zero polynomial and could
hide invalid algebraic state.

Resolution:

Polynomial scalar division now rejects a zero divisor before computing the
single inverse used to scale all coefficients.

Verification:

- `Poly_Audit_Test` checks scalar division-by-zero rejection; the existing
  scalar test checks nonzero division.

## AUD-090: Sparse-matrix validation ignored trailing column entries

Status: fixed

Affected code:

- `SparseMtx::validate()`.

Concern:

Validation consumed column entries corresponding to row entries but never
required the column iterators to reach their ends. It also did not reject
duplicate adjacency or views detached from the owned flat vectors.

Impact:

A malformed one-sided adjacency representation could be reported as valid and
then produce inconsistent results depending on whether an operation traversed
rows or columns.

Resolution:

Validation now checks owned-storage coverage, view backing, ordering,
duplicates, reciprocal adjacency, and complete consumption of every column.

Verification:

- `Mtx_Audit_Test` injects an extra externally backed column entry and checks
  that validation and copying both reject the malformed representation.

## AUD-091: LDPC generator utilities trusted assertion-only dimensions

Status: fixed

Affected code:

- `computeGen()`, `computeSysGen()`, and `colSwap()`.

Concern:

Invalid matrix dimensions and swap indices were assertion-only or unchecked,
allowing Release out-of-bounds access. A failed systematic conversion also
left a partially modified caller-provided swap list.

Impact:

Invalid direct inputs could access outside matrix storage or expose partial
output state as if it described a completed conversion.

Resolution:

Each utility now validates its own matrix dimensions and swap indices before
indexing. Column swaps are accumulated separately and committed to the caller
only after generator construction succeeds.

Verification:

- `Mtx_Audit_Test` checks invalid parity-check and generator dimensions,
  invalid swap indices, and preservation of the swap output on conversion
  failure.

## AUD-092: Coefficient powers admitted out-of-object bit indices

Status: fixed

Affected code:

- `CoeffCtxInteger::powerOfTwo()`.

Concern:

The helper wrote through a `BitIterator` without checking that the requested
bit belonged to the coefficient object.

Impact:

An invalid direct power could write past the coefficient and corrupt adjacent
memory.

Resolution:

The public helper now validates the storage bit index. An explicitly named
unchecked helper retains the original instructions for callers that validate
the complete domain before entering a hot loop; Noisy VOLE uses that path
after its existing field-width validation.

Verification:

- `Field_Audit_Test` checks the highest valid `u8` power and rejection of the
  first out-of-range power.

## AUD-093: Coefficient range helpers accepted reversed ranges

Status: fixed

Affected code:

- Coefficient copy, serialization, deserialization, zero-fill, and one-fill
  helpers.

Concern:

Negative iterator distances reached byte-count multiplication and then
`memcpy()` or `memset()`. Malformed serialization domains also terminated the
process instead of reporting an input error.

Impact:

A reversed direct range could become an enormous memory operation in Release,
while a malformed serialization range could unconditionally abort the
process.

Resolution:

Each bulk entry point now validates the range once before its existing bulk
operation and checks byte-count multiplication. Serialization failures throw
exceptions. The element-processing loops and bulk memory operations are
unchanged.

Verification:

- `Field_Audit_Test` checks reversed copy and fill ranges and a serialization
  length that is not divisible by the destination element size.

## AUD-094: Fp accepted moduli unsupported by narrow addition and subtraction

Status: fixed

Affected code:

- `Fp` template constraints and its addition and subtraction operators.

Concern:

The type allowed a modulus larger than half the storage range, but addition
and subtraction relied on narrow unsigned wrap followed by one modular
correction. It also allowed moduli that narrowed to zero or otherwise did not
fit the storage type.

Impact:

Valid field operands could produce incorrect results. For example,
`Fp<32769, u16, u32>` computed both addition and subtraction incorrectly near
the top of the field, invalidating algebra and any protocol using it.

Resolution:

The template now requires an unsigned, representable modulus of at least two.
Moduli supported by narrow arithmetic retain the original compile-time path;
only larger moduli use the already-required wide type for addition and
subtraction.

Verification:

- `Field_Audit_Test` checks ordinary and compound addition and subtraction at
  the boundary of `Fp<32769, u16, u32>`.

## AUD-095: Generic DPF multiplication did not validate its output length

Status: fixed

Affected code:

- `DpfMult::multiply()` and `DpfMult::MultSession::multiply()`.

Concern:

The public wrapper passed only `xy.begin()` into the session and never checked
the output container size. The session also probed `xyBegin + (n - 1)` when
`n` was zero.

Impact:

An undersized direct output caused out-of-bounds writes after interactive
state had been consumed, and an empty multiplication underflowed its output
iterator.

Resolution:

The sized public wrapper validates input and output counts before setup.
Empty multiplications return before communication, OT-state checks, or
iterator arithmetic, including in direct multiplication sessions.

Verification:

- `Dpf_Audit_Test` checks rejection of an undersized output and successful
  empty multiplication without configured OTs.

## AUD-096: DPF multiplication dimensions could wrap OT and message bounds

Status: fixed

Affected code:

- DPF multiplication, setup, random-session, bit-multiplication, and generic
  message allocation paths.

Concern:

OT availability was checked with `count + current`, and generic message sizes
were formed with unchecked element-count multiplication. The shared
ceiling-division idiom could also overflow when converting maximum bit counts
to bytes.

Impact:

Wrapped direct dimensions could pass validation and then index beyond the OT
vectors or underallocate a serialized protocol message.

Resolution:

OT counts are bounded individually against the remaining count, message byte
sizes are checked before setup and allocation, and bit-to-byte conversion uses
division plus a remainder bit. All checks occur outside the arithmetic and
serialization kernels.

Verification:

- `Dpf_Audit_Test` checks an OT request that would wrap the former addition.

## AUD-097: DPF bit packing trusted row widths and physical strides

Status: fixed

Affected code:

- `DpfMult::packBits()` and `DpfMult::unpackBits()`.

Concern:

The helpers did not validate row width or checked total-bit multiplication.
For byte-aligned inputs they advanced the packed stream by the physical matrix
row width instead of the logical encoded width. Non-byte-aligned packing left
unused output padding unchanged.

Impact:

Matrices with padded or undersized rows could be serialized incorrectly or
accessed out of bounds, and stale padding bits could leak into a serialized
buffer.

Resolution:

The helpers validate logical row widths and total dimensions once, advance by
the logical byte width, and normalize partial-byte padding. Their per-bit and
per-byte copy loops retain the existing structure.

Verification:

- `Dpf_Audit_Test` checks padded physical rows, undersized rows, and
  normalization of partial-byte padding in both directions.

## AUD-098: OT extension moves retained active source state

Status: fixed

Affected code:

- KOS and KOS-Dot sender and receiver move operations.
- KKRT sender and receiver move operations.
- OOS sender move operations.

Concern:

Defaulted move constructors and incomplete move assignments left flags,
counters, configuration, and fixed AES schedules live in the source object.
Several moved containers also relied on unspecified post-move state.

Impact:

A moved-from object could still report configured base OTs or retain protocol
secrets and session state, making accidental reuse possible and extending the
lifetime of sensitive material.

Resolution:

Move constructors now use the corresponding clearing assignment. Source
flags, counters, configuration, matrices, and containers are reset explicitly;
fixed AES schedules are overwritten with zero-key schedules. These operations
only affect object moves and do not alter OT generation loops.

Verification:

- `OtExt_MoveState_Test` covers both roles of KOS and KOS-Dot.
- `NcoOt_OosMove_Test` covers both KKRT roles and both OOS roles.

## AUD-099: OOS accepted vacuous or malformed malicious security parameters

Status: fixed

Affected code:

- OOS sender and receiver configuration and initialization.

Concern:

Malicious OOS accepted a zero statistical security parameter, producing a
vacuous proof, and deferred byte-alignment validation until the final check.
The public parameter could also be changed after configuration.

Impact:

A caller could select no effective malicious check or begin a protocol that
could only fail after communication and computation.

Resolution:

Configuration requires a nonzero, byte-aligned malicious parameter and bounds
all OOS statistical parameters at 256 bits. Initialization repeats the checks
before allocation or communication to defend the public state boundary.

Verification:

- `NcoOt_StateValidation_Test` checks zero, non-byte-aligned, and oversized
  parameters.

## AUD-100: NCO OT count rounding could overflow

Status: fixed

Affected code:

- KKRT sender and receiver initialization.
- OOS sender and receiver initialization.

Concern:

Rounding an unrestricted `u64` OT count added 127 and, for OOS, the statistical
security parameter before allocation. A sufficiently large direct count could
wrap to a small matrix size.

Impact:

Later protocol processing could operate against storage much smaller than the
requested logical OT domain.

Resolution:

Each initialization entry point individually bounds the caller's OT count at
`2^32 - 1` before arithmetic, allocation, base-OT generation, or network I/O.
The check is outside all expansion and transpose loops.

Verification:

- `NcoOt_StateValidation_Test` checks oversized counts for both roles of both
  protocols.

## AUD-101: Generic OOS proof scratch storage was partly uninitialized

Status: fixed

Affected code:

- The generic-width branch of `OosNcoOtSender::computeProof()`.

Concern:

The scratch array's `memset()` cleared only four of sixteen blocks, and its
capacity check compared the code size to the outer two-element dimension in
the wrong direction.

Impact:

A future non-four-block OOS code could read uninitialized stack data or index
past the fixed scratch row during the malicious proof.

Resolution:

The complete array is value-initialized and the codeword stride must be
nonzero and no larger than the eight-block row capacity. The current
four-block optimized proof loop is unchanged.

Verification:

- `NcoOt_Oos_Test` continues to exercise the active four-block malicious proof.
- The corrected generic capacity invariant is checked before its processing
  loop.

## AUD-102: Reused FFT decode caches accumulated stale transforms

Status: fixed

Affected code:

- Nondestructive `FFTPoly::decode()` with a caller-provided `DecodeCache`.

Concern:

The decode path reserved capacity and appended the polynomial to `mTemp2`
without clearing its previous contents.

Impact:

Reusing a cache transformed stale data, returned an incorrect decode, and grew
memory on every call.

Resolution:

The temporary is assigned from the current polynomial before each transform.
Capacity is still reused, and the copy already required by nondestructive
decoding remains the only data movement.

Verification:

- `Tools_bitpolymul_test` decodes the same transform twice through one cache
  and compares the results.

## AUD-103: `mul190()` omitted the high-limb product

Status: fixed

Affected code:

- The public carryless `mul190()` arithmetic helper.

Concern:

The `a1 * b1` multiplication and its contribution to the Karatsuba middle
term were commented out while the uninitialized result limb was still read.

Impact:

Direct callers received undefined and generally incorrect 190-bit products.
No in-tree protocol currently calls this helper.

Resolution:

The missing carryless multiplication and cross-term XOR are restored, matching
the corresponding low three limbs of `mul256()`.

Verification:

- `Tools_Arithmetic_Audit_Test` compares `mul190()` against the low three limbs
  of `mul256()` with nonzero high input limbs.

## AUD-104: Silent-triple initialization could wrap and mix configurations

Status: fixed

Affected code:

- `SilentOtTriple::init()`.

Concern:

The requested count was rounded and, for triples, doubled before its supported
domain was validated. The wrapper also assigned its party and count before the
underlying Silent OT configuration succeeded.

Impact:

An invalid local request could wrap to a smaller count. A rejected
reconfiguration could also expose new wrapper metadata alongside the previous
or partially replaced OT configuration.

Resolution:

Initialization now individually validates the party, nonzero count, enum value,
and type-specific count bound before deriving dimensions. Wrapper metadata is
committed only after Silent OT configuration succeeds. A later configuration
failure leaves the wrapper inactive rather than exposing mixed state, and a new
configuration clears cached base choices.

Verification:

- `SilentOtTriple_Audit_test` rejects every invalid input class and confirms
  that a parameter rejection preserves the prior live configuration.

## AUD-105: Silent triples forgot their configured correlation type

Status: fixed

Affected code:

- Both `SilentOtTriple::expand()` overloads.
- The internal Silent-triple compression boundary checks.

Concern:

Initialization accepted either triple or OLE mode but did not store it. Either
expansion overload could therefore be called afterward. The triple compression
helpers also checked the `A` output twice and never checked `B`.

Impact:

The wrong overload could consume one-time protocol state before failing or
return a correlation count different from the initialized request. The public
wrapper's equal-length checks prevented the missing internal `B` check from
currently becoming an out-of-bounds write.

Resolution:

The configured type is retained and the wrong overload is rejected before
dimension checks, randomness consumption, or communication. Compression now
validates all three outputs with division-based, overflow-safe boundary checks.
The fixed-width compression loops are unchanged.

Verification:

- `SilentOtTriple_Audit_test` initializes each mode and requires the opposite
  overload to fail without entering the protocol.
- The existing Silent OLE and triple tests cover both valid modes, including
  the scalar no-SSE compression implementation.

## AUD-106: Goldilocks reported twice the intended field range

Status: fixed

Affected code:

- `Goldilocks::order()`.

Concern:

The stored modulus already represented `2^64 - 2^32 + 1`, but `order()` added
another `2^64` after widening it to 128 bits.

Impact:

Public field metadata and generic root-of-unity or NTT validation used a value
larger than the actual field order. The specialized power-of-two Goldilocks root
table remained correct.

Resolution:

`order()` now widens and returns the stored modulus directly.

Verification:

- `Goldilocks_Inverse_Test` requires the reported order to equal the exact
  Goldilocks modulus as a 128-bit integer.

## AUD-107: Goldilocks unary operations mishandled noncanonical representatives

Status: fixed

Affected code:

- `Goldilocks::inv()` and `Goldilocks::increment()`.

Concern:

The field permits every `u64` as a representative, but inversion recognized
only literal zero. The valid noncanonical zero `mModulus` was therefore assigned
an inverse of one. Increment also lost the Goldilocks carry correction when its
input was `UINT64_MAX`.

Impact:

Division by a valid representation of zero returned the numerator instead of
the documented zero convention. Incrementing the maximum representative
returned zero instead of `2^32 - 1`.

Resolution:

Inversion canonicalizes once at its API boundary before the Euclidean loop.
Increment applies the Goldilocks carry correction to the single overflowing
representative. Multiplication, reduction, and NTT loops are unchanged.

Verification:

- `Goldilocks_Inverse_Test` covers inversion and division by noncanonical zero,
  and increment of `UINT64_MAX`.

## AUD-108: Silent-VOLE debug receive allowed a peer-sized copy

Status: fixed

Affected code:

- `SilentVoleReceiver::checkRT()`.

Concern:

The receiver allocated exact storage for the sender's noisy base values but
used `recvResize()` for their serialized frame. Deserialization then copied the
entire peer-selected frame into the fixed-size destination without a destination
end iterator.

Impact:

When insecure debug checking was enabled, a malicious peer could request an
excessive allocation or send an oversized aligned frame that overflowed the
destination vector.

Resolution:

The debug path now performs a fixed-length receive into the already-sized
buffer. Coproto rejects a frame whose transmitted length differs from the
expected length before deserialization. No protocol or arithmetic loop changed.

Verification:

- `Vole_Silent_baseOT_test` runs successfully with debug checking enabled in
  the primary, base, and no-SSE Release configurations.

## AUD-109: Negative integers were zero-extended into fixed-width unsigned values

Status: fixed

Affected code:

- The integral constructor of `UInt<W>`.

Concern:

The constructor first converted a signed source to the source type's unsigned
counterpart and then widened it. A negative source narrower than 64 bits was
therefore zero-extended within the low limb, and all higher limbs were also
zeroed.

Impact:

For example, `UInt<128>(int{-1})` produced `0x00000000ffffffff`
instead of the builtin unsigned conversion result modulo `2^128`. Arithmetic
using negative integral constants could consequently start from the wrong
value.

Resolution:

Signed negative sources now initialize the destination limbs with ones and
convert directly into the low limb, preserving sign extension. Wider source
chunks continue to overwrite the corresponding destination limbs.

Verification:

- `UInt_Conversions_Test` checks negative 8- and 32-bit sources across 128- and
  256-bit destinations.

## AUD-110: Goldilocks omitted the generic member inverse interface

Status: fixed

Affected code:

- `Goldilocks` and generic field algorithms that call `F::inverse()`.

Concern:

Goldilocks exposed only the static `inv(result, input)` helper, while the other
field types and generic inverse NTT code use a member `inverse()` operation.

Impact:

Generic inverse algorithms instantiated with Goldilocks, including vector-field
inversion, failed to compile.

Resolution:

Goldilocks now provides an inline member wrapper around the existing static
inversion implementation. The arithmetic implementation is unchanged.

Verification:

- `Goldilocks_Inverse_Test` compares the member and static inverse interfaces.

## AUD-111: Matrix inverse NTT normalized only one vector lane

Status: fixed

Affected code:

- `inttNegWrapMatrix()` with `FVec` coefficient types.

Concern:

The inverse constructed its normalization factor as `F(a.size())`. For an
`FVec`, the initializer-list constructor stored the size in lane zero and
zero-filled the remaining lanes. The inverse path also initialized vector
accumulators from a scalar zero and placed the scalar root on the unsupported
left side of vector multiplication.

Impact:

For vector fields that compiled through the normalization expression, lane zero
was scaled correctly and every other lane was multiplied by zero. Other vector
field combinations failed to instantiate.

Resolution:

The accumulator now uses `F::zero()`, scalar multiplication uses the supported
vector-times-scalar order, and the normalization inverse is constructed from
the scalar root type. The quadratic transform loops retain their existing
structure.

Verification:

- `Ntt_Audit_Test` round-trips a two-lane `FVec<Fp31, 2>` through the matrix
  forward and inverse transforms with distinct lane values.

## AUD-112: Regular DPF working-matrix dimensions could wrap

Status: fixed

Affected code:

- `RegularDpf::init()` and the full-domain expansion working matrices.

Concern:

Initialization bounded the OT count but did not bound the rounded domain times
the number of points. The matrix container multiplies its row and column counts
in `u64`, so accepted dimensions such as a `2^63` domain with eight points
wrapped all three working-matrix allocations to zero.

Impact:

Release builds could subsequently write through empty matrix views, causing
out-of-bounds memory access from a caller-size error.

Resolution:

Initialization now bounds the point count against the rounded power-of-two
domain before committing state or configuring the multiplier. Expansion loops
are unchanged.

Verification:

- `Dpf_Audit_Test` requires rejection of the wrapping `2^63`-by-eight
  configuration.

## AUD-113: Ternary DPF derived storage dimensions could wrap

Status: fixed

Affected code:

- `TernaryDpf::init()` and its seed, leaf, and tag storage allocations.

Concern:

The OT-count bound did not also bound the independently derived seed-storage
byte count or the point-count-times-domain leaf dimensions. Those products
were formed directly during expansion.

Impact:

Extreme caller parameters could wrap an allocation dimension and form matrix
views larger than their backing allocation.

Resolution:

Initialization now individually bounds the leaf/tag element count and the
complete seed-storage byte count before clearing prior OTs or committing the
new configuration. Expansion loops are unchanged.

Verification:

- `Dpf_Audit_Test` requires rejection of a depth-32 ternary configuration whose
  derived seed-storage size exceeds `u64`.

## AUD-114: MR POPF overfilled a two-block randomness buffer

Status: fixed

Affected code:

- `MRPopf::program()`.

Concern:

The POPF requested 32 blocks of PRNG output through a pointer into a
`Block256`, whose storage contains only two blocks.

Impact:

Calling `program()` overwrote adjacent stack storage and corrupted the
function's local state before it was returned.

Resolution:

The PRNG request now uses the destination object's two-block size. The change
does not add work or checks to the protocol path; it corrects the requested
output length.

Verification:

- `Bot_McQuoidRR_Moeller_MR_Test` checks that `program()` consumes exactly one
  `Block256` and passes for both enabled MR configurations.

## AUD-115: ExConv checker mishandled a partial generator batch

Status: fixed

Affected code:

- `getCompressedGenerator()` and `getGeneratorWeight2()`.

Concern:

Both checker helpers processed fixed 1024-row batches without consistently
accounting for the final partial batch. One helper initialized rows beyond the
matrix, while the other ignored its current offset and omitted the last row.

Impact:

Non-multiple-of-1024 dimensions could cause out-of-bounds access or an
incorrect reported generator weight in the offline code checker.

Resolution:

Each batch now derives one active-row count from the remaining rows and uses it
for initialization, packing, and progress accounting. Protocol encoding loops
are unchanged.

Verification:

- `ExConvCode_Audit_Test` checks both helpers with a 1025-row identity code.

## AUD-116: Offline code checkers accepted invalid derived dimensions

Status: fixed

Affected code:

- `EAChecker()`, `ahash()`, and `ExConvChecker()`.

Concern:

CLI-provided sizes and weights reached divisions, shifts, products,
allocations, and worker setup without validation. Exceptions raised inside
workers also terminated the process, and an ExConv worker failure could leave
the progress loop waiting forever.

Impact:

Invalid checker inputs could trigger undefined shifts, division by zero,
wrapped dimensions, excessive allocations, process termination, or a hang.

Resolution:

The checker entry points now validate individual dimensions and relationships
before worker creation. Dynamically discovered exponential sets are bounded at
the point of use. Worker exceptions are captured, all threads are joined, and
the first exception is rethrown to the caller. These are offline checker and
CLI boundaries; no protocol hot loop was changed.

Verification:

- `ExConvCode_Audit_Test` requires rejection of zero thread or weight counts
  and 64-bit logarithmic shifts.
- The checker tests pass in the primary, base, no-SSE, and bit-polynomial build
  configurations.

## AUD-117: Chosen NCO matrix dimensions could wrap before allocation

Status: fixed

Affected code:

- `NcoOtExtReceiver::receiveChosen()`.

Concern:

The chosen-message adapter multiplied the OT count by the messages-per-OT
count for an internal matrix allocation without bounding the product.

Impact:

For a 64-bit configured input domain, extreme caller sizes could wrap the
allocation dimension after state validation, leading to undersized storage and
subsequent out-of-bounds access.

Resolution:

The public adapter now bounds the two caller-controlled factors before choices
are processed, base-OT state is consumed, or protocol work begins. Inner NCO
loops are unchanged.

Verification:

- `NcoOt_ChosenValidation_Test` requires rejection of an overflowing
  two-by-`2^63` request and confirms that receiver state remains unconsumed.

## AUD-118: Prime-field exponentiation truncated large unsigned exponents

Status: fixed

Affected code:

- `Fp::pow()` and generic field inversion for large `u64` moduli.

Concern:

The exponent interface accepted only `i64`. Passing a `u64` exponent above
`INT64_MAX`, including `modulus - 2` for large moduli, converted it to a
negative signed value and caused rejection.

Impact:

Valid large unsigned powers and generic inversions over prime moduli above the
signed 64-bit range could not be computed through the field interface.

Resolution:

`pow()` now accepts non-Boolean integral exponent types, rejects negative
signed values, and performs the square-and-multiply loop using the source
type's unsigned counterpart. The arithmetic loop retains the same structure.

Verification:

- `Field_Audit_Test` checks `UINT64_MAX` against its Fermat-reduced exponent and
  confirms that negative signed exponents remain rejected.

## AUD-119: RingLPN initialization accepted unsafe dimensions and roles

Status: fixed

Affected code:

- `RingLpnTriple::init()`.

Concern:

Initialization accepted invalid party and enum values, zero requests,
unsupported polynomial counts and weights, and derived dimensions that could
overflow or underflow before reaching lower-level components.

Impact:

Caller-controlled configurations could trigger undefined shifts, invalid tree
depths, oversized tensor correlations, or inconsistent protocol state.

Resolution:

The initialization boundary now validates each public parameter and derived
dimension before committing state. The existing DPF and arithmetic expansion
loops are unchanged, and RevCuckoo internals remain outside this audit track.

Verification:

- `RingLpn_Audit_test` covers invalid roles, zero and oversized requests,
  excessive polynomial counts and weights, and rings too small for the chosen
  weight.

## AUD-120: Small-field and subspace VOLE initialization was non-atomic

Status: fixed

Affected code:

- `SmallFieldVoleBase`, `SmallFieldVoleSender`, and `SmallFieldVoleReceiver`.
- Semi-honest and malicious-leaky `SubspaceVole` initialization.

Concern:

Invalid field widths and VOLE counts were used in divisions, shifts, and seed
table products before complete validation. Failed initialization could leave
objects partially configured. Two seed setters also asserted an unrelated
comparison, and a signed shift was undefined at the maximum field width.

Impact:

Invalid caller dimensions could cause division by zero, undefined behavior,
oversized allocation requests, or reuse of a partially changed object.

Resolution:

Field widths, nonzero counts, base-OT products, and padded seed-table sizes are
now bounded before state changes. Subspace wrappers construct their code,
VOLE, and correction storage in temporaries and move them into place only
after validation. The signed shift and seed assertions were corrected. No
generation hot loop was changed.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` covers zero and maximum field widths,
  zero/oversized counts, failed-initialization state preservation, valid seed
  installation, and all four subspace wrapper boundaries.

## AUD-121: BetaCircuit deserializers trusted counts and structure

Status: fixed

Affected code:

- BetaCircuit JSON, binary, and Bristol readers in the cryptoTools submodule.

Concern:

Serialized counts were allocated or narrowed without practical bounds, stream
failures left scalars indeterminate, Bristol dimension subtraction could
underflow, and gate, level, wire, flag, and print relationships were not fully
validated. Readers also modified the destination incrementally.

Impact:

Malformed circuit files could cause excessive allocations, out-of-bounds
access during parsing or later evaluation, or leave a reusable circuit object
partially overwritten after an exception.

Resolution:

All readers now parse into a temporary circuit, bound individual serialized
collections and strings, check every stream operation and narrowing boundary,
validate circuit structure, verify the hash, and commit only on success.
Copy-gate ranges are validated according to their length encoding.

Verification:

- `BetaCircuit_bin_Tests` continues to round-trip valid binary circuits.
- `Gmw_Audit_Test` rejects structurally invalid and truncated binary circuits
  and malformed Bristol dimensions while preserving the destination object.

## AUD-122: GMW accepted malformed roles and circuit metadata

Status: fixed

Affected code:

- `Gmw::init()`, wire-bundle mapping, and the run precondition.

Concern:

GMW did not validate the party role or preflight circuit wire ordering, gate
types and dependencies, nonlinear counts, outputs, or level metadata. Empty
or out-of-range bundles could also be dereferenced before rejection.

Impact:

A malformed caller-provided circuit could cause out-of-bounds access, consume
the wrong amount of OLE correlation, or fail after protocol execution began.

Resolution:

Initialization now performs a one-time structural preflight before allocating
or committing state, and bundle accessors reject empty and out-of-range
bundles. The evaluator's gate loops are unchanged; unsupported copy encodings
and gate types are rejected at initialization.

Verification:

- `Gmw_Audit_Test` covers invalid roles and evaluation counts, out-of-range
  wires, inconsistent levels, empty bundles, and parser failures.

## AUD-123: Bit-polynomial sizes could overflow allocation arithmetic

Status: fixed

Affected code:

- `AlignmentAllocator`, `FFTPoly::resize()`, and the raw `bitpolymul()` entry
  point.

Concern:

The aligned allocator multiplied element counts and added its alignment header
without accounting for overflow. FFT sizing also rounded unrestricted 64-bit
input lengths and doubled the transform size.

Impact:

Extreme caller sizes could wrap an allocation byte count or transform length,
leading to an undersized allocation and subsequent out-of-bounds writes.

Resolution:

The allocator exposes a header-aware maximum and rejects larger requests.
FFT inputs are explicitly limited to the supported 32-bit range, and resize
commits dimensions only after storage allocation succeeds. Transform hot loops
are unchanged.

Verification:

- `Tools_bitpolymul_test` checks allocator overflow rejection and atomic
  rejection of an unsupported FFT size in a bitpolymul-enabled build.

## AUD-124: Small-field VOLE generation trusted unexpanded seed state

Status: fixed

Affected code:

- Checked `SmallFieldVoleSender::generate()` and
  `SmallFieldVoleReceiver::generate()` overloads.

Concern:

Initialization installs dimensions and generation dispatch before PPRF seeds
are expanded. Generation guarded the required seed storage only with an
assertion inside the specialized kernel.

Impact:

In release builds, generating from an initialized but unexpanded object could
read an empty seed table out of bounds.

Resolution:

The checked span entry points now require initialized dimensions, a selected
dispatch function, and expanded seeds before entering the generation kernel.
Raw pointer kernels and their inner AES loops remain unchanged.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` requires both roles to reject generation
  before seeds are installed.

## AUD-125: Malicious subspace VOLE wrappers formed unchecked subspans

Status: fixed

Affected code:

- Malicious sender and receiver generation and hash wrappers.

Concern:

Generation formed padded subspans before validating the supplied storage, and
hash entry points indexed caller spans according to protocol dimensions
without checking their lengths.

Impact:

Short caller buffers could cause out-of-bounds reads or writes before a lower
layer had an opportunity to reject the request.

Resolution:

Each batch wrapper now validates its individual input and output dimensions
before constructing subspans or entering the unrolled hash loop. Generation
also requires expanded seed state. No check was added inside a hot loop.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` covers short random, chosen, sender-hash,
  and receiver output spans.

## AUD-126: Malicious subspace VOLE challenge sequencing was assertion-only

Status: fixed

Affected code:

- Sender and receiver hash entry points, response generation, and response
  checking.

Concern:

The universal-hash update kernel asserted that a challenge was installed, but
release builds could hash or finalize using the default key and an unseeded
PRNG.

Impact:

Incorrect protocol sequencing could bypass the intended randomized
consistency-check state or access invalid PRNG state.

Resolution:

Challenge readiness is now checked once at each public hash or response state
transition. The per-block universal-hash kernel remains unchanged.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` requires both roles to reject hashing
  before challenge setup.

## AUD-127: SoftSpoken VOLE moves left active source metadata

Status: fixed

Affected code:

- Small-field VOLE sender and receiver move operations.
- Malicious subspace VOLE base, sender, and receiver move operations.

Concern:

Default moves transferred owning storage but copied primitive dimensions,
dispatch pointers, and challenge counters. A moved-from object could therefore
still appear initialized while its backing storage had been transferred.

Impact:

Accidental reuse of a moved-from protocol object could dispatch generation or
hashing against empty storage, causing out-of-bounds access or invalid
challenge use.

Resolution:

Custom moves transfer state and deterministically clear the source dimensions,
dispatch pointers, seed and delta storage, challenge material, counters, and
hash buffers. Moved-from objects are valid but inert.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` checks move construction and assignment,
  cleared source state, and rejection of source reuse.

## AUD-128: Silent OT hash helpers trusted unavailable internal state

Status: fixed

Affected code:

- `SilentOtExtSender::hash()` and `SilentOtExtReceiver::hash()`.

Concern:

The internal-by-convention hash helpers trusted expanded message vectors and,
for the sender, the correlation delta. The receiver also formed element-zero
addresses even for empty spans.

Impact:

Direct or incorrectly sequenced calls could dereference absent internal state
or trigger undefined behavior on an empty request.

Resolution:

The helpers now perform cheap entry checks for exact expanded-state sizes and
the sender delta before entering their eight-at-a-time loops. The receiver uses
`data()` so the empty case does not form an invalid element reference. Hash
loops are unchanged.

Verification:

- `OtExt_Silent_AuditState_Test` requires both roles to reject hashing after
  configuration but before internal expansion.

## AUD-129: Malicious SoftSpoken exposed a distinguishable base-VOLE abort

Status: fixed

Affected code:

- Malicious SmallField VOLE expansion and the enclosing malicious subspace
  VOLE consistency check.

Concern:

The SmallField PPRF consistency check aborted immediately, before the outer
subspace-VOLE consistency transcript. A malicious peer could distinguish a
base-VOLE failure from the final VOLE failure by observing whether subsequent
protocol messages arrived.

Impact:

The separate abort events exposed an additional selective-failure predicate
of the honest party's secret PPRF choices and did not follow the composed
protocol's requirement to reveal only the final consistency result.

Resolution:

SmallField VOLE supports explicit deferred consistency failure for its
malicious subspace-VOLE caller while retaining immediate failure for direct
callers. The enclosing receiver completes the normal transcript and combines
the latched result with the final consistency decision. The generation and
hash hot loops are unchanged.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` verifies that a deferred base failure is
  reported only by the final malicious subspace-VOLE check.

## AUD-130: Failed SmallField VOLE expansion retained false seed readiness

Status: fixed

Affected code:

- Sender and receiver `SmallFieldVole::expand()` failure paths.
- Final malicious subspace-VOLE failure handling.

Concern:

Both expansion roles allocated `mSeeds` before awaited PPRF and network work.
An exception closed the socket but left the seed vector nonempty, so
`hasSeed()` reported the failed endpoint as ready.

Impact:

Reusing the endpoint could skip expansion and generate from partial or
zero-filled seed state, causing transcript desynchronization or silently
invalid correlations.

Resolution:

Every SmallField expansion exception now clears seed readiness. A failed final
malicious consistency check also invalidates the deferred seed state, and the
outer OT sender clears it if the remainder of a deferred-failure transcript
terminates early.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` checks sender and receiver expansion
  exceptions, the deferred final failure, and cleared readiness afterward.

## AUD-131: Prime-field deserialization accepted noncanonical residues

Status: fixed

Affected code:

- `CoeffCtxFp` deserialization and generic protocols receiving serialized
  prime-field coefficients.

Concern:

The prime-field context inherited bytewise deserialization without checking
that the resulting storage value was below the field modulus. Field arithmetic
only asserted that invariant.

Impact:

A peer could supply a noncanonical residue that aborted a debug build and
entered arithmetic with violated reduction assumptions in a release build.
Addition, subtraction, and Barrett multiplication could then produce invalid
correlations.

Resolution:

Prime-field deserialization checks every decoded residue once at the wire
boundary and rejects noncanonical encodings. A failed decode clears the whole
destination range. Arithmetic kernels are unchanged.

Verification:

- `Field_Audit_Test` rejects an all-one `F12289` encoding, requires failure to
  clear the destination, and round-trips a canonical encoding.

## AUD-132: Vector fields selected the integer coefficient context

Status: fixed

Affected code:

- Default coefficient-context selection for `FVec<F, N>`.
- Vector coefficient sampling, decomposition, powers, and serialization.

Concern:

`FVec` fell through to `CoeffCtxInteger`. Random blocks were copied directly
into scalar field lanes without reduction, and binary powers treated unused
high storage bits as valid scalar values. In particular, the advertised
`FVec<Fp31, 4>` configuration used four invalid power rows and commonly
sampled noncanonical lanes.

Impact:

Debug builds could abort on scalar-field assertions. Release DPF, VOLE, and
Ring-LPN computations could silently produce invalid correlations.

Resolution:

A dedicated compile-time vector context delegates canonical sampling and
validation to the scalar context. Binary decomposition remains an
allocation-free lane-storage view; unused scalar high-bit rows map to zero.
The fixed lane loops remain compile-time unrolled, and arithmetic kernels are
unchanged.

Verification:

- `Field_Audit_Test` checks default context selection, canonical sampling,
  unused Fp31 power rows, and reconstruction from the complete decomposition.
- `Vole_Noisy_test` exercises scalar `F12289` and two-lane `Fp31` vector VOLE.

## AUD-133: Raw vector serialization included alignment padding

Status: fixed

Affected code:

- Serialization and deserialization of aligned `FVec` coefficients.

Concern:

The integer context serialized `sizeof(FVec)`. For lane arrays whose byte size
was not a multiple of the vector's 16-byte alignment, this included
uninitialized tail padding. Binary decomposition included the same padding.

Impact:

A padded vector protocol instantiation could transmit stale stack or heap
bytes and allow indeterminate padding to affect protocol choices.

Resolution:

The vector context serializes only the packed scalar lanes, excludes tail
padding from its decomposition, and zeroes the complete destination object
before decoding. Padding-free vectors retain a bulk-copy fast path.

Verification:

- `Field_Audit_Test` verifies that `FVec<Fp31, 2>` serializes eight bytes,
  leaves bytes beyond that representation untouched, zeroes decoded padding,
  and rejects a noncanonical lane atomically.

## AUD-134: Ternary DPF bypassed coefficient wire encodings

Status: fixed

Affected code:

- The final coefficient-share exchange in `TernaryDpf::expand`.

Concern:

Ternary DPF sent and received its coefficient vector as raw typed storage
instead of using the supplied coefficient context. This bypassed any
context-defined canonical validation and included alignment padding for
padded coefficient types.

Impact:

A malicious peer could inject representations that the coefficient context
would reject before arithmetic. Padded coefficient types could also disclose
stale bytes, and custom contexts could not define their intended wire
representation.

Resolution:

The final reveal is serialized to a fixed-size byte buffer and deserialized
through the coefficient context. Validation remains at the transcript
boundary, outside the leaf-expansion loops.

Verification:

- `TritDpf_Proto_Test` uses an instrumented binary coefficient context and
  requires both parties to serialize and deserialize the final reveal.

## AUD-135: DPF bit multiplication retained peer-controlled padding

Status: fixed

Affected code:

- `DpfMult::multiplyBits` for a bit count not divisible by eight.

Concern:

The local party cleared unused high bits in its final packed byte, but did not
normalize the corresponding bytes received from its peer. The bytewise
multiplication therefore allowed those nonlogical bits to affect output
padding.

Impact:

A peer could make the packed result noncanonical. Code that later handled the
backing bytes rather than the logical bit length could serialize or consume
the peer-controlled padding.

Resolution:

The two received final bytes are masked once before the existing bytewise
multiplication loop. Full-byte inputs and the loop itself are unchanged.

Verification:

- `Dpf_Audit_Test` injects set padding bits from a peer and requires the
  one-bit multiplication result to retain zero padding.

## AUD-136: GMW ignored constant and inverted output flags

Status: fixed

Affected code:

- GMW circuit initialization, evaluation setup, and output extraction.

Concern:

GMW exported the raw storage associated with each output wire without applying
the circuit's `Zero`, `One`, or `InvWire` metadata. Constant output wires had
never been written, while inverted wires represented the underlying value
rather than its complement. Circuit levelization could also rewrite the wire
flags before output extraction.

Impact:

Constant or inverted outputs were incorrect. Reconstructing a constant MPC
output could disclose stale allocator contents contained in the uninitialized
output share.

Resolution:

Initialization captures logical output flags before levelization. Evaluation
materializes constant output shares after wire allocation, and extraction
flips only the inverted output bits belonging to party one. Ordinary outputs
and the gate-evaluation loops are unchanged.

Verification:

- `Gmw_Audit_Test` evaluates a circuit with ordinary, constant-one, and
  inverted outputs and reconstructs all three across a partial SIMD batch.

## AUD-137: GMW accepted same-round nonlinear data dependencies

Status: fixed

Affected code:

- GMW validation of caller-supplied and generated circuit levels.

Concern:

Level metadata was checked for total gate and nonlinear-gate counts, but not
for data hazards within a round. A gate could consume a nonlinear output before
the peer's response had produced it, or overwrite an input that an earlier
nonlinear gate needed again during response processing.

Impact:

Malformed level metadata could make the protocol read unwritten wire storage
and silently evaluate a different circuit.

Resolution:

Initialization now rejects both same-round hazards. Per-wire epoch markers
make the validation linear in the circuit size without adding checks to the
evaluation loops.

Verification:

- `Gmw_Audit_Test` rejects two dependent AND gates placed in one round.

## AUD-138: GMW could rerun a consumed gate schedule

Status: fixed

Affected code:

- GMW initialization, OLE installation, and run preconditions.

Concern:

Successful evaluation advanced `mGates` to an empty span. Installing a fresh
set of OLE correlations then allowed another run to form nonempty subspans
from that consumed span.

Impact:

A second evaluation could access beyond the circuit's gate vector in Release
builds.

Resolution:

Evaluation now marks the instance consumed when it commits its one-time OLE
state. Both OLE installation and the run precondition reject consumed
instances, while `init()` establishes fresh state and discards any prior OLEs.

Verification:

- `Gmw_Audit_Test` requires fresh OLE installation and a second zero-OLE
  linear evaluation on a consumed evaluator to fail before state changes.

## AUD-139: GMW copies retained views into the source object

Status: fixed

Affected code:

- GMW object construction and assignment.
- Move support for `BetaCircuit`.

Concern:

The implicit GMW copy operations copied `mGates`, `mPrint`, and `mWords` as
non-owning references. These references continued to address the source
object's circuit and wire storage instead of the copied containers.

Impact:

Evaluation through a copy could modify the source object. Destroying the
source before evaluation left the copy with dangling references and enabled
use-after-free.

Resolution:

GMW is now move-only. Its explicit move operations transfer the owning
containers together with their internal references and clear the source.
`BetaCircuit` exposes its default vector moves so circuit transfer does not
copy a potentially large gate schedule.

Verification:

- Compile-time checks require GMW to be noncopyable and nothrow movable.
- `Gmw_Audit_Test` evaluates move-constructed and move-assigned instances and
  requires both source objects to be inert.

## AUD-140: RingLPN reinitialization retained tensor state

Status: fixed

Affected code:

- `RingLpnTriple::init`.

Concern:

Reinitialization replaced the DPF and GMW state but retained tensor
coefficients, tensor OTs, choices, and product positions. The retained tensor
coefficient vector made `baseCorCount()` treat the new session's tensor as
ready.

Impact:

The reported base-correlation count omitted the tensor material required by
the new session. Later setup could clear the retained tensor without producing
a replacement, causing failure after protocol state had been consumed.

Resolution:

After validating the new configuration, initialization discards all tensor
and product state from the previous session. Reusable base-OT extension state
and public transform caches remain available.

Verification:

- `RingLpn_Audit_test` populates every tensor-state container, reinitializes
  the object, and requires the new base-correlation count to include the
  complete tensor.

## AUD-141: RingLPN validated outputs after consuming protocol state

Status: fixed

Affected code:

- The OLE and triple overloads of `RingLpnTriple::expand`.

Concern:

Expansion checked output lengths only after generating or consuming the
tensor, DPF, GMW, and OT state. A caller could therefore begin both parties'
protocol work with incompatible output spans.

Impact:

A local size error consumed one-time correlations, closed the protocol socket,
and forced the peer to abort before the error was reported.

Resolution:

Both overloads now validate their complete output interface before entering
the protocol body or its failure-cleanup scope. Invalid calls preserve the
initialized state and leave the socket untouched.

Verification:

- `RingLpn_Audit_test` supplies mismatched triple outputs and requires
  rejection before the tensor state or socket changes.

## AUD-142: Scalar RingLPN conversion removed GMW masks

Status: fixed

Affected code:

- The non-SSE SIMD emulation used by RingLPN OT-to-OLE conversion.

Concern:

The scalar movemask read byte zero in every iteration and placed no input
most-significant bit in the result. The preceding lane shift therefore always
produced a zero packed mask. The scalar shuffle and shift also used signed
operations whose behavior did not match the unsigned SIMD instructions.

Impact:

The OT sender obtained zero multiplication and addition shares. RingLPN still
produced algebraically valid correlations, so correctness tests passed. The
sender's GMW messages were nevertheless unmasked and exposed its input-wire
shares to the peer.

Resolution:

The non-SSE shuffle, lane shift, and movemask now use the fixed-width scalar
implementation shared in structure with Silent-triple conversion. The SSE
path and the conversion loops are unchanged.

Verification:

- `RingLpn_conversion_test` checks every packed sender and receiver bit
  against the source OT messages in both SSE and non-SSE builds.

## AUD-143: Stationary Sum DMPF omitted refreshed base OTs

Status: fixed

Affected code:

- RingLPN base-correlation counting and installation after a Sum-DMPF
  expansion.

Concern:

A successful expansion retained the programmed Sum-DMPF points and set
`mHasDpf`. The embedded Regular DPF consumed its multiplication OTs during the
same expansion. `baseCorCount()` treated `mHasDpf` as proof that no further DPF
correlations were required.

Impact:

A stationary reuse supplied only fresh tensor correlations. The next
expansion then failed after accepting those correlations because the DPF
multiplier had no OTs.

Resolution:

RingLPN now distinguishes programmed points from available Sum-DMPF base OTs.
It requests and installs fresh DPF OTs after each Sum-DMPF expansion without
requesting a second set of GMW OLEs. RevCuckoo accounting is unchanged.

Verification:

- `RingLpn_Audit_test` exhausts the embedded Sum-DMPF multiplier and checks
  the refreshed correlation counts and installation.
- `RingLpn_stationary_test` completes two Sum-DMPF expansions with fresh base
  correlations for the second expansion.

## AUD-144: Prime-field sampling used one 64-bit candidate

Status: fixed

Affected code:

- PRNG assignment for `Fp` and Goldilocks elements.
- Block-to-field mapping in prime-field coefficient contexts.
- Scalar fallback mapping for vector fields.

Concern:

The samplers reduced one 64-bit value modulo the field order. Block mapping
also ignored the upper 64-bit limb. The resulting statistical distance per
sample was approximately `2^-35` for Fp31 and `2^-32` for Goldilocks.

Impact:

RingLPN and field-based DPF or VOLE protocols sample many field elements.
Their aggregate sampling distance could exceed the selected 40-bit
statistical-security allowance.

Resolution:

PRNG assignment now rejection-samples complete 64-bit candidates. Block
mapping tries both limbs before rehashing the block after a double rejection.
The supported scalar fields reject with negligible probability. Fp retains
its existing modular reduction on the common path. Goldilocks uses a compare
and conditional subtraction instead of division.

Verification:

- `Field_Audit_Test` uses Fp31 and Goldilocks vectors whose low limb is
  rejected and requires the mapper to consume the high limb.
- RingLPN, DPF, noisy-VOLE, and field regression tests pass with the new
  mapping.

## AUD-145: Silent VOLE inferred subgroup size from field status

Status: fixed

Affected code:

- Silent-VOLE syndrome-decoding configuration.
- Default contexts for vector fields and Goldilocks.

Concern:

Silent VOLE used `isField()` to infer the smallest nonzero additive subgroup.
A product of prime fields is not a field, but its smallest additive subgroup
has the scalar field's characteristic. The generic Goldilocks context also
reported that its scalar coefficient type was not a field. Both cases were
therefore configured as if they contained an order-two subgroup.

Impact:

Stationary-noise sessions over these types used the less conservative
binary-group parameter calculation instead of the calculation required for
their odd-characteristic additive groups.

Resolution:

Coefficient contexts now expose the additive-group bit count independently
of field status. Vector contexts delegate this value to their scalar context.
Goldilocks has a field-specific context that reports its 64-bit characteristic.
Legacy custom contexts retain the previous field-based fallback.

Verification:

- `Field_Audit_Test` checks the subgroup metadata for Fp31 vectors and
  Goldilocks.
- `Vole_Silent_Clear_test` checks the resulting conservative parameters for
  both coefficient types.

## AUD-146: DPF owners copied one-time correlations

Status: fixed

Affected code:

- `DpfMult` and the DPF protocol objects that own multiplication OTs.

Concern:

The protocol objects used implicit copy operations. A copy duplicated each OT
seed and its consumption index. The original object and its copy could then
consume the same one-time correlations in different protocol executions.

Impact:

Reusing OT-derived multiplication correlations can cancel the masks between
two transcripts. The peer can then learn relations between the secret inputs
that the correlations were intended to hide.

Resolution:

`DpfMult`, Regular DPF, Sparse DPF, Sum DMPF, and Ternary DPF are move-only.
Each move transfers the protocol state and clears the source object.

Verification:

- Compile-time checks require the protocol types to be non-copyable and
  movable.
- `Dpf_Audit_Test` moves each state-bearing DPF type and requires the source
  object to contain no protocol state.

## AUD-147: DPF multiplication sessions copied mask state

Status: fixed

Affected code:

- `DpfMult::MultSession`.

Concern:

A multiplication session contains spans over reserved OTs and an expansion
index. Its implicit copy operation duplicated both. The original session and
its copy therefore derived the same masks for their next multiplication.

Impact:

Two transcripts with the same OT-derived masks can expose relations between
the fixed secret bit sharing and the multiplicands supplied to each session.

Resolution:

Multiplication sessions are move-only. A move transfers the OT spans, fixed
bit sharing, and expansion index. It then clears all state in the source
session.

Verification:

- Compile-time checks require multiplication sessions to be non-copyable and
  movable.
- `Dpf_Audit_Test` verifies that moving a populated session clears its source
  without changing the transferred state.

## AUD-148: Failed DPF multiplication reused exposed Beaver correlations

Status: fixed

Affected code:

- The block-vector overload of `DpfMult::multiply`.

Concern:

The protocol incremented its OT index only after both network operations
completed. A peer could receive the opened Beaver masks and close the socket
before replying. A retry would then use the same multiplication correlations.

Impact:

Differences between two openings under one Beaver correlation cancel the
random masks. A peer can use the result to learn a relation between the secret
inputs from the two executions.

Resolution:

The multiplication reserves its complete OT range before it computes or sends
the first protocol message. All later accesses use the reserved starting
index. The inner multiplication loops are unchanged.

Verification:

- `Dpf_Audit_Test` closes the peer socket, requires multiplication to fail,
  and verifies that the attempted OT range remains consumed.

## AUD-150: Parallel protocol joins discarded child failures

Status: fixed

Affected code:

- Parallel protocol joins in Silent VOLE, RingLPN triples, Foleage triples,
  Ternary DPF, and Sparse DPF.

Concern:

`when_all_ready` waits for every child task but stores each child exception in
the returned task object. The affected call sites discarded these objects, so
a failed transport or base-correlation task did not fail the parent protocol.

Impact:

The parent could install or consume partially initialized correlation state.
Ternary DPF could also continue from an incomplete correction-word exchange
and derive a response from receive buffers that the peer did not initialize.

Resolution:

Every affected join checks the result of each child after all children finish.
Any child exception now fails the parent before it installs or consumes the
parallel operation's output. The checks run only at protocol boundaries.

Verification:

- `Dpf_Audit_Test` closes the peer socket before a parallel Sparse DPF receive
  completes and requires the parent operation to report the failure.
- Release and scalar builds exercise the affected protocol implementations.

## AUD-151: Sparse DPF accepted non-bit correction tags

Status: fixed

Affected code:

- `SparseDpf::reveal` for seed and tag corrections.

Concern:

The protocol received each correction tag as a byte and combined it with a
local bit without checking that the peer sent zero or one.

Impact:

A peer could inject high bits into the binary tag state. Those bits then
entered tag arithmetic and block-mask construction, producing malformed DPF
outputs outside the protocol's binary invariant.

Resolution:

Sparse DPF validates both received tag components before it combines either
component with local state. The validation occurs once per exchanged tree
node and does not change the expansion kernels.

Verification:

- `Dpf_Audit_Test` sends a correction tag with value two and requires the
  receiver to reject it before changing its output state.

## AUD-152: Failed stationary Silent sessions retained consumed correlations

Status: fixed

Affected code:

- The online exception paths of the Silent OT and Silent VOLE sender and
  receiver implementations.

Concern:

Successful stationary executions discarded their per-execution base VOLE and
malicious-check correlations. Exceptional exits only closed the socket and
re-threw the error. A caller could therefore retry an object after the peer had
observed a correlation-dependent transcript. The Silent OT sender could also
retain malicious-check OT pairs already reordered by the failed execution.

Impact:

A retry could reuse one-time masks across distinct transcripts. This is outside
the OT and VOLE security arguments and can expose relations by mask
cancellation. Reapplying OT derandomization to already reordered pairs could
also make an otherwise honest retry inconsistent.

Resolution:

Every affected online exception path clears the complete protocol object before
it closes the socket and re-throws. The successful path and all expansion and
compression loops are unchanged.

Verification:

- `OtExt_Silent_AuditState_Test` preloads both malicious stationary roles,
  forces a transport failure, and requires all base and malicious-check
  correlations to be invalidated.
- `Vole_Silent_Clear_test` performs the corresponding check for both Silent
  VOLE roles.
- Release and scalar builds pass the new failure tests and the existing
  malicious and stationary success tests.

## AUD-153: LogVole receiver trusted the peer's offline output length

Status: fixed

Affected code:

- `LogVole::civoleReceiverOffline`.

Concern:

The receiver learned the output length from the sender's offline metadata. The
public wrapper knew the configured length, but it compared the result only
after the low-level protocol had constructed the CRT context and completed the
offline setup. A peer could therefore advertise a larger valid length and make
the receiver perform unintended allocation and computation before rejection.

Impact:

A malicious peer could amplify the cost of an offline request and consume
receiver memory or CPU beyond the agreed session size.

Resolution:

The low-level receiver input now includes the agreed output length. The
receiver rejects zero local lengths and mismatched peer metadata immediately
after the fixed-size metadata receive, before CRT construction or protocol
setup. The public wrapper supplies its configured request size.

Verification:

- `LogVole_Civole_RejectsPeerOfflineWidth` sends a mismatched metadata count
  without sending the remaining protocol messages. The receiver rejects it
  immediately and leaves the output state empty.
- The existing CI-VOLE validation and state-machine tests pass.

## AUD-154: Moved-from LogVole wrappers retained active session metadata

Status: fixed

Affected code:

- `LogVoleSender` and `LogVoleReceiver`.

Concern:

Implicit moves transferred the owning protocol state but copied scalar
metadata, including the wrapper state and next session identifier. A moved-from
wrapper could still report that it held offline state and attempt another
protocol call using incomplete transferred storage.

Impact:

Using both objects after a move could contact the peer with inconsistent
session state or attempt to reuse a session identifier.

Resolution:

Both wrappers are explicitly move-only. Move construction and assignment
transfer the timer, configuration, session counters, communication statistics,
and nested offline state. They then clear the source to its default inert state.
The move operations do not affect protocol kernels or online loops.

Verification:

- Compile-time checks require both wrappers to be non-copyable and movable.
- `LogVole_Civole_StateMachineAutoOfflineSequentialSids` moves populated
  offline wrappers, checks that all representative source state and owning
  pointers are clear, and completes the next online SID with the destinations.

## AUD-155: IKNP did not preserve its semi-honest mode invariant

Status: fixed

Affected code:

- `IknpOtExtSender` and `IknpOtExtReceiver` construction and move operations.

Concern:

The receiver constructor that accepted base OTs did not disable the inherited
KOS malicious check. In addition, inherited KOS moves reset the source object
to malicious mode. Reusing a moved-from IKNP object after installing new base
OTs could therefore select a different wire protocol.

Impact:

IKNP peers constructed or reused through different public paths could disagree
about whether the malicious KOS check was present. The disagreement could hang
the session or misinterpret later messages.

Resolution:

The base-OT constructors delegate through the IKNP default constructors.
Explicit IKNP moves preserve semi-honest mode in both the destination and the
cleared source. These changes do not affect extension loops.

Verification:

- `OtExt_MoveState_Test` checks both base-OT constructors, both move forms, and
  reuse of the moved-from objects.
- Release and scalar builds pass the focused move-state test.

## AUD-156: Failed malicious subspace-VOLE checks allowed empty retries

Status: fixed

Affected code:

- `SubspaceVoleMaliciousSender::sendResponse`.
- `SubspaceVoleMaliciousReceiver::checkResponse`.

Concern:

Both roles cleared their accumulated hashes before response I/O but retained
the active challenge after a transport or consistency failure. A retry then
advanced the challenge PRNG and authenticated cleared, all-zero accumulators.
The receiver also allowed the retry after clearing its VOLE seed.

Impact:

A caller could observe a failed malicious consistency check and then obtain a
successful empty check from the same objects. External outputs from the failed
batch could already have been released.

Resolution:

Failure paths clear the VOLE seed, challenge PRNG and keys, and accumulated
hashes before closing the socket and re-throwing. The final sender response now
uses an awaited reference send, so the response buffer remains live and an I/O
failure is observable by the coroutine. Hashing and VOLE generation kernels
are unchanged.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` forces a deferred receiver consistency
  failure and an injected sender I/O failure. Both roles discard the challenge
  and reject a second response operation.
- The existing malicious SoftSpoken OT test passes in Release and scalar builds.

## AUD-157: SmallField VOLE expansion relied on assertions for readiness

Status: fixed

Affected code:

- `SmallFieldVoleSender::expand` and `SmallFieldVoleReceiver::expand`.

Concern:

Expansion checked initialization, dimensions, and empty seed state only with
assertions. A Release build could dereference a null PPRF from a default object
or begin overwriting retained direct seeds before a lower layer rejected the
call.

Impact:

Invalid public call order could cause a null dereference or destroy valid seed
state before reporting failure.

Resolution:

Each expansion entry point now validates initialization, PPRF ownership and
base OTs, dimensions, and empty seed state before any mutation or network
operation. The checks run once per expansion and do not enter the generation
loops.

Verification:

- `Vole_SoftSpokenSmall_Audit_Test` requires default and directly seeded
  objects to reject expansion and verifies that rejection preserves direct
  seeds.
- Release and scalar builds pass the focused SmallField VOLE audit test.
