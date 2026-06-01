# LogVole clean-ot audit and port accounting

Date: 2026-05-29

## Audit source

Reference implementation:

- Repo: `C:\Users\peter\repo\antilabel`
- Branch: `origin/clean-ot`
- Commit: `8ff1244afefbb6caed8c1118c60c2597a45beb84`
- Imported frozen copy: `thirdparty/logvole-clean-ot/`

The frozen reference builds and passes its correctness suite in WSL against stock Microsoft SEAL 4.1.1. The expanded reference tests also pass, including direct recursive LogVOLE tests, CI-VOLE API tests, multithreaded execution, sender precompute, cached-root reuse, internal setup reuse, full-noise recursive gadget input, the width rejection test, the disabled five-level stress test when run explicitly, and both examples.

## Executive decision

We should rewrite the libOTe LogVole implementation from the clean-ot reference instead of trying to refactor the current libOTe scaffold into the full protocol.

This is not a style preference. The current libOTe implementation is an older, partial shrink/expand plus key-derive prototype. The clean-ot branch is the complete SH/LogVole implementation and its state machine has moved materially:

- key-derive is gone from the real protocol path;
- recursive LogVOLE is present;
- root randomized digest/derandomization is present;
- golden seed search/evaluation is present;
- sender precompute and cached-root reuse are present;
- CI-VOLE over `Zp` is present;
- shrink/expand gained digest trees, public `A/B` NTT caches, sampling seed domains, truncation flags, gadget-leaf handling, and worker control;
- the message set is different;
- the comm layer is callback/spec based and should be replaced by coproto, not mechanically wrapped.

Trying to mutate the current scaffold would preserve too many stale names and assumptions while still requiring almost all of clean-ot to be ported. The safer landing path is an in-place rewrite of `libOTe/Vole/LogVole` using clean-ot as the oracle, with libOTe naming, `osuCrypto::LogVole`, stock SEAL, and coproto.

## What clean-ot contains

### Ring and low-level arithmetic

Files:

- `include/logvole/ring_types.hpp`
- `include/logvole/ring_ops.hpp`
- `src/protocol/ring_ops.cpp`
- `src/protocol/parallel_utils.hpp`
- `src/protocol/runtime_cache_scope.hpp`
- `src/protocol/simd_hints.hpp`

Responsibilities:

- RNS polynomial and tensor types.
- SEAL-backed NTT context construction.
- In-place and out-of-place add/sub/mul/scalar arithmetic.
- Gadget decomposition, including bit-range and centered decomposition variants.
- Tensor pack/unpack helpers.
- Deterministic uniform and Gaussian sampling from seed material.
- Batch nonce derivation and batch polynomial sampling.
- Worker scheduling for memory-bandwidth-heavy polynomial operations.
- Cache scoping for public polynomial caches.

Porting notes:

- This is hot code. Preserve the data-oriented structure and batching behavior.
- `unsigned __int128` appears in the reference and blocks MSVC. The libOTe port needs a small portable 128-bit arithmetic helper or equivalent use of existing cryptoTools/SEAL helpers.
- `boost::multiprecision::cpp_int` is used in the reference for wide arithmetic paths. We should avoid making Boost a public libOTe dependency unless a focused audit proves it is unavoidable.
- `std::uniform_int_distribution<uint8_t>` is not portable on MSVC and should be sampled as a wider integer then cast.

### LENC/LHE/shrink-expand core

Files:

- `src/protocol/lenc_ops.hpp`
- `src/protocol/lenc_ops.cpp`
- `src/protocol/lhe_ops.hpp`
- `src/protocol/lhe_ops.cpp`
- `include/logvole/shrinkexpand_types.hpp`
- `include/logvole/shrinkexpand_noise.hpp`
- `include/logvole/shrinkexpand_backend.hpp`
- `src/protocol/shrinkexpand_backend_seal.cpp`
- `src/protocol/shrinkexpand_shared_ops.hpp`
- `src/protocol/shrinkexpand_shared_ops.cpp`
- `include/logvole/shrinkexpand_protocol.hpp`
- `src/protocol/shrinkexpand_protocol.cpp`
- `include/logvole/shrinkexpand_spec.hpp`

Responsibilities:

- LENC encode/digest/eval.
- Digest tree construction and reuse.
- LHE operations and SEAL-specific plaintext/noise handling.
- Shrink/expand offline and online math.
- Deterministic and full-noise modes.
- Public `A/B` NTT cache generation and reuse.
- `truncate_one_gadget_digit` and `leaf_inputs_are_gadget` behavior.
- `sampling_seed_config` with separate noise and `ct2` root domains.

Porting notes:

- The clean-ot backend has a virtual interface, but libOTe should use a concrete stock-SEAL implementation internally. There is no need to abstract all of SEAL.
- The current libOTe `ShrinkExpandParams` is missing important fields from clean-ot. This is a fundamental type mismatch, not a minor extension.
- The current libOTe shrink/expand code does not carry digest trees or public cache pointers, so recursive online behavior cannot be bolted onto it cleanly.

### Recursive LogVole

Files:

- `include/logvole/logvole_types.hpp`
- `include/logvole/logvole_protocol.hpp`
- `include/logvole/logvole_spec.hpp`
- `include/logvole/logvole_backend.hpp`
- `include/logvole/logvole_shared_ops.hpp`
- `src/protocol/logvole_protocol.cpp`
- `src/protocol/logvole_shared_ops.cpp`
- `include/logvole/seedlabel_types.hpp`
- `include/logvole/seedlabel_backend.hpp`
- `include/logvole/seedlabel_shared_ops.hpp`
- `src/protocol/seedlabel_backend_seal.cpp`
- `src/protocol/seedlabel_shared_ops.cpp`

Responsibilities:

- Full recursive LogVOLE offline and online phases.
- Recursive state chaining through `next_level_state`.
- Root wrapper setup and root randomized digest handling.
- Golden seed search, caching, transmission, and evaluation.
- Sender precompute of `tbk`.
- Receiver derandomization of root digest response.
- Seed-label backend operations used by the recursive protocol.

Porting notes:

- This is the largest missing piece in the current libOTe code.
- The current libOTe sender/receiver only run local key-derive and shrink/expand wrappers. They do not implement the recursive state machine.
- This layer should be split by top-level role in libOTe: `LogVoleSender.*` and `LogVoleReceiver.*`.
- Helper functions shared by both roles can live in one compact lower-level pair rather than recreating clean-ot's `protocol/backend/spec/type` spread.

### CI-VOLE wrapper

Files:

- `include/logvole/civole_protocol.hpp`
- `include/logvole/zp_crt_helpers.hpp`
- `src/protocol/civole_protocol.cpp`
- `src/protocol/zp_crt_helpers.cpp`

Responsibilities:

- Public API over `Zp`.
- Default parameter construction.
- CRT wrapping/unwrapping between `Zp` vectors and ring labels/MACs.
- SID single-use enforcement.
- Per-SID sampling seed derivation.
- Sender `releasek_int` / `release_int`.
- Receiver `setx_int`.

Porting notes:

- This is likely the most useful libOTe-facing API, but it depends on the recursive LogVole stack being correct first.
- The SID bookkeeping is part of the security/usage contract and should be preserved.
- `Zp` CRT helpers contain batch work and should be ported with their worker-aware structure.

### Communication layer

Files:

- `include/logvole/comm/*`
- `src/comm/*`
- `*_spec.hpp` message traits in protocol headers

Responsibilities:

- Blocking/callback protocol engine.
- In-memory and socket transports.
- Subchannel wrappers.
- Encoding/decoding traits.
- Counters and result/error wrappers.

Porting notes:

- Do not import this into the new libOTe implementation.
- Replace each protocol exchange directly with coproto sends/receives.
- Do the communication cutover as one coherent change. A half callback, half coroutine LogVole stack will be hard to reason about and hard to review.
- Keep message structs and byte encoders, but write them in libOTe style.

## What the current libOTe implementation contains

Files:

- `libOTe/Vole/LogVole/LogVoleRing.{h,cpp}`
- `libOTe/Vole/LogVole/LogVoleLenc.{h,cpp}`
- `libOTe/Vole/LogVole/LogVoleEncoding.{h,cpp}`
- `libOTe/Vole/LogVole/LogVoleSender.{h,cpp}`
- `libOTe/Vole/LogVole/LogVoleReceiver.{h,cpp}`
- `libOTe_Tests/LogVole/tests/*`

Current capabilities:

- Basic SEAL/RNS polynomial and tensor machinery.
- Basic NTT, add/sub/mul/scalar, gadget decomposition, pack/unpack, deterministic polynomial derivation, and small noise helpers.
- Local LENC encode/digest/eval.
- Stale key-derive request/response math and coproto wrappers.
- Partial shrink/expand offline and online math.
- Simple message encoding for key-derive, shrink/expand offline, and polynomial messages.
- Unit tests for the above scaffold.

Current gaps relative to clean-ot:

- No recursive LogVole protocol.
- CI-VOLE public API, CRT wrapping/unwrapping, SID state, and default params are present in the fresh LogVole2 port.
- Root helper math, golden-seed search, root offline setup, and local root online digest/response flow are present.
- Top-level root local relation is covered with clean-ot-style small plaintext inputs, golden-root seed selection, and CRT-centered noise tolerance.
- Top-level root local sender/receiver API helpers are present and relation-tested.
- No coproto root randomized digest exchange is wired yet.
- Full recursive VOLE relation tests are not ported yet.
- No sender precompute path.
- No cached-root reuse path.
- Seed-label helpers are partial; the recursive seed-label protocol path is not wired yet.
- LHE/LENC/shrink-expand helper layers are substantially ported, but still need recursive wrapper integration.
- Runtime cache scoping/per-role cache behavior is not at clean-ot parity yet.
- Root/seed message encoding is present; coproto root protocol wiring is not.
- Contains stale key-derive API and tests that should not drive the final design.

## Required libOTe changes

| Area | Existing status | Needed change | % done |
| --- | --- | --- | ---: |
| Frozen clean-ot oracle | Imported and passing in WSL | Keep as reference while porting; do not compile into final libOTe | 100% |
| Build option/dependency | `ENABLE_LOGVOLE` and stock `SEAL::seal` hook exist | Keep SEAL mandatory when LogVole is enabled; add Windows portability fixes as port code lands | 80% |
| Current scaffold cleanup | Still compiled as LogVole | Quarantine or replace stale key-derive/shrink-only scaffold; do not extend it as final protocol | 20% |
| Ring ops | Partial libOTe implementation exists | Replace with clean-ot superset while preserving hot-path batching and memory layout | 60% |
| Portable 128-bit math | Current code avoids some clean-ot portability failures | Add focused helper for `__int128` use on MSVC/GCC/Clang | 25% |
| Boost/cpp_int dependency | Clean-ot uses Boost in ring ops | Audit exact need and either remove/replace or make it private and justified | 0% |
| LENC/LHE | LENC and LHE helpers are substantially ported | Finish parity around recursive gadget-leaf use and cache behavior | 70% |
| Shrink/expand | Deterministic/full-noise shrink-expand and truncation tests pass | Add recursive gadget-leaf relation coverage through the LogVole parent path | 70% |
| Seed-label backend | Missing | Port concrete SEAL seed-label operations without virtual abstraction in hot path | 45% |
| Recursive LogVole | Root wrapper setup, digest/response, derandomization, top-level local API, golden seed, root precompute/cache reuse, repeated local online, internal setup reuse, recursive gadget subproblem coverage, clean-ot-profile two-/three-level local recursion, and recursive coproto offline/online are present | Audit clean-ot reuse/counter semantics exactly and remove staging-only API once parity is confirmed | 82% |
| CI-VOLE API | Default params, `Zp` CRT wrapper, SID state, releasek/release/setx flows, and clean-ot public API tests are ported over coproto | Add any missing example/benchmark smoke surfaces only after final API naming settles | 80% |
| Serialization | Stale message set exists | Replace with clean-ot message set in libOTe byte encoding style | 40% |
| Networking | Coproto wrappers exist for key-derive, shrink/expand, recursive LogVole offline/online, and CI-VOLE public API flows | Continue direct coproto translation for any remaining clean-ot-facing API; do not port clean-ot comm layer | 82% |
| Tests | LogVole2 has 76 expected tests after this checkpoint, including clean-ot-profile recursive coverage, recursive coproto relation coverage, and the six clean-ot CI-VOLE public API tests | Port any remaining clean-ot communication/reuse accounting tests without changing their parameter profiles | 87% |
| Benchmarks | Not started | Add only after correctness and coproto integration are stable; run serially | 0% |

## Recommended file layout

Keep the top-level protocol split by role and keep lower layers compact:

```text
libOTe/Vole/LogVole/
  LogVoleTypes.h
  LogVoleRing.h
  LogVoleRing.cpp
  LogVoleLenc.h
  LogVoleLenc.cpp
  LogVoleCore.h
  LogVoleCore.cpp
  LogVoleEncoding.h
  LogVoleEncoding.cpp
  LogVoleSender.h
  LogVoleSender.cpp
  LogVoleReceiver.h
  LogVoleReceiver.cpp
  LogVoleCivole.h
  LogVoleCivole.cpp
```

`LogVoleCore` is the escape hatch for shared seed-label, root wrapper, LHE, and recursive helpers. If it becomes too large, split by actual pressure after the port is compiling and tested, not preemptively into clean-ot's `protocol/backend/spec/type` layout.

Use `namespace osuCrypto::LogVole`. Inside that namespace, avoid repeating `LogVole` in every type name unless the type crosses a broad public boundary.

## Rewrite strategy

1. Keep `thirdparty/logvole-clean-ot` frozen as the executable oracle.
2. Stop treating the current libOTe key-derive tests as final protocol requirements.
3. Port clean-ot data types into `LogVoleTypes.h`, merging with existing names only where the semantics match exactly.
4. Port ring ops and portability helpers first. Validate with ring and decomposition tests.
5. Port LENC/LHE and shrink/expand math next. Validate deterministic and full-noise shrink/expand tests against clean-ot behavior.
6. Finish seed-label/root wrapper parity for the internal recursive path, especially gadget-leaf inputs.
7. Implement recursive sender/receiver offline and online locally first, then wire the same flow with coproto.
8. Port clean-ot recursive tests into `libOTe_Tests`, starting with one-level root, then two-level recursion, then cached/precompute cases.
9. Port CI-VOLE wrapper and public API tests.
10. Remove stale key-derive API/tests and any leftover scaffold-only behavior.
11. Only then add benchmark smoke coverage, with serial execution.

## Refactor-vs-rewrite conclusion

Do not refactor the current libOTe scaffold into the final implementation.

The recommended path is a controlled rewrite of the LogVole directory, using the existing scaffold only for small pieces that match clean-ot exactly. In practice that means some mechanical reuse in ring encoding or basic polynomial operations may survive, but the protocol structure should come from clean-ot. This keeps us accurate to the passing branch Lucian prepared while still landing in libOTe's architecture: stock SEAL, no TinyLabels, no clean-ot networking stack, no broad SEAL abstraction, and coproto-native sender/receiver code.

## Current parity rule

Clean-ot is the oracle. Porting should preserve its parameter profiles, tests, state machine, and send/receive ordering. Callback protocol steps should translate mechanically to coroutine `send`/`recv` awaits; they are not permission to adjust VOLE math or parameter choices. Any extra parameter experiments belong after clean-ot parity and must be clearly separated from porting work.

## Next concrete work

The next coding step should be an exact clean-ot audit of reuse/counter behavior around `golden_seed_transmitted`, sender precompute, repeated online calls, and example/benchmark smoke expectations. After that, remove or rename staging-only `LogVole2` surfaces once final parity is confirmed.
