# LogVole Integration Plan

## Current status note

This document records the earlier integration path and the first fresh-port checkpoint. After auditing `origin/clean-ot`, the current source of truth for the port decision and remaining work is `docs/LogVoleCleanOtAudit.md`.

The important change is that the existing libOTe LogVole scaffold is no longer considered the final implementation path. It should be treated as partial/stale scaffold code while the complete clean-ot protocol is ported into libOTe.

## Goal

Port the LWE-based VOLE protocol from `C:\Users\peter\repo\antilabel\native\loglabel` into libOTe as **LogVole**.

The current implementation still uses the older LogLabel name. In this plan, LogLabel means the existing code and LogVole means the final libOTe feature.

## Dependency Story

`ENABLE_LOGVOLE` should commit to stock Microsoft SEAL. If LogVole is enabled and SEAL is not available, configure should fail clearly.

Planned shape:

- Add `ENABLE_LOGVOLE` beside the other VOLE options in `cmake/buildOptions.cmake`.
- Add `#cmakedefine ENABLE_LOGVOLE` in `libOTe/config.h.in`.
- Resolve stock SEAL in `cmake/libOTeDepHelper.cmake` with `find_package(SEAL 4.1.1 REQUIRED)` when `ENABLE_LOGVOLE=ON`.
- Link `libOTe` to `SEAL::seal` only when `ENABLE_LOGVOLE=ON`.
- Do not abstract SEAL behind a broad backend.
- Do not port TinyLabels or depend on patched SEAL behavior.
- Keep LogVole plaintext modulus, denoise, CRT-style recomposition, and protocol-specific rounding logic in LogVole code.

The lean SEAL build validated during cleanup used:

```powershell
cmake -S C:\Users\peter\repo\SEAL-stock-4.1.1 `
  -B C:\Users\peter\repo\SEAL-stock-4.1.1\build_stock `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_INSTALL_PREFIX=C:\Users\peter\repo\SEAL-stock-4.1.1-install `
  -DSEAL_BUILD_DEPS=ON `
  -DSEAL_BUILD_EXAMPLES=OFF `
  -DSEAL_BUILD_TESTS=OFF `
  -DSEAL_BUILD_BENCH=OFF `
  -DSEAL_BUILD_SEAL_C=OFF `
  -DSEAL_USE_MSGSL=OFF `
  -DSEAL_USE_ZLIB=OFF `
  -DSEAL_USE_ZSTD=OFF `
  -DSEAL_USE_INTEL_HEXL=OFF
```

## Progress

| Task | % Done | Status | Notes |
| --- | ---: | --- | --- |
| Create libOTe integration branch | 100% | Done | Branch: `codex/logvole-integration-plan`. |
| Audit SEAL patch dependency | 100% | Done | TinyLabels needs patched SEAL; LogVole does not need the patch after portable modular arithmetic cleanup. |
| Isolate LogVole from TinyLabels in `antilabel` | 100% | Done | `native/loglabel` has no TinyLabels references and builds standalone against stock SEAL. |
| Commit stock-SEAL cleanup in `antilabel` | 100% | Done | Commit `d5664ff1` on `codex/logvole-stock-seal`: `logvole: build against stock seal`. |
| Add libOTe integration plan | 100% | Done | This document tracks dependency and porting work. |
| Add libOTe build option and SEAL dependency hook | 100% | Done | Added `ENABLE_LOGVOLE`, config export, and required `SEAL::seal` lookup/link when enabled; default configure, LogVole configure, and enabled `libOTe` build pass. |
| Port LogVole arithmetic/protocol modules | 100% | Done | Imported cleaned LogVole headers and sources under `libOTe/Vole/LogVole/`, preserving the old `loglabel` include/namespace shape for now. |
| Freeze imported LogVole reference | 100% | Done | Current stock-SEAL import and native tests are the known-good reference. New libOTe-facing code should copy behavior, not preserve the old callback/transport architecture. |
| Rewrite LogVole libOTe integration shell | 84% | In progress | Added fresh lower-layer files under `osuCrypto::LogVole`; implemented standalone message encoding/decoding, fresh SEAL-backed ring/RNS ops, fresh LENC/LHE enc/digest/eval ops, fresh key-derive core request/response math, fresh shrink/expand deterministic/full-noise/denoise core math, root wrapper setup/digest/response helpers, and sender/receiver coproto entrypoints for key-derive and shrink/expand with no aliases or includes into the frozen `loglabel` reference. |
| Add libOTe LogVole tests | 100% | Done | Imported original correctness tests under `libOTe_Tests/LogVole/`, compiled them into libOTe's native `TestCollection`, and kept the old test bodies through a small local compatibility shim. |
| Validate libOTe build and tests | 100% | Done | `ENABLE_LOGVOLE=ON` configure/build/native tests pass with stock SEAL; `ENABLE_LOGVOLE=OFF` configure/build also passes. |
| Harden native LogVole tests | 100% | Done | Factored native assertions and skips into `LogVole_TestUtil.h`; ported all compiled LogVole tests off the GTest shim; added join guards around threaded protocol tests; removed the unused shim and standalone GTest main. |
| Add coproto protocol entrypoints | 55% | In progress | Added fresh `Sender`/`Receiver` coroutine wrappers over `coproto::Socket&` for key-derive, shrink/expand offline setup, and deterministic shrink/expand online expansion. Root and recursive LogVole exchanges are still local-only and need coproto wiring after algebraic parity lands. |
| Decide benchmark landing path | 0% | Pending | Start with smoke tests only; never run two benchmarks at the same time. |

## Rewrite Target

The imported LogLabel-shaped code is frozen as a reference implementation. The libOTe landing code should use a compact LogVole layout:

```text
libOTe/Vole/LogVole/
  LogVoleSender.h
  LogVoleSender.cpp
  LogVoleReceiver.h
  LogVoleReceiver.cpp
  LogVoleEncoding.h
  LogVoleEncoding.cpp
  LogVoleRing.h
  LogVoleRing.cpp
  LogVoleLenc.h
  LogVoleLenc.cpp
```

Top-level protocol code is split by role. Lower layers stay compact:

- Fresh code lives in `namespace osuCrypto::LogVole`; names inside the namespace should not repeat `LogVole`.
- `LogVoleSender.*`: sender-facing inputs, outputs, and straight-line coroutine entrypoints.
- `LogVoleReceiver.*`: receiver-facing inputs, outputs, and straight-line coroutine entrypoints.
- `LogVoleEncoding.*`: typed message structs and encode/decode helpers. Malformed payload tests target this directly.
- `LogVoleRing.*`: concrete SEAL/RNS polynomial machinery and hot arithmetic.
- `LogVoleLenc.*`: LENC, key-derivation, and shrink/expand arithmetic above raw ring ops.

Do not recreate the imported `protocol/backend/spec/type` split. Do not adapt the callback `protocol_engine` to coproto. New rewrite files should use `namespace osuCrypto` directly and must not include or alias the frozen `loglabel` implementation. Delete or stop compiling the old `comm/` stack, `round_dsl.hpp`, `protocol_engine.hpp`, and `*_spec.hpp` when the coroutine cutover lands.

## Rewrite Order

1. Commit this freeze/rewrite plan.
2. Add the new lower-layer files (`LogVoleEncoding.*`, `LogVoleRing.*`, `LogVoleLenc.*`) while the old reference still compiles.
3. Move/copy behavior into the new lower-layer files and point arithmetic/encoding tests at them.
4. Add `LogVoleSender.*` and `LogVoleReceiver.*` coroutine entrypoints using `coproto::Socket&`.
5. In one networking cutover commit, rewrite keyderive/shrinkexpand protocol tests to coproto sockets and delete the old imported comm/callback stack.
6. Keep algebraic correctness tests continuous. Let old comm-only tests die with the old networking layer unless the new API has an equivalent behavior.
7. Add benchmark smoke coverage only after the coroutine integration is stable. Never run two benchmarks at the same time.

## Rewrite Validation Story

- Every rewrite commit: configure/build with `ENABLE_LOGVOLE=ON` and run `LogVoleNativeTests`.
- Lower-layer rewrite commit: ring, lenc, encoding/malformed-decode tests plus full old native tests as regression.
- Networking cutover commit: full native LogVole tests over coproto local sockets, plus direct malformed decode tests.
- Before broader review: also validate `ENABLE_LOGVOLE=OFF` configure/build.

## Current Validation From `antilabel`

Configured LogVole against stock SEAL:

```powershell
cmake -S native\loglabel -B build_logvole_stock_tests `
  -DCMAKE_PREFIX_PATH=C:\Users\peter\repo\SEAL-stock-4.1.1-install `
  -DSEAL_BUILD_TESTS=ON `
  -DSEAL_BUILD_BENCH=OFF `
  -DSEAL_BUILD_LOGLABEL_BENCH=ON `
  -DSEAL_BUILD_DEPS=ON
```

Correctness tests:

```powershell
ctest --test-dir build_logvole_stock_tests -C Release `
  -R "Loglabel(Comm|Keyderive|ShrinkExpand|Lenc)Tests" `
  --output-on-failure
```

Result: 4/4 passed.

Bench smoke tests:

```powershell
ctest --test-dir build_logvole_stock_tests -C Release `
  -R "Loglabel.*BenchSmoke" `
  -j 1 `
  --output-on-failure
```

Result: 4/4 passed.

## Landing Principles

- `ENABLE_LOGVOLE=ON` means stock SEAL is a hard dependency.
- Avoid broad SEAL abstraction and keep churn low.
- Do not import TinyLabels.
- Preserve the optimized reference structure in hot arithmetic code unless there is a concrete libOTe integration reason to change it.
- Prefer mechanical communication and build-system refactors before algorithm changes.
