# LogVole Integration Plan

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
| Replace LogVole communication layer | 0% | Pending | Replace current transport with coproto `Socket`, `task<>`, and libOTe-style `PRNG&` ownership. |
| Add libOTe LogVole tests | 100% | Done | Imported original correctness tests under `libOTe_Tests/LogVole/`, compiled them into libOTe's native `TestCollection`, and kept the old test bodies through a small local compatibility shim. |
| Validate libOTe build and tests | 100% | Done | `ENABLE_LOGVOLE=ON` configure/build/native tests pass with stock SEAL; `ENABLE_LOGVOLE=OFF` configure/build also passes. |
| Harden native LogVole tests | 100% | Done | Factored native assertions and skips into `LogVole_TestUtil.h`; ported all compiled LogVole tests off the GTest shim; added join guards around threaded protocol tests; removed the unused shim and standalone GTest main. |
| Decide benchmark landing path | 0% | Pending | Start with smoke tests only; never run two benchmarks at the same time. |

## Porting Order

1. Add the CMake/config option and required SEAL lookup.
2. Copy the cleaned LogVole core into `libOTe/Vole/LogVole/` with minimal renaming.
3. Keep arithmetic local and direct: SEAL util calls, fixed-size/batched loops, no virtual ring backend.
4. Separate pure protocol state from transport.
5. Replace the old LogVole communication API with coproto integration.
6. Port correctness tests before changing algorithm structure.
7. Add focused benchmark smoke coverage after correctness is stable.

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
