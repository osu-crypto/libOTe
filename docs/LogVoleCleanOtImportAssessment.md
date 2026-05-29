# LogVole clean-ot import assessment

Date: 2026-05-29

## Source snapshot

- Upstream repo: `C:\Users\peter\repo\antilabel`
- Upstream branch: `origin/clean-ot`
- Commit: `8ff1244afefbb6caed8c1118c60c2597a45beb84`
- Imported tree: `clean-ot/`
- Imported tree hash: `91461e0a735d78d4af3eb791cf9e91fea7540ddd`
- Local destination: `thirdparty/logvole-clean-ot/`

This import is intentionally a frozen baseline. It should be used as the source of truth for the complete LogVole/CI-VOLE implementation before any libOTe-style refactor.

## Cleanup done before import

Removed the earlier `native/loglabel`-derived import from `libOTe/Vole/LogVole/include/loglabel`, `libOTe/Vole/LogVole/src`, and its old comm/keyderive/shrinkexpand tests and benchmarks.

The newer `osuCrypto::LogVole` files currently remain in `libOTe/Vole/LogVole/` as a checkpointed scaffold. They are not treated as canonical relative to `clean-ot`.

## Baseline build check

Configured the frozen baseline with:

```text
cmake -S thirdparty/logvole-clean-ot -B out/build/logvole-clean-ot -G Ninja
  -DSEAL_DIR=C:\Users\peter\repo\SEAL-stock-4.1.1-install\lib\cmake\SEAL-4.1
  -DLOGVOLE_BUILD_BENCH=OFF
  -DLOGVOLE_BUILD_TESTS=ON
  -DLOGVOLE_BUILD_EXAMPLES=ON
  -DLOGVOLE_GTEST_SOURCE_DIR=C:\Users\peter\repo\antilabel\thirdparty\googletest-src
  -DCMAKE_BUILD_TYPE=Release
```

Configure succeeded and found stock Microsoft SEAL 4.1.1.

Build with MSVC failed before tests could run. Main blockers:

- `unsigned __int128` is used throughout `clean-ot`, but MSVC does not support it.
- `std::uniform_int_distribution<uint8_t>` is rejected by MSVC's standard library.
- `boost/multiprecision/cpp_int.hpp` is included by `ring_ops.cpp`, but Boost headers were not on the standalone include path.

These are portability/build-system issues in the frozen artifact, not protocol-integration changes.

## Immediate recommendation

Keep this import frozen. Next, either:

1. Build the frozen baseline with a compiler/environment closer to Lucian's original target, likely GCC/Clang with Boost headers, to establish a passing reference, or
2. Add a small Windows portability patch on top of the frozen baseline before using it as the local executable reference.

Do not start the coproto/libOTe refactor until one of those two reference paths passes.

## WSL reference build

The frozen baseline does build and test successfully in WSL with GCC after installing Boost headers and building stock SEAL locally for Linux.

Additional WSL dependency:

```text
sudo apt-get install -y libboost-dev
```

Local WSL SEAL configure/install:

```text
cmake -S /mnt/c/Users/peter/repo/SEAL-stock-4.1.1 \
  -B out/wsl-build/seal-4.1.1 \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/mnt/c/Users/peter/.codex/worktrees/9b1a/libOTe/out/wsl-install/seal-4.1.1 \
  -DSEAL_BUILD_DEPS=ON \
  -DSEAL_BUILD_EXAMPLES=OFF \
  -DSEAL_BUILD_TESTS=OFF \
  -DSEAL_BUILD_BENCH=OFF

cmake --build out/wsl-build/seal-4.1.1 --target install --config Release
```

Frozen clean-ot configure/build/test:

```text
cmake -S thirdparty/logvole-clean-ot \
  -B out/wsl-build/logvole-clean-ot \
  -G Ninja \
  -DSEAL_DIR=/mnt/c/Users/peter/.codex/worktrees/9b1a/libOTe/out/wsl-install/seal-4.1.1/lib/cmake/SEAL-4.1 \
  -DLOGVOLE_BUILD_BENCH=OFF \
  -DLOGVOLE_BUILD_TESTS=ON \
  -DLOGVOLE_BUILD_EXAMPLES=ON \
  -DLOGVOLE_GTEST_SOURCE_DIR=/mnt/c/Users/peter/repo/antilabel/thirdparty/googletest-src \
  -DCMAKE_BUILD_TYPE=Release

cmake --build out/wsl-build/logvole-clean-ot --target logvole_correctness_tests civole_example civole_socket_example --config Release -- -j4

ctest --test-dir out/wsl-build/logvole-clean-ot --output-on-failure -R LogVOLECorrectnessTests
```

Result:

```text
100% tests passed, 0 tests failed out of 1
LogVOLECorrectnessTests Passed in 2.43 sec
```

This gives us a passing frozen reference. The remaining Windows failures should be treated as portability work, not protocol-correctness blockers.
