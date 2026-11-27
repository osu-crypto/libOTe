# LogVole GPU validation

Run the checks in order on each host. An RTX 4090 validates SM89 runtime. An H200 validates SM90 runtime and can exercise H200-specific dispatch. An SM90 object build records compilation coverage. The [optimization guide](GPU_OPTIMIZATION_GUIDE.md) describes the dispatch conditions and arithmetic contracts.

## Build two revisions

Use `b80413b5` for the full comparison against the original LogVole PR. Use `ff8a006a` when measuring the GPU pruning series alone. Record the full baseline and candidate commit IDs. Use separate worktrees and build directories. The candidate checkout contains the current tests and A/B runner.

The local handoff includes `libOTe.bundle` and `cryptoTools.bundle`. The first contains the candidate branch and baseline history. The second supplies the cryptoTools revisions pinned by those checkouts. Use absolute paths to the received files.

```sh
git clone --branch codex/pr195-cuda-stress /path/to/libOTe.bundle libOTe-gpu-candidate
cd libOTe-gpu-candidate
git worktree add --detach ../libOTe-gpu-baseline b80413b5
CRYPTO_BUNDLE=/path/to/cryptoTools.bundle
git -c protocol.file.allow=always -c "submodule.cryptoTools.url=$CRYPTO_BUNDLE" submodule update --init --recursive
git -C ../libOTe-gpu-baseline -c protocol.file.allow=always -c "submodule.cryptoTools.url=$CRYPTO_BUNDLE" submodule update --init --recursive
git rev-parse HEAD
git -C ../libOTe-gpu-baseline rev-parse HEAD
```

For a candidate checkout with access to the pinned submodule revision through its configured repository, initialize both worktrees directly.

```sh
git worktree add --detach ../libOTe-gpu-baseline b80413b5
git -C ../libOTe-gpu-baseline submodule update --init --recursive
git submodule update --init --recursive
git rev-parse HEAD
git -C ../libOTe-gpu-baseline rev-parse HEAD
```

On Windows, apply the [original baseline compatibility patch](../../../libOTe_Tests/LogVole/original_b80413b5_windows_compat.patch) to the `b80413b5` worktree and add `-Xcompiler=/Zc:preprocessor` to its CUDA flags before building. On Linux, use the original source unchanged. Match the host compiler, CUDA toolkit, generator, target architecture, and build configuration between worktrees. Honor each checkout's cryptoTools submodule pin. Pin other dependencies before configuring because automatic fetch can update them. Keep writable dependency clones and installation prefixes separate for the two worktrees. A shared installed package can supply read-only inputs through an explicit find hint such as `SEAL_DIR`.

| Dependency | Revision used for the comparison |
| --- | --- |
| cryptoTools | Original `b80413b5` pins `cc54d946a7643795b5f523fe235392de8271a5b3`. The candidate and pruning reference `ff8a006a` pin `3e69c5b9ac0f0c43d0fd1c9e1b886a3ea8df8979`. |
| coproto | `ded64cbc51c041ee534e5c34a5a81135af455ce7` |
| macoro | `feea851f3bda2bdc80993252144fd38a46acca85` |
| function2 | `02ca99831de59c7c3a4b834789260253cace0ced`, pinned by coproto |
| SEAL | `206648d0e4634e5c61dcf9370676630268290b59` (4.1.1), pinned by libOTe |

Pass the macoro revision explicitly. It supplies the coroutine APIs used by this source. The commit is available on the upstream branch `codex/macoro-scope-lifetime`. If using a prepopulated dependency cache, fetch that branch into each clone before configuring and verify the pinned commit is available. [macoro commit](https://github.com/ladnir/macoro/commit/feea851f3bda2bdc80993252144fd38a46acca85)

The local validation configuration uses Release, Ninja, `FETCH_AUTO=ON`, and `ENABLE_BOOST=OFF`. Windows uses an x64 developer shell for the selected MSVC. Linux uses the compiler selected for NVCC. Set `CMAKE_CUDA_COMPILER` and `CMAKE_CUDA_HOST_COMPILER` at initial configure if the intended versions need explicit paths. Select architecture 89 for an RTX 4090 or 4060 and 90 for an H200.

From the candidate worktree, record the absolute path to its CMake launcher include. Pass that same path when configuring both worktrees. The target compiles the unmodified `frontend/ExampleLogVole.cpp` in each revision and links it to that revision's library.

```sh
BENCH_INCLUDE="$(pwd)/libOTe_Tests/LogVole/gpu_bench_target.cmake"
```

For PowerShell, use `$BENCH_INCLUDE = (Resolve-Path libOTe_Tests/LogVole/gpu_bench_target.cmake).Path` while still in the candidate worktree.

Run the following from each worktree with `BENCH_INCLUDE` set. The example selects architecture 89.

```sh
DEPS="$(pwd)/out/install/gpu-validation"
BUILD="$(pwd)/out/build/gpu-validation"
cmake -S . -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release "-DLIBOTE_BUILD_DIR=$BUILD" \
  -DFETCH_AUTO=ON -DENABLE_BOOST=OFF -DENABLE_LOGVOLE=ON -DENABLE_LOGVOLE_CUDA=ON \
  -DOC_ENABLE_AVX512_IFMA=OFF \
  -DCOPROTO_GIT_TAG=ded64cbc51c041ee534e5c34a5a81135af455ce7 \
  -DMACORO_GIT_TAG=feea851f3bda2bdc80993252144fd38a46acca85 \
  -DCMAKE_CUDA_ARCHITECTURES=89 "-DCMAKE_PROJECT_INCLUDE=$BENCH_INCLUDE" \
  "-DCMAKE_INSTALL_PREFIX=$DEPS" "-DOC_THIRDPARTY_INSTALL_PREFIX=$DEPS" \
  "-DOC_THIRDPARTY_HINT=$DEPS" "-DOC_THIRDPARTY_CLONE_DIR=$(pwd)/out"
cmake --build "$BUILD" --target logvole_gpu_bench logvole_cuda_tests logvole_cuda_lifetime_tests --parallel 2
```

Match actual CPU IFMA eligibility between builds. In the local tests, the original MSVC path had no IFMA dispatch and the WSL CPU lacked IFMA. On a capable GNU host where the original auto-dispatches to IFMA, enable the candidate's `OC_ENABLE_AVX512_IFMA` to match, or record the mismatch explicitly.

Record the resolved dependency revisions from each worktree. For local checkouts, use `git -C <dependency checkout> rev-parse HEAD` for `cryptoTools`, `out/coproto`, `out/macoro`, and `out/function2`. Record the version and provenance of SEAL and any preinstalled dependencies. Confirm the manifests match apart from the expected per-revision cryptoTools pins before timing.

On machines with limited host memory, reduce build parallelism. Finish compilation before launching GPU validation or profiling. Retain the dependency manifest, build log, and `CMakeCache.txt` from each worktree.

## Runtime correctness and leaks

From the candidate worktree, set `TEST` to `out/build/gpu-validation/libOTe_Tests/logvole_cuda_tests`. In PowerShell, set `$TEST = (Resolve-Path out/build/gpu-validation/libOTe_Tests/logvole_cuda_tests.exe).Path` and invoke it with `& $TEST`. Run the shared tests on the baseline when the tests exist there. The candidate adds direct tests introduced during pruning.

```sh
TEST=out/build/gpu-validation/libOTe_Tests/logvole_cuda_tests
python libOTe_Tests/LogVole/run_cuda_checks.py "$TEST" --kernel-parity --suite-timeout 300 --job-timeout 90 --log-dir out/gpu-validation/functional
python libOTe_Tests/LogVole/run_cuda_leak_checks.py "$TEST" --sanitizer compute-sanitizer --suite-timeout 300 --job-timeout 90 --log-dir out/gpu-validation/leaks
```

Pass the installed Compute Sanitizer path to `--sanitizer` if it is outside `PATH`. The leak runner uses the sibling `logvole_cuda_lifetime_tests` by default. Run the functional and leak suites separately. The release commands allow up to 300 seconds per suite and 90 seconds per child. A timeout or skip fails the gate. The leak suite additionally requires zero reported leaks and sanitizer errors. Save the complete logs and JSON summaries.

Use the test selector to reproduce a failure from the functional log. For example, these commands isolate the two sampling oracles, the outer product oracle, and the H200-focused arithmetic oracles.

```sh
"$TEST" -u LogVole_RingOps_GpuCt2SeedAesParity LogVole_RingOps_RootZetaParity -gpu 1 -lvFactoryFast 1
"$TEST" -u LogVole_RingOps_PointwiseOuterParity -gpu 1 -lvFactoryFast 1
"$TEST" -u LogVole_RingOps_NttTwoTileInPlaceParity LogVole_RingOps_AccumulatorParity LogVole_RingOps_GadgetParity -gpu 1 -lvFactoryFast 1
```

On H200, collect a separate CUDA trace of the H200 parity tests and a NoGoldenSeed protocol run. Inspect the actual launched kernel names. Include the forward and inverse FP52 routes, integer routes, and H200 accumulators where the case admits them. Record the workload, ring geometry, and packed-root availability when interpreting dispatch. On the RTX 4090, record the generic or log13 route used for each case.

## Serial A/B

Point the [runner](../../../libOTe_Tests/LogVole/run_gpu_ab.py) at the two frontends. Both use the same CUDA device and request settings. When several GPUs are visible, select the same device for both programs and record its UUID. Choose a new log directory per comparison and use the same lock path for every invocation on the host.

The [runner self-tests](../../../libOTe_Tests/LogVole/test_gpu_ab_runner.py) require no GPU. Run them with `python libOTe_Tests/LogVole/test_gpu_ab_runner.py -v`.

```sh
BASE=../libOTe-gpu-baseline
CANDIDATE_BIN=out/build/gpu-validation/logvole_gpu_bench
BASELINE_BIN="$BASE/out/build/gpu-validation/logvole_gpu_bench"
# On Windows set the corresponding .exe paths using the syntax of your shell.
python libOTe_Tests/LogVole/run_gpu_ab.py \
  --baseline "$BASELINE_BIN" --baseline-revision "$(git -C "$BASE" rev-parse HEAD)" \
  --candidate "$CANDIDATE_BIN" --candidate-revision "$(git rev-parse HEAD)" \
  --compiler "$HOST_COMPILER_VERSION" --cuda-version "$CUDA_TOOLKIT_VERSION" --cuda-arch "$CUDA_ARCH" \
  --output-dir out/gpu-validation/ab-smoke --lock-file out/gpu-validation/gpu-ab.lock \
  --mode all --n 16 --threads 1 --warmup-blocks 1 --blocks 1
```

Set `HOST_COMPILER_VERSION`, `CUDA_TOOLKIT_VERSION`, and `CUDA_ARCH` to the build values before running. The 16-output run checks the workflow. For timing, use a new output directory with `--n 65539 --threads 2 --warmup-blocks 1 --blocks 3`. Assess a larger H200 request, such as 262144 outputs, after exact checks pass and capacity is established. Use a separate comparison for each workload. Never run two benchmarks at the same time, including across Windows, WSL, or remote hosts. Schedule sanitizer runs and profilers outside timing.

The runner preserves the frontend logs and `report.json`. The footer's `pbits` field reports the plaintext modulus setting. Record it alongside the selected prime, whose integer bit length can differ. The NoGoldenSeed modes select the 52-bit setting. The parsed frontend time covers local offline setup, online evaluation, and relation verification. It is an end-to-end measurement. Use a separate trace for kernel time or copy overlap. Report mode, size, host and GPU identity, both revisions, clock and power settings, driver and toolchain versions, raw samples, and median and range for each revision.

## Report

Keep separate results for Windows SM89, Linux SM89, SM90 compile coverage, and actual H200 runtime. For each runtime record, include the direct and protocol test counts, strict leak result, and any A/B result. Attach H200 dispatch evidence to the corresponding test or workload. Record pending runtime checks as pending until the target hardware executes them.

The [local RTX 4060 results](GPU_VALIDATION_RESULTS.md) include the WSL LeakSanitizer diagnostic and its reproducer.
