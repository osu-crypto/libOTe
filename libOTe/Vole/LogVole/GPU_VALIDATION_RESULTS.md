# Local LogVole GPU validation results

The candidate production source is `f4d60193fcae7b90f079ec578d4e2d8f9a5ae61b`. The A/B baseline is `ff8a006a740b11d92f41cd68eee875aa80e99224`. Subsequent handoff and test-runner commits leave the candidate library and example source at the tested revision. See the [validation commands](GPU_VALIDATION.md) for the dependency revisions and build configuration.

Windows and Ubuntu 24.04 under WSL2 used the same NVIDIA GeForce RTX 4060 Laptop GPU, compute capability 8.9, with Windows driver 610.60. Both builds used Ninja, Release, and architecture 89. Windows used MSVC 19.50.35740 with toolset 14.50.35717 and NVCC 13.2.78. WSL used GNU C++ 13.3.0 and NVCC 13.2.51.

| Gate | Windows | WSL Ubuntu 24.04 |
| --- | --- | --- |
| Candidate build of focused test, lifetime, and A/B targets | Passed in 200.12 s | Passed in 897.51 s. The uninstrumented executables relinked in 26.09 s. |
| Release functional suite with kernel parity | 18 jobs, 68 test executions, 0 skips, 189.90 s | 18 jobs, 68 test executions, 0 skips, 53.74 s |
| Compute Sanitizer memcheck and full leak check | 9 groups, 23 test executions plus the lifetime executable, 122.89 s | 9 groups, 23 test executions plus the lifetime executable, 37.42 s |

Each Compute Sanitizer group reported zero errors, leaked bytes, leaked allocations, and skipped tests. Timings include the respective process wrappers. Local raw logs and summaries are under `out/review/gpu-final-functional-windows`, `gpu-final-functional-release-linux`, `gpu-final-leaks-windows`, and `gpu-final-leaks-release-linux`.

The isolated Windows CUDA object compile for `compute_90,sm_90` passed in 63.10 s. `cuobjdump` found all four CT2 entries, six Root zeta entries, all seven outer-product reuse instantiations, and the expected H200 FP52 transform, indexed product, accumulator, and gadget entries. The monolithic CT2 entry was absent. The command, log, object, and symbol listing share the prefix `out/review/gpu-pruning-final-sm90`. These are compile results. RTX 4090 runtime, H200 runtime, and traces of H200-specific dispatch are pending.

## Serial A/B on the RTX 4060

The baseline launcher built in 464.41 s on Windows and 843.26 s on WSL. Each launcher compiled its revision's unchanged example. The local dependency manifest records matching build flags and pinned sources within each platform. The WSL timing executables used the same CUDA runtime and uninstrumented linking.

Each platform completed 12 smoke executions at `n=16` and 48 executions at `n=65539`. Every execution exited successfully after checking the VOLE relation. Within each mode, all runs reported the same output count, modulus setting, selected prime, and online byte count. GoldenSeed reported setting 55 and prime `18014398508400641`. Both NoGoldenSeed modes reported setting 52 and prime `2251799813554177`.

The production-size workload used `n=65539` and two configured threads. Each mode ran one warmup block, then three measured blocks in ABBA, BAAB, and ABBA order. The medians use six samples per revision and exclude warmup. The frontend timer covers local offline setup, online evaluation, and relation verification.

| Platform | Mode | Baseline median (range), ms | Candidate median (range), ms | Median change |
| --- | --- | ---: | ---: | ---: |
| Windows | Interactive GoldenSeed | 1032 (1013–1038) | 919 (918–947) | −10.95% |
| Windows | Interactive NoGoldenSeed | 6394.5 (6238–6481) | 6050 (6000–6130) | −5.39% |
| Windows | Noninteractive NoGoldenSeed | 6784 (6451–7284) | 6113 (5877–7130) | −9.89% |
| WSL | Interactive GoldenSeed | 882 (757–898) | 619.5 (498–643) | −29.76% |
| WSL | Interactive NoGoldenSeed | 1951.5 (1910–2105) | 1571.5 (1513–1903) | −19.47% |
| WSL | Noninteractive NoGoldenSeed | 2351.5 (1984–2536) | 1945 (1767–2578) | −17.29% |

The median change is relative to the baseline. The WSL noninteractive block medians changed by −19.63%, −18.16%, and +4.83%, respectively. The ranges and block results show timing variation. The before and after telemetry shows different clocks and power states, and the example uses its usual randomized setup. Treat these as local end-to-end measurements for the tested workload and GPU. Use separate dispatch traces and same-hardware A/B runs for claims about individual kernels, RTX 4090, or H200.

The first Windows smoke attempt stopped in the timing parser after the baseline frontend exited successfully. It reported `pbits=55` and the 54-bit prime `18014398508400641`. The runner had treated the modulus setting as the prime's integer bit length. The corrected parser checks both values independently and retains exact cross-run checks. The completed smoke used a fresh output directory.

Reports, raw logs, and before/after telemetry are under `out/review`, with report directories `ab-smoke-windows-retry`, `ab-smoke-linux`, `ab-65539-windows`, and `ab-65539-linux`. The aborted smoke report remains in `ab-smoke-windows`. The build and dependency comparison is in `ab-dependencies.json`.

## Serial A/B against the original LogVole PR

This comparison uses `b80413b5c882ea571e9fc2a30bd85f54acb39455` as the baseline and `29c64dbd87f2bca8858e020a160aa0e1856a8eb7` as the candidate. The candidate launcher binaries are the same ones used in the pruning comparison above. The candidate library and example source are unchanged from `f4d60193`.

WSL built the original source unchanged from Git archives staged on the WSL filesystem. The Windows build required `/Zi` scoping to C++ compilation, `__umulh` for MSVC host high-word multiplication, separate inverse NTT entry points that retain the fixed 32/40-register limits and leave the generic kernel unconstrained, and paired `_aligned_malloc`/`_aligned_free` for the page-aligned staging pool. The Windows original also used the CUDA host flag `-Xcompiler=/Zc:preprocessor` required by CUDA 13.2's CCCL headers. The original CUDA device arithmetic, NTT butterfly body, staged allocation sizes and alignment, and protocol defaults were preserved. The [Windows baseline patch](../../../libOTe_Tests/LogVole/original_b80413b5_windows_compat.patch) applies to `b80413b5` and has SHA-256 `10110a9fd3e0a05f625a7cdd831d0da2e002e1a240b504f436926b17d8b0921c`. Apply it to the baseline checkout before configuring with the additional CUDA flag. The Windows timings characterize this compatibility build. The source and compiler adjustments may affect generated machine code.

Both variants used the same toolchain, C++20 frontend, CUDA C++17, Release optimization, SSE and AVX2 settings, and architecture 89 within each OS. The original uses its committed cryptoTools gitlink `cc54d946a7643795b5f523fe235392de8271a5b3`. The candidate uses `3e69c5b9ac0f0c43d0fd1c9e1b886a3ea8df8979`. The cryptoTools PRNG source matches between these pins. The original LogVole IFMA paths require GCC or Clang and are absent in the MSVC build. WSL reported no AVX-512 IFMA support, and HEAD built with `OC_ENABLE_AVX512_IFMA=OFF` on both platforms. The coproto, macoro, function2, and SEAL pins match the pruning comparison. WSL resolved both launchers to the same CUDA runtime and neither linked a sanitizer. The original LogVole sampler and the candidate AES sampler run as implemented in each revision.

Both frontends use local paired sockets, begin timing immediately before the offline call, and stop after checking the full VOLE relation. The benchmark uses the same command-line settings and each revision's default GPU tuning. No LogVole tuning environment or CUDA device-selection overrides were set. NoGoldenSeed uses modulus setting 52 in both frontends even though the runner passes `-p 55`.

All 120 launches passed. On each platform, the smoke run used `n=16`, one configured thread, and one ABBA block per mode. The production run used `n=65539`, two configured threads, one ABBA warmup block per mode, then measured ABBA, BAAB, and ABBA blocks. Each production median uses six measured launches per revision. Windows ran before WSL for production, with one process at a time and a shared lock across platforms.

| Mode | Modulus setting | Prime | Online bytes |
| --- | ---: | ---: | ---: |
| Interactive GoldenSeed | 55 | 18014398508400641 | 1048664 |
| Interactive NoGoldenSeed | 52 | 2251799813554177 | 4194360 |
| Noninteractive NoGoldenSeed | 52 | 2251799813554177 | 2097176 |

### Production timings at `n=65539`

| Platform | Mode | Original frontend median (range), ms | HEAD frontend median (range), ms | Frontend change | Original → HEAD process wall median, ms | Wall change |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Windows compatibility build | Interactive GoldenSeed | 528 (508–680) | 1122 (929–1257) | +112.50% | 670.4 → 1282.5 | +91.30% |
| Windows compatibility build | Interactive NoGoldenSeed | 1742.5 (1639–1791) | 5771.5 (4932–6120) | +231.22% | 1959.3 → 5956.3 | +204.00% |
| Windows compatibility build | Noninteractive NoGoldenSeed | 2274 (1891–2537) | 5451 (5021–5961) | +139.71% | 2488.3 → 5636.8 | +126.53% |
| WSL | Interactive GoldenSeed | 843.5 (818–993) | 596.5 (589–617) | −29.28% | 1276.5 → 1022.7 | −19.89% |
| WSL | Interactive NoGoldenSeed | 1406 (1342–1443) | 1443.5 (1412–1526) | +2.67% | 1927.9 → 1901.6 | −1.36% |
| WSL | Noninteractive NoGoldenSeed | 1399.5 (1372–1771) | 1408.5 (1356–1868) | +0.64% | 1912.0 → 1877.8 | −1.79% |

Changes are relative to the original. The process wall clock includes launch, frontend configuration and construction, teardown, and capture overhead. Every Windows block was slower in HEAD. WSL GoldenSeed improved across all blocks. WSL interactive NoGoldenSeed had a small frontend slowdown in all blocks and a lower process-wall median. The WSL noninteractive frontend timings varied across the blocks.

| Platform | Mode | Frontend changes by measured block |
| --- | --- | --- |
| Windows compatibility build | Interactive GoldenSeed | +93.21%, +90.49%, +104.94% |
| Windows compatibility build | Interactive NoGoldenSeed | +205.48%, +237.65%, +247.17% |
| Windows compatibility build | Noninteractive NoGoldenSeed | +128.41%, +150.83%, +158.53% |
| WSL | Interactive GoldenSeed | −29.00%, −30.75%, −33.30% |
| WSL | Interactive NoGoldenSeed | +2.41%, +6.60%, +4.65% |
| WSL | Noninteractive NoGoldenSeed | +1.09%, −1.00%, +7.15% |

### Smoke timings at `n=16`

| Platform | Mode | Original → HEAD frontend median, ms | Frontend change | Original → HEAD process wall median, ms | Wall change |
| --- | --- | ---: | ---: | ---: | ---: |
| Windows compatibility build | Interactive GoldenSeed | 646.5 → 883 | +36.58% | 892.6 → 1074.8 | +20.41% |
| Windows compatibility build | Interactive NoGoldenSeed | 1988 → 5053 | +154.18% | 2217.8 → 5252.8 | +136.84% |
| Windows compatibility build | Noninteractive NoGoldenSeed | 2778 → 5015 | +80.53% | 3015.2 → 5213.1 | +72.89% |
| WSL | Interactive GoldenSeed | 867 → 460.5 | −46.89% | 1400.5 → 795.5 | −43.20% |
| WSL | Interactive NoGoldenSeed | 1337.5 → 1344 | +0.49% | 1831.4 → 1777.1 | −2.97% |
| WSL | Noninteractive NoGoldenSeed | 1478.5 → 1554.5 | +5.14% | 1926.9 → 2053.6 | +6.58% |

Local raw reports and logs are under `out/review/ab-original-{smoke,65539}-{windows,linux}`. The matching `*-launchers.json` and `*-environment.json` files record binary hashes and environment checks. The matching `*-{before,after}-telemetry.log` files capture the GPU state outside the timing runs. Both production runs started at 64 °C and 210 MHz and ended at 66 °C and 1470 MHz in those snapshots. The reports measure the full local protocol on this GPU and build configuration. Attributing the differences to individual kernels or implementation changes requires phase timings and dispatch traces.

## WSL LeakSanitizer result

The earlier instrumented WSL candidate executables linked with host LeakSanitizer. All 68 functional test executions passed their assertions in 74.42 s. Fifteen of 18 processes exited with status 23 after LeakSanitizer reported a 40-byte allocation in `/usr/lib/wsl/lib/libcuda.so.1` at offset `0x1c982`, build ID `40086cd1e9cdd1a51c0a6012766358f78c33662b`. Three focused CPU processes completed 16 test executions without a LeakSanitizer report.

The diagnostic stack led through `cuDriverGetVersion`. The standalone probe below reproduced the same 40-byte allocation using only that driver operation. It also reported a separate 260-byte driver allocation. Both executions exited with status 23, including the run that called `dlclose`. This reproduces the matching allocation outside LogVole and the CUDA runtime library. The host LeakSanitizer gate remains failed on this WSL driver. The Release and Compute Sanitizer results above came from a separate uninstrumented link. No LeakSanitizer suppressions were applied.

```cpp
#include <cuda.h>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    const bool close = std::strcmp(argv[1], "close") == 0;
    if (!close && std::strcmp(argv[1], "keep") != 0) return 2;
    auto* driver = dlopen("/usr/lib/wsl/lib/libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!driver)
    {
        std::fprintf(stderr, "%s\n", dlerror());
        return 1;
    }
    const auto getVersion = reinterpret_cast<decltype(&cuDriverGetVersion)>(
        dlsym(driver, "cuDriverGetVersion"));
    int version = 0;
    if (!getVersion || getVersion(&version) != CUDA_SUCCESS) return 1;
    std::printf("cuDriverGetVersion succeeded: %d\n", version);
    std::fflush(stdout);
    if (close && dlclose(driver) != 0) return 1;
    return 0;
}
```

Save the probe as `wsl_driver_lsan_probe.cpp`. Set `CUDA_INCLUDE` to the toolkit's include directory.

```sh
c++ -O3 -g -fsanitize=leak -I"$CUDA_INCLUDE" wsl_driver_lsan_probe.cpp -ldl -o wsl_driver_lsan_probe
LSAN_OPTIONS=exitcode=23:fast_unwind_on_malloc=0 ./wsl_driver_lsan_probe keep
LSAN_OPTIONS=exitcode=23:fast_unwind_on_malloc=0 ./wsl_driver_lsan_probe close
```

Local evidence is in `out/review/gpu-final-functional-linux`, `logvole-cputest-lsan-minimal-unwind.log`, and `wsl-driver-lsan-final-{keep,close}.log`.
