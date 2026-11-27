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

## WSL LeakSanitizer result

The original WSL executables linked with host LeakSanitizer. All 68 functional test executions passed their assertions in 74.42 s. Fifteen of 18 processes exited with status 23 after LeakSanitizer reported a 40-byte allocation in `/usr/lib/wsl/lib/libcuda.so.1` at offset `0x1c982`, build ID `40086cd1e9cdd1a51c0a6012766358f78c33662b`. Three focused CPU processes completed 16 test executions without a LeakSanitizer report.

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
