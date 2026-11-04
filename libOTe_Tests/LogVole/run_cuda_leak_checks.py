"""Check CUDA ownership and process teardown with Compute Sanitizer.

Run serially on a GPU-equipped Windows or Linux host. Each protocol mode
runs in a separate process with 8193 outputs and three queries; this is a leak regression, not a load
or performance test. Nonzero sanitizer results, skips, and timeouts fail the run.
"""
import argparse
import json
import os
import pathlib
import shutil
import time

from cuda_test_process import run_bounded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("--sanitizer", default="compute-sanitizer")
    parser.add_argument("--lifetime-executable", type=pathlib.Path,
                        help="explicit-owner test binary (defaults to a sibling of executable)")
    parser.add_argument("--log-dir", type=pathlib.Path,
                        default=pathlib.Path("out/logvole-cuda-leaks"))
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    lifetime = (args.lifetime_executable or executable.with_name(
        "logvole_cuda_lifetime_tests" + executable.suffix)).resolve(strict=True)
    sanitizer = shutil.which(args.sanitizer)
    if not sanitizer:
        parser.error("Compute Sanitizer not found; use --sanitizer PATH")
    args.log_dir.mkdir(parents=True, exist_ok=True)
    jobs = [
        ("owned-lifetimes", None),
        ("pool-lifecycle", ["LogVole_RingOps_GpuMemoryPoolLifecycle",
                            "LogVole_RingOps_UniformSamplerScratchOwnership",
                            "LogVole_RingOps_GpuStreamStagingLifetime",
                            "LogVole_RingOps_GpuBufferResizeBounds",
                            "LogVole_Core_LeafGoldenSeedGpuParity"]),
        ("wire-and-caches", ["LogVole_Cpu_PreparedExecutionLifetime",
                             "LogVole_Cpu_NttMatchesReference",
                             "LogVole_ShrinkExpandCore_ParamsValidation",
                             "LogVole_Cpu_CrtMixedWidthsMatchSeal",
                             "LogVole_Cpu_GpuZkMatMulSeededInputsMatchReference",
                             "LogVole_Cpu_GpuZkBufferOwnership",
                             "LogVole_Encoding_PinnedWireBufferOwnership",
                             "LogVole_Encoding_RootResidentWireExact",
                             "LogVole_NativeSealBundle_ProductionConfigureUsesDeviceAndFreshRuns",
                             "LogVole_RingOps_GaussianPrefixBatchParity",
                             "LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch",
                             "LogVole_RingOps_PartyCachesDoNotAlias"]),
        ("zk-scalar-use", ["LogVole_Zk_FreshMaskGpu"]),
        ("retention-cold", ["LogVole_RingOps_PublicUniformRetentionParity"]),
        ("mode-golden", ["LogVole_Modes_InteractiveGolden"]),
        ("mode-no-golden", ["LogVole_Modes_InteractiveNoGolden"]),
        ("mode-noninteractive", ["LogVole_Modes_NonInteractive"]),
        ("root-prefetch", ["LogVole_Core_RootFinalizePrefetchExactAndCleanup",
                           "LogVole_Core_NoGoldenSeedRootFinalizePrefetchTwoQueryExact"]),
    ]
    results = []
    started = time.monotonic()
    for name, tests in jobs:
        environment = os.environ.copy()
        if name == "root-prefetch":
            environment["LV_GPU_ROOT_FINALIZE_PRIORITY_PREFETCH"] = "1"
            # Exercise the opt-in deferred device hash in this fresh process;
            # its execution owner must survive the intervening wire exchange.
            environment["LV_GPU_ROOT_DIGEST_HASH"] = "1"
        command = [sanitizer, "--tool", "memcheck", "--leak-check", "full",
                   "--error-exitcode", "99"]
        command += ([str(lifetime)] if tests is None else
                    [str(executable), "-u", *tests, "-gpu", "1", "-lvCount", "8193",
                     "-lvRounds", "3", "-lvRandom", "1"])
        tick = time.monotonic()
        remaining = 90 - (tick - started)
        if remaining <= 0:
            results.append(dict(name=name, exit_code=124))
            break
        log_path = args.log_dir / (name + ".log")
        with log_path.open("w") as log:
            log.write(repr(command) + "\n")
            log.flush()
            code = run_bounded(command, stdout=log,
                               timeout=min(40, remaining), env=environment)
        output = log_path.read_text(errors="replace")
        clean = ("LEAK SUMMARY: 0 bytes leaked in 0 allocations" in output
                 and "ERROR SUMMARY: 0 errors" in output
                 and "skipped" not in output.lower())
        if tests is None:
            clean = clean and "CUDA owned lifetime checks passed" in output
        results.append(dict(name=name, exit_code=code, clean=clean,
                            seconds=round(time.monotonic() - tick, 2)))
        print(json.dumps(results[-1]), flush=True)
        if code or not clean:
            break
    (args.log_dir / "results.json").write_text(json.dumps(results, indent=2))
    return int(len(results) != len(jobs) or any(r["exit_code"] or not r.get("clean") for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
