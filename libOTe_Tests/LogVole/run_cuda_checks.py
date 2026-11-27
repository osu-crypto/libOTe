"""Run bounded CUDA regressions serially on Windows or Linux.

Build with: cmake --build BUILD --target logvole_cuda_tests --parallel 4
Usage: python run_cuda_checks.py BUILD/libOTe_Tests/logvole_cuda_tests [--log-dir DIR]
On Windows, append .exe. A CUDA-enabled frontend_libOTe also works.
Pass --kernel-parity to include the full kernel and root-prefetch parity matrix.
Run run_cuda_leak_checks.py separately for bounded full leak detection.
"""
import argparse
import json
import pathlib
import time

from cuda_test_process import all_selected_tests_passed, positive_seconds, run_bounded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("--log-dir", type=pathlib.Path,
                        default=pathlib.Path("out/logvole-cuda-checks"))
    parser.add_argument("--kernel-parity", action="store_true",
                        help="also run the full kernel and root-prefetch parity matrix")
    parser.add_argument("--suite-timeout", type=positive_seconds, default=90, metavar="SECONDS")
    parser.add_argument("--job-timeout", type=positive_seconds, metavar="SECONDS",
                        help="per-process limit (default 20, or 40 for CPU control jobs)")
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    checks = [
        "Cpu_ReduceMatchesReference", "Cpu_ScaleAndRoundMatchesReference",
        "Cpu_NttMatchesReference", "Cpu_CrtMixedWidthsMatchSeal",
        "Cpu_DyadicMatchesReference", "Cpu_SamplerMatchesSeal", "Cpu_ErrorSamplingMatchesSeal",
        "Cpu_ResamplingOverwritesPreviousQuery", "Cpu_ParallelFailureJoinsChildren",
        "Cpu_PreparedExecutionLifetime",
        "Cpu_ZkArithmeticMatchesReference", "Cpu_ZkProofMatchesReference",
        "Core_Ct2SeedBudgets",
        "Cpu_GpuZkMatMulSeededInputsMatchReference",
        "Cpu_GpuZkBufferOwnership", "Core_LeafGoldenSeedGpuParity",
        "RingOps_PartyCachesDoNotAlias", "RingOps_ScalarUploadLifetimeAndRoleSwitch",
        "RingOps_GpuBufferResizeBounds", "RingOps_GpuMemoryPoolLifecycle", "RingOps_UniformSamplerScratchOwnership", "RingOps_GpuStreamStagingLifetime", "Encoding_PinnedWireBufferOwnership", "Encoding_RootResidentWireExact",
        "RingOps_GaussianPrefixBatchParity", "NativeSealBundle_ProductionConfigureUsesDeviceAndFreshRuns",
        "Civole_RejectsZeroDelta", "Civole_RejectsPeerOfflineWidth",
        "Civole_StateMachineAutoOfflineSequentialSids",
        "KeyDeriveCoproto_OversizedFramesRejectedBeforeAllocation",
    ]
    # Keep both cold processes under the same 20s bound. CPU arithmetic and
    # sequential-session checks together exceeded it on Windows even though
    # each case passed alone; retain all coverage and the 90s aggregate bound.
    split = checks.index("Cpu_GpuZkMatMulSeededInputsMatchReference")
    def logvole_job(name, selected, *options):
        return name, ["LogVole_" + test for test in selected], list(options)

    jobs = [logvole_job(name, selected, "-gpu", "1")
            for name, selected in (("cpu-arithmetic", checks[:split]),
                                   ("owners-and-protocol", checks[split:]))]
    jobs.append(("word-arithmetic", ["UInt_WordArithmetic_Test"], []))
    # Small CPU-only ownership and exact/truncated relation cases (degree 1024).
    jobs.append(logvole_job("cpu-scratch", ["ShrinkExpandCore_ParamsValidation",
                                           "ShrinkExpandCore_DeterministicRelationExact",
                                           "ShrinkExpandCore_TruncDeterministicRelationBounded"], "-gpu", "0"))
    fast_gpu = ("-gpu", "1", "-lvFactoryFast", "1")
    jobs.append(logvole_job("ntt", ["RingOps_NttTwoTileInPlaceParity"], *fast_gpu))
    jobs.append(logvole_job("seed-parity", ["RingOps_GpuCt2SeedAesParity", "RingOps_RootZetaParity"], *fast_gpu))
    # A separate process must succeed without another test warming its caches.
    jobs.append(logvole_job("retention-cold", ["RingOps_PublicUniformRetentionParity"], "-gpu", "1"))
    # Before/at/after a batch boundary and one recursive boundary with a tail.
    modes = ["Modes_InteractiveGolden", "Modes_InteractiveNoGolden", "Modes_NonInteractive", "Modes_ProtocolOptions"]
    for count in (8191, 8192, 8193, 262147):
        jobs.append(logvole_job(f"modes-{count}", modes, "-gpu", "1",
                                "-lvCount", str(count), "-lvRounds", "2", "-lvRandom", "1"))
    # One CPU control per setting; GPU cases above exercise all three modes.
    # CPU controls build real SEAL contexts and need their own cold-start bound.
    for name, test in (("golden", "InteractiveGolden"), ("noninteractive", "NonInteractive")):
        jobs.append(logvole_job("cpu-control-" + name, ["Modes_" + test], "-gpu", "0",
                                "-lvCount", "8193", "-lvRounds", "2", "-lvRandom", "1"))
    if args.kernel_parity:
        for name, tests in (
            ("options-outer", ["RingOps_KernelOptions", "RingOps_PointwiseOuterParity"]),
            ("ntt", ["RingOps_NttLog13ForwardParity", "RingOps_NttLog13InverseParity"]),
            ("tree", ["RingOps_NttLog13TreeParity", "RingOps_NttLog13ScatterParity", "RingOps_NttLog13SparseParity"]),
            ("arithmetic", ["RingOps_ScaleNttGatherParity", "RingOps_DenoiseValidationParity",
                            "RingOps_AccumulatorParity", "RingOps_GadgetParity"]),
        ):
            jobs.append(logvole_job("kernel-parity-" + name, tests, *fast_gpu))
        jobs.append(logvole_job("kernel-parity-root", ["Core_RootFinalizePrefetchExactAndCleanup",
                                                         "Core_NoGoldenSeedRootFinalizePrefetchTwoQueryExact"],
                                *fast_gpu, "-root_finalize_priority_prefetch", "1"))
    started = time.monotonic()
    results = []
    for name, tests, options in jobs:
        remaining = args.suite_timeout - (time.monotonic() - started)
        if remaining <= 0:
            results.append(dict(name=name, exit_code=124, reason="suite time budget exhausted"))
            break
        tick = time.monotonic()
        command = [str(executable), "-u", *tests, *options]
        job_timeout = args.job_timeout or (40 if name.startswith("cpu-control-") else 20)
        log_path = args.log_dir / (name + ".log")
        with log_path.open("w") as log:
            log.write(repr(command) + "\n")
            log.flush()
            code = run_bounded(command, stdout=log, timeout=min(job_timeout, remaining))
        passed = all_selected_tests_passed(log_path.read_text(errors="replace"), len(tests))
        entry = dict(name=name, exit_code=code, passed=passed, expected_tests=len(tests),
                     seconds=round(time.monotonic() - tick, 2))
        results.append(entry)
        print(json.dumps(entry), flush=True)
        if code == 124:
            break
    report = dict(seconds=round(time.monotonic() - started, 2), results=results)
    (args.log_dir / "results.json").write_text(json.dumps(report, indent=2))
    return int(len(results) != len(jobs) or any(r["exit_code"] or not r.get("passed") for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
