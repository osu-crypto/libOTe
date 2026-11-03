"""Run bounded CUDA regressions serially on Windows or Linux.

Build with: cmake --build BUILD --target logvole_cuda_tests --parallel 4
Usage: python run_cuda_checks.py BUILD/libOTe_Tests/logvole_cuda_tests [--log-dir DIR]
On Windows, append .exe. A CUDA-enabled frontend_libOTe also works.
Run run_cuda_leak_checks.py separately for bounded full leak detection.
Large allocation tests are intentionally not selected.
"""
import argparse
import json
import pathlib
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("--log-dir", type=pathlib.Path,
                        default=pathlib.Path("out/logvole-cuda-checks"))
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    checks = [
        "Cpu_ReduceMatchesReference", "Cpu_ScaleAndRoundMatchesReference",
        "Cpu_NttMatchesReference", "Cpu_CrtMixedWidthsMatchSeal",
        "Cpu_DyadicMatchesReference", "Cpu_SamplerMatchesSeal",
        "Cpu_ResamplingOverwritesPreviousQuery", "Cpu_ZkArithmeticMatchesReference",
        "Cpu_GpuZkMatMulSeededInputsMatchReference",
        "RingOps_PartyCachesDoNotAlias", "RingOps_ScalarUploadLifetimeAndRoleSwitch",
        "RingOps_GpuBufferResizeBounds", "RingOps_GpuMemoryPoolLifecycle", "RingOps_GpuStreamStagingLifetime", "Encoding_PinnedWireBufferOwnership",
        "RingOps_GaussianPrefixBatchParity",
        "Civole_RejectsZeroDelta", "Civole_RejectsPeerOfflineWidth",
        "Civole_StateMachineAutoOfflineSequentialSids",
        "KeyDeriveCoproto_OversizedFramesRejectedBeforeAllocation",
    ]
    jobs = [("targeted", ["-u", *["LogVole_" + s for s in checks], "-gpu", "1"])]
    jobs.append(("word-arithmetic", ["-u", "UInt_WordArithmetic_Test"]))
    jobs.append(("ntt", ["-u", "LogVole_RingOps_NttTwoTileInPlaceParity", "-gpu", "1"]))
    # A separate process must succeed without another test warming its caches.
    jobs.append(("retention-cold", ["-u", "LogVole_RingOps_PublicUniformRetentionParity",
                                    "-gpu", "1"]))
    # Before/at/after a batch boundary and one recursive boundary with a tail.
    for count in (8191, 8192, 8193, 262147):
        jobs.append((f"modes-{count}", ["-u", "LogVole_Modes_", "-gpu", "1",
                                      "-lvCount", str(count), "-lvRounds", "2",
                                      "-lvRandom", "1"]))
    # One CPU control per setting; GPU cases above exercise all three modes.
    jobs.append(("cpu-control", ["-u", "LogVole_Modes_InteractiveGolden",
                                  "LogVole_Modes_NonInteractive", "-gpu", "0",
                                  "-lvCount", "8193", "-lvRounds", "2", "-lvRandom", "1"]))
    started = time.monotonic()
    results = []
    for name, options in jobs:
        remaining = 45 - (time.monotonic() - started)
        if remaining <= 0:
            results.append(dict(name=name, exit_code=124, reason="suite time budget exhausted"))
            break
        tick = time.monotonic()
        command = [str(executable), *options]
        with (args.log_dir / (name + ".log")).open("w") as log:
            log.write(repr(command) + "\n")
            log.flush()
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=min(20, remaining))
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        entry = dict(name=name, exit_code=code, seconds=round(time.monotonic() - tick, 2))
        results.append(entry)
        print(json.dumps(entry), flush=True)
        if code == 124:
            break
    report = dict(seconds=round(time.monotonic() - started, 2), results=results)
    (args.log_dir / "results.json").write_text(json.dumps(report, indent=2))
    return int(any(result["exit_code"] != 0 for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
