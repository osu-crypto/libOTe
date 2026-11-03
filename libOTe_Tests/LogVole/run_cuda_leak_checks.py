"""Check CUDA ownership and process teardown with Compute Sanitizer.

Run serially on a GPU-equipped Windows or Linux host. The three protocol modes
use 8193 outputs and three queries each; this is a leak regression, not a load
or performance test. Nonzero sanitizer results, skips, and timeouts fail the run.
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import time


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
        ("pool-lifecycle", ["LogVole_RingOps_GpuMemoryPoolLifecycle"]),
        ("wire-and-caches", ["LogVole_Encoding_PinnedWireBufferOwnership",
                             "LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch",
                             "LogVole_RingOps_PartyCachesDoNotAlias"]),
        ("zk-scalar-use", ["LogVole_Zk_FreshMaskGpu"]),
        ("retention-cold", ["LogVole_RingOps_PublicUniformRetentionParity"]),
        ("protocol-modes", ["LogVole_Modes_"]),
    ]
    results = []
    started = time.monotonic()
    for name, tests in jobs:
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
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=min(40, remaining))
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
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
