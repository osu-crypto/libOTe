"""Run a serial A/B comparison of two CUDA-enabled LogVole frontends."""

import argparse
import itertools
import json
import os
import platform
import re
import statistics
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from cuda_test_process import run_bounded


MODES = {"golden": (0, 0), "nogold": (1, 0), "noninteractive": (1, 1)}
ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")
FOOTER = re.compile(
    r"^LogVole local n:\s*(?P<n>[0-9]+)\s+pbits:\s*(?P<pbits>[0-9]+)"
    r"\s+p:\s*(?P<prime>[0-9]+)\s+online-bytes:\s*(?P<online_bytes>[0-9]+)"
    r"\s+\|\|\s+(?P<frontend_ms>[0-9]+)\s+ms\s*$"
)


def parse_footer(output, request_size):
    lines = [
        line for line in ANSI_SGR.sub("", output).splitlines()
        if line.startswith("LogVole local ")
    ]
    match = FOOTER.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        raise ValueError("expected one complete LogVole local timing footer")
    values = {key: int(value) for key, value in match.groupdict().items()}
    if values["n"] != request_size or values["prime"].bit_length() != values["pbits"]:
        raise ValueError("frontend reported an unexpected output count or prime")
    return values


def trial_order(blocks):
    return itertools.chain.from_iterable(
        ("baseline", "candidate", "candidate", "baseline") if i % 2 == 0
        else ("candidate", "baseline", "baseline", "candidate")
        for i in range(blocks)
    )


def positive_int(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def nonnegative_int(value):
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return result


def get_args():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        parser.add_argument(f"--{label}", type=Path, required=True)
        parser.add_argument(f"--{label}-revision", required=True)
    parser.add_argument("--compiler", required=True, help="host compiler and version")
    parser.add_argument("--cuda-version", required=True, help="CUDA toolkit version")
    parser.add_argument("--cuda-arch", required=True, help="compiled CUDA architecture flags")
    parser.add_argument("--output-dir", type=Path, required=True, help="new log directory")
    parser.add_argument(
        "--lock-file", type=Path,
        default=Path(__file__).resolve().parents[2] / "out" / "review" / "gpu-benchmark.lock",
        help="shared lock path for comparisons using the same GPU",
    )
    parser.add_argument("--mode", choices=["all", *MODES], default="all")
    parser.add_argument("--n", type=positive_int, default=16, help="request size (default smoke case: 16)")
    parser.add_argument("--threads", type=positive_int, default=1)
    parser.add_argument("--warmup-blocks", type=nonnegative_int, default=1)
    parser.add_argument("--blocks", type=positive_int, default=1, help="measured four-trial blocks per mode")
    parser.add_argument("--timeout", type=positive_int, default=300, help="seconds per invocation")
    args = parser.parse_args()
    for label in ("baseline", "candidate"):
        path = getattr(args, label).resolve()
        if not path.is_file():
            parser.error(f"{label} frontend is not a file: {path}")
        setattr(args, label, path)
    if args.baseline.samefile(args.candidate):
        parser.error("baseline and candidate must be different executable files")
    if max(args.n, args.threads) > 2**31 - 1:
        parser.error("--n and --threads must fit in a positive C++ int")
    return args


@contextmanager
def benchmark_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock = path.open("x", encoding="utf-8")
    except FileExistsError as error:
        raise RuntimeError(f"Benchmark lock already exists at {path}") from error
    try:
        with lock:
            lock.write(f"host={platform.node()} pid={os.getpid()}\n")
        yield
    finally:
        path.unlink()


def capture(command, log_path, timeout):
    with log_path.open("w", encoding="utf-8") as log:
        start = time.monotonic()
        status = run_bounded(command, stdout=log, timeout=timeout)
        wall_ms = (time.monotonic() - start) * 1000
    return status, wall_ms


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def run_comparison(args):
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=False)
    modes = list(MODES) if args.mode == "all" else [args.mode]
    report = {
        "platform": platform.platform(),
        "baseline": {"executable": str(args.baseline), "revision": args.baseline_revision},
        "candidate": {"executable": str(args.candidate), "revision": args.candidate_revision},
        "compiler": args.compiler,
        "cuda_toolkit": args.cuda_version,
        "compiled_cuda_arch": args.cuda_arch,
        "cuda_visibility": {
            name: os.environ.get(name) for name in ("CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER")
        },
        "modes": modes,
        "request_size": args.n,
        "smoke": args.n == 16,
        "workload_note": (
            "Default smoke workload. Select a production request size explicitly with --n."
            if args.n == 16 else "Operator-selected request size."
        ),
        "measurement_scope": "Local frontend timer covering offline setup, online execution, and relation verification.",
        "threads": args.threads,
        "warmup_blocks": args.warmup_blocks,
        "measured_blocks": args.blocks,
        "timeout_seconds": args.timeout,
        "trials": [],
        "summaries": {},
        "complete": False,
    }
    report_path = output_dir / "report.json"
    inventory_command = [
        "nvidia-smi", "--query-gpu=index,uuid,name,driver_version,compute_cap,pci.bus_id,memory.total",
        "--format=csv",
    ]
    inventory_log = "nvidia-smi.log"
    report["gpu_inventory"] = {"command": inventory_command, "log": inventory_log}
    try:
        status, _ = capture(inventory_command, output_dir / inventory_log, 15)
        report["gpu_inventory"]["returncode"] = status
    except OSError as error:
        report["gpu_inventory"]["error"] = str(error)
    write_json(report_path, report)

    for mode in modes:
        nogold, noninteractive = MODES[mode]
        flags = [
            "-logvole", "-n", str(args.n), "-t", str(args.threads), "-gpu", "1",
            "-nogold", str(nogold), "-noninteractive", str(noninteractive), "-p", "55", "-delta", "7",
        ]
        expected_contract = None
        measured = {"baseline": [], "candidate": []}
        for phase, blocks in (("warmup", args.warmup_blocks), ("measure", args.blocks)):
            for number, label in enumerate(trial_order(blocks), 1):
                log_name = f"{mode}-{phase}-{number:03d}-{label}.log"
                log_path = output_dir / log_name
                trial = {
                    "mode": mode, "phase": phase, "variant": label, "log": log_name,
                    "command": [str(getattr(args, label)), *flags],
                }
                report["trials"].append(trial)
                print(f"{mode} {phase} {number}: {label}", flush=True)
                write_json(report_path, report)
                try:
                    status, wall_ms = capture(trial["command"], log_path, args.timeout)
                    trial.update(returncode=status, wall_ms=wall_ms)
                    if status != 0:
                        print(f"Frontend exited with status {status}. See {log_path}.", file=sys.stderr)
                        return status if status > 0 else 128 - status
                    values = parse_footer(log_path.read_text(encoding="utf-8", errors="replace"), args.n)
                    trial.update(values)
                    contract = (values["pbits"], values["prime"], values["online_bytes"])
                    if expected_contract is not None and contract != expected_contract:
                        raise ValueError("frontend prime or online byte count differed within this mode")
                    expected_contract = contract
                    if phase == "measure":
                        measured[label].append(values["frontend_ms"])
                except (OSError, ValueError) as error:
                    trial["error"] = str(error)
                    print(f"{error}. See {log_path}.", file=sys.stderr)
                    return 1
                finally:
                    write_json(report_path, report)

        report["summaries"][mode] = {
            label: {
                "samples": len(samples),
                "median_frontend_ms": statistics.median(samples),
                "min_frontend_ms": min(samples),
                "max_frontend_ms": max(samples),
            }
            for label, samples in measured.items()
        }
        write_json(report_path, report)

    report["complete"] = True
    write_json(report_path, report)
    print(f"Comparison log and measured timing summaries saved to {report_path}.")
    return 0


if __name__ == "__main__":
    try:
        args = get_args()
        with benchmark_lock(args.lock_file):
            sys.exit(run_comparison(args))
    except (OSError, RuntimeError) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit(130)
