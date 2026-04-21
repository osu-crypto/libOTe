#!/usr/bin/env python3

import argparse
import csv
import os
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FRONTEND = ROOT / "out" / "build" / "x64-Release" / "frontend" / "frontend_libOTe.exe"
CSV_FIELDNAMES = [
    "k",
    "sigma",
    "outer_n",
    "inner_n",
    "inner_tau",
    "inner_tau_frac",
    "threads",
    "case_name",
    "runtime_ms",
    "md_reported",
    "zero_rel_reported",
    "zero_val_reported",
    "kernel_h",
    "kernel_weight",
    "dist_file",
    "error",
]


def parse_int_list(text: str) -> list[int]:
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def newest_matching(pattern: str, after: float) -> Path:
    matches = [p for p in ROOT.glob(pattern) if p.stat().st_mtime >= after]
    if not matches:
        raise FileNotFoundError(f"no file matching {pattern!r} created after {after}")
    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0]


def parse_stdout(stdout: str) -> dict[str, object]:
    result: dict[str, object] = {
        "md": None,
        "zero_rel": None,
        "zero_val": None,
        "kernel_h": None,
        "kernel_weight": None,
        "runtime_ms": None,
        "case_name": None,
    }

    zero_match = re.search(r"zero\s+(\d+)\s+([^\s]+)", stdout)
    if zero_match:
        result["kernel_h"] = int(zero_match.group(1))
        result["kernel_weight"] = zero_match.group(2)

    md_match = re.search(r"MD:\s+([^\s]+)\s+zero:\s+([^\s]+)\s+zeroVal:\s+([^\s]+)", stdout)
    if md_match:
        result["md"] = float(md_match.group(1))
        result["zero_rel"] = float(md_match.group(2))
        result["zero_val"] = float(md_match.group(3))

    time_match = re.search(r"^(\S+)\s+time:\s+(\d+)ms", stdout, re.MULTILINE)
    if time_match:
        result["case_name"] = time_match.group(1)
        result["runtime_ms"] = int(time_match.group(2))

    return result


def run_case(frontend: Path, k: int, sigma: int, tau_frac: float, threads: int) -> dict[str, object]:
    outer_n = 2 * k + sigma
    inner_tau = max(0, round(tau_frac * outer_n))
    inner_n = outer_n + inner_tau

    cmd = [
        str(frontend),
        "-minimumdistance",
        "-subcode",
        "sysBand",
        "wrapConvDp",
        "-k",
        str(k),
        "-stageN",
        str(outer_n),
        str(inner_n),
        "-stageSigma",
        str(sigma),
        str(sigma),
        "-threads",
        str(threads),
        "-noPlot",
    ]

    before = max((p.stat().st_mtime for p in ROOT.glob("dist_*.txt")), default=0.0)
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"case k={k}, sigma={sigma}, outer_n={outer_n}, inner_n={inner_n} failed with code {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )

    stdout_info = parse_stdout(proc.stdout)
    dist_path = newest_matching("dist_*.txt", before)

    return {
        "k": k,
        "sigma": sigma,
        "outer_n": outer_n,
        "inner_n": inner_n,
        "inner_tau": inner_tau,
        "inner_tau_frac": tau_frac,
        "threads": threads,
        "case_name": stdout_info["case_name"],
        "runtime_ms": stdout_info["runtime_ms"],
        "md_reported": stdout_info["md"],
        "zero_rel_reported": stdout_info["zero_rel"],
        "zero_val_reported": stdout_info["zero_val"],
        "kernel_h": stdout_info["kernel_h"],
        "kernel_weight": stdout_info["kernel_weight"],
        "dist_file": str(dist_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sweep the sysBand + wrapConvDp regime with exact stage lengths.")
    parser.add_argument("--frontend", type=Path, default=DEFAULT_FRONTEND)
    parser.add_argument("--k", default="24,32,40,48,56,64,72,80,96")
    parser.add_argument("--sigma", type=int, default=8)
    parser.add_argument("--tau-frac", type=float, default=0.1)
    parser.add_argument("--threads", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--csv", type=Path, default=ROOT / "sysband_regime_longrun.csv")
    parser.add_argument("--stop-on-error", action="store_true")
    args = parser.parse_args()

    ks = parse_int_list(args.k)
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        f.flush()

        for k in ks:
            print(f"running k={k}, sigma={args.sigma}, tau_frac={args.tau_frac}...", flush=True)
            start = time.time()
            try:
                row = run_case(args.frontend, k, args.sigma, args.tau_frac, args.threads)
            except Exception as exc:
                if args.stop_on_error:
                    raise
                row = {
                    "k": k,
                    "sigma": args.sigma,
                    "inner_tau_frac": args.tau_frac,
                    "threads": args.threads,
                    "error": str(exc),
                }
                writer.writerow(row)
                f.flush()
                print(f"  failed after {time.time() - start:.1f}s: {exc}", flush=True)
                continue

            writer.writerow(row)
            f.flush()
            print(
                f"  zero_rel={row['zero_rel_reported']} kernel_h={row['kernel_h']} "
                f"runtime={row['runtime_ms']}ms dist={Path(str(row['dist_file'])).name}",
                flush=True,
            )

    print(f"wrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
