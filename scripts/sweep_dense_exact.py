#!/usr/bin/env python3

import argparse
import csv
import math
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FRONTEND = ROOT / "out" / "build" / "x64-Release" / "frontend" / "frontend_libOTe.exe"


def parse_int_list(text: str) -> list[int]:
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def newest_matching(pattern: str, after: float) -> Path:
    matches = [p for p in ROOT.glob(pattern) if p.stat().st_mtime >= after]
    if not matches:
        raise FileNotFoundError(f"no file matching {pattern!r} created after {after}")
    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0]


def parse_dist_file(path: Path) -> dict[str, float | int | None]:
    lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if len(lines) < 3:
        raise ValueError(f"unexpected distribution file format in {path}")

    name = lines[0]
    log_counts = [entry for entry in lines[1].split(",")[:-1]]
    log_cumulative = [entry for entry in lines[2].split(",")[:-1]]

    def first_ge_zero(entries: list[str], offset: int = 0) -> tuple[int | None, float | None]:
        for idx, entry in enumerate(entries[offset:], start=offset):
            if not entry or entry == "nan":
                continue
            value = float(entry)
            if value >= 0:
                return idx, value
        return None, None

    # First line is indexed by h directly. Ignore h=0 because nonzero kernel mass is tracked separately.
    positive_count_h, positive_count_log2 = first_ge_zero(log_counts, offset=1)

    # Second line starts with an empty slot and then cumulative sums for h=1..n.
    positive_cum_h = None
    positive_cum_log2 = None
    for idx, entry in enumerate(log_cumulative[1:], start=1):
        if not entry or entry == "nan":
            continue
        value = float(entry)
        if value >= 0:
            positive_cum_h = idx
            positive_cum_log2 = value
            break

    return {
        "name": name,
        "positive_count_h": positive_count_h,
        "positive_count_rel": (positive_count_h / (len(log_counts) - 1)) if positive_count_h is not None else None,
        "positive_count_log2": positive_count_log2,
        "positive_cum_h": positive_cum_h,
        "positive_cum_rel": (positive_cum_h / (len(log_counts) - 1)) if positive_cum_h is not None else None,
        "positive_cum_log2": positive_cum_log2,
    }


def parse_stdout(stdout: str) -> dict[str, float | int | None]:
    result: dict[str, float | int | None] = {
        "md": None,
        "zero_rel": None,
        "zero_val": None,
        "kernel_h": None,
        "kernel_weight": None,
        "runtime_ms": None,
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

    time_match = re.search(r"\stime:\s+(\d+)ms", stdout)
    if time_match:
        result["runtime_ms"] = int(time_match.group(1))

    return result


def run_case(frontend: Path, k: int, sigma: int, rate: float, full: bool, threads: int) -> dict[str, object]:
    cmd = [
        str(frontend),
        "-minimumdistance",
        "-subcode",
        "band",
        "randConv",
        "-k",
        str(k),
        "-rate",
        str(rate),
        "-sigma",
        str(sigma),
        "-threads",
        str(threads),
        "-noPlot",
    ]
    if full:
        cmd.append("-full")

    before = max((p.stat().st_mtime for p in ROOT.glob("dist_*.txt")), default=0.0)
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"case k={k}, sigma={sigma} failed with code {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )

    dist_path = newest_matching("dist_*.txt", before)
    dist_info = parse_dist_file(dist_path)
    stdout_info = parse_stdout(proc.stdout)

    row: dict[str, object] = {
        "k_requested": k,
        "sigma": sigma,
        "rate": rate,
        "threads": threads,
        "case_name": dist_info["name"],
        "dist_file": str(dist_path),
        "runtime_ms": stdout_info["runtime_ms"],
        "kernel_h": stdout_info["kernel_h"],
        "kernel_weight": stdout_info["kernel_weight"],
        "md_reported": stdout_info["md"],
        "zero_rel_reported": stdout_info["zero_rel"],
        "zero_val_reported": stdout_info["zero_val"],
        "positive_count_h": dist_info["positive_count_h"],
        "positive_count_rel": dist_info["positive_count_rel"],
        "positive_count_log2": dist_info["positive_count_log2"],
        "positive_cum_h": dist_info["positive_cum_h"],
        "positive_cum_rel": dist_info["positive_cum_rel"],
        "positive_cum_log2": dist_info["positive_cum_log2"],
    }

    if full:
        enum_path = newest_matching("enum_*.txt", before)
        row["enum_file"] = str(enum_path)

    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="Sweep exact dense band->randConv compositions.")
    parser.add_argument("--frontend", type=Path, default=DEFAULT_FRONTEND)
    parser.add_argument("--k", default="4,8,12,16,20,24,32")
    parser.add_argument("--sigma", default="2,3,4")
    parser.add_argument("--rate", type=float, default=0.5)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--csv", type=Path, default=ROOT / "dense_exact_sweep.csv")
    parser.add_argument("--stop-on-error", action="store_true")
    args = parser.parse_args()

    ks = parse_int_list(args.k)
    sigmas = parse_int_list(args.sigma)

    rows: list[dict[str, object]] = []
    for sigma in sigmas:
        for k in ks:
            print(f"running k={k}, sigma={sigma}...", flush=True)
            try:
                row = run_case(args.frontend, k, sigma, args.rate, args.full, args.threads)
            except Exception as exc:
                if args.stop_on_error:
                    raise
                row = {
                    "k_requested": k,
                    "sigma": sigma,
                    "rate": args.rate,
                    "error": str(exc),
                }
                rows.append(row)
                print(f"  failed: {exc}", flush=True)
                continue
            rows.append(row)
            print(
                f"  positive cumulative threshold: h={row['positive_cum_h']} "
                f"(rel={row['positive_cum_rel']}) runtime={row['runtime_ms']}ms",
                flush=True,
            )

    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    with args.csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
