#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path
from typing import Dict


FILTERS: Dict[str, str] = {
    "2level": "BM_LogVOLE_2Level",
    "3level": "BM_LogVOLE_3Level",
    "5level": "BM_LogVOLE_5Level_W256",
    "n2p24": "BM_LogVOLE_N2Pow24",
    "n2p25": "BM_LogVOLE_N2Pow25",
}


def parse_threads(raw: str) -> list[int]:
    values: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        value = int(token)
        if value <= 0:
            raise argparse.ArgumentTypeError("thread counts must be positive")
        values.append(value)
    if not values:
        raise argparse.ArgumentTypeError("provide at least one thread count")
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run LogVOLE Google Benchmark sweeps.")
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--preset", choices=sorted(FILTERS), default="n2p25")
    parser.add_argument("--threads", type=parse_threads, default=parse_threads("1,2,4,8,16"))
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--min-time", default="0.01")
    parser.add_argument("--output-root", type=Path, default=Path("results/logvole"))
    parser.add_argument("--precompute", action="store_true", help="Enable sender pre-computation path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bench_binary = args.binary or (args.build_dir / "bin" / "logvole_bench")
    if not bench_binary.exists():
        raise SystemExit(f"Benchmark binary not found: {bench_binary}")

    out_dir = args.output_root / args.preset / f"it{args.iterations}"
    out_dir.mkdir(parents=True, exist_ok=True)

    for threads in args.threads:
        output = out_dir / f"t{threads}.json"
        env = os.environ.copy()
        env["LOGVOLE_BENCH_SENDER_THREADS"] = str(threads)
        env["LOGVOLE_BENCH_RECEIVER_THREADS"] = str(threads)
        env["LOGVOLE_BENCH_ITERATIONS"] = str(args.iterations)
        if args.precompute:
            env["LOGVOLE_BENCH_PRECOMPUTE"] = "1"

        cmd = [
            str(bench_binary),
            f"--benchmark_filter=^{FILTERS[args.preset]}(/.*)?$",
            f"--benchmark_min_time={args.min_time}",
            "--benchmark_format=json",
            f"--benchmark_out={output}",
            "--benchmark_out_format=json",
        ]
        print(f"Running {args.preset} with {threads} threads per party -> {output}")
        subprocess.run(cmd, check=True, env=env)


if __name__ == "__main__":
    main()
