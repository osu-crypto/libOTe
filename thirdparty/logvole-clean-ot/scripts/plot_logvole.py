#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib.pyplot as plt


def detect_cores_per_role(bench: dict, file_path: Path) -> Optional[int]:
    sender = bench.get("sender_worker_threads")
    receiver = bench.get("receiver_worker_threads")
    if sender is not None and receiver is not None:
        sender_i = int(round(float(sender)))
        receiver_i = int(round(float(receiver)))
        if sender_i == receiver_i and sender_i > 0:
            return sender_i

    match = re.search(r"(?:^|_)t(\d+)\.json$", file_path.name)
    if match:
        return int(match.group(1))
    return None


def phase_time_ms(bench: dict, key: str) -> Optional[float]:
    value = bench.get(key)
    if isinstance(value, (int, float)) and float(value) >= 0.0:
        return float(value)
    return None


def total_e2e_ms(bench: dict) -> Optional[float]:
    offline = phase_time_ms(bench, "phase_time/offline_e2e_ms")
    precompute = phase_time_ms(bench, "phase_time/precompute_e2e_ms")
    online = phase_time_ms(bench, "phase_time/online_e2e_ms")
    if offline is not None and precompute is not None and online is not None and online > 0.0:
        return offline + precompute + online

    value = phase_time_ms(bench, "phase_time/e2e_ms")
    if value is not None and value > 0.0:
        return value
    return None


def load_records(input_root: Path, json_glob: str) -> List[dict]:
    records: List[dict] = []
    for json_file in sorted(input_root.rglob(json_glob)):
        with json_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        for bench in payload.get("benchmarks", []):
            cores = detect_cores_per_role(bench, json_file)
            n_labels = bench.get("N_labels")
            online_ms = phase_time_ms(bench, "phase_time/online_e2e_ms")
            receiver_crit_ms = phase_time_ms(bench, "phase_time/online_receiver_compute_crit_ms")
            receiver_ms = phase_time_ms(bench, "phase_time/online_receiver_compute_ms")
            setup_ms = phase_time_ms(bench, "phase_time/offline_e2e_ms")
            precompute_ms = phase_time_ms(bench, "phase_time/precompute_e2e_ms")
            e2e_ms = total_e2e_ms(bench)

            if cores is None or n_labels is None or online_ms is None or setup_ms is None:
                continue
            if precompute_ms is None or e2e_ms is None or online_ms <= 0.0:
                continue

            receiver_path_ms = receiver_crit_ms if receiver_crit_ms and receiver_crit_ms > 0.0 else receiver_ms
            if receiver_path_ms is None or receiver_path_ms <= 0.0:
                continue

            labels = float(n_labels)
            records.append(
                {
                    "file": str(json_file),
                    "cores_per_role": int(cores),
                    "n_labels": labels,
                    "online_tp": labels * 1000.0 / online_ms,
                    "receiver_only_online_tp": labels * 1000.0 / receiver_path_ms,
                    "e2e_tp": labels * 1000.0 / e2e_ms,
                    "setup_ms": setup_ms,
                    "precompute_ms": precompute_ms,
                    "online_ms": online_ms,
                }
            )
    return records


def best_by_core(records: List[dict], metric: str) -> Dict[int, dict]:
    best: Dict[int, dict] = {}
    for record in records:
        core = record["cores_per_role"]
        if core not in best or record[metric] > best[core][metric]:
            best[core] = record
    return best


def plot_throughput(records: List[dict], output_path: Path, max_cores: int, show: bool) -> None:
    online_best = best_by_core(records, "online_tp")
    receiver_best = best_by_core(records, "receiver_only_online_tp")
    e2e_best = best_by_core(records, "e2e_tp")
    cores = [
        core
        for core in sorted(set(online_best) | set(receiver_best) | set(e2e_best))
        if core <= max_cores and core in online_best and core in receiver_best and core in e2e_best
    ]
    if not cores:
        raise ValueError(f"No records at or below {max_cores} cores per role")

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.plot(
        cores,
        [receiver_best[c]["receiver_only_online_tp"] / 1e6 for c in cores],
        marker="x",
        linewidth=2.0,
        color="#2ca02c",
        label="Receiver Critical Path",
    )
    ax.plot(
        cores,
        [online_best[c]["online_tp"] / 1e6 for c in cores],
        marker="x",
        linestyle="--",
        linewidth=2.0,
        color="#1f77b4",
        label="Online Phase",
    )
    ax.plot(
        cores,
        [e2e_best[c]["e2e_tp"] / 1e6 for c in cores],
        marker="x",
        linestyle="--",
        linewidth=2.0,
        color="#ff7f0e",
        label="End to End",
    )
    ax.set_xlabel("#Threads per Party")
    ax.set_ylabel("Throughput (Million Labels/s)")
    ax.set_xticks(cores)
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(loc="best")
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=180)
    if show:
        plt.show()
    plt.close(fig)


def plot_breakdown(records: List[dict], output_path: Path, max_cores: int, show: bool) -> None:
    online_best = best_by_core(records, "online_tp")
    e2e_best = best_by_core(records, "e2e_tp")
    cores = [core for core in sorted(online_best) if core <= max_cores and core in e2e_best]
    if not cores:
        raise ValueError(f"No records at or below {max_cores} cores per role")

    online_tp = [online_best[c]["online_tp"] / 1e6 for c in cores]
    e2e_tp = [e2e_best[c]["e2e_tp"] / 1e6 for c in cores]
    setup_ms = [online_best[c]["setup_ms"] for c in cores]
    precompute_ms = [online_best[c]["precompute_ms"] for c in cores]
    online_ms = [online_best[c]["online_ms"] for c in cores]
    total_ms = [a + b + c for a, b, c in zip(setup_ms, precompute_ms, online_ms)]

    setup_bar = [tp * setup / total for tp, setup, total in zip(online_tp, setup_ms, total_ms)]
    precompute_bar = [tp * pre / total for tp, pre, total in zip(online_tp, precompute_ms, total_ms)]
    online_bar = [tp * online / total for tp, online, total in zip(online_tp, online_ms, total_ms)]

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(
        cores,
        setup_bar,
        width=0.8,
        bottom=[o + p for o, p in zip(online_bar, precompute_bar)],
        color="#9c755f",
        label="Setup",
    )
    ax.bar(cores, precompute_bar, width=0.8, bottom=online_bar, color="#4c78a8", label="Pre-computation")
    ax.bar(cores, online_bar, width=0.8, color="#59a14f", label="Online")
    ax.plot(cores, online_tp, marker="x", linewidth=1.8, color="#2ca02c", label="Online TP")
    ax.plot(cores, e2e_tp, marker="x", linestyle="--", linewidth=1.8, color="#ff7f0e", label="End-to-End TP")
    ax.set_xlabel("#Threads per Party")
    ax.set_ylabel("Throughput (Million Labels/s)")
    ax.set_xticks(cores)
    y_max = max(1, math.ceil(max(online_tp + e2e_tp)))
    ax.set_ylim(0, y_max)
    ax.set_yticks(list(range(0, y_max + 1)))
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(loc="best")
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=180)
    if show:
        plt.show()
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot LogVOLE throughput from Google Benchmark JSON files.")
    parser.add_argument("--input", type=Path, default=Path("results/logvole/n2p25/it1"))
    parser.add_argument("--glob", default="t*.json")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--breakdown-output", type=Path, default=None)
    parser.add_argument("--expected-labels", type=float, default=2**25)
    parser.add_argument("--max-cores", type=int, default=16)
    parser.add_argument("--show", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output = args.output or (args.input / "tp_vs_cores.png")
    breakdown_output = args.breakdown_output or (args.input / "online_tp_breakdown_vs_cores.pdf")

    records = load_records(args.input, args.glob)
    if not records:
        raise SystemExit(f"No benchmark records found under {args.input} matching {args.glob!r}")

    observed = sorted({record["n_labels"] for record in records})
    if any(abs(value - args.expected_labels) > 0.5 for value in observed):
        formatted = ", ".join(f"{int(value):,}" for value in observed)
        print(f"Warning: observed N_labels differs from expected value: {formatted}")

    plot_throughput(records, output, args.max_cores, args.show)
    plot_breakdown(records, breakdown_output, args.max_cores, args.show)

    online_best = best_by_core(records, "online_tp")
    receiver_best = best_by_core(records, "receiver_only_online_tp")
    e2e_best = best_by_core(records, "e2e_tp")
    print("core_per_role | online_phase_TP(M/s) | receiver_critical_TP(M/s) | end_to_end_TP(M/s)")
    for core in sorted(set(online_best) | set(receiver_best) | set(e2e_best)):
        if core not in online_best or core not in receiver_best or core not in e2e_best:
            continue
        print(
            f"{core:13d} | {online_best[core]['online_tp'] / 1e6:20.3f} | "
            f"{receiver_best[core]['receiver_only_online_tp'] / 1e6:23.3f} | {e2e_best[core]['e2e_tp'] / 1e6:18.3f}"
        )
    print(f"Wrote {output}")
    print(f"Wrote {breakdown_output}")


if __name__ == "__main__":
    main()
