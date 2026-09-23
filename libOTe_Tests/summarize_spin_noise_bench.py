"""Summarize serial regular/stationary sender runs; never launches benchmarks."""
import hashlib
import json
import statistics
import sys
from pathlib import Path


def summarize(directory, mode):
    records = []
    geometries = []
    receipts = {}
    for repeat in (1, 2, 3):
        path = directory / f"{mode}-{repeat}.jsonl"
        raw = path.read_bytes()
        geometry, sender, checks = [json.loads(line) for line in raw.splitlines()]
        assert geometry["geometry"] and not geometry["paired_resident"]
        assert sender["party"] == "sender" and sender["K"] == geometry["K"]
        assert geometry["streaming_stores"] == mode.startswith("nt")
        assert geometry["consume_output"] == mode.endswith("-read")
        assert checks["initial_hashed_ots_verified"]
        regular = geometry["noise"] == "regular"
        assert checks["fixed_full_code_reused"] == regular
        assert checks["fresh_code_each_batch"] != regular
        assert checks["cached_leaves_reused"] != regular
        assert len(sender["samples"]) == 101
        for index, key in enumerate((
            "expansion_ms" if regular else "leaves_ms",
            "compress_ms" if regular else "compress_refresh_ms",
            "hash_ms", "total_ms", "consume_ms",
        )):
            assert abs(statistics.median(x[index] for x in sender["samples"])
                       - sender[key]) < 1e-6, (path, key)
        assert abs(sender["million_ot_per_s"] - sender["K"] / (1000 * sender["total_ms"])) < 1e-5
        geometries.append(geometry)
        records.append(sender)
        receipts[path.name] = hashlib.sha256(raw).hexdigest()
    assert all(g == geometries[0] for g in geometries)
    geometry = geometries[0]
    med = lambda key: statistics.median(r[key] for r in records)
    regular = geometry["noise"] == "regular"
    return {
        "geometry": geometry,
        "expansion_ms": med("expansion_ms" if regular else "leaves_ms"),
        "compression_ms": med("compress_ms" if regular else "compress_refresh_ms"),
        "hash_ms": med("hash_ms"),
        "consume_ms": med("consume_ms"),
        "total_ms": med("total_ms"),
        "million_ot_per_s": geometry["K"] / (1000 * med("total_ms")),
        "process_total_ms": [r["total_ms"] for r in records],
        "receipts": receipts,
    }


if __name__ == "__main__":
    root = Path(sys.argv[1])
    print(json.dumps({
        name: {mode: summarize(root / name, mode)
               for mode in ("cached", "nt", "cached-read", "nt-read")}
        for name in ("k18", "stationary-k18", "k20")
    }, indent=2))
