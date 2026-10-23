#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${SPARSE_DPF_BUILD:-"$repo/out/build/rev-width-slack-min"}
profile=${1:-rev3}
cpu=${2:-0}
cd "$build"
# Frozen binaries from the original comparison, not the diagnostic binary.
# Warm up each once, then perform ABBA and BAAB. Never overlap benchmarks.
echo 'variant,profile,logN,setup_ms,median_expand_ms,min_expand_ms,max_expand_ms,expand_bytes,result'
taskset -c "$cpu" ./cached_internal_before "$profile" before_warmup 20
taskset -c "$cpu" ./cached_internal_after "$profile" after_warmup 20
for mode in before after after before after before before after; do
    taskset -c "$cpu" "./cached_internal_$mode" "$profile" "$mode" 20
done
