#!/usr/bin/env bash
set -euo pipefail
exe=${1:?path to spin_stationary_bench}
out=${2:?output directory}
exponent=${3:-18}
trials=${4:-31}
extra=("${@:5}")
mkdir -p "$out"
# Shared with the SPIN, encoder, and Hypercat measurement campaigns.
exec 8>/tmp/prindal-addition-encoder-benchmark.lock
exec 9>/tmp/bare-spin-benchmark.lock
exec 7>/tmp/hypercat-benchmark.lock
flock -n 8
flock -n 9
flock -n 7
for repeat in 1 2 3; do
    taskset -c 15 "$exe" "$exponent" "$trials" "${extra[@]}" > "$out/m${exponent}-r${repeat}.jsonl"
done
