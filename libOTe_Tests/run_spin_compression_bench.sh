#!/usr/bin/env bash
set -euo pipefail
exe=${1:?spin_compression_bench executable}
out=${2:?results directory}
trials=${3:-101}
mkdir -p "$out"
exec 8>/tmp/prindal-addition-encoder-benchmark.lock
exec 9>/tmp/bare-spin-benchmark.lock
exec 7>/tmp/hypercat-benchmark.lock
flock -n 8
flock -n 9
flock -n 7
for repeat in 1 2 3; do
    for family in fixed frozen fresh; do
        for context in bare copy leaves resident stream stream-nt pipeline; do
            taskset -c 15 "$exe" "$family" "$context" "$trials" \
                > "$out/$family-$context-$repeat.json"
        done
    done
done
