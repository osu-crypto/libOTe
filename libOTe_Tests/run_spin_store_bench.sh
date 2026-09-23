#!/usr/bin/env bash
set -euo pipefail
exe=${1:?spin_stationary_bench executable}
out=${2:?results directory}
exponent=${3:-18}
trials=${4:-101}
extra=("${@:5}")
mkdir -p "$out"
exec 8>/tmp/prindal-addition-encoder-benchmark.lock
exec 9>/tmp/bare-spin-benchmark.lock
exec 7>/tmp/hypercat-benchmark.lock
flock -n 8
flock -n 9
flock -n 7
for repeat in 1 2 3; do
    modes=(cached nt cached-read nt-read)
    if ((repeat % 2 == 0)); then modes=(nt-read cached-read nt cached); fi
    for mode in "${modes[@]}"; do
        flags=()
        case "$mode" in
            nt) flags=(nt);;
            cached-read) flags=(consume);;
            nt-read) flags=(nt consume);;
        esac
        taskset -c 15 "$exe" "$exponent" "$trials" "${flags[@]}" "${extra[@]}" \
            > "$out/$mode-$repeat.jsonl"
    done
done
