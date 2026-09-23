#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${SPARSE_DPF_BUILD:-"$repo/out/build/rev-width-slack-min"}
baseline=${INTERNAL_NODE_BASELINE:-"$build/cached_internal_before"}
test -x "$baseline" || { echo "Supply the frozen pre-internal-rekey benchmark binary via INTERNAL_NODE_BASELINE." >&2; exit 1; }
cd -- "$build"
compile=$(ninja -t commands libOTe_Tests/CMakeFiles/libOTe_Tests.dir/Dpf_Tests.cpp.o | tail -n 1)
compile=${compile%% -MD *}
eval "$compile -g0 -c '$repo/analysis/cached_leaf_e2e_benchmark.cpp' -o cached_internal_after.o"
c++ -pthread -o cached_internal_after cached_internal_after.o \
    -Wl,--start-group libOTe/liblibOTe.a cryptoTools/cryptoTools/libcryptoTools.a \
    coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a -Wl,--end-group
echo "variant,profile,logN,setup_ms,median_expand_ms,min_expand_ms,max_expand_ms,expand_bytes,result"
# Both executables already include leaf rekeying. Only internal rekeying differs.
# All runs are sequential. Never run concurrently with another benchmark.
for profile in waterfall4 waterfall3 rev3; do
    "$baseline" "$profile" before "${1:-20}"
    ./cached_internal_after "$profile" after "${1:-20}"
    ./cached_internal_after "$profile" after "${1:-20}"
    "$baseline" "$profile" before "${1:-20}"
done

