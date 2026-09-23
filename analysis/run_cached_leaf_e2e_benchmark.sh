#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${SPARSE_DPF_BUILD:-"$repo/out/build/rev-width-slack-min"}
baseline=$(mktemp -d "$build/leaf-rekey-baseline.XXXXXX")
# Only the three headers changed by leaf rekeying are rolled back. Keep all
# earlier correctness fixes from the current worktree in both executables.
git -C "$repo" archive b2e9b7b5c5ab60adf800ba56b087c0d1b4330812 \
    libOTe/Dpf/CachedDpfExpansion.h libOTe/Dpf/RevCuckooDmpf.h \
    libOTe/Dpf/WaterfallDmpf.h | tar -x -C "$baseline"
cd -- "$build"
compile=$(ninja -t commands libOTe_Tests/CMakeFiles/libOTe_Tests.dir/Dpf_Tests.cpp.o | tail -n 1)
compile=${compile%% -MD *}
for variant in before after; do
    overlay=""
    if [[ "$variant" == before ]]; then overlay="-I'$baseline'"; fi
    compiler=${compile%% *}
    flags=${compile#* }
    eval "$compiler $overlay $flags -I'$repo/libOTe/Dpf' -g0 -c '$repo/analysis/cached_leaf_e2e_benchmark.cpp' -o cached_leaf_e2e_$variant.o"
    c++ -pthread -o cached_leaf_e2e_$variant cached_leaf_e2e_$variant.o \
        -Wl,--start-group libOTe/liblibOTe.a cryptoTools/cryptoTools/libcryptoTools.a \
        coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a -Wl,--end-group
done
echo "variant,profile,logN,setup_ms,median_expand_ms,min_expand_ms,max_expand_ms,expand_bytes,result"
# Never overlap benchmarks. ABBA ordering limits one-way thermal/time drift.
for profile in waterfall4 waterfall3 rev3; do
    for variant in before after after before; do
        ./cached_leaf_e2e_$variant "$profile" "$variant" "${1:-20}"
    done
done
