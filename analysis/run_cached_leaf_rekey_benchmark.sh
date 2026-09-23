#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${SPARSE_DPF_BUILD:-"$repo/out/build/rev-width-slack-min"}
cd -- "$build"
compile=$(ninja -t commands libOTe_Tests/CMakeFiles/libOTe_Tests.dir/Dpf_Tests.cpp.o | tail -n 1)
compile=${compile%% -MD *}
eval "$compile -c '$repo/analysis/cached_leaf_rekey_benchmark.cpp' -o cached_leaf_rekey_benchmark.o"
c++ -pthread -o cached_leaf_rekey_benchmark cached_leaf_rekey_benchmark.o \
    -Wl,--start-group cryptoTools/cryptoTools/libcryptoTools.a \
    coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a -Wl,--end-group
# Never run concurrently with another benchmark.
./cached_leaf_rekey_benchmark

