#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${SPARSE_DPF_BUILD:-"$repo/out/build/rev-width-slack-min"}
cd "$build"
compile=$(ninja -t commands libOTe_Tests/CMakeFiles/libOTe_Tests.dir/Dpf_Tests.cpp.o | tail -n 1)
compile=${compile%% -MD *}
eval "$compile -g0 -c '$repo/analysis/internal_node_probe.cpp' -o internal_node_probe.o"
c++ -pthread -o internal_node_probe internal_node_probe.o \
    -Wl,--start-group libOTe/liblibOTe.a cryptoTools/cryptoTools/libcryptoTools.a \
    coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a -Wl,--end-group
echo 'kind,profile,trial,mode,setup_ms,total_ms,leaf_ms,update_ms,other_ms,result'
./internal_node_probe "${1:-rev3}" "${2:--1}" "${3:-stages}"
