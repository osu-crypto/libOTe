#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${SPARSE_DPF_BUILD:-"$repo/out/build/rev-width-slack-min"}
cd -- "$build"
test_objects=(
    libOTe_Tests/CMakeFiles/libOTe_Tests.dir/Dpf_Tests.cpp.o
    libOTe_Tests/CMakeFiles/libOTe_Tests.dir/Waterfall_Tests.cpp.o
    libOTe_Tests/CMakeFiles/libOTe_Tests.dir/RevCuckoo_Tests.cpp.o
)
cmake --build . -j 3 --target libOTe "${test_objects[@]}"

# Reuse the configured compiler and feature flags, without rebuilding the
# multi-gigabyte aggregate test archive. Ninja's command is local build data.
compile=$(ninja -t commands "${test_objects[0]}" | tail -n 1)
compile=${compile%% -MD *}
eval "$compile -c '$repo/analysis/sparse_dpf_mask_driver.cpp' -o sparse_dpf_mask_driver.o"
c++ -pthread -o sparse_dpf_mask_tests sparse_dpf_mask_driver.o \
    "${test_objects[@]}" -Wl,--start-group \
    cryptoTools/tests_cryptoTools/libtests_cryptoTools.a \
    libOTe/liblibOTe.a cryptoTools/cryptoTools/libcryptoTools.a \
    coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a -Wl,--end-group
./sparse_dpf_mask_tests "$@"
