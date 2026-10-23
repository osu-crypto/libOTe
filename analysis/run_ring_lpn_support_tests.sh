#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${RING_LPN_BUILD:-"$repo/out/build/rev-width-slack-min"}
cd -- "$build"
objects=(
    libOTe_Tests/CMakeFiles/libOTe_Tests.dir/RingLpnSupport_Tests.cpp.o
    libOTe_Tests/CMakeFiles/libOTe_Tests.dir/RingLpn_Tests.cpp.o
)
cmake --build . -j 3 --target libOTe "${objects[@]}"
compile=$(ninja -t commands "${objects[0]}" | tail -n 1)
compile=${compile%% -MD *}
eval "$compile -c '$repo/analysis/ring_lpn_support_driver.cpp' -o ring_lpn_support_driver.o"
c++ -pthread -o ring_lpn_support_tests ring_lpn_support_driver.o \
    "${objects[@]}" -Wl,--start-group \
    cryptoTools/tests_cryptoTools/libtests_cryptoTools.a \
    libOTe/liblibOTe.a cryptoTools/cryptoTools/libcryptoTools.a \
    coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a -Wl,--end-group
./ring_lpn_support_tests "$@"
