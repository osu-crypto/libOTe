# LogVOLE Clean Submission Artifact

This folder contains a standalone LogVOLE implementation artifact with a public
interactive CI-VOLE wrapper over `Z_p`:

- `include/logvole/` and `src/`: protocol implementation and required support code.
- `include/logvole/civole_protocol.hpp`: public staged CI-VOLE API.
- `examples/civole_example.cpp`: minimal two-party in-memory example.
- `examples/civole_socket_example.cpp`: two-process TCP sender/receiver example.
- `tests/test_logvole.cpp`: correctness tests.
- `bench/bench_logvole.cpp`: Google Benchmark harness.
- `scripts/logvole_optimizer.py`: parameter search.
- `scripts/logvole_sparse_repair_optimizer.py`: sparse-repair analysis.
- `run_bench`: standalone configure/build/run benchmark entrypoint.
- `scripts/run_logvole_bench.py`: benchmark sweep helper.
- `scripts/plot_logvole.py`: plot generation from benchmark JSON.

## Dependencies

Required:

- CMake 3.16 or newer
- C++17 compiler
- Microsoft SEAL 4.1.1
- OpenSSL development package, if the SEAL build uses AES-CTR-DRBG
- GoogleTest, for correctness tests
- Google Benchmark, for benchmarks
- Python 3 with `matplotlib`, for plots and optimizer scripts

Install SEAL, GoogleTest, and Google Benchmark system-wide, or pass their CMake
package/source locations at configure time.

## Build and Test

From this directory:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DSEAL_DIR=/path/to/seal/cmake \
  -DLOGVOLE_GTEST_SOURCE_DIR=/path/to/googletest \
  -DLOGVOLE_BENCHMARK_SOURCE_DIR=/path/to/google-benchmark

cmake --build build --target logvole_correctness_tests logvole_bench -j
ctest --test-dir build -R LogVOLECorrectnessTests --output-on-failure
```

If GoogleTest and Google Benchmark are installed as CMake packages, omit
`LOGVOLE_GTEST_SOURCE_DIR` and `LOGVOLE_BENCHMARK_SOURCE_DIR`.

## Public CI-VOLE API

The public wrapper follows the interactive CI-VOLE functionality:

- `run_civole_sender_offl(...)` and `run_civole_receiver_offl(...)`
- `run_civole_sender_releasek_int(...)`
- `run_civole_receiver_setx_int(...)`
- `run_civole_sender_release_int(...)`

Callers provide and receive scalar field vectors as `std::uint64_t` values in
`Z_p`. The modulus `p` is resolved from the same RLWE parameter profile used by
the library:

```cpp
auto params = logvole::make_default_civole_params();
auto p = logvole::resolve_civole_modulus(params.value());
```

The sender calls `releasek_int(sid)` to obtain the protocol-sampled key vector
`k`. The receiver calls `setx_int(sid, x)` while the sender calls
`release_int(sid)`, and the receiver obtains `m = k + x * Delta mod p`.

## Run The Example

```bash
cmake --build build --target civole_example -j
build/bin/civole_example
```

## Run The Two-Process TCP Example

Build the socket example:

```bash
cmake --build build --target civole_socket_example -j
```

Start the receiver in one terminal:

```bash
build/bin/civole_socket_example --role receiver --host 127.0.0.1 --port 29090
```

Then start the sender in another terminal:

```bash
build/bin/civole_socket_example --role sender --host 127.0.0.1 --port 29090
```

The receiver listens on `port` for `offl` and on `port + 1` for
`setx_int`/`release_int`. The sender connects to those two ports in sequence.

## Run Benchmarks

Configure, build, and run the default standalone benchmark:

```bash
./run_bench
```

Run a larger preset and save JSON:

```bash
./run_bench --preset n2p25 --threads 4 --iterations 1 \
  --save-json results/logvole/n2p25/it1/t4.json
```

Run the built benchmark directly:

```bash
LOGVOLE_BENCH_SENDER_THREADS=4 \
LOGVOLE_BENCH_RECEIVER_THREADS=4 \
LOGVOLE_BENCH_ITERATIONS=1 \
LOGVOLE_BENCH_PRECOMPUTE=1 \
build/bin/logvole_bench --benchmark_filter='^BM_LogVOLE_N2Pow25(/.*)?$' \
  --benchmark_format=json \
  --benchmark_out=results/logvole/n2p25/it1/t4.json \
  --benchmark_out_format=json
```

Or run a thread sweep:

```bash
scripts/run_logvole_bench.py --build-dir build \
  --threads 1,2,4,8,16 --iterations 1 --precompute
```

Useful benchmark presets are `2level`, `3level`, `5level`, `n2p24`, and
`n2p25`.

## Generate Plots

After producing JSON files such as `results/logvole/n2p25/it1/t4.json`, run:

```bash
python3 -m pip install matplotlib
scripts/plot_logvole.py --input results/logvole/n2p25/it1
```

This writes:

- `results/logvole/n2p25/it1/tp_vs_cores.png`
- `results/logvole/n2p25/it1/online_tp_breakdown_vs_cores.pdf`

## Parameter Search

```bash
scripts/logvole_optimizer.py
scripts/logvole_sparse_repair_optimizer.py
```

Both scripts print candidate parameters and derived estimates. Edit the
`DEFAULT_*` values near the bottom of each script to match a different target
label count or security setting.
