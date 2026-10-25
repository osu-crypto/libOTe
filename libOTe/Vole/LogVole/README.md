# LogVole

LogVole implements semi-honest chosen-input VOLE over a batching prime `p`.
The receiver chooses `x`, the sender chooses `Delta`, and the output satisfies
`a[i] = b[i] + x[i] * Delta mod p`. This implementation follows the Ring-LWE
construction of Lucien K. L. Ng, Peter Rindal and Akash Shah,
*LogVOLE: Succinct and Efficient Chosen-Input VOLE for ZK and Beyond*.

## Build

LogVole uses libOTe's C++20 toolchain, its pinned cryptoTools/coproto dependencies,
and stock Microsoft SEAL 4.1.1 (`SEAL::seal`). libOTe's normal `FETCH_AUTO` flow
fetches SEAL. An existing installation can be selected with `SEAL_DIR` and
`FETCH_SEAL=OFF`. HEXL and Python scientific packages are not required.

From the libOTe repository root:

```sh
git submodule update --init --recursive
python3 build.py --all --boost --sodium --par=8 -DENABLE_LOGVOLE=ON
./out/build/linux/frontend/frontend_libOTe -u
```

`ENABLE_LOGVOLE=OFF` omits LogVole. CUDA is separately optional and defaults to
OFF. CUDA builds require CMake 3.18 or newer and a compatible CUDA/host compiler
pair. Select the architecture for your device, for example `90` for H100/H200:

```sh
python3 build.py --all --boost --sodium --par=8 \
    -DENABLE_LOGVOLE=ON -DENABLE_LOGVOLE_CUDA=ON \
    -DCMAKE_CUDA_ARCHITECTURES=90
```

The standard `CMAKE_CUDA_COMPILER`, `CMAKE_CUDA_HOST_COMPILER`, and
`CMAKE_CUDA_ARCHITECTURES` settings are respected. `LOGVOLE_CUDA_ARCH` is an
optional fallback when `CMAKE_CUDA_ARCHITECTURES` was not set. Installed CPU
packages do not require CUDA; installed CUDA packages discover CUDAToolkit for
their exported `CUDA::cudart` link dependency.

## Protocol modes and API

The public wrappers are `osuCrypto::LogVoleSender` and `LogVoleReceiver` in
`LogVole.h`. Both parties call
`configure(n, plaintextModulusBits, numThreads, setting, mode)`, use the actual
prime returned by `modulus()`, and then perform offline setup and online queries.
Both peers must use the same setting, online mode, and updated wire format.
The added mode metadata changes setup framing from the upstream base revision.

| Setting | Online mode | CPU | CUDA |
| --- | --- | --- | --- |
| `CivoleSetting::GoldenSeed` | `OnlineMode::Interactive` (default) | Yes | Yes |
| `CivoleSetting::NoGoldenSeed` | `OnlineMode::Interactive` | Yes | Yes |
| `CivoleSetting::NoGoldenSeed` | `OnlineMode::NonInteractive` | Yes | Yes |

Non-interactive mode requires NoGoldenSeed. Its fixed parameters choose a 52-bit
plaintext prime. GoldenSeed with non-interactive mode is rejected.

For interactive use, run `sender.offline(delta, senderPrng, senderSocket)` with
`receiver.offline(receiverSocket)`, then run
`sender.send(keys, senderPrng, senderSocket)` with
`receiver.receive(x, macs, receiverPrng, receiverSocket)`.
Offline setup is reusable; sequential online calls consume distinct session IDs.
Wrappers are move-only to prevent accidental copying of live session state.

In non-interactive mode the sender can finish offline setup into a
`coproto::BufferingSocket` and publish its outbound bytes before a receiver exists.
The receiver imports those public-key bytes during offline setup. It can then
finish each online query locally, producing MACs and one outbound message without
receiving a sender reply. The sender later processes that message to obtain keys.
Use distinct session IDs across clients sharing a public key. The regression
test `LogVole_Civole_NonInteractivePublicKeyAndSequentialQueries` demonstrates
this deferred lifecycle and rejects replay.

CUDA applications include `cuda/LogVoleGpuProtocol.h` and call
`LogVole::gpu::setEnabled(true)` before configuration. Check `gpu::enabled()`
when GPU execution is required. CPU remains available in a CUDA build via
`setEnabled(false)`. Set `mKeepOutputOnDevice` to keep outputs in device memory;
`outputDevice()` and `outputDeviceCount()` expose the resulting device token.
The receiver can also supply its own input token through `mInputDevice`.
The two parties retain separate protocol state and communicate through coproto
socket messages.

`LogVoleGarbled.h` provides three-component additive 128-bit garbled labels.
`LogVoleZk.h` provides multiplication-circuit and matrix-product checks on top of
the correlations. Neither API changes the underlying semi-honest VOLE threat
model. Garbled labels are additive field tuples, not XOR/free-XOR blocks.

Matrix checks follow the public-product workload in Section 12.2 and Table 6
of the October 17 paper: every one of the `n*n` length-`n` inner products is
evaluated directly. Independent per-entry coefficients batch those equations;
there is no Freivalds-style matrix projection. CPU checking packs B's columns
contiguously and accumulates exact products in bounded 128-bit chunks,
reducing once per chunk. It dispatches to AVX-512 IFMA on compatible CPUs for
51- and 54-bit fields, with an exact scalar fallback. Set
`LV_CPU_VECTOR_MATMUL=0` to exercise that fallback. Unweighted inner products
are reused across repetitions, giving CPU work `O(n^3 + repetitions*n^2)`;
CUDA currently performs `O(repetitions*n^3)` work. The private VOLE input
contains A, B, then one fresh mask per repetition, totaling `2*n*n + repetitions` entries.

The application supplies the expected public C explicitly to
`ZkMatMulVerifier::verify(publicProduct, prng, socket)`. The verifier validates
and snapshots its `n*n` canonical field elements before the online exchange.
`zkMatMulWitness` returns the private witness and public product separately;
`zkMatMulFillProduct` and its CUDA counterpart also have separate product
outputs. Product generation belongs to statement preparation, outside proof
timing. Public C is common input and is not transmitted inside the proof.

Matrix checks send one 16-byte response per repetition.
`ZkMatMulProver::mLastProofs` and
`ZkMatMulVerifier::mLastValues` expose every equation; the singular diagnostic
members expose the first. Low-level callers use the vector overloads of
`zkMatMulProverResponse` and `zkMatMulVerifierValue`, then `zkMatMulAccept`.
The verifier-value functions require the public product immediately after the
key span. Challenges contain `repetitions*n*n` coefficients.
The scalar overloads accept one repetition. Both peers must use the updated
layout and direct inner-product algorithm. Each equation receives its own fresh mask.

Independent repetitions prevent residuals from cancelling across equations.
Their residual batching error is at most `(1/p)^repetitions`, but all equations
share the same base-field `Delta`; this does not amplify authentication beyond
the field-size limit or change the underlying semi-honest threat model.

## Examples and correctness tests

```sh
B=./out/build/linux/frontend/frontend_libOTe
$B -logvole -n 65539 -t 2
$B -logvole -n 65539 -t 2 -noninteractive 1
$B -logvole -n 65539 -t 2 -nogold 1
# The same three examples accept -gpu 1 in a CUDA build.
$B -logvole -n 65539 -t 2 -gpu 1
$B -logvole -n 65539 -t 2 -noninteractive 1 -gpu 1

$B -u LogVole
$B -u LogVole -gpu 1
$B -u
```

The local example verifies every output against the VOLE relation. libOTe's
usual `-r` and `-ip` options run separate roles using coproto Boost sockets.
The mode tests exercise partial CRT batches, repeated queries, moved sessions,
and GPU output tokens. They fail if `-gpu 1` cannot produce device outputs.

Standalone CUDA arithmetic checks are built independently:

```sh
cmake -S libOTe_Tests/LogVole/tests/cuda -B out/build/logvole-cuda-tests \
    -DCMAKE_CUDA_ARCHITECTURES=90
cmake --build out/build/logvole-cuda-tests --parallel 8
ctest --test-dir out/build/logvole-cuda-tests --output-on-failure
```

The source extraction includes library code, public examples, correctness tests,
and build integration. Research drivers, parameter-search scripts, datasets,
plots, profiling outputs, and benchmark results are excluded.
