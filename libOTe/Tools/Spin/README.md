# SPIN usage

Select `MultType::Spin` through the normal Silent OT configuration interface:

```cpp
sender.configure(requested, 2, 1, security, noise, osuCrypto::MultType::Spin);
receiver.configure(requested, 2, 1, security, noise, osuCrypto::MultType::Spin);
```

libOTe uses Turbo SPIN (`spin::Parameters::PacketRs8T64`) and rounds the code
size up to a multiple of 128. Positive requests below 16384 use that size, the
smallest certified length; only the requested outputs are returned. Zero requests are rejected. The default `MultType` is unchanged.
Enabling the SPIN dependency does not add a Silent VOLE profile.

## Dependency

SPIN 0.3 requires CMake 3.20+ and x86-64 with AVX2. `ENABLE_SPIN` defaults on
with Silent OT or Silent VOLE; explicit `ENABLE_SPIN=OFF` is respected.
Use an installed package through `CMAKE_PREFIX_PATH`, or let `FETCH_SPIN=ON`
or `FETCH_AUTO=ON` fetch it. For development, `LIBOTE_SPIN_SOURCE=/path/to/spin`
uses an editable source directory. External consumers link `oc::libOTe` after
`find_package(libOTe CONFIG REQUIRED COMPONENTS spin)`.

## Preparation and reuse

`configure()` selects parameters but does not construct the code or scratch.
The first compression prepares them lazily. To move preparation outside the
critical path, initialize the public members after configuring:

```cpp
// Optional: both endpoints must agree on the seed.
sender.mCodeSeed = receiver.mCodeSeed = agreedSeed;
sender.mSpin = std::make_unique<osuCrypto::SpinOtState>(
    sender.mRequestNumOts, sender.mCodeSeed, false, sender.mNoiseDist);
receiver.mSpin = std::make_unique<osuCrypto::SpinOtState>(
    receiver.mRequestNumOts, receiver.mCodeSeed, true, receiver.mNoiseDist);
sender.mB.reserve(sender.mNoiseVecSize);
receiver.mA.reserve(receiver.mNoiseVecSize);
receiver.mC.reserve(receiver.mNoiseVecSize); // Separate choices only.
```

The default seed needs no assignment. Buffers also accept moved `AlignedUnVector`
allocations. Preparation does not cover every protocol allocation.

- Regular noise reuses the full precomputed code. Changing `mCodeSeed` rebuilds
  the map at the next compression, retaining compatible scratch.
- Stationary noise selects banked heuristic setup and advances `mCodeSeed`
  after each compression. Refresh reorders the bank's routing regions and inner
  updates and draws fresh outer scalars; it retains the bank and scratch without
  constructing a full route each batch.
- Both parties must start with matching seeds and options. Block and separate-choice
  encoding use the same map within a batch.
- `clear()` deallocates the code, scratch, and protocol buffers. Reconfiguration
  also discards prepared state, so apply overrides afterward. Copying convenience
  methods can clear state; repeated in-place calls retain compatible preparation.

Banked refresh is a heuristic permutation family outside SPIN's uniform-setup
distance certificates. Under uniform setup, Turbo SPIN's minimum distance exceeds
N/10 at K=2^14, 2^16, ..., 2^26 (Lean-certified); other natural lengths are allowed
without a size-specific certificate. The noise configurator uses a linear-attack
tuning value of 0.25, matching BAA; this is not a claim of 25% minimum distance.
See the [SPIN library](https://github.com/ladnir/spin_codes) for construction and
certificate details.

## Generic coefficients

`SpinCode` compresses 2K coefficients to K using the same binary linear map:

```cpp
osuCrypto::SpinCode code({.message_size=65536,
                         .parameters=spin::Parameters::PacketRs8T64,
                         .route_seed=17, .inner_seed=29});
auto workspace = code.make_workspace<osuCrypto::block>();
code.transpose_inplace<osuCrypto::block>(buffer, workspace);
```

The buffer must contain exactly 2K elements; its first K elements receive the
result and its suffix remains unchanged. Use one workspace per simultaneous call.
`block` with `CoeffCtxGF2` or `CoeffCtxGF128` uses the optimized kernel.
Turbo SPIN transposes only these 128-bit elements: `make_workspace` rejects other
types and contexts with `std::invalid_argument`. The map acts on each bit lane
independently, so narrower values can travel in the low bits of a `block`;
Silent OT's separate choice bytes use this path. Prime fields are unsupported.

## Profiling

The existing frontend provides `-spinOtBench` and `-spinCompressionBench`.
For example:

```sh
frontend_libOTe -spinOtBench -logN 18 -regular -check
frontend_libOTe -spinOtBench -logN 18 -regular -trials 101 -nt
```

Omit `-regular` for stationary noise. `-check` runs a complete hashed-OT check
without timing. Timed runs report per-stage medians and throughput in C++;
`-paired` also measures the receiver serially and checks every batch.
Timings exclude initial setup, supplied base-correlation generation, and transport.
`-nt` selects streaming sender-output stores; `-consume` adds a sequential output
scan. Run benchmarks one at a time on an otherwise idle host.
