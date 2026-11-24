# SPIN usage

Select `MultType::Spin` through the normal Silent OT configuration interface:

```cpp
sender.configure(requested, 2, 1, security, noise, osuCrypto::MultType::Spin);
receiver.configure(requested, 2, 1, security, noise, osuCrypto::MultType::Spin);
```

libOTe uses Turbo SPIN (`spin::Parameters::PacketRs8T64`). The code size K is
the request rounded up to a multiple of 128, and at least 8192 so the noise
configuration has room for its partitions; only the requested outputs are
returned. Zero requests are rejected. The default `MultType` is unchanged, and
SPIN adds no Silent VOLE profile.

## Dependency and platforms

SPIN 0.4.2 needs CMake 3.20+ and a little-endian target. It runs on every CPU:
SPIN picks AVX-512, AVX2+GFNI or AVX2 kernels on x86-64, NEON on AArch64
(including Apple silicon), and a portable C++ kernel elsewhere, all computing
the same map. `ENABLE_SPIN` defaults on with Silent OT or Silent VOLE; explicit
`ENABLE_SPIN=OFF` is respected. Use an installed package through
`CMAKE_PREFIX_PATH`, or let `FETCH_SPIN=ON` or `FETCH_AUTO=ON` fetch it. For
development, `LIBOTE_SPIN_SOURCE=/path/to/spin` uses a source directory.
External consumers link `oc::libOTe` after
`find_package(libOTe CONFIG REQUIRED COMPONENTS spin)`.

On x86-64, configure with `-DENABLE_VAES=ON` where the CPU has VAES: the GGM
expansion and sender hash otherwise use the 128-bit AES-NI paths.

## Interface

[`SpinCode.h`](SpinCode.h) holds everything libOTe adds on top of the SPIN
library; `SpinConfigure` (`ConfigureCode.h`) picks the noise parameters.

```cpp
osuCrypto::SpinCode code(requested, seed, noise);  // one party's encoder
code.transpose(blocks);   // 2K blocks -> first K, in place
code.transpose(choices);  // 2K choice bytes (0 or 1) -> first K, in place
```

Regular noise uses the full seeded setup. Stationary noise uses SPIN's banked
heuristic refresh, which reorders a fixed bank's routing regions and inner
updates and draws fresh outer scalars per seed, without allocating. Banked
codes are outside SPIN's uniform-setup distance certificates (Turbo SPIN's
minimum distance exceeds N/10 at K = 2^14, 2^16, ..., 2^26 under uniform
setup). The noise configurator's linear-attack tuning value of 0.25 matches
BAA; it is not a claim of 25% minimum distance. See the
[SPIN library](https://github.com/ladnir/spin_codes) for the construction and
certificates.

Choice bytes go through SPIN's bit-vector transpose: the same binary map on
one bit per position, about a third of the record cost at K = 2^18.

## Preparation

The sender and receiver hold a `std::optional<SpinCode> mSpin`, prepared at the
first compression and reseeded (not rebuilt) while the size and noise
distribution match. To move preparation out of the critical path, emplace it
after `configure()`; both parties must use the same seed:

```cpp
sender.mCodeSeed = receiver.mCodeSeed = agreedSeed; // optional
sender.mSpin.emplace(sender.mRequestNumOts, sender.mCodeSeed, sender.mNoiseDist);
receiver.mSpin.emplace(receiver.mRequestNumOts, receiver.mCodeSeed, receiver.mNoiseDist);
```

Regular noise keeps the code fixed across batches. Stationary noise advances
`mCodeSeed` after each compression and refreshes in place. `configure()` and
`clear()` release the encoder.

## Profiling

```sh
frontend_libOTe -spinOtBench -logN 18 -regular -check
frontend_libOTe -spinOtBench -logN 18 -regular -trials 101 -nt
```

Omit `-regular` for stationary noise. `-check` runs a complete hashed-OT check
and prints a fixed-seed output digest, so two builds can be compared bit for
bit. Timed runs report per-stage medians; `-paired` also measures the receiver
and checks every batch; `-nt` selects streaming sender-output stores;
`-consume` adds a sequential output scan. `-spinCompressionBench` isolates the
compression stage. Timings exclude initial setup, base correlations and
transport. Run benchmarks one at a time on an otherwise idle host.
