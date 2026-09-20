# SPIN in libOTe

SPIN provides a half-rate binary linear map. Its transpose compresses 2K
coefficients to K coefficients. libOTe uses the standalone `spin::spin` library;
it does not vendor another encoder implementation.

## Build

SPIN defaults on when Silent OT, Silent VOLE, LogVole, Foleage, RingLPN, or
bitpolymul is enabled. An explicit `ENABLE_SPIN=OFF` is respected.
This makes the encoder available; it does not change libOTe's default `MultType`
or add a Silent VOLE profile. SPIN currently requires x86-64
with AVX2; the library selects its AVX-512 kernels when available.
On unsupported platforms, disable SPIN explicitly. SPIN requires CMake 3.20+.

Dependency selection follows libOTe's normal pattern:

- `LIBOTE_SPIN_SOURCE=/path/to/spin` uses editable local sources, without fetching.
- Otherwise, an installed `spin` package can be found through `CMAKE_PREFIX_PATH`.
- `FETCH_SPIN=ON`, or `FETCH_AUTO=ON` without a SPIN-specific override, fetches
  the dependency when needed. `FETCH_SPIN=OFF` suppresses automatic fetching.

The fetcher obtains exactly commit `5abbb3312a9d02a2f7650d267c357920e041f955`
from [ladnir/spin_codes](https://github.com/ladnir/spin_codes) with Git depth one
and builds only `spin/`. It does not download historical experiment binaries.
The repository is public; fetching does not require GitHub credentials.
Sources are cached under `OC_THIRDPARTY_CLONE_DIR`. Build and install trees are
private to the libOTe build and keyed by revision and toolchain/configuration.
Modified source caches are rejected; use the source override for development.

```sh
cmake -S . -B out/build/spin -DENABLE_SILENTOT=ON -DFETCH_SPIN=ON
cmake --build out/build/spin --target spin_integration_tests -j2
ctest --test-dir out/build/spin -R 'SpinIntegration|SpinOptions' --output-on-failure
```

Other libOTe dependency and protocol options follow the ordinary build instructions.
The package exports `ENABLE_SPIN` and `libOTe_spin_FOUND`. An external consumer
can request `find_package(libOTe CONFIG REQUIRED COMPONENTS spin)` and link
`oc::libOTe`; the package resolves the `spin::spin` dependency.

## Coefficient contexts

```cpp
#include <libOTe/Tools/Spin/SpinCode.h>
osuCrypto::SpinCode code({.message_size=65536,
                         .parameters=spin::Parameters::T64S12R2,
                         .route_seed=17, .inner_seed=29});
auto blocks=code.make_workspace<osuCrypto::block>();
auto choices=code.make_workspace<osuCrypto::u8>();
code.transpose_inplace<osuCrypto::block>(block_buffer, blocks);
code.transpose_inplace<osuCrypto::u8>(choice_buffer, choices);
```

Each buffer contains exactly 2K elements. The first K elements receive the
transpose result; the suffix remains unchanged. Both calls apply the same map.
Use one workspace per simultaneous call. Workspace creation allocates scratch;
encoding reuses it.

`block` with exactly `CoeffCtxGF2` or `CoeffCtxGF128` uses the optimized SIMD
kernel. Other type/context combinations use the generic circuit with `ctx.plus`.
The generic path needs neither `operator^` nor a 128-bit representation.
It supports contiguous, default-constructible, copyable values, excluding
`bool` and proxy containers. Use bytes for separate choices.

For a custom context, use `make_workspace<F>(ctx)` and
`transpose_inplace<F, Ctx>(buffer, workspace)`. The workspace owns its context.
The context supplies `characteristicTwo<F>()`, `make<F>()`, and
`plus(result, lhs, rhs)`. Its addition must implement a characteristic-two
additive group. A false `characteristicTwo` result is rejected during setup.
Copying and adding values must not allocate if allocation-free encoding is required.

The dispatch is compile-time: there are no virtual calls, runtime callbacks,
or conversions of entire block buffers. The generic workspace owns a copy of
routing information; the optimized block workspace does not need that copy.
Prime-field arithmetic is not supported. No Silent VOLE profile is enabled by
this adapter; the coefficient interface is available for subsequent integration.

## Silent OT

Select `MultType::Spin` through the ordinary configuration interface:

```cpp
sender.configure(requested, 2, 1, security, noise, osuCrypto::MultType::Spin);
receiver.configure(requested, 2, 1, security, noise, osuCrypto::MultType::Spin);
```

No additional caller configuration is needed. `syndromeDecodingConfigure`
selects the PPRF parameters using a linear-attack tuning value of 0.25, matching BAA.
This heuristic setting is intended to keep linear attacks from determining the
overall parameters; it is not an estimate or certificate of 25% minimum distance.
The configuration formula alone does not establish security against other attacks.
For requests up to 2^16, SPIN uses T64S12R2 and rounds K up to a multiple of 8192.
The minimum code size is K=8192: smaller positive requests use that code and
return only the requested outputs. Zero requests are rejected.
Larger requests use T128S19 and round K up to a multiple of 16384.
Setup uses libOTe's `mCodeSeed`: its low 64 bits seed routing and its high 64 bits
seed the inner. Both endpoints derive the same configuration from the requested
size, current code seed, and ordinary protocol options.

Separately, 10% minimum distance has full certificates at K=2^16 for T64S12R2 and
K=2^18, 2^20, 2^22, 2^24 for T128S19. Their setup-failure margins are at least
49.32, 50.18, 50.06, 48.39, and 46.45 bits, respectively.
The source records in the SPIN repository are
`research/workstreams/spin_optimized/R2_RESULTS.md` and
`research/workstreams/inner_design/finite_migration/PAPER_RESULTS.md`.

Other natural lengths are allowed and use the same tuning value, without a
size-specific distance certificate. No setup-failure margin is extrapolated.
The internal policy can change without changing the caller interface.
Only routing representation and available memory limit the encoder size;
there is no certificate-range cap. The largest supported K is 2^31-16384.

Configuration prepares the first map and endpoint-owned scratch. After each
successful compression, both endpoints advance `mCodeSeed` with libOTe's existing
fixed-key hash. Before the next compression, SPIN rebuilds its plan and scratch
if the seed changed. Changing `mCodeSeed` explicitly is handled by the same check.
The preparation helper also checks code size, inner parameters, and workspace role
before reusing a plan.
Block and separate-choice encoding use one shared map before advancing the seed.
Reconfiguration creates a new plan, and `clear()` releases it. `split()` copies
the MultType but leaves the new endpoint to create its own scratch.
Packed and separate choices are supported. Output is truncated only after encoding,
from K to the requested number of OTs.
The existing copying convenience methods can call `clear()` after a batch.
Encoding itself remains allocation-free after preparation; repeated-batch timing
must account separately for rebuilding setup under the updated seed.

The PPRF expands into its exact domain. The adapter then restores the full 2K
buffer and zero-fills the uncovered suffix. If that suffix has p coordinates,
the noise configurator uses `floor(0.25 * 2K) - p` as an effective weight on
the active coordinates. This retains a conservative tail adjustment within the
heuristic model, not a bound derived from the distance certificate.
It increases the partition count until libOTe's
regular or stationary noise formula reaches the requested security parameter
(128 bits for Silent OT). At 128 bits, regular noise uses 128 partitions with
no uncovered suffix at every supported aligned size.

Protocol coroutines retain the endpoint-owned state across suspension.
The encoding helpers are synchronous; SIMD scratch is not stored in coroutine locals.

## Checks

`spin_integration_tests` compares block, byte, 64-bit, and custom context outputs.
The custom type has no XOR operator, and its stateful context records additions.
The test also rejects non-characteristic-two contexts and mismatched workspaces.
Protocol tests exercise the automatic parameter choices, non-power-of-two
requests, both choice layouts, repeated batches, regular and stationary noise,
and the malicious consistency check. Lifecycle tests cover setup reuse, changed
geometry, seed changes, and reconfiguration between SPIN and BAA.
Test base correlations are supplied locally;
these tests do not measure or exercise base-OT generation.

Large configuration-only tests cover requests above 2^24 and the routing limit
without allocating encoder buffers. The libOTe integration has not yet been
benchmarked.
Release tests passed with GCC 13.3 on Linux (pinned fetch) and MSVC 19.50 on
Windows (local source): all 24 protocol cases with three batches each, including
explicit seed changes, plus hashed random OT and the arithmetic and configuration
checks. The seed-lifecycle regression checks matching
descriptors, both seed halves, synchronized hash advancement, and OT correlations.

`SpinOptions` checks defaults for each code-based feature, explicit OFF, local
source selection, and the fetch overrides without compiling dependencies.

The pinned public snapshot was fetched, built, and tested through
`FETCH_SPIN=ON` on Linux. CI runs the integration and option tests on Linux
and Windows, and exercises an installed-package consumer on Linux. The
ARM/macOS job explicitly disables the currently x86-only dependency.

Known upstream issue: at this pin, SPIN's standalone Windows CI with MSVC
19.51 fails the packed-bit forward comparison (`spin_api`). The same standalone
test passes locally with MSVC 19.50; the cause remains unresolved. libOTe uses
the transpose API, not packed-bit forward encoding. Do not interpret local
integration results as validation of that newer compiler.

The separate `libOTe_Tests/spin_consumer` project passed a build-tree package
consumer check: it resolves `libOTe`, links the SPIN dependency transitively,
configures a small OT request, and compares optimized and generic transpose
outputs on nonzero inputs. To repeat it:

```sh
cmake -S libOTe_Tests/spin_consumer -B out/build/spin-consumer \
  -DCMAKE_BUILD_TYPE=Release \
  -DlibOTe_DIR="$PWD/out/build/spin" \
  -Dspin_DIR="$PWD/out/build/spin/spin" \
  -DCMAKE_PREFIX_PATH=/path/to/installed/dependencies
cmake --build out/build/spin-consumer -j2
ctest --test-dir out/build/spin-consumer --output-on-failure
```

The example above assumes a local-source build. For an installed or fetched
SPIN package, set `spin_DIR` to its `lib/cmake/spin` directory (reported in the
libOTe build's CMake cache).
CMake configuration with `ENABLE_SPIN=OFF` also passed without a SPIN dependency.
