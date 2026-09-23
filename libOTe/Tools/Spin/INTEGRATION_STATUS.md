# Prepared SPIN integration checkpoint

## Implemented

- Ordinary `MultType::Spin` configuration and generic characteristic-two contexts.
- Reusable public `mSpin` state and caller-owned endpoint buffers; `configure`
  stays cheap and `clear` releases allocations.
- Full setup for regular noise; persistent permutation bank and cheap seed refresh
  for stationary noise. Both endpoints advance the same code seed per batch.
- Optional 256-bit VAES in cryptoTools (`ENABLE_VAES=ON`, default OFF).
- Optional non-temporal sender hash stores; ordinary cached stores remain default.
- SPIN package version 0.2 and matching libOTe minimum dependency version,
  so an older installed package is not silently accepted without PreparedEncoder.

## Validation completed

- GCC 13 VAES ON and OFF: SPIN integration and option tests.
- MSVC Release: SPIN integration tests.
- Paired stationary checks: all hashed OT messages across multiple refreshes,
  including streaming stores, tails, and immediate output consumption.
- Separate CMake consumer: build-tree libOTe export plus an **installed SPIN 0.2**
  package. Both full and banked setup pass three seed changes, comparing the
  optimized block path with the generic u64 path and retaining workspaces.
- Fully installed consumer: a separate GCC 13 Release build with VAES, real
  SimplestOT/Edwards25519, DPF, and RingLPN enabled builds and installs libOTe,
  cryptoTools, and their test archives. The consumer resolves installed SPIN 0.2,
  libOTe, and cryptoTools, then passes the same refresh/context checks.
  SpinIntegration and SpinOptions also pass in this release configuration.
- Paper: leads with regular-noise sender performance (89.0 million hashed OTs/s
  at K=2^18), with stationary mode separate (84.5 million). Stage breakdowns,
  timing exclusions, and heuristic-family scope are explicit. Both PDFs compile and changed pages were
  visually checked. Fixed precomputed encoder measurements remain separate.

## Published dependencies

- SPIN 0.2: `f2010e03d2dbe5003e90c89ba346c743793536a6` on `ladnir/spin_codes` main.
- cryptoTools VAES: `cc54d946a7643795b5f523fe235392de8271a5b3` on
  `ladnir/cryptoTools` master. AES profiling uses the existing
  `frontend_cryptoTools -aesBench`; there is no separate benchmark executable.
- libOTe pins both exact commits. No raw experiment data is included.

## Public-pin validation (2026-09-23)

A fresh shallow clone of libOTe commit
`c575f1606f648e4b029b9cead060472cb1539b9f` fetched both published dependencies.
SPIN was built through `FETCH_SPIN=ON`, with no local-source override and a
fresh source cache. The GCC 13.4 Release build enabled VAES, real
SimplestOT/Edwards25519, DPF, and RingLPN.

- `SpinIntegration` and `SpinOptions` passed.
- libOTe, cryptoTools, SPIN, and both test archives built and installed.
- A separate installed-package consumer passed `SpinConsumer`, covering full
  and banked modes, seed changes, and optimized/generic coefficient agreement.
  All three package configurations resolved from the new installation.
- The published VAES code passed AES correctness tests on GCC and MSVC.
- The MSVC local-source SPIN integration and option tests passed again.

The clean validation is retained at `/tmp/libote-spin-public-TcazgY` on the
measurement host. Existing installed coproto/macoro/libdivide dependencies
were reused; SPIN, libOTe, and cryptoTools were freshly fetched and built.
This was correctness and packaging validation, not another performance run.
The cryptoTools changes are merged into master. libOTe remains on its integration
branch. After moving AES profiling into the existing frontend, Linux AES,
SpinIntegration, and SpinOptions checks passed again at the new cryptoTools pin.

The reduced benchmark configuration cannot build/install libOTe's
unconditional full test library: with DPF disabled, `Dedup.h` references `DpfMult`;
with RingLPN disabled, its test references `convertToOle`. Enabling both then
requires a configured base OT (`DefaultBaseOT`). These are outside the SPIN changes.
The benchmark configuration has intentionally disabled base OT because supplied
base correlations are used. The separate release build supplies real base OT
and enables DPF and RingLPN; its full install and consumer check pass without
source workarounds. The measured benchmark build and timing records are unchanged.

The release validation is retained in `/tmp/libote-spin-ssd-pq75QW/build-package`
on the measurement host, with installed libraries under `package-check` and the
consumer under `package-consumer-installed`. Rebuild both `libOTe_Tests` and
`tests_cryptoTools` before installation: the package exports those archives too.
The consumer links `oc::libOTe` transitively; no manual cryptoTools or SPIN link
flags are needed.

See [REGULAR_PERFORMANCE.md](REGULAR_PERFORMANCE.md) for 89.05 million hashed
OTs/s with full setup reuse, and [STREAMING_HASH.md](STREAMING_HASH.md) for the
stationary result. No matched speedup is inferred from the older 47-million-OT/s run.
