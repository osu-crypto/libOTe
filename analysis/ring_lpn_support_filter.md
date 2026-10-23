# Ring-LPN support rejection

The implementation now matches the paper's filtered support law at the
analyzed Goldilocks point: ring degree 2^20, four polynomials, weight 16.
Selection uses the scalar field order and the initialized ring dimensions,
not the requested output count or the selected DMPF backend. A triple request
of 2^19 has the same ring degree as an OLE request of 2^20.

Each party independently samples 64 block-local offsets. For each polynomial,
the filter counts occupied absolute-position residues modulo 128; the four
counts are summed and the tuple is accepted if the sum is at least 61.
Because the block size is 2^16, reducing the block-local offset gives the
same residue as reducing the absolute position. Residue counts are computed
before coefficient cancellation. A rejection replaces all 64 offsets.

The predicate uses two 64-bit occupancy masks per polynomial. The sampler
has no allocation in its retry loop and lives in a non-coroutine helper.
It consumes only local randomness, before support-dependent routing; it
adds no messages or OTs. Under independent uniform sampling, acceptance is
approximately 0.501914, hence about 1.992 attempts per party in expectation.
The accepted tuple has the original distribution conditioned on the predicate.
There is no retry cap, unfiltered fallback, or per-polynomial resampling.

`genDpf` uses the sampler once per setup. Ordinary reusable expansions retain
the accepted supports. Other fields, ring degrees, and noise dimensions keep
their existing sampler; no security threshold is inferred for those profiles.
`usesSupportFilter()` exposes whether the initialized profile is covered.

## Regression checks

`RingLpn_SupportFilter_test` covers:

- folded weights 4, 60, 61, and 64, including both 64-bit mask words;
- separate polynomial identities and repeated residues with different high bits;
- invalid dimensions and offsets;
- a scripted rejection followed by acceptance, consuming two complete tuples;
- 256 accepted samples compared exactly with an independent `std::set`-based
  reference sampler, including identical subsequent PRNG state;
- both DMPF backends, OLE/triple sizing, reinitialization, and unsupported
  field/dimension profiles;
- preservation of the setup lifecycle and of legacy sampling outside the profile.

The focused runner also invokes existing Ring-LPN audit, stationary reuse,
and OLE integration tests:

```sh
bash analysis/run_ring_lpn_support_tests.sh
```

Set `RING_LPN_BUILD` to select another compatible Ninja build. The local
production-profile checks exercise sampling and initialization, not a full
degree-2^20 OLE expansion; the existing integration tests use smaller rings.
This change does not resolve the separate OLE composition argument or the
concrete AES assumptions. Benchmark tables have not been refreshed.

Validation on 2026-09-23: the support-filter, Ring-LPN audit, stationary-reuse,
and OLE tests pass under WSL/GCC (`-trials 2`), including a second run with
`-dmpf 1` for sum-of-DPFs reuse. All seven exact Python
hash-conditioning checks also pass. Cross-platform CI remains a separate check.
