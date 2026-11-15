# ChosenBAA30 setup and scan scheduling

November 15, 2026. Setup packs coefficient bytes from contiguous PRNG views and
prefetches Fisher--Yates destinations in batches of 64. Draws, rejection draws,
and swaps retain their original order, preserving the exact seed-to-code map.
GF128 scans on x86 VPCLMUL builds use four-element, fully unrolled batches;
ARM, portable arithmetic, and other field policies retain sixteen-element
batches. Distance, field, coefficient distribution, and noise parameters are
unchanged.

Sequential Peach comparisons use CPU 2 on a Ryzen 7950X at 4.5 GHz, GCC 15.2,
`-O3 -march=native` (AVX-512/VPCLMUL/GFNI), three seeds, two warmups, and eleven
samples per seed. Each entry is the median of the three per-seed medians.
Setup includes fresh permutations and coefficients, reusing allocated capacity;
encoding excludes setup and uses caller-owned buffers. Times are milliseconds.

`ChosenBaaSetup.cpp` reproduces the sampling and correctness checks. Build it
with the same Release/ISA flags and cryptoTools installation as the library;
its arguments are codeword length and seed. Run one process at a time, pinned
to CPU 2, for lengths 2097152 and 2823424 and seeds 4, 5, and 6. Setup uses a
fresh seed per sample; encoding reuses the final configured code.

| Codeword length | Setup before / after | Forward before / after | Transpose before / after |
| --- | ---: | ---: | ---: |
| 2,097,152 (`k=2^20`) | 10.38 / 8.20 | 17.11 / 15.21 | 17.08 / 15.62 |
| 2,823,424 (2^20-item PSI shape) | 14.59 / 11.38 | 24.37 / 21.74 | 24.60 / 22.55 |

The shorter scan also improves the AVX2/VPCLMUL paths with and without GFNI
on Peach. Other fields and the ARM/portable scan schedule are unchanged;
these measurements do not establish native Apple timings. Metadata and output
checksums match the previous implementation for every compared seed. The unit
test compares every metadata entry with scalar setup, including batch tails
and a 1,048,592-element case with rejection sampling; field-generic scalar
references and transpose identities also pass. ASan/UBSan checks pass at
lengths 16, 48, 64, 80, 144, 1040, and 262144.

With one core per party, the dependent 2^20-item SH PSI benchmark improves from
392.8 to 377.3 ms warm median (six trials; first run 542.6 to 530.0 ms).
Both measurements include fresh BAA setup and use the default allocator.
The harness uses two processes pinned to CPUs 2 and 3 and BufferingSocket over
AF_UNIX, including IPC and copies. These are elapsed protocol times, not
per-party CPU work or TCP-network measurements. OKVS is unchanged.

Paired scans, a 512-bit GFNI recurrence, altered encoding prefetch policies,
and delayed local-RS reductions did not improve the measured workload and
were not retained. Historical comparisons are in [ChosenBaaDirections.md](ChosenBaaDirections.md).
