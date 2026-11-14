# BAA code distance and encoding time

These experiments compare rate-one-half linear codes at message dimension
`k = 1,048,576` and code length `n = 2,097,152`. Forward encoding maps `k -> n`;
transpose encoding applies the same matrix transposed, `n -> k`. Distance
refers to the forward code. All performance measurements are single-threaded
and run sequentially, including across hosts.

Two standalone GF(2^128) profiles are available. `ReedMullerBaaCode<>` uses
RM(2,5)[32,16,8], two Fisher--Yates permutations, and two plain accumulators.
It needs only XORs during encoding. `SmallAlphabetBaaCode<>` uses RS[16,8,9], two
Fisher--Yates permutations, and two recursive scans with independently sampled
coefficients. Each scan computes `y[i] = x[perm[i]] + a[i] * y[i-1]`, starting
from zero. The alphabet consists of polynomial-basis elements with integer
encodings 1 through 256; these are 256 distinct nonzero field elements, not
integer scalar multiples of one. Metadata packs a 24-bit index and an eight-bit
coefficient selector into one word. Supported lengths are positive multiples
of 16 up to 2^24; RM lengths must instead be multiples of 32 below 2^32.

Both profiles accept caller-owned, disjoint input/output/scratch buffers and
perform no allocation while encoding. The transpose overwrites the input
prefix. `SmallAlphabetBaaCode<F, Field>` also supports other fields through a
compile-time policy; Goldilocks is exercised against scalar references.
`ReedMullerBaaCode<F, Field>` requires characteristic two. The pre-existing
full-field `ChosenBaaCode` now also provides forward encoding and a transpose
overload accepting scratch. Its seed schedule and transpose map are unchanged.

The Fp controls use `p = 2^128 - 159` and the existing optimized Newton
[16,8,9] reference from gen-BAA. The low-distance control has all coefficients
one; the high-distance control samples 1 through 256. `FpBaaDirections.cpp`
reuses that forward implementation and adds its transpose, including the
reversed 77-addition Newton circuit with eight-block AVX-512 batching. This
standalone comparison requires the reference sources and an AVX-512/BMI2 x86
host; it is not part of the portable library build.

| Code | Minimum distance at these dimensions | Setup-failure bound |
| --- | ---: | ---: |
| GF(2^128), lifted RM BAA | 209,716 (>10%) | <= 2^-47.093 |
| Fp, Newton, all-one scans | 245,367 (>11.7%) | < 2^-49.64736 |
| GF(2^128), RS, q=256 scans | 640,135 (>30.524%) | < 2^-59.13394 |
| Fp, Newton, q=256 scans | 640,135 (>30.524%) | < 2^-59.13394 |

These are lower bounds for all nonzero messages, including messages selected
after setup. They are not measurements of actual minimum distance. The
probability space uses ideal independent uniform permutations and coefficients.
The implementations expand seeds with AES; the Fp research benchmark uses
deterministic reproducibility streams. The finite certificates do not directly
establish the same failure probabilities for those pseudorandom ensembles or
for other lengths. No protocol security claim is made here.

For RM, the binary generator matrix is unchanged under field extension.
Expand a nonzero extension-field message in an F2 basis. At least one binary
component is nonzero, and its encoded support is contained in the support of
the extension-field codeword. Thus the extension-field distance is at least the
binary distance. Embedding binary messages gives the reverse inequality, so
the distances are equal for every fixed setup. The original first-moment
script from gen-BAA commit `568cfc7` is included with a constituent selector.
Its complete length-2^21 calculation is in `certificates/rm-2097152.txt`.
This is the paper's floating-point numerical procedure, with a one-bit
allowance on each subtotal; it is not an interval-arithmetic certificate.

For q=256, the saved certificate's sparse leaves use the direct quotient-rank
bound, and all 349 dense leaves use that same direct bound. No leaf uses the
short-gap, triangle-free argument that depends on large characteristic.
The direct bound applies over any one fixed field with a local [16,8,9] MDS
code and 256 distinct nonzero coefficients: after conditioning on previous
coefficients and imposed zero equations, a new independent zero equation
raises rank; if the input and feedback forms are dependent, at most one of
the 256 fresh coefficients cancels them identically. This uses only field
linear algebra and the coefficient atom bound 1/256. The support polynomial
`1 + sum(d=9..16, binom(16,d) z^d tau^(d-8))` follows from the MDS shortened
dimensions and is also independent of characteristic. Permutation averaging,
the two-scan rank potential, and the final support sums therefore transfer
without changing a numerical witness. The compressed ledger, original replay,
and transfer result are stored under `certificates/`. The transfer checker
rejects any characteristic-dependent leaf before replaying the exact rational
sum. The all-one Fp proof does not transfer by this argument; its Newton circuit
also fails to be MDS if simply reduced modulo two.

The GF small-alphabet encoder evaluates its RS polynomial at polynomial-basis
points 0 through 15, with the first eight coordinates systematic. For the
subspace U={0,...,7}, its subspace polynomial P_U is additive with constant
nonzero derivative. Lagrange coefficients on the coset 8+U therefore have the
form `M[i,j] = c[i XOR j]`. In characteristic two, changing each group-algebra
variable from x to t=x+1 gives t^2=0. A three-bit zeta transform converts this
XOR convolution into subset convolution. The constant transformed coefficient
is one, leaving 19 nontrivial products instead of 64. `AdditiveRs8` uses three
explicit batches of eight SIMD slots and fixed unrolled transforms. The same
kernel handles the transpose because M is symmetric. Independent scalar RS
evaluation checks the resulting encoder; exhaustive tests check the RM local
weight spectrum and all 256 small multipliers on all 128 basis vectors.

Build the GF comparison with `LIBOTE_BAA_BENCHMARK=ON`, then run
`chosen_baa_directions 2097152 31 1`. Build the Fp comparison with
`python build_fp_comparison.py --reference /path/to/gen-BAA --build-dir /tmp/fp-baa`;
run `/tmp/fp-baa/fp_baa_directions --test`, followed by
`/tmp/fp-baa/fp_baa_directions 2097152 31 1`. The builder copies the reference
unchanged, extracts its shared prefixes before `main`, and records source
hashes. Pin both benchmark executables to the same CPU. Run them sequentially.
Setup, allocation, input restoration, reference comparisons, and checksums are
outside the timers. Each direction has two warmups, followed by 31 samples.
The forward and transpose phases run separately, so transpose restoration does
not change the forward cache conditions. Repeat across six seeds and alternate
the order of the GF and Fp processes. Report the median of the six per-seed
medians, retaining their range.

Replay distance evidence with:

```
python certificates/binary_first_moment.py --n 2097152 --constituent rm
python certificates/verify_field_transfer.py /path/to/gen-BAA
```

The second command uses the original gen-BAA verifier and its numpy/scipy
dependencies. Its uncompressed ledger SHA-256 is
`45cce4c94abfbfc967eeb9c4316b75a8c497dbd75605e8fcbe7cc3ee4a4adda1`.

On Peach (Ryzen 7950X, CPU 2, 4.5 GHz, boost disabled, GCC 15.2, `-O3
-march=native`), the six-seed results are below. Times are milliseconds;
parentheses show the range of per-seed medians. The archive in
`results/peach-code-directions-20261113.tar.gz` contains the measured source,
source hashes, compiler/machine details, and per-seed results. The separate
`results/final-summary.json` records the aggregate values.

| Code | Forward k -> n | Transpose n -> k |
| --- | ---: | ---: |
| GF(2^128), RM, >10% | 10.72 (10.70–10.78) | 12.98 (12.98–13.36) |
| Fp, all-one, >11.7% | 12.15 (12.13–12.21) | 17.15 (17.10–17.17) |
| GF(2^128), q=256, >30.524% | 19.94 (19.86–20.02) | 19.49 (19.44–19.51) |
| Fp, q=256, >30.524% | 17.36 (17.27–17.56) | 23.04 (23.01–23.12) |
| Previous GF full-field RS, 30% | 30.92 (30.80–31.01) | 28.02 (27.73–28.16) |

The high-distance GF forward encoder remains about 15% slower than Fp. Its
transpose is about 15% faster, and its two directions are within 3%. The lower
distance GF code is faster than the corresponding Fp control, with the weaker
10% versus 11.7% distance bound. These results do not establish a forward-time
match for the high-distance code. The previous full-field row is measured with
the same caller-owned buffers; older timings that included allocation and
different cache preparation should not be substituted into this table.

Backend spot checks at the same full dimensions are shown separately. Peach
AVX2 rows use 15 samples for one seed; portable uses five samples for that seed.
Apple M3 uses Apple Clang 15 and 15 samples. The M3 range covers two runs
bracketing the prefetch experiment; it is not a six-seed statistical summary.
Every run checked the full forward/transpose inner-product identity.

| Backend | RM forward / transpose | q256 forward / transpose |
| --- | ---: | ---: |
| Peach AVX2 + VPCLMUL | 10.86 / 13.23 | 21.40 / 22.64 |
| Peach AVX2 + PCLMUL | 11.05 / 13.61 | 23.78 / 24.07 |
| Apple M3 PMULL | 20.85–22.29 / 17.72–18.05 | 35.71–35.84 / 28.14–28.25 |
| Peach portable arithmetic | 21.39 / 21.33 | 329.84 / 297.25 |

ARM prefetch, paired-recursion expansion, and a CLMUL-only small-product
reduction were tried and not retained. The selected small-product kernel uses
two carryless products and a bounded shift/XOR reduction. Portable correctness
also passed the scalar encoder references, local RM spectrum, and all small
multiplier basis cases. ASan/UBSan passed sizes 32, 96, 1056, and 262144 on
the AVX2/VPCLMUL path. Fp transpose tests cover every local basis vector,
zero, maximal canonical values, random values, batch tails, and in-place use.
