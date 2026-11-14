# Chosen-block BAA for GF(2^128) VOLE

Standalone code experiments now also provide `ReedMullerBaaCode` (10% distance)
and `SmallAlphabetBaaCode` (30.524% distance), with allocation-free forward and
transpose interfaces. See the [code-distance and encoding comparison](../../../libOTe_Tests/benchmarks/ChosenBaaDirections.md)
for their exact certificate dimensions, proof scope, Fp controls, and timing
method. These are separate encoder classes; the protocol profiles described
below still use the original full-field `ChosenBaaCode`.

`ChosenBaa16x8` uses the systematic RS[16,8,9] constituent over GF(2^128).
`ChosenBaa16x4` uses RS[16,4,13]. Both profiles apply two independently
weighted accumulator stages and two independent Fisher--Yates shuffles.
The implementation uses the polynomial basis of cryptoTools `block::gf128Mul`.

The transpose encoder accepts `n` field elements, where `n` is a positive
multiple of 16 below 2^32. It replaces the input prefix with `n/2` or `n/4`
outputs. The paired interface applies the same matrix to two separate buffers.
It shares permutation traversal and coefficient generation between the buffers.
The encoder modifies its input and allocates scratch once per call.

The local RS map and fused scan/multiply/scatter follow
[the chosen-block BAA implementation](https://github.com/ladnir/libOTe/blob/fa7bfc3c8a0178fc99b0b666d5f31fc2a9277579/libOTe/Tools/Ppcg/ChosenBlockBaa.h).
The VOLE port specializes the local dimension at compile time, batches eight
scan positions, and generates weights during encoding. It does not retain
two arrays of field weights or create worker threads. The shuffle sampler uses
rejection sampling; power-of-two lengths do not select a Feistel permutation.

## Seed exchange

Each chosen-BAA VOLE call establishes a fresh public seed before generating
base correlations. The sender samples 16 bytes and sends their domain-separated
32-byte hash. The receiver sends its own fresh 16-byte contribution. The sender
opens its commitment, and the receiver verifies it. Both parties XOR the
contributions to obtain the code seed. An invalid opening aborts the protocol.
This adds three messages, totaling 64 payload bytes, including in reduced-round
applications. Both peers must select the same profile and protocol version.

This exchange relies on the hash commitment's hiding and binding properties.
It prevents a party from adapting its contribution to the other contribution
without breaking those properties. It does not prevent selective aborts.
AES expands the seed into separate permutation and weight streams. Each weight
is sampled from the nonzero field elements by rejection.

## Security scope and parameters

[Chosen-Block BAA Codes](https://eprint.iacr.org/2026/1903) analyzes independent
uniform permutations and independent uniform nonzero field weights. Its
[finite certificates](https://github.com/ladnir/gen-BAA/tree/main/rs-certification)
give the following code-sampling bounds at message dimension `k = 2^20`:

| Constituent | Code length | Relative distance | Sampling failure |
|---|---:|---:|---:|
| RS[16,8,9] | 2^21 | 0.30 | < 2^-137.56 |
| RS[16,4,13] | 2^22 | 0.60 | < 2^-209.60 |

These bounds concern the ideal random code ensemble over fields of order at
least 2^127. They are not a proof for every requested length, a particular
seed, AES-expanded public randomness, or the complete VOLE protocol.
Using seeded randomness retains a cryptographic assumption about the resulting
code ensemble. A fresh joint seed alone does not remove that assumption.

The adapter uses pseudo-distance 0.30 for RS[16,8,9] and 0.60 for RS[16,4,13].
These are engineering choices informed by the paper, applied across supported
lengths as attack calibrations. They do not extend the finite certificates.
The 64-bit linear-character criterion gives rounded noise floors of 128 and
56 positions, respectively. The independent attack floor is `secParam`
positions at rate 1/2 and `ceil(secParam / 2)` at rate 1/4. The selector takes
the maximum of the distance requirement, attack floor, and implementation
minimum, then rounds up to eight positions. At the default `secParam = 128`,
the profiles therefore use 128 and 64 noise positions, respectively.
Increasing the pseudo-distances further would not lower this default count.
These calibrations are not a proof of 128-bit security for all sizes.
The rate-dependent floors reflect the different decoding costs; the historical
107-position SSD calibration is superseded by the stronger estimates in
[Regular Syndrome Decoding Is Easier Than Previously Estimated](https://arxiv.org/abs/2610.29175).

The PPRF expands its physical prefix. The adapter pads that prefix with at
most 15 additional zeros when rounding to a multiple of 16, in addition to
any padding already selected by the generic adapter. Truncating the encoder's
output selects a subcode; zero-padding its input punctures the corresponding
forward code. Any finite certificate used for a concrete VOLE configuration
must account for those exact dimensions and punctured coordinates.

Silent VOLE accepts these profiles only with `CoeffCtxGF128` and `block` for
both scalar and value types. Other field contexts require a separate port.
The existing libOTe default remains unchanged; applications can explicitly
select either new profile.

## Fields and arithmetic backends

The standalone `ChosenBaaCode<K, F, Field>` encoder supports fields with sixteen
distinct evaluation points. `K` is 4 or 8. `F` defaults to `block` for GF(2^128),
and `Field` defaults to `ChosenBaaField<F>`. For example,
`ChosenBaaCode<8, Goldilocks>` encodes over the Goldilocks prime field. The
generic policy uses field operators, `inverse()`, and a uniform `PRNG::Any`
constructor. Other representations can supply a stateless policy with the same
interface. Its `point(0)` through `point(15)` must be distinct, and `sample8`
must sample eight independent, uniform nonzero field elements. Byte copying
into modular representations does not satisfy that sampling contract.

Field policies are selected at compile time. There are no virtual calls or
heap-allocated callbacks in the kernels. The fixed RS matrix is initialized
once per field/profile, cached immutably, and laid out by parity column so
consecutive output rows occupy consecutive SIMD lanes. Initialization is
thread-safe; configuration retains only a pointer to the matrix. The public
seed, shuffles, nonzero-weight draw order, and GF(2^128) outputs are unchanged.

GF(2^128) has the following statically selected paths:

* AVX-512 plus VPCLMUL: four independent field products per vector, batched
  accumulator products, and four RS output rows per vector.
* AVX2 plus VPCLMUL: two RS output rows per vector. Accumulator products keep
  the interleaved 128-bit schedule, which performs better on large paired
  inputs than the tested two-lane accumulator schedules.
* AVX2/PCLMUL without VPCLMUL: interleaved 128-bit products and fixed RS kernels.
* Apple ARM: hardware PMULL products and ARM AES expansion.
* Portable: fixed-operation polynomial multiplication built from 32-bit integer
  products, Karatsuba composition, and two fixed reduction folds. This removes
  operand-dependent branches from these field-arithmetic routines; it is not a
  claim about the constant-time behavior of every dependency or every CPU.

`ENABLE_VPCLMUL` is detected on native x86 builds and can be disabled explicitly.
AVX2 and AVX-512 alone do not imply VPCLMUL support. As with the existing ISA
options, enabling it produces a binary requiring that instruction set; there is
no per-operation runtime dispatch. Cross builds default conservatively and must
select the intended target explicitly. `ENABLE_AVX512` selects the four-lane
path when VPCLMUL is enabled.

The Silent VOLE adapter still accepts only GF(2^128). Generic encoder support
does not assign VOLE noise parameters or transfer the finite-distance
certificates to other fields. It is tested separately over Goldilocks for RS
interpolation, linearity, paired encoding, and the forward/transpose identity.

## Reproducing encoder timings

Configure with `-DLIBOTE_BAA_BENCHMARK=ON`, then build the
`chosen_baa_benchmark` target and run it with a physical input length, for
example `chosen_baa_benchmark 1048576`. It reports configuration, single-vector,
and paired-vector times separately, as medians of five trials after one warmup.
Allocation of encoding scratch is included; generating inputs and checking all
paired outputs against the single-vector result are outside the timed regions.
Run only one benchmark at a time. These are encoder timings, not complete VOLE
or PSI timings.

Native measurements on November 13, 2026, used the same fixed inputs and seeds
before and after the optimization. The baseline is libOTe `1afe55bb` with
cryptoTools `12fa6f9`. All runs were sequential. Times below are milliseconds
for the half-rate profile; each row compares the same machine and input length.

| Machine / backend | Input length | Single before | Single after | Pair before | Pair after |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ryzen 7950X, AVX2/PCLMUL | 1,048,576 | 29.58 | 30.01 | 65.84 | 65.30 |
| Ryzen 7950X, AVX2 + VPCLMUL | 1,048,576 | 29.58 | 26.23 | 65.84 | 57.43 |
| Ryzen 7950X, AVX-512 + VPCLMUL | 1,048,576 | 29.58 | 24.78 | 65.84 | 53.84 |
| Apple M3, ARM AES/PMULL | 1,048,576 | 788.32 | 18.17 | 1,573.23 | 34.02 |
| Apple M3, portable arithmetic and AES | 65,536 | 74.07 | 31.18 | 127.49 | 53.55 |

The ordinary AVX2 path is effectively unchanged in this measurement. The large
ARM improvement primarily fixes the previous accidental software-multiply
dispatch. Backend comparisons against the original encoder, plus independent
bit-polynomial arithmetic tests, check correctness separately from timings.

### Prefetch follow-up

The x86 GF(2^128) path now prefetches eight random destination cache lines 64
entries ahead, retaining the eight-entry arithmetic schedule. The hint uses
`_MM_HINT_T2` and requires no additional instruction-set feature. Both the
permutation-index reads and destination addresses stay in bounds; the final
eight batches issue no hints. A single dispatch per stage enables this loop
only at physical input lengths of at least 2^18. Smaller inputs, ARM, portable,
and generic-field policies retain their previous schedule.

The following sequential Peach measurements compare the previous PR revision
`50f27b4d` with this follow-up using the same harness, flags, seeds, and half-rate
profile. Peach was pinned to CPU 2, with boost disabled and a 4.5 GHz setting;
the compiler was GCC 15.2 at `-O3`. Length means the number of input field
elements to the transpose encoder, whose output length is half as large.
Setup is excluded and scratch allocation is included, as in the preceding table.

| Backend | Input length | Single before | Single after | Pair before | Pair after |
| --- | ---: | ---: | ---: | ---: | ---: |
| AVX-512 + VPCLMUL | 65,536 | 0.784 | 0.790 | 1.746 | 1.747 |
| AVX-512 + VPCLMUL | 1,048,576 | 23.84 | 13.72 | 51.63 | 34.68 |
| AVX-512 + VPCLMUL | 2,097,152 | 67.74 | 40.82 | 114.19 | 74.60 |
| AVX2 + VPCLMUL | 1,048,576 | 25.32 | 15.60 | 56.33 | 43.72 |
| AVX2/PCLMUL | 1,048,576 | 29.68 | 20.00 | 65.32 | 52.36 |

Alternating repeat runs at 1,048,576 inputs measured 13.68--13.72 ms single and
34.68--34.85 ms paired for AVX-512. The smaller input showed no material change.
Tests around the dispatch threshold cover the non-power-of-two tail and the
forward/transpose identity. Native M3 experiments found no benefit from these
hints, so ARM keeps its existing schedule. Wider scatter batches and an
additional inverse-permutation gather pass were also measured and rejected.

A separate stage-only comparison with identical precomputed full-field weights
measured 8.86 ms transpose and 9.06 ms forward at 2,097,152 elements on Peach.
This excludes weight generation and the RS map and is not a full-encoder timing.
