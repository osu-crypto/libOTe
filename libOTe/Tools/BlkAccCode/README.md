# Chosen-block BAA for GF(2^128) VOLE

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

The adapter keeps libOTe's existing conservative large-field tuning: a 0.20
pseudo-distance for the 64-bit linear-character criterion and at least
`secParam` noise positions. At the default `secParam = 128`, this selects 200
positions. The same tuning applies to both constituents; the quarter-rate
profile does not use the paper's 0.60 value to reduce noise.
These are attack calibrations, not a proof of 128-bit security for all sizes.

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
