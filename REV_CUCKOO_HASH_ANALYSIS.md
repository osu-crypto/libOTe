# Conditional Failure Analysis of the RevCuckoo Goldreich Hash

**Date:** 2026-09-01

**Status:** Isolated analysis; retain `linearSecParam = 40` and hard-code an
additional eight-bit hash-width margin for 40-bit batch correctness.

**Relevant implementation:** `libOTe/Dpf/RevCuckoo/GoldreichHash.h` and
`libOTe/Dpf/RevCuckooDmpf.h`

**Reference:** [Fully Distributed Multi-Point Functions for PCGs and
Beyond, IACR ePrint 2025/2294](https://eprint.iacr.org/2025/2294.pdf),
Section 7.3 and Figure 7.

## Executive conclusion

The RevCuckoo call sequence fixes and shuffles the input points before it
jointly samples the Goldreich-hash seed. This order rules out an adversary
choosing a bad set after seeing the hash. It does not, however, make the hash
failure probability independent of the fixed set.

For a fixed partition, the relevant probability is over the freshly sampled
hash matrices. If the hash's lifted feature rows are independent, the final
matrix has the same rank distribution as a uniformly random binary matrix,
and the usual `d + 40` output dimension gives approximately 40 bits of
conditional robustness. If the fixed points have low-degree additive
relations, the one-AND-layer lift can preserve those relations with a much
higher probability. Some degree-two relations are preserved for every hash
seed.

This is not, by itself, a demonstrated break of the present RingLPN or
AnyField callers. Their unconditional failure probability must also include
the probability that input generation and the secret shuffle produce a
harmful fixed partition.

The RingLPN caller admits a useful simplification. Within one DPF set, its
`t` points are independent samples from the triangular distribution obtained
by adding two uniform block offsets. The reuse of offsets correlates different
sets, but a union bound needs only the expected relation count. The bounded
analysis below finds that XOR parallelograms dominate all observed
zero-linear-moment relations. Their analytic batch contribution is at most
`2^-39.469` for the current `w = 2` profile. This is a narrow loss of margin,
not evidence of a catastrophic failure.

The final random compression contributes a larger batch union bound of
`2^-38.288`. The complete analytic bound gives 37.694 bits at the previous
56-bit widths. The implementation keeps `linearSecParam = 40` and hard-codes
an additional eight-bit hash-width margin. This raises both widths to 64 bits
and gives 41.935 bits.

## 1. Probability experiment

The implementation performs the following operations in this order:

1. It deduplicates the real points and pads the input with a shared sentinel
   point `N`.
2. It applies the protocol's secret shuffle and assigns the shuffled rows to
   partitions.
3. It jointly samples a fresh root from which the Goldreich-hash matrices are
   derived.
4. It hashes the points and solves the resulting binary linear system.

Consequently, the correct conditional experiment is:

1. Fix the complete post-shuffle partition, including its real points and
   their assigned public row labels.
2. Sample the hash matrices.
3. Ask whether the system needed by RevCuckoo is consistent.

There are therefore two distinct failure probabilities:

- **Input/partition failure:** the probability that point generation and the
  shuffle produce a structurally bad fixed partition.
- **Conditional hash failure:** the probability that a fresh hash fails on
  that already fixed partition.

Any end-to-end bound must account for both. The analysis below concerns the
second probability and identifies which fixed partitions make it large.

## 2. Hash model and correctness condition

Work over `F_2`. Let the input length be `ell`, let the intermediate width be
`qPrime`, and let the final output width be `q`. Ignoring storage padding, the
raw one-AND-layer function has the form

```text
a = M0 x
b = M1 x
c = a AND b
F(x) = M2 (x || c).
```

The implementation includes an affine toggle in the raw function. RevCuckoo
then offsets every output by the raw value at the sentinel `N`. The affine
term cancels, so the map actually used by the protocol is

```text
H(x) = F(x) XOR F(N)
     = M2 ((x XOR N) || (c(x) XOR c(N))),
```

and `H(N) = 0` as required by the construction.

For one fixed partition, write its `r` real points as `x_1, ..., x_r`. Let
`Y` contain their assigned public row labels. Define the anchored feature
lift

```text
Phi(x) = (x XOR N, c(x) XOR c(N)).
```

Stacking these rows gives a feature matrix `Phi_A`, and the matrix presented
to the solver is

```text
H_A = Phi_A M2.
```

The protocol needs `H_A h = Y` to be solvable, independently for every bit of
the right-hand side. A row relation `alpha` is harmful exactly when

```text
alpha^T H_A = 0    but    alpha^T Y != 0.
```

A rank deficiency alone is not necessarily a protocol failure: it is harmless
when every lost row relation also holds among the corresponding labels.

## 3. Ideal case: independent feature rows

Suppose `Phi_A` has full row rank `r`. Since `M2` is sampled uniformly, `H_A`
is a uniformly random `r` by `q` binary matrix. Thus

```text
Pr[rank(H_A) < r]
  = 1 - product from i=0 to r-1 of (1 - 2^(i-q))
  < 2^(r-q).
```

This is an upper bound on inconsistency, because some deficient matrices can
still be consistent with `Y`. When the intended number of independent rows is
`d` and `q = d + 40`, the usual heuristic is therefore approximately 40 bits
per independently analyzed system.

The important premise is full row rank of the lifted features. It does not
follow merely from sampling the matrices after fixing the inputs.

## 4. Conditional probability for a fixed row relation

Fix a nonzero coefficient vector `alpha` over the `r` rows. Define its
anchored linear moment

```text
L_alpha = sum_i alpha_i (x_i XOR N).
```

For one intermediate product coordinate, let `u` and `v` denote the
corresponding random columns of `M0` and `M1`. Define

```text
Q_alpha = sum_i alpha_i x_i x_i^T
          + (sum_i alpha_i) N N^T.
```

The `alpha`-sum of that product coordinate is `u^T Q_alpha v`. Moreover, the
diagonal of `Q_alpha` is `L_alpha`.

If `L_alpha != 0`, the linear part of the lifted relation is nonzero for every
choice of `M0` and `M1`. The final random compression then preserves the row
relation with probability exactly `2^-q`.

Now suppose `L_alpha = 0`. In this case `Q_alpha` is alternating and has an
even rank `s`. For one independently sampled pair `(u,v)`,

```text
Pr[u^T Q_alpha v = 0] = 1/2 + 2^(-s-1).
```

Across `qPrime` independent product coordinates, define

```text
A_alpha = (1/2 + 2^(-s-1))^qPrime.
```

The lifted relation is zero with probability `A_alpha`. If it is nonzero, the
final random matrix `M2` maps it to zero with probability `2^-q`. Therefore

```text
Pr[alpha^T H_A = 0]
  = A_alpha + (1 - A_alpha) 2^-q.
```

This becomes a conditional inconsistency probability when
`alpha^T Y != 0`. A union bound can sum this expression over harmful
relations, although the events for different relations are correlated.

Two consequences are immediate:

- High-rank quadratic moments behave close to the ideal random-row case.
- Low-rank quadratic moments can dominate the nominal `2^-40` linear-system
  margin.

If both `L_alpha = 0` and `Q_alpha = 0`, the relation is present for every
hash seed. Its conditional failure probability is one when
`alpha^T Y != 0`, and zero when the same relation holds among the labels.

## 5. Concrete structured relations

### 5.1 A parallelogram

Consider four fixed points in one partition:

```text
x, x XOR a, x XOR b, x XOR a XOR b,
```

with independent directions `a` and `b`. Their all-ones row relation has zero
linear moment and a quadratic moment of rank two. One product coordinate
preserves the relation with probability `5/8`. Hence

```text
Pr[the lifted relation is zero] = (5/8)^qPrime,
```

and

```text
Pr[the final hash preserves it]
  = (5/8)^qPrime + (1 - (5/8)^qPrime) 2^-q.
```

This only makes the solver inconsistent if the XOR of the four assigned
labels is nonzero.

For the common, byte-aligned dimensions, the fixed margin changes the
single-relation contribution as follows:

| `d` | previous `qPrime = d + 40` | fixed `qPrime = d + 48` | fixed `-log2((5/8)^qPrime)` |
|---:|---:|---:|---:|
| 8 | 48 | 56 | 37.97 bits |
| 16 | 56 | 64 | 43.40 bits |
| 32 | 72 | 80 | 54.25 bits |
| 64 | 104 | 112 | 75.94 bits |

Thus a fixed harmful parallelogram in a small partition need not receive the
nominal 40-bit margin from the previous intermediate width. The fixed margin
raises the single-relation exponent, while the caller-level analysis below
accounts for the number of candidate relations in a batch.

A bounded simulation with 200,000 trials and `qPrime = 12` observed a
survival frequency of `0.00362`; the exact value is
`(5/8)^12 = 0.0035527137`. This experiment only confirms the formula for a
fixed rank-two relation. It is not an end-to-end RevCuckoo failure estimate.

### 5.2 An affine three-dimensional cube

Consider the eight points

```text
x XOR t0*a XOR t1*b XOR t2*c,
```

for every `t0,t1,t2` in `{0,1}`. The XOR of any degree-at-most-two function
over this cube is zero. Every output bit of the one-AND-layer Goldreich hash
has degree at most two, so the XOR of all eight hash outputs is zero for every
hash seed.

This is a deterministic lifted relation. If the eight assigned labels have a
nonzero XOR, the conditional solver failure probability is one. If their
label XOR is zero, the relation is harmless.

The protocol order still matters: a cube in the global input only creates
this fixed-partition condition if the shuffle and partitioning place the
relevant rows together. That placement probability belongs to the separate
input/partition analysis.

## 6. Implications for the current implementation

### AUD-213: The conditional hash guarantee depends on the fixed set

The statement "the inputs are fixed before the hash is sampled" is necessary
and useful, but it is not sufficient to obtain the ideal random-matrix bound.
The exact conditional probability depends on the linear and quadratic moments
of row relations in the fixed partition.

### AUD-214: The previous intermediate width undercut the nominal margin

The implementation sets `mNumIntermediateBytes = mOutBytes`. In logical bits,
the fixed eight-bit margin now makes `qPrime` approximately `d + 48`, subject
to byte rounding. Before this change, `qPrime` was approximately `d + 40`. A
rank-two relation survives the nonlinear lift with probability
`(5/8)^qPrime`, which explains the loss at the previous smaller dimensions.

The paper permits a larger intermediate width and gives `qPrime = 2q` as one
example. Increasing `qPrime` would suppress probabilistic low-rank relations,
but it would not remove deterministic degree-two relations such as affine
three-cubes. It is therefore a possible parameter change, not a complete
resolution, and should be evaluated only after measuring the caller
distributions.

### AUD-215: The present dimension check is not a security condition

`GoldreichHash.h` currently compares the intermediate width against the
square of the byte-padded input width. This check neither establishes feature
rank nor matches the paper's stated role for `qPrime`. It also reasons about
storage bits rather than the exact logical input dimension. The check should
not be interpreted as a bound on hash failure probability.

Sampling more degree-two coordinates than the vector-space dimension of all
degree-two functions is not inherently invalid. Additional samples can reduce
the survival probability of low-rank relations until deterministic
degree-two identities become the limiting case.

### AUD-216: Existing statistical tests do not exercise the required property

`Goldreich_stat_Test` hashes sequential inputs under one seed and checks
marginal output-bit and byte frequencies. Marginal uniformity does not test:

- rank of the matrix presented to the RevCuckoo solver;
- consistency of `H_A h = Y`;
- survival of parallelogram relations;
- deterministic affine-cube relations; or
- the point distributions produced by RingLPN and AnyField.

The statistical test can therefore pass even when an exact row relation is
present.

## 7. Caller distributions and unconditional risk

The actual RevCuckoo callers do not obviously supply independent uniformly
random subsets:

- RingLPN forms points from structured sums of sparse polynomial positions.
- AnyField forms convolution-channel product points from sums of sparse
  positions and then groups them by output region.

These constructions can create additive relations at rates different from a
uniform random subset. The secret shuffle hides the assignment of individual
points, but it does not erase algebraic relations among points that land in
the same partition.

For scale only, if an `r`-element subset of an `N = 2^ell` point domain were
sampled independently and uniformly, rough first-moment estimates would be

```text
expected parallelograms  approximately r^4 / (24 N)
expected affine 3-cubes approximately r^8 / (1344 N^4).
```

These are illustrations, not bounds for either current caller. Applying them
mechanically to structured sumsets could substantially understate or
overstate the real probability. In particular, the high power of `r` in the
cube count makes the answer sensitive to the exact number of points per
partition and to correlations in their generation.

The same public partition hash is reused across several sets in one batch.
This reuse correlates failure events across those systems. A per-system
`linearSecParam = 40` estimate is therefore not automatically a 40-bit bound
for the entire batch; the batch-level accounting must include the number and
dependence of the systems being solved.

## 8. Bounded RingLPN analyzer

The first bounded analyzer is implemented in
`analysis/rev_cuckoo_hash_relations.py`, with regression tests in
`analysis/test_rev_cuckoo_hash_relations.py`. It samples the actual RingLPN
diagonal-sum construction: for each polynomial pair and output block, it forms
the `t` points

```text
left[a, i] + right[b, (k - i) mod t]
```

in the DPF domain, and it removes duplicate points as the caller does.

For each set, the analyzer enumerates every nonempty row subset whose anchored
linear moment is zero. It classifies each relation by its weight and the rank
of its quadratic moment. This spectrum includes XOR parallelograms, affine
three-cubes, and all intermediate low-rank relations.

Under the ideal-uniform-shuffle model, the analyzer applies two exact factors.
The first is the probability that every row in a relation enters one
partition. The second is the probability that the assigned row labels have
nonzero XOR. The same hash is reused across all sets, so the final accounting
uses a union bound. It does not assume independent hash failures.

For the current RingLPN parameters `P = 4`, `t = 16`, `N = 2^20`, and
RevCuckoo profile `w = 2`, `d = 16`, 5,000 seeded batches gave:

| quantity | estimate |
|---|---:|
| XOR parallelograms per batch before the shuffle | 3.8016 $\mathbin{\pm}$ 0.0275 |
| Uniform-subset baseline | approximately 3.55 |
| Shuffle, label, and hash factor per global parallelogram | `3.465790e-13` |
| Mean batch union contribution | $1.317555\mathbin{\cdot}10^{-12} \mathbin{\pm} 9.55\mathbin{\cdot}10^{-15}$ |
| Negative log of the mean contribution | 39.465 bits |

The structured RingLPN sets therefore produced about seven percent more XOR
parallelograms than uniform subsets in this experiment. More importantly, the
estimated parallelogram contribution alone is slightly larger than `2^-40`.
This is not a demonstrated attack or a certified failure bound. It is a
Monte Carlo estimate of one explicitly identified class of harmful relations
under the uniform-shuffle model.

The parallelogram expectation also has an analytic upper bound. The Walsh
transform computes the exact probability that four independent triangular
samples are distinct and have XOR zero. There are at most
`3.791522` corresponding index quartets per batch. Deduplication cannot
increase this count. The resulting union contribution is at most
`1.314062e-12 = 2^-39.469`. The Monte Carlo result above agrees with this
calculation.

Increasing only the intermediate width from 56 to 64 bits would reduce the
plane contribution to approximately `2^-44.89`. It would not reduce the final
compression term or deterministic relations. The implementation couples the
intermediate and final widths. It therefore retains `linearSecParam = 40` and
hard-codes an additional eight bits when computing both widths.

A 1,000-batch run enumerated the complete zero-linear-moment spectrum:

| relation weight | quadratic rank | mean count per batch | union contribution |
|---:|---:|---:|---:|
| 4 | 2 | 3.787 | `2^-39.471` |
| 6 | 4 | 15.823 | `2^-52.976` |
| 8 | 6 | 25.162 | `2^-58.364` |
| 10 | 8 | 15.549 | `2^-62.934` |

The run also found a few exceptional relations of ranks four, six, and eight.
Their combined contribution was below `2^-67`. No relation of quadratic rank
zero occurred. The union contribution of every observed class was
`1.312610e-12`, which has negative logarithm 39.471 bits. Thus the observed
higher-weight relations do not materially change the parallelogram estimate.

The absence of sampled affine cubes is not a security bound. The RingLPN
distribution nevertheless gives a direct bound. Each point has probability
at most `2/|X|`, where `X` is the DPF domain. Assigning eight distinct samples
to the vertices of an affine cube shows that

```text
E[number of affine cubes per batch] <= 8.574516e-11.
```

The deterministic relations admit a complete count. Their supports are the
codewords of `RM(2,17)^perp`. The weight distribution follows from the
MacWilliams identity. Since one set contains at most 16 real rows, only four
nonzero weights matter:

| relation weight | expected-count bound | union contribution |
|---:|---:|---:|
| 8 | `8.572684e-11` | `2^-42.217` |
| 12 | `7.822823e-18` | `2^-72.863` |
| 14 | `1.169022e-21` | `2^-90.441` |
| 16 | `5.650154e-26` | zero |

The weight-16 contribution is zero because the XOR of all 16 row labels is
zero. Thus affine cubes account for essentially the complete deterministic
contribution. The total is at most `1.956062e-13 = 2^-42.217`.

The higher-rank term also admits an analytic count. Fix a relation weight
`k`. The Hamming MacWilliams transform fixes the constant and linear moments.
The eigenmatrix of the binary alternating-forms scheme then resolves the
quadratic moment by rank. The analyzer implements this transform and validates
it by exhaustive enumeration in dimensions three and four. The eigenmatrix
formula is due to
[Delsarte and Goethals](https://doi.org/10.1016/0097-3165(75)90090-4).

Concretely, let `B[k,s]` count the `k`-subsets whose constant and linear
moments vanish and whose quadratic moment has rank `2s`. Let `K` be the
dimension of `RM(2,17)`. The transform computes

```text
B[k,s] = 2^(-K) sum_i v[i] P[i,s] T[k,i].
```

Here `v[i]` counts alternating forms of rank `2i`, and `P[i,s]` is the
alternating-forms eigenmatrix. The term `T[k,i]` sums the Hamming Krawtchouk
polynomial over all affine parts of a quadratic form of rank `2i`. This
formula counts every possible quadratic rank without sampling a point set.

For each resulting support, the RingLPN point distribution has maximum mass
`2/|X|`. This gives a distributional upper bound for every rank class. The
dominant structural terms are:

| relation weight | quadratic rank | union contribution |
|---:|---:|---:|
| 4 | 2 | `2^-39.469` |
| 8 | 0 | `2^-42.217` |
| 6 | 4 | `2^-46.993` |
| 8 | 6 | `2^-50.366` |
| 10 | 8 | `2^-52.928` |

All remaining rank classes contribute less. Their complete structural union
bound is `1.517623e-12 = 2^-39.261` at the 56-bit widths. At the 64-bit
widths, the structural bound is `2.262496e-13 = 2^-42.007`. These bounds are
independent of the Monte Carlo run.

The final compression requires separate accounting. Conditioned on
independent lifted rows, a partition containing `r` real rows loses rank with
probability less than `2^(r-q)`. Averaging this expression over the exact
hypergeometric occupancy distribution and taking a union bound over all sets
and partitions gives:

| final width | compression bound | complete analytic batch bound |
|---:|---:|---:|
| 56 | `2^-38.288` | `2^-37.694` |
| 64 | `2^-46.288` | `2^-41.935` |

Thus a larger intermediate width alone is insufficient for 40-bit batch
correctness. Raising both widths to 64 bits gives about 1.94 bits of margin
for the complete analytic bound.

For comparison, the `w = 3`, `d = 8` profile has only 32.577 analytic bits
without width slack. Adding eight slack bits raises its widths to 56 bits and
gives 40.194 bits. The smaller partition does not preserve the `w = 2` margin
because it also reduces both hash widths.

The measurements are reproducible with:

```text
python analysis/rev_cuckoo_hash_relations.py --trials 1000 --width-slack 0
python analysis/rev_cuckoo_hash_relations.py --trials 1000
python -m unittest -v analysis/test_rev_cuckoo_hash_relations.py
```

The `--width-slack` option is an analysis override used to compare the old
widths against the fixed margin. It is not a protocol parameter.

Under the stated ideal models, this is a complete caller-level union bound for
RingLPN. It includes every zero-linear-moment rank class and the ordinary rank
loss of the final compression. The Monte Carlo spectrum remains useful only
as a check on the conservative maximum-density relaxation.

The calculation supports a fixed construction margin rather than a new hash
or another security parameter. For the RingLPN `w = 2` profile, the
implementation retains `linearSecParam = 40` and adds eight bits internally.
This raises both widths to 64 bits and gives 41.935 bits under the stated
model. A higher-degree layer is unnecessary for this target and would require
a separate analysis.

## 9. Scope limits

This report analyzes rank and consistency of the one-AND-layer hash after the
input partition is fixed. It does not claim an end-to-end attack probability
for the current PCGs, and it does not analyze malicious bias of the joint
coin-tossing step. The current RevCuckoo use is semi-honest, so malicious
coin-tossing is a separate question.

For RingLPN, the complete bound assumes an ideal uniform shuffle, ideal random
linear maps, and uniform block offsets. It does not cover a malicious party
that biases joint sampling. The AnyField caller still needs its own
input-distribution analysis.
