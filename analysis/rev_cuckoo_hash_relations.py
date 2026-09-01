#!/usr/bin/env python3
"""Bounded relation analysis for the RevCuckoo Goldreich hash.

The Ring-LPN caller gives each DMPF set the ``weight`` diagonal sums

    left[poly_a, i] + right[poly_b, block - i]

over ordinary integers.  Every summand lies in ``[0, block_size)``, so the
result lies in the DPF domain ``[0, 2 * block_size)``.  RevCuckoo deduplicates
each set before shuffling it.

This analyzer counts the binary-XOR relations preserved unusually often by
the degree-two Goldreich lift:

* four-point affine planes (XOR parallelograms); and
* eight-point affine three-flats (affine cubes).

It then integrates out an ideal uniform shuffle analytically.  It does not
sample hash seeds and does not assume independent failure events across sets.
The reported failure contributions are union bounds.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from typing import Iterable, Iterator, Sequence


def falling_factorial(n: int, k: int) -> int:
    if k < 0 or k > n:
        return 0
    result = 1
    for value in range(n - k + 1, n + 1):
        result *= value
    return result


def next_power_of_two(value: int) -> int:
    if value <= 0:
        raise ValueError("value must be positive")
    return 1 << (value - 1).bit_length()


def partition_size(weight: int, partitions: int) -> int:
    """Mirror RevCuckooDmpf::init for the supported partition counts."""
    if weight <= 0:
        raise ValueError("weight must be positive")
    if partitions == 2:
        return next_power_of_two(weight)
    if partitions == 3:
        return next_power_of_two((weight + 1) // 2)
    raise ValueError("RevCuckoo supports two or three partitions")


def same_partition_probability(partitions: int, size: int, arity: int) -> float:
    """Probability that fixed distinct rows share one partition after shuffling."""
    total = partitions * size
    if arity > size:
        return 0.0
    return partitions * falling_factorial(size, arity) / falling_factorial(total, arity)


def label_xor_zero_probability(size: int, arity: int) -> float:
    """Probability that a uniform arity-subset of F_2^log2(size) XORs to zero."""
    if size <= 0 or size & (size - 1):
        raise ValueError("label domain size must be a power of two")
    if arity < 0 or arity > size:
        return 0.0
    total = math.comb(size, arity)
    if total == 0:
        return 0.0

    # Character orthogonality gives
    #   N_0 = (C(size,k) + (size-1)[z^k](1-z^2)^(size/2)) / size.
    signed = 0
    if arity % 2 == 0:
        half_arity = arity // 2
        if half_arity <= size // 2:
            signed = (-1) ** half_arity * math.comb(size // 2, half_arity)
    zero_count = (total + (size - 1) * signed) // size
    return zero_count / total


def count_xor_parallelograms(points: Sequence[int]) -> int:
    """Count four-element subsets whose XOR is zero in O(r^2) time."""
    unique = tuple(dict.fromkeys(points))
    pair_counts: dict[int, int] = {}
    for left, right in combinations(unique, 2):
        value = left ^ right
        pair_counts[value] = pair_counts.get(value, 0) + 1

    # Every four-set of XOR zero has exactly three complementary pairings.
    paired_pairs = sum(count * (count - 1) // 2 for count in pair_counts.values())
    if paired_pairs % 3:
        raise AssertionError("pair count does not decompose into parallelograms")
    return paired_pairs // 3


def count_affine_three_flats(points: Sequence[int]) -> int:
    """Count eight-element affine F_2-subspaces of dimension three.

    For each base point, enumerate unordered triples of independent direction
    vectors.  One contained affine three-flat has eight base points and 28
    unordered bases at each base point, so the raw count is divided by 224.
    """
    unique = tuple(dict.fromkeys(points))
    if len(unique) < 8:
        return 0
    point_set = set(unique)
    basis_hits = 0
    for base in unique:
        directions = [point ^ base for point in unique if point != base]
        for first, second, third in combinations(directions, 3):
            # Three distinct nonzero vectors are dependent exactly when their
            # XOR is zero or one equals the XOR of the other two.
            if third == (first ^ second):
                continue
            vertices = (
                base ^ first ^ second,
                base ^ first ^ third,
                base ^ second ^ third,
                base ^ first ^ second ^ third,
            )
            if all(vertex in point_set for vertex in vertices):
                basis_hits += 1
    if basis_hits % 224:
        raise AssertionError("basis count does not decompose into affine three-flats")
    return basis_hits // 224


def gf2_rank(rows: Sequence[int]) -> int:
    """Return the binary rank of a matrix whose rows are integer bit vectors."""
    pivots: dict[int, int] = {}
    for source in rows:
        row = source
        while row:
            pivot = row.bit_length() - 1
            if pivot in pivots:
                row ^= pivots[pivot]
            else:
                pivots[pivot] = row
                break
    return len(pivots)


def quadratic_moment_rank(points: Sequence[int], relation_mask: int) -> int:
    """Return rank(sum x x^T) for the rows selected by relation_mask."""
    if relation_mask < 0 or relation_mask >= 1 << len(points):
        raise ValueError("relation mask is outside the point set")
    dimension = max((point.bit_length() for point in points), default=0)
    rows = [0] * dimension
    for index, point in enumerate(points):
        if relation_mask >> index & 1:
            bits = point
            while bits:
                bit = bits & -bits
                rows[bit.bit_length() - 1] ^= point
                bits ^= bit
    return gf2_rank(rows)


def zero_linear_moment_spectrum(points: Sequence[int]) -> Counter[tuple[int, int]]:
    """Count all nonempty relations by (weight, quadratic-moment rank).

    RevCuckoo anchors each real input at the sentinel N.  Since every real
    input is below N, an anchored linear moment vanishes exactly when the
    relation has even weight and the XOR of its real inputs is zero.
    """
    unique = tuple(dict.fromkeys(points))
    split = len(unique) // 2
    left = unique[:split]
    right = unique[split:]

    def subset_data(values: Sequence[int]) -> list[tuple[int, int]]:
        data = [(0, 0)] * (1 << len(values))
        for mask in range(1, 1 << len(values)):
            bit = mask & -mask
            index = bit.bit_length() - 1
            prior_xor, prior_weight = data[mask ^ bit]
            data[mask] = (prior_xor ^ values[index], prior_weight + 1)
        return data

    left_data = subset_data(left)
    right_data = subset_data(right)
    left_by_xor: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for mask, (value, weight) in enumerate(left_data):
        left_by_xor[value].append((mask, weight))

    spectrum: Counter[tuple[int, int]] = Counter()
    for right_mask, (value, right_weight) in enumerate(right_data):
        for left_mask, left_weight in left_by_xor.get(value, ()):
            weight = left_weight + right_weight
            if weight == 0 or weight & 1:
                continue
            relation_mask = left_mask | (right_mask << split)
            rank = quadratic_moment_rank(unique, relation_mask)
            spectrum[weight, rank] += 1
    return spectrum


def uniform_expected_parallelograms(rows: int, domain: int) -> float:
    """Expected plane count in a uniform rows-subset of an F_2 domain."""
    if domain <= 0 or domain & (domain - 1):
        raise ValueError("domain must be a power of two")
    if rows < 4:
        return 0.0
    return math.comb(rows, 4) / (domain - 3)


def uniform_expected_cubes(rows: int, domain: int) -> float:
    """Expected affine three-flat count in a uniform rows-subset."""
    if domain <= 0 or domain & (domain - 1):
        raise ValueError("domain must be a power of two")
    if rows < 8:
        return 0.0
    flats = domain * (domain - 1) * (domain - 2) * (domain - 4) // 1344
    return flats * math.comb(rows, 8) / math.comb(domain, 8)


def iid_affine_cube_expectation_bound(
    rows: int,
    domain: int,
    density_ratio: float,
) -> float:
    """Bound expected cubes for iid points with max mass density_ratio/domain.

    A union bound assigns eight distinct sample positions to the vertices of
    each affine cube.  Relative to a uniform rows-subset, replacing every
    point mass by density_ratio/domain costs at most density_ratio**8.
    Deduplication cannot create a cube, so the same bound applies afterward.
    """
    if density_ratio < 0.0:
        raise ValueError("density ratio must be nonnegative")
    return uniform_expected_cubes(rows, domain) * density_ratio**8


def triangular_distinct_xor_zero_probability(block_size: int) -> float:
    """Return Pr[X1 XOR ... XOR X4 = 0 and the Xi are distinct].

    Each Xi is the ordinary-integer sum of two independent uniform elements
    of [block_size].  The DPF domain has size 2*block_size.  Parseval's
    identity for the Walsh transform gives the unrestricted XOR-zero
    probability.  The final two terms remove the all-equal and two-pair cases.
    """
    domain = 2 * block_size
    if block_size <= 0 or domain & (domain - 1):
        raise ValueError("twice the block size must be a power of two")
    probabilities = [0.0] * domain
    denominator = float(block_size * block_size)
    for point in range(domain - 1):
        multiplicity = (
            point + 1 if point < block_size else 2 * block_size - 1 - point
        )
        probabilities[point] = multiplicity / denominator

    second_moment = sum(value * value for value in probabilities)
    fourth_moment = sum(value**4 for value in probabilities)
    transform = probabilities.copy()
    width = 1
    while width < domain:
        for offset in range(0, domain, 2 * width):
            for index in range(offset, offset + width):
                left = transform[index]
                right = transform[index + width]
                transform[index] = left + right
                transform[index + width] = left - right
        width *= 2
    unrestricted = sum(value**4 for value in transform) / domain
    distinct = unrestricted - 3.0 * second_moment**2 + 2.0 * fourth_moment
    return max(0.0, distinct)


def triangular_parallelogram_expectation_bound(
    rows: int,
    block_size: int,
) -> float:
    """Bound expected distinct parallelograms after deduplicating iid rows."""
    if rows < 4:
        return 0.0
    return math.comb(rows, 4) * triangular_distinct_xor_zero_probability(block_size)


def alternating_form_count(dimension: int, rank: int) -> int:
    """Count alternating binary matrices of the requested rank."""
    if dimension < 0 or rank < 0 or rank > dimension or rank & 1:
        return 0
    if rank == 0:
        return 1
    half_rank = rank // 2
    numerator = math.prod((1 << dimension) - (1 << index) for index in range(rank))
    symplectic_order = (1 << (half_rank * half_rank)) * math.prod(
        (1 << (2 * index)) - 1 for index in range(1, half_rank + 1)
    )
    return numerator // symplectic_order


def binary_krawtchouk(length: int, degree: int, point: int) -> int:
    """Evaluate the binary Krawtchouk polynomial K_degree(point)."""
    lower = max(0, degree - (length - point))
    upper = min(degree, point)
    return sum(
        (-1 if index & 1 else 1)
        * math.comb(point, index)
        * math.comb(length - point, degree - index)
        for index in range(lower, upper + 1)
    )


def gaussian_binomial(top: int, bottom: int, base: int) -> int:
    """Return the Gaussian binomial coefficient with the requested base."""
    if bottom < 0 or bottom > top:
        return 0
    numerator = 1
    denominator = 1
    for index in range(bottom):
        numerator *= base**top - base**index
        denominator *= base**bottom - base**index
    return numerator // denominator


def alternating_forms_eigenvalue(
    dimension: int,
    character_half_rank: int,
    orbit_half_rank: int,
) -> int:
    """Return an eigenvalue of the binary alternating-forms scheme."""
    diameter = dimension // 2
    if (
        diameter == 0
        or character_half_rank < 0
        or character_half_rank > diameter
        or orbit_half_rank < 0
        or orbit_half_rank > diameter
    ):
        return int(character_half_rank == 0 and orbit_half_rank == 0)
    parameter = dimension * (dimension - 1) // (2 * diameter)
    return sum(
        (-1 if (orbit_half_rank - index) & 1 else 1)
        * 2
        ** (
            (orbit_half_rank - index) * (orbit_half_rank - index - 1)
            + index * parameter
        )
        * gaussian_binomial(
            diameter - index,
            diameter - orbit_half_rank,
            4,
        )
        * gaussian_binomial(
            diameter - character_half_rank,
            index,
            4,
        )
        for index in range(orbit_half_rank + 1)
    )


def zero_linear_moment_rank_distribution(
    dimension: int,
    relation_weight: int,
) -> dict[int, int]:
    """Count supports by rank of their alternating quadratic moment.

    The Hamming MacWilliams transform fixes the constant and linear moments.
    The eigenmatrix of the alternating-forms scheme then resolves the
    quadratic syndrome by rank.
    """
    if dimension <= 1 or relation_weight < 0 or relation_weight > 1 << dimension:
        raise ValueError("invalid moment-distribution parameters")
    length = 1 << dimension
    diameter = dimension // 2
    code_dimension = 1 + dimension + dimension * (dimension - 1) // 2

    character_sums: list[int] = []
    for character_half_rank in range(diameter + 1):
        rank = 2 * character_half_rank
        deviation = 1 << (dimension - character_half_rank - 1)
        image_size = 1 << rank
        character_sums.append(
            image_size
            * (
                binary_krawtchouk(
                    length,
                    relation_weight,
                    length // 2 - deviation,
                )
                + binary_krawtchouk(
                    length,
                    relation_weight,
                    length // 2 + deviation,
                )
            )
            + 2
            * (length - image_size)
            * binary_krawtchouk(length, relation_weight, length // 2)
        )

    divisor = 1 << code_dimension
    distribution: dict[int, int] = {}
    for orbit_half_rank in range(diameter + 1):
        numerator = sum(
            alternating_form_count(dimension, 2 * character_half_rank)
            * alternating_forms_eigenvalue(
                dimension,
                character_half_rank,
                orbit_half_rank,
            )
            * character_sums[character_half_rank]
            for character_half_rank in range(diameter + 1)
        )
        if numerator % divisor:
            raise AssertionError("rank-resolved MacWilliams coefficient is not integral")
        coefficient = numerator // divisor
        if coefficient:
            distribution[2 * orbit_half_rank] = coefficient

    expected_total = 0
    if relation_weight % 2 == 0:
        expected_total = (
            math.comb(length, relation_weight)
            + (length - 1)
            * (-1) ** (relation_weight // 2)
            * math.comb(length // 2, relation_weight // 2)
        ) // length
    if sum(distribution.values()) != expected_total:
        raise AssertionError("rank-resolved moment counts have the wrong total")
    return distribution


def degree_two_dual_weight_distribution(
    dimension: int,
    maximum_weight: int,
) -> dict[int, int]:
    """Return low weights of RM(2, dimension)^perp via MacWilliams' identity."""
    if dimension <= 0 or maximum_weight < 0:
        raise ValueError("invalid Reed--Muller parameters")
    length = 1 << dimension
    maximum_weight = min(maximum_weight, length)
    code_dimension = 1 + dimension + dimension * (dimension - 1) // 2

    primal_weights: Counter[int] = Counter()
    for half_rank in range(dimension // 2 + 1):
        rank = 2 * half_rank
        forms = alternating_form_count(dimension, rank)
        deviation = 1 << (dimension - half_rank - 1)
        unbalanced_count = forms * (1 << rank)
        primal_weights[length // 2 - deviation] += unbalanced_count
        primal_weights[length // 2 + deviation] += unbalanced_count
        primal_weights[length // 2] += forms * 2 * (length - (1 << rank))

    if sum(primal_weights.values()) != 1 << code_dimension:
        raise AssertionError("invalid RM(2,m) weight distribution")

    dual_weights: dict[int, int] = {}
    divisor = 1 << code_dimension
    for weight in range(maximum_weight + 1):
        numerator = sum(
            count * binary_krawtchouk(length, weight, primal_weight)
            for primal_weight, count in primal_weights.items()
        )
        if numerator % divisor:
            raise AssertionError("MacWilliams coefficient is not integral")
        coefficient = numerator // divisor
        if coefficient:
            dual_weights[weight] = coefficient
    return dual_weights


def ring_lpn_sets(
    rng: random.Random,
    num_polynomials: int,
    weight: int,
    block_size: int,
) -> Iterator[tuple[int, ...]]:
    """Sample one caller batch and yield its deduplicated DPF point sets."""
    if num_polynomials <= 0 or weight <= 0 or block_size <= 0:
        raise ValueError("Ring-LPN parameters must be positive")
    left = [
        [rng.randrange(block_size) for _ in range(weight)]
        for _ in range(num_polynomials)
    ]
    right = [
        [rng.randrange(block_size) for _ in range(weight)]
        for _ in range(num_polynomials)
    ]
    for left_poly in range(num_polynomials):
        for right_poly in range(num_polynomials):
            for output_block in range(weight):
                points = {
                    left[left_poly][index]
                    + right[right_poly][(output_block - index) % weight]
                    for index in range(weight)
                }
                yield tuple(sorted(points))


@dataclass(frozen=True)
class Parameters:
    trials: int
    seed: int
    num_polynomials: int
    weight: int
    ring_size: int
    block_size: int
    dpf_domain: int
    partitions: int
    partition_size: int
    linear_security: int
    width_slack: int
    final_width: int
    intermediate_width: int


@dataclass(frozen=True)
class TrialResult:
    sets: int
    real_rows: int
    duplicate_rows: int
    parallelograms: int
    cubes: int
    sets_with_parallelogram: int
    sets_with_cube: int
    uniform_expected_parallelograms: float
    uniform_expected_cubes: float
    moment_spectrum: dict[str, int]


def one_trial(
    rng: random.Random,
    num_polynomials: int,
    weight: int,
    block_size: int,
) -> TrialResult:
    sets = 0
    real_rows = 0
    duplicate_rows = 0
    parallelograms = 0
    cubes = 0
    sets_with_parallelogram = 0
    sets_with_cube = 0
    uniform_planes = 0.0
    uniform_cubes = 0.0
    moment_spectrum: Counter[tuple[int, int]] = Counter()
    domain = 2 * block_size
    for points in ring_lpn_sets(rng, num_polynomials, weight, block_size):
        sets += 1
        real_rows += len(points)
        duplicate_rows += weight - len(points)
        set_spectrum = zero_linear_moment_spectrum(points)
        moment_spectrum.update(set_spectrum)
        plane_count = set_spectrum[4, 2]
        cube_count = set_spectrum[8, 0]
        parallelograms += plane_count
        cubes += cube_count
        sets_with_parallelogram += plane_count != 0
        sets_with_cube += cube_count != 0
        uniform_planes += uniform_expected_parallelograms(len(points), domain)
        uniform_cubes += uniform_expected_cubes(len(points), domain)
    return TrialResult(
        sets=sets,
        real_rows=real_rows,
        duplicate_rows=duplicate_rows,
        parallelograms=parallelograms,
        cubes=cubes,
        sets_with_parallelogram=sets_with_parallelogram,
        sets_with_cube=sets_with_cube,
        uniform_expected_parallelograms=uniform_planes,
        uniform_expected_cubes=uniform_cubes,
        moment_spectrum={
            f"{relation_weight}:{rank}": count
            for (relation_weight, rank), count in sorted(moment_spectrum.items())
        },
    )


def mean_and_error(values: Iterable[float | int]) -> tuple[float, float]:
    sample = list(values)
    mean = statistics.fmean(sample)
    if len(sample) < 2:
        return mean, 0.0
    return mean, statistics.stdev(sample) / math.sqrt(len(sample))


def security_bits(probability: float) -> float | None:
    if probability <= 0.0:
        return None
    return -math.log2(min(1.0, probability))


def relation_factor(parameters: Parameters, relation_weight: int, rank: int) -> float:
    """Union-bound factor for one global zero-linear-moment relation."""
    if rank < 0 or rank & 1:
        raise ValueError("an alternating quadratic moment must have even rank")
    if relation_weight <= 0:
        raise ValueError("relation weight must be positive")
    nonlinear_zero = (0.5 + 2.0 ** (-rank - 1)) ** parameters.intermediate_width
    hash_survival = nonlinear_zero + (
        1.0 - nonlinear_zero
    ) * 2.0 ** (-parameters.final_width)
    return (
        same_partition_probability(
            parameters.partitions,
            parameters.partition_size,
            relation_weight,
        )
        * (
            1.0
            - label_xor_zero_probability(
                parameters.partition_size,
                relation_weight,
            )
        )
        * hash_survival
    )


def compression_rank_loss_union_bound(parameters: Parameters) -> float:
    """Bound batch rank loss from the final random linear compression.

    The bound conditions on independent lifted rows.  It averages the active
    row count in one partition over a uniform shuffle, then unions over every
    partition and set.  Deduplication can only reduce the active row count.
    """
    slots = parameters.partitions * parameters.partition_size
    real_rows = parameters.weight
    if real_rows > slots:
        raise ValueError("more real rows than shuffle slots")
    partition_rows = parameters.partition_size
    denominator = math.comb(slots, partition_rows)
    lower = max(0, partition_rows - (slots - real_rows))
    upper = min(partition_rows, real_rows)
    expected_power = sum(
        math.comb(real_rows, count)
        * math.comb(slots - real_rows, partition_rows - count)
        * 2.0**count
        for count in range(lower, upper + 1)
    ) / denominator
    sets = parameters.num_polynomials**2 * parameters.weight
    return min(
        1.0,
        sets
        * parameters.partitions
        * expected_power
        * 2.0 ** (-parameters.final_width),
    )


def analyze(parameters: Parameters) -> dict[str, object]:
    rng = random.Random(parameters.seed)
    trials = [
        one_trial(
            rng,
            parameters.num_polynomials,
            parameters.weight,
            parameters.block_size,
        )
        for _ in range(parameters.trials)
    ]

    plane_mean, plane_error = mean_and_error(result.parallelograms for result in trials)
    cube_mean, cube_error = mean_and_error(result.cubes for result in trials)
    duplicate_mean, duplicate_error = mean_and_error(result.duplicate_rows for result in trials)
    uniform_plane_mean = statistics.fmean(
        result.uniform_expected_parallelograms for result in trials
    )
    uniform_cube_mean = statistics.fmean(result.uniform_expected_cubes for result in trials)

    spectrum_keys = sorted(
        {key for result in trials for key in result.moment_spectrum},
        key=lambda key: tuple(map(int, key.split(":"))),
    )
    spectrum_summary: dict[str, dict[str, float | int | None]] = {}
    spectrum_factors: dict[str, float] = {}
    for key in spectrum_keys:
        relation_weight, rank = map(int, key.split(":"))
        mean, error = mean_and_error(
            result.moment_spectrum.get(key, 0) for result in trials
        )
        factor = relation_factor(parameters, relation_weight, rank)
        spectrum_factors[key] = factor
        spectrum_summary[key] = {
            "relation_weight": relation_weight,
            "quadratic_rank": rank,
            "mean_count_per_trial": mean,
            "stderr_count_per_trial": error,
            "factor_per_relation": factor,
            "mean_union_contribution": mean * factor,
            "contribution_bits": security_bits(mean * factor),
        }

    structural_trial_contributions = [
        sum(
            count * spectrum_factors[key]
            for key, count in result.moment_spectrum.items()
        )
        for result in trials
    ]
    structural_mean, structural_error = mean_and_error(structural_trial_contributions)

    d = parameters.partition_size
    plane_factor = relation_factor(parameters, 4, 2)
    cube_factor = relation_factor(parameters, 8, 0)
    plane_hash = (5.0 / 8.0) ** parameters.intermediate_width
    plane_hash += (1.0 - plane_hash) * 2.0 ** (-parameters.final_width)
    plane_bound = min(1.0, plane_mean * plane_factor)
    cube_bound = min(1.0, cube_mean * cube_factor)
    combined_bound = min(1.0, structural_mean)
    triangular_cube_count_bound = (
        trials[0].sets
        * iid_affine_cube_expectation_bound(
            parameters.weight,
            parameters.dpf_domain,
            2.0,
        )
    )
    triangular_cube_union_bound = min(
        1.0,
        triangular_cube_count_bound * cube_factor,
    )
    combined_with_cube_bound = min(
        1.0,
        structural_mean + triangular_cube_union_bound,
    )
    triangular_plane_count_bound = (
        trials[0].sets
        * triangular_parallelogram_expectation_bound(
            parameters.weight,
            parameters.block_size,
        )
    )
    triangular_plane_union_bound = min(
        1.0,
        triangular_plane_count_bound * plane_factor,
    )
    deterministic_supports = degree_two_dual_weight_distribution(
        parameters.dpf_domain.bit_length() - 1,
        parameters.weight,
    )
    deterministic_classes: dict[str, dict[str, float | int | None]] = {}
    deterministic_union_bound = 0.0
    for relation_weight, support_count in deterministic_supports.items():
        if relation_weight == 0:
            continue
        expected_count_bound = (
            trials[0].sets
            * support_count
            * falling_factorial(parameters.weight, relation_weight)
            * (2.0 / parameters.dpf_domain) ** relation_weight
        )
        factor = relation_factor(parameters, relation_weight, 0)
        contribution = expected_count_bound * factor
        deterministic_union_bound += contribution
        deterministic_classes[str(relation_weight)] = {
            "relation_weight": relation_weight,
            "support_count": support_count,
            "expected_count_bound": expected_count_bound,
            "factor_per_relation": factor,
            "union_contribution": contribution,
            "contribution_bits": security_bits(contribution),
        }
    deterministic_union_bound = min(1.0, deterministic_union_bound)
    compression_bound = compression_rank_loss_union_bound(parameters)
    minimum_relation_union_bound = min(
        1.0,
        triangular_plane_union_bound + deterministic_union_bound,
    )
    analytic_accounted_bound = min(
        1.0,
        minimum_relation_union_bound + compression_bound,
    )
    rank_resolved_classes: dict[str, dict[str, float | int | str | None]] = {}
    rank_resolved_union_bound = 0.0
    dimension = parameters.dpf_domain.bit_length() - 1
    for relation_weight in range(4, parameters.weight + 1, 2):
        rank_distribution = zero_linear_moment_rank_distribution(
            dimension,
            relation_weight,
        )
        for rank, support_count in rank_distribution.items():
            if relation_weight == 4 and rank == 2:
                expected_count_bound = triangular_plane_count_bound
                method = "exact triangular XOR transform"
            else:
                expected_count_bound = (
                    trials[0].sets
                    * support_count
                    * falling_factorial(parameters.weight, relation_weight)
                    * (2.0 / parameters.dpf_domain) ** relation_weight
                )
                method = "maximum-density bound"
            factor = relation_factor(parameters, relation_weight, rank)
            contribution = expected_count_bound * factor
            rank_resolved_union_bound += contribution
            rank_resolved_classes[f"{relation_weight}:{rank}"] = {
                "relation_weight": relation_weight,
                "quadratic_rank": rank,
                "support_count": support_count,
                "expected_count_bound": expected_count_bound,
                "counting_method": method,
                "factor_per_relation": factor,
                "union_contribution": contribution,
                "contribution_bits": security_bits(contribution),
            }
    rank_resolved_union_bound = min(1.0, rank_resolved_union_bound)
    full_analytic_bound = min(
        1.0,
        rank_resolved_union_bound + compression_bound,
    )

    return {
        "parameters": asdict(parameters),
        "per_trial": [asdict(result) for result in trials],
        "summary": {
            "sets_per_trial": trials[0].sets,
            "mean_real_rows_per_set": statistics.fmean(
                result.real_rows / result.sets for result in trials
            ),
            "mean_duplicate_rows_per_trial": duplicate_mean,
            "stderr_duplicate_rows_per_trial": duplicate_error,
            "mean_parallelograms_per_trial": plane_mean,
            "stderr_parallelograms_per_trial": plane_error,
            "uniform_expected_parallelograms_per_trial": uniform_plane_mean,
            "parallelogram_ratio_to_uniform": (
                plane_mean / uniform_plane_mean if uniform_plane_mean else None
            ),
            "mean_cubes_per_trial": cube_mean,
            "stderr_cubes_per_trial": cube_error,
            "uniform_expected_cubes_per_trial": uniform_cube_mean,
            "mean_sets_with_parallelogram": statistics.fmean(
                result.sets_with_parallelogram for result in trials
            ),
            "mean_sets_with_cube": statistics.fmean(
                result.sets_with_cube for result in trials
            ),
        },
        "zero_linear_moment_spectrum": spectrum_summary,
        "triangular_affine_cube_bound": {
            "maximum_density_ratio": 2.0,
            "expected_cubes_per_trial": triangular_cube_count_bound,
            "union_contribution": triangular_cube_union_bound,
            "contribution_bits": security_bits(triangular_cube_union_bound),
        },
        "triangular_parallelogram_bound": {
            "expected_index_quartets_per_trial": triangular_plane_count_bound,
            "union_contribution": triangular_plane_union_bound,
            "contribution_bits": security_bits(triangular_plane_union_bound),
        },
        "deterministic_relation_bound": {
            "classes": deterministic_classes,
            "union_contribution": deterministic_union_bound,
            "contribution_bits": security_bits(deterministic_union_bound),
        },
        "compression_rank_loss_bound": {
            "union_contribution": compression_bound,
            "contribution_bits": security_bits(compression_bound),
        },
        "rank_resolved_relation_bound": {
            "classes": rank_resolved_classes,
            "union_contribution": rank_resolved_union_bound,
            "contribution_bits": security_bits(rank_resolved_union_bound),
        },
        "analytic_factors": {
            "parallelogram_same_partition": same_partition_probability(
                parameters.partitions, d, 4
            ),
            "parallelogram_harmful_label": 1.0 - label_xor_zero_probability(d, 4),
            "parallelogram_hash_survival": plane_hash,
            "parallelogram_per_relation": plane_factor,
            "cube_same_partition": same_partition_probability(parameters.partitions, d, 8),
            "cube_harmful_label": 1.0 - label_xor_zero_probability(d, 8),
            "cube_per_relation": cube_factor,
        },
        "estimated_union_contributions": {
            "parallelogram": plane_bound,
            "parallelogram_stderr": plane_error * plane_factor,
            "parallelogram_bits": security_bits(plane_bound),
            "cube": cube_bound,
            "cube_stderr": cube_error * cube_factor,
            "cube_bits": security_bits(cube_bound),
            "combined": combined_bound,
            "combined_stderr": structural_error,
            "combined_bits": security_bits(combined_bound),
            "combined_with_cube_bound": combined_with_cube_bound,
            "combined_with_cube_bound_bits": security_bits(combined_with_cube_bound),
            "minimum_relation_bound": minimum_relation_union_bound,
            "minimum_relation_bound_bits": security_bits(minimum_relation_union_bound),
            "analytic_accounted_bound": analytic_accounted_bound,
            "analytic_accounted_bound_bits": security_bits(analytic_accounted_bound),
            "full_analytic_bound": full_analytic_bound,
            "full_analytic_bound_bits": security_bits(full_analytic_bound),
        },
    }


def make_parameters(args: argparse.Namespace) -> Parameters:
    if args.trials <= 0:
        raise ValueError("trials must be positive")
    if args.ring_size <= 0 or args.ring_size % args.weight:
        raise ValueError("ring size must be a positive multiple of weight")
    block_size = args.ring_size // args.weight
    dpf_domain = 2 * block_size
    if dpf_domain & (dpf_domain - 1):
        raise ValueError("the Ring-LPN DPF domain must be a power of two")
    d = partition_size(args.weight, args.partitions)
    if args.linear_security < 0 or args.width_slack < 0:
        raise ValueError("security and width-slack parameters must be nonnegative")
    q = 8 * ((d + args.linear_security + args.width_slack + 7) // 8)
    q_prime = (
        args.intermediate_width
        if args.intermediate_width is not None
        else 8 * ((q + 7) // 8)
    )
    if q_prime <= 0:
        raise ValueError("intermediate width must be positive")
    return Parameters(
        trials=args.trials,
        seed=args.seed,
        num_polynomials=args.num_polynomials,
        weight=args.weight,
        ring_size=args.ring_size,
        block_size=block_size,
        dpf_domain=dpf_domain,
        partitions=args.partitions,
        partition_size=d,
        linear_security=args.linear_security,
        width_slack=args.width_slack,
        final_width=q,
        intermediate_width=q_prime,
    )


def print_report(report: dict[str, object]) -> None:
    parameters = report["parameters"]
    summary = report["summary"]
    factors = report["analytic_factors"]
    bounds = report["estimated_union_contributions"]
    spectrum = report["zero_linear_moment_spectrum"]
    cube_density = report["triangular_affine_cube_bound"]
    plane_analytic = report["triangular_parallelogram_bound"]
    deterministic = report["deterministic_relation_bound"]
    compression = report["compression_rank_loss_bound"]
    rank_resolved = report["rank_resolved_relation_bound"]
    assert isinstance(parameters, dict)
    assert isinstance(summary, dict)
    assert isinstance(factors, dict)
    assert isinstance(bounds, dict)
    assert isinstance(spectrum, dict)
    assert isinstance(cube_density, dict)
    assert isinstance(plane_analytic, dict)
    assert isinstance(deterministic, dict)
    assert isinstance(compression, dict)
    assert isinstance(rank_resolved, dict)

    print("RevCuckoo Goldreich relation analysis")
    print(
        f"  trials={parameters['trials']}  P={parameters['num_polynomials']}  "
        f"t={parameters['weight']}  ring={parameters['ring_size']}"
    )
    print(
        f"  w={parameters['partitions']}  d={parameters['partition_size']}  "
        f"sec={parameters['linear_security']}  slack={parameters['width_slack']}  "
        f"q={parameters['final_width']}  q'={parameters['intermediate_width']}"
    )
    print(
        f"  sets/trial={summary['sets_per_trial']}  "
        f"mean real rows/set={summary['mean_real_rows_per_set']:.6f}"
    )
    print(
        "  parallelograms/trial="
        f"{summary['mean_parallelograms_per_trial']:.6g} +/- "
        f"{summary['stderr_parallelograms_per_trial']:.3g}"
    )
    print(
        "  uniform-subset baseline="
        f"{summary['uniform_expected_parallelograms_per_trial']:.6g}  "
        f"ratio={summary['parallelogram_ratio_to_uniform']:.6f}"
    )
    print(
        f"  cubes/trial={summary['mean_cubes_per_trial']:.6g} +/- "
        f"{summary['stderr_cubes_per_trial']:.3g}"
    )
    print("Zero-linear-moment classes by union contribution")
    ordered_classes = sorted(
        spectrum.values(),
        key=lambda item: item["mean_union_contribution"],
        reverse=True,
    )
    for item in ordered_classes[:10]:
        print(
            f"  weight={item['relation_weight']:2d} rank={item['quadratic_rank']:2d}  "
            f"count={item['mean_count_per_trial']:.6g} +/- "
            f"{item['stderr_count_per_trial']:.3g}  "
            f"contribution={item['mean_union_contribution']:.6e} "
            f"({_format_bits(item['contribution_bits'])})"
        )
    print("Analytic factor per global relation")
    print(
        f"  parallelogram={factors['parallelogram_per_relation']:.6e}  "
        f"cube={factors['cube_per_relation']:.6e}"
    )
    print("Estimated mean batch union contribution")
    print(
        f"  parallelogram={bounds['parallelogram']:.6e} +/- "
        f"{bounds['parallelogram_stderr']:.2e} "
        f"({_format_bits(bounds['parallelogram_bits'])})"
    )
    print(
        "  parallelogram analytic bound="
        f"{plane_analytic['union_contribution']:.6e} "
        f"({_format_bits(plane_analytic['contribution_bits'])})"
    )
    print(
        f"  cube={bounds['cube']:.6e} +/- {bounds['cube_stderr']:.2e} "
        f"({_format_bits(bounds['cube_bits'])})"
    )
    print(
        "  affine-cube density bound="
        f"{cube_density['union_contribution']:.6e} "
        f"({_format_bits(cube_density['contribution_bits'])})"
    )
    print(
        "  all deterministic relations="
        f"{deterministic['union_contribution']:.6e} "
        f"({_format_bits(deterministic['contribution_bits'])})"
    )
    for item in deterministic["classes"].values():
        print(
            f"    weight={item['relation_weight']:2d}  "
            f"count-bound={item['expected_count_bound']:.6e}  "
            f"contribution={item['union_contribution']:.6e} "
            f"({_format_bits(item['contribution_bits'])})"
        )
    print(
        f"  all-zero-linear-moment={bounds['combined']:.6e} +/- "
        f"{bounds['combined_stderr']:.2e} "
        f"({_format_bits(bounds['combined_bits'])})"
    )
    print(
        "  estimated spectrum plus cube bound="
        f"{bounds['combined_with_cube_bound']:.6e} "
        f"({_format_bits(bounds['combined_with_cube_bound_bits'])})"
    )
    print(
        "  analytic planes plus all deterministic relations="
        f"{bounds['minimum_relation_bound']:.6e} "
        f"({_format_bits(bounds['minimum_relation_bound_bits'])})"
    )
    print(
        "  final-compression rank-loss bound="
        f"{compression['union_contribution']:.6e} "
        f"({_format_bits(compression['contribution_bits'])})"
    )
    print(
        "  analytic accounted classes="
        f"{bounds['analytic_accounted_bound']:.6e} "
        f"({_format_bits(bounds['analytic_accounted_bound_bits'])})"
    )
    print(
        "  all rank-resolved structural relations="
        f"{rank_resolved['union_contribution']:.6e} "
        f"({_format_bits(rank_resolved['contribution_bits'])})"
    )
    ordered_bounds = sorted(
        rank_resolved["classes"].values(),
        key=lambda item: item["union_contribution"],
        reverse=True,
    )
    for item in ordered_bounds[:8]:
        print(
            f"    weight={item['relation_weight']:2d} "
            f"rank={item['quadratic_rank']:2d}  "
            f"contribution={item['union_contribution']:.6e} "
            f"({_format_bits(item['contribution_bits'])})"
        )
    print(
        "  full analytic batch bound="
        f"{bounds['full_analytic_bound']:.6e} "
        f"({_format_bits(bounds['full_analytic_bound_bits'])})"
    )
    print("  Spectrum rows are Monte Carlo estimates; analytic bounds are distributional bounds.")


def _format_bits(bits: float | None) -> str:
    return "no observed contribution" if bits is None else f"{bits:.3f} bits"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--num-polynomials", type=int, default=4)
    parser.add_argument("--weight", type=int, default=16)
    parser.add_argument("--ring-size", type=int, default=1 << 20)
    parser.add_argument("--partitions", type=int, choices=(2, 3), default=2)
    parser.add_argument("--linear-security", type=int, default=40)
    parser.add_argument(
        "--width-slack",
        type=int,
        default=8,
        help="analysis override for the fixed eight-bit implementation margin",
    )
    parser.add_argument(
        "--intermediate-width",
        type=int,
        help="override q'; the default is q rounded up to a whole byte",
    )
    parser.add_argument("--json", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    parameters = make_parameters(args)
    report = analyze(parameters)
    print_report(report)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
