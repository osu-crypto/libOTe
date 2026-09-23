#!/usr/bin/env python3
"""Exact correctness accounting after the proposed folded-support filter.

Each party independently samples P regular supports until their total number
of occupied residues is at least the threshold. Each product list depends on
one polynomial per party. Its marginal density increases by at most (b/a)^2,
where a is local acceptance and b is the maximum acceptance probability after
fixing one polynomial. Apply this factor to the additive structural bound,
not directly to an arbitrary batch event. Final compression is bounded
pointwise in the supports and needs no conditioning factor.

This is a deterministic calculation, not a sampler or an attack experiment.
All probabilities below are rational; floats are used only for display.
"""

from __future__ import annotations

import argparse
import json
import math
from fractions import Fraction
from functools import lru_cache

from analysis.rev_cuckoo_hash_relations import (
    Parameters,
    falling_factorial,
    make_parameters,
    zero_linear_moment_rank_distribution,
)


def folded_weight_counts(polys: int, weight: int, degree: int) -> tuple[int, ...]:
    """Count residue assignments by total occupancy, separately per polynomial."""
    if polys < 0 or weight < 0 or degree <= 0:
        raise ValueError("invalid occupancy parameters")
    one = [1] + [0] * weight
    for _ in range(weight):
        following = [0] * (weight + 1)
        for occupied, count in enumerate(one):
            following[occupied] += occupied * count
            if occupied < min(weight, degree):
                following[occupied + 1] += (degree - occupied) * count
        one = following
    total = [1]
    for _ in range(polys):
        following = [0] * (len(total) + weight)
        for left, left_count in enumerate(total):
            for right, right_count in enumerate(one):
                following[left + right] += left_count * right_count
        total = following
    return tuple(total)


def acceptance_probability(polys: int, weight: int, degree: int,
                           threshold: int) -> Fraction:
    counts = folded_weight_counts(polys, weight, degree)
    return Fraction(sum(counts[max(0, threshold):]), degree ** (polys * weight))


def conditioning_factors(polys: int, weight: int, degree: int,
                         threshold: int) -> tuple[Fraction, Fraction, Fraction]:
    """Return acceptance a, maximum completion b, and pair-density bound."""
    if polys <= 0:
        raise ValueError("at least one polynomial is required")
    acceptance = acceptance_probability(polys, weight, degree, threshold)
    if not acceptance:
        raise ValueError("the filter has zero acceptance probability")
    completion = acceptance_probability(
        polys - 1, weight, degree, threshold - min(weight, degree)
    )
    return acceptance, completion, (completion / acceptance) ** 2


@lru_cache(maxsize=None)
def triangular_distinct_xor_probability(block_size: int) -> Fraction:
    """Integer Walsh transform for four distinct triangular samples."""
    if block_size <= 0 or block_size & (block_size - 1):
        raise ValueError("block size must be a positive power of two")
    domain = 2 * block_size
    counts = [min(x + 1, domain - 1 - x) for x in range(domain)]
    second = sum(x * x for x in counts)
    fourth = sum(x ** 4 for x in counts)
    width = 1
    while width < domain:
        for offset in range(0, domain, 2 * width):
            for index in range(offset, offset + width):
                left, right = counts[index], counts[index + width]
                counts[index], counts[index + width] = left + right, left - right
        width *= 2
    unrestricted = Fraction(sum(x ** 4 for x in counts), domain)
    return (unrestricted - 3 * second ** 2 + 2 * fourth) / block_size ** 8


def exact_hash_bounds(parameters: Parameters) -> tuple[Fraction, Fraction]:
    """Reproduce the original structural and compression bounds, without floats.

    The structural sum retains the original analyzer's final-compression
    survival term; counting it again in the separate compression bound is
    conservative. This preserves the existing numerical comparison point.
    """
    p = parameters
    sets = p.num_polynomials ** 2 * p.weight
    slots = p.partitions * p.partition_size
    if p.weight > slots:
        raise ValueError("more real rows than shuffle slots")
    dimension = p.dpf_domain.bit_length() - 1
    structural = Fraction(0)
    for arity in range(4, min(p.weight, p.partition_size) + 1, 2):
        placement = Fraction(
            p.partitions * falling_factorial(p.partition_size, arity),
            falling_factorial(slots, arity),
        )
        labels = math.comb(p.partition_size, arity)
        zero_labels = Fraction(
            labels + (p.partition_size - 1) * (-1) ** (arity // 2)
            * math.comb(p.partition_size // 2, arity // 2),
            p.partition_size * labels,
        )
        for rank, count in zero_linear_moment_rank_distribution(dimension, arity).items():
            if arity == 4 and rank == 2:
                expected = (sets * math.comb(p.weight, 4)
                            * triangular_distinct_xor_probability(p.block_size))
            else:
                expected = (sets * falling_factorial(p.weight, arity) * count
                            * Fraction(2, p.dpf_domain) ** arity)
            lift = (Fraction(1, 2) + Fraction(1, 2 ** (rank + 1))) ** p.intermediate_width
            survival = lift + (1 - lift) / 2 ** p.final_width
            structural += expected * placement * (1 - zero_labels) * survival
    occupancy = sum(
        math.comb(p.partition_size, real)
        * math.comb(slots - p.partition_size, p.weight - real) * 2 ** real
        for real in range(max(0, p.weight - slots + p.partition_size),
                          min(p.weight, p.partition_size) + 1)
    )
    compression = Fraction(
        sets * p.partitions * occupancy,
        math.comb(slots, p.weight) * 2 ** p.final_width,
    )
    return structural, compression


def conditioned_hash_bound(parameters: Parameters, degree: int = 128,
                           threshold: int = 61) -> dict[str, Fraction]:
    if degree <= 0 or parameters.block_size % degree:
        raise ValueError("this occupancy law requires degree to divide block size")
    acceptance, completion, factor = conditioning_factors(
        parameters.num_polynomials, parameters.weight, degree, threshold
    )
    structural, compression = exact_hash_bounds(parameters)
    return {
        "local_acceptance": acceptance,
        "max_completion": completion,
        "pair_density_factor": factor,
        "unfiltered_structural": structural,
        "compression": compression,
        "unfiltered_complete": structural + compression,
        "blanket_conditioned": (structural + compression) / acceptance ** 2,
        "pair_conditioned": factor * (structural + compression),
        "conditioned_complete": factor * structural + compression,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ring-size", type=int, default=1 << 20)
    parser.add_argument("--minimum-folded-weight", type=int, default=61)
    args = parser.parse_args()
    parameters = make_parameters(argparse.Namespace(
        trials=1, seed=0, num_polynomials=4, weight=16,
        ring_size=args.ring_size, partitions=2, linear_security=40,
        width_slack=8, intermediate_width=None,
    ))
    bounds = conditioned_hash_bound(parameters, threshold=args.minimum_folded_weight)
    report = {
        "parameters": {"ring_size": parameters.ring_size, "P": 4, "t": 16,
                       "w": 2, "d": 16, "q": 64, "q_prime": 64,
                       "fold_degree": 128, "minimum_weight": args.minimum_folded_weight},
        "bounds": {key: {"value": float(value),
                         "negative_log2": -math.log2(float(value)) if value else None}
                   for key, value in bounds.items()},
        "below_2_to_minus_40_exact": bounds["conditioned_complete"] < Fraction(1, 2 ** 40),
        "scope": "Independent local support-only filters; ideal shuffle and evaluator maps. "
                 "Not an attack estimate; does not implement rejection sampling.",
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
