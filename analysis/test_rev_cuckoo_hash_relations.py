#!/usr/bin/env python3

import argparse
import itertools
import math
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.rev_cuckoo_hash_relations import (
    Parameters,
    alternating_form_count,
    alternating_forms_eigenvalue,
    compression_rank_loss_union_bound,
    count_affine_three_flats,
    count_xor_parallelograms,
    degree_two_dual_weight_distribution,
    iid_affine_cube_expectation_bound,
    label_xor_zero_probability,
    make_parameters,
    partition_size,
    quadratic_moment_rank,
    ring_lpn_sets,
    same_partition_probability,
    triangular_distinct_xor_zero_probability,
    triangular_parallelogram_expectation_bound,
    uniform_expected_cubes,
    uniform_expected_parallelograms,
    zero_linear_moment_spectrum,
    zero_linear_moment_rank_distribution,
)


def brute_parallelograms(points: list[int]) -> int:
    return sum(
        left ^ second ^ third ^ right == 0
        for left, second, third, right in itertools.combinations(set(points), 4)
    )


def brute_cubes(points: list[int]) -> int:
    point_set = set(points)
    cubes: set[tuple[int, ...]] = set()
    for subset in itertools.combinations(point_set, 8):
        subset_set = set(subset)
        base = subset[0]
        differences = {point ^ base for point in subset_set}
        if len(differences) != 8:
            continue
        if all(left ^ right in differences for left in differences for right in differences):
            cubes.add(tuple(sorted(subset)))
    return len(cubes)


class RelationCountTests(unittest.TestCase):
    def test_known_affine_spaces(self) -> None:
        self.assertEqual(count_xor_parallelograms([0, 1, 2, 3]), 1)
        self.assertEqual(count_affine_three_flats([0, 1, 2, 3]), 0)
        self.assertEqual(count_xor_parallelograms(list(range(8))), 14)
        self.assertEqual(count_affine_three_flats(list(range(8))), 1)

    def test_complete_moment_spectrum(self) -> None:
        plane = zero_linear_moment_spectrum([0, 1, 2, 3])
        self.assertEqual(plane, {(4, 2): 1})

        cube = zero_linear_moment_spectrum(list(range(8)))
        self.assertEqual(cube, {(4, 2): 14, (8, 0): 1})
        self.assertEqual(quadratic_moment_rank([0, 1, 2, 3], 0b1111), 2)

    def test_degree_two_dual_weights(self) -> None:
        self.assertEqual(degree_two_dual_weight_distribution(3, 8), {0: 1, 8: 1})
        self.assertEqual(
            degree_two_dual_weight_distribution(4, 16),
            {0: 1, 8: 30, 16: 1},
        )

    def test_alternating_scheme_distribution(self) -> None:
        for dimension in (3, 4):
            spectrum = zero_linear_moment_spectrum(list(range(1 << dimension)))
            for relation_weight in range(2, (1 << dimension) + 1, 2):
                observed = {
                    rank: count
                    for (weight, rank), count in spectrum.items()
                    if weight == relation_weight
                }
                self.assertEqual(
                    zero_linear_moment_rank_distribution(
                        dimension,
                        relation_weight,
                    ),
                    observed,
                )

        for half_rank in range(3):
            self.assertEqual(
                alternating_forms_eigenvalue(4, 0, half_rank),
                alternating_form_count(4, 2 * half_rank),
            )

        self.assertEqual(
            zero_linear_moment_rank_distribution(17, 4),
            {2: 93822844764160},
        )
        self.assertEqual(
            zero_linear_moment_rank_distribution(17, 8)[0],
            219592368170516480,
        )

    def test_counts_match_brute_force(self) -> None:
        rng = random.Random(7)
        for _ in range(50):
            points = rng.sample(range(32), rng.randrange(4, 13))
            self.assertEqual(count_xor_parallelograms(points), brute_parallelograms(points))
            self.assertEqual(count_affine_three_flats(points), brute_cubes(points))

    def test_label_probabilities(self) -> None:
        self.assertEqual(label_xor_zero_probability(4, 4), 1.0)
        self.assertAlmostEqual(label_xor_zero_probability(8, 4), 1.0 / 5.0)
        self.assertEqual(label_xor_zero_probability(8, 8), 1.0)

        for size in (8, 16):
            for arity in (4, 8):
                if arity > size:
                    continue
                zero = sum(
                    _xor_all(subset) == 0
                    for subset in itertools.combinations(range(size), arity)
                )
                self.assertAlmostEqual(
                    label_xor_zero_probability(size, arity),
                    zero / math.comb(size, arity),
                )

    def test_shuffle_probability(self) -> None:
        self.assertAlmostEqual(
            same_partition_probability(2, 8, 4),
            2 * math.perm(8, 4) / math.perm(16, 4),
        )
        self.assertEqual(same_partition_probability(2, 4, 8), 0.0)

    def test_uniform_baselines(self) -> None:
        self.assertEqual(uniform_expected_parallelograms(8, 8), 14.0)
        self.assertEqual(uniform_expected_cubes(8, 8), 1.0)
        self.assertEqual(iid_affine_cube_expectation_bound(8, 8, 1.0), 1.0)
        self.assertEqual(iid_affine_cube_expectation_bound(8, 8, 2.0), 256.0)

    def test_triangular_parallelogram_probability(self) -> None:
        self.assertEqual(triangular_distinct_xor_zero_probability(2), 0.0)

        block_size = 4
        multiplicities = [1, 2, 3, 4, 3, 2, 1, 0]
        numerator = 0
        for points in itertools.product(range(8), repeat=4):
            if len(set(points)) == 4 and _xor_all(points) == 0:
                numerator += math.prod(multiplicities[point] for point in points)
        probability = numerator / block_size**8
        self.assertAlmostEqual(
            triangular_distinct_xor_zero_probability(block_size),
            probability,
        )
        self.assertAlmostEqual(
            triangular_parallelogram_expectation_bound(4, block_size),
            probability,
        )

    def test_ring_lpn_set_shape(self) -> None:
        sets = list(ring_lpn_sets(random.Random(11), 2, 4, 32))
        self.assertEqual(len(sets), 2 * 2 * 4)
        self.assertTrue(all(1 <= len(points) <= 4 for points in sets))
        self.assertTrue(all(0 <= point < 64 for points in sets for point in points))

    def test_partition_sizes_match_current_profiles(self) -> None:
        self.assertEqual(partition_size(16, 2), 16)
        self.assertEqual(partition_size(16, 3), 8)

    def test_width_slack_is_independent(self) -> None:
        parameters = make_parameters(
            argparse.Namespace(
                trials=1,
                seed=0,
                num_polynomials=4,
                weight=16,
                ring_size=1 << 20,
                partitions=2,
                linear_security=40,
                width_slack=8,
                intermediate_width=None,
            )
        )
        self.assertEqual(parameters.linear_security, 40)
        self.assertEqual(parameters.width_slack, 8)
        self.assertEqual(parameters.final_width, 64)
        self.assertEqual(parameters.intermediate_width, 64)

    def test_compression_rank_loss_bound(self) -> None:
        parameters = Parameters(
            trials=1,
            seed=0,
            num_polynomials=4,
            weight=16,
            ring_size=1 << 20,
            block_size=1 << 16,
            dpf_domain=1 << 17,
            partitions=2,
            partition_size=16,
            linear_security=40,
            width_slack=0,
            final_width=56,
            intermediate_width=56,
        )
        self.assertAlmostEqual(
            compression_rank_loss_union_bound(parameters),
            2.9795684630939002e-12,
        )


def _xor_all(values: tuple[int, ...]) -> int:
    result = 0
    for value in values:
        result ^= value
    return result


if __name__ == "__main__":
    unittest.main()
