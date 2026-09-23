import argparse
import itertools
import math
import unittest
from collections import Counter
from fractions import Fraction

from analysis.rev_cuckoo_hash_conditioning import (
    acceptance_probability,
    conditioned_hash_bound,
    conditioning_factors,
    folded_weight_counts,
    triangular_distinct_xor_probability,
)
from analysis.rev_cuckoo_hash_relations import (
    compression_rank_loss_union_bound,
    make_parameters,
    triangular_distinct_xor_zero_probability,
)


def parameters(ring_size=1 << 20):
    return make_parameters(argparse.Namespace(
        trials=1, seed=0, num_polynomials=4, weight=16, ring_size=ring_size,
        partitions=2, linear_security=40, width_slack=8, intermediate_width=None,
    ))


class ConditioningTests(unittest.TestCase):
    def test_occupancy_counts_against_enumeration(self):
        for polys, weight, degree in ((0, 2, 3), (2, 2, 3), (2, 3, 2)):
            observed = Counter()
            for residues in itertools.product(range(degree), repeat=polys * weight):
                occupied = sum(len(set(residues[a * weight:(a + 1) * weight]))
                               for a in range(polys))
                observed[occupied] += 1
            actual = folded_weight_counts(polys, weight, degree)
            self.assertEqual(sum(actual), degree ** (polys * weight))
            self.assertEqual(actual, tuple(observed[i] for i in range(len(actual))))

    def test_equal_residues_in_different_polynomials_count_separately(self):
        self.assertEqual(folded_weight_counts(4, 1, 1), (0, 0, 0, 0, 1))

    def test_every_toy_pair_marginal_is_bounded(self):
        # Pointwise validation implies the bound for any nonnegative local cost.
        polys, weight, degree, threshold = 3, 2, 2, 5
        accepted = Counter()
        for residues in itertools.product(range(degree), repeat=polys * weight):
            occupied = sum(len(set(residues[a * weight:(a + 1) * weight]))
                           for a in range(polys))
            if occupied >= threshold:
                accepted[residues[:weight]] += 1
        total = sum(accepted.values())
        _, _, factor = conditioning_factors(polys, weight, degree, threshold)
        ratios = []
        for left in itertools.product(range(degree), repeat=weight):
            for right in itertools.product(range(degree), repeat=weight):
                ratio = Fraction(accepted[left] * accepted[right] * degree ** (2 * weight),
                                 total ** 2)
                self.assertLessEqual(ratio, factor)
                ratios.append(ratio)
        self.assertEqual(max(ratios), factor)

    def test_filter_edges(self):
        self.assertEqual(conditioning_factors(4, 16, 128, 0), (1, 1, 1))
        self.assertEqual(acceptance_probability(0, 16, 128, 0), 1)
        self.assertEqual(acceptance_probability(0, 16, 128, 1), 0)
        with self.assertRaises(ValueError):
            conditioning_factors(4, 16, 128, 65)
        with self.assertRaises(ValueError):
            conditioning_factors(0, 16, 128, 0)
        with self.assertRaises(ValueError):
            folded_weight_counts(4, 16, 0)
        with self.assertRaises(ValueError):
            conditioned_hash_bound(parameters(), degree=127)

    def test_exact_triangular_transform_against_enumeration(self):
        for block in (1, 2, 4):
            sums = Counter(a + b for a in range(block) for b in range(block))
            favorable = sum(
                math.prod(sums[x] for x in points)
                for points in itertools.permutations(sums, 4)
                if points[0] ^ points[1] ^ points[2] ^ points[3] == 0
            )
            self.assertEqual(triangular_distinct_xor_probability(block),
                             Fraction(favorable, block ** 8))
        self.assertAlmostEqual(float(triangular_distinct_xor_probability(64)),
                               triangular_distinct_xor_zero_probability(64), places=15)

    def test_production_acceptance_and_density(self):
        acceptance, completion, factor = conditioning_factors(4, 16, 128, 61)
        self.assertAlmostEqual(float(acceptance), 0.5019144582520833, places=14)
        self.assertAlmostEqual(float(completion), 0.7174085983980503, places=14)
        self.assertAlmostEqual(float(factor), 2.0430252897413563, places=13)

    def test_exact_complete_correctness_bound(self):
        p = parameters()
        bounds = conditioned_hash_bound(p)
        self.assertAlmostEqual(float(bounds['compression']),
                               compression_rank_loss_union_bound(p), places=26)
        self.assertTrue(math.isclose(float(bounds['unfiltered_complete']),
                                    2.3788857796662323e-13, rel_tol=1e-10))
        self.assertLess(bounds['conditioned_complete'], Fraction(1, 2 ** 40))
        self.assertLess(bounds['conditioned_complete'], Fraction(4739, 10 ** 16))
        self.assertLess(bounds['unfiltered_complete'], Fraction(2379, 10 ** 16))
        self.assertGreater(bounds['blanket_conditioned'], Fraction(1, 2 ** 40))
        self.assertLess(bounds['conditioned_complete'], bounds['pair_conditioned'])
        self.assertAlmostEqual(-math.log2(float(bounds['conditioned_complete'])),
                               40.94056576698431, places=8)


if __name__ == '__main__':
    unittest.main()
