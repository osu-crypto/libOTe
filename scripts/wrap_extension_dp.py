#!/usr/bin/env python3

"""
Exact expected enumerator for the extended wrapping convolution.

Model:
- input length k
- output length n >= k
- for i < k, x_i is the message bit
- for i >= k, x_i = 0 (zero-tail extension)
- for each time i, y_i = <c_i, state_i> + x_i over GF(2)
- if i < sigma, c_i is fully random on its available support of length i
- if i >= sigma, c_i has length sigma and its oldest tap is fixed to 1
  while the remaining sigma-1 taps are uniform

This script computes the expected IOWE by a transfer-matrix / DP formula
over the sigma-bit output state, and can validate the result against
brute-force enumeration on tiny instances.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from fractions import Fraction
from itertools import product
from math import comb


def popcount(x: int) -> int:
    return x.bit_count()


def masks_for_step(i: int, sigma: int) -> list[int]:
    length = min(i, sigma)
    if length < sigma:
        return list(range(1 << length))
    fixed = 1 << (sigma - 1)
    return [fixed | low for low in range(1 << (sigma - 1))]


def step_output(state: int, mask: int, x_i: int, sigma: int) -> tuple[int, int]:
    y_i = (popcount(state & mask) & 1) ^ x_i
    next_state = ((state << 1) | y_i) & ((1 << sigma) - 1)
    return y_i, next_state


def dp_expected_iowe(k: int, n: int, sigma: int) -> list[list[Fraction]]:
    if not (0 <= k <= n):
        raise ValueError("require 0 <= k <= n")
    if sigma <= 0:
        raise ValueError("sigma must be positive")

    dp: dict[tuple[int, int, int], Fraction] = {(0, 0, 0): Fraction(1, 1)}

    for i in range(n):
        next_dp: dict[tuple[int, int, int], Fraction] = defaultdict(Fraction)
        masks = masks_for_step(i, sigma)
        p_mask = Fraction(1, len(masks))
        x_values = (0, 1) if i < k else (0,)

        for (w, h, state), mass in dp.items():
            for x_i in x_values:
                for mask in masks:
                    y_i, next_state = step_output(state, mask, x_i, sigma)
                    next_dp[(w + x_i, h + y_i, next_state)] += mass * p_mask

        dp = next_dp

    iowe = [[Fraction(0, 1) for _ in range(n + 1)] for _ in range(k + 1)]
    for (w, h, _state), mass in dp.items():
        iowe[w][h] += mass
    return iowe


def brute_force_expected_iowe(k: int, n: int, sigma: int) -> list[list[Fraction]]:
    if not (0 <= k <= n):
        raise ValueError("require 0 <= k <= n")
    if sigma <= 0:
        raise ValueError("sigma must be positive")

    mask_lists = [masks_for_step(i, sigma) for i in range(n)]
    denom = 1
    for masks in mask_lists:
        denom *= len(masks)

    iowe = [[Fraction(0, 1) for _ in range(n + 1)] for _ in range(k + 1)]

    for matrix_masks in product(*mask_lists):
        for x in range(1 << k):
            state = 0
            h = 0
            for i in range(n):
                x_i = (x >> i) & 1 if i < k else 0
                y_i, state = step_output(state, matrix_masks[i], x_i, sigma)
                h += y_i
            iowe[popcount(x)][h] += Fraction(1, denom)

    return iowe


def compare_iowe(lhs: list[list[Fraction]], rhs: list[list[Fraction]]) -> None:
    if len(lhs) != len(rhs) or len(lhs[0]) != len(rhs[0]):
        raise AssertionError("shape mismatch")
    for w in range(len(lhs)):
        for h in range(len(lhs[w])):
            if lhs[w][h] != rhs[w][h]:
                raise AssertionError(
                    f"mismatch at (w={w}, h={h}): lhs={lhs[w][h]} rhs={rhs[w][h]}"
                )


def print_nonzero_rows(iowe: list[list[Fraction]]) -> None:
    for w, row in enumerate(iowe):
        nz = [(h, val) for h, val in enumerate(row) if val]
        if not nz:
            continue
        summary = ", ".join(f"h={h}:{val}" for h, val in nz[:12])
        if len(nz) > 12:
            summary += ", ..."
        print(f"w={w}: {summary}")


def main() -> int:
    parser = argparse.ArgumentParser(description="DP formula for extended wrap convolution.")
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--sigma", type=int, required=True)
    parser.add_argument("--bruteforce", action="store_true")
    args = parser.parse_args()

    dp_iowe = dp_expected_iowe(args.k, args.n, args.sigma)
    print(f"DP enumerator for k={args.k}, n={args.n}, sigma={args.sigma}")
    print_nonzero_rows(dp_iowe)

    if args.bruteforce:
        brute_iowe = brute_force_expected_iowe(args.k, args.n, args.sigma)
        compare_iowe(dp_iowe, brute_iowe)
        print("bruteforce validation passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
