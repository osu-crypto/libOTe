#!/usr/bin/env python3
"""Finite-length binary chosen-block BAA first-moment certificate.

For low outer weights the script uses exact coefficients of ``W_0(z)^B`` and
sums the binary accumulator transition over every feasible intermediate
weight.  For the remaining outer weights it combines a coefficient Chernoff
bound with the maximum transition term and counts every feasible intermediate
weight.  The resulting number is an upper bound on the complete sum (B4), not
only a sparse-term proxy.

All logarithms are natural internally.  Each floating-point subtotal is rounded
outward by ``SAFETY_NATS`` before it enters the reported certificate.
"""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass

import numpy as np


LN2 = math.log(2.0)
NEG_INF = float("-inf")
# A full bit is vastly larger than the observed floating-point variation when
# changing the low-weight cutoff or the tilt-grid density.
SAFETY_NATS = LN2


@dataclass(frozen=True)
class Constituent:
    name: str
    m: int
    sigma: int
    spectrum: dict[int, int]


CONSTITUENTS = (
    Constituent(
        "Golay [24,12,8]",
        24,
        12,
        {0: 1, 8: 759, 12: 2576, 16: 759, 24: 1},
    ),
    Constituent(
        "RM(2,5) [32,16,8]",
        32,
        16,
        {0: 1, 8: 620, 12: 13_888, 16: 36_518, 20: 13_888, 24: 620, 32: 1},
    ),
)


def logadd(a: float, b: float) -> float:
    if a == NEG_INF:
        return b
    if b == NEG_INF:
        return a
    if a < b:
        a, b = b, a
    return a + math.log1p(math.exp(b - a))


def logsumexp(values: np.ndarray) -> float:
    if values.size == 0:
        return NEG_INF
    maximum = float(np.max(values))
    return maximum + math.log(float(np.exp(values - maximum).sum()))


def log_factorials(n: int) -> np.ndarray:
    result = np.empty(n + 1, dtype=np.float64)
    result[0] = 0.0
    result[1:] = np.cumsum(np.log(np.arange(1, n + 1, dtype=np.float64)))
    return result


def logchoose_from_factorials(logfac: np.ndarray, n: int, k: np.ndarray | int):
    return logfac[n] - logfac[k] - logfac[n - k]


def local_log_enumerator(theta: np.ndarray, spectrum: dict[int, int]) -> np.ndarray:
    weights = np.array(sorted(spectrum), dtype=np.float64)
    logs = np.log(np.array([spectrum[int(w)] for w in weights], dtype=np.float64))
    terms = logs[:, None] + weights[:, None] * theta[None, :]
    maxima = terms.max(axis=0)
    return maxima + np.log(np.exp(terms - maxima).sum(axis=0))


def local_tilt_mean(theta: np.ndarray, spectrum: dict[int, int]) -> np.ndarray:
    weights = np.array(sorted(spectrum), dtype=np.float64)
    coeffs = np.array([spectrum[int(w)] for w in weights], dtype=np.float64)
    terms = np.log(coeffs)[:, None] + weights[:, None] * theta[None, :]
    maxima = terms.max(axis=0)
    scaled = np.exp(terms - maxima)
    return (weights[:, None] * scaled).sum(axis=0) / scaled.sum(axis=0)


def outer_coefficient_chernoff_logs(
    constituent: Constituent,
    block_count: int,
    weights: np.ndarray,
) -> np.ndarray:
    """Upper bounds log([z^w] W(z)^B), using an explicit exponential tilt."""
    target_means = weights.astype(np.float64) / block_count
    # Any theta gives a valid coefficient bound.  A dense monotone grid makes
    # this close to the optimizing saddle while retaining the inequality.
    theta_grid = np.linspace(-24.0, 0.0, 240_001, dtype=np.float64)
    means = local_tilt_mean(theta_grid, constituent.spectrum)
    theta = np.interp(target_means, means, theta_grid)
    log_w = local_log_enumerator(theta, constituent.spectrum)
    return block_count * log_w - weights * theta


def hypergeometric_tail_log_bounds(logfac: np.ndarray, n: int, ell: int) -> np.ndarray:
    """Upper-bound Q(h,L) by its first hypergeometric term and a geometric tail.

    The identity

      Q(h,L) = Pr[X >= ceil(h/2)],  X ~ Hypergeom(n,L,h)

    turns the second accumulator tail into a hypergeometric upper tail.  At and
    above ``ceil(h/2)`` its successive-term ratio decreases and is below one, so
    the first term divided by one minus the first ratio bounds the whole tail.
    """
    h = np.arange(1, 2 * ell + 1, dtype=np.int64)
    x = (h + 1) // 2
    first = (
        logchoose_from_factorials(logfac, ell, x)
        + logchoose_from_factorials(logfac, n - ell, h - x)
        - logchoose_from_factorials(logfac, n, h)
    )
    ratio = ((ell - x) / (x + 1)) * ((h - x) / (n - ell - h + x + 1))
    result = np.empty(2 * ell + 1, dtype=np.float64)
    result[0] = NEG_INF
    result[1:] = first - np.log1p(-ratio)
    return result


def pair_term_log(
    logfac: np.ndarray,
    log_q_upper: np.ndarray,
    n: int,
    w: int,
    h: int,
) -> float:
    r = (w + 1) // 2
    s = w // 2
    return float(
        logfac[h - 1]
        - logfac[r - 1]
        - logfac[h - r]
        + logfac[n - h]
        - logfac[s]
        - logfac[n - h - s]
        - logchoose_from_factorials(logfac, n, w)
        + log_q_upper[h]
    )


def pair_sum_log_bound(
    logfac: np.ndarray,
    log_q_upper: np.ndarray,
    n: int,
    ell: int,
    w: int,
) -> float:
    """Sum the transition bound over every feasible h for a low input weight."""
    r = (w + 1) // 2
    s = w // 2
    h = np.arange(r, min(2 * ell, n - s) + 1, dtype=np.int64)
    values = (
        logfac[h - 1]
        - logfac[r - 1]
        - logfac[h - r]
        + logfac[n - h]
        - logfac[s]
        - logfac[n - h - s]
        - logchoose_from_factorials(logfac, n, w)
        + log_q_upper[h]
    )
    return logsumexp(values)


def exact_outer_coefficients(
    spectrum: dict[int, int], block_count: int, cutoff: int
) -> list[int]:
    """Compute [z^w] W_0(z)^B exactly through ``cutoff``.

    From W f' = B W' f for f=W^B and W(0)=1,

      w f_w = sum_j (((B+1)j-w) W_j f_{w-j}).
    """
    coefficients = [0] * (cutoff + 1)
    coefficients[0] = 1
    nonzero = [(j, a) for j, a in spectrum.items() if j]
    for w in range(1, cutoff + 1):
        numerator = sum(
            ((block_count + 1) * j - w) * a * coefficients[w - j]
            for j, a in nonzero
            if j <= w
        )
        coefficients[w], remainder = divmod(numerator, w)
        if remainder:
            raise ArithmeticError("power-series recurrence lost integrality")
    return coefficients


def low_weight_log_bound(
    constituent: Constituent,
    n: int,
    ell: int,
    cutoff: int,
    logfac: np.ndarray,
    log_q_upper: np.ndarray,
) -> tuple[float, list[tuple[int, float]]]:
    coefficients = exact_outer_coefficients(
        constituent.spectrum, n // constituent.m, cutoff
    )
    terms: list[tuple[int, float]] = []
    total = NEG_INF
    for w, coefficient in enumerate(coefficients):
        if w == 0 or coefficient == 0:
            continue
        value = math.log(coefficient) + pair_sum_log_bound(
            logfac, log_q_upper, n, ell, w
        )
        terms.append((w, value))
        total = logadd(total, value)
    return total + SAFETY_NATS, terms


def maximize_pair_term_by_parity(
    logfac: np.ndarray,
    log_q_upper: np.ndarray,
    n: int,
    ell: int,
    w: int,
    starts: list[int],
) -> tuple[float, list[int]]:
    """Find each parity subsequence's mode by discrete hill climbing.

    For the tail ranges used here, the logarithm of the product of the
    accumulator transition and the hypergeometric-tail bound is strictly
    unimodal on each h-parity subsequence.  The neighboring-value checks below
    locate those two modes; the caller carries the modes forward as w grows.
    """
    lo = (w + 1) // 2
    hi = min(2 * ell, n - w // 2)
    maxima: list[float] = []
    modes: list[int] = []
    for parity in (0, 1):
        parity_lo = lo + ((parity - lo) & 1)
        parity_hi = hi - ((hi - parity) & 1)
        if parity_lo > parity_hi:
            maxima.append(NEG_INF)
            modes.append(parity_lo)
            continue
        h = min(max(starts[parity], parity_lo), parity_hi)
        if (h & 1) != parity:
            h += 1 if h < parity_hi else -1
        value = pair_term_log(logfac, log_q_upper, n, w, h)
        while h - 2 >= parity_lo:
            candidate = pair_term_log(logfac, log_q_upper, n, w, h - 2)
            if candidate <= value:
                break
            h -= 2
            value = candidate
        while h + 2 <= parity_hi:
            candidate = pair_term_log(logfac, log_q_upper, n, w, h + 2)
            if candidate <= value:
                break
            h += 2
            value = candidate
        if h - 2 >= parity_lo:
            assert pair_term_log(logfac, log_q_upper, n, w, h - 2) <= value + 1e-7
        if h + 2 <= parity_hi:
            assert pair_term_log(logfac, log_q_upper, n, w, h + 2) <= value + 1e-7
        maxima.append(value)
        modes.append(h)
    return max(maxima), modes


def verify_tail_unimodality_boundary(
    logfac: np.ndarray,
    log_q_upper: np.ndarray,
    n: int,
    ell: int,
    w: int,
) -> None:
    """Check strict parity-wise log concavity at the least-curved tail weight.

    The two binomial ratios in the first-accumulator transition decrease more
    strongly as w increases.  Thus the first tail weight is the boundary case
    for the parity-wise unimodality used by the mode search.
    """
    r = (w + 1) // 2
    s = w // 2
    h = np.arange(r, min(2 * ell, n - s) + 1, dtype=np.int64)
    values = (
        logfac[h - 1]
        - logfac[r - 1]
        - logfac[h - r]
        + logfac[n - h]
        - logfac[s]
        - logfac[n - h - s]
        - logchoose_from_factorials(logfac, n, w)
        + log_q_upper[h]
    )
    for parity in (0, 1):
        subsequence = values[(h & 1) == parity]
        if subsequence.size >= 3 and float(np.max(np.diff(subsequence, n=2))) >= -1e-7:
            raise ArithmeticError("tail transition failed the unimodality check")


def bounded_tail(
    constituent: Constituent,
    n: int,
    ell: int,
    cutoff: int,
    logfac: np.ndarray,
    log_q_upper: np.ndarray,
) -> tuple[float, tuple[int, int, float]]:
    block_count = n // constituent.m
    first = cutoff + (4 - cutoff % 4) % 4
    if first <= cutoff:
        first += 4
    last = min(n, 4 * ell)
    weights = np.arange(first, last + 1, 4, dtype=np.int64)
    verify_tail_unimodality_boundary(logfac, log_q_upper, n, ell, int(weights[0]))
    outer = outer_coefficient_chernoff_logs(constituent, block_count, weights)
    subtotal = np.empty(weights.size, dtype=np.float64)
    starts = [first, first + 1]
    largest = (0, 0, NEG_INF)
    for index, (w_value, outer_log) in enumerate(zip(weights, outer)):
        w = int(w_value)
        pair_max, starts = maximize_pair_term_by_parity(
            logfac, log_q_upper, n, ell, w, starts
        )
        h_count = min(2 * ell, n - w // 2) - (w + 1) // 2 + 1
        subtotal[index] = float(outer_log) + pair_max + math.log(h_count)
        if subtotal[index] > largest[2]:
            valid_modes = [h for h in starts if (w + 1) // 2 <= h <= min(2 * ell, n - w // 2)]
            best_h = max(
                valid_modes,
                key=lambda h: pair_term_log(logfac, log_q_upper, n, w, h),
            )
            largest = (w, best_h, subtotal[index])
    return logsumexp(subtotal) + SAFETY_NATS, largest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=2_097_024)
    parser.add_argument("--delta", type=float, default=0.10)
    parser.add_argument("--constituent", choices=("all", "rm", "golay"), default="all")
    parser.add_argument(
        "--cutoff",
        type=int,
        default=32,
        help="largest outer weight summed directly (multiple of 4, at least 24)",
    )
    args = parser.parse_args()
    constituents = CONSTITUENTS if args.constituent == "all" else (CONSTITUENTS[1 if args.constituent == "rm" else 0],)

    n = args.n
    ell = math.floor(args.delta * n)
    if not 0 < ell < n // 2:
        raise SystemExit("delta must give 0 < floor(delta*n) < n/2")
    if args.cutoff < 24 or args.cutoff % 4:
        raise SystemExit("cutoff must be a multiple of 4 and at least 24")
    if any(n % c.m for c in constituents):
        raise SystemExit("n must be divisible by every constituent block length")
    logfac = log_factorials(n)
    log_q_upper = hypergeometric_tail_log_bounds(logfac, n, ell)

    print(f"n={n} L={ell} delta_actual={ell/n:.17g} cutoff={args.cutoff}")
    for constituent in constituents:
        low, low_terms = low_weight_log_bound(
            constituent, n, ell, args.cutoff, logfac, log_q_upper
        )
        tail, largest = bounded_tail(
            constituent, n, ell, args.cutoff, logfac, log_q_upper
        )
        complete = logadd(low, tail)
        print(constituent.name)
        for w, value in low_terms:
            print(f"  exact outer coefficient w={w:2d}: bounded contribution 2^({value/LN2:.6f})")
        print(f"  w<={args.cutoff} subtotal upper bound: 2^({low/LN2:.6f})")
        print(f"  w>{args.cutoff} subtotal upper bound: 2^({tail/LN2:.6f})")
        print(
            f"  largest tail summand bound: w={largest[0]} h={largest[1]} "
            f"2^({largest[2]/LN2:.6f})"
        )
        print(f"  COMPLETE mu_bin upper bound: 2^({complete/LN2:.6f})")
        print(f"  CERTIFIED SECURITY BITS: {-complete/LN2:.6f}")


if __name__ == "__main__":
    main()
