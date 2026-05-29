#!/usr/bin/env python3
"""
LogVOLE Sparse-Repair Fixed-Parameter Analyzer

This script fixes one LogVOLE parameter tuple and optimizes only the
golden-seed gap multiplier c for that tuple as the number of ct2 instances
changes.

Hybrid communication model:

- derive ct2 from one global seed as in the golden-seed approach
- if a coefficient lands in a bad interval, repair only that coefficient
  by sending:
    * a flattened coefficient index in [0, N)
    * a per-coefficient rejection counter d

The script keeps the same Sec. 6-style noise model as logvole_optimizer.py
but replaces the parameter search with:

- fixed RLWE tuple:
    n = 8192
    log_q = 220
    log_p = 55
    m = 2
    w' = 8
- variable ct2 count:
    num_ct2 = 2^t
- derived reuse parameter:
    T = num_ct2 / 2
- optimized c:
    choose the largest feasible c > 0 for each num_ct2

That largest feasible c minimizes the expected sparse-repair communication for
the fixed tuple because larger c strictly decreases p_bad = 1/(cN). For small
ct2 counts the optimum may satisfy c > 1; for larger ct2 counts it can drop
below 1, which means more repaired coefficients and therefore more extra
communication.

Communication model:
  p_bad = 1 / (c * N)
  repairs M ~ Binomial(N, p_bad), so E[M] = 1 / c

Index estimate:
  fixed-width flattened index => ceil(log2(N)) bits per repaired coefficient

Counter estimate:
  two estimators are supported:
    * Elias-gamma expected code length (default in the example search)
    * Shannon entropy lower bound
  Both use the shifted geometric counter
    P[D=t | repair] = (1-p_bad) * p_bad^(t-1),  t >= 1
  whose entropy is
    H(D | repair) = -log2(1-p_bad) - (p_bad / (1-p_bad)) * log2(p_bad)

The entropy estimate matches the paper-style "~2 bits per counter" intuition in
the special case p_bad = 1/2. The default output uses Elias-gamma because it is
a more realistic wire estimate when repairs are sparse.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt


class LogVOLEMode(Enum):
    STANDARD = "standard"


class NoiseModel(Enum):
    SEC6 = "sec6"


class CounterEncoding(Enum):
    ENTROPY = "entropy"
    ELIAS_GAMMA = "elias_gamma"


def is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1) == 0)


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def safe_log2(x: float) -> float:
    if x <= 0:
        raise ValueError(f"log2 undefined for x={x}")
    return math.log2(x)


def eta_epsilon_ring(n: int, lambda_sec: int) -> float:
    """Concrete smoothing-parameter approximation for eta_epsilon(R)."""
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    if lambda_sec <= 0:
        raise ValueError(f"lambda_sec must be positive, got {lambda_sec}")
    return math.sqrt((float(lambda_sec) * math.log(2.0) + math.log(float(n))) / math.pi)


def log2_sum(logx: float, logy: float) -> float:
    if logx < logy:
        logx, logy = logy, logx
    diff = logx - logy
    if diff > 80:
        return logx
    return logx + math.log2(1.0 + 2.0 ** (-diff))


def geometric_entropy_bits(p: float) -> float:
    """
    Entropy of shifted geometric D in {1,2,...} with
      P[D=t] = (1-p) p^(t-1)
    """
    if not (0.0 < p < 1.0):
        raise ValueError(f"geometric_entropy_bits expects 0 < p < 1, got {p}")
    q = 1.0 - p
    return -safe_log2(q) - (p / q) * safe_log2(p)


def expected_elias_gamma_bits_for_shifted_geometric(p: float, tail_mass_tol: float = 1e-15) -> float:
    """
    Practical alternative to the entropy lower bound: expected Elias-gamma
    length for a positive integer counter D with
      P[D=t] = (1-p) p^(t-1), t >= 1.
    """
    if not (0.0 < p < 1.0):
        raise ValueError(f"expected_elias_gamma_bits_for_shifted_geometric expects 0 < p < 1, got {p}")

    q = 1.0 - p
    expected = 0.0
    prob = q
    t = 1
    remaining = 1.0
    while remaining > tail_mass_tol:
        length = 2 * int(math.floor(math.log2(t))) + 1
        expected += prob * float(length)
        remaining -= prob
        prob *= p
        t += 1

    return expected


@dataclass
class SparseRepairCommEstimate:
    total_coefficients: int
    c: float
    p_bad: float
    expected_repairs: float
    prob_any_repair: float
    prob_no_repair: float
    index_bits_per_repair: float
    counter_bits_per_repair: float
    expected_index_bits: float
    expected_counter_bits: float
    expected_total_extra_bits: float
    expected_total_bits_with_seed: float
    counter_encoding: CounterEncoding


def estimate_sparse_repair_comm_bits(
    total_coefficients: int,
    c: float,
    lambda_sec: int,
    counter_encoding: CounterEncoding = CounterEncoding.ENTROPY,
) -> SparseRepairCommEstimate:
    if total_coefficients <= 0:
        raise ValueError(f"total_coefficients must be positive, got {total_coefficients}")
    if c <= 0.0:
        raise ValueError(f"c must be positive, got {c}")

    p_bad = 1.0 / (c * float(total_coefficients))
    if p_bad >= 1.0:
        raise ValueError(
            f"invalid repair regime: p_bad={p_bad} >= 1 for total_coefficients={total_coefficients}, c={c}"
        )

    expected_repairs = float(total_coefficients) * p_bad
    prob_no_repair = math.exp(float(total_coefficients) * math.log1p(-p_bad))
    prob_any_repair = 1.0 - prob_no_repair
    index_bits_per_repair = float(math.ceil(math.log2(float(total_coefficients))))

    if counter_encoding == CounterEncoding.ENTROPY:
        counter_bits_per_repair = geometric_entropy_bits(p_bad)
    elif counter_encoding == CounterEncoding.ELIAS_GAMMA:
        counter_bits_per_repair = expected_elias_gamma_bits_for_shifted_geometric(p_bad)
    else:
        raise ValueError(f"unsupported counter encoding: {counter_encoding}")

    expected_index_bits = expected_repairs * index_bits_per_repair
    expected_counter_bits = expected_repairs * counter_bits_per_repair
    expected_total_extra_bits = expected_index_bits + expected_counter_bits

    return SparseRepairCommEstimate(
        total_coefficients=total_coefficients,
        c=c,
        p_bad=p_bad,
        expected_repairs=expected_repairs,
        prob_any_repair=prob_any_repair,
        prob_no_repair=prob_no_repair,
        index_bits_per_repair=index_bits_per_repair,
        counter_bits_per_repair=counter_bits_per_repair,
        expected_index_bits=expected_index_bits,
        expected_counter_bits=expected_counter_bits,
        expected_total_extra_bits=expected_total_extra_bits,
        expected_total_bits_with_seed=float(lambda_sec) + expected_total_extra_bits,
        counter_encoding=counter_encoding,
    )


@dataclass
class LogVOLEParams:
    n: int
    log_q: int
    log_p: int
    lambda_sec: int
    log_g: int
    m: int
    w: int
    w_prime: int
    T: int = 2**10
    c: float = 1.0
    noise_model: NoiseModel = NoiseModel.SEC6
    mode: LogVOLEMode = LogVOLEMode.STANDARD
    s_star: int = 8
    eta_eps_R: Optional[float] = None
    gamma_R: Optional[float] = None
    alpha: int = 2
    mu: Optional[int] = None
    log_delta: int = field(init=False)

    def __post_init__(self) -> None:
        if not is_power_of_two(self.n):
            raise ValueError(f"n must be power of 2, got {self.n}")
        if self.log_q <= self.log_p:
            raise ValueError(f"log_q must be > log_p, got log_q={self.log_q}, log_p={self.log_p}")
        if self.lambda_sec not in (128, 192, 256):
            raise ValueError(f"lambda_sec must be 128/192/256, got {self.lambda_sec}")
        if self.w <= 0 or self.w_prime <= 0:
            raise ValueError("w and w_prime must be positive")
        if self.T <= 0:
            raise ValueError("T must be positive")
        if self.c <= 0.0:
            raise ValueError("c must be positive")
        if self.log_g <= 0 or self.m <= 0:
            raise ValueError("log_g and m must be positive")
        if self.alpha <= 0:
            raise ValueError("alpha must be positive")
        if self.m <= 1:
            raise ValueError("Sparse-repair LogVOLE optimizer assumes one truncated gadget digit, so m must be >= 2")

        self.log_delta = self.log_q - self.log_p

        if self.eta_eps_R is None:
            self.eta_eps_R = eta_epsilon_ring(self.n, self.lambda_sec)
        elif self.eta_eps_R < 0.0:
            raise ValueError(f"eta_eps_R must be non-negative, got {self.eta_eps_R}")

        if self.gamma_R is None:
            self.gamma_R = float(self.n)

        if self.mu is None:
            rho = ceil_div(self.log_q, self.log_p)
            self.mu = self.alpha * (self.m - 1) * rho
        if self.mu is not None and self.mu <= 0:
            raise ValueError("mu must be positive")

        if self.log_g * self.m < self.log_q:
            need_m = math.ceil(self.log_q / self.log_g)
            raise ValueError(
                f"Gadget too small: log_g*m={self.log_g*self.m} < log_q={self.log_q}. "
                f"Need m >= {need_m} (or larger log_g)."
            )


@dataclass
class ValidationResult:
    is_valid: bool = True
    failures: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def fail(self, check: str, msg: str) -> None:
        self.is_valid = False
        self.failures.append({"check": check, "message": msg})

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


@dataclass
class FixedParameterPoint:
    t: int
    num_ct2: int
    params: LogVOLEParams
    margin_bits_at_c1: float
    c_max: float
    c_opt: float
    noise_details: Dict[str, Any]
    repair_comm: SparseRepairCommEstimate


class LogVOLEValidator:
    HE_LIMITS_128 = {
        1024: 29,
        2048: 56,
        4096: 111,
        8192: 220,
        16384: 438,
        32768: 876,
        65536: 1750,
    }

    def __init__(self, params: LogVOLEParams, enforce_he_limit: bool = False) -> None:
        self.p = params
        self.enforce_he_limit = enforce_he_limit

    def validate(self) -> ValidationResult:
        r = ValidationResult()
        self._check_ring_guidance(r)
        self._check_noise(r)
        return r

    def _check_ring_guidance(self, r: ValidationResult) -> None:
        p = self.p
        base = self.HE_LIMITS_128.get(p.n, None)
        if base is None:
            r.warn(f"No HE-limit table entry for n={p.n}. Skipping HE guidance.")
            return

        max_log_q = int(round(base * (p.lambda_sec / 128.0)))
        r.details["he_guidance"] = {
            "n": p.n,
            "lambda": p.lambda_sec,
            "max_log_q_guidance": max_log_q,
            "actual_log_q": p.log_q,
        }

        if p.log_q > max_log_q:
            msg = f"HE guidance: log_q={p.log_q} > {max_log_q} for n={p.n} (advisory)"
            if self.enforce_he_limit:
                r.fail("HE Standard Guidance", msg)
            else:
                r.warn(msg)

    def _noise_budget_log2(self) -> float:
        p = self.p
        if p.mode != LogVOLEMode.STANDARD:
            raise ValueError(f"Only LogVOLEMode.STANDARD noise budget is supported, got mode={p.mode.value}")

        total_coefficients = 2.0 * float(p.w_prime) * float(p.n) * float(p.T)
        log2_gap = math.log2(2.0 * p.c * total_coefficients)
        return float(p.log_delta - log2_gap)

    def _check_noise(self, r: ValidationResult) -> None:
        p = self.p
        if p.mode != LogVOLEMode.STANDARD:
            r.fail("Mode", f"Only LogVOLEMode.STANDARD is supported, got mode={p.mode.value}.")
            return

        if p.noise_model != NoiseModel.SEC6:
            raise ValueError(f"Unknown noise model: {p.noise_model}")

        noise = self._noise_sec6_log2()
        log_budget = self._noise_budget_log2()
        margin = log_budget - noise["log2_B_total"]

        noise["log2_budget"] = log_budget
        noise["margin_bits"] = margin
        noise["constraint_ok"] = margin > 0.0
        noise["c"] = p.c
        r.details["noise"] = noise

        if margin <= 0.0:
            r.fail(
                "Correctness / Noise",
                f"Noise exceeds budget by {-margin:.2f} bits "
                f"(log2(B_total)={noise['log2_B_total']:.2f} vs log2(budget)={log_budget:.2f}).",
            )

    def _noise_sec6_log2(self) -> Dict[str, Any]:
        p = self.p

        s = 2.0 * float(p.s_star) + 1.0 + float(p.eta_eps_R)
        if s <= 0:
            raise ValueError(f"Computed s<=0: s={s}")

        effective_m = float(p.m - 1)
        if effective_m <= 0.0:
            raise ValueError(f"Computed effective_m<=0: effective_m={effective_m}")

        L = float(math.ceil(math.log2(p.w_prime)) + 1) if p.w_prime > 1 else 1.0

        log2_termA = (
            float(p.log_g)
            + safe_log2(effective_m)
            + safe_log2(float(p.gamma_R))
            + safe_log2(s)
            + safe_log2(L)
        )

        log2_sbar = (
            safe_log2(s + 1.0)
            + float(p.log_g)
            + safe_log2(float(p.n))
            + 0.5 * safe_log2(float(2.0 * effective_m * p.T))
        )

        log2_termB = 1.0 + log2_sbar
        log2_inside = log2_sum(log2_termA, log2_termB)
        log2_pref = 1.0 + 0.5 * safe_log2(float(p.lambda_sec))
        log2_B_total = log2_pref + log2_inside
        log2_trunc = (
            float(p.log_g)
            + safe_log2(float(p.n))
            + safe_log2(1.0 + safe_log2(float(p.mu)))
        )
        log2_B_total = log2_sum(log2_B_total, log2_trunc)

        return {
            "noise_model": "SEC6",
            "s": s,
            "eta_eps_R": p.eta_eps_R,
            "effective_m": effective_m,
            "L": L,
            "log2_termA_gmGamma_s_L": log2_termA,
            "log2_sbar": log2_sbar,
            "log2_termB_2sbar": log2_termB,
            "log2_inside": log2_inside,
            "log2_pref_2sqrt(lambda)": log2_pref,
            "mu": p.mu,
            "log2_truncation_margin": log2_trunc,
            "log2_B_total": log2_B_total,
            "log_delta": float(p.log_delta),
        }


@dataclass
class FixedTupleConfig:
    lambda_sec: int = 128
    n: int = 2**13
    log_q: int = 220
    log_p: int = 55
    m: int = 2
    w_prime: int = 8
    s_star: int = 8
    eta_eps_R: Optional[float] = None
    counter_encoding: CounterEncoding = CounterEncoding.ELIAS_GAMMA
    min_t: int = 1
    max_t: int = 20

    @property
    def w(self) -> int:
        return self.n * self.w_prime

    @property
    def log_g(self) -> int:
        return int(math.ceil(self.log_q / self.m))


def make_fixed_params(cfg: FixedTupleConfig, T: int, c: float) -> LogVOLEParams:
    return LogVOLEParams(
        n=cfg.n,
        log_q=cfg.log_q,
        log_p=cfg.log_p,
        lambda_sec=cfg.lambda_sec,
        log_g=cfg.log_g,
        m=cfg.m,
        w=cfg.w,
        w_prime=cfg.w_prime,
        T=T,
        c=c,
        noise_model=NoiseModel.SEC6,
        mode=LogVOLEMode.STANDARD,
        s_star=cfg.s_star,
        eta_eps_R=cfg.eta_eps_R,
        gamma_R=None,
        alpha=2,
    )


def optimize_c_for_fixed_tuple(
    cfg: FixedTupleConfig,
    t: int,
    *,
    enforce_he_limit: bool = True,
) -> Optional[FixedParameterPoint]:
    if t < 1:
        raise ValueError(f"t must be >= 1 because this model uses num_ct2 = 2T, got t={t}")

    num_ct2 = 1 << t
    T = num_ct2 // 2
    params_c1 = make_fixed_params(cfg, T=T, c=1.0)
    validator_c1 = LogVOLEValidator(params_c1, enforce_he_limit=enforce_he_limit)
    result_c1 = validator_c1.validate()
    noise_c1 = result_c1.details.get("noise", {})
    margin_bits_at_c1 = float(noise_c1.get("margin_bits", float("-inf")))

    safety_margin_bits = 1e-6
    total_coefficients = 2 * cfg.w_prime * cfg.n * T
    c_max = 2.0 ** margin_bits_at_c1
    c_opt = 2.0 ** (margin_bits_at_c1 - safety_margin_bits)
    min_valid_c = math.nextafter(1.0 / float(total_coefficients), math.inf)
    if c_max <= min_valid_c:
        return None
    if c_opt <= min_valid_c:
        c_opt = min_valid_c

    params_opt = make_fixed_params(cfg, T=T, c=c_opt)
    validator_opt = LogVOLEValidator(params_opt, enforce_he_limit=enforce_he_limit)
    result_opt = validator_opt.validate()
    if not result_opt.is_valid:
        return None

    repair_comm = estimate_sparse_repair_comm_bits(
        total_coefficients=total_coefficients,
        c=params_opt.c,
        lambda_sec=params_opt.lambda_sec,
        counter_encoding=cfg.counter_encoding,
    )

    return FixedParameterPoint(
        t=t,
        num_ct2=num_ct2,
        params=params_opt,
        margin_bits_at_c1=margin_bits_at_c1,
        c_max=c_max,
        c_opt=c_opt,
        noise_details=result_opt.details.get("noise", {}),
        repair_comm=repair_comm,
    )


def analyze_fixed_tuple_curve(cfg: FixedTupleConfig) -> List[FixedParameterPoint]:
    points: List[FixedParameterPoint] = []
    for t in range(cfg.min_t, cfg.max_t + 1):
        point = optimize_c_for_fixed_tuple(cfg, t)
        if point is None:
            continue
        points.append(point)
    return points


def plot_curve(points: List[FixedParameterPoint], cfg: FixedTupleConfig) -> None:
    if not points:
        raise ValueError("plot_curve requires at least one feasible point")

    x_vals = [point.num_ct2 for point in points]
    y_vals = [point.repair_comm.expected_total_extra_bits for point in points]
    all_x_ticks = [1 << t for t in range(cfg.min_t, cfg.max_t + 1)]

    fig, ax = plt.subplots(figsize=(12.0, 5.5))
    ax.plot(x_vals, y_vals, marker="o", linewidth=2.0, color="#1f5aa6")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    ax.set_xlabel("Number of ct2 instances (2^t)")
    ax.set_ylabel("Expected extra communication (bits, log2 scale)")
    ax.set_title(
        "Sparse-repair overhead vs ct2 count\n"
        f"fixed n={cfg.n}, log_q={cfg.log_q}, log_p={cfg.log_p}, m={cfg.m}, w'={cfg.w_prime}"
    )
    ax.grid(True, which="both", linestyle="--", linewidth=0.6, alpha=0.5)
    ax.set_xlim(all_x_ticks[0], all_x_ticks[-1])
    ax.set_xticks(all_x_ticks)
    ax.set_xticklabels([f"$2^{{{t}}}$" for t in range(cfg.min_t, cfg.max_t + 1)], rotation=45, ha="right")
    fig.tight_layout()
    plt.show()
    plt.close(fig)


def main() -> None:
    cfg = FixedTupleConfig()
    points = analyze_fixed_tuple_curve(cfg)

    print("LogVOLE Sparse-Repair Fixed-Parameter Analyzer")
    print("=" * 80)
    print(
        f"fixed tuple: n={cfg.n} log_q={cfg.log_q} log_p={cfg.log_p} log_g={cfg.log_g} "
        f"m={cfg.m} w'={cfg.w_prime} counter_code={cfg.counter_encoding.value}"
    )

    if not points:
        print("\nNo feasible ct2 counts in the requested t-range.")
        return

    plot_curve(points, cfg)

    print(f"\nFeasible points: {len(points)}")
    print("Top curve samples:")
    for point in points[: min(10, len(points))]:
        print(
            "  "
            f"t={point.t} num_ct2=2^{point.t} T={point.params.T} "
            f"c_opt={point.c_opt:.4f} margin@c=1={point.margin_bits_at_c1:.2f} "
            f"E[extra_bits]={point.repair_comm.expected_total_extra_bits:.2f}"
        )



if __name__ == "__main__":
    main()
