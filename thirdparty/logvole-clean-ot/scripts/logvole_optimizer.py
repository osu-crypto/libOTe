#!/usr/bin/env python3
"""
LogVOLE Parameter Optimizer (v2)

This is a drop-in replacement for the optimizer with the key fixes needed to
(1) reproduce LogVOLE Sec. 6 concrete parameters, and
(2) search practical parameters without silently using the wrong noise model.

Key fixes vs the previous script:
- Uses NoiseModel.SEC6 with a Leaky-LWE-style variance condition replacing
  the older internal-noise rule.
- Keeps gamma_R = n by default (paper proves gamma_R <= n).
- Keeps the backend SEC6-style estimator shape, but replaces the old
  LogVOLE leakage-flooding parameters with:
    eta_eps_R = sqrt((lambda*ln(2) + ln(n)) / pi)
    A = s_star^2 + 2*eta_eps_R^2
    s = argmin over s > sqrt(A) of the resulting total correctness bound
    L = 1 if mu <= 1 else ceil(log2(mu)) + 1
    s_bar = g*n*sqrt(2*m*T) / sqrt(1/A - 1/s^2)
    B = 2*sqrt(lambda) * ( g*m*gamma_R*s*L + 2*s_bar )
    assumes one truncated gadget digit, with truncation margin g*n*s*(1 + log2(mu))
- Removes the hard-coded w_prime=8 and makes (w, w_prime, T, mu) first-class.
- Computes all noise bounds in log2-domain (prevents overflow).

Run:
  python logvole_optimizer.py

You can edit DEFAULT_* constants near the bottom to match the target application.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from itertools import product
from typing import Any, Dict, Iterator, List, Optional, Tuple

GOLDEN_SEED_SLACK = 1.0


# =============================================================================
# Enums / Helpers
# =============================================================================

class LogVOLEMode(Enum):
    STANDARD = "standard"       # concrete / paper-style


class NoiseModel(Enum):
    SEC6 = "sec6"               # Sec. 6 instantiation with Leaky LWE refinement


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
    """Return log2(2^logx + 2^logy) robustly."""
    if logx < logy:
        logx, logy = logy, logx
    # now logx >= logy
    diff = logx - logy
    if diff > 80:  # 2^-80 negligible
        return logx
    return logx + math.log2(1.0 + 2.0 ** (-diff))


# =============================================================================
# Core Data Structures
# =============================================================================

@dataclass
class LogVOLEParams:
    # Ring / moduli
    n: int
    log_q: int
    log_p: int
    lambda_sec: int

    # Gadget
    log_g: int
    m: int

    # Application
    w: int
    w_prime: int  # typically ceil(w/n)

    # Reuse parameter
    T: int = 2**10

    # Noise-model choice
    noise_model: NoiseModel = NoiseModel.SEC6
    mode: LogVOLEMode = LogVOLEMode.STANDARD

    # Sec. 6 concrete instantiation knobs
    s_star: int = 8            # paper: s* = 8 (SEAL recommendation for n=4096, logq<=111)
    eta_eps_R: Optional[float] = None

    # Ring expansion factor gamma_R (paper: gamma_R <= n)
    gamma_R: Optional[float] = None
    alpha: int = 2
    mu: Optional[int] = None

    # Derived
    log_delta: int = field(init=False)

    def __post_init__(self) -> None:
        # basic checks
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
        if self.log_g <= 0 or self.m <= 0:
            raise ValueError("log_g and m must be positive")
        if self.alpha <= 0:
            raise ValueError("alpha must be positive")
        if self.m <= 1:
            raise ValueError("LogVOLE optimizer assumes one truncated gadget digit, so m must be >= 2")

        # derived
        self.log_delta = self.log_q - self.log_p

        if self.eta_eps_R is None:
            self.eta_eps_R = eta_epsilon_ring(self.n, self.lambda_sec)
        elif self.eta_eps_R < 0.0:
            raise ValueError(f"eta_eps_R must be non-negative, got {self.eta_eps_R}")

        # gamma_R default
        if self.gamma_R is None:
            # safe default per paper bound gamma_R <= n
            self.gamma_R = float(self.n)

        if self.mu is None:
            rho = ceil_div(self.log_q, self.log_p)
            self.mu = self.alpha * (self.m - 1) * rho
        if self.mu is not None and self.mu <= 0:
            raise ValueError("mu must be positive")

        # gadget representability sanity: need g^m >= q
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
class OptimizationResult:
    params: LogVOLEParams
    cost: float
    margin_bits: float
    noise_details: Dict[str, Any]


# =============================================================================
# Validator
# =============================================================================

class LogVOLEValidator:
    """
    Validates:
      - ring constraints (HE standard guidance)
      - correctness margin under chosen noise model + mode
    """

    # conservative HE limits (log2(q) upper bounds) for 128-bit security style,
    # used as "practical guidance", not hard failure (unless you want it).
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
        # scale the 128-bit table roughly by lambda (very rough; keep advisory)
        base = self.HE_LIMITS_128.get(p.n, None)
        if base is None:
            r.warn(f"No HE-limit table entry for n={p.n}. Skipping HE guidance.")
            return

        # heuristic scaling by lambda/128
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
        """
        Returns log2(budget) for LogVOLEMode.STANDARD only.
        """
        p = self.p
        log_delta = p.log_delta

        if p.mode != LogVOLEMode.STANDARD:
            raise ValueError(f"Only LogVOLEMode.STANDARD noise budget is supported, got mode={p.mode.value}")

        # Sec. 6 uses Delta directly, but to probabilistically find a golden seed,
        # the paper specifies Delta / (2 * c * N) where N is the number of
        # coefficients checked by one recursive LogVOLE seed.
        n_cts = self._recursive_seed_checked_coefficients()
        log2_gap = math.log2(2.0 * GOLDEN_SEED_SLACK * n_cts)
        return float(log_delta - log2_gap)

    def _recursive_seed_checked_coefficients(self) -> int:
        p = self.p
        rho = ceil_div(p.log_q, p.log_p)
        tau_hi = p.m - 1
        mu = int(p.mu)
        if rho <= 0 or tau_hi <= 0 or mu <= 0:
            raise ValueError("Invalid recursive LogVOLE dimensions")

        # Optimizer notation: p.w_prime is packed ring width per batch and p.T
        # is N_labels / (n * p.w_prime). The C++ recursive LogVOLE seed checks
        # all sampled ring polynomials while unwinding all recursive levels.
        width = p.w_prime * p.T
        sampled_polys = 0
        while True:
            level_sampled = ceil_div(width, mu) * mu
            sampled_polys += level_sampled
            if width <= mu:
                break
            width = ceil_div(width, mu) * tau_hi * rho

        return p.n * sampled_polys

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
        noise["constraint_ok"] = (margin > 0)

        r.details["noise"] = noise

        if margin <= 0:
            r.fail(
                "Correctness / Noise",
                f"Noise exceeds budget by {-margin:.2f} bits "
                f"(log2(B_total)={noise['log2_B_total']:.2f} vs log2(budget)={log_budget:.2f})."
            )

    def _noise_sec6_log2(self) -> Dict[str, Any]:
        """
        Sec. 6-style correctness estimator with a Leaky-LWE-style variance
        condition for the error-only leakage term.

          Error-only leakage condition:
          ||L^T L|| <= sigma_f^2 * ((s_star^2 + 2*eta^2)^-1 - s^-2).

          A = s_star^2 + 2*eta_eps_R^2
          s > sqrt(A)
          L = 1 if mu <= 1 else ceil(log2(mu)) + 1
          s_bar = g*n*sqrt(2*m*T) / sqrt(1/A - 1/s^2)

          Base estimator:
            Delta >= 2*sqrt(lambda) * ( g*m*gamma_R*s*(ceil(log2 mu)+1) + 2*s_bar )

          Always includes the backend's truncation-rounding term
          g*n*s*(1 + log2(mu)), where s bounds the short r masks.

        The script chooses s by minimizing this total estimator, including the
        truncation term. With x = s/sqrt(A), the minimizer has
          x = sqrt(1 + k^(2/3))
        for the coefficient ratio k derived below.

        Returns a dict including log2(B_total), s, s_bar (log2), etc.
        """
        p = self.p

        effective_m = float(p.m - 1)
        if effective_m <= 0.0:
            raise ValueError(f"Computed effective_m<=0: effective_m={effective_m}")

        # L is the local LacE tree depth inside one ShrinkExpand block plus
        # the matching LHE/base term. It is per-block, so use mu rather than
        # the number of packed ring blocks w_prime.
        L = float(math.ceil(math.log2(p.mu)) + 1) if p.mu > 1 else 1.0
        log2_pref = 1.0 + 0.5 * safe_log2(float(p.lambda_sec))
        pref = 2.0 * math.sqrt(float(p.lambda_sec))

        leaky_A = float(p.s_star) ** 2 + 2.0 * float(p.eta_eps_R) ** 2
        if leaky_A <= 0.0:
            raise ValueError(f"Computed non-positive Leaky LWE A={leaky_A}")
        leaky_s_threshold = math.sqrt(leaky_A)

        # Minimize
        #   pref*(g*effective_m*gamma_R*L*s + 2*s_bar(s))
        #     + g*n*s*(1+log2(mu))
        # where s_bar(s)=g*n*sqrt(2*effective_m*T)/sqrt(1/A - 1/s^2).
        # The common factor g cancels from the minimizer.
        log2_mu = safe_log2(float(p.mu))
        linear_coeff = (
            pref * effective_m * float(p.gamma_R) * L
            + float(p.n) * (1.0 + log2_mu)
        )
        leak_coeff = pref * 2.0 * float(p.n) * math.sqrt(2.0 * effective_m * float(p.T))
        if linear_coeff <= 0.0 or leak_coeff <= 0.0:
            raise ValueError(
                f"Invalid Leaky LWE minimizer coefficients: linear={linear_coeff}, leak={leak_coeff}"
            )
        minimizer_k = leak_coeff / linear_coeff
        s_multiplier = math.sqrt(1.0 + minimizer_k ** (2.0 / 3.0))
        if not math.isfinite(s_multiplier) or s_multiplier <= 1.0:
            raise ValueError(f"Invalid Leaky LWE s multiplier: {s_multiplier}")

        s = leaky_s_threshold * s_multiplier
        if s <= leaky_s_threshold:
            raise ValueError(f"Computed s={s} does not exceed Leaky LWE threshold {leaky_s_threshold}")

        # termA = g*m*gamma_R*s*L
        # log2(termA) = log_g + log2(m) + log2(gamma_R) + log2(s) + log2(L)
        log2_termA = (
            float(p.log_g)
            + safe_log2(effective_m)
            + safe_log2(float(p.gamma_R))
            + safe_log2(s)
            + safe_log2(L)
        )

        sbar_over_leakage_norm = leaky_s_threshold * s_multiplier / math.sqrt(s_multiplier * s_multiplier - 1.0)
        log2_sbar = (
            safe_log2(sbar_over_leakage_norm)
            + float(p.log_g)
            + safe_log2(float(p.n))
            + 0.5 * safe_log2(float(2.0 * effective_m * p.T))
        )

        # termB = 2*s_bar => log2(termB) = 1 + log2_sbar
        log2_termB = 1.0 + log2_sbar

        # inside = termA + termB
        log2_inside = log2_sum(log2_termA, log2_termB)

        # B_total = 2*sqrt(lambda) * inside
        # log2(2*sqrt(lambda)) = 1 + 0.5*log2(lambda)
        log2_B_total = log2_pref + log2_inside
        log2_trunc = (
            float(p.log_g)
            + safe_log2(float(p.n))
            + safe_log2(s)
            + safe_log2(1.0 + safe_log2(float(p.mu)))
        )
        log2_B_total = log2_sum(log2_B_total, log2_trunc)

        return {
            "noise_model": "SEC6_LEAKY_LWE",
            "s": s,
            "s_baseline": 2.0 * float(p.s_star) + 1.0 + float(p.eta_eps_R),
            "leaky_lwe_A": leaky_A,
            "leaky_lwe_s_threshold": leaky_s_threshold,
            "leaky_lwe_s_multiplier": s_multiplier,
            "leaky_lwe_minimizer_k": minimizer_k,
            "leaky_lwe_sbar_over_leakage_norm": sbar_over_leakage_norm,
            "eta_eps_R": p.eta_eps_R,
            "effective_m": effective_m,
            "L": L,
            "mu": p.mu,
            "local_lace_width_mu": p.mu,
            "global_packed_width_w_prime": p.w_prime,
            "recursive_checked_coefficients": self._recursive_seed_checked_coefficients(),
            "log2_termA_gmGamma_s_L": log2_termA,
            "log2_sbar": log2_sbar,
            "log2_termB_2sbar": log2_termB,
            "log2_inside": log2_inside,
            "log2_pref_2sqrt(lambda)": log2_pref,
            "truncation_mask_bound": s,
            "log2_truncation_margin": log2_trunc,
            "log2_B_total": log2_B_total,
            "log_delta": float(p.log_delta),
        }


# =============================================================================
# Optimizer
# =============================================================================

class LogVOLEOptimizer:
    """
    Simple grid-search optimizer.
    - You set ranges for (n, log_p, log_q, m); log_g is derived as ceil(log_q/m) unless you override.
    - Validates each candidate and returns best by cost.
    """

    def __init__(self, lambda_sec: int = 128) -> None:
        self.lambda_sec = lambda_sec

        # HE guidance table (same as validator uses)
        self.he_limits = LogVOLEValidator.HE_LIMITS_128.copy()

    @staticmethod
    def _iter_candidate_points(
        w: int,
        n_candidates: List[int],
        log_p_range: range,
        log_q_range: range,
        m_range: range,
    ) -> Iterator[Tuple[int, int, int, int, int, int]]:
        """
        Yield valid candidate tuples:
        (n, w_prime, log_p, log_q, m, log_g).
        """
        for n in n_candidates:
            if not is_power_of_two(n):
                continue

            w_prime = ceil_div(w, n)
            for log_p, log_q, m in product(log_p_range, log_q_range, m_range):
                if log_p <= 0:
                    continue
                if log_q <= log_p or log_q % log_p != 0:
                    continue
                if m <= 0:
                    continue

                log_g = int(math.ceil(log_q / m))
                if log_g <= 0 or log_g > 512:
                    continue

                yield (n, w_prime, log_p, log_q, m, log_g)

    @staticmethod
    def cost_function(n: int, log_q: int, log_p: int, m: int) -> float:
        def get_pow2(x):
            return 1 << (x - 1).bit_length()

        rho = ceil_div(log_q, log_p)
        tau = m
        mu = get_pow2(2 * rho * (tau - 1))
        return float(mu) * math.log2(mu) * (tau - 1)

    def search(
        self,
        mode: LogVOLEMode,
        noise_model: NoiseModel,
        w: int,
        T: int,
        n_candidates: List[int],
        log_p_range: range,
        log_q_range: range,
        m_range: range,
        *,
        s_star: int = 8,
        eta_eps_R: Optional[float] = None,
        enforce_he_limit: bool = False,
        min_margin_bits: float = 0.0,
        verbose_every: int = 0,
    ) -> List[OptimizationResult]:

        results: List[OptimizationResult] = []
        checked = 0

        for n, w_prime, log_p, log_q, m, log_g in self._iter_candidate_points(
            w=w,
            n_candidates=n_candidates,
            log_p_range=log_p_range,
            log_q_range=log_q_range,
            m_range=m_range,
        ):
            try:
                params = LogVOLEParams(
                    n=n,
                    log_q=log_q,
                    log_p=log_p,
                    lambda_sec=self.lambda_sec,
                    log_g=log_g,
                    m=m,
                    w=w,
                    w_prime=w_prime,
                    T=T,
                    noise_model=noise_model,
                    mode=mode,
                    s_star=s_star,
                    eta_eps_R=eta_eps_R,
                    gamma_R=None,            # default to n
                    alpha=2,
                )
            except ValueError:
                continue

            checked += 1
            if verbose_every and checked % verbose_every == 0:
                print(f"[checked={checked}] n={n}, logp={log_p}, logq={log_q}, m={m}, logg={log_g}")

            v = LogVOLEValidator(params, enforce_he_limit=enforce_he_limit).validate()
            if not v.is_valid:
                continue

            noise = v.details.get("noise", {})
            margin = float(noise.get("margin_bits", -1e9))
            if margin < min_margin_bits:
                continue

            cost = self.cost_function(n, log_q, log_p, m)
            results.append(
                OptimizationResult(
                    params=params,
                    cost=cost,
                    margin_bits=margin,
                    noise_details=noise,
                )
            )

        results.sort(key=lambda r: r.cost)
        return results


def pretty_result(res: OptimizationResult) -> str:
    p = res.params
    rho = ceil_div(p.log_q, p.log_p)
    mu_hi = 2 * (p.m - 1) * rho
    log2_noise_bound = float(res.noise_details.get("log2_B_total", float("nan")))
    noise_bound = f" noise_bound=2^{log2_noise_bound:.2f}" if math.isfinite(log2_noise_bound) else ""
    eta_eps_R = float(res.noise_details.get("eta_eps_R", float("nan")))
    s = float(res.noise_details.get("s", float("nan")))
    sbar_over_B = float(res.noise_details.get("leaky_lwe_sbar_over_leakage_norm", float("nan")))
    eta_summary = (
        f" eta_R={eta_eps_R:.2f} s={s:.2f} sbar/B={sbar_over_B:.2f}"
        if math.isfinite(eta_eps_R) and math.isfinite(s) and math.isfinite(sbar_over_B)
        else ""
    )
    expected = expected_retrials_summary(res.margin_bits)
    return (
        f"n={p.n} log_q={p.log_q} log_p={p.log_p} log_g={p.log_g} m={p.m} "
        f"rho={rho} mu_hi={mu_hi} w'={p.w_prime} T={p.T} margin={res.margin_bits:.2f}{noise_bound} "
        f"{expected}{eta_summary} cost={res.cost:.3e}"
    )


def expected_retrials_summary(margin_bits: float) -> str:
    """Format expected failed seed attempts from the golden-seed exponent."""
    if not math.isfinite(margin_bits):
        return "expected_retrials=unknown"
    if GOLDEN_SEED_SLACK <= 0.0:
        return "expected_retrials=invalid_slack"

    # margin = log2(Delta / (2 * slack * B * N)), so the seed-search
    # exponent x = 2BN/Delta is 2^-margin / slack. A seed succeeds with
    # probability about exp(-x), giving expected failed attempts exp(x) - 1.
    log2_retry_exponent = -margin_bits - math.log2(GOLDEN_SEED_SLACK)
    if log2_retry_exponent < -53.0:
        expected_retrials = 2.0 ** log2_retry_exponent
        return f"expected_retrials={expected_retrials:.2f}"

    max_direct_log2_exponent = math.log2(700.0)
    if log2_retry_exponent <= max_direct_log2_exponent:
        retry_exponent = 2.0 ** log2_retry_exponent
        expected_retrials = math.expm1(retry_exponent)
        return f"expected_retrials={expected_retrials:.2f}"

    if log2_retry_exponent > 1023.0:
        return "expected_retrials=astronomical"

    log2_expected_retrials = (2.0 ** log2_retry_exponent) * math.log2(math.e)
    if math.isfinite(log2_expected_retrials):
        return f"expected_retrials=2^{log2_expected_retrials:.2f}"
    return "expected_retrials=astronomical"


# =============================================================================
# Main
# =============================================================================

def optimization_for_logvole(opt: LogVOLEOptimizer) -> List[OptimizationResult]:
    # Tight search around paper-ish region
    N = 2 ** 25
    n = 2 ** 13
    w_prime = 8
    w = n * w_prime
    T = N // w

    return opt.search(
        mode=LogVOLEMode.STANDARD,
        noise_model=NoiseModel.SEC6,
        w=w,
        T=T,
        n_candidates=[n // 2, n, 2 * n],
        log_p_range=range(41, 61),
        log_q_range=range(10, 221),
        m_range=range(2, 9),
        s_star=8,
        eta_eps_R=None,
        enforce_he_limit=True,
        min_margin_bits=0.0,
    )


def fixed_logvole_reference_result(opt: LogVOLEOptimizer) -> Tuple[OptimizationResult, ValidationResult]:
    # Reference profile used by the LogVOLE tests/benchmarks.
    N = 2 ** 24
    n = 2 ** 13
    w_prime = 8
    w = n * w_prime
    T = N // w
    log_q = 220
    log_p = 55
    m = 2
    log_g = int(math.ceil(log_q / m))

    params = LogVOLEParams(
        n=n,
        log_q=log_q,
        log_p=log_p,
        lambda_sec=opt.lambda_sec,
        log_g=log_g,
        m=m,
        w=w,
        w_prime=w_prime,
        T=T,
        noise_model=NoiseModel.SEC6,
        mode=LogVOLEMode.STANDARD,
        s_star=8,
        eta_eps_R=None,
        gamma_R=None,
        alpha=2,
    )
    validation = LogVOLEValidator(params, enforce_he_limit=True).validate()
    noise = validation.details.get("noise", {})
    margin = float(noise.get("margin_bits", float("-inf")))
    cost = opt.cost_function(n, log_q, log_p, m)
    return (
        OptimizationResult(
            params=params,
            cost=cost,
            margin_bits=margin,
            noise_details=noise,
        ),
        validation,
    )


def main() -> None:
    print("LogVOLE Optimizer")
    print("=" * 80)
    print("\n[1] Optimization for logvole (STANDARD mode, SEC6 + Leaky LWE noise)")

    opt = LogVOLEOptimizer(lambda_sec=128)
    results_logvole = optimization_for_logvole(opt)

    if results_logvole:
        print(f"  Found {len(results_logvole)} feasible candidates. Top 5 by cost:")
        for i, r0 in enumerate(results_logvole[:5], 1):
            print(f"   #{i}: {pretty_result(r0)}")
    else:
        print("  No feasible candidates in this search region.")

    print("\n[2] Reference tuple noise bound")
    reference_result, reference_validation = fixed_logvole_reference_result(opt)
    print(f"  {pretty_result(reference_result)}")
    if not reference_validation.is_valid:
        print("  Reference tuple is not feasible:")
        for failure in reference_validation.failures:
            print(f"    - {failure['check']}: {failure['message']}")

    print("\nDone.")


if __name__ == "__main__":
    main()
