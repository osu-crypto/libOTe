#pragma once

#include <cuda_runtime.h>
#include <cmath>

namespace osuCrypto::LogVole::gpu
{
    // Experimental exact FP64 residue arithmetic, NOT approximate arithmetic.
    // Contract: 2^51 < q < 2^52, integer doubles |a| < q and 0 <= b < q,
    // invQ = RN(1/q). All conversions to double are consequently exact.
    // The rounded product and its FMA error form an exact two-double product.
    // The estimated quotient differs from floor(a*b/q) by at most one.
    // Before floor(), reciprocal/product rounding contributes less than 3/4
    // to h/q. Thus |h-floor(h*invQ)*q| < 7*q/4 < 2^53 and this integer FMA
    // result is exact. Adding the product error yields an exact integer in
    // (-q,2q); one correction in either direction makes it canonical.
    __device__ __forceinline__ double mulModFp52(
        double a, double b, double q, double invQ)
    {
        const double h = __dmul_rn(a, b);
        const double l = __fma_rn(a, b, -h);
        const double quotient = floor(__dmul_rn(h, invQ));
        double r = __dadd_rn(__fma_rn(-quotient, q, h), l);
        if (r < 0.0) r = __dadd_rn(r, q);
        if (r >= q) r = __dsub_rn(r, q);
        return r;
    }

    __device__ __forceinline__ double addModFp52(double a, double b, double q)
    {
        double r = __dadd_rn(a, b);
        if (r >= q) r = __dsub_rn(r, q);
        return r;
    }

    // Experimental predivided-multiplier form. Same integer-input contract as
    // mulModFp52, but bDivQ must be RN(b/q), NOT b * RN(1/q).
    // Since b/q < 1 and |a| < q < 2^52, reciprocal-ratio rounding contributes
    // < 1/4 to a*bDivQ and the following multiplication contributes <= 1/4.
    // The quotient estimate is consequently within 1/2 before floor. The
    // rounded full product has absolute error < q/2, so h-floor(a*bDivQ)*q
    // is an integer strictly between -q and 2q: the residual FMA is exact.
    // Adding its exact product error and correcting once in either direction
    // returns the same canonical integer residue. The independent quotient
    // multiply can overlap the full-product/error chain when bDivQ is cached.
    __device__ __forceinline__ double mulModFp52Prediv(
        double a, double b, double q, double bDivQ)
    {
        const double h = __dmul_rn(a, b);
        const double l = __fma_rn(a, b, -h);
        const double quotient = floor(__dmul_rn(a, bDivQ));
        double r = __dadd_rn(__fma_rn(-quotient, q, h), l);
        if (r < 0.0) r = __dadd_rn(r, q);
        if (r >= q) r = __dsub_rn(r, q);
        return r;
    }
}
