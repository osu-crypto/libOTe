#pragma once

// Device-side modular arithmetic that reproduces Microsoft SEAL 4.1.1
// bit-for-bit. Every helper here mirrors a specific SEAL function so that GPU
// results are exactly equal to the CPU results produced by
// libOTe/Vole/LogVole/LogVoleRing.cpp. The mirrored SEAL sources are
// native/src/seal/util/uintarithsmallmod.h, uintarith.h and dwthandler.h.

#include <cstdint>

namespace osuCrypto::LogVole::gpu
{
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i64 = std::int64_t;

    // Mirrors seal::util::MultiplyUIntModOperand: an operand together with
    // quotient = floor(operand * 2^64 / modulus), used for Shoup multiplication.
    struct ShoupOperand
    {
        u64 mOperand;
        u64 mQuotient;
    };

    // Per-RNS-limb constants. mRatio0/mRatio1 are seal::Modulus::const_ratio()
    // words 0 and 1, i.e. the low and high words of floor(2^128 / q).
    struct GpuModulus
    {
        u64 mValue;
        u64 mRatio0;
        u64 mRatio1;
    };

    __host__ __device__ inline u64 mulHi64(u64 a, u64 b)
    {
#if defined(__CUDA_ARCH__)
        return __umul64hi(a, b);
#else
        return static_cast<u64>((static_cast<unsigned __int128>(a) * b) >> 64);
#endif
    }

    // Mirrors seal::util::add_uint64: returns the carry.
    __host__ __device__ inline unsigned char addU64(u64 a, u64 b, u64* out)
    {
        *out = a + b;
        return static_cast<unsigned char>(*out < a);
    }

    // Mirrors seal::util::barrett_reduce_128 for a 128-bit input given as
    // (lo, hi). See SEAL uintarithsmallmod.h.
    __host__ __device__ inline u64 barrettReduce128(u64 lo, u64 hi, const GpuModulus& mod)
    {
        u64 tmp1;
        u64 tmp3;
        u64 carry;

        // Round 1
        carry = mulHi64(lo, mod.mRatio0);
        const u64 t20 = lo * mod.mRatio1;
        const u64 t21 = mulHi64(lo, mod.mRatio1);
        tmp3 = t21 + addU64(t20, carry, &tmp1);

        // Round 2
        const u64 s20 = hi * mod.mRatio0;
        const u64 s21 = mulHi64(hi, mod.mRatio0);
        carry = s21 + addU64(tmp1, s20, &tmp1);

        // This is all we care about
        tmp1 = hi * mod.mRatio1 + tmp3 + carry;

        // Barrett subtraction
        tmp3 = lo - tmp1 * mod.mValue;

        // One more subtraction is enough
        return (tmp3 >= mod.mValue) ? (tmp3 - mod.mValue) : tmp3;
    }

    // Mirrors seal::util::barrett_reduce_64.
    __host__ __device__ inline u64 barrettReduce64(u64 input, const GpuModulus& mod)
    {
        const u64 tmp = mulHi64(input, mod.mRatio1);
        const u64 res = input - tmp * mod.mValue;
        return (res >= mod.mValue) ? (res - mod.mValue) : res;
    }

    // Mirrors seal::util::multiply_uint_mod(uint64_t, uint64_t, Modulus).
    __host__ __device__ inline u64 mulMod(u64 a, u64 b, const GpuModulus& mod)
    {
        return barrettReduce128(a * b, mulHi64(a, b), mod);
    }

    // Mirrors seal::util::multiply_uint_mod_lazy(x, MultiplyUIntModOperand,
    // Modulus): result is in [0, 2q).
    __host__ __device__ inline u64 mulShoupLazy(u64 x, const ShoupOperand& y, u64 q)
    {
        const u64 tmp = mulHi64(x, y.mQuotient);
        return y.mOperand * x - tmp * q;
    }

    // Mirrors seal::util::multiply_uint_mod(x, MultiplyUIntModOperand, Modulus).
    __host__ __device__ inline u64 mulShoup(u64 x, const ShoupOperand& y, u64 q)
    {
        const u64 res = mulShoupLazy(x, y, q);
        return (res >= q) ? (res - q) : res;
    }

    // Mirrors seal::util::add_uint_mod.
    __host__ __device__ inline u64 addMod(u64 a, u64 b, u64 q)
    {
        const u64 sum = a + b;
        return (sum >= q) ? (sum - q) : sum;
    }

    // Mirrors seal::util::sub_uint_mod.
    __host__ __device__ inline u64 subMod(u64 a, u64 b, u64 q)
    {
        return (a >= b) ? (a - b) : (a + q - b);
    }

    // Mirrors osuCrypto::LogVole::mulAddMod (LogVoleArithmetic.h): reduce a*b
    // then add c, all modulo q.
    __host__ __device__ inline u64 mulAddMod(u64 a, u64 b, u64 c, const GpuModulus& mod)
    {
        return addMod(mulMod(a, b, mod), c, mod.mValue);
    }

    // SEAL's DWT "guard": values are kept in [0, 4q) between butterflies and
    // pulled back below 2q on read.
    __host__ __device__ inline u64 nttGuard(u64 a, u64 twoQ)
    {
        return (a >= twoQ) ? (a - twoQ) : a;
    }

    // ---- 128-bit helpers, mirroring LogVoleArithmetic.h ------------------

    struct Wide
    {
        u64 mLo;
        u64 mHi;
    };

    __host__ __device__ inline Wide wideAdd(Wide a, Wide b, unsigned char* carryOut = nullptr)
    {
        u64 lo;
        const unsigned char c0 = addU64(a.mLo, b.mLo, &lo);
        u64 hi1;
        const unsigned char c1 = addU64(a.mHi, b.mHi, &hi1);
        u64 hi;
        const unsigned char c2 = addU64(hi1, static_cast<u64>(c0), &hi);
        if (carryOut) *carryOut = static_cast<unsigned char>(c1 | c2);
        return { lo, hi };
    }

    __host__ __device__ inline Wide wideSub(Wide a, Wide b)
    {
        const u64 lo = a.mLo - b.mLo;
        const u64 borrow = static_cast<u64>(a.mLo < b.mLo);
        const u64 hi = a.mHi - b.mHi - borrow;
        return { lo, hi };
    }

    __host__ __device__ inline Wide wideMul(u64 a, u64 b)
    {
        return { a * b, mulHi64(a, b) };
    }

    // Low 128 bits of a 64x128 product; mirrors wideU64MulLow.
    __host__ __device__ inline Wide wideMulLow(u64 a, Wide b)
    {
        const u64 lo = a * b.mLo;
        const u64 hi = mulHi64(a, b.mLo) + a * b.mHi;
        return { lo, hi };
    }

    // High 128 bits of a 128x128 product; mirrors wideU64MulHigh.
    __host__ __device__ inline Wide wideMulHigh(Wide a, Wide b)
    {
        const Wide t00 = wideMul(a.mLo, b.mLo);
        const Wide t01 = wideMul(a.mLo, b.mHi);
        const Wide t10 = wideMul(a.mHi, b.mLo);
        const Wide t11 = wideMul(a.mHi, b.mHi);

        u64 acc;
        const unsigned char c1 = addU64(t00.mHi, t01.mLo, &acc);
        u64 acc2;
        const unsigned char c2 = addU64(acc, t10.mLo, &acc2);
        const u64 carry1 = static_cast<u64>(c1) + static_cast<u64>(c2);

        u64 b0;
        const unsigned char d1 = addU64(t01.mHi, t10.mHi, &b0);
        u64 b1;
        const unsigned char d2 = addU64(b0, t11.mLo, &b1);
        u64 word2;
        const unsigned char d3 = addU64(b1, carry1, &word2);
        const u64 carry2 = static_cast<u64>(d1) + static_cast<u64>(d2) + static_cast<u64>(d3);

        return { word2, t11.mHi + carry2 };
    }

    // Exact division of a 128-bit numerator by a 64-bit divisor using
    // reciprocal = floor(2^128 / divisor). Mirrors divModWide128.
    __host__ __device__ inline void divModWide(
        Wide numerator, u64 divisor, Wide reciprocal, Wide* quotient, u64* remainder)
    {
        Wide q = wideMulHigh(numerator, reciprocal);
        Wide r = wideSub(numerator, wideMulLow(divisor, q));
        for (int i = 0; i < 2 && (r.mHi != 0 || r.mLo >= divisor); ++i)
        {
            r = wideSub(r, Wide{ divisor, 0 });
            q = wideAdd(q, Wide{ 1, 0 });
        }
        *quotient = q;
        *remainder = r.mLo;
    }
}
