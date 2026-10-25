#pragma once

#include "cryptoTools/Common/Defines.h"

#include "seal/modulus.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"

#include <cmath>
#include <limits>

namespace osuCrypto::LogVole
{
    struct wideU64
    {
        u64 mLo;
        u64 mHi;
    };

    inline wideU64 makeWideU64(u64 lo, u64 hi)
    {
        return { lo, hi };
    }

    inline wideU64 wideU64AllOnes()
    {
        return { ~u64(0), ~u64(0) };
    }

    inline wideU64 wideU64OneShift(u32 bit)
    {
        if (bit >= 128)
        {
            return {};
        }
        return bit < 64 ? wideU64{ u64(1) << bit, 0 } : wideU64{ 0, u64(1) << (bit - 64) };
    }

    inline wideU64 wideU64Mask(u32 bits)
    {
        if (bits == 0)
        {
            return {};
        }
        if (bits >= 128)
        {
            return wideU64AllOnes();
        }
        if (bits < 64)
        {
            return { (u64(1) << bits) - 1, 0 };
        }
        if (bits == 64)
        {
            return { ~u64(0), 0 };
        }
        return { ~u64(0), (u64(1) << (bits - 64)) - 1 };
    }

    inline wideU64 wideU64And(wideU64 value, wideU64 mask)
    {
        return { value.mLo & mask.mLo, value.mHi & mask.mHi };
    }

    inline int compareWideU64(wideU64 lhs, wideU64 rhs)
    {
        if (lhs.mHi != rhs.mHi)
        {
            return lhs.mHi < rhs.mHi ? -1 : 1;
        }
        if (lhs.mLo != rhs.mLo)
        {
            return lhs.mLo < rhs.mLo ? -1 : 1;
        }
        return 0;
    }

    inline bool wideU64Less(wideU64 lhs, wideU64 rhs)
    {
        return compareWideU64(lhs, rhs) < 0;
    }

    inline bool wideU64LessEq(wideU64 lhs, wideU64 rhs)
    {
        return compareWideU64(lhs, rhs) <= 0;
    }

    inline bool wideU64Equal(wideU64 lhs, wideU64 rhs)
    {
        return lhs.mLo == rhs.mLo && lhs.mHi == rhs.mHi;
    }

    inline wideU64 wideU64Add(wideU64 lhs, wideU64 rhs, unsigned char* carryOut = nullptr)
    {
        unsigned long long lo = 0;
        unsigned long long hi = 0;
        const auto carry = seal::util::add_uint64(lhs.mLo, rhs.mLo, &lo);
        const auto carry2 = seal::util::add_uint64(lhs.mHi, rhs.mHi, carry, &hi);
        if (carryOut)
        {
            *carryOut = carry2;
        }
        return { static_cast<u64>(lo), static_cast<u64>(hi) };
    }

    inline wideU64 wideU64Sub(wideU64 lhs, wideU64 rhs)
    {
        unsigned long long lo = 0;
        unsigned long long hi = 0;
        const auto borrow = seal::util::sub_uint64(lhs.mLo, rhs.mLo, &lo);
        (void)seal::util::sub_uint64(lhs.mHi, rhs.mHi, borrow, &hi);
        return { static_cast<u64>(lo), static_cast<u64>(hi) };
    }

    inline wideU64 wideU64Negate(wideU64 value)
    {
        unsigned long long lo = 0;
        unsigned long long hi = 0;
        const auto carry = seal::util::add_uint64(~value.mLo, u64(1), &lo);
        (void)seal::util::add_uint64(~value.mHi, u64(0), carry, &hi);
        return { static_cast<u64>(lo), static_cast<u64>(hi) };
    }

    inline wideU64 wideU64Mul(u64 lhs, u64 rhs)
    {
        unsigned long long words[2] = { 0, 0 };
        seal::util::multiply_uint64(lhs, rhs, words);
        return { static_cast<u64>(words[0]), static_cast<u64>(words[1]) };
    }

    inline wideU64 wideU64MulLow(u64 lhs, wideU64 rhs)
    {
        unsigned long long loProd[2] = { 0, 0 };
        unsigned long long hiProd[2] = { 0, 0 };
        seal::util::multiply_uint64(lhs, rhs.mLo, loProd);
        seal::util::multiply_uint64(lhs, rhs.mHi, hiProd);
        return {
            static_cast<u64>(loProd[0]),
            static_cast<u64>(loProd[1] + hiProd[0])
        };
    }

    inline u64 wideU64Mod(wideU64 value, const seal::Modulus& modulus)
    {
        u64 words[2] = { value.mLo, value.mHi };
        return seal::util::barrett_reduce_128(words, modulus);
    }

    inline u64 mulMod(u64 lhs, u64 rhs, const seal::Modulus& modulus)
    {
        return seal::util::multiply_uint_mod(lhs, rhs, modulus);
    }

    inline u64 mulAddMod(u64 lhs, u64 rhs, u64 addend, const seal::Modulus& modulus)
    {
        return seal::util::multiply_add_uint_mod(lhs, rhs, addend, modulus);
    }

    inline u64 addMod(u64 lhs, u64 rhs, const seal::Modulus& modulus)
    {
        return seal::util::add_uint_mod(lhs, rhs, modulus);
    }

    // High 128 bits of the 256-bit product of two 128-bit values.
    inline wideU64 wideU64MulHigh(wideU64 lhs, wideU64 rhs)
    {
        const wideU64 t00 = wideU64Mul(lhs.mLo, rhs.mLo);
        const wideU64 t01 = wideU64Mul(lhs.mLo, rhs.mHi);
        const wideU64 t10 = wideU64Mul(lhs.mHi, rhs.mLo);
        const wideU64 t11 = wideU64Mul(lhs.mHi, rhs.mHi);

        // word1 = t00.hi + t01.lo + t10.lo
        u64 word1 = 0;
        unsigned char c1 = 0;
        unsigned char c2 = 0;
        {
            unsigned long long acc = 0;
            c1 = seal::util::add_uint64(t00.mHi, t01.mLo, &acc);
            unsigned long long acc2 = 0;
            c2 = seal::util::add_uint64(static_cast<u64>(acc), t10.mLo, &acc2);
            word1 = static_cast<u64>(acc2);
        }
        const u64 carry1 = static_cast<u64>(c1) + static_cast<u64>(c2);

        // word2 = t01.hi + t10.hi + t11.lo + carry1
        u64 word2 = 0;
        u64 carry2 = 0;
        {
            unsigned long long acc = 0;
            unsigned char d1 = seal::util::add_uint64(t01.mHi, t10.mHi, &acc);
            unsigned long long acc2 = 0;
            unsigned char d2 = seal::util::add_uint64(static_cast<u64>(acc), t11.mLo, &acc2);
            unsigned long long acc3 = 0;
            unsigned char d3 = seal::util::add_uint64(static_cast<u64>(acc2), carry1, &acc3);
            word2 = static_cast<u64>(acc3);
            carry2 = static_cast<u64>(d1) + static_cast<u64>(d2) + static_cast<u64>(d3);
        }

        const u64 word3 = t11.mHi + carry2;
        (void)word1;
        return { word2, word3 };
    }

    // Exact floor(numerator / divisor) and numerator mod divisor for a 128-bit
    // numerator, using v = floor(2^128 / divisor) as produced by
    // reciprocal2Pow128Wide. Replaces a software 128/64 division with a handful
    // of multiplies. Requires numerator < 2^127 and divisor >= 2.
    inline void divModWide128(
        wideU64 numerator, u64 divisor, wideU64 reciprocal, wideU64& quotient, u64& remainder)
    {
        wideU64 q = wideU64MulHigh(numerator, reciprocal);

        // q is either the true quotient or one less, so at most two correction
        // steps are ever needed.
        wideU64 prod = wideU64MulLow(divisor, q);
        wideU64 r = wideU64Sub(numerator, prod);
        for (int i = 0; i < 2 && (r.mHi != 0 || r.mLo >= divisor); ++i)
        {
            r = wideU64Sub(r, wideU64{ divisor, 0 });
            unsigned char carry = 0;
            q = wideU64Add(q, wideU64{ 1, 0 }, &carry);
        }

        quotient = q;
        remainder = r.mLo;
    }

    inline wideU64 reciprocal2Pow128Wide(u64 modulus)
    {
        u64 numerator[2] = { 0, 1 };
        u64 quotient[2] = { 0, 0 };
        seal::util::divide_uint128_inplace(numerator, modulus, quotient);
        const u64 hi = quotient[0];
        const u64 rem = numerator[0];

        numerator[0] = 0;
        numerator[1] = rem;
        quotient[0] = 0;
        quotient[1] = 0;
        seal::util::divide_uint128_inplace(numerator, modulus, quotient);
        return { quotient[0], hi };
    }

    inline wideU64 floorToWideU64(long double value)
    {
        if (!(value > 0.0L))
        {
            return {};
        }

        constexpr long double two64 = 18446744073709551616.0L;
        const long double hiLd = std::floor(value / two64);
        if (hiLd >= two64)
        {
            return wideU64AllOnes();
        }

        const u64 hi = static_cast<u64>(hiLd);
        const long double loLd = std::floor(value - hiLd * two64);
        const u64 lo = static_cast<u64>((loLd > 0.0L) ? loLd : 0.0L);
        return { lo, hi };
    }
}
