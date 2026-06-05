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
