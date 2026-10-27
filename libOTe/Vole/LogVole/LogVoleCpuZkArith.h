#pragma once

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"

#include <cstdlib>

namespace osuCrypto::LogVole::detail
{
    template<unsigned Bits>
    struct CpuZkArithmetic
    {
        const seal::Modulus& mMod;

        u64 multiply(u64 a, u64 b) const
        {
#if defined(__SIZEOF_INT128__)
            if constexpr (Bits != 0)
            {
                static_assert(Bits == 51 || Bits == 54);
                const u64 q = mMod.value();
                // Preserve the scalar API for noncanonical inputs too.
                if (a >= q || b >= q) return mulMod(a, b, mMod);
                constexpr u64 radix = u64{1} << Bits;
                constexpr u64 mask = radix - 1;
                const u64 gap = radix - q;
                const __uint128_t product = static_cast<__uint128_t>(a) * b;
                const __uint128_t folded = (static_cast<u64>(product) & mask) +
                    (product >> Bits) * gap;
                // q=2^Bits-gap, gap<2^24: the second fold is below
                // 2^Bits+gap^2 < 2q. One subtraction makes it canonical.
                const u64 result = (static_cast<u64>(folded) & mask) +
                    static_cast<u64>(folded >> Bits) * gap;
                return result >= q ? result - q : result;
            }
#endif
            return mulMod(a, b, mMod);
        }

        u64 multiplyAdd(u64 a, u64 b, u64 c) const
        {
            if constexpr (Bits != 0)
                return addMod(multiply(a, b), c, mMod);
            else
                return mulAddMod(a, b, c, mMod);
        }
    };

    template<typename Fn>
    auto withCpuZkArithmetic(const seal::Modulus& mod, Fn&& fn)
    {
#if defined(__SIZEOF_INT128__)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_ZK_PSEUDO_REDUCE");
            return !value || value[0] != '0';
        }();
        const u64 q = mod.value();
        if (enabled && q < (u64{1} << 51) && (u64{1} << 51) - q < (u64{1} << 24))
            return fn(CpuZkArithmetic<51>{mod});
        if (enabled && q < (u64{1} << 54) && (u64{1} << 54) - q < (u64{1} << 24))
            return fn(CpuZkArithmetic<54>{mod});
#endif
        return fn(CpuZkArithmetic<0>{mod});
    }
}
