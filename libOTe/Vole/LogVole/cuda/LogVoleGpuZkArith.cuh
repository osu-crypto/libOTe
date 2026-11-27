#pragma once

#include "libOTe/Vole/LogVole/cuda/LogVoleGpuWideCarry.cuh"

namespace osuCrypto::LogVole::gpu
{
    // Canonical product modulo q = 2^Bits-c, for 0 <= a,b < q and
    // 0 < c < 2^24. The default ZK plaintext fields use Bits=51 or 54.
    // With R=2^Bits, a*b = low + high*R and high<R. The first fold
    // low+high*c is < R*(c+1), so its high radix digit is <=c. The
    // second fold is < R+c*c < 2*q for Bits>=51: one subtraction
    // suffices. Both folds are integer-exact, including their carries.
    template<u32 Bits>
    __device__ __forceinline__ u64 mulModZkPseudo(u64 a, u64 b, u64 q)
    {
        static_assert(Bits >= 51u && Bits <= 54u);
        constexpr u64 radix = u64{1} << Bits;
        constexpr u64 mask = radix - 1;
        const u32 c = static_cast<u32>(radix - q);
        const u64 lo = a * b;
        const u64 hi = __umul64hi(a, b);
        const u64 high = (lo >> Bits) | (hi << (64u - Bits));
        const u64 p0 = static_cast<u64>(static_cast<u32>(high)) * c;
        const u64 p1 = static_cast<u64>(static_cast<u32>(high >> 32u)) * c;
        const Wide folded = wideAddCarry(
            wideAddCarry(Wide{p0, 0}, Wide{p1 << 32u, p1 >> 32u}),
            Wide{lo & mask, 0});
        const u32 high2 = static_cast<u32>(
            (folded.mLo >> Bits) | (folded.mHi << (64u - Bits)));
        u64 result = (folded.mLo & mask) + static_cast<u64>(high2) * c;
        if (result >= q) result -= q;
        return result;
    }
}
