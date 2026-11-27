#pragma once

#include "libOTe/Vole/LogVole/cuda/LogVoleGpuWideCarry.cuh"

namespace osuCrypto::LogVole::gpu
{
    struct SamplePseudo52Word
    {
        u64 residue;
        u32 rejected;
    };

    // Full-u64 reduction for q=R-c, R=2^52, 0<c<2^24. The fold
    // t=(x mod R)+floor(x/R)*c is below R+2^36 < 2q.
    // The standard SEAL threshold is 4096*q-1 = UINT64_MAX-4096*c.
    // For that threshold only, rejection is h=4095 and t>=q-1.
    // Custom thresholds retain their exact original comparison and replay.
    template<bool FusedReject>
    __device__ __forceinline__ SamplePseudo52Word samplePseudo52ReduceWord(
        u64 x, u64 q, u32 c, u64 threshold)
    {
        constexpr u64 mask = (u64{1} << 52u) - 1u;
        const u32 h = static_cast<u32>(x >> 52u);
        u64 t = (x & mask) + static_cast<u64>(h) * c;
        u32 rejected;
        if constexpr (FusedReject)
        {
            const u64 standard = ~u64{0} - (static_cast<u64>(c) << 12u);
            rejected = static_cast<u32>(threshold == standard
                ? h == 4095u && t >= q - 1u : x >= threshold);
        }
        else rejected = static_cast<u32>(x >= threshold);
        if (t >= q) t -= q;
        return { t, rejected };
    }

    // Exact for ANY unsigned 128-bit value, with q=2^52-c and 0<c<2^24.
    // Write x=s0+s1*R+s2*R^2, R=2^52. Here s2<2^24, so
    // u=s1+s2*c < 2^52+2^48 < 2^53. The second fold u*c+s0
    // fits 77 bits. Its high radix digit is <2^25; one final fold is
    // below R+2^49 < 2q. No canonical-input or product-count assumption
    // is needed, including when a preceding Wide sum wrapped modulo 2^128.
    template<bool Carry>
    __device__ __forceinline__ u64 reducePseudo52FullWide(Wide value, u64 q)
    {
        constexpr u64 radix = u64{1} << 52u, mask = radix - 1u;
        const u32 c = static_cast<u32>(radix - q);
        const u64 s0 = value.mLo & mask;
        const u64 s1 = ((value.mLo >> 52u) | (value.mHi << 12u)) & mask;
        const u32 s2 = static_cast<u32>(value.mHi >> 40u);
        const u64 u = s1 + static_cast<u64>(s2) * c;
        const u64 p0 = static_cast<u64>(static_cast<u32>(u)) * c;
        const u64 p1 = static_cast<u64>(static_cast<u32>(u >> 32u)) * c;
        Wide folded;
        if constexpr (Carry)
            folded = wideAddCarry(wideAddCarry(Wide{p0, 0u},
                Wide{p1 << 32u, p1 >> 32u}), Wide{s0, 0u});
        else
        {
            u64 lo = p0 + (p1 << 32u);
            u64 carry = static_cast<u64>(lo < p0);
            const u64 before = lo;
            lo += s0;
            carry += static_cast<u64>(lo < before);
            folded = Wide{lo, (p1 >> 32u) + carry};
        }
        const u64 low = folded.mLo & mask;
        const u32 high = static_cast<u32>((folded.mLo >> 52u) | (folded.mHi << 12u));
        u64 residue = low + static_cast<u64>(high) * c;
        if (residue >= q) residue -= q;
        return residue;
    }
}
