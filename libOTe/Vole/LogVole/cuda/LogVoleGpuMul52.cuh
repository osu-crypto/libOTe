#pragma once

#include <cuda_runtime.h>
#include <cstdint>

namespace osuCrypto::LogVole::gpu
{
    // Exact 128-bit product for canonical residues a,b < 2^52 only.
    // Splitting at bit 32 leaves 20-bit high halves. The two cross-products
    // sum to less than 2^53, so that addition needs no high carry. The low
    // word addition supplies the sole carry into the high result word.
    // No truncation of input bits is used to manufacture this precondition.
    __device__ __forceinline__ ulonglong2 mulWide52(std::uint64_t a, std::uint64_t b)
    {
        const std::uint32_t a0 = static_cast<std::uint32_t>(a);
        const std::uint32_t b0 = static_cast<std::uint32_t>(b);
        const std::uint32_t a1 = static_cast<std::uint32_t>(a >> 32u);
        const std::uint32_t b1 = static_cast<std::uint32_t>(b >> 32u);
        const std::uint64_t p00 = static_cast<std::uint64_t>(a0) * b0;
        const std::uint64_t cross = static_cast<std::uint64_t>(a0) * b1 +
            static_cast<std::uint64_t>(a1) * b0;
        const std::uint64_t lo = p00 + (cross << 32u);
        const std::uint64_t hi = static_cast<std::uint64_t>(a1) * b1 +
            (cross >> 32u) + static_cast<std::uint64_t>(lo < p00);
        return make_ulonglong2(lo, hi);
    }
}
