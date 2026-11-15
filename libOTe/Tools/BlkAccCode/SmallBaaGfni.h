#pragma once
#include "ChosenBaaField.h"
#include <array>

#if defined(OC_ENABLE_SSE2) && defined(__GFNI__)
#include <immintrin.h>

namespace osuCrypto::chosen_baa_detail
{
    // GFNI applies an 8x8 binary matrix to each byte. Its matrix row for
    // output bit i occupies byte 7-i. These are polynomial products, not
    // multiplication in GF(256): bytes carry into the next byte of GF(2^128).
    struct alignas(64) SmallGfniMatrices
    {
        u64 lo, loCopy, hi, hiCopy, foldLo, foldHi;
    };

    constexpr std::array<SmallGfniMatrices, 256> smallGfniMatrices()
    {
        std::array<SmallGfniMatrices, 256> result{};
        for (unsigned c = 1; c <= 256; ++c)
        {
            auto& m = result[c - 1];
            for (unsigned j = 0; j < 8; ++j)
            {
                const unsigned product = c << j;
                unsigned folded = 0;
                // The highest byte's overflow is reduced modulo
                // x^128 + x^7 + x^2 + x + 1. It occupies at most two bytes.
                for (unsigned k = 0; k < 8; ++k)
                    if ((product >> 8) & (1u << k)) folded ^= 0x87u << k;
                for (unsigned i = 0; i < 8; ++i)
                {
                    const auto bit = u64{1} << (8 * (7 - i) + j);
                    if ((product >> i) & 1) m.lo |= bit;
                    if ((product >> (i + 8)) & 1) m.hi |= bit;
                    if ((folded >> i) & 1) m.foldLo |= bit;
                    if ((folded >> (i + 8)) & 1) m.foldHi |= bit;
                }
            }
            m.loCopy = m.lo; m.hiCopy = m.hi;
        }
        return result;
    }

    // The 16 KiB table is shared by all instances. Its layout avoids two
    // broadcasts per recurrence step; each selector touches one cache line.
    // Selection depends only on the code's public coefficient, never input.
    inline constexpr auto smallGfniTable = smallGfniMatrices();

    OC_FORCEINLINE block smallGfniMadd(block state, u32 coefficient, block input)
    {
        const auto& m = smallGfniTable[coefficient - 1];
        const auto lo = _mm_gf2p8affine_epi64_epi8(state,
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(&m.lo)), 0);
        const auto hi = _mm_gf2p8affine_epi64_epi8(state,
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(&m.hi)), 0);
        const auto top = _mm_shuffle_epi8(state, _mm_set1_epi8(15));
        auto fold = _mm_gf2p8affine_epi64_epi8(top,
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(&m.foldLo)), 0);
        // Low and high reduction bytes were computed in separate quadwords.
        fold = _mm_shuffle_epi8(fold,
            _mm_setr_epi8(0, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1));
        return input ^ block(lo) ^ block(_mm_slli_si128(hi, 1)) ^ block(fold);
    }
}
#endif
