#pragma once

#include <cstddef>
#include <cstdint>

namespace osuCrypto::LogVole::gpu
{
    // One raw polar pair is four u32 words. Stable compaction preserves the
    // library's y-then-cached-x order, including independent clipping of each.
    // candidate storage: rows * ceil(wordsPerRow/512) * 512 u64.
    // blockCounts storage: rows * ceil(wordsPerRow/512) u32.
    bool launchGaussianTransform(
        const std::uint64_t* prefixes, std::uint32_t wordsPerRow,
        std::uint32_t rows, std::uint32_t coefficients, double sigma, double clip,
        std::uint64_t modulus, std::uint64_t* candidates, std::uint32_t* blockCounts,
        std::uint64_t* output, std::uint8_t* complete, void* stream,
        const std::uint32_t* outputRows = nullptr);
}
