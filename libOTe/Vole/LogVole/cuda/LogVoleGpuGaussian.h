#pragma once

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include <array>
#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole::gpu
{
    class DeviceScalars;
    struct GaussianPrngPrefixBuffer
    {
        // Immutable, completed pinned download. Readers retain this ownership
        // until every CPU normal transform using the prefix has finished.
        std::shared_ptr<const u64> mData;
        std::size_t mWords = 0;
    };

    // Exact BLAKE2xb byte prefixes for independent SEAL seeds. A prefix is a
    // whole number of SEAL's 4096-byte refills. Output is unchanged on failure.
    bool sampleGaussianPrngPrefixesDevice(
        std::span<const std::array<u64, 8>> seeds,
        u32 wordsPerPrefix,
        GaussianPrngPrefixBuffer& out);

    struct GaussianSampleBuffer
    {
        GaussianPrngPrefixBuffer mValues;
        // Incomplete rows have an insufficient finite prefix and must be
        // replayed from their original seed. Their values are never consumed.
        std::vector<u8> mComplete;
    };

    struct GaussianDeviceSampleBuffer
    {
        // Completed compact q0 samples, retained on device. Inactive logical
        // rows are zero; incomplete active rows require exact seeded repair.
        std::shared_ptr<DeviceScalars> mValues;
        std::vector<u8> mComplete;
    };

    bool gaussianTransformHostCompatible();

    // Exact compact q0 samples under the recognized CPU arithmetic/libm ABI.
    // The GPU performs PRG, transform, clipping and stable compaction; no
    // approximation or bound-based acceptance changes the transcript.
    // wordsPerPrefix=0 chooses a conservative finite prefix. On false, out is
    // unchanged. Success may identify rows requiring exact CPU replay.
    bool sampleGaussianCompactDevice(
        std::span<const std::array<u64, 8>> seeds, u32 coefficients,
        double sigma, double clip, u64 modulus, GaussianSampleBuffer& out,
        u32 wordsPerPrefix = 0);

    bool sampleGaussianCompactResidentDevice(
        std::span<const std::array<u64, 8>> seeds, u32 coefficients,
        double sigma, double clip, u64 modulus, GaussianDeviceSampleBuffer& out,
        u32 wordsPerPrefix = 0, std::span<const u8> active = {});
}
