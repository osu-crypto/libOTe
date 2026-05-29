#pragma once

#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"

#include <span>
#include <vector>

namespace osuCrypto::LogVole2
{
    using Buffer = std::vector<u8>;

    struct PolyMessage
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        std::vector<u64> mCoeffs;
    };

    Buffer encode(const KeyDeriveRequest& message);
    Buffer encode(const KeyDeriveResponse& message);
    Buffer encode(const ShrinkExpandOfflineMessage& message);
    Buffer encode(const PolyMessage& message);

    bool decode(std::span<const u8> payload, KeyDeriveRequest& message);
    bool decode(std::span<const u8> payload, KeyDeriveResponse& message);
    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message);
    bool decode(std::span<const u8> payload, PolyMessage& message);

    PolyMessage makePolyMessage(const RingParams& params, const RnsPoly& poly);
    bool readPolyMessage(const RingParams& params, PolyMessage& message, RnsPoly& out);
}
