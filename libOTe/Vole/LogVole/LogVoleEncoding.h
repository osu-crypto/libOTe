#pragma once

#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    using Buffer = AlignedUnVec<u8>;

    struct PolyMessage
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        AlignedUnVec<u64> mCoeffs;
    };

    struct SeedMessage
    {
        AlignedUnVec<u8> mSeed;
    };

    struct RootOfflineMessage
    {
        RingParams mRing;
        u32 mTauHi = 0;
        u32 mGadgetLogBase = 0;
        u32 mPlaintextModulusBits = 0;
        u32 mLeftWidth = 0;
        u32 mRandomizerWidth = 0;
        RingTensor mCtR;
        ShrinkExpandLacct mLacctLeft;
        RingTensor mTopCt;
        std::vector<RnsPoly> mPublicBStarNtt;
    };

    struct RootDigestMessage
    {
        AlignedUnVec<u64> mDPrimeCoeffs;
    };

    struct RootResponseMessage
    {
        AlignedUnVec<u8> mSeed;
        AlignedUnVec<u64> mSkPrimeCoeffs;
    };

    Buffer encode(const KeyDeriveRequest& message);
    Buffer encode(const KeyDeriveResponse& message);
    Buffer encode(const ShrinkExpandOfflineMessage& message);
    Buffer encode(const PolyMessage& message);
    Buffer encode(const SeedMessage& message);
    Buffer encode(const RootOfflineMessage& message);
    Buffer encode(const RootDigestMessage& message);
    Buffer encode(const RootResponseMessage& message);

    bool decode(std::span<const u8> payload, KeyDeriveRequest& message);
    bool decode(std::span<const u8> payload, KeyDeriveResponse& message);
    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message);
    bool decode(std::span<const u8> payload, PolyMessage& message);
    bool decode(std::span<const u8> payload, SeedMessage& message);
    bool decode(std::span<const u8> payload, RootOfflineMessage& message);
    bool decode(std::span<const u8> payload, RootDigestMessage& message);
    bool decode(std::span<const u8> payload, RootResponseMessage& message);

    PolyMessage makePolyMessage(const RingParams& params, const RnsPoly& poly);
    bool readPolyMessage(const RingParams& params, PolyMessage& message, RnsPoly& out);
}
