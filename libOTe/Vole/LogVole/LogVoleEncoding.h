#pragma once

#include <cryptoTools/Common/Defines.h>

#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    using Buffer = std::vector<u8>;

    struct KeyDeriveRequest
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        std::vector<u64> mDCoeffs;
    };

    struct KeyDeriveResponse
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        std::vector<u64> mMNttCoeffs;
    };

    struct ShrinkExpandOfflineMessage
    {
        u32 mPolyModulusDegree = 0;
        std::vector<u16> mCoeffModulusBits;

        u32 mPlaintextModulusBits = 0;
        u32 mAlpha = 0;
        u32 mMu = 0;
        u32 mTau = 0;
        u32 mGadgetLogBase = 0;
        u8 mMode = 0;

        u64 mMetadataFingerprint = 0;

        u32 mCt1Rows = 0;
        u32 mCt1Cols = 0;
        std::vector<u64> mCt1Coeffs;

        u32 mLacctWidthPadded = 0;
        u32 mLacctLevels = 0;
        u32 mLacctCtRows = 0;
        u32 mLacctCtCols = 0;
        std::vector<u64> mLacctCtCoeffs;
    };

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
}
