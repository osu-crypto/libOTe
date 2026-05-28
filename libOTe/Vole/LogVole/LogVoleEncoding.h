#pragma once

#include <cryptoTools/Common/Defines.h>

#include <span>
#include <vector>

namespace osuCrypto
{
    using LogVoleBuffer = std::vector<u8>;

    struct LogVoleKeyDeriveRequest
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        std::vector<u64> mDCoeffs;
    };

    struct LogVoleKeyDeriveResponse
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        std::vector<u64> mMNttCoeffs;
    };

    struct LogVoleShrinkExpandOfflineMessage
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

    LogVoleBuffer logVoleEncode(const LogVoleKeyDeriveRequest& message);
    LogVoleBuffer logVoleEncode(const LogVoleKeyDeriveResponse& message);
    LogVoleBuffer logVoleEncode(const LogVoleShrinkExpandOfflineMessage& message);

    bool logVoleDecode(std::span<const u8> payload, LogVoleKeyDeriveRequest& message);
    bool logVoleDecode(std::span<const u8> payload, LogVoleKeyDeriveResponse& message);
    bool logVoleDecode(std::span<const u8> payload, LogVoleShrinkExpandOfflineMessage& message);
}
