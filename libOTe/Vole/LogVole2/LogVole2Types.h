#pragma once

#include <cryptoTools/Common/Defines.h>

#include <memory>
#include <vector>

namespace osuCrypto::LogVole2
{
    struct RingParams
    {
        u32 mPolyModulusDegree = 0;
        std::vector<int> mCoeffModulusBits;

        bool operator==(const RingParams& other) const
        {
            return mPolyModulusDegree == other.mPolyModulusDegree &&
                   mCoeffModulusBits == other.mCoeffModulusBits;
        }

        bool operator!=(const RingParams& other) const
        {
            return !(*this == other);
        }
    };

    struct RnsPoly
    {
        std::vector<u64> mCoeffs;
    };

    struct RingTensor
    {
        u32 mRows = 0;
        u32 mCols = 0;
        std::vector<RnsPoly> mPolys;
    };

    inline u64 ringPolyCoeffCount(const RingParams& params)
    {
        return static_cast<u64>(params.mPolyModulusDegree) * params.mCoeffModulusBits.size();
    }

    inline u64 ringTensorSize(const RingTensor& tensor)
    {
        return static_cast<u64>(tensor.mRows) * tensor.mCols;
    }

    inline u64 ringTensorIndex(const RingTensor& tensor, u32 row, u32 col)
    {
        return static_cast<u64>(row) * tensor.mCols + col;
    }

    enum class ShrinkExpandMode : u8
    {
        Deterministic = 0,
        FullNoise = 1
    };

    struct SamplingSeedConfig
    {
        static constexpr u64 DefaultNoiseRoot = 0x5EEDBEEF1234ull;
        static constexpr u64 DefaultCt2Root = 0xB720AA55D1CE5EEDull;

        u64 mNoiseRoot = DefaultNoiseRoot;
        u64 mCt2Root = DefaultCt2Root;
    };

    struct ShrinkExpandParams
    {
        RingParams mRing;
        u32 mPlaintextModulusBits = 0;
        u32 mAlpha = 2;
        u32 mMu = 0;
        u32 mGadgetLogBase = 0;
        u32 mTau = 0;
        u32 mNumWorkerThreads = 1;
        bool mTruncateOneGadgetDigit = false;
        bool mLeafInputsAreGadget = false;
        ShrinkExpandMode mMode = ShrinkExpandMode::Deterministic;
        SamplingSeedConfig mSamplingSeeds;
        i64 mNoiseBound = 2;
    };

    struct DigestTree;

    struct ShrinkExpandLacct
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RingTensor mCt;
    };

    struct ShrinkExpandSenderState
    {
        ShrinkExpandParams mParams;
        i64 mEffectiveNoiseBound = 0;
        std::vector<RnsPoly> mS;
        std::vector<RnsPoly> mR;
        std::vector<RnsPoly> mSk1;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicANtt;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicBNtt;
        RingTensor mCt1;
        ShrinkExpandLacct mLacct;
    };

    struct ShrinkExpandReceiverState
    {
        ShrinkExpandParams mParams;
        i64 mEffectiveNoiseBound = 0;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicANtt;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicBNtt;
        RingTensor mCt1;
        ShrinkExpandLacct mLacct;
    };

    struct Params
    {
        ShrinkExpandParams mShrinkExpand;
        u32 mW = 0;
        u32 mGamma = 0;
        u64 mTotalLabelCount = 0;
    };

    struct SenderState
    {
        Params mParams;
        std::vector<RnsPoly> mSk1;
        ShrinkExpandSenderState mShrinkExpandState;
        std::vector<RnsPoly> mRootSkRRt;
        std::vector<RnsPoly> mRootR1Rt;
        u32 mRootRandomizerWidth = 0;
        mutable std::vector<u8> mGoldenSeed;
        mutable std::shared_ptr<RnsPoly> mRootKPrimeRt;
        mutable std::shared_ptr<RnsPoly> mRootKRt;
        mutable std::shared_ptr<std::vector<RnsPoly>> mPrecomputedTbk;
        mutable bool mGoldenSeedTransmitted = false;
        std::unique_ptr<SenderState> mNextLevelState;
    };

    struct ReceiverState
    {
        Params mParams;
        ShrinkExpandReceiverState mShrinkExpandState;
        RingTensor mRootCtRRt;
        ShrinkExpandLacct mRootLacctLeft;
        RingTensor mRootTopCt;
        std::vector<RnsPoly> mRootPublicBStarNtt;
        u32 mRootRandomizerWidth = 0;
        mutable std::vector<u8> mGoldenSeed;
        std::unique_ptr<ReceiverState> mNextLevelState;
    };
}
