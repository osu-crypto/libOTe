#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Aligned.h>

#include <algorithm>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    template<typename T>
    using AlignedUnVec = AlignedUnVector<T>;

    template<typename T>
    void resizeZero(AlignedUnVec<T>& value, u64 size)
    {
        value.resize(static_cast<std::size_t>(size), AllocType::Zeroed);
    }

    template<typename T>
    void resizeFill(AlignedUnVec<T>& value, u64 size, const T& fill)
    {
        value.resize(static_cast<std::size_t>(size));
        std::fill(value.begin(), value.end(), fill);
    }

    template<typename T, typename It>
    void assignRange(AlignedUnVec<T>& value, It begin, It end)
    {
        const auto size = static_cast<std::size_t>(std::distance(begin, end));
        value.resize(size);
        std::copy(begin, end, value.begin());
    }

    template<typename T>
    void assignSpan(AlignedUnVec<T>& value, std::span<const T> input)
    {
        value.resize(input.size());
        std::copy(input.begin(), input.end(), value.begin());
    }

    template<typename T>
    void assignValues(AlignedUnVec<T>& value, std::initializer_list<T> input)
    {
        value.resize(input.size());
        std::copy(input.begin(), input.end(), value.begin());
    }

    template<typename L, typename R>
    bool rangesEqual(const L& lhs, const R& rhs)
    {
        return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
    }

    struct RingParams
    {
        u32 mPolyModulusDegree = 0;
        AlignedUnVec<int> mCoeffModulusBits;

        bool operator==(const RingParams& other) const
        {
            return mPolyModulusDegree == other.mPolyModulusDegree
                && mCoeffModulusBits.size() == other.mCoeffModulusBits.size()
                && std::equal(
                    mCoeffModulusBits.begin(),
                    mCoeffModulusBits.end(),
                    other.mCoeffModulusBits.begin());
        }

        bool operator!=(const RingParams& other) const
        {
            return !(*this == other);
        }
    };

    struct RnsPoly
    {
        AlignedUnVec<u64> mCoeffs;
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
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
        Deterministic = 0,
#endif
        FullNoise = 1
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
        ShrinkExpandMode mMode = ShrinkExpandMode::FullNoise;
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
        u64 mSessionId = 0;
    };

    struct SenderState
    {
        Params mParams;
        std::vector<RnsPoly> mSk1;
        ShrinkExpandSenderState mShrinkExpandState;
        std::vector<RnsPoly> mRootSkRRt;
        std::vector<RnsPoly> mRootR1Rt;
        u32 mRootRandomizerWidth = 0;
        mutable AlignedUnVec<u8> mGoldenSeed;
        mutable std::shared_ptr<RnsPoly> mRootKPrimeRt;
        mutable std::shared_ptr<RnsPoly> mRootDPrimeRt;
        mutable std::shared_ptr<std::vector<RnsPoly>> mPrecomputedTbk;
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
        mutable AlignedUnVec<u8> mGoldenSeed;
        mutable std::shared_ptr<RnsPoly> mRootDPrimeRt;
        std::unique_ptr<ReceiverState> mNextLevelState;
    };
}
