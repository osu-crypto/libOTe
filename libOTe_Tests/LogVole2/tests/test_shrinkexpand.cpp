#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto::LogVole2;

namespace
{
    ShrinkExpandParams make_params(bool trunc = false)
    {
        ShrinkExpandParams params{};
        params.mRing.mPolyModulusDegree = 1024;
        params.mRing.mCoeffModulusBits = { 30, 30 };
        params.mPlaintextModulusBits = 20;
        params.mAlpha = 2;
        params.mMu = trunc ? 4u : 3u;
        params.mTau = trunc ? 2u : 3u;
        params.mGadgetLogBase = 20;
        params.mMode = ShrinkExpandMode::Deterministic;
        params.mNoiseBound = 2;
        params.mSamplingSeeds.mNoiseRoot = 0xBAD5EEDu;
        params.mSamplingSeeds.mCt2Root = 0xC72C72u;
        params.mTruncateOneGadgetDigit = trunc;
        return params;
    }

    std::vector<RnsPoly> sample_batch(const RingNttContext& ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0003u, i));
        }
        return out;
    }

    RnsPoly sample_scalar(const RingNttContext& ctx, std::uint64_t seed)
    {
        return deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0004u, 0);
    }

    bool compute_expected_s_mul_x(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        const std::vector<RnsPoly>& x,
        std::vector<RnsPoly>& out)
    {
        if (s.size() != x.size())
        {
            return false;
        }

        out.clear();
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i)
        {
            RnsPoly prod{};
            if (!ringMultiply(s[i], x[i], ctx, prod))
            {
                return false;
            }
            out.push_back(std::move(prod));
        }
        return true;
    }

    bool subtract_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b,
        std::vector<RnsPoly>& out)
    {
        if (a.size() != b.size())
        {
            return false;
        }

        out.clear();
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly diff{};
            if (!ringSub(a[i], b[i], ctx, diff))
            {
                return false;
            }
            out.push_back(std::move(diff));
        }
        return true;
    }

    long double centered_max_log2(const RingNttContext& ctx, const std::vector<RnsPoly>& batch)
    {
        std::uint64_t maxAbs = 0;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (const auto& poly : batch)
        {
            for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
            {
                const std::uint64_t mod = ctx.mModuli[modIdx].value();
                const std::size_t offset = modIdx * n;
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::uint64_t reduced = poly.mCoeffs[offset + i] % mod;
                    const std::uint64_t centered = (reduced <= (mod / 2u)) ? reduced : (mod - reduced);
                    if (centered > maxAbs)
                    {
                        maxAbs = centered;
                    }
                }
            }
        }

        return maxAbs == 0 ? 0.0L : std::log2(static_cast<long double>(maxAbs));
    }

    bool run_relation(bool trunc)
    {
        const auto params = make_params(trunc);
        RingNttContext ctx{};
        if (!makeRingNttContext(params.mRing, ctx))
        {
            return false;
        }

        const auto s = sample_batch(ctx, params.mMu, trunc ? 0x1101u : 0x1100u);
        const auto x = sample_batch(ctx, params.mMu, trunc ? 0x2201u : 0x2200u);
        const auto sk1 = sample_batch(ctx, params.mTau, trunc ? 0x3301u : 0x3300u);
        const auto tbkPrime = sample_scalar(ctx, trunc ? 0x4401u : 0x4400u);

        ShrinkExpandSenderOfflineInput senderInput{};
        senderInput.mParams = params;
        senderInput.mS = s;
        senderInput.mFixedSk1 = sk1;

        ShrinkExpandSenderState senderState{};
        if (!prepareShrinkExpandSenderOffline(senderInput, senderState))
        {
            return false;
        }

        ShrinkExpandReceiverOfflineInput receiverInput{};
        receiverInput.mParams = params;

        ShrinkExpandReceiverState receiverState{};
        if (!finalizeShrinkExpandReceiverOffline(receiverInput, senderState, receiverState))
        {
            return false;
        }

        ShrinkExpandShrinkOutput shrink{};
        if (!shrinkExpandShrink(receiverState, x, shrink))
        {
            return false;
        }

        RnsPoly skX{};
        bool skxOk = false;
        if (trunc)
        {
            skxOk = deriveSkxTrunc(ctx, senderState.mSk1, shrink.mDigest, tbkPrime, params.mGadgetLogBase, params.mTau, skX);
        }
        else
        {
            skxOk = deriveSkx(ctx, senderState.mSk1, shrink.mDigest, tbkPrime, params.mGadgetLogBase, params.mTau, skX);
        }
        if (!skxOk)
        {
            return false;
        }

        ShrinkExpandExpandSenderInput senderExpandInput{};
        senderExpandInput.mNonce = trunc ? 0x5501u : 0x5500u;
        senderExpandInput.mTbkPrime = tbkPrime;

        ShrinkExpandSenderExpandOutput senderExpand{};
        if (!shrinkExpandExpandSender(senderState, senderExpandInput, senderExpand))
        {
            return false;
        }

        ShrinkExpandExpandReceiverInput receiverExpandInput{};
        receiverExpandInput.mNonce = senderExpandInput.mNonce;
        receiverExpandInput.mX = x;
        receiverExpandInput.mDigest = shrink.mDigest;
        receiverExpandInput.mSkX = skX;
        receiverExpandInput.mTree = shrink.mTree;

        ShrinkExpandReceiverExpandOutput receiverExpand{};
        if (!shrinkExpandExpandReceiver(receiverState, receiverExpandInput, receiverExpand))
        {
            return false;
        }

        std::vector<RnsPoly> diff;
        std::vector<RnsPoly> expected;
        if (!subtract_batches(ctx, receiverExpand.mTbm, senderExpand.mTbk, diff) ||
            !compute_expected_s_mul_x(ctx, s, x, expected) ||
            diff.size() != expected.size())
        {
            return false;
        }

        if (!trunc)
        {
            for (std::size_t i = 0; i < diff.size(); ++i)
            {
                if (diff[i].mCoeffs != expected[i].mCoeffs)
                {
                    return false;
                }
            }
            return true;
        }

        std::vector<RnsPoly> residual;
        if (!subtract_batches(ctx, diff, expected, residual))
        {
            return false;
        }

        const long double pathLen = 1.0L + std::log2(static_cast<long double>(params.mMu));
        const long double truncationBoundLog2 = static_cast<long double>(params.mGadgetLogBase) +
                                               std::log2(static_cast<long double>(params.mRing.mPolyModulusDegree)) +
                                               std::log2(pathLen);
        return centered_max_log2(ctx, residual) < truncationBoundLog2 + 2.0L;
    }
}

void LogVole2_ShrinkExpandCore_ParamsValidation(const oc::CLP&)
{
    auto params = make_params();
    LOGVOLE_REQUIRE_TRUE(validateShrinkExpandParams(params));

    params.mPlaintextModulusBits = 0;
    LOGVOLE_REQUIRE_FALSE(validateShrinkExpandParams(params));
}

void LogVole2_ShrinkExpandCore_OfflineStateShapes(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mS = sample_batch(ctx, params.mMu, 0x6600u);
    senderInput.mFixedSk1 = sample_batch(ctx, params.mTau, 0x7700u);

    ShrinkExpandSenderState senderState{};
    LOGVOLE_REQUIRE_TRUE(prepareShrinkExpandSenderOffline(senderInput, senderState));

    LOGVOLE_EXPECT_EQ(senderState.mS.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(senderState.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(senderState.mSk1.size(), params.mTau);
    LOGVOLE_EXPECT_EQ(senderState.mCt1.mRows, params.mMu);
    LOGVOLE_EXPECT_EQ(senderState.mCt1.mCols, params.mTau);
    LOGVOLE_EXPECT_EQ(senderState.mLacct.mWidthPadded, 4u);

    ShrinkExpandReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    ShrinkExpandReceiverState receiverState{};
    LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(receiverInput, senderState, receiverState));
    LOGVOLE_EXPECT_EQ(receiverState.mCt1.mRows, params.mMu);
    LOGVOLE_EXPECT_EQ(receiverState.mLacct.mCt.mRows, senderState.mLacct.mCt.mRows);
}

void LogVole2_ShrinkExpandCore_DeterministicRelationExact(const oc::CLP&)
{
    LOGVOLE_REQUIRE_TRUE(run_relation(false));
}

void LogVole2_ShrinkExpandCore_TruncDeterministicRelationBounded(const oc::CLP&)
{
    LOGVOLE_REQUIRE_TRUE(run_relation(true));
}

void LogVole2_ShrinkExpandCore_OfflineMetadataMismatchRejected(const oc::CLP&)
{
    auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mS = sample_batch(ctx, params.mMu, 0x8800u);
    senderInput.mFixedSk1 = sample_batch(ctx, params.mTau, 0x9900u);

    ShrinkExpandSenderState senderState{};
    LOGVOLE_REQUIRE_TRUE(prepareShrinkExpandSenderOffline(senderInput, senderState));

    ShrinkExpandReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;
    receiverInput.mParams.mTau += 1;

    ShrinkExpandReceiverState receiverState{};
    LOGVOLE_REQUIRE_FALSE(finalizeShrinkExpandReceiverOffline(receiverInput, senderState, receiverState));
}
