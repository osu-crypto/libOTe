#include "libOTe/Vole/LogVole2/LogVole2Receiver.h"
#include "libOTe/Vole/LogVole2/LogVole2Sender.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole2;

namespace
{
    ShrinkExpandParams make_params()
    {
        ShrinkExpandParams params{};
        params.mRing.mPolyModulusDegree = 1024;
        params.mRing.mCoeffModulusBits = { 30, 30 };
        params.mPlaintextModulusBits = 20;
        params.mAlpha = 2;
        params.mMu = 3;
        params.mTau = 3;
        params.mGadgetLogBase = 20;
        params.mMode = ShrinkExpandMode::Deterministic;
        params.mNoiseBound = 2;
        params.mSamplingSeeds.mNoiseRoot = 0xBAD5EEDu;
        params.mSamplingSeeds.mCt2Root = 0xC72C72u;
        return params;
    }

    std::vector<RnsPoly> sample_batch(const RingNttContext& ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0005u, i));
        }
        return out;
    }

    RnsPoly sample_poly(const RingNttContext& ctx, std::uint64_t seed)
    {
        return deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0006u, 0);
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }

    std::vector<RnsPoly> multiply_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b)
    {
        std::vector<RnsPoly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(a[i], b[i], ctx, product));
            out.push_back(std::move(product));
        }
        return out;
    }

    std::vector<RnsPoly> subtract_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b)
    {
        std::vector<RnsPoly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly diff{};
            LOGVOLE_REQUIRE_TRUE(ringSub(a[i], b[i], ctx, diff));
            out.push_back(std::move(diff));
        }
        return out;
    }
}

void LogVole2_ShrinkExpandCoproto_OfflineAndExpandDeterministicRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput senderOfflineInput{};
    senderOfflineInput.mParams = params;
    senderOfflineInput.mS = sample_batch(ctx, params.mMu, 0x2001u);

    ShrinkExpandReceiverOfflineInput receiverOfflineInput{};
    receiverOfflineInput.mParams = params;

    Sender sender{};
    Receiver receiver{};
    ShrinkExpandSenderState senderState{};
    ShrinkExpandReceiverState receiverState{};

    auto offlineSockets = coproto::LocalAsyncSocket::makePair();
    auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.offline(senderOfflineInput, senderState, offlineSockets[0]),
        receiver.offline(receiverOfflineInput, receiverState, offlineSockets[1])));
    std::get<0>(offlineResult).result();
    std::get<1>(offlineResult).result();

    auto x = sample_batch(ctx, params.mMu, 0x3001u);
    const auto tbkPrime = sample_poly(ctx, 0x4001u);

    ShrinkExpandExpandSenderInput senderExpandInput{};
    senderExpandInput.mNonce = 0x999u;
    senderExpandInput.mTbkPrime = tbkPrime;

    ReceiverExpandInput receiverExpandInput{};
    receiverExpandInput.mNonce = senderExpandInput.mNonce;
    receiverExpandInput.mX = x;

    ShrinkExpandSenderExpandOutput senderOutput{};
    ShrinkExpandReceiverExpandOutput receiverOutput{};

    auto onlineSockets = coproto::LocalAsyncSocket::makePair();
    auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.expand(senderState, senderExpandInput, senderOutput, onlineSockets[0]),
        receiver.expand(receiverState, receiverExpandInput, receiverOutput, onlineSockets[1])));
    std::get<0>(onlineResult).result();
    std::get<1>(onlineResult).result();

    const auto tbmMinusTbk = subtract_batches(ctx, receiverOutput.mTbm, senderOutput.mTbk);
    const auto expected = multiply_batches(ctx, senderOfflineInput.mS, x);
    expect_batch_equal(tbmMinusTbk, expected);
}
