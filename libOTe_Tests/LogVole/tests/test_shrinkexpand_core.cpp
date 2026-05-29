#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto::LogVole;

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
        params.mNoiseSeed = 0xBAD5EEDu;
        params.mNoiseBound = 2;
        return params;
    }

    std::vector<RnsPoly> sample_batch(
        const RingNttContext& ctx,
        std::uint32_t count,
        std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0xABCDu, i));
        }
        return out;
    }

    RnsPoly sample_poly(const RingNttContext& ctx, std::uint64_t seed)
    {
        return deriveUniformPolyFromNonce(ctx, seed, 0xABCDu, 0);
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

void LogVole_ShrinkExpandCore_DeterministicRelationExact(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput sender_input{};
    sender_input.mParams = params;
    sender_input.mS = sample_batch(ctx, params.mMu, 0x2001u);

    ShrinkExpandOfflineMessage offline_message{};
    ShrinkExpandSenderState sender_state{};
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(sender_input, offline_message, sender_state));

    ShrinkExpandReceiverOfflineInput receiver_input{};
    receiver_input.mParams = params;
    ShrinkExpandReceiverState receiver_state{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiver_input, offline_message, receiver_state));

    auto x = sample_batch(ctx, params.mMu, 0x3001u);
    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(shrink(receiver_state, x, digest));

    const auto tbk_prime = sample_poly(ctx, 0x4001u);
    RnsPoly sk_x{};
    LOGVOLE_REQUIRE_TRUE(deriveSkX(sender_state, digest, tbk_prime, sk_x));

    ShrinkExpandSenderExpandInput sender_expand_input{};
    sender_expand_input.mNonce = 0x999u;
    sender_expand_input.mTbkPrime = tbk_prime;

    ShrinkExpandSenderExpandOutput sender_expand{};
    LOGVOLE_REQUIRE_TRUE(expandSender(sender_state, sender_expand_input, sender_expand));

    ShrinkExpandReceiverExpandInput receiver_expand_input{};
    receiver_expand_input.mNonce = sender_expand_input.mNonce;
    receiver_expand_input.mX = x;
    receiver_expand_input.mDigest = digest;
    receiver_expand_input.mSkX = sk_x;

    ShrinkExpandReceiverExpandOutput receiver_expand{};
    LOGVOLE_REQUIRE_TRUE(expandReceiver(receiver_state, receiver_expand_input, receiver_expand));

    const auto tbm_minus_tbk = subtract_batches(ctx, receiver_expand.mTbm, sender_expand.mTbk);
    const auto expected = multiply_batches(ctx, sender_input.mS, x);
    expect_batch_equal(tbm_minus_tbk, expected);
}

void LogVole_ShrinkExpandCore_OfflineMetadataMismatchRejected(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput sender_input{};
    sender_input.mParams = params;
    sender_input.mS = sample_batch(ctx, params.mMu, 0x5001u);

    ShrinkExpandOfflineMessage offline_message{};
    ShrinkExpandSenderState sender_state{};
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(sender_input, offline_message, sender_state));

    offline_message.mMetadataFingerprint ^= 1u;

    ShrinkExpandReceiverOfflineInput receiver_input{};
    receiver_input.mParams = params;
    ShrinkExpandReceiverState receiver_state{};
    LOGVOLE_REQUIRE_FALSE(finalizeReceiverOffline(receiver_input, offline_message, receiver_state));
}
