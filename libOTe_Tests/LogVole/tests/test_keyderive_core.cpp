#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    RingParams make_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30 });
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
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x4B4452495645u, i));
        }
        return out;
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

    void expect_keyderive_relation(
        const RingNttContext& ctx,
        const KeyDeriveSenderInput& sender,
        const KeyDeriveReceiverInput& receiver,
        const KeyDeriveSenderOutput& senderOutput,
        const KeyDeriveReceiverOutput& receiverOutput)
    {
        expect_batch_equal(senderOutput.mK, sender.mSk2);
        LOGVOLE_REQUIRE_EQ(receiverOutput.mM.size(), receiver.mD.size());

        for (std::size_t i = 0; i < receiver.mD.size(); ++i)
        {
            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(sender.mSk1[i], receiver.mD[i], ctx, product));

            RnsPoly expected{};
            LOGVOLE_REQUIRE_TRUE(ringAdd(product, sender.mSk2[i], ctx, expected));

            expect_poly_equal(receiverOutput.mM[i], expected);
        }
    }

    void run_core_case(std::uint64_t seed, std::uint32_t tau)
    {
        const auto params = make_params();
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

        KeyDeriveSenderInput sender{};
        sender.mParams = params;
        sender.mSk1 = sample_batch(ctx, tau, seed + 1u);
        sender.mSk2 = sample_batch(ctx, tau, seed + 2u);

        KeyDeriveReceiverInput receiver{};
        receiver.mParams = params;
        receiver.mD = sample_batch(ctx, tau, seed + 3u);

        KeyDeriveRequest request{};
        LOGVOLE_REQUIRE_TRUE(prepareKeyDeriveRequest(receiver, request));
        LOGVOLE_EXPECT_EQ(request.mPolyModulusDegree, params.mPolyModulusDegree);
        LOGVOLE_EXPECT_EQ(request.mCoeffModulusCount, params.mCoeffModulusBits.size());
        LOGVOLE_EXPECT_EQ(request.mTau, receiver.mD.size());

        KeyDeriveResponse response{};
        KeyDeriveSenderOutput senderOutput{};
        LOGVOLE_REQUIRE_TRUE(processKeyDeriveRequest(sender, request, response, senderOutput));

        KeyDeriveReceiverOutput receiverOutput{};
        LOGVOLE_REQUIRE_TRUE(finalizeKeyDeriveResponse(receiver, response, receiverOutput));

        expect_keyderive_relation(ctx, sender, receiver, senderOutput, receiverOutput);
    }
}

void LogVole_KeyDeriveCore_AlgebraicRelation(const oc::CLP&)
{
    run_core_case(0x1110u, 3);
}

void LogVole_KeyDeriveCore_DeterministicRegressionSeeds(const oc::CLP&)
{
    for (const auto seed : { 0x10u, 0x20u, 0x30u, 0x40u })
    {
        run_core_case(seed, 2);
    }
}

void LogVole_KeyDeriveCore_MetadataMismatchRejected(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    KeyDeriveSenderInput sender{};
    sender.mParams = params;
    sender.mSk1 = sample_batch(ctx, 2, 0x4444u);
    sender.mSk2 = sample_batch(ctx, 2, 0x5555u);

    KeyDeriveReceiverInput receiver{};
    receiver.mParams = params;
    receiver.mD = sample_batch(ctx, 2, 0x6666u);

    KeyDeriveRequest request{};
    LOGVOLE_REQUIRE_TRUE(prepareKeyDeriveRequest(receiver, request));
    request.mPolyModulusDegree *= 2;

    KeyDeriveResponse response{};
    KeyDeriveSenderOutput senderOutput{};
    LOGVOLE_REQUIRE_FALSE(processKeyDeriveRequest(sender, request, response, senderOutput));
}
