#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto;

namespace
{
    LogVoleRingParams make_params()
    {
        LogVoleRingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits = { 30, 30 };
        return params;
    }

    std::vector<LogVoleRnsPoly> sample_batch(
        const LogVoleRingNttContext& ctx,
        std::uint32_t count,
        std::uint64_t seed)
    {
        std::vector<LogVoleRnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(logVoleDeriveUniformPolyFromNonce(ctx, seed, 0x4B4452495645u, i));
        }
        return out;
    }

    void expect_poly_equal(const LogVoleRnsPoly& a, const LogVoleRnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<LogVoleRnsPoly>& a, const std::vector<LogVoleRnsPoly>& b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }
}

void LogVole_KeyDeriveCore_AlgebraicRelation(const oc::CLP&)
{
    const auto params = make_params();
    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params, ctx));

    LogVoleKeyDeriveSenderInput sender{};
    sender.mParams = params;
    sender.mSk1 = sample_batch(ctx, 3, 0x1111u);
    sender.mSk2 = sample_batch(ctx, 3, 0x2222u);

    LogVoleKeyDeriveReceiverInput receiver{};
    receiver.mParams = params;
    receiver.mD = sample_batch(ctx, 3, 0x3333u);

    LogVoleKeyDeriveRequest request{};
    LOGVOLE_REQUIRE_TRUE(logVolePrepareKeyDeriveRequest(receiver, request));
    LOGVOLE_EXPECT_EQ(request.mPolyModulusDegree, params.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(request.mCoeffModulusCount, params.mCoeffModulusBits.size());
    LOGVOLE_EXPECT_EQ(request.mTau, receiver.mD.size());

    LogVoleKeyDeriveResponse response{};
    LogVoleKeyDeriveSenderOutput sender_output{};
    LOGVOLE_REQUIRE_TRUE(logVoleProcessKeyDeriveRequest(sender, request, response, sender_output));
    expect_batch_equal(sender_output.mK, sender.mSk2);

    LogVoleKeyDeriveReceiverOutput receiver_output{};
    LOGVOLE_REQUIRE_TRUE(logVoleFinalizeKeyDeriveResponse(receiver, response, receiver_output));
    LOGVOLE_REQUIRE_EQ(receiver_output.mM.size(), receiver.mD.size());

    for (std::size_t i = 0; i < receiver.mD.size(); ++i)
    {
        LogVoleRnsPoly product{};
        LOGVOLE_REQUIRE_TRUE(logVoleRingMultiply(sender.mSk1[i], receiver.mD[i], ctx, product));

        LogVoleRnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(logVoleRingAdd(product, sender.mSk2[i], ctx, expected));

        expect_poly_equal(receiver_output.mM[i], expected);
    }
}

void LogVole_KeyDeriveCore_MetadataMismatchRejected(const oc::CLP&)
{
    const auto params = make_params();
    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params, ctx));

    LogVoleKeyDeriveSenderInput sender{};
    sender.mParams = params;
    sender.mSk1 = sample_batch(ctx, 2, 0x4444u);
    sender.mSk2 = sample_batch(ctx, 2, 0x5555u);

    LogVoleKeyDeriveReceiverInput receiver{};
    receiver.mParams = params;
    receiver.mD = sample_batch(ctx, 2, 0x6666u);

    LogVoleKeyDeriveRequest request{};
    LOGVOLE_REQUIRE_TRUE(logVolePrepareKeyDeriveRequest(receiver, request));
    request.mPolyModulusDegree *= 2;

    LogVoleKeyDeriveResponse response{};
    LogVoleKeyDeriveSenderOutput sender_output{};
    LOGVOLE_REQUIRE_FALSE(logVoleProcessKeyDeriveRequest(sender, request, response, sender_output));
}
