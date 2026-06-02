#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <cstddef>
#include <cstdint>
#include <tuple>
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

    void run_coproto_case(std::uint64_t seed, std::uint32_t tau)
    {
        const auto params = make_params();
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

        KeyDeriveSenderInput senderInput{};
        senderInput.mParams = params;
        senderInput.mSk1 = sample_batch(ctx, tau, seed + 1u);
        senderInput.mSk2 = sample_batch(ctx, tau, seed + 2u);

        KeyDeriveReceiverInput receiverInput{};
        receiverInput.mParams = params;
        receiverInput.mD = sample_batch(ctx, tau, seed + 3u);

        LogVoleRingSender sender{};
        LogVoleRingReceiver receiver{};
        KeyDeriveSenderOutput senderOutput{};
        KeyDeriveReceiverOutput receiverOutput{};

        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            sender.keyDerive(senderInput, senderOutput, sockets[0]),
            receiver.keyDerive(receiverInput, receiverOutput, sockets[1])));
        std::get<0>(result).result();
        std::get<1>(result).result();

        expect_batch_equal(senderOutput.mK, senderInput.mSk2);
        LOGVOLE_REQUIRE_EQ(receiverOutput.mM.size(), receiverInput.mD.size());

        for (std::size_t i = 0; i < receiverInput.mD.size(); ++i)
        {
            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(senderInput.mSk1[i], receiverInput.mD[i], ctx, product));

            RnsPoly expected{};
            LOGVOLE_REQUIRE_TRUE(ringAdd(product, senderInput.mSk2[i], ctx, expected));

            expect_poly_equal(receiverOutput.mM[i], expected);
        }
    }
}

void LogVole_KeyDeriveCoproto_HappyPathAndAlgebraicRelation(const oc::CLP&)
{
    run_coproto_case(0x1110u, 3);
}

void LogVole_KeyDeriveCoproto_DeterministicRegressionSeeds(const oc::CLP&)
{
    for (const auto seed : { 0x10u, 0x20u, 0x30u, 0x40u })
    {
        run_coproto_case(seed, 2);
    }
}
