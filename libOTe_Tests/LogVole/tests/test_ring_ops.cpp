#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>

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

    void expect_poly_equal(const LogVoleRnsPoly& a, const LogVoleRnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << "coeff index " << i;
        }
    }

} // namespace

void LogVole_RingOps_NttRoundTrip(const oc::CLP&)
{
    const auto params = make_params();
    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params, ctx));

    LogVoleRnsPoly poly = logVoleDeriveUniformPolyFromNonce(ctx, 0x1234u, 0x5678u, 0);
    LogVoleRnsPoly expected = poly;

    LOGVOLE_REQUIRE_TRUE(logVoleCanonicalizePoly(expected, ctx));

    LOGVOLE_REQUIRE_TRUE(logVoleForwardNtt(poly, ctx));

    LOGVOLE_REQUIRE_TRUE(logVoleInverseNtt(poly, ctx));

    expect_poly_equal(poly, expected);
}

void LogVole_RingOps_GadgetDecomposeRecompose(const oc::CLP&)
{
    const auto params = make_params();
    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params, ctx));

    LogVoleRnsPoly poly = logVoleDeriveUniformPolyFromNonce(ctx, 0x55AAu, 0xCCDDu, 0);

    std::vector<LogVoleRnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(logVoleGadgetDecompose(poly, /*base=*/(1u << 10u), /*tau=*/4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    LogVoleRnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(logVoleGadgetRecompose(digits, /*base=*/(1u << 10u), ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(logVoleCanonicalizePoly(poly, ctx));

    LOGVOLE_REQUIRE_TRUE(logVoleCanonicalizePoly(recomposed, ctx));

    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_params();
    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params, ctx));

    LogVoleRnsPoly poly = logVoleDeriveUniformPolyFromNonce(ctx, 0xAA55u, 0x11EEu, 0);

    std::vector<LogVoleRnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(logVoleGadgetDecomposeBits(poly, /*digitBits=*/20u, /*levels=*/4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    LogVoleRnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(logVoleGadgetRecomposeBits(digits, /*digitBits=*/20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(logVoleCanonicalizePoly(poly, ctx));

    LOGVOLE_REQUIRE_TRUE(logVoleCanonicalizePoly(recomposed, ctx));

    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_TensorPackUnpack(const oc::CLP&)
{
    const auto params = make_params();
    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params, ctx));

    LogVoleRingTensor tensor{};
    tensor.mRows = 2;
    tensor.mCols = 3;
    for (std::uint32_t i = 0; i < tensor.mRows * tensor.mCols; ++i)
    {
        tensor.mPolys.push_back(logVoleDeriveUniformPolyFromNonce(ctx, 0x77u, 0x99u, i));
    }

    auto packed = logVolePackRingTensor(tensor);
    LogVoleRingTensor unpacked{};
    LOGVOLE_REQUIRE_TRUE(logVoleUnpackRingTensor(
        tensor.mRows,
        tensor.mCols,
        params.mPolyModulusDegree,
        static_cast<std::uint32_t>(params.mCoeffModulusBits.size()),
        packed,
        unpacked));
    LOGVOLE_REQUIRE_EQ(unpacked.mRows, tensor.mRows);
    LOGVOLE_REQUIRE_EQ(unpacked.mCols, tensor.mCols);
    LOGVOLE_REQUIRE_EQ(unpacked.mPolys.size(), tensor.mPolys.size());

    for (std::size_t i = 0; i < tensor.mPolys.size(); ++i)
    {
        expect_poly_equal(tensor.mPolys[i], unpacked.mPolys[i]);
    }
}
