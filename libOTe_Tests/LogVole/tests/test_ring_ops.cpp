#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>

using namespace osuCrypto::LogVole;

namespace
{
    RingParams make_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits = { 30, 30 };
        return params;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
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
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x1234u, 0x5678u, 0);
    RnsPoly expected = poly;

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(expected, ctx));

    LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));

    LOGVOLE_REQUIRE_TRUE(inverseNtt(poly, ctx));

    expect_poly_equal(poly, expected);
}

void LogVole_RingOps_GadgetDecomposeRecompose(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x55AAu, 0xCCDDu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecompose(poly, /*base=*/(1u << 10u), /*tau=*/4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecompose(digits, /*base=*/(1u << 10u), ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));

    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xAA55u, 0x11EEu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, /*digitBits=*/20u, /*levels=*/4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, /*digitBits=*/20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));

    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_TensorPackUnpack(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RingTensor tensor{};
    tensor.mRows = 2;
    tensor.mCols = 3;
    for (std::uint32_t i = 0; i < tensor.mRows * tensor.mCols; ++i)
    {
        tensor.mPolys.push_back(deriveUniformPolyFromNonce(ctx, 0x77u, 0x99u, i));
    }

    auto packed = packRingTensor(tensor);
    RingTensor unpacked{};
    LOGVOLE_REQUIRE_TRUE(unpackRingTensor(
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
