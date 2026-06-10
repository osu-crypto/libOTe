#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>

using namespace osuCrypto::LogVole;

namespace
{
    RingParams make_small_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30 });
        return params;
    }

    RingParams make_four_limb_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30, 30, 30 });
        return params;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << " coeff index " << i;
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
}

void LogVole_RingOps_NttRoundTrip(const oc::CLP&)
{
    const auto params = make_small_params();
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
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x55AAu, 0xCCDDu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecompose(poly, 1u << 10u, 4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecompose(digits, 1u << 10u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xAA55u, 0x11EEu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, 20u, 4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, 20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeBitsRangeMatchesSlice(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xBEEFu, 0xCAFEu, 1);

    std::vector<RnsPoly> full;
    std::vector<RnsPoly> range;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, 10u, 6u, ctx, full));
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, 10u, 2u, 3u, ctx, range));
    LOGVOLE_REQUIRE_EQ(range.size(), 3u);

    for (std::size_t i = 0; i < range.size(); ++i)
    {
        expect_poly_equal(range[i], full[i + 2]);
    }
}

void LogVole_RingOps_CenteredGadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_four_limb_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xA11CEu, 0xB0Bu, 2);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, 20u, 0u, 7u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 7u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, 20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_TensorPackUnpack(const oc::CLP&)
{
    const auto params = make_small_params();
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

void LogVole_RingOps_NonceBatchDeterminism(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::vector<std::uint64_t> nonces{ 1, 2, 3, 4 };
    auto a = deriveUniformPolyBatchFromNonceList(ctx, nonces, 0xF00Du, 3u, 1u);
    auto b = deriveUniformPolyBatchFromNonceList(ctx, nonces, 0xF00Du, 3u, 1u);
    expect_batch_equal(a, b);

    std::vector<RnsPoly> c;
    LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromNonceListInplace(ctx, nonces, 0xF00Du, 3u, c, 1u));
    expect_batch_equal(a, c);
}
