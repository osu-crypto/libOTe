#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto;

namespace
{
    struct LencParams
    {
        LogVoleRingParams mRing{};
        std::uint32_t mMu = 3;
        std::uint32_t mTau = 3;
        std::uint32_t mGadgetLogBase = 126;
    };

    LencParams make_params()
    {
        LencParams p{};
        p.mRing.mPolyModulusDegree = 16384;
        p.mRing.mCoeffModulusBits = { 54, 54, 54, 54, 54, 54, 54 };
        return p;
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
            out.push_back(logVoleDeriveUniformPolyFromNonce(ctx, seed, 0x1E2C0001u, i));
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

    void expect_tensor_equal(const LogVoleRingTensor& a, const LogVoleRingTensor& b)
    {
        LOGVOLE_EXPECT_EQ(a.mRows, b.mRows);
        LOGVOLE_EXPECT_EQ(a.mCols, b.mCols);
        expect_batch_equal(a.mPolys, b.mPolys);
    }

} // namespace

void LogVole_LencOps_EncShapeAndDeterminism(const oc::CLP&)
{
    const auto params = make_params();

    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x1111u);

    LogVoleLencEncodeOutput enc1{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencEnc(ctx, s, params.mTau, params.mGadgetLogBase, 0xABCDEF01u, enc1));

    LogVoleLencEncodeOutput enc2{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencEnc(ctx, s, params.mTau, params.mGadgetLogBase, 0xABCDEF01u, enc2));

    LOGVOLE_EXPECT_EQ(enc1.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mLevels, 2u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mRows, enc1.mLacct.mLevels * enc1.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mCols, 2u * params.mTau);

    expect_batch_equal(enc1.mR, enc2.mR);
    expect_tensor_equal(enc1.mLacct.mCt, enc2.mLacct.mCt);
}

void LogVole_LencOps_DigestDeterministic(const oc::CLP&)
{
    const auto params = make_params();

    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params.mRing, ctx));

    auto x = sample_batch(ctx, params.mMu, 0x2222u);

    LogVoleRnsPoly digest1{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest1));

    LogVoleRnsPoly digest2{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest2));

    expect_poly_equal(digest1, digest2);
}

void LogVole_LencOps_EvalMatchesRmulDigestMinusSmulX(const oc::CLP&)
{
    const auto params = make_params();

    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x3333u);
    auto x = sample_batch(ctx, params.mMu, 0x4444u);

    LogVoleLencEncodeOutput enc{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencEnc(ctx, s, params.mTau, params.mGadgetLogBase, 0x5555u, enc));

    LogVoleRnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest, enc.mLacct.mWidthPadded));

    std::vector<LogVoleRnsPoly> eval;
    LOGVOLE_REQUIRE_TRUE(logVoleLencEval(ctx, enc.mLacct, x, params.mMu, params.mTau, params.mGadgetLogBase, eval));

    LOGVOLE_REQUIRE_EQ(eval.size(), params.mMu);
    for (std::size_t i = 0; i < params.mMu; ++i)
    {
        LogVoleRnsPoly r_mul_digest{};
        LOGVOLE_REQUIRE_TRUE(logVoleRingMultiply(enc.mR[i], digest, ctx, r_mul_digest));

        LogVoleRnsPoly s_mul_x{};
        LOGVOLE_REQUIRE_TRUE(logVoleRingMultiply(s[i], x[i], ctx, s_mul_x));

        LogVoleRnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(logVoleRingSub(r_mul_digest, s_mul_x, ctx, expected));

        expect_poly_equal(eval[i], expected);
    }
}

void LogVole_LencOps_EvalRejectsMuMismatch(const oc::CLP&)
{
    const auto params = make_params();

    LogVoleRingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(logVoleMakeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x6666u);
    auto x = sample_batch(ctx, params.mMu, 0x7777u);

    LogVoleLencEncodeOutput enc{};
    LOGVOLE_REQUIRE_TRUE(logVoleLencEnc(ctx, s, params.mTau, params.mGadgetLogBase, 0x8888u, enc));

    std::vector<LogVoleRnsPoly> eval;
    LOGVOLE_REQUIRE_FALSE(logVoleLencEval(
        ctx,
        enc.mLacct,
        x,
        params.mMu + 1u,
        params.mTau,
        params.mGadgetLogBase,
        eval));
}
