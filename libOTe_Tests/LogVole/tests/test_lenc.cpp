#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    struct LencParams
    {
        RingParams mRing{};
        std::uint32_t mMu = 3;
        std::uint32_t mTau = 3;
        std::uint32_t mTauHi = 2;
        std::uint32_t mGadgetLogBase = 20;
        std::uint32_t mPlaintextModulusBits = 20;
    };

    LencParams make_params()
    {
        LencParams p{};
        p.mRing.mPolyModulusDegree = 1024;
        assignValues<int>(p.mRing.mCoeffModulusBits, { 30, 30 });
        return p;
    }

    std::vector<RnsPoly> sample_batch(const RingNttContext& ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0001u, i));
        }
        return out;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << " coeff idx " << i;
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

    void expect_tensor_equal(const RingTensor& a, const RingTensor& b)
    {
        LOGVOLE_EXPECT_EQ(a.mRows, b.mRows);
        LOGVOLE_EXPECT_EQ(a.mCols, b.mCols);
        expect_batch_equal(a.mPolys, b.mPolys);
    }
}

void LogVole_LencOps_EncShapeAndDeterminism(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x1111u);
    LencEncodeOutput enc1{};
    oc::PRNG prng1(oc::block(0xABCDEF01u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng1, enc1));

    LencEncodeOutput enc2{};
    oc::PRNG prng2(oc::block(0xABCDEF01u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng2, enc2));

    LOGVOLE_EXPECT_EQ(enc1.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mRNtt.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mLevels, 2u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mRows, enc1.mLacct.mLevels * enc1.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mCols, 2u * params.mTau);

    expect_batch_equal(enc1.mR, enc2.mR);
    expect_batch_equal(enc1.mRNtt, enc2.mRNtt);
    expect_tensor_equal(enc1.mLacct.mCt, enc2.mLacct.mCt);
}

void LogVole_LencOps_DigestTreeDeterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto x = sample_batch(ctx, params.mMu, 0x2222u);

    DigestTree tree1{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree1));

    DigestTree tree2{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree2));

    LOGVOLE_EXPECT_EQ(tree1.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(tree1.mLevels, 2u);
    expect_poly_equal(tree1.mDigest, tree2.mDigest);
    LOGVOLE_REQUIRE_EQ(tree1.mNodeDecompNtt.size(), tree2.mNodeDecompNtt.size());
    for (std::size_t i = 1; i < tree1.mNodeDecompNtt.size(); ++i)
    {
        expect_batch_equal(tree1.mNodeDecompNtt[i], tree2.mNodeDecompNtt[i]);
    }

    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(lencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest));
    expect_poly_equal(digest, tree1.mDigest);
}

void LogVole_LencOps_EvalMatchesRmulDigestMinusSmulX(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x3333u);
    auto x = sample_batch(ctx, params.mMu, 0x4444u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x5555u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));

    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(lencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest, enc.mLacct.mWidthPadded));

    std::vector<RnsPoly> eval;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, enc.mLacct, x, params.mMu, params.mTau, params.mGadgetLogBase, eval));

    LOGVOLE_REQUIRE_EQ(eval.size(), params.mMu);
    for (std::size_t i = 0; i < params.mMu; ++i)
    {
        RnsPoly rMulDigest{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(enc.mR[i], digest, ctx, rMulDigest));

        RnsPoly sMulX{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(s[i], x[i], ctx, sMulX));

        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringSub(rMulDigest, sMulX, ctx, expected));

        expect_poly_equal(eval[i], expected);
    }
}

void LogVole_LencOps_EvalFromPrebuiltTreeMatchesEvalFromX(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x6666u);
    auto x = sample_batch(ctx, params.mMu, 0x7777u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x8888u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));

    std::vector<RnsPoly> evalFromX;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, enc.mLacct, x, params.mMu, params.mTau, params.mGadgetLogBase, evalFromX));

    DigestTree tree{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree, enc.mLacct.mWidthPadded));

    std::vector<RnsPoly> evalFromTree;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, enc.mLacct, tree, params.mMu, params.mTau, params.mGadgetLogBase, evalFromTree));

    expect_batch_equal(evalFromX, evalFromTree);
}

void LogVole_LencOps_EvalRejectsMuMismatch(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x9999u);
    auto x = sample_batch(ctx, params.mMu, 0xAAAAu);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0xBBBBu, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));

    std::vector<RnsPoly> eval;
    LOGVOLE_REQUIRE_FALSE(lencEval(
        ctx,
        enc.mLacct,
        x,
        params.mMu + 1u,
        params.mTau,
        params.mGadgetLogBase,
        eval));
}

void LogVole_LencOps_TruncEncShapeAndDeterminism(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x110011u);
    LencEncodeOutput enc1{};
    oc::PRNG prng1(oc::block(0x221122u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEncTrunc(
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng1,
        enc1));

    LencEncodeOutput enc2{};
    oc::PRNG prng2(oc::block(0x221122u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEncTrunc(
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng2,
        enc2));

    LOGVOLE_EXPECT_EQ(enc1.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mRNtt.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mLevels, 2u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mRows, enc1.mLacct.mLevels * enc1.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mCols, 2u * params.mTauHi);

    expect_batch_equal(enc1.mR, enc2.mR);
    expect_batch_equal(enc1.mRNtt, enc2.mRNtt);
    expect_tensor_equal(enc1.mLacct.mCt, enc2.mLacct.mCt);
}

void LogVole_LencOps_TruncDigestTreeDeterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto x = sample_batch(ctx, params.mMu, 0x330033u);

    DigestTree tree1{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree1));

    DigestTree tree2{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree2));

    LOGVOLE_EXPECT_EQ(tree1.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(tree1.mLevels, 2u);
    expect_poly_equal(tree1.mDigest, tree2.mDigest);
    LOGVOLE_REQUIRE_EQ(tree1.mNodeDecompNtt.size(), tree2.mNodeDecompNtt.size());
    for (std::size_t i = 1; i < tree1.mNodeDecompNtt.size(); ++i)
    {
        expect_batch_equal(tree1.mNodeDecompNtt[i], tree2.mNodeDecompNtt[i]);
    }

    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(lencDigestTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        digest));
    expect_poly_equal(digest, tree1.mDigest);
}

void LogVole_LencOps_TruncEvalFromPrebuiltTreeMatchesEvalFromX(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x440044u);
    auto x = sample_batch(ctx, params.mMu, 0x550055u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x660066u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEncTrunc(
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng,
        enc));

    std::vector<RnsPoly> evalFromX;
    LOGVOLE_REQUIRE_TRUE(lencEvalTrunc(
        ctx,
        enc.mLacct,
        x,
        params.mMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        evalFromX));

    DigestTree tree{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree,
        enc.mLacct.mWidthPadded));

    std::vector<RnsPoly> evalFromTree;
    LOGVOLE_REQUIRE_TRUE(lencEvalTrunc(
        ctx,
        enc.mLacct,
        tree,
        params.mMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        evalFromTree));

    expect_batch_equal(evalFromX, evalFromTree);
}

void LogVole_LencOps_TruncEvalRejectsMuMismatch(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x770077u);
    auto x = sample_batch(ctx, params.mMu, 0x880088u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x990099u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEncTrunc(
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng,
        enc));

    std::vector<RnsPoly> eval;
    LOGVOLE_REQUIRE_FALSE(lencEvalTrunc(
        ctx,
        enc.mLacct,
        x,
        params.mMu + 1u,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        eval));
}

void LogVole_LencOps_TruncLeafInputsAreGadgetPath(const oc::CLP&)
{
    auto params = make_params();
    params.mMu = 4;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0xAA00AAu);
    auto x = sample_batch(ctx, params.mMu, 0xBB00BBu);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0xCC00CCu, 0));
    LOGVOLE_REQUIRE_TRUE(lencEncTrunc(
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng,
        enc,
        0.0,
        0.0,
        0,
        true,
        true));

    DigestTree tree{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree,
        enc.mLacct.mWidthPadded,
        true));

    const std::uint32_t firstLeaf = tree.mWidthPadded - 1u;
    LOGVOLE_REQUIRE_EQ(tree.mNodeDecompNtt[firstLeaf].size(), 1u);

    std::vector<RnsPoly> eval;
    LOGVOLE_REQUIRE_TRUE(lencEvalTrunc(
        ctx,
        enc.mLacct,
        tree,
        params.mMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        eval,
        false,
        1,
        true));
    LOGVOLE_EXPECT_EQ(eval.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc.mLacct.mCt.mCols, 2u * params.mTauHi);
}
