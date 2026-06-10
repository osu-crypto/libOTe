#include "libOTe/Vole/LogVole/LogVoleLhe.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    struct LheParams
    {
        RingParams mRing{};
        std::uint32_t mMu = 3;
        std::uint32_t mTau = 3;
        std::uint32_t mTauHi = 2;
        std::uint32_t mGadgetLogBase = 20;
    };

    LheParams make_params()
    {
        LheParams p{};
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
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0002u, i));
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

    bool batches_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        if (a.size() != b.size())
        {
            return false;
        }

        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (!rangesEqual(a[i].mCoeffs, b[i].mCoeffs))
            {
                return false;
            }
        }

        return true;
    }

    void expect_tensor_equal(const RingTensor& a, const RingTensor& b)
    {
        LOGVOLE_EXPECT_EQ(a.mRows, b.mRows);
        LOGVOLE_EXPECT_EQ(a.mCols, b.mCols);
        expect_batch_equal(a.mPolys, b.mPolys);
    }

    bool forward_tensor(RingTensor& tensor, const RingNttContext& ctx)
    {
        for (auto& poly : tensor.mPolys)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }
        return true;
    }

    bool zero_poly(const RingNttContext& ctx, RnsPoly& out)
    {
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        return true;
    }

    bool recompute_trunc_high_part(
        const RingNttContext& ctx,
        const RnsPoly& digest,
        std::uint32_t gadgetLogBase,
        std::uint32_t tauHi,
        RnsPoly& out)
    {
        std::vector<RnsPoly> hiDigits;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, hiDigits) ||
            !zero_poly(ctx, out))
        {
            return false;
        }

        for (std::uint32_t i = 0; i < tauHi; ++i)
        {
            RnsPoly shifted{};
            if (!multiplyByGPower(ctx, hiDigits[i], gadgetLogBase, i + 1u, shifted) ||
                !ringAddInplace(out, shifted, ctx))
            {
                return false;
            }
        }
        return true;
    }
}

void LogVole_LheOps_PublicADeterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    std::vector<RnsPoly> a1;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, a1));

    std::vector<RnsPoly> a2;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, a2));

    LOGVOLE_EXPECT_EQ(a1.size(), params.mMu);
    expect_batch_equal(a1, a2);
}

void LogVole_LheOps_Enc1ShapeDeterminismAndColumnDecrypt(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto r = sample_batch(ctx, params.mMu, 0x1010u);
    auto sk1 = sample_batch(ctx, params.mTau, 0x2020u);

    std::vector<RnsPoly> publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, publicA));

    RingTensor ct1{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk1, params.mGadgetLogBase, ct1, 0.0, 0.0, nullptr, false, &publicA));

    RingTensor ct2{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk1, params.mGadgetLogBase, ct2, 0.0, 0.0, nullptr, false, &publicA));

    LOGVOLE_EXPECT_EQ(ct1.mRows, params.mMu);
    LOGVOLE_EXPECT_EQ(ct1.mCols, params.mTau);
    expect_tensor_equal(ct1, ct2);

    for (std::uint32_t col = 0; col < params.mTau; ++col)
    {
        std::vector<RnsPoly> column;
        column.reserve(params.mMu);
        for (std::uint32_t row = 0; row < params.mMu; ++row)
        {
            column.push_back(ct1.mPolys[ringTensorIndex(ct1, row, col)]);
        }

        std::vector<RnsPoly> dec;
        LOGVOLE_REQUIRE_TRUE(lheDec(ctx, column, sk1[col], dec, &publicA));

        for (std::uint32_t row = 0; row < params.mMu; ++row)
        {
            RnsPoly expected{};
            LOGVOLE_REQUIRE_TRUE(multiplyByGPower(ctx, r[row], params.mGadgetLogBase, col, expected));
            expect_poly_equal(dec[row], expected);
        }
    }
}

void LogVole_LheOps_ApplyCt1AndDeriveSkxRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto r = sample_batch(ctx, params.mMu, 0x4040u);
    auto sk1 = sample_batch(ctx, params.mTau, 0x5050u);
    auto digest = deriveUniformPolyFromNonce(ctx, 0x6060u, 0x7070u, 0);

    std::vector<RnsPoly> publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, publicA));

    RingTensor ct1{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk1, params.mGadgetLogBase, ct1, 0.0, 0.0, nullptr, false, &publicA));
    LOGVOLE_REQUIRE_TRUE(forward_tensor(ct1, ctx));

    std::vector<RnsPoly> applied;
    LOGVOLE_REQUIRE_TRUE(lheApplyCt1(ctx, ct1, digest, params.mGadgetLogBase, params.mTau, applied, true));

    RnsPoly tbkPrime{};
    LOGVOLE_REQUIRE_TRUE(zero_poly(ctx, tbkPrime));

    RnsPoly skx{};
    LOGVOLE_REQUIRE_TRUE(deriveSkx(ctx, sk1, digest, tbkPrime, params.mGadgetLogBase, params.mTau, skx));

    std::vector<RnsPoly> dec;
    LOGVOLE_REQUIRE_TRUE(lheDec(ctx, applied, skx, dec, &publicA, true));

    for (std::uint32_t row = 0; row < params.mMu; ++row)
    {
        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(r[row], digest, ctx, expected));
        expect_poly_equal(dec[row], expected);
    }
}

void LogVole_LheOps_TruncApplyCt1AndDeriveSkxRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto r = sample_batch(ctx, params.mMu, 0x8080u);
    auto sk1 = sample_batch(ctx, params.mTauHi, 0x9090u);
    auto digest = deriveUniformPolyFromNonce(ctx, 0xA0A0u, 0xB0B0u, 0);

    std::vector<RnsPoly> publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, publicA));

    RingTensor ct1{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1Trunc(ctx, r, sk1, params.mGadgetLogBase, ct1, 0.0, 0.0, nullptr, false, &publicA));
    LOGVOLE_REQUIRE_TRUE(forward_tensor(ct1, ctx));

    std::vector<RnsPoly> applied;
    LOGVOLE_REQUIRE_TRUE(lheApplyCt1Trunc(ctx, ct1, digest, params.mGadgetLogBase, params.mTauHi, applied, true));

    RnsPoly tbkPrime{};
    LOGVOLE_REQUIRE_TRUE(zero_poly(ctx, tbkPrime));

    RnsPoly skx{};
    LOGVOLE_REQUIRE_TRUE(deriveSkxTrunc(ctx, sk1, digest, tbkPrime, params.mGadgetLogBase, params.mTauHi, skx));

    std::vector<RnsPoly> dec;
    LOGVOLE_REQUIRE_TRUE(lheDec(ctx, applied, skx, dec, &publicA, true));

    RnsPoly highPart{};
    LOGVOLE_REQUIRE_TRUE(recompute_trunc_high_part(ctx, digest, params.mGadgetLogBase, params.mTauHi, highPart));

    for (std::uint32_t row = 0; row < params.mMu; ++row)
    {
        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(r[row], highPart, ctx, expected));
        expect_poly_equal(dec[row], expected);
    }
}

void LogVole_LheOps_ApplyCt1AndDeriveSkxRelations(const oc::CLP& cmd)
{
    LogVole_LheOps_ApplyCt1AndDeriveSkxRelation(cmd);
    LogVole_LheOps_TruncApplyCt1AndDeriveSkxRelation(cmd);
}

void LogVole_LheOps_HashedCt2Deterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    AlignedUnVec<std::uint8_t> seed(16);
    for (std::size_t idx = 0; idx < seed.size(); ++idx)
    {
        seed[idx] = static_cast<std::uint8_t>(idx + 1);
    }
    const auto digest = deriveUniformPolyFromNonce(ctx, 0xD1CEu, 0xC720u, 0);

    std::vector<RnsPoly> ct2A;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, digest, 2, ct2A));

    std::vector<RnsPoly> ct2B;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, digest, 2, ct2B));

    expect_batch_equal(ct2A, ct2B);

    std::vector<RnsPoly> ct2Sid;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 18, digest, 2, ct2Sid));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Sid));

    const auto otherDigest = deriveUniformPolyFromNonce(ctx, 0xD1CEu, 0xC720u, 1);
    std::vector<RnsPoly> ct2Digest;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, otherDigest, 2, ct2Digest));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Digest));

    std::vector<RnsPoly> ct2Instance;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, digest, 3, ct2Instance));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Instance));

    AlignedUnVec<std::uint8_t> otherSeed = seed;
    otherSeed[0] ^= 0x80;
    std::vector<RnsPoly> ct2Seed;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, otherSeed, 17, digest, 2, ct2Seed));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Seed));

    const auto seedBlock = deriveSeedInstanceBlock(seed, 17, digest, 2, params.mMu);
    const auto otherMuSeedBlock = deriveSeedInstanceBlock(seed, 17, digest, 2, params.mMu + 1);
    LOGVOLE_EXPECT_FALSE(seedBlock == otherMuSeedBlock);
}
