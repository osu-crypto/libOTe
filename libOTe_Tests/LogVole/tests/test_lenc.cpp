#include "loglabel/ring_ops.hpp"

#include "../src/protocol/lenc_ops.hpp"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace loglabel;

namespace
{
    struct lenc_params
    {
        ring_params ring{};
        std::uint32_t mu = 3;
        std::uint32_t tau = 3;
        std::uint32_t gadget_log_base = 126;
    };

    lenc_params make_params()
    {
        lenc_params p{};
        p.ring.poly_modulus_degree = 16384;
        p.ring.coeff_modulus_bits = { 54, 54, 54, 54, 54, 54, 54 };
        return p;
    }

    std::vector<ring_rns_poly> sample_batch(const ring_ntt_context &ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(derive_uniform_poly_from_nonce(ctx, seed, 0x1E2C0001u, i));
        }
        return out;
    }

    void expect_poly_equal(const ring_rns_poly &a, const ring_rns_poly &b)
    {
        LOGVOLE_REQUIRE_EQ(a.coeffs.size(), b.coeffs.size());
        for (std::size_t i = 0; i < a.coeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.coeffs[i], b.coeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<ring_rns_poly> &a, const std::vector<ring_rns_poly> &b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }

    void expect_tensor_equal(const ring_tensor &a, const ring_tensor &b)
    {
        LOGVOLE_EXPECT_EQ(a.rows, b.rows);
        LOGVOLE_EXPECT_EQ(a.cols, b.cols);
        expect_batch_equal(a.polys, b.polys);
    }

} // namespace

void LogVole_LencOps_EncShapeAndDeterminism(const oc::CLP&)
{
    const auto params = make_params();

    auto ctx_result = make_ring_ntt_context(params.ring);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    auto s = sample_batch(ctx, params.mu, 0x1111u);

    auto enc1 = lenc_enc(ctx, s, params.tau, params.gadget_log_base, 0xABCDEF01u);
    LOGVOLE_REQUIRE_TRUE(enc1) << enc1.message();

    auto enc2 = lenc_enc(ctx, s, params.tau, params.gadget_log_base, 0xABCDEF01u);
    LOGVOLE_REQUIRE_TRUE(enc2) << enc2.message();

    LOGVOLE_EXPECT_EQ(enc1.value().r.size(), params.mu);
    LOGVOLE_EXPECT_EQ(enc1.value().lacct.width_padded, 4u);
    LOGVOLE_EXPECT_EQ(enc1.value().lacct.levels, 2u);
    LOGVOLE_EXPECT_EQ(enc1.value().lacct.ct.rows, enc1.value().lacct.levels * enc1.value().lacct.width_padded);
    LOGVOLE_EXPECT_EQ(enc1.value().lacct.ct.cols, 2u * params.tau);

    expect_batch_equal(enc1.value().r, enc2.value().r);
    expect_tensor_equal(enc1.value().lacct.ct, enc2.value().lacct.ct);
}

void LogVole_LencOps_DigestDeterministic(const oc::CLP&)
{
    const auto params = make_params();

    auto ctx_result = make_ring_ntt_context(params.ring);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    auto x = sample_batch(ctx, params.mu, 0x2222u);

    auto digest1 = lenc_digest(ctx, x, params.tau, params.gadget_log_base);
    LOGVOLE_REQUIRE_TRUE(digest1) << digest1.message();

    auto digest2 = lenc_digest(ctx, x, params.tau, params.gadget_log_base);
    LOGVOLE_REQUIRE_TRUE(digest2) << digest2.message();

    expect_poly_equal(digest1.value(), digest2.value());
}

void LogVole_LencOps_EvalMatchesRmulDigestMinusSmulX(const oc::CLP&)
{
    const auto params = make_params();

    auto ctx_result = make_ring_ntt_context(params.ring);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    auto s = sample_batch(ctx, params.mu, 0x3333u);
    auto x = sample_batch(ctx, params.mu, 0x4444u);

    auto enc = lenc_enc(ctx, s, params.tau, params.gadget_log_base, 0x5555u);
    LOGVOLE_REQUIRE_TRUE(enc) << enc.message();

    auto digest = lenc_digest(ctx, x, params.tau, params.gadget_log_base, enc.value().lacct.width_padded);
    LOGVOLE_REQUIRE_TRUE(digest) << digest.message();

    auto eval = lenc_eval(ctx, enc.value().lacct, x, params.mu, params.tau, params.gadget_log_base);
    LOGVOLE_REQUIRE_TRUE(eval) << eval.message();

    LOGVOLE_REQUIRE_EQ(eval.value().size(), params.mu);
    for (std::size_t i = 0; i < params.mu; ++i)
    {
        auto r_mul_digest = ring_multiply(enc.value().r[i], digest.value(), ctx);
        LOGVOLE_REQUIRE_TRUE(r_mul_digest) << r_mul_digest.message();

        auto s_mul_x = ring_multiply(s[i], x[i], ctx);
        LOGVOLE_REQUIRE_TRUE(s_mul_x) << s_mul_x.message();

        auto expected = ring_sub(r_mul_digest.value(), s_mul_x.value(), ctx);
        LOGVOLE_REQUIRE_TRUE(expected) << expected.message();

        expect_poly_equal(eval.value()[i], expected.value());
    }
}

void LogVole_LencOps_EvalRejectsMuMismatch(const oc::CLP&)
{
    const auto params = make_params();

    auto ctx_result = make_ring_ntt_context(params.ring);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    auto s = sample_batch(ctx, params.mu, 0x6666u);
    auto x = sample_batch(ctx, params.mu, 0x7777u);

    auto enc = lenc_enc(ctx, s, params.tau, params.gadget_log_base, 0x8888u);
    LOGVOLE_REQUIRE_TRUE(enc) << enc.message();

    auto eval = lenc_eval(ctx, enc.value().lacct, x, params.mu + 1u, params.tau, params.gadget_log_base);
    LOGVOLE_REQUIRE_FALSE(eval);
    LOGVOLE_EXPECT_EQ(eval.error(), comm::protocol_errc::config_error);
}
