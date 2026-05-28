#include "loglabel/ring_ops.hpp"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>

using namespace loglabel;

namespace
{
    ring_params make_params()
    {
        ring_params params{};
        params.poly_modulus_degree = 1024;
        params.coeff_modulus_bits = { 30, 30 };
        return params;
    }

    void expect_poly_equal(const ring_rns_poly &a, const ring_rns_poly &b)
    {
        LOGVOLE_REQUIRE_EQ(a.coeffs.size(), b.coeffs.size());
        for (std::size_t i = 0; i < a.coeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.coeffs[i], b.coeffs[i]) << "coeff index " << i;
        }
    }

} // namespace

void LogVole_RingOps_NttRoundTrip(const oc::CLP&)
{
    const auto params = make_params();
    auto ctx_result = make_ring_ntt_context(params);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    ring_rns_poly poly = derive_uniform_poly_from_nonce(ctx, 0x1234u, 0x5678u, 0);
    ring_rns_poly expected = poly;

    auto canonical_ok = canonicalize_poly_inplace(expected, ctx);
    LOGVOLE_REQUIRE_TRUE(canonical_ok) << canonical_ok.message();

    auto fwd_ok = forward_ntt_inplace(poly, ctx);
    LOGVOLE_REQUIRE_TRUE(fwd_ok) << fwd_ok.message();

    auto inv_ok = inverse_ntt_inplace(poly, ctx);
    LOGVOLE_REQUIRE_TRUE(inv_ok) << inv_ok.message();

    expect_poly_equal(poly, expected);
}

void LogVole_RingOps_GadgetDecomposeRecompose(const oc::CLP&)
{
    const auto params = make_params();
    auto ctx_result = make_ring_ntt_context(params);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    ring_rns_poly poly = derive_uniform_poly_from_nonce(ctx, 0x55AAu, 0xCCDDu, 0);

    auto digits = gadget_decompose(poly, /*base=*/(1u << 10u), /*tau=*/4u, ctx);
    LOGVOLE_REQUIRE_TRUE(digits) << digits.message();
    LOGVOLE_REQUIRE_EQ(digits.value().size(), 4u);

    auto recomposed = gadget_recompose(digits.value(), /*base=*/(1u << 10u), ctx);
    LOGVOLE_REQUIRE_TRUE(recomposed) << recomposed.message();

    auto canonical_poly = canonicalize_poly_inplace(poly, ctx);
    LOGVOLE_REQUIRE_TRUE(canonical_poly) << canonical_poly.message();

    auto canonical_recomposed = canonicalize_poly_inplace(recomposed.value(), ctx);
    LOGVOLE_REQUIRE_TRUE(canonical_recomposed) << canonical_recomposed.message();

    expect_poly_equal(poly, recomposed.value());
}

void LogVole_RingOps_GadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_params();
    auto ctx_result = make_ring_ntt_context(params);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    ring_rns_poly poly = derive_uniform_poly_from_nonce(ctx, 0xAA55u, 0x11EEu, 0);

    auto digits = gadget_decompose_bits(poly, /*digit_bits=*/20u, /*levels=*/4u, ctx);
    LOGVOLE_REQUIRE_TRUE(digits) << digits.message();
    LOGVOLE_REQUIRE_EQ(digits.value().size(), 4u);

    auto recomposed = gadget_recompose_bits(digits.value(), /*digit_bits=*/20u, ctx);
    LOGVOLE_REQUIRE_TRUE(recomposed) << recomposed.message();

    auto canonical_poly = canonicalize_poly_inplace(poly, ctx);
    LOGVOLE_REQUIRE_TRUE(canonical_poly) << canonical_poly.message();

    auto canonical_recomposed = canonicalize_poly_inplace(recomposed.value(), ctx);
    LOGVOLE_REQUIRE_TRUE(canonical_recomposed) << canonical_recomposed.message();

    expect_poly_equal(poly, recomposed.value());
}

void LogVole_RingOps_TensorPackUnpack(const oc::CLP&)
{
    const auto params = make_params();
    auto ctx_result = make_ring_ntt_context(params);
    LOGVOLE_REQUIRE_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    ring_tensor tensor{};
    tensor.rows = 2;
    tensor.cols = 3;
    for (std::uint32_t i = 0; i < tensor.rows * tensor.cols; ++i)
    {
        tensor.polys.push_back(derive_uniform_poly_from_nonce(ctx, 0x77u, 0x99u, i));
    }

    auto packed = pack_ring_tensor(tensor);
    auto unpacked = unpack_ring_tensor(
        tensor.rows,
        tensor.cols,
        params.poly_modulus_degree,
        static_cast<std::uint32_t>(params.coeff_modulus_bits.size()),
        packed,
        "tensor");

    LOGVOLE_REQUIRE_TRUE(unpacked) << unpacked.message();
    LOGVOLE_REQUIRE_EQ(unpacked.value().rows, tensor.rows);
    LOGVOLE_REQUIRE_EQ(unpacked.value().cols, tensor.cols);
    LOGVOLE_REQUIRE_EQ(unpacked.value().polys.size(), tensor.polys.size());

    for (std::size_t i = 0; i < tensor.polys.size(); ++i)
    {
        expect_poly_equal(tensor.polys[i], unpacked.value().polys[i]);
    }
}
