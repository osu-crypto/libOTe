#include "seal/util/clipnormal.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "loglabel/ring_ops.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <random>
#include <string>
#include <tuple>
#include <utility>

namespace loglabel
{
    namespace
    {
        bool is_power_of_two(std::uint32_t value)
        {
            return value > 0 && (value & (value - 1u)) == 0u;
        }

        comm::protocol_result<void> validate_shape_against_context(
            const ring_rns_poly &poly, const ring_ntt_context &ctx)
        {
            const std::size_t expected_size = ring_poly_coeff_count(ctx.params);
            if (poly.coeffs.size() != expected_size)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "ring polynomial shape does not match context parameters");
            }
            return comm::protocol_result<void>::success();
        }

        std::uint64_t combine_seed(std::uint64_t value)
        {
            value += 0x9E3779B97F4A7C15ull;
            value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ull;
            value = (value ^ (value >> 27u)) * 0x94D049BB133111EBull;
            return value ^ (value >> 31u);
        }

        std::uint64_t base_pow_mod(std::uint64_t base, std::uint32_t exp, std::uint64_t mod)
        {
            seal::Modulus modulus(mod);
            std::uint64_t result = 1u;
            std::uint64_t power = base % mod;
            std::uint32_t e = exp;
            while (e > 0u)
            {
                if ((e & 1u) != 0u)
                {
                    result = seal::util::multiply_uint_mod(result, power, modulus);
                }
                power = seal::util::multiply_uint_mod(power, power, modulus);
                e >>= 1u;
            }
            return result;
        }

        std::uint64_t add_mod(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t mod)
        {
            const std::uint64_t sum = lhs + rhs;
            return (sum >= mod) ? (sum - mod) : sum;
        }

        void sample_poly_normal(
            std::shared_ptr<seal::UniformRandomGenerator> prng, const seal::EncryptionParameters &parms,
            uint64_t *destination, double noise_standard_deviation, double noise_max_deviation)
        {
            auto &coeff_modulus = parms.coeff_modulus();
            std::size_t coeff_modulus_size = coeff_modulus.size();
            std::size_t coeff_count = parms.poly_modulus_degree();

            seal::RandomToStandardAdapter engine(prng);
            seal::util::ClippedNormalDistribution dist(0, noise_standard_deviation, noise_max_deviation);

            SEAL_ITERATE(seal::util::iter(destination), coeff_count, [&](auto &I) {
                int64_t noise = static_cast<int64_t>(dist(engine));
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
                SEAL_ITERATE(
                    seal::util::iter(seal::util::StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus),
                    coeff_modulus_size, [&](auto J) {
                        *::std::get<0>(J) = static_cast<uint64_t>(noise) + (flag & ::std::get<1>(J).value());
                    });
            });
        }

    } // namespace

    comm::protocol_result<void> validate_ring_params(const ring_params &params)
    {
        if (!is_power_of_two(params.poly_modulus_degree) || params.poly_modulus_degree < 1024u)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error,
                "poly_modulus_degree must be a power-of-two >= 1024 for SEAL context validity");
        }

        if (params.coeff_modulus_bits.empty())
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "coeff_modulus_bits cannot be empty");
        }

        if (params.coeff_modulus_bits.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "coeff_modulus_bits size exceeds uint32 range");
        }

        for (std::size_t i = 0; i < params.coeff_modulus_bits.size(); ++i)
        {
            const int bits = params.coeff_modulus_bits[i];
            if (bits < 2 || bits > 60)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "coeff_modulus_bits entries must be in [2, 60]");
            }
        }

        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> validate_ring_poly_shape(
        const ring_rns_poly &poly, const ring_params &params, const char *name)
    {
        const std::size_t expected_size = ring_poly_coeff_count(params);
        if (poly.coeffs.size() != expected_size)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, std::string(name) + " has unexpected coefficient count");
        }
        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> validate_ring_batch_shape(
        const std::vector<ring_rns_poly> &polys, const ring_params &params, const char *name)
    {
        for (std::size_t i = 0; i < polys.size(); ++i)
        {
            auto valid = validate_ring_poly_shape(polys[i], params, name);
            if (!valid)
            {
                return comm::protocol_result<void>::failure(
                    valid.error(), std::string(name) + "[" + std::to_string(i) + "]: " + valid.message());
            }
        }
        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<ring_ntt_context> make_ring_ntt_context(const ring_params &params)
    {
        auto params_ok = validate_ring_params(params);
        if (!params_ok)
        {
            return comm::protocol_result<ring_ntt_context>::failure(params_ok.error(), params_ok.message());
        }

        std::vector<seal::Modulus> moduli;
        try
        {
            moduli = seal::CoeffModulus::Create(params.poly_modulus_degree, params.coeff_modulus_bits);
        }
        catch (const std::exception &ex)
        {
            return comm::protocol_result<ring_ntt_context>::failure(
                comm::protocol_errc::config_error, std::string("failed to create coeff modulus: ") + ex.what());
        }

        if (moduli.size() != params.coeff_modulus_bits.size())
        {
            return comm::protocol_result<ring_ntt_context>::failure(
                comm::protocol_errc::config_error, "unexpected coeff modulus count created from coeff_modulus_bits");
        }

        ring_ntt_context out{};
        out.params = params;
        out.moduli = moduli;

        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(params.poly_modulus_degree);
        parms.set_coeff_modulus(moduli);

        out.context = std::make_shared<seal::SEALContext>(parms, true, seal::sec_level_type::none);
        if (!out.context || !out.context->key_context_data())
        {
            return comm::protocol_result<ring_ntt_context>::failure(
                comm::protocol_errc::config_error, "failed to derive SEAL context data for ring params");
        }

        if (out.context->key_context_data()->parms().coeff_modulus().size() != params.coeff_modulus_bits.size())
        {
            return comm::protocol_result<ring_ntt_context>::failure(
                comm::protocol_errc::config_error, "SEAL context coefficient modulus count does not match ring params");
        }

        return comm::protocol_result<ring_ntt_context>::success(std::move(out));
    }

    comm::protocol_result<void> canonicalize_poly_inplace(ring_rns_poly &poly, const ring_ntt_context &ctx)
    {
        auto shape_ok = validate_shape_against_context(poly, ctx);
        if (!shape_ok)
        {
            return shape_ok;
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                poly.coeffs[offset + i] %= mod;
            }
        }

        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> forward_ntt_inplace(ring_rns_poly &poly, const ring_ntt_context &ctx)
    {
        auto canonical = canonicalize_poly_inplace(poly, ctx);
        if (!canonical)
        {
            return canonical;
        }

        const auto &tables = ctx.context->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            seal::util::ntt_negacyclic_harvey(poly.coeffs.data() + (mod_idx * n), tables[mod_idx]);
        }

        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> inverse_ntt_inplace(ring_rns_poly &poly, const ring_ntt_context &ctx)
    {
        auto shape_ok = validate_shape_against_context(poly, ctx);
        if (!shape_ok)
        {
            return shape_ok;
        }

        const auto &tables = ctx.context->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            seal::util::inverse_ntt_negacyclic_harvey(poly.coeffs.data() + (mod_idx * n), tables[mod_idx]);
        }

        return canonicalize_poly_inplace(poly, ctx);
    }

    comm::protocol_result<ring_rns_poly> dyadic_multiply_add_ntt(
        const ring_rns_poly &a_ntt, const ring_rns_poly &b_ntt, const ring_rns_poly &c_ntt, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a_ntt, ctx);
        if (!a_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(a_ok.error(), a_ok.message());
        }

        auto b_ok = validate_shape_against_context(b_ntt, ctx);
        if (!b_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(b_ok.error(), b_ok.message());
        }

        auto c_ok = validate_shape_against_context(c_ntt, ctx);
        if (!c_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(c_ok.error(), c_ok.message());
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        ring_rns_poly out{};
        out.coeffs.resize(a_ntt.coeffs.size(), 0u);

        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const auto &modulus = ctx.moduli[mod_idx];
            const std::uint64_t mod = modulus.value();
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t index = offset + i;
                const std::uint64_t mul_mod =
                    seal::util::multiply_uint_mod(a_ntt.coeffs[index] % mod, b_ntt.coeffs[index] % mod, modulus);
                out.coeffs[index] = add_mod(mul_mod, c_ntt.coeffs[index], mod);
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> ring_add(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(a_ok.error(), a_ok.message());
        }

        auto b_ok = validate_shape_against_context(b, ctx);
        if (!b_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(b_ok.error(), b_ok.message());
        }

        ring_rns_poly out{};
        out.coeffs.resize(a.coeffs.size(), 0u);

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                out.coeffs[idx] = add_mod(a.coeffs[idx], b.coeffs[idx], mod);
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> ring_sub(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(a_ok.error(), a_ok.message());
        }

        auto b_ok = validate_shape_against_context(b, ctx);
        if (!b_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(b_ok.error(), b_ok.message());
        }

        ring_rns_poly out{};
        out.coeffs.resize(a.coeffs.size(), 0u);

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                const std::uint64_t av = a.coeffs[idx] % mod;
                const std::uint64_t bv = b.coeffs[idx] % mod;
                out.coeffs[idx] = (av >= bv) ? (av - bv) : static_cast<std::uint64_t>(mod - (bv - av));
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> ring_multiply(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(a_ok.error(), a_ok.message());
        }

        auto b_ok = validate_shape_against_context(b, ctx);
        if (!b_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(b_ok.error(), b_ok.message());
        }

        ring_rns_poly a_ntt = a;
        ring_rns_poly b_ntt = b;

        auto a_ntt_ok = forward_ntt_inplace(a_ntt, ctx);
        if (!a_ntt_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(a_ntt_ok.error(), a_ntt_ok.message());
        }

        auto b_ntt_ok = forward_ntt_inplace(b_ntt, ctx);
        if (!b_ntt_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(b_ntt_ok.error(), b_ntt_ok.message());
        }

        ring_rns_poly zero{};
        zero.coeffs.assign(a_ntt.coeffs.size(), 0u);
        auto product_ntt = dyadic_multiply_add_ntt(a_ntt, b_ntt, zero, ctx);
        if (!product_ntt)
        {
            return product_ntt;
        }

        auto intt_ok = inverse_ntt_inplace(product_ntt.value(), ctx);
        if (!intt_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(intt_ok.error(), intt_ok.message());
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(product_ntt.value()));
    }

    comm::protocol_result<ring_rns_poly> ring_multiply_scalar(
        const ring_rns_poly &a, std::uint64_t scalar, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(a_ok.error(), a_ok.message());
        }

        ring_rns_poly out = a;
        const std::size_t n = ctx.params.poly_modulus_degree;

        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const auto &modulus = ctx.moduli[mod_idx];
            const std::uint64_t mod = modulus.value();
            const std::uint64_t scalar_mod = scalar % mod;
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                out.coeffs[idx] = seal::util::multiply_uint_mod(out.coeffs[idx] % mod, scalar_mod, modulus);
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose(
        const ring_rns_poly &poly, std::uint32_t base, std::uint32_t tau, const ring_ntt_context &ctx)
    {
        if (base < 2u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gadget base must be >= 2");
        }

        if (tau == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gadget tau must be > 0");
        }

        auto shape_ok = validate_shape_against_context(poly, ctx);
        if (!shape_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(shape_ok.error(), shape_ok.message());
        }

        ring_rns_poly canonical = poly;
        auto canonical_ok = canonicalize_poly_inplace(canonical, ctx);
        if (!canonical_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                canonical_ok.error(), canonical_ok.message());
        }

        std::vector<ring_rns_poly> out;
        out.resize(tau);
        for (auto &digit : out)
        {
            digit.coeffs.assign(canonical.coeffs.size(), 0u);
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        const std::uint64_t base_u64 = static_cast<std::uint64_t>(base);

        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;

            for (std::size_t i = 0; i < n; ++i)
            {
                std::uint64_t value = canonical.coeffs[offset + i] % mod;
                for (std::uint32_t j = 0; j < tau; ++j)
                {
                    const std::uint64_t digit = value % base_u64;
                    out[j].coeffs[offset + i] = digit;
                    value /= base_u64;
                }
            }
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> gadget_recompose(
        const std::vector<ring_rns_poly> &digits, std::uint32_t base, const ring_ntt_context &ctx)
    {
        if (digits.empty())
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "gadget digits cannot be empty");
        }

        if (base < 2u)
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "gadget base must be >= 2");
        }

        for (std::size_t i = 0; i < digits.size(); ++i)
        {
            auto shape_ok = validate_shape_against_context(digits[i], ctx);
            if (!shape_ok)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    shape_ok.error(), "gadget digit[" + std::to_string(i) + "] invalid shape");
            }
        }

        ring_rns_poly out{};
        out.coeffs.assign(digits[0].coeffs.size(), 0u);

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;

            std::vector<std::uint64_t> base_pows(digits.size(), 1u);
            for (std::size_t j = 0; j < digits.size(); ++j)
            {
                base_pows[j] = base_pow_mod(static_cast<std::uint64_t>(base), static_cast<std::uint32_t>(j), mod);
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                std::uint64_t acc = 0u;
                for (std::size_t j = 0; j < digits.size(); ++j)
                {
                    const std::uint64_t term = seal::util::multiply_uint_mod(
                        digits[j].coeffs[offset + i] % mod, base_pows[j], ctx.moduli[mod_idx]);
                    acc = add_mod(acc, term, mod);
                }
                out.coeffs[offset + i] = acc;
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t levels, const ring_ntt_context &ctx)
    {
        if (digit_bits == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gadget digit_bits must be > 0");
        }

        if (levels == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gadget levels must be > 0");
        }

        auto shape_ok = validate_shape_against_context(poly, ctx);
        if (!shape_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(shape_ok.error(), shape_ok.message());
        }

        ring_rns_poly canonical = poly;
        auto canonical_ok = canonicalize_poly_inplace(canonical, ctx);
        if (!canonical_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                canonical_ok.error(), canonical_ok.message());
        }

        std::vector<ring_rns_poly> out(levels);
        for (auto &digit : out)
        {
            digit.coeffs.assign(canonical.coeffs.size(), 0u);
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        const std::size_t coeff_mod_count = ctx.moduli.size();
        auto context_data = ctx.context->key_context_data();
        if (!context_data)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "missing SEAL context data");
        }

        seal::util::Pointer<std::uint64_t> composed_poly =
            seal::util::allocate_poly(n, coeff_mod_count, seal::MemoryManager::GetPool());

        // SEAL RNS compose requires the input buffer to be in normal SEAL poly format (coeff_count inner, prime outer)
        // Wait, seal::util::RNSBase::compose_array requires poly in standard SEAL layout.
        // Our layout is exactly standard SEAL layout: (coeff_count for prime 0) followed by (coeff_count for prime
        // 1)...
        std::copy(canonical.coeffs.begin(), canonical.coeffs.end(), composed_poly.get());

        // Compose to RNS BigInt
        context_data->rns_tool()->base_q()->compose_array(composed_poly.get(), n, seal::MemoryManager::GetPool());

        auto temp_mpi = seal::util::allocate_uint(coeff_mod_count, seal::MemoryManager::GetPool());

        for (std::size_t i = 0; i < n; ++i)
        {
            std::uint64_t *val_ptr = composed_poly.get() + i * coeff_mod_count;

            for (std::uint32_t level = 0; level < levels; ++level)
            {
                // Extract digit_bits into temp_mpi
                seal::util::set_uint(val_ptr, coeff_mod_count, temp_mpi.get());

                // We want to keep only digit_bits in temp_mpi. All higher bits should be 0.
                // digit_bits can be larger than 64.
                for (std::size_t w = 0; w < coeff_mod_count; ++w)
                {
                    std::uint32_t bit_offset = w * 64;
                    if (bit_offset >= digit_bits)
                    {
                        temp_mpi[w] = 0;
                    }
                    else if (bit_offset + 64 > digit_bits)
                    {
                        std::uint32_t remaining_bits = digit_bits - bit_offset;
                        std::uint64_t mask = (static_cast<std::uint64_t>(1u) << remaining_bits) - 1u;
                        temp_mpi[w] &= mask;
                    }
                }

                // We must then convert temp_mpi (the digit) back to RNS for all primes and save in out[level][i]
                for (std::size_t mod_idx = 0; mod_idx < coeff_mod_count; ++mod_idx)
                {
                    out[level].coeffs[mod_idx * n + i] =
                        seal::util::modulo_uint(temp_mpi.get(), coeff_mod_count, ctx.moduli[mod_idx]);
                }

                // Shift val_ptr right by digit_bits
                seal::util::right_shift_uint(val_ptr, digit_bits, coeff_mod_count, val_ptr);
            }
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> gadget_recompose_bits(
        const std::vector<ring_rns_poly> &digits, std::uint32_t digit_bits, const ring_ntt_context &ctx)
    {
        if (digits.empty())
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "gadget digits cannot be empty");
        }

        if (digit_bits == 0u)
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "gadget digit_bits must be > 0");
        }

        for (std::size_t i = 0; i < digits.size(); ++i)
        {
            auto shape_ok = validate_shape_against_context(digits[i], ctx);
            if (!shape_ok)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    shape_ok.error(), "gadget digit[" + std::to_string(i) + "] invalid shape");
            }
        }

        ring_rns_poly out{};
        out.coeffs.assign(digits[0].coeffs.size(), 0u);

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;

            std::vector<std::uint64_t> pow2_shifts(digits.size(), 0u);
            for (std::size_t level = 0; level < digits.size(); ++level)
            {
                const std::uint64_t shift_u64 =
                    static_cast<std::uint64_t>(level) * static_cast<std::uint64_t>(digit_bits);
                if (shift_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
                {
                    return comm::protocol_result<ring_rns_poly>::failure(
                        comm::protocol_errc::config_error, "gadget level*digit_bits exceeds supported exponent range");
                }
                pow2_shifts[level] = base_pow_mod(2u, static_cast<std::uint32_t>(shift_u64), mod);
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                std::uint64_t acc = 0u;
                for (std::size_t level = 0; level < digits.size(); ++level)
                {
                    const std::uint64_t term = seal::util::multiply_uint_mod(
                        digits[level].coeffs[offset + i] % mod, pow2_shifts[level], ctx.moduli[mod_idx]);
                    acc = add_mod(acc, term, mod);
                }
                out.coeffs[offset + i] = acc;
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    std::vector<std::uint64_t> pack_ring_batch(const std::vector<ring_rns_poly> &polys)
    {
        std::size_t total = 0;
        for (const auto &poly : polys)
        {
            total += poly.coeffs.size();
        }

        std::vector<std::uint64_t> out;
        out.reserve(total);
        for (const auto &poly : polys)
        {
            out.insert(out.end(), poly.coeffs.begin(), poly.coeffs.end());
        }

        return out;
    }

    comm::protocol_result<std::vector<ring_rns_poly>> unpack_ring_batch(
        std::uint32_t count, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name)
    {
        if (count == 0u || poly_modulus_degree == 0u || coeff_modulus_count == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::decode_validation_failure,
                std::string(field_name) + " metadata cannot contain zeros");
        }

        const std::size_t per_poly = static_cast<std::size_t>(poly_modulus_degree) * coeff_modulus_count;
        if (count > std::numeric_limits<std::size_t>::max() / per_poly)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::decode_validation_failure, std::string(field_name) + " metadata overflow");
        }

        const std::size_t expected = static_cast<std::size_t>(count) * per_poly;
        if (flat.size() != expected)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::decode_validation_failure,
                std::string(field_name) + " payload size does not match metadata");
        }

        std::vector<ring_rns_poly> out;
        out.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto begin = flat.begin() + static_cast<std::ptrdiff_t>(i * per_poly);
            const auto end = begin + static_cast<std::ptrdiff_t>(per_poly);
            out.push_back(ring_rns_poly{ std::vector<std::uint64_t>(begin, end) });
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    std::vector<std::uint64_t> pack_ring_tensor(const ring_tensor &tensor)
    {
        return pack_ring_batch(tensor.polys);
    }

    comm::protocol_result<ring_tensor> unpack_ring_tensor(
        std::uint32_t rows, std::uint32_t cols, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name)
    {
        if (rows == 0u || cols == 0u)
        {
            return comm::protocol_result<ring_tensor>::failure(
                comm::protocol_errc::decode_validation_failure,
                std::string(field_name) + " rows/cols must be non-zero");
        }

        if (rows > std::numeric_limits<std::uint32_t>::max() / cols)
        {
            return comm::protocol_result<ring_tensor>::failure(
                comm::protocol_errc::decode_validation_failure, std::string(field_name) + " tensor shape overflow");
        }

        const std::uint32_t count = rows * cols;
        auto unpacked = unpack_ring_batch(count, poly_modulus_degree, coeff_modulus_count, flat, field_name);
        if (!unpacked)
        {
            return comm::protocol_result<ring_tensor>::failure(unpacked.error(), unpacked.message());
        }

        ring_tensor tensor{};
        tensor.rows = rows;
        tensor.cols = cols;
        tensor.polys = std::move(unpacked.value());
        return comm::protocol_result<ring_tensor>::success(std::move(tensor));
    }

    ring_rns_poly derive_uniform_poly_from_nonce(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t index)
    {
        const std::uint64_t raw_seed = combine_seed(nonce) ^ combine_seed(domain_tag) ^ combine_seed(index) ^
                                       combine_seed(ctx.params.poly_modulus_degree) ^
                                       combine_seed(static_cast<std::uint64_t>(ctx.params.coeff_modulus_bits.size()));

        std::mt19937_64 rng(raw_seed);

        ring_rns_poly out{};
        out.coeffs.resize(ring_poly_coeff_count(ctx.params), 0u);

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            std::uniform_int_distribution<std::uint64_t> dist(0u, mod - 1u);
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                out.coeffs[offset + i] = dist(rng);
            }
        }

        return out;
    }

    comm::protocol_result<void> add_gaussian_noise_inplace(
        ring_rns_poly &poly, double noise_standard_deviation, double noise_max_deviation, std::uint64_t seed,
        std::uint64_t stream_id, const ring_ntt_context &ctx)
    {
        if (noise_standard_deviation < 0)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "noise_standard_deviation cannot be negative");
        }

        auto canonical = canonicalize_poly_inplace(poly, ctx);
        if (!canonical)
        {
            return canonical;
        }

        const std::uint64_t raw_seed = combine_seed(seed) ^ combine_seed(stream_id);
        std::shared_ptr<seal::UniformRandomGenerator> prng =
            seal::UniformRandomGeneratorFactory::DefaultFactory()->create({ raw_seed, 0 });
        seal::RandomToStandardAdapter engine(prng);
        seal::util::ClippedNormalDistribution dist(0, noise_standard_deviation, noise_max_deviation);

        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                const std::int64_t noise = static_cast<std::int64_t>(dist(engine));
                const std::uint64_t value = poly.coeffs[idx] % mod;
                if (noise >= 0)
                {
                    poly.coeffs[idx] = add_mod(value, static_cast<std::uint64_t>(noise), mod);
                }
                else
                {
                    const std::uint64_t abs_noise = static_cast<std::uint64_t>(-noise) % mod;
                    poly.coeffs[idx] = (value >= abs_noise) ? static_cast<std::uint64_t>(value - abs_noise)
                                                            : static_cast<std::uint64_t>(mod - (abs_noise - value));
                }
            }
        }

        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> add_poly_error(
        ring_rns_poly &poly, double noise_standard_deviation, double noise_max_deviation, std::uint64_t seed,
        std::uint64_t stream_id, const ring_ntt_context &ctx)
    {
        if (noise_standard_deviation < 0)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "noise_standard_deviation cannot be negative");
        }

        auto canonical = canonicalize_poly_inplace(poly, ctx);
        if (!canonical)
        {
            return canonical;
        }

        const std::uint64_t raw_seed = combine_seed(seed) ^ combine_seed(stream_id);
        std::shared_ptr<seal::UniformRandomGenerator> prng =
            seal::UniformRandomGeneratorFactory::DefaultFactory()->create({ raw_seed, 0 });

        auto context_data_ptr = ctx.context->key_context_data();
        if (!context_data_ptr)
        {
            return comm::protocol_result<void>::failure(comm::protocol_errc::config_error, "missing SEAL context data");
        }
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        std::size_t coeff_count = parms.poly_modulus_degree();

        seal::util::Pointer<uint64_t> temp =
            seal::util::allocate_poly(coeff_count, coeff_modulus_size, seal::MemoryManager::GetPool());
        seal::util::RNSIter temp_iter(temp.get(), coeff_count);

        sample_poly_normal(prng, parms, temp.get(), noise_standard_deviation, noise_max_deviation);

        seal::util::PolyIter destination_iter(poly.coeffs.data(), coeff_count, coeff_modulus_size);
        seal::util::add_poly_coeffmod(
            destination_iter[0], temp_iter, coeff_modulus_size, coeff_modulus, destination_iter[0]);

        return comm::protocol_result<void>::success();
    }

} // namespace loglabel
