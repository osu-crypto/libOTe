#include "logvole/zp_crt_helpers.hpp"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include "parallel_utils.hpp"
#include "simd_hints.hpp"

namespace logvole
{
    namespace
    {
        unsigned __int128 reciprocal_2pow128(std::uint64_t modulus)
        {
            const unsigned __int128 two64 = static_cast<unsigned __int128>(1) << 64;
            const std::uint64_t hi = static_cast<std::uint64_t>(two64 / modulus);
            const std::uint64_t rem = static_cast<std::uint64_t>(two64 % modulus);
            const std::uint64_t lo = static_cast<std::uint64_t>((static_cast<unsigned __int128>(rem) << 64) / modulus);
            return (static_cast<unsigned __int128>(hi) << 64) | lo;
        }

        comm::protocol_result<void> validate_zp_value(
            const zp_crt_context &ctx, std::uint64_t value, const char *name, std::size_t index)
        {
            if (value >= ctx.plaintext_modulus)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error,
                    std::string(name) + "[" + std::to_string(index) + "] must be in Zp");
            }
            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<void> validate_zp_values(
            const zp_crt_context &ctx, const std::vector<std::uint64_t> &values, const char *name)
        {
            for (std::size_t idx = 0; idx < values.size(); ++idx)
            {
                auto ok = validate_zp_value(ctx, values[idx], name, idx);
                if (!ok)
                {
                    return ok;
                }
            }
            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<void> validate_zp_context(const zp_crt_context &ctx)
        {
            if (ctx.plaintext_modulus == 0u)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "Zp plaintext_modulus must be > 0");
            }
            if (ctx.ring.moduli.empty())
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "Zp ring modulus set must be non-empty");
            }
            if (ctx.delta_mod_qj.size() != ctx.ring.moduli.size())
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "Zp delta_mod_qj shape mismatch");
            }
            if (!ctx.batching_context || !ctx.batching_context->first_context_data())
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "Zp batching context is not initialized");
            }
            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<ring_rns_poly> encode_slots_to_ring_crt(
            const zp_crt_context &ctx, const std::vector<std::uint64_t> &slots, seal::BatchEncoder &encoder,
            bool multiply_by_delta, std::uint32_t requested_workers)
        {
            const std::size_t slot_count = zp_slot_count(ctx);
            if (slots.size() != slot_count)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::config_error, "Zp slot vector size must match the batching slot count");
            }

            seal::Plaintext plain;
            try
            {
                encoder.encode(slots, plain);
            }
            catch (const std::exception &ex)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::config_error, std::string("Zp batch encode failed: ") + ex.what());
            }

            const std::size_t rho = ctx.ring.moduli.size();
            ring_rns_poly out{};
            out.coeffs.assign(slot_count * rho, 0u);

            const std::uint64_t *plain_coeffs = plain.data();
            const std::size_t plain_coeff_count = std::min(slot_count, plain.coeff_count());
            std::uint64_t *out_coeffs = out.coeffs.data();

            if (!multiply_by_delta)
            {
                auto copy_status = detail::run_parallel_tasks(
                    rho, requested_workers, [&](std::size_t mod_idx) -> comm::protocol_result<void> {
                        std::copy_n(plain_coeffs, plain_coeff_count, out_coeffs + (mod_idx * slot_count));
                        return comm::protocol_result<void>::success();
                    });
                if (!copy_status)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(copy_status.error(), copy_status.message());
                }
                return comm::protocol_result<ring_rns_poly>::success(std::move(out));
            }

            auto scale_status = detail::run_parallel_tasks(
                rho, requested_workers, [&](std::size_t mod_idx) -> comm::protocol_result<void> {
                    std::uint64_t *limb_coeffs = out_coeffs + (mod_idx * slot_count);
                    const std::uint64_t delta_mod_qj = ctx.delta_mod_qj[mod_idx];
                    const auto &modulus = ctx.ring.moduli[mod_idx];
                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t coeff_idx = 0; coeff_idx < plain_coeff_count; ++coeff_idx)
                    {
                        limb_coeffs[coeff_idx] =
                            seal::util::multiply_uint_mod(plain_coeffs[coeff_idx], delta_mod_qj, modulus);
                    }
                    return comm::protocol_result<void>::success();
                });
            if (!scale_status)
            {
                return comm::protocol_result<ring_rns_poly>::failure(scale_status.error(), scale_status.message());
            }

            return comm::protocol_result<ring_rns_poly>::success(std::move(out));
        }
    } // namespace

    std::size_t zp_slot_count(const zp_crt_context &ctx)
    {
        return ctx.ring.params.poly_modulus_degree;
    }

    std::size_t zp_ring_label_count(const zp_crt_context &ctx, std::size_t zp_label_count)
    {
        const std::size_t slots = zp_slot_count(ctx);
        if (slots == 0u)
        {
            return 0u;
        }
        return (zp_label_count + slots - 1u) / slots;
    }

    comm::protocol_result<zp_crt_context> make_zp_crt_context(
        const ring_params &ring, std::uint32_t plaintext_modulus_bits)
    {
        if (plaintext_modulus_bits == 0u)
        {
            return comm::protocol_result<zp_crt_context>::failure(
                comm::protocol_errc::config_error, "Zp plaintext_modulus_bits must be > 0");
        }

        auto ring_ctx_result = make_ring_ntt_context(ring);
        if (!ring_ctx_result)
        {
            return comm::protocol_result<zp_crt_context>::failure(
                ring_ctx_result.error(), ring_ctx_result.message());
        }

        const auto &ring_ctx = ring_ctx_result.value();
        const auto min_modulus_it = std::min_element(
            ring_ctx.moduli.begin(), ring_ctx.moduli.end(),
            [](const seal::Modulus &lhs, const seal::Modulus &rhs) { return lhs.value() < rhs.value(); });
        if (min_modulus_it == ring_ctx.moduli.end())
        {
            return comm::protocol_result<zp_crt_context>::failure(
                comm::protocol_errc::config_error, "Zp requires non-empty coeff modulus set");
        }

        seal::Modulus batching_plain_modulus{};
        std::uint32_t selected_plaintext_bits = 0u;
        for (std::uint32_t bits = plaintext_modulus_bits; bits >= 2u; --bits)
        {
            try
            {
                auto candidate = seal::PlainModulus::Batching(ring.poly_modulus_degree, bits);
                if (candidate.value() < min_modulus_it->value())
                {
                    batching_plain_modulus = candidate;
                    selected_plaintext_bits = bits;
                    break;
                }
            }
            catch (const std::exception &)
            {}
        }

        if (selected_plaintext_bits == 0u)
        {
            return comm::protocol_result<zp_crt_context>::failure(
                comm::protocol_errc::config_error,
                "failed to find a batching-compatible plaintext modulus below the ring moduli");
        }

        seal::EncryptionParameters batching_params(seal::scheme_type::bgv);
        batching_params.set_poly_modulus_degree(ring.poly_modulus_degree);
        batching_params.set_coeff_modulus(ring_ctx.moduli);
        batching_params.set_plain_modulus(batching_plain_modulus);

        auto batching_context = std::make_shared<seal::SEALContext>(batching_params, true, seal::sec_level_type::none);
        if (!batching_context || !batching_context->first_context_data())
        {
            return comm::protocol_result<zp_crt_context>::failure(
                comm::protocol_errc::config_error, "failed to initialize Zp batching context");
        }

        zp_crt_context out{};
        out.ring = ring_ctx;
        out.plaintext_modulus_bits = selected_plaintext_bits;
        out.plaintext_modulus = batching_plain_modulus.value();
        out.batching_context = std::move(batching_context);
        out.delta_mod_qj.reserve(ring_ctx.moduli.size());

        auto ring_context_data = ring_ctx.context->key_context_data();
        if (!ring_context_data || !ring_context_data->rns_tool() || !ring_context_data->rns_tool()->base_q())
        {
            return comm::protocol_result<zp_crt_context>::failure(
                comm::protocol_errc::config_error, "missing SEAL RNS base data for Zp context");
        }

        const std::size_t rho = ring_ctx.moduli.size();
        auto pool = seal::MemoryManager::GetPool();
        auto numerator = seal::util::allocate_uint(rho, pool);
        seal::util::set_uint(ring_context_data->rns_tool()->base_q()->base_prod(), rho, numerator.get());
        auto denominator = seal::util::allocate_zero_uint(rho, pool);
        denominator[0] = batching_plain_modulus.value();
        auto delta = seal::util::allocate_zero_uint(rho, pool);
        seal::util::divide_uint_inplace(numerator.get(), denominator.get(), rho, delta.get(), pool);

        for (const auto &modulus : ring_ctx.moduli)
        {
            out.delta_mod_qj.push_back(seal::util::modulo_uint(delta.get(), rho, modulus));
        }

        return comm::protocol_result<zp_crt_context>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> wrap_zp_batch_crt(
        const zp_crt_context &ctx, const std::vector<std::uint64_t> &labels, bool multiply_by_delta,
        std::uint64_t pad_value, std::uint32_t requested_workers)
    {
        auto ctx_ok = validate_zp_context(ctx);
        if (!ctx_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(ctx_ok.error(), ctx_ok.message());
        }

        const std::size_t slot_count = zp_slot_count(ctx);
        if (labels.size() > slot_count)
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "Zp batch size exceeds the batching slot count");
        }

        auto labels_ok = validate_zp_values(ctx, labels, "labels");
        if (!labels_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(labels_ok.error(), labels_ok.message());
        }

        auto pad_ok = validate_zp_value(ctx, pad_value, "pad_value", 0u);
        if (!pad_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(pad_ok.error(), pad_ok.message());
        }

        std::vector<std::uint64_t> slots(slot_count, pad_value);
        std::copy(labels.begin(), labels.end(), slots.begin());

        seal::BatchEncoder encoder(*ctx.batching_context);
        return encode_slots_to_ring_crt(ctx, slots, encoder, multiply_by_delta, requested_workers);
    }

    comm::protocol_result<ring_rns_poly> wrap_zp_constant_crt(
        const zp_crt_context &ctx, std::uint64_t value, bool multiply_by_delta, std::uint32_t requested_workers)
    {
        auto ctx_ok = validate_zp_context(ctx);
        if (!ctx_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(ctx_ok.error(), ctx_ok.message());
        }

        auto value_ok = validate_zp_value(ctx, value, "value", 0u);
        if (!value_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(value_ok.error(), value_ok.message());
        }

        std::vector<std::uint64_t> slots(zp_slot_count(ctx), value);
        seal::BatchEncoder encoder(*ctx.batching_context);
        return encode_slots_to_ring_crt(ctx, slots, encoder, multiply_by_delta, requested_workers);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> wrap_zp_labels_crt(
        const zp_crt_context &ctx, const std::vector<std::uint64_t> &labels, bool multiply_by_delta,
        std::uint64_t pad_value, std::uint32_t requested_workers)
    {
        auto ctx_ok = validate_zp_context(ctx);
        if (!ctx_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_ok.error(), ctx_ok.message());
        }

        auto labels_ok = validate_zp_values(ctx, labels, "labels");
        if (!labels_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(labels_ok.error(), labels_ok.message());
        }

        auto pad_ok = validate_zp_value(ctx, pad_value, "pad_value", 0u);
        if (!pad_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(pad_ok.error(), pad_ok.message());
        }

        const std::size_t slot_count = zp_slot_count(ctx);
        const std::size_t chunk_count = zp_ring_label_count(ctx, labels.size());
        std::vector<ring_rns_poly> out(chunk_count);
        auto wrap_status = detail::run_parallel_tasks(
            chunk_count, requested_workers, [&](std::size_t chunk_idx) -> comm::protocol_result<void> {
                const std::size_t offset = chunk_idx * slot_count;
                const std::size_t chunk_size = std::min(slot_count, labels.size() - offset);
                std::vector<std::uint64_t> slots(slot_count, pad_value);
                std::copy_n(labels.data() + offset, chunk_size, slots.begin());

                seal::BatchEncoder encoder(*ctx.batching_context);
                auto wrapped = encode_slots_to_ring_crt(ctx, slots, encoder, multiply_by_delta, 1u);
                if (!wrapped)
                {
                    return comm::protocol_result<void>::failure(wrapped.error(), wrapped.message());
                }
                out[chunk_idx] = std::move(wrapped.value());
                return comm::protocol_result<void>::success();
            });
        if (!wrap_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                wrap_status.error(), wrap_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<std::uint64_t>> unwrap_ring_labels_crt(
        const zp_crt_context &ctx, const std::vector<ring_rns_poly> &labels, std::size_t zp_label_count,
        bool scale_and_round, std::uint32_t requested_workers)
    {
        auto ctx_ok = validate_zp_context(ctx);
        if (!ctx_ok)
        {
            return comm::protocol_result<std::vector<std::uint64_t>>::failure(ctx_ok.error(), ctx_ok.message());
        }

        auto shape_ok = validate_ring_batch_shape(labels, ctx.ring.params, "labels");
        if (!shape_ok)
        {
            return comm::protocol_result<std::vector<std::uint64_t>>::failure(shape_ok.error(), shape_ok.message());
        }

        const std::size_t slot_count = zp_slot_count(ctx);
        if (zp_label_count > labels.size() * slot_count)
        {
            return comm::protocol_result<std::vector<std::uint64_t>>::failure(
                comm::protocol_errc::config_error, "requested Zp label count exceeds encoded ring capacity");
        }

        auto batching_context_data = ctx.batching_context->first_context_data();
        if (!batching_context_data || !batching_context_data->rns_tool())
        {
            return comm::protocol_result<std::vector<std::uint64_t>>::failure(
                comm::protocol_errc::config_error, "missing SEAL RNS tool data for Zp unwrap");
        }
        auto pool = seal::MemoryManager::GetPool();
        auto ring_context_data = ctx.ring.context->key_context_data();
        if (!ring_context_data || !ring_context_data->rns_tool() || !ring_context_data->rns_tool()->base_q())
        {
            return comm::protocol_result<std::vector<std::uint64_t>>::failure(
                comm::protocol_errc::config_error, "missing SEAL ring RNS tool data for Zp unwrap");
        }

        const auto &plain_modulus = batching_context_data->parms().plain_modulus();
        const std::uint64_t plain_modulus_value = plain_modulus.value();
        const std::size_t n = ctx.ring.params.poly_modulus_degree;
        const std::size_t rho = ctx.ring.moduli.size();
        seal::util::RNSBase full_base(ring_context_data->parms().coeff_modulus(), pool);
        auto inv_punct_prod = full_base.inv_punctured_prod_mod_base_array();
        std::vector<std::uint64_t> crt_inv_punctured(rho, 0u);
        std::vector<std::uint64_t> q_i(rho, 0u);
        std::vector<unsigned __int128> frac_inv_modulus(rho, 0u);
        for (std::size_t mod_idx = 0; mod_idx < rho; ++mod_idx)
        {
            q_i[mod_idx] = full_base.base()[mod_idx].value();
            crt_inv_punctured[mod_idx] = inv_punct_prod[mod_idx].operand;
            frac_inv_modulus[mod_idx] = reciprocal_2pow128(q_i[mod_idx]);
        }
        const unsigned __int128 half = static_cast<unsigned __int128>(1) << 127;

        const std::uint64_t *const crt_inv_punctured_data = crt_inv_punctured.data();
        const std::uint64_t *const q_i_data = q_i.data();
        const unsigned __int128 *const frac_inv_modulus_data = frac_inv_modulus.data();
        const std::size_t chunk_count = zp_ring_label_count(ctx, zp_label_count);
        std::vector<std::vector<std::uint64_t>> decoded_chunks(chunk_count);
        auto unwrap_status = detail::run_parallel_tasks(
            chunk_count, requested_workers, [&](std::size_t label_idx) -> comm::protocol_result<void> {
                ring_rns_poly canonical = labels[label_idx];
                auto canonical_ok = canonicalize_poly_inplace(canonical, ctx.ring);
                if (!canonical_ok)
                {
                    return comm::protocol_result<void>::failure(canonical_ok.error(), canonical_ok.message());
                }

                seal::Plaintext plain;
                plain.resize(slot_count);

                if (scale_and_round)
                {
                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t coeff_idx = 0; coeff_idx < slot_count; ++coeff_idx)
                    {
                        std::uint64_t scaled_coeff = 0u;
                        unsigned __int128 frac_sum = half;
                        LOGVOLE_PRAGMA_UNROLL
                        for (std::size_t mod_idx = 0; mod_idx < rho; ++mod_idx)
                        {
                            const std::uint64_t v_i = canonical.coeffs[mod_idx * slot_count + coeff_idx];
                            const std::uint64_t x_i = seal::util::multiply_uint_mod(
                                v_i, crt_inv_punctured_data[mod_idx], ctx.ring.moduli[mod_idx]);

                            const unsigned __int128 scaled_numerator =
                                static_cast<unsigned __int128>(x_i) * plain_modulus_value;
                            std::uint64_t scaled_words[2] = { static_cast<std::uint64_t>(scaled_numerator),
                                                              static_cast<std::uint64_t>(scaled_numerator >> 64u) };
                            std::uint64_t quotient_words[2] = { 0u, 0u };
                            seal::util::divide_uint128_inplace(scaled_words, q_i_data[mod_idx], quotient_words);

                            scaled_coeff += quotient_words[0];
                            if (scaled_coeff >= plain_modulus_value)
                            {
                                scaled_coeff -= plain_modulus_value;
                            }

                            const unsigned __int128 term =
                                static_cast<unsigned __int128>(scaled_words[0]) * frac_inv_modulus_data[mod_idx];
                            const unsigned __int128 old_frac = frac_sum;
                            frac_sum += term;
                            if (frac_sum < old_frac)
                            {
                                ++scaled_coeff;
                                if (scaled_coeff == plain_modulus_value)
                                {
                                    scaled_coeff = 0u;
                                }
                            }
                        }
                        plain[coeff_idx] = scaled_coeff;
                    }
                }
                else
                {
                    auto composed_local = seal::util::allocate_poly(n, rho, pool);
                    std::copy(canonical.coeffs.begin(), canonical.coeffs.end(), composed_local.get());
                    ring_context_data->rns_tool()->base_q()->compose_array(composed_local.get(), n, pool);

                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t coeff_idx = 0; coeff_idx < slot_count; ++coeff_idx)
                    {
                        plain[coeff_idx] =
                            seal::util::modulo_uint(composed_local.get() + (coeff_idx * rho), rho, plain_modulus);
                    }
                }

                std::vector<std::uint64_t> slots;
                try
                {
                    seal::BatchEncoder encoder(*ctx.batching_context);
                    encoder.decode(plain, slots);
                }
                catch (const std::exception &ex)
                {
                    return comm::protocol_result<void>::failure(
                        comm::protocol_errc::config_error, std::string("Zp batch decode failed: ") + ex.what());
                }

                const std::size_t offset = label_idx * slot_count;
                const std::size_t remaining = zp_label_count - offset;
                const std::size_t copy_count = std::min(remaining, slots.size());
                decoded_chunks[label_idx].assign(slots.begin(), slots.begin() + copy_count);
                return comm::protocol_result<void>::success();
            });
        if (!unwrap_status)
        {
            return comm::protocol_result<std::vector<std::uint64_t>>::failure(
                unwrap_status.error(), unwrap_status.message());
        }

        std::vector<std::uint64_t> out;
        out.reserve(zp_label_count);
        for (auto &chunk : decoded_chunks)
        {
            out.insert(out.end(), chunk.begin(), chunk.end());
        }
        return comm::protocol_result<std::vector<std::uint64_t>>::success(std::move(out));
    }
} // namespace logvole
