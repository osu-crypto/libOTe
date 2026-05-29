#include "seal/util/clipnormal.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include "logvole/ring_ops.hpp"
#include "logvole/shrinkexpand_types.hpp"
#include <algorithm>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <exception>
#include <limits>
#include <random>
#include <string>
#include <tuple>
#include <utility>
#include "parallel_utils.hpp"
#include "simd_hints.hpp"

namespace logvole
{
    namespace
    {
        using boost::multiprecision::cpp_int;

        constexpr std::uint64_t k_noise_family_domain = 0x4E4F495345F10001ull;
        constexpr std::uint64_t k_ct2_family_domain = 0x435432F100010001ull;
        constexpr std::uint64_t k_seed_bytes_domain = 0x5345454442595445ull;

        bool is_power_of_two(std::uint32_t value)
        {
            return value > 0 && (value & (value - 1u)) == 0u;
        }

        cpp_int limbs_to_cpp_int(const std::uint64_t *limbs, std::size_t limb_count)
        {
            cpp_int value = 0;
            for (std::size_t limb_idx = limb_count; limb_idx > 0u; --limb_idx)
            {
                value <<= 64u;
                value += limbs[limb_idx - 1u];
            }
            return value;
        }

        std::uint64_t cpp_int_mod_u64(const cpp_int &value, std::uint64_t modulus)
        {
            cpp_int reduced = value % modulus;
            if (reduced < 0)
            {
                reduced += modulus;
            }
            return static_cast<std::uint64_t>(reduced);
        }

        std::uint64_t extract_u64_window(const std::uint64_t *limbs, std::size_t limb_count, std::uint64_t start_bit)
        {
            const std::size_t word_index = static_cast<std::size_t>(start_bit >> 6u);
            const std::uint32_t bit_offset = static_cast<std::uint32_t>(start_bit & 63u);
            if (word_index >= limb_count)
            {
                return 0u;
            }

            std::uint64_t value = limbs[word_index] >> bit_offset;
            if (bit_offset != 0u && (word_index + 1u) < limb_count)
            {
                value |= limbs[word_index + 1u] << (64u - bit_offset);
            }
            return value;
        }

#if defined(__SIZEOF_INT128__)
        using uint128 = unsigned __int128;
        using int128 = __int128_t;

        uint128 lower_bits_mask_u128(std::uint32_t bit_count)
        {
            if (bit_count >= 128u)
            {
                return ~static_cast<uint128>(0u);
            }
            return (static_cast<uint128>(1u) << bit_count) - 1u;
        }

        uint128 extract_bits_u128(
            const std::uint64_t *limbs, std::size_t limb_count, std::uint64_t start_bit, std::uint32_t bit_count)
        {
            if (bit_count == 0u)
            {
                return 0u;
            }

            uint128 value = static_cast<uint128>(extract_u64_window(limbs, limb_count, start_bit));
            if (bit_count > 64u && start_bit <= (std::numeric_limits<std::uint64_t>::max() - 64u))
            {
                value |= static_cast<uint128>(extract_u64_window(limbs, limb_count, start_bit + 64u)) << 64u;
            }
            return value & lower_bits_mask_u128(bit_count);
        }

        comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits_range_centered_fast(
            const ring_rns_poly &canonical, std::uint32_t digit_bits, std::uint32_t start_level, std::uint32_t levels,
            const ring_ntt_context &ctx)
        {
            if (digit_bits > 126u)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "fast centered gadget decomposition requires digit_bits <= 126");
            }

            const std::uint64_t total_levels = static_cast<std::uint64_t>(start_level) + levels;
            if (total_levels == 0u)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "gadget levels must be > 0");
            }
            if ((total_levels - 1u) >
                (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(digit_bits)))
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "gadget decomposition shift exceeds supported range");
            }

            std::vector<ring_rns_poly> out(levels);
            for (auto &digit : out)
            {
                digit.coeffs.assign(canonical.coeffs.size(), 0u);
            }

            const std::size_t n = ctx.params.poly_modulus_degree;
            const std::size_t coeff_mod_count = ctx.moduli.size();
            const seal::Modulus *moduli = ctx.moduli.data();
            auto context_data = ctx.context->key_context_data();
            if (!context_data)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "missing SEAL context data");
            }

            auto pool = seal::MemoryManager::GetPool();
            seal::util::Pointer<std::uint64_t> composed_poly = seal::util::allocate_poly(n, coeff_mod_count, pool);
            std::copy(canonical.coeffs.begin(), canonical.coeffs.end(), composed_poly.get());
            context_data->rns_tool()->base_q()->compose_array(composed_poly.get(), n, pool);

            const std::uint64_t *q_limbs = context_data->rns_tool()->base_q()->base_prod();
            auto q_half = seal::util::allocate_uint(coeff_mod_count, pool);
            seal::util::set_uint(q_limbs, coeff_mod_count, q_half.get());
            seal::util::right_shift_uint(q_half.get(), 1, coeff_mod_count, q_half.get());

            std::vector<std::uint64_t> modulus_values(coeff_mod_count, 0u);
            std::vector<std::size_t> modulus_offsets(coeff_mod_count, 0u);
            for (std::size_t mod_idx = 0u; mod_idx < coeff_mod_count; ++mod_idx)
            {
                modulus_values[mod_idx] = ctx.moduli[mod_idx].value();
                modulus_offsets[mod_idx] = mod_idx * n;
            }

            std::vector<std::uint64_t *> out_coeffs(levels, nullptr);
            for (std::size_t level_idx = 0u; level_idx < levels; ++level_idx)
            {
                out_coeffs[level_idx] = out[level_idx].coeffs.data();
            }

            std::vector<uint128> q_digits(static_cast<std::size_t>(total_levels), 0u);
            for (std::uint64_t level = 0u; level < total_levels; ++level)
            {
                const std::uint64_t shift_bits = level * static_cast<std::uint64_t>(digit_bits);
                q_digits[static_cast<std::size_t>(level)] =
                    extract_bits_u128(q_limbs, coeff_mod_count, shift_bits, digit_bits);
            }

            const int128 base = static_cast<int128>(static_cast<uint128>(1u) << digit_bits);
            const int128 half_base = static_cast<int128>(static_cast<uint128>(1u) << (digit_bits - 1u));
            const auto total_levels_u32 = static_cast<std::uint32_t>(total_levels);

            LOGVOLE_PRAGMA_IVDEP
            for (std::size_t coeff_idx = 0u; coeff_idx < n; ++coeff_idx)
            {
                const std::uint64_t *coeff_limbs = composed_poly.get() + (coeff_idx * coeff_mod_count);
                const bool negative = seal::util::is_greater_than_uint(coeff_limbs, q_half.get(), coeff_mod_count);
                int carry = 0;

                for (std::uint32_t level = 0u; level < total_levels_u32; ++level)
                {
                    const std::uint64_t shift_bits =
                        static_cast<std::uint64_t>(level) * static_cast<std::uint64_t>(digit_bits);
                    int128 digit =
                        static_cast<int128>(extract_bits_u128(coeff_limbs, coeff_mod_count, shift_bits, digit_bits));
                    if (negative)
                    {
                        digit -= static_cast<int128>(q_digits[static_cast<std::size_t>(level)]);
                    }
                    digit += carry;

                    int128 centered_digit = digit;
                    if (centered_digit >= half_base)
                    {
                        centered_digit -= base;
                        carry = 1;
                    }
                    else if (centered_digit < -half_base)
                    {
                        centered_digit += base;
                        carry = -1;
                    }
                    else
                    {
                        carry = 0;
                    }

                    if (level < start_level)
                    {
                        continue;
                    }

                    const std::size_t out_level = static_cast<std::size_t>(level - start_level);
                    std::uint64_t *level_out_coeffs = out_coeffs[out_level];
                    const bool is_negative_digit = centered_digit < 0;
                    const uint128 magnitude =
                        static_cast<uint128>(is_negative_digit ? -centered_digit : centered_digit);
                    const std::uint64_t mag_lo = static_cast<std::uint64_t>(magnitude);
                    const std::uint64_t mag_hi = static_cast<std::uint64_t>(magnitude >> 64u);
                    const std::uint64_t magnitude_words[2] = { mag_lo, mag_hi };

                    for (std::size_t mod_idx = 0u; mod_idx < coeff_mod_count; ++mod_idx)
                    {
                        const std::uint64_t qi = modulus_values[mod_idx];
                        std::uint64_t rem = 0u;
                        if (mag_hi == 0u)
                        {
                            rem = seal::util::barrett_reduce_64(mag_lo, moduli[mod_idx]);
                        }
                        else
                        {
                            rem = seal::util::barrett_reduce_128(magnitude_words, moduli[mod_idx]);
                        }

                        if (is_negative_digit && rem != 0u)
                        {
                            rem = qi - rem;
                        }

                        level_out_coeffs[modulus_offsets[mod_idx] + coeff_idx] = rem;
                    }
                }
            }

            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }
#endif

        comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits_range_centered_slow(
            const ring_rns_poly &canonical, std::uint32_t digit_bits, std::uint32_t start_level, std::uint32_t levels,
            const ring_ntt_context &ctx)
        {
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
            std::copy(canonical.coeffs.begin(), canonical.coeffs.end(), composed_poly.get());
            context_data->rns_tool()->base_q()->compose_array(composed_poly.get(), n, seal::MemoryManager::GetPool());

            cpp_int q = 1;
            for (const auto &modulus : ctx.moduli)
            {
                q *= modulus.value();
            }
            const cpp_int q_half = q >> 1u;
            const cpp_int base = cpp_int(1) << digit_bits;
            const cpp_int half_base = cpp_int(1) << (digit_bits - 1u);
            const cpp_int digit_mask = base - 1;

            for (std::size_t coeff_idx = 0u; coeff_idx < n; ++coeff_idx)
            {
                cpp_int value = limbs_to_cpp_int(composed_poly.get() + (coeff_idx * coeff_mod_count), coeff_mod_count);
                if (value > q_half)
                {
                    value -= q;
                }

                for (std::uint32_t level = 0u; level < (start_level + levels); ++level)
                {
                    cpp_int digit = value & digit_mask;
                    value >>= digit_bits;
                    if (digit >= half_base)
                    {
                        digit -= base;
                        value += 1;
                    }

                    if (level < start_level)
                    {
                        continue;
                    }

                    const std::size_t out_level = static_cast<std::size_t>(level - start_level);
                    for (std::size_t mod_idx = 0; mod_idx < coeff_mod_count; ++mod_idx)
                    {
                        out[out_level].coeffs[mod_idx * n + coeff_idx] =
                            cpp_int_mod_u64(digit, ctx.moduli[mod_idx].value());
                    }
                }
            }

            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
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

        std::uint64_t base_pow_mod(std::uint64_t base, std::uint32_t exp, std::uint64_t mod)
        {
            std::uint64_t result = 1u;
            std::uint64_t power = base % mod;
            std::uint32_t e = exp;
            while (e > 0u)
            {
                if ((e & 1u) != 0u)
                {
                    const auto mul = static_cast<unsigned __int128>(result) * power;
                    result = static_cast<std::uint64_t>(mul % mod);
                }
                const auto sq = static_cast<unsigned __int128>(power) * power;
                power = static_cast<std::uint64_t>(sq % mod);
                e >>= 1u;
            }
            return result;
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

        std::shared_ptr<seal::UniformRandomGeneratorFactory> poly_sampling_prng_factory()
        {
#ifdef SEAL_USE_AES_CTR_DRBG
            static const auto factory = std::make_shared<seal::AesCtrDrbgPRNGFactory>();
#else
            static const auto factory = seal::UniformRandomGeneratorFactory::DefaultFactory();
#endif
            return factory;
        }

        struct pending_ring_ops_stats
        {
            std::uint64_t epoch = 0u;
            bool epoch_initialized = false;
            std::uint64_t ntt_count = 0u;
            std::uint64_t intt_count = 0u;
            std::uint64_t add_count = 0u;
            std::uint64_t sub_count = 0u;
            std::uint64_t mul_count = 0u;
            std::uint64_t mul_scalar_count = 0u;
            std::uint64_t dyadic_mul_add_count = 0u;
            std::uint64_t gadget_decompose_count = 0u;
            std::uint64_t gadget_recompose_count = 0u;
            std::uint64_t prng_poly_count = 0u;
            std::uint64_t error_add_count = 0u;

            void clear()
            {
                ntt_count = 0u;
                intt_count = 0u;
                add_count = 0u;
                sub_count = 0u;
                mul_count = 0u;
                mul_scalar_count = 0u;
                dyadic_mul_add_count = 0u;
                gadget_decompose_count = 0u;
                gadget_recompose_count = 0u;
                prng_poly_count = 0u;
                error_add_count = 0u;
            }

            void sync_epoch()
            {
                const std::uint64_t global_epoch = ring_ops_stats::reset_epoch.load(std::memory_order_relaxed);
                if (!epoch_initialized)
                {
                    epoch = global_epoch;
                    epoch_initialized = true;
                    return;
                }

                if (epoch != global_epoch)
                {
                    clear();
                    epoch = global_epoch;
                }
            }

            void flush()
            {
                if (ntt_count != 0u)
                {
                    global_ring_ops_stats.ntt_count.fetch_add(ntt_count, std::memory_order_relaxed);
                    ntt_count = 0u;
                }
                if (intt_count != 0u)
                {
                    global_ring_ops_stats.intt_count.fetch_add(intt_count, std::memory_order_relaxed);
                    intt_count = 0u;
                }
                if (add_count != 0u)
                {
                    global_ring_ops_stats.add_count.fetch_add(add_count, std::memory_order_relaxed);
                    add_count = 0u;
                }
                if (sub_count != 0u)
                {
                    global_ring_ops_stats.sub_count.fetch_add(sub_count, std::memory_order_relaxed);
                    sub_count = 0u;
                }
                if (mul_count != 0u)
                {
                    global_ring_ops_stats.mul_count.fetch_add(mul_count, std::memory_order_relaxed);
                    mul_count = 0u;
                }
                if (mul_scalar_count != 0u)
                {
                    global_ring_ops_stats.mul_scalar_count.fetch_add(mul_scalar_count, std::memory_order_relaxed);
                    mul_scalar_count = 0u;
                }
                if (dyadic_mul_add_count != 0u)
                {
                    global_ring_ops_stats.dyadic_mul_add_count.fetch_add(
                        dyadic_mul_add_count, std::memory_order_relaxed);
                    dyadic_mul_add_count = 0u;
                }
                if (gadget_decompose_count != 0u)
                {
                    global_ring_ops_stats.gadget_decompose_count.fetch_add(
                        gadget_decompose_count, std::memory_order_relaxed);
                    gadget_decompose_count = 0u;
                }
                if (gadget_recompose_count != 0u)
                {
                    global_ring_ops_stats.gadget_recompose_count.fetch_add(
                        gadget_recompose_count, std::memory_order_relaxed);
                    gadget_recompose_count = 0u;
                }
                if (prng_poly_count != 0u)
                {
                    global_ring_ops_stats.prng_poly_count.fetch_add(prng_poly_count, std::memory_order_relaxed);
                    prng_poly_count = 0u;
                }
                if (error_add_count != 0u)
                {
                    global_ring_ops_stats.error_add_count.fetch_add(error_add_count, std::memory_order_relaxed);
                    error_add_count = 0u;
                }
            }

            ~pending_ring_ops_stats()
            {
                flush();
            }
        };

        thread_local pending_ring_ops_stats tls_ring_ops_stats{};

        inline void bump_ring_stat(std::atomic<std::uint64_t> &global, std::uint64_t &local)
        {
            constexpr std::uint64_t flush_threshold = 256u;
            tls_ring_ops_stats.sync_epoch();
            ++local;
            if (local >= flush_threshold)
            {
                global.fetch_add(local, std::memory_order_relaxed);
                local = 0u;
            }
        }

    } // namespace

    void flush_ring_ops_thread_local_stats()
    {
        tls_ring_ops_stats.sync_epoch();
        tls_ring_ops_stats.flush();
    }

    std::uint64_t combine_seed_public(std::uint64_t value)
    {
        value += 0x9E3779B97F4A7C15ull;
        value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ull;
        value = (value ^ (value >> 27u)) * 0x94D049BB133111EBull;
        return value ^ (value >> 31u);
    }

    std::uint64_t derive_deterministic_seed_material(
        std::uint64_t root, std::uint64_t domain_tag, std::uint64_t value0, std::uint64_t value1, std::uint64_t value2,
        std::uint64_t value3)
    {
        std::uint64_t mixed = combine_seed_public(root);
        mixed = combine_seed_public(mixed ^ combine_seed_public(domain_tag));
        mixed = combine_seed_public(mixed ^ combine_seed_public(value0));
        mixed = combine_seed_public(mixed ^ combine_seed_public(value1));
        mixed = combine_seed_public(mixed ^ combine_seed_public(value2));
        mixed = combine_seed_public(mixed ^ combine_seed_public(value3));
        return mixed;
    }

    std::uint64_t derive_noise_seed(
        const sampling_seed_config &config, std::uint64_t domain_tag, std::uint64_t stream_id, std::uint64_t salt0,
        std::uint64_t salt1)
    {
        return derive_deterministic_seed_material(
            config.noise_root, domain_tag ^ k_noise_family_domain, stream_id, salt0, salt1, 0u);
    }

    std::uint64_t derive_ct2_nonce(
        const sampling_seed_config &config, std::uint64_t nonce, std::uint64_t coeff_count)
    {
        return derive_deterministic_seed_material(
            config.ct2_root, 0xC720AA55ull ^ k_ct2_family_domain, nonce, coeff_count, 0u, 0u);
    }

    std::uint64_t derive_seed_instance_nonce(
        const sampling_seed_config &config, const std::vector<std::uint8_t> &seed, std::uint64_t instance_idx,
        std::uint64_t fallback_nonce)
    {
        std::uint64_t mixed_seed = derive_deterministic_seed_material(
            config.ct2_root, k_seed_bytes_domain, fallback_nonce, seed.size(), 0u, 0u);
        constexpr std::size_t chunk_bytes = sizeof(std::uint64_t);
        for (std::size_t offset = 0u, chunk_idx = 0u; offset < seed.size(); offset += chunk_bytes, ++chunk_idx)
        {
            std::uint64_t chunk = 0u;
            const std::size_t available = std::min(chunk_bytes, seed.size() - offset);
            std::memcpy(&chunk, seed.data() + offset, available);
            const std::uint64_t chunk_tag =
                derive_deterministic_seed_material(config.ct2_root, k_seed_bytes_domain, chunk_idx, 0u, 0u, 0u);
            mixed_seed = combine_seed_public(mixed_seed ^ combine_seed_public(chunk ^ chunk_tag));
        }

        return derive_deterministic_seed_material(
            config.ct2_root, 0xC720AA55ull ^ k_ct2_family_domain, mixed_seed, instance_idx, fallback_nonce, 0u);
    }

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
        parms.set_random_generator(poly_sampling_prng_factory());

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
        seal::util::PolyIter poly_iter(poly.coeffs.data(), n, ctx.moduli.size());
        seal::util::modulo_poly_coeffs(poly_iter[0], ctx.moduli.size(), ctx.moduli, poly_iter[0]);

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

        bump_ring_stat(global_ring_ops_stats.ntt_count, tls_ring_ops_stats.ntt_count);

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

        bump_ring_stat(global_ring_ops_stats.intt_count, tls_ring_ops_stats.intt_count);

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

        seal::util::PolyIter a_iter(const_cast<std::uint64_t *>(a_ntt.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter b_iter(const_cast<std::uint64_t *>(b_ntt.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter c_iter(const_cast<std::uint64_t *>(c_ntt.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter out_iter(out.coeffs.data(), n, ctx.moduli.size());

        seal::util::dyadic_product_coeffmod(a_iter[0], b_iter[0], ctx.moduli.size(), ctx.moduli, out_iter[0]);
        seal::util::add_poly_coeffmod(out_iter[0], c_iter[0], ctx.moduli.size(), ctx.moduli, out_iter[0]);

        bump_ring_stat(global_ring_ops_stats.dyadic_mul_add_count, tls_ring_ops_stats.dyadic_mul_add_count);

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<void> dyadic_multiply_add_ntt_inplace(
        const ring_rns_poly &a_ntt, const ring_rns_poly &b_ntt, ring_rns_poly &c_ntt, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a_ntt, ctx);
        if (!a_ok)
            return a_ok;

        auto b_ok = validate_shape_against_context(b_ntt, ctx);
        if (!b_ok)
            return b_ok;

        auto c_ok = validate_shape_against_context(c_ntt, ctx);
        if (!c_ok)
            return c_ok;

        const std::size_t n = ctx.params.poly_modulus_degree;
        seal::util::PolyIter a_iter(const_cast<std::uint64_t *>(a_ntt.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter b_iter(const_cast<std::uint64_t *>(b_ntt.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter c_iter(c_ntt.coeffs.data(), n, ctx.moduli.size());

        auto pool = seal::MemoryManager::GetPool();
        auto temp = seal::util::allocate_poly(n, ctx.moduli.size(), pool);
        seal::util::PolyIter temp_iter(temp.get(), n, ctx.moduli.size());

        seal::util::dyadic_product_coeffmod(a_iter[0], b_iter[0], ctx.moduli.size(), ctx.moduli, temp_iter[0]);
        seal::util::add_poly_coeffmod(temp_iter[0], c_iter[0], ctx.moduli.size(), ctx.moduli, c_iter[0]);

        bump_ring_stat(global_ring_ops_stats.dyadic_mul_add_count, tls_ring_ops_stats.dyadic_mul_add_count);

        return comm::protocol_result<void>::success();
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
        seal::util::PolyIter a_iter(const_cast<std::uint64_t *>(a.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter b_iter(const_cast<std::uint64_t *>(b.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter out_iter(out.coeffs.data(), n, ctx.moduli.size());

        seal::util::add_poly_coeffmod(a_iter[0], b_iter[0], ctx.moduli.size(), ctx.moduli, out_iter[0]);

        bump_ring_stat(global_ring_ops_stats.add_count, tls_ring_ops_stats.add_count);

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<void> ring_add_inplace(ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return a_ok;
        }

        auto b_ok = validate_shape_against_context(b, ctx);
        if (!b_ok)
        {
            return b_ok;
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        seal::util::PolyIter a_iter(a.coeffs.data(), n, ctx.moduli.size());
        seal::util::PolyIter b_iter(const_cast<std::uint64_t *>(b.coeffs.data()), n, ctx.moduli.size());

        seal::util::add_poly_coeffmod(a_iter[0], b_iter[0], ctx.moduli.size(), ctx.moduli, a_iter[0]);

        bump_ring_stat(global_ring_ops_stats.add_count, tls_ring_ops_stats.add_count);

        return comm::protocol_result<void>::success();
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
        seal::util::PolyIter a_iter(const_cast<std::uint64_t *>(a.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter b_iter(const_cast<std::uint64_t *>(b.coeffs.data()), n, ctx.moduli.size());
        seal::util::PolyIter out_iter(out.coeffs.data(), n, ctx.moduli.size());

        seal::util::sub_poly_coeffmod(a_iter[0], b_iter[0], ctx.moduli.size(), ctx.moduli, out_iter[0]);

        bump_ring_stat(global_ring_ops_stats.sub_count, tls_ring_ops_stats.sub_count);

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<void> ring_sub_inplace(ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return a_ok;
        }

        auto b_ok = validate_shape_against_context(b, ctx);
        if (!b_ok)
        {
            return b_ok;
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        seal::util::PolyIter a_iter(a.coeffs.data(), n, ctx.moduli.size());
        seal::util::PolyIter b_iter(const_cast<std::uint64_t *>(b.coeffs.data()), n, ctx.moduli.size());

        seal::util::sub_poly_coeffmod(a_iter[0], b_iter[0], ctx.moduli.size(), ctx.moduli, a_iter[0]);

        bump_ring_stat(global_ring_ops_stats.sub_count, tls_ring_ops_stats.sub_count);

        return comm::protocol_result<void>::success();
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

        bump_ring_stat(global_ring_ops_stats.mul_count, tls_ring_ops_stats.mul_count);

        return comm::protocol_result<ring_rns_poly>::success(std::move(product_ntt.value()));
    }

    comm::protocol_result<void> ring_multiply_inplace(
        ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
            return a_ok;

        auto b_ok = validate_shape_against_context(b, ctx);
        if (!b_ok)
            return b_ok;

        auto a_ntt_ok = forward_ntt_inplace(a, ctx);
        if (!a_ntt_ok)
            return a_ntt_ok;

        ring_rns_poly b_ntt = b;
        auto b_ntt_ok = forward_ntt_inplace(b_ntt, ctx);
        if (!b_ntt_ok)
            return b_ntt_ok;

        ring_rns_poly zero{};
        zero.coeffs.assign(a.coeffs.size(), 0u);
        auto res = dyadic_multiply_add_ntt_inplace(a, b_ntt, zero, ctx);
        if (!res)
            return res;

        a = std::move(zero);
        auto intt_ok = inverse_ntt_inplace(a, ctx);
        if (!intt_ok)
            return intt_ok;

        bump_ring_stat(global_ring_ops_stats.mul_count, tls_ring_ops_stats.mul_count);
        return comm::protocol_result<void>::success();
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

        seal::util::PolyIter out_iter(out.coeffs.data(), n, ctx.moduli.size());

        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            auto mod = ctx.moduli[mod_idx];
            seal::util::multiply_poly_scalar_coeffmod(out_iter[0][mod_idx], n, scalar, mod, out_iter[0][mod_idx]);
        }

        bump_ring_stat(global_ring_ops_stats.mul_scalar_count, tls_ring_ops_stats.mul_scalar_count);

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<void> ring_multiply_scalar_inplace(
        ring_rns_poly &a, std::uint64_t scalar, const ring_ntt_context &ctx)
    {
        auto a_ok = validate_shape_against_context(a, ctx);
        if (!a_ok)
        {
            return a_ok;
        }

        const std::size_t n = ctx.params.poly_modulus_degree;

        seal::util::PolyIter a_iter(a.coeffs.data(), n, ctx.moduli.size());

        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            auto mod = ctx.moduli[mod_idx];
            seal::util::multiply_poly_scalar_coeffmod(a_iter[0][mod_idx], n, scalar, mod, a_iter[0][mod_idx]);
        }

        bump_ring_stat(global_ring_ops_stats.mul_scalar_count, tls_ring_ops_stats.mul_scalar_count);

        return comm::protocol_result<void>::success();
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

        bump_ring_stat(global_ring_ops_stats.gadget_decompose_count, tls_ring_ops_stats.gadget_decompose_count);

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
                    const auto term_mul =
                        static_cast<unsigned __int128>(digits[j].coeffs[offset + i] % mod) * base_pows[j];
                    const std::uint64_t term = static_cast<std::uint64_t>(term_mul % mod);
                    acc = static_cast<std::uint64_t>((static_cast<unsigned __int128>(acc) + term) % mod);
                }
                out.coeffs[offset + i] = acc;
            }
        }

        bump_ring_stat(global_ring_ops_stats.gadget_recompose_count, tls_ring_ops_stats.gadget_recompose_count);

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits_range(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t start_level, std::uint32_t levels,
        const ring_ntt_context &ctx, std::uint32_t requested_workers)
    {
        static_cast<void>(requested_workers);

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
        const std::size_t full_words =
            std::min<std::size_t>(coeff_mod_count, static_cast<std::size_t>(digit_bits / 64u));
        const std::uint32_t tail_bits = digit_bits & 63u;
        const bool has_tail_word = (tail_bits != 0u) && (full_words < coeff_mod_count);
        const std::uint64_t tail_mask = tail_bits == 0u ? std::numeric_limits<std::uint64_t>::max()
                                                        : ((static_cast<std::uint64_t>(1u) << tail_bits) - 1u);
        const std::size_t zero_start = full_words + (has_tail_word ? 1u : 0u);
        auto context_data = ctx.context->key_context_data();
        if (!context_data)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "missing SEAL context data");
        }

        seal::util::Pointer<std::uint64_t> composed_poly =
            seal::util::allocate_poly(n, coeff_mod_count, seal::MemoryManager::GetPool());

        std::copy(canonical.coeffs.begin(), canonical.coeffs.end(), composed_poly.get());

        // Compose to RNS BigInt
        context_data->rns_tool()->base_q()->compose_array(composed_poly.get(), n, seal::MemoryManager::GetPool());

        const std::uint64_t total_shift_bits =
            static_cast<std::uint64_t>(digit_bits) * static_cast<std::uint64_t>(start_level);
        if (total_shift_bits > static_cast<std::uint64_t>(std::numeric_limits<unsigned int>::max()))
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gadget decomposition shift exceeds supported range");
        }

        for (std::size_t coeff_idx = 0u; coeff_idx < n; ++coeff_idx)
        {
            std::uint64_t *val_ptr = composed_poly.get() + (coeff_idx * coeff_mod_count);
            seal::util::right_shift_uint(
                val_ptr, static_cast<unsigned int>(total_shift_bits), coeff_mod_count, val_ptr);
        }

        seal::util::Pointer<std::uint64_t> level_composed =
            seal::util::allocate_poly(n, coeff_mod_count, seal::MemoryManager::GetPool());

        for (std::uint32_t level = 0; level < levels; ++level)
        {
            for (std::size_t coeff_idx = 0u; coeff_idx < n; ++coeff_idx)
            {
                std::uint64_t *val_ptr = composed_poly.get() + (coeff_idx * coeff_mod_count);
                std::uint64_t *dest_ptr = level_composed.get() + (coeff_idx * coeff_mod_count);

                std::copy_n(val_ptr, coeff_mod_count, dest_ptr);
                if (has_tail_word)
                {
                    dest_ptr[full_words] &= tail_mask;
                }
                if (zero_start < coeff_mod_count)
                {
                    std::fill(dest_ptr + zero_start, dest_ptr + coeff_mod_count, std::uint64_t{ 0u });
                }

                if (level + 1u < levels)
                {
                    seal::util::right_shift_uint(val_ptr, digit_bits, coeff_mod_count, val_ptr);
                }
            }

            context_data->rns_tool()->base_q()->decompose_array(
                level_composed.get(), n, seal::MemoryManager::GetPool());

            std::copy(level_composed.get(), level_composed.get() + n * coeff_mod_count, out[level].coeffs.begin());
        }

        bump_ring_stat(global_ring_ops_stats.gadget_decompose_count, tls_ring_ops_stats.gadget_decompose_count);

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t levels, const ring_ntt_context &ctx,
        std::uint32_t requested_workers)
    {
        return gadget_decompose_bits_range(poly, digit_bits, 0u, levels, ctx, requested_workers);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits_range_centered(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t start_level, std::uint32_t levels,
        const ring_ntt_context &ctx, std::uint32_t requested_workers)
    {
        static_cast<void>(requested_workers);

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

#if defined(__SIZEOF_INT128__)
        comm::protocol_result<std::vector<ring_rns_poly>> result =
            digit_bits <= 126u
                ? gadget_decompose_bits_range_centered_fast(canonical, digit_bits, start_level, levels, ctx)
                : gadget_decompose_bits_range_centered_slow(canonical, digit_bits, start_level, levels, ctx);
#else
        comm::protocol_result<std::vector<ring_rns_poly>> result =
            gadget_decompose_bits_range_centered_slow(canonical, digit_bits, start_level, levels, ctx);
#endif
        if (!result)
        {
            return result;
        }

        bump_ring_stat(global_ring_ops_stats.gadget_decompose_count, tls_ring_ops_stats.gadget_decompose_count);

        return result;
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

            seal::util::PolyIter out_iter(out.coeffs.data(), n, ctx.moduli.size());

            for (std::size_t level = 0; level < digits.size(); ++level)
            {
                const std::uint64_t shift_u64 =
                    static_cast<std::uint64_t>(level) * static_cast<std::uint64_t>(digit_bits);
                if (shift_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
                {
                    return comm::protocol_result<ring_rns_poly>::failure(
                        comm::protocol_errc::config_error, "gadget level*digit_bits exceeds supported exponent range");
                }

                seal::util::PolyIter digit_iter(
                    const_cast<std::uint64_t *>(digits[level].coeffs.data()), n, ctx.moduli.size());

                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    std::uint64_t pow2_shift =
                        base_pow_mod(2u, static_cast<std::uint32_t>(shift_u64), ctx.moduli[mod_idx].value());

                    if (level == 0)
                    {
                        seal::util::multiply_poly_scalar_coeffmod(
                            digit_iter[0][mod_idx], n, pow2_shift, ctx.moduli[mod_idx], out_iter[0][mod_idx]);
                    }
                    else
                    {
                        // Temporary buffer for the multiplied digit
                        std::vector<std::uint64_t> temp(n);
                        seal::util::multiply_poly_scalar_coeffmod(
                            digit_iter[0][mod_idx], n, pow2_shift, ctx.moduli[mod_idx], temp.data());
                        seal::util::add_poly_coeffmod(
                            out_iter[0][mod_idx], temp.data(), n, ctx.moduli[mod_idx], out_iter[0][mod_idx]);
                    }
                }
            }
        }

        bump_ring_stat(global_ring_ops_stats.gadget_recompose_count, tls_ring_ops_stats.gadget_recompose_count);

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
        const std::vector<std::uint64_t> &flat, const char *field_name, std::uint32_t requested_workers)
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

        std::vector<ring_rns_poly> out(count);
        auto unpack_status =
            detail::run_parallel_tasks(static_cast<std::size_t>(count), requested_workers, [&](std::size_t i) {
                const auto begin = flat.begin() + static_cast<std::ptrdiff_t>(i * per_poly);
                const auto end = begin + static_cast<std::ptrdiff_t>(per_poly);
                out[i].coeffs.assign(begin, end);
                return comm::protocol_result<void>::success();
            });
        if (!unpack_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                unpack_status.error(), unpack_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    std::vector<std::uint64_t> pack_ring_tensor(const ring_tensor &tensor)
    {
        return pack_ring_batch(tensor.polys);
    }

    comm::protocol_result<ring_tensor> unpack_ring_tensor(
        std::uint32_t rows, std::uint32_t cols, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name, std::uint32_t requested_workers)
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
        auto unpacked =
            unpack_ring_batch(count, poly_modulus_degree, coeff_modulus_count, flat, field_name, requested_workers);
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

    namespace
    {
        std::shared_ptr<seal::UniformRandomGenerator> make_batch_poly_prng(
            const std::shared_ptr<seal::UniformRandomGeneratorFactory> &prng_factory, std::uint64_t raw_seed,
            std::uint32_t poly_index)
        {
            // Domain-separate each polynomial stream so every worker can sample independently.
            const std::uint64_t mixed_index =
                combine_seed_public(static_cast<std::uint64_t>(poly_index) ^ 0xD1B54A32D192ED03ull);
            const std::uint64_t seed_lo = combine_seed_public(raw_seed ^ mixed_index ^ 0xB47C11A5ull);
            const std::uint64_t seed_hi = combine_seed_public(raw_seed + mixed_index + 0x94D049BB133111EBull);
            return prng_factory->create({ seed_lo, seed_hi });
        }

        std::vector<ring_rns_poly> sample_uniform_batch_from_raw_seed(
            const ring_ntt_context &ctx, std::uint64_t raw_seed, std::uint32_t count)
        {
            std::vector<ring_rns_poly> out;
            if (count == 0u)
            {
                return out;
            }

            const std::size_t per_poly_coeff_count = ring_poly_coeff_count(ctx.params);
            out.resize(count);
            for (auto &poly : out)
            {
                poly.coeffs.resize(per_poly_coeff_count);
            }

            static const auto prng_factory = poly_sampling_prng_factory();
            const std::uint32_t requested_workers = (count >= 8u) ? 0u : 1u;

            if (ctx.context)
            {
                auto context_data = ctx.context->key_context_data();
                if (context_data)
                {
                    auto sample_status = detail::run_parallel_tasks(
                        static_cast<std::size_t>(count), requested_workers,
                        [&](std::size_t task_idx) -> comm::protocol_result<void> {
                            auto prng =
                                make_batch_poly_prng(prng_factory, raw_seed, static_cast<std::uint32_t>(task_idx));
                            seal::util::sample_poly_uniform(prng, context_data->parms(), out[task_idx].coeffs.data());
                            bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                            return comm::protocol_result<void>::success();
                        });
                    if (!sample_status)
                    {
                        for (std::size_t i = 0; i < static_cast<std::size_t>(count); ++i)
                        {
                            auto prng = make_batch_poly_prng(prng_factory, raw_seed, static_cast<std::uint32_t>(i));
                            seal::util::sample_poly_uniform(prng, context_data->parms(), out[i].coeffs.data());
                            bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                        }
                    }
                    return out;
                }
            }

            // Fallback to slower sampling if context is not available.
            const std::size_t n = ctx.params.poly_modulus_degree;
            auto sample_status = detail::run_parallel_tasks(
                static_cast<std::size_t>(count), requested_workers,
                [&](std::size_t task_idx) -> comm::protocol_result<void> {
                    auto prng = make_batch_poly_prng(prng_factory, raw_seed, static_cast<std::uint32_t>(task_idx));
                    seal::RandomToStandardAdapter rng(prng);
                    auto &poly = out[task_idx];
                    for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                    {
                        const std::uint64_t mod = ctx.moduli[mod_idx].value();
                        std::uniform_int_distribution<std::uint64_t> dist(0u, mod - 1u);
                        const std::size_t offset = mod_idx * n;
                        for (std::size_t i = 0; i < n; ++i)
                        {
                            poly.coeffs[offset + i] = dist(rng);
                        }
                    }
                    bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                    return comm::protocol_result<void>::success();
                });
            if (!sample_status)
            {
                for (std::size_t task_idx = 0; task_idx < static_cast<std::size_t>(count); ++task_idx)
                {
                    auto prng = make_batch_poly_prng(prng_factory, raw_seed, static_cast<std::uint32_t>(task_idx));
                    seal::RandomToStandardAdapter rng(prng);
                    auto &poly = out[task_idx];
                    for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                    {
                        const std::uint64_t mod = ctx.moduli[mod_idx].value();
                        std::uniform_int_distribution<std::uint64_t> dist(0u, mod - 1u);
                        const std::size_t offset = mod_idx * n;
                        for (std::size_t i = 0; i < n; ++i)
                        {
                            poly.coeffs[offset + i] = dist(rng);
                        }
                    }
                    bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                }
            }

            return out;
        }

    } // namespace

    ring_rns_poly derive_uniform_poly_from_nonce(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t index)
    {
        auto_timer total_sampling_timer(global_timing_stats.seed_sampling_time_us);
        auto_timer poly_sampling_timer(global_timing_stats.poly_sampling_time_us);
        const std::uint64_t mixed_nonce = combine_seed_public(nonce);
        const std::uint64_t mixed_domain = combine_seed_public(domain_tag);
        const std::uint64_t mixed_index = combine_seed_public(static_cast<std::uint64_t>(index));
        const std::uint64_t mixed_n = combine_seed_public(static_cast<std::uint64_t>(ctx.params.poly_modulus_degree));
        const std::uint64_t mixed_rho =
            combine_seed_public(static_cast<std::uint64_t>(ctx.params.coeff_modulus_bits.size()));
        const std::uint64_t raw_seed = mixed_nonce ^ mixed_domain ^ mixed_index ^ mixed_n ^ mixed_rho;

        static const auto prng_factory = poly_sampling_prng_factory();
        std::shared_ptr<seal::UniformRandomGenerator> prng = prng_factory->create({ raw_seed, 0 });

        ring_rns_poly out{};
        out.coeffs.resize(ring_poly_coeff_count(ctx.params));

        if (ctx.context)
        {
            auto context_data = ctx.context->key_context_data();
            if (context_data)
            {
                seal::util::sample_poly_uniform(prng, context_data->parms(), out.coeffs.data());
                bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                return out;
            }
        }

        // Fallback to slower sampling if context is not available
        seal::RandomToStandardAdapter rng(prng);
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

        bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);

        return out;
    }

    ring_rns_poly derive_uniform_poly_from_nonce_ntt(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t index)
    {
        // For uniform components over the base ring, a polynomial sampled uniformly in the coefficient domain
        // is statistically indistinguishable from one sampled uniformly directly in the NTT domain.
        // Doing it directly as NTT saves a forward NTT operation.
        return derive_uniform_poly_from_nonce(ctx, nonce, domain_tag, index);
    }

    std::vector<ring_rns_poly> derive_uniform_poly_batch_from_nonce(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t count)
    {
        auto_timer total_sampling_timer(global_timing_stats.seed_sampling_time_us);
        auto_timer poly_sampling_timer(global_timing_stats.poly_sampling_time_us);
        if (count == 0u)
        {
            return {};
        }

        const std::uint64_t mixed_nonce = combine_seed_public(nonce);
        const std::uint64_t mixed_domain = combine_seed_public(domain_tag);
        const std::uint64_t mixed_n = combine_seed_public(static_cast<std::uint64_t>(ctx.params.poly_modulus_degree));
        const std::uint64_t mixed_rho =
            combine_seed_public(static_cast<std::uint64_t>(ctx.params.coeff_modulus_bits.size()));
        const std::uint64_t mixed_batch_tag = combine_seed_public(0xB47C11A5ull);
        const std::uint64_t raw_seed = mixed_nonce ^ mixed_domain ^ mixed_n ^ mixed_rho ^ mixed_batch_tag;

        return sample_uniform_batch_from_raw_seed(ctx, raw_seed, count);
    }

    std::vector<ring_rns_poly> derive_uniform_poly_batch_from_nonce_ntt(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t count)
    {
        // As with single-poly sampling, we treat sampled coefficients as already in NTT form for protocol usage.
        return derive_uniform_poly_batch_from_nonce(ctx, nonce, domain_tag, count);
    }

    comm::protocol_result<void> derive_uniform_poly_batch_from_nonce_list_inplace(
        const ring_ntt_context &ctx, const std::vector<std::uint64_t> &nonces, std::uint64_t domain_tag,
        std::uint32_t per_nonce_count, std::vector<ring_rns_poly> &out, std::uint32_t requested_workers)
    {
        auto_timer total_sampling_timer(global_timing_stats.seed_sampling_time_us);
        auto_timer poly_sampling_timer(global_timing_stats.poly_sampling_time_us);
        if (nonces.empty() || per_nonce_count == 0u)
        {
            out.clear();
            return comm::protocol_result<void>::success();
        }

        if (nonces.size() > (std::numeric_limits<std::size_t>::max() / static_cast<std::size_t>(per_nonce_count)))
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "nonce_count * per_nonce_count exceeds size_t range");
        }

        const std::size_t nonce_count = nonces.size();
        const std::size_t total_count = nonce_count * static_cast<std::size_t>(per_nonce_count);
        const std::size_t per_poly_coeff_count = ring_poly_coeff_count(ctx.params);

        if (out.size() != total_count)
        {
            out.resize(total_count);
        }

        for (auto &poly : out)
        {
            if (poly.coeffs.size() != per_poly_coeff_count)
            {
                poly.coeffs.resize(per_poly_coeff_count);
            }
        }

        const std::uint64_t mixed_domain = combine_seed_public(domain_tag);
        const std::uint64_t mixed_n = combine_seed_public(static_cast<std::uint64_t>(ctx.params.poly_modulus_degree));
        const std::uint64_t mixed_rho =
            combine_seed_public(static_cast<std::uint64_t>(ctx.params.coeff_modulus_bits.size()));
        const std::uint64_t mixed_batch_tag = combine_seed_public(0xB47C11A5ull);

        std::vector<std::uint64_t> raw_seeds(nonce_count);
        for (std::size_t i = 0; i < nonce_count; ++i)
        {
            raw_seeds[i] = combine_seed_public(nonces[i]) ^ mixed_domain ^ mixed_n ^ mixed_rho ^ mixed_batch_tag;
        }

        std::uint32_t effective_workers = requested_workers;
        if (effective_workers == 0u && total_count < 8u)
        {
            effective_workers = 1u;
        }

        static const auto prng_factory = poly_sampling_prng_factory();
        if (ctx.context)
        {
            auto context_data = ctx.context->key_context_data();
            if (context_data)
            {
                auto sample_status = detail::run_parallel_tasks(
                    total_count, effective_workers, [&](std::size_t task_idx) -> comm::protocol_result<void> {
                        const std::size_t nonce_idx = task_idx / static_cast<std::size_t>(per_nonce_count);
                        const std::uint32_t poly_idx =
                            static_cast<std::uint32_t>(task_idx % static_cast<std::size_t>(per_nonce_count));
                        auto prng = make_batch_poly_prng(prng_factory, raw_seeds[nonce_idx], poly_idx);
                        seal::util::sample_poly_uniform(prng, context_data->parms(), out[task_idx].coeffs.data());
                        bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                        return comm::protocol_result<void>::success();
                    });
                if (!sample_status)
                {
                    for (std::size_t task_idx = 0; task_idx < total_count; ++task_idx)
                    {
                        const std::size_t nonce_idx = task_idx / static_cast<std::size_t>(per_nonce_count);
                        const std::uint32_t poly_idx =
                            static_cast<std::uint32_t>(task_idx % static_cast<std::size_t>(per_nonce_count));
                        auto prng = make_batch_poly_prng(prng_factory, raw_seeds[nonce_idx], poly_idx);
                        seal::util::sample_poly_uniform(prng, context_data->parms(), out[task_idx].coeffs.data());
                        bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                    }
                }
                return comm::protocol_result<void>::success();
            }
        }

        // Fallback to slower sampling if context is not available.
        const std::size_t n = ctx.params.poly_modulus_degree;
        auto sample_status = detail::run_parallel_tasks(
            total_count, effective_workers, [&](std::size_t task_idx) -> comm::protocol_result<void> {
                const std::size_t nonce_idx = task_idx / static_cast<std::size_t>(per_nonce_count);
                const std::uint32_t poly_idx =
                    static_cast<std::uint32_t>(task_idx % static_cast<std::size_t>(per_nonce_count));
                auto prng = make_batch_poly_prng(prng_factory, raw_seeds[nonce_idx], poly_idx);
                seal::RandomToStandardAdapter rng(prng);
                auto &poly = out[task_idx];
                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    const std::uint64_t mod = ctx.moduli[mod_idx].value();
                    std::uniform_int_distribution<std::uint64_t> dist(0u, mod - 1u);
                    const std::size_t offset = mod_idx * n;
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        poly.coeffs[offset + i] = dist(rng);
                    }
                }
                bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
                return comm::protocol_result<void>::success();
            });
        if (!sample_status)
        {
            for (std::size_t task_idx = 0; task_idx < total_count; ++task_idx)
            {
                const std::size_t nonce_idx = task_idx / static_cast<std::size_t>(per_nonce_count);
                const std::uint32_t poly_idx =
                    static_cast<std::uint32_t>(task_idx % static_cast<std::size_t>(per_nonce_count));
                auto prng = make_batch_poly_prng(prng_factory, raw_seeds[nonce_idx], poly_idx);
                seal::RandomToStandardAdapter rng(prng);
                auto &poly = out[task_idx];
                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    const std::uint64_t mod = ctx.moduli[mod_idx].value();
                    std::uniform_int_distribution<std::uint64_t> dist(0u, mod - 1u);
                    const std::size_t offset = mod_idx * n;
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        poly.coeffs[offset + i] = dist(rng);
                    }
                }
                bump_ring_stat(global_ring_ops_stats.prng_poly_count, tls_ring_ops_stats.prng_poly_count);
            }
        }

        return comm::protocol_result<void>::success();
    }

    std::vector<ring_rns_poly> derive_uniform_poly_batch_from_nonce_list(
        const ring_ntt_context &ctx, const std::vector<std::uint64_t> &nonces, std::uint64_t domain_tag,
        std::uint32_t per_nonce_count, std::uint32_t requested_workers)
    {
        std::vector<ring_rns_poly> out;
        auto status = derive_uniform_poly_batch_from_nonce_list_inplace(
            ctx, nonces, domain_tag, per_nonce_count, out, requested_workers);
        if (!status)
        {
            return {};
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

        const std::uint64_t raw_seed = combine_seed_public(seed) ^ combine_seed_public(stream_id);
        std::shared_ptr<seal::UniformRandomGenerator> prng = poly_sampling_prng_factory()->create({ raw_seed, 0 });
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
                    const auto sum = static_cast<unsigned __int128>(value) + static_cast<std::uint64_t>(noise);
                    poly.coeffs[idx] = static_cast<std::uint64_t>(sum % mod);
                }
                else
                {
                    const std::uint64_t abs_noise = static_cast<std::uint64_t>(-noise) % mod;
                    poly.coeffs[idx] = (value >= abs_noise) ? static_cast<std::uint64_t>(value - abs_noise)
                                                            : static_cast<std::uint64_t>(mod - (abs_noise - value));
                }
            }
        }

        bump_ring_stat(global_ring_ops_stats.error_add_count, tls_ring_ops_stats.error_add_count);

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

        const std::uint64_t raw_seed = combine_seed_public(seed) ^ combine_seed_public(stream_id);
        std::shared_ptr<seal::UniformRandomGenerator> prng = poly_sampling_prng_factory()->create({ raw_seed, 0 });

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

        bump_ring_stat(global_ring_ops_stats.error_add_count, tls_ring_ops_stats.error_add_count);

        return comm::protocol_result<void>::success();
    }

} // namespace logvole
