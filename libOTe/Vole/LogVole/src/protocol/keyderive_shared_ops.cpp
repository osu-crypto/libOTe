#include "loglabel/keyderive_shared_ops.hpp"

#include "loglabel/ring_ops.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace loglabel
{
    comm::protocol_result<void> validate_keyderive_params_internal(const keyderive_params &params)
    {
        return validate_ring_params(params);
    }

    comm::protocol_result<void> validate_keyderive_sender_input_internal(const keyderive_sender_input &input)
    {
        auto params_ok = validate_keyderive_params_internal(input.params);
        if (!params_ok)
        {
            return params_ok;
        }

        if (input.sk1.empty() || input.sk2.empty())
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error,
                "sender inputs sk1/sk2 cannot be empty");
        }

        if (input.sk1.size() != input.sk2.size())
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error,
                "sender inputs sk1/sk2 must have the same tau");
        }

        auto sk1_shape = validate_ring_batch_shape(input.sk1, input.params, "sk1");
        if (!sk1_shape)
        {
            return sk1_shape;
        }

        auto sk2_shape = validate_ring_batch_shape(input.sk2, input.params, "sk2");
        if (!sk2_shape)
        {
            return sk2_shape;
        }

        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> validate_keyderive_receiver_input_internal(const keyderive_receiver_input &input)
    {
        auto params_ok = validate_keyderive_params_internal(input.params);
        if (!params_ok)
        {
            return params_ok;
        }

        if (input.d.empty())
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error,
                "receiver input d cannot be empty");
        }

        return validate_ring_batch_shape(input.d, input.params, "d");
    }

    std::vector<std::uint64_t> pack_ring_batch_internal(const std::vector<ring_rns_poly> &polys)
    {
        return pack_ring_batch(polys);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> unpack_ring_batch_internal(
        std::uint32_t tau, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name)
    {
        return unpack_ring_batch(tau, poly_modulus_degree, coeff_modulus_count, flat, field_name);
    }

    comm::protocol_result<keyderive_request_msg> prepare_keyderive_request_receiver_internal(
        const keyderive_receiver_input &input)
    {
        auto valid = validate_keyderive_receiver_input_internal(input);
        if (!valid)
        {
            return comm::protocol_result<keyderive_request_msg>::failure(valid.error(), valid.message());
        }

        if (input.d.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return comm::protocol_result<keyderive_request_msg>::failure(
                comm::protocol_errc::config_error,
                "receiver batch size exceeds uint32 range");
        }

        keyderive_request_msg request{};
        request.poly_modulus_degree = input.params.poly_modulus_degree;
        request.coeff_modulus_count = static_cast<std::uint32_t>(input.params.coeff_modulus_bits.size());
        request.tau = static_cast<std::uint32_t>(input.d.size());
        request.d_coeffs = pack_ring_batch_internal(input.d);

        return comm::protocol_result<keyderive_request_msg>::success(std::move(request));
    }

} // namespace loglabel
