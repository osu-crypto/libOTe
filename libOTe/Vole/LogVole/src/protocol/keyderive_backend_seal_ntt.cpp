#include "loglabel/keyderive_backend.hpp"

#include "loglabel/keyderive_shared_ops.hpp"
#include "loglabel/ring_ops.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace loglabel
{
    comm::protocol_result<keyderive_response_msg> keyderive_seal_ntt_backend::process_request_sender(
        const keyderive_sender_input &sender_input, const keyderive_request_msg &request,
        keyderive_sender_output &sender_output) const
    {
        auto sender_ok = validate_keyderive_sender_input_internal(sender_input);
        if (!sender_ok)
        {
            return comm::protocol_result<keyderive_response_msg>::failure(sender_ok.error(), sender_ok.message());
        }

        const std::uint32_t expected_mod_count = static_cast<std::uint32_t>(sender_input.params.coeff_modulus_bits.size());
        if (request.poly_modulus_degree != sender_input.params.poly_modulus_degree ||
            request.coeff_modulus_count != expected_mod_count)
        {
            return comm::protocol_result<keyderive_response_msg>::failure(
                comm::protocol_errc::flow_violation,
                "request ring metadata does not match sender keyderive params");
        }

        if (request.tau != sender_input.sk1.size())
        {
            return comm::protocol_result<keyderive_response_msg>::failure(
                comm::protocol_errc::flow_violation,
                "request tau does not match sender batch size");
        }

        auto d_batch = unpack_ring_batch_internal(
            request.tau, request.poly_modulus_degree, request.coeff_modulus_count, request.d_coeffs, "request.d_coeffs");
        if (!d_batch)
        {
            return comm::protocol_result<keyderive_response_msg>::failure(d_batch.error(), d_batch.message());
        }

        auto ctx_result = make_ring_ntt_context(sender_input.params);
        if (!ctx_result)
        {
            return comm::protocol_result<keyderive_response_msg>::failure(
                ctx_result.error(), ctx_result.message());
        }

        const auto &ctx = ctx_result.value();

        std::vector<ring_rns_poly> m_ntt_batch;
        m_ntt_batch.reserve(request.tau);

        for (std::size_t i = 0; i < request.tau; ++i)
        {
            ring_rns_poly sk1 = sender_input.sk1[i];
            ring_rns_poly sk2 = sender_input.sk2[i];
            ring_rns_poly d = d_batch.value()[i];

            auto sk1_ntt = forward_ntt_inplace(sk1, ctx);
            if (!sk1_ntt)
            {
                return comm::protocol_result<keyderive_response_msg>::failure(sk1_ntt.error(), sk1_ntt.message());
            }

            auto sk2_ntt = forward_ntt_inplace(sk2, ctx);
            if (!sk2_ntt)
            {
                return comm::protocol_result<keyderive_response_msg>::failure(sk2_ntt.error(), sk2_ntt.message());
            }

            auto d_ntt = forward_ntt_inplace(d, ctx);
            if (!d_ntt)
            {
                return comm::protocol_result<keyderive_response_msg>::failure(d_ntt.error(), d_ntt.message());
            }

            auto m_ntt = dyadic_multiply_add_ntt(sk1, d, sk2, ctx);
            if (!m_ntt)
            {
                return comm::protocol_result<keyderive_response_msg>::failure(m_ntt.error(), m_ntt.message());
            }

            m_ntt_batch.push_back(std::move(m_ntt.value()));
        }

        keyderive_response_msg response{};
        response.poly_modulus_degree = request.poly_modulus_degree;
        response.coeff_modulus_count = request.coeff_modulus_count;
        response.tau = request.tau;
        response.m_ntt_coeffs = pack_ring_batch_internal(m_ntt_batch);

        sender_output.k = sender_input.sk2;

        return comm::protocol_result<keyderive_response_msg>::success(std::move(response));
    }

    comm::protocol_result<keyderive_receiver_output> keyderive_seal_ntt_backend::finalize_response_receiver(
        const keyderive_receiver_input &receiver_input, const keyderive_response_msg &response) const
    {
        auto receiver_ok = validate_keyderive_receiver_input_internal(receiver_input);
        if (!receiver_ok)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(receiver_ok.error(), receiver_ok.message());
        }

        const std::uint32_t expected_mod_count = static_cast<std::uint32_t>(receiver_input.params.coeff_modulus_bits.size());
        if (response.poly_modulus_degree != receiver_input.params.poly_modulus_degree ||
            response.coeff_modulus_count != expected_mod_count)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                comm::protocol_errc::flow_violation,
                "response ring metadata does not match receiver keyderive params");
        }

        if (response.tau != receiver_input.d.size())
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                comm::protocol_errc::flow_violation,
                "response tau does not match receiver batch size");
        }

        auto m_ntt_batch = unpack_ring_batch_internal(
            response.tau, response.poly_modulus_degree, response.coeff_modulus_count,
            response.m_ntt_coeffs, "response.m_ntt_coeffs");
        if (!m_ntt_batch)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                m_ntt_batch.error(), m_ntt_batch.message());
        }

        auto ctx_result = make_ring_ntt_context(receiver_input.params);
        if (!ctx_result)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                ctx_result.error(), ctx_result.message());
        }

        const auto &ctx = ctx_result.value();

        keyderive_receiver_output output{};
        output.m.reserve(response.tau);

        for (std::size_t i = 0; i < response.tau; ++i)
        {
            ring_rns_poly poly = std::move(m_ntt_batch.value()[i]);
            auto canonical = canonicalize_poly_inplace(poly, ctx);
            if (!canonical)
            {
                return comm::protocol_result<keyderive_receiver_output>::failure(
                    canonical.error(), canonical.message());
            }

            auto intt = inverse_ntt_inplace(poly, ctx);
            if (!intt)
            {
                return comm::protocol_result<keyderive_receiver_output>::failure(intt.error(), intt.message());
            }

            output.m.push_back(std::move(poly));
        }

        return comm::protocol_result<keyderive_receiver_output>::success(std::move(output));
    }

} // namespace loglabel
