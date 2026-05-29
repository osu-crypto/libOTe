#include "libOTe/Vole/LogVole/LogVoleSender.h"

#include <array>
#include <cstddef>
#include <limits>
#include <stdexcept>

namespace osuCrypto::LogVole
{
    namespace
    {
        constexpr u64 kFrameHeaderSize = sizeof(u64);

        void writeU64(std::array<u8, kFrameHeaderSize>& out, u64 value)
        {
            for (u64 i = 0; i < kFrameHeaderSize; ++i)
            {
                out[i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
            }
        }

        u64 readU64(const std::array<u8, kFrameHeaderSize>& in)
        {
            u64 value = 0;
            for (u64 i = 0; i < kFrameHeaderSize; ++i)
            {
                value |= static_cast<u64>(in[i]) << (8u * i);
            }
            return value;
        }

        task<> sendFrame(Socket& sock, const Buffer& payload)
        {
            std::array<u8, kFrameHeaderSize> header{};
            writeU64(header, static_cast<u64>(payload.size()));

            co_await sock.send(coproto::copy(header));
            if (!payload.empty())
            {
                co_await sock.send(coproto::copy(payload));
            }
        }

        task<Buffer> recvFrame(Socket& sock)
        {
            std::array<u8, kFrameHeaderSize> header{};
            co_await sock.recv(header);

            const auto size = readU64(header);
            if (size > static_cast<u64>(std::numeric_limits<std::size_t>::max()))
            {
                throw std::length_error("LogVole frame is too large");
            }

            Buffer payload(static_cast<std::size_t>(size));
            if (!payload.empty())
            {
                co_await sock.recv(payload);
            }

            co_return payload;
        }
    }

    task<> Sender::keyDerive(
        const KeyDeriveSenderInput& input,
        KeyDeriveSenderOutput& output,
        Socket& sock)
    {
        const auto requestPayload = co_await recvFrame(sock);

        KeyDeriveRequest request{};
        if (!decode(requestPayload, request))
        {
            throw std::runtime_error("LogVole sender received malformed key-derive request");
        }

        KeyDeriveResponse response{};
        if (!processKeyDeriveRequest(input, request, response, output))
        {
            throw std::runtime_error("LogVole sender rejected key-derive request");
        }

        co_await sendFrame(sock, encode(response));
    }
}
