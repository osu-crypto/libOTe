#include "libOTe/Vole/LogVole/LogVoleReceiver.h"

#include <array>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <utility>

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

        PolyMessage makePolyMessage(const RingParams& params, const RnsPoly& poly)
        {
            PolyMessage message{};
            message.mPolyModulusDegree = params.mPolyModulusDegree;
            message.mCoeffModulusCount = static_cast<u32>(params.mCoeffModulusBits.size());
            message.mCoeffs = poly.mCoeffs;
            return message;
        }

        bool readPolyMessage(const RingParams& params, PolyMessage& message, RnsPoly& out)
        {
            if (message.mPolyModulusDegree != params.mPolyModulusDegree ||
                message.mCoeffModulusCount != params.mCoeffModulusBits.size() ||
                message.mCoeffs.size() !=
                    static_cast<std::size_t>(params.mPolyModulusDegree) * params.mCoeffModulusBits.size())
            {
                return false;
            }

            out.mCoeffs = std::move(message.mCoeffs);
            return true;
        }
    }

    task<> Receiver::offline(
        const ShrinkExpandReceiverOfflineInput& input,
        ShrinkExpandReceiverState& state,
        Socket& sock)
    {
        const auto payload = co_await recvFrame(sock);

        ShrinkExpandOfflineMessage message{};
        if (!decode(payload, message))
        {
            throw std::runtime_error("LogVole receiver received malformed shrink/expand offline message");
        }

        if (!finalizeReceiverOffline(input, message, state))
        {
            throw std::runtime_error("LogVole receiver rejected shrink/expand offline message");
        }
    }

    task<> Receiver::keyDerive(
        const KeyDeriveReceiverInput& input,
        KeyDeriveReceiverOutput& output,
        Socket& sock)
    {
        KeyDeriveRequest request{};
        if (!prepareKeyDeriveRequest(input, request))
        {
            throw std::runtime_error("LogVole receiver could not prepare key-derive request");
        }

        co_await sendFrame(sock, encode(request));

        const auto responsePayload = co_await recvFrame(sock);

        KeyDeriveResponse response{};
        if (!decode(responsePayload, response))
        {
            throw std::runtime_error("LogVole receiver received malformed key-derive response");
        }

        if (!finalizeKeyDeriveResponse(input, response, output))
        {
            throw std::runtime_error("LogVole receiver rejected key-derive response");
        }
    }

    task<> Receiver::expand(
        const ShrinkExpandReceiverState& state,
        const ReceiverExpandInput& input,
        ShrinkExpandReceiverExpandOutput& output,
        Socket& sock)
    {
        RnsPoly digest{};
        if (!shrink(state, input.mX, digest))
        {
            throw std::runtime_error("LogVole receiver could not shrink");
        }

        co_await sendFrame(sock, encode(makePolyMessage(state.mParams.mRing, digest)));

        const auto skXPayload = co_await recvFrame(sock);
        PolyMessage skXMessage{};
        if (!decode(skXPayload, skXMessage))
        {
            throw std::runtime_error("LogVole receiver received malformed shrink/expand key");
        }

        RnsPoly skX{};
        if (!readPolyMessage(state.mParams.mRing, skXMessage, skX))
        {
            throw std::runtime_error("LogVole receiver rejected shrink/expand key metadata");
        }

        ShrinkExpandReceiverExpandInput coreInput{};
        coreInput.mNonce = input.mNonce;
        coreInput.mX = input.mX;
        coreInput.mDigest = std::move(digest);
        coreInput.mSkX = std::move(skX);

        if (!expandReceiver(state, coreInput, output))
        {
            throw std::runtime_error("LogVole receiver could not expand");
        }
    }
}
