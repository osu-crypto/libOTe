#include "libOTe/Vole/LogVole2/LogVole2Sender.h"

#include "libOTe/Vole/LogVole2/LogVole2Encoding.h"

#include <array>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole2
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
                throw std::length_error("LogVole2 frame is too large");
            }

            Buffer payload(static_cast<std::size_t>(size));
            if (!payload.empty())
            {
                co_await sock.recv(payload);
            }

            co_return payload;
        }

        bool computeTauHi(const Params& params, u32& out)
        {
            if (params.mShrinkExpand.mTau < 2)
            {
                return false;
            }
            out = params.mShrinkExpand.mTau - 1;
            return true;
        }

        bool recursiveMode(const Params& params, RecursiveMode& out)
        {
            u32 tauHi = 0;
            if (!computeTauHi(params, tauHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            out = evalRecursiveMode(params.mW, params.mShrinkExpand.mAlpha, tauHi, rho);
            return true;
        }

        bool childParams(const Params& params, Params& out)
        {
            u32 tauHi = 0;
            if (!computeTauHi(params, tauHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const u32 muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
            if (rho == 0 || muHi == 0)
            {
                return false;
            }

            const u32 wDoublePrime = (params.mW + muHi - 1u) / muHi;
            if (wDoublePrime == 0)
            {
                return false;
            }

            out = params;
            out.mW = wDoublePrime * tauHi * rho;
            out.mGamma = tauHi;
            return true;
        }

        task<> sendOfflineMessage(
            const Params& params,
            const OfflineMessage& message,
            Socket& sock)
        {
            RecursiveMode mode{};
            if (!recursiveMode(params, mode))
            {
                throw std::runtime_error("LogVole2 sender has invalid recursive offline parameters");
            }

            co_await sendFrame(sock, encode(message.mShrinkExpandMessage));
            if (mode == RecursiveMode::Root)
            {
                co_await sendFrame(sock, encode(message.mRootMessage));
                co_return;
            }

            if (!message.mNextLevel)
            {
                throw std::runtime_error("LogVole2 sender missing recursive offline message");
            }

            Params child{};
            if (!childParams(params, child))
            {
                throw std::runtime_error("LogVole2 sender could not derive child parameters");
            }

            co_await sendOfflineMessage(child, *message.mNextLevel, sock);
        }
    }

    task<> Sender::offline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandSenderState& state,
        Socket& sock)
    {
        ShrinkExpandOfflineMessage message{};
        if (!prepareShrinkExpandSenderOffline(input, message, state))
        {
            throw std::runtime_error("LogVole2 sender could not prepare shrink/expand offline message");
        }

        co_await sendFrame(sock, encode(message));
    }

    task<> Sender::offline(
        const SenderOfflineInput& input,
        SenderState& state,
        Socket& sock)
    {
        SenderOfflineOutput output{};
        if (!prepareSenderOffline(input, output))
        {
            throw std::runtime_error("LogVole2 sender could not prepare recursive offline state");
        }

        co_await sendOfflineMessage(input.mParams, output.mMessage, sock);
        state = std::move(output.mState);
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
            throw std::runtime_error("LogVole2 sender could not decode key-derive request");
        }

        KeyDeriveResponse response{};
        if (!processKeyDeriveRequest(input, request, response, output))
        {
            throw std::runtime_error("LogVole2 sender rejected key-derive request");
        }

        co_await sendFrame(sock, encode(response));
    }

    task<> Sender::online(
        const SenderState& state,
        SenderOnlineOutput& output,
        Socket& sock)
    {
        RecursiveMode mode{};
        if (!recursiveMode(state.mParams, mode))
        {
            throw std::runtime_error("LogVole2 sender has invalid recursive online parameters");
        }

        if (!ensureSenderPrecompute(state) || !state.mPrecomputedTbk)
        {
            throw std::runtime_error("LogVole2 sender could not prepare recursive online cache");
        }

        if (mode == RecursiveMode::Root)
        {
            const auto digestPayload = co_await recvFrame(sock);

            RootDigestMessage digest{};
            if (!decode(digestPayload, digest))
            {
                throw std::runtime_error("LogVole2 sender could not decode root digest");
            }

            RootResponseMessage response{};
            if (!prepareRootResponseSender(state, digest, response))
            {
                throw std::runtime_error("LogVole2 sender could not prepare root response");
            }

            co_await sendFrame(sock, encode(response));

            SenderOnlineOutput next{};
            next.mSeed = response.mSeed;
            next.mTbk = *state.mPrecomputedTbk;
            output = std::move(next);
            co_return;
        }

        if (!state.mNextLevelState)
        {
            throw std::runtime_error("LogVole2 sender missing recursive child state");
        }

        SenderOnlineOutput childOutput{};
        co_await online(*state.mNextLevelState, childOutput, sock);

        SenderOnlineOutput next{};
        next.mSeed = state.mGoldenSeed;
        next.mTbk = *state.mPrecomputedTbk;
        output = std::move(next);
    }

    task<> Sender::expand(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& output,
        Socket& sock)
    {
        const auto digestPayload = co_await recvFrame(sock);

        PolyMessage digestMessage{};
        if (!decode(digestPayload, digestMessage))
        {
            throw std::runtime_error("LogVole2 sender received malformed shrink digest");
        }

        RnsPoly digest{};
        if (!readPolyMessage(state.mParams.mRing, digestMessage, digest))
        {
            throw std::runtime_error("LogVole2 sender rejected shrink digest metadata");
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            throw std::runtime_error("LogVole2 sender could not build ring context");
        }

        RnsPoly skX{};
        bool skxOk = false;
        if (state.mParams.mTruncateOneGadgetDigit)
        {
            skxOk = deriveSkxTrunc(
                ctx,
                state.mSk1,
                digest,
                input.mTbkPrime,
                state.mParams.mGadgetLogBase,
                state.mParams.mTau,
                skX);
        }
        else
        {
            skxOk = deriveSkx(
                ctx,
                state.mSk1,
                digest,
                input.mTbkPrime,
                state.mParams.mGadgetLogBase,
                state.mParams.mTau,
                skX);
        }
        if (!skxOk)
        {
            throw std::runtime_error("LogVole2 sender could not derive shrink/expand key");
        }

        co_await sendFrame(sock, encode(makePolyMessage(state.mParams.mRing, skX)));

        if (!shrinkExpandExpandSender(state, input, output))
        {
            throw std::runtime_error("LogVole2 sender could not expand");
        }
    }
}
