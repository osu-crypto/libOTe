#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include <array>
#include <cstddef>
#include <exception>
#include <limits>
#include <span>
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

        u64 frameBytes(const Buffer& payload)
        {
            return kFrameHeaderSize + static_cast<u64>(payload.size());
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

        bool computeMuHi(const Params& params, u32& out)
        {
            u32 tauHi = 0;
            if (!computeTauHi(params, tauHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (rho == 0)
            {
                return false;
            }

            out = params.mShrinkExpand.mAlpha * tauHi * rho;
            return out != 0;
        }

        u64 countSeedInstances(const SenderState& state)
        {
            u32 muHi = 0;
            if (!computeMuHi(state.mParams, muHi))
            {
                return 0;
            }

            RecursiveMode mode{};
            if (!recursiveMode(state.mParams, mode))
            {
                return 0;
            }
            if (mode == RecursiveMode::Root)
            {
                return 1;
            }
            if (!state.mNextLevelState)
            {
                return 0;
            }

            const u32 wDoublePrime = (state.mParams.mW + muHi - 1u) / muHi;
            return countSeedInstances(*state.mNextLevelState) + wDoublePrime;
        }

        void applySessionId(SenderState& state, u64 sid)
        {
            state.mParams.mSessionId = sid;
            if (state.mNextLevelState)
            {
                applySessionId(*state.mNextLevelState, sid);
            }
        }

        void clearSenderOnlineCache(SenderState& state)
        {
            state.mGoldenSeed.clear();
            state.mRootKPrimeRt.reset();
            state.mRootDPrimeRt.reset();
            state.mPrecomputedTbk.reset();
            if (state.mNextLevelState)
            {
                clearSenderOnlineCache(*state.mNextLevelState);
            }
        }

        task<> sendOfflineMessage(
            const Params& params,
            const OfflineMessage& message,
            Socket& sock,
            bool isTopLevel,
            bool hasReusableState)
        {
            RecursiveMode mode{};
            if (!recursiveMode(params, mode))
            {
                throw std::runtime_error("LogVole sender has invalid recursive offline parameters");
            }

            bool childHasReusableState = hasReusableState;
            if (hasReusableState)
            {
                if (message.mHasShrinkExpandMessage)
                {
                    throw std::runtime_error("LogVole sender has unexpected reusable offline message");
                }
            }
            else
            {
                if (!message.mHasShrinkExpandMessage)
                {
                    throw std::runtime_error("LogVole sender missing shrink/expand offline message");
                }

                auto shrinkExpandSock = sock.fork();
                co_await sendFrame(shrinkExpandSock, encode(message.mShrinkExpandMessage));
                if (!isTopLevel)
                {
                    childHasReusableState = true;
                }
            }

            if (mode == RecursiveMode::Root)
            {
                auto rootSock = sock.fork();
                co_await sendFrame(rootSock, encode(message.mRootMessage));
                co_return;
            }

            if (!message.mNextLevel)
            {
                throw std::runtime_error("LogVole sender missing recursive offline message");
            }

            Params child{};
            if (!childParams(params, child))
            {
                throw std::runtime_error("LogVole sender could not derive child parameters");
            }

            auto childSock = sock.fork();
            co_await sendOfflineMessage(child, *message.mNextLevel, childSock, false, childHasReusableState);
        }

        task<> senderOnlineService(
            SenderState& state,
            SenderState& precomputeRoot,
            Socket& sock,
            PRNG& prng,
            CommunicationStats& comm)
        {
            RecursiveMode mode{};
            if (!recursiveMode(state.mParams, mode))
            {
                throw std::runtime_error("LogVole sender has invalid recursive online parameters");
            }

            if (mode == RecursiveMode::Root)
            {
                Buffer digestPayload;
                Buffer responsePayload;
                {
                    auto rootSock = sock.fork();
                    digestPayload = co_await recvFrame(rootSock);

                    RootDigestMessage digest{};
                    if (!decode(digestPayload, digest))
                    {
                        throw std::runtime_error("LogVole sender could not decode root digest");
                    }

                    RootResponseMessage response{};
                    if (!prepareRootResponseSender(state, digest, prng, response, &precomputeRoot))
                    {
                        throw std::runtime_error("LogVole sender could not prepare root response");
                    }

                    responsePayload = encode(response);
                    co_await sendFrame(rootSock, responsePayload);
                }
                comm.mBytesSent += frameBytes(responsePayload);
                comm.mBytesReceived += frameBytes(digestPayload);
                co_return;
            }

            if (!state.mNextLevelState)
            {
                throw std::runtime_error("LogVole sender missing recursive child state");
            }

            auto childSock = sock.fork();
            co_await senderOnlineService(*state.mNextLevelState, precomputeRoot, childSock, prng, comm);
            if (!state.mPrecomputedTbk)
            {
                throw std::runtime_error("LogVole sender could not prepare recursive online cache");
            }
        }
    }

    task<> LogVoleRingSender::offline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandSenderState& state,
        PRNG& prng,
        Socket& sock)
    {
        ShrinkExpandOfflineMessage message{};
        if (!prepareShrinkExpandSenderOffline(input, prng, message, state))
        {
            throw std::runtime_error("LogVole sender could not prepare shrink/expand offline message");
        }

        co_await sendFrame(sock, encode(message));
    }

    task<> LogVoleRingSender::offline(
        const SenderOfflineInput& input,
        SenderState& state,
        PRNG& prng,
        Socket& sock)
    {
        SenderOfflineOutput output{};
        if (!prepareSenderOffline(input, prng, output))
        {
            throw std::runtime_error("LogVole sender could not prepare recursive offline state");
        }

        co_await sendOfflineMessage(input.mParams, output.mMessage, sock, true, false);
        state = std::move(output.mState);
    }

    task<> LogVoleRingSender::keyDerive(
        const KeyDeriveSenderInput& input,
        KeyDeriveSenderOutput& output,
        Socket& sock)
    {
        const auto requestPayload = co_await recvFrame(sock);

        KeyDeriveRequest request{};
        if (!decode(requestPayload, request))
        {
            throw std::runtime_error("LogVole sender could not decode key-derive request");
        }

        KeyDeriveResponse response{};
        if (!processKeyDeriveRequest(input, request, response, output))
        {
            throw std::runtime_error("LogVole sender rejected key-derive request");
        }

        co_await sendFrame(sock, encode(response));
    }

    task<> LogVoleRingSender::online(
        SenderState& state,
        SenderOnlineOutput& output,
        PRNG& prng,
        Socket& sock)
    {
        SenderOnlineOptions options{};
        co_await online(state, options, output, prng, sock);
    }

    task<> LogVoleRingSender::online(
        SenderState& state,
        const SenderOnlineOptions& options,
        SenderOnlineOutput& output,
        PRNG& prng,
        Socket& sock)
    {
        ProtocolCacheScope cacheScope = currentProtocolCacheScope();
        if (cacheScope.mRunId == 0)
        {
            cacheScope.mRunId = allocateProtocolCacheRunId();
            cacheScope.mRole = ProtocolCacheRole::Sender;
        }
        ScopedProtocolCacheScope scopedCache(cacheScope);
        clearSenderOnlineCache(state);
        applySessionId(state, options.mSid);

        std::exception_ptr serviceException{};
        CommunicationStats comm{};
        try
        {
            co_await senderOnlineService(state, state, sock, prng, comm);
        }
        catch (...)
        {
            serviceException = std::current_exception();
        }

        if (serviceException)
        {
            std::rethrow_exception(serviceException);
        }
        if (!state.mPrecomputedTbk)
        {
            throw std::runtime_error("LogVole sender could not prepare recursive online cache");
        }

        SenderOnlineOutput next{};
        next.mSeed = state.mGoldenSeed;
        if (!options.mSkipTbkOutput)
        {
            next.mTbk = *state.mPrecomputedTbk;
        }
        next.mComm = comm;
        output = std::move(next);
    }

    task<> LogVoleRingSender::expand(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& output,
        Socket& sock)
    {
        const auto digestPayload = co_await recvFrame(sock);

        PolyMessage digestMessage{};
        if (!decode(digestPayload, digestMessage))
        {
            throw std::runtime_error("LogVole sender received malformed shrink digest");
        }

        RnsPoly digest{};
        if (!readPolyMessage(state.mParams.mRing, digestMessage, digest))
        {
            throw std::runtime_error("LogVole sender rejected shrink digest metadata");
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            throw std::runtime_error("LogVole sender could not build ring context");
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
            throw std::runtime_error("LogVole sender could not derive shrink/expand key");
        }

        co_await sendFrame(sock, encode(makePolyMessage(state.mParams.mRing, skX)));

        ShrinkExpandExpandSenderInput expandInput = input;
        expandInput.mDigest = std::move(digest);
        if (!shrinkExpandExpandSender(state, expandInput, output))
        {
            throw std::runtime_error("LogVole sender could not expand");
        }
    }
}
