#include "libOTe/Vole/LogVole2/LogVole2Receiver.h"

#include "libOTe/Vole/LogVole2/LogVole2Encoding.h"
#include "libOTe/Vole/LogVole2/LogVole2Parallel.h"

#include <algorithm>
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

        u64 countSeedInstances(const ReceiverState& state)
        {
            u32 tauHi = 0;
            if (!computeTauHi(state.mParams, tauHi))
            {
                return 0;
            }

            const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const u32 muHi = state.mParams.mShrinkExpand.mAlpha * tauHi * rho;
            if (evalRecursiveMode(state.mParams.mW, state.mParams.mShrinkExpand.mAlpha, tauHi, rho) ==
                RecursiveMode::Root)
            {
                return 1;
            }
            if (!state.mNextLevelState || muHi == 0)
            {
                return 0;
            }

            const u32 wDoublePrime = (state.mParams.mW + muHi - 1u) / muHi;
            return countSeedInstances(*state.mNextLevelState) + wDoublePrime;
        }

        task<> recvOfflineMessage(
            const Params& params,
            OfflineMessage& message,
            Socket& sock,
            bool isTopLevel,
            bool hasReusableState)
        {
            RecursiveMode mode{};
            if (!recursiveMode(params, mode))
            {
                throw std::runtime_error("LogVole2 receiver has invalid recursive offline parameters");
            }

            bool childHasReusableState = hasReusableState;
            if (hasReusableState)
            {
                message.mHasShrinkExpandMessage = false;
            }
            else
            {
                auto shrinkExpandSock = sock.fork();
                const auto shrinkExpandPayload = co_await recvFrame(shrinkExpandSock);
                if (!decode(shrinkExpandPayload, message.mShrinkExpandMessage))
                {
                    throw std::runtime_error("LogVole2 receiver could not decode shrink/expand offline message");
                }
                message.mHasShrinkExpandMessage = true;
                if (!isTopLevel)
                {
                    childHasReusableState = true;
                }
            }

            if (mode == RecursiveMode::Root)
            {
                auto rootSock = sock.fork();
                const auto rootPayload = co_await recvFrame(rootSock);
                if (!decode(rootPayload, message.mRootMessage))
                {
                    throw std::runtime_error("LogVole2 receiver could not decode root offline message");
                }
                co_return;
            }

            Params child{};
            if (!childParams(params, child))
            {
                throw std::runtime_error("LogVole2 receiver could not derive child parameters");
            }

            message.mNextLevel = std::make_unique<OfflineMessage>();
            auto childSock = sock.fork();
            co_await recvOfflineMessage(child, *message.mNextLevel, childSock, false, childHasReusableState);
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
            throw std::runtime_error("LogVole2 receiver received malformed shrink/expand offline message");
        }

        if (!finalizeShrinkExpandReceiverOffline(input, message, state))
        {
            throw std::runtime_error("LogVole2 receiver rejected shrink/expand offline message");
        }
    }

    task<> Receiver::offline(
        const ReceiverOfflineInput& input,
        ReceiverState& state,
        Socket& sock)
    {
        OfflineMessage message{};
        co_await recvOfflineMessage(input.mParams, message, sock, true, false);

        ReceiverOfflineOutput output{};
        if (!finalizeReceiverOffline(input, message, output))
        {
            throw std::runtime_error("LogVole2 receiver rejected recursive offline message");
        }

        state = std::move(output.mState);
    }

    task<> Receiver::keyDerive(
        const KeyDeriveReceiverInput& input,
        KeyDeriveReceiverOutput& output,
        Socket& sock)
    {
        KeyDeriveRequest request{};
        if (!prepareKeyDeriveRequest(input, request))
        {
            throw std::runtime_error("LogVole2 receiver could not prepare key-derive request");
        }

        co_await sendFrame(sock, encode(request));

        const auto responsePayload = co_await recvFrame(sock);

        KeyDeriveResponse response{};
        if (!decode(responsePayload, response))
        {
            throw std::runtime_error("LogVole2 receiver could not decode key-derive response");
        }

        if (!finalizeKeyDeriveResponse(input, response, output))
        {
            throw std::runtime_error("LogVole2 receiver rejected key-derive response");
        }
    }

    task<> Receiver::online(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output,
        Socket& sock)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi))
        {
            throw std::runtime_error("LogVole2 receiver has invalid recursive online parameters");
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 muHi = state.mParams.mShrinkExpand.mAlpha * tauHi * rho;
        RecursiveMode mode{};
        if (rho == 0 || muHi == 0 || !recursiveMode(state.mParams, mode))
        {
            throw std::runtime_error("LogVole2 receiver has invalid recursive online shape");
        }

        if (mode == RecursiveMode::Root)
        {
            auto rootSock = sock.fork();
            RootDigestState digestState{};
            RootDigestMessage digest{};
            if (!prepareRootDigestReceiver(state, input.mX, digestState, digest))
            {
                throw std::runtime_error("LogVole2 receiver could not prepare root digest");
            }

            co_await sendFrame(rootSock, encode(digest));

            const auto responsePayload = co_await recvFrame(rootSock);
            RootResponseMessage response{};
            if (!decode(responsePayload, response))
            {
                throw std::runtime_error("LogVole2 receiver could not decode root response");
            }

            if (!finalizeRootOnlineReceiver(state, input, digestState, response, output))
            {
                throw std::runtime_error("LogVole2 receiver could not finalize root online");
            }
            co_return;
        }

        if (!state.mNextLevelState || input.mX.size() != state.mParams.mW)
        {
            throw std::runtime_error("LogVole2 receiver missing recursive child state");
        }

        const u32 wDoublePrime = (state.mParams.mW + muHi - 1u) / muHi;
        const u32 wNext = wDoublePrime * tauHi * rho;
        const u32 wPrime =
            (state.mParams.mW + state.mParams.mShrinkExpand.mAlpha - 1u) /
            state.mParams.mShrinkExpand.mAlpha;

        std::vector<std::vector<RnsPoly>> dHatChunks(wDoublePrime);
        std::vector<RnsPoly> digests(wDoublePrime);
        std::vector<std::shared_ptr<DigestTree>> trees(wDoublePrime);

        const bool shrinkOk = detail::runParallelTasks(
            wDoublePrime,
            state.mParams.mShrinkExpand.mNumWorkerThreads,
            [&](std::size_t taskIdx) {
                const auto chunkIdx = static_cast<u32>(taskIdx);
                const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                const std::size_t end = std::min(start + static_cast<std::size_t>(muHi), input.mX.size());

                std::vector<RnsPoly> chunk(input.mX.begin() + start, input.mX.begin() + end);
                while (chunk.size() < muHi)
                {
                    RnsPoly zero{};
                    zero.mCoeffs.assign(ringPolyCoeffCount(state.mParams.mShrinkExpand.mRing), 0);
                    chunk.push_back(std::move(zero));
                }

                ShrinkExpandShrinkOutput shrink{};
                std::vector<RnsPoly> decomposed;
                if (!shrinkExpandShrink(state.mShrinkExpandState, chunk, shrink) ||
                    !seedLabelGadgetDecomposeHiAndUnbundle(
                        shrink.mDigest,
                        state.mParams.mShrinkExpand.mGadgetLogBase,
                        tauHi,
                        state.mParams.mShrinkExpand.mRing,
                        decomposed) ||
                    decomposed.size() != static_cast<std::size_t>(tauHi) * rho)
                {
                    return false;
                }

                digests[chunkIdx] = std::move(shrink.mDigest);
                trees[chunkIdx] = std::move(shrink.mTree);
                dHatChunks[chunkIdx] = std::move(decomposed);
                return true;
            });
        if (!shrinkOk)
        {
            throw std::runtime_error("LogVole2 receiver could not prepare recursive child input");
        }

        std::vector<RnsPoly> dHat;
        dHat.reserve(wNext);
        for (auto& chunk : dHatChunks)
        {
            for (auto& poly : chunk)
            {
                dHat.push_back(std::move(poly));
            }
        }

        ReceiverOnlineInput childInput{};
        childInput.mX = std::move(dHat);

        ReceiverOnlineOutput childOutput{};
        auto childSock = sock.fork();
        co_await online(*state.mNextLevelState, childInput, childOutput, childSock);

        std::vector<RnsPoly> skXHat;
        std::vector<RnsPoly> skX;
        if (!seedLabelDenoiseTbm(
                childOutput.mTbm,
                wPrime,
                tauHi,
                state.mParams.mShrinkExpand.mRing,
                skXHat) ||
            !seedLabelAgg(
                skXHat,
                wDoublePrime,
                tauHi,
                state.mParams.mShrinkExpand.mRing,
                skX) ||
            skX.size() != wDoublePrime)
        {
            throw std::runtime_error("LogVole2 receiver could not derive recursive expansion keys");
        }

        const u64 instanceBase = countSeedInstances(*state.mNextLevelState);
        std::vector<RnsPoly> finalTbm(state.mParams.mW);
        const bool expandOk = detail::runParallelTasks(
            wDoublePrime,
            state.mParams.mShrinkExpand.mNumWorkerThreads,
            [&](std::size_t taskIdx) {
                const auto chunkIdx = static_cast<u32>(taskIdx);
                const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                const std::size_t end = std::min(start + static_cast<std::size_t>(muHi), input.mX.size());

                ShrinkExpandExpandReceiverInput expandInput{};
                expandInput.mNonce = deriveSeedInstanceNonce(
                    state.mParams.mShrinkExpand.mSamplingSeeds,
                    childOutput.mSeed,
                    instanceBase + chunkIdx);
                expandInput.mDigest = digests[chunkIdx];
                expandInput.mSkX = skX[chunkIdx];
                expandInput.mTree = trees[chunkIdx];

                ShrinkExpandReceiverExpandOutput expandOutput{};
                if (!shrinkExpandExpandReceiver(state.mShrinkExpandState, expandInput, expandOutput) ||
                    expandOutput.mTbm.size() < end - start)
                {
                    return false;
                }

                for (std::size_t itemIdx = 0; itemIdx < end - start; ++itemIdx)
                {
                    finalTbm[start + itemIdx] = std::move(expandOutput.mTbm[itemIdx]);
                }
                return true;
            });
        if (!expandOk)
        {
            throw std::runtime_error("LogVole2 receiver could not expand recursive chunk");
        }

        ReceiverOnlineOutput next{};
        next.mSeed = childOutput.mSeed;
        next.mTbm = std::move(finalTbm);
        output = std::move(next);
    }

    task<> Receiver::expand(
        const ShrinkExpandReceiverState& state,
        const ReceiverExpandInput& input,
        ShrinkExpandReceiverExpandOutput& output,
        Socket& sock)
    {
        ShrinkExpandShrinkOutput shrink{};
        if (!shrinkExpandShrink(state, input.mX, shrink))
        {
            throw std::runtime_error("LogVole2 receiver could not shrink");
        }

        co_await sendFrame(sock, encode(makePolyMessage(state.mParams.mRing, shrink.mDigest)));

        const auto skXPayload = co_await recvFrame(sock);

        PolyMessage skXMessage{};
        if (!decode(skXPayload, skXMessage))
        {
            throw std::runtime_error("LogVole2 receiver received malformed shrink/expand key");
        }

        RnsPoly skX{};
        if (!readPolyMessage(state.mParams.mRing, skXMessage, skX))
        {
            throw std::runtime_error("LogVole2 receiver rejected shrink/expand key metadata");
        }

        ShrinkExpandExpandReceiverInput coreInput{};
        coreInput.mNonce = input.mNonce;
        coreInput.mX = input.mX;
        coreInput.mDigest = std::move(shrink.mDigest);
        coreInput.mSkX = std::move(skX);
        coreInput.mTree = std::move(shrink.mTree);

        if (!shrinkExpandExpandReceiver(state, coreInput, output))
        {
            throw std::runtime_error("LogVole2 receiver could not expand");
        }
    }
}
