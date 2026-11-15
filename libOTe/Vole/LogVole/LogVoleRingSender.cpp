#include "libOTe/Vole/LogVole/LogVoleGpuCompatibility.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleTransport.h"
#include "libOTe/config.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include <cstddef>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
        task<> sendOfflineFrame(Socket& sock, Buffer payload, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark = {})
        {
            HostStep phase(profile, "setup transport: send offline frame", &cpuBenchmark);
            // Encoding creates a fresh, single-use buffer. Keep ownership in
            // the coroutine and hand it to coproto, avoiding a second complete
            // copy of the (potentially hundreds of MB) offline message.
            co_await detail::sendOwnedFrame(sock, std::move(payload));
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
            state.mRootKPrimeRtDevice.reset();
            state.mRootDPrimeRt.reset();
            state.mRootDPrimeHashValid = false;
            state.mPrecomputedTbk.reset();
            state.mPrecomputedTbkDevice.reset();
            state.mPrecomputedTbkCount = 0;
            if (state.mNextLevelState)
            {
                clearSenderOnlineCache(*state.mNextLevelState);
            }
        }

        task<> sendOfflineMessage(
            const Params& params,
            OfflineMessage& message,
            Socket& sock,
            bool isTopLevel,
            bool hasReusableState,
            bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark = {})
        {
            RecursiveMode mode{};
            if (!detail::recursiveMode(params, mode))
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
                Buffer payload;
                {
                    payload = message.mEncodedShrinkExpandMessage.empty()
                        ? encode(message.mShrinkExpandMessage,
                            params.mShrinkExpand.mNumWorkerThreads, params.mShrinkExpand.mTransport.mEncoding, useGpu, profile, cpuBenchmark)
                        : std::move(message.mEncodedShrinkExpandMessage);
                }
                co_await sendOfflineFrame(shrinkExpandSock, std::move(payload), profile, cpuBenchmark);
                if (!isTopLevel)
                {
                    childHasReusableState = true;
                }
            }

            if (mode == RecursiveMode::Root)
            {
                auto rootSock = sock.fork();
                Buffer payload = encode(message.mRootMessage,
                    params.mShrinkExpand.mNumWorkerThreads, params.mShrinkExpand.mTransport.mEncoding, useGpu, profile, cpuBenchmark);
                co_await sendOfflineFrame(rootSock, std::move(payload), profile, cpuBenchmark);
                co_return;
            }

            if (!message.mNextLevel)
            {
                throw std::runtime_error("LogVole sender missing recursive offline message");
            }

            Params child{};
            if (!detail::childParams(params, child))
            {
                throw std::runtime_error("LogVole sender could not derive child parameters");
            }

            auto childSock = sock.fork();
            co_await sendOfflineMessage(child, *message.mNextLevel,
                childSock, false, childHasReusableState, useGpu, profile, cpuBenchmark);
        }

        task<> senderOnlineService(
            SenderState& state,
            SenderState& precomputeRoot,
            Socket& sock,
            PRNG& prng,
            CommunicationStats& comm,
            ProtocolCacheScope senderScope, CpuBenchmarkState cpuBenchmark,
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers)
        {
            RecursiveMode mode{};
            if (!detail::recursiveMode(state.mParams, mode))
            {
                throw std::runtime_error("LogVole sender has invalid recursive online parameters");
            }

            if (mode == RecursiveMode::Root)
            {
                Buffer digestPayload;
                Buffer responsePayload;
                u64 responseFrameSize = 0;
                const bool nonInteractive = state.mParams.mOnlineMode == OnlineMode::NonInteractive;
                {
                    auto rootSock = sock.fork();
                    // k'_Rt is fresh sender randomness that does not depend on the
                    // digest, so it is drawn while the digest is still in flight.
                    // Supported GPU paths draw only the small parent seed on
                    // the host and finish device sampling before the suspension.
                    RnsPoly preKPrime{};
                    std::shared_ptr<void> preKPrimeDevice;
                    bool havePreK = false;
                    {
                        havePreK = !nonInteractive && sampleRootResponseKPrime(
                            state, prng, preKPrime, &preKPrimeDevice, senderScope);
                        if (havePreK || nonInteractive)
                        {
                            // Prepare the immutable SK cache and, if requested,
                            // a legacy host-key upload without replacing a
                            // freshly device-generated key.
                            std::shared_ptr<void> uploadedKPrime;
                            (void)prepareRootResponseDeviceOperands(
                                state, preKPrime, uploadedKPrime, senderScope);
                            if (!preKPrimeDevice)
                                preKPrimeDevice = std::move(uploadedKPrime);
                        }
                    }
                    {
                        HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "send: recv root digest", &cpuBenchmark);
                        u64 maxPayload = 0;
                        const bool validPayloadSize = rootDigestPayloadSize(state.mParams.mShrinkExpand.mRing, maxPayload);
                        digestPayload = co_await detail::recvFrame<ProtocolCacheRole::Sender>(rootSock, detail::requirePayloadSize(validPayloadSize, maxPayload), state.mParams.mShrinkExpand.mTransport.mEncoding.mWire, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), timingStats(state.mShrinkExpandState.mRingFactoryOwner));
                    }

                    RootDigestMessage digest{};
                    RootResponseMessage response{};
                    {
                        {
                            auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                            AutoTimer serTimer(timing ? &timing->mRootSerializeUs : nullptr);
                            if (!decode(digestPayload, digest, state.mParams.mShrinkExpand.mTransport.mEncoding, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), cpuBenchmark))
                            {
                                throw std::runtime_error("LogVole sender could not decode root digest");
                            }
                        }
                    }
                    {
                        HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "send: root response", &cpuBenchmark);
                        auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                        AutoTimer rootTimer(timing ? &timing->mRootSenderHostUs : nullptr);
                        auto preparation = prepareRootResponseSender(executor, buffers, state, std::move(digest),
                                    prng, response, &precomputeRoot, havePreK ? &preKPrime : nullptr,
                                    true, preKPrimeDevice, cpuBenchmark, senderScope);
                        if (!co_await std::move(preparation))
                            throw std::runtime_error("LogVole sender could not prepare root response");
                    }
                    {
                        if (!nonInteractive)
                        {
                            auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                            AutoTimer serTimer(timing ? &timing->mRootSerializeUs : nullptr);
                            responsePayload = encode(response, state.mParams.mShrinkExpand.mTransport.mEncoding, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), cpuBenchmark);
                        }
                    }
                    if (!nonInteractive)
                    {
                        responseFrameSize = detail::frameBytes(responsePayload);
                        HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "send: send root response", &cpuBenchmark);
                        co_await detail::sendOwnedFrame(rootSock, std::move(responsePayload));
                    }

                    // Deferred by prepareRootResponseSender: the reply is already
                    // on the wire, so the receiver runs its finalize while this
                    // runs instead of waiting for it.
                    if (state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed)
                    {
                        HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu sender: post-response precompute", &cpuBenchmark);
                        auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                        AutoTimer rootTimer(timing ? &timing->mRootSenderHostUs : nullptr);
                        auto precompute = senderPrecompute(executor, buffers,
                            precomputeRoot, prng, cpuBenchmark, senderScope);
                        if (!co_await std::move(precompute) || state.mGoldenSeed.empty())
                            throw std::runtime_error("LogVole sender could not prepare root response");
                    }
                }
                comm.mBytesSent += responseFrameSize;
                comm.mBytesReceived += detail::frameBytes(digestPayload);
                co_return;
            }

            if (!state.mNextLevelState)
            {
                throw std::runtime_error("LogVole sender missing recursive child state");
            }

            auto childSock = sock.fork();
            co_await senderOnlineService(*state.mNextLevelState,
                precomputeRoot, childSock, prng, comm, senderScope, cpuBenchmark, executor, buffers);
            if (!state.mPrecomputedTbk)
            {
                throw std::runtime_error("LogVole sender could not prepare recursive online cache");
            }
        }
    }

    task<> LogVoleRingSender::offline(macoro::thread_pool &executor, std::span<u8> setupResults,
                                      const ShrinkExpandSenderOfflineInput &input,
                                      ShrinkExpandSenderState &state, PRNG &prng, Socket &sock, ProtocolCacheScope cacheScope)
    {
        return offlineStart(executor, setupResults, input, state, prng, sock, std::move(cacheScope));
    }

    task<> LogVoleRingSender::offlineStart(macoro::thread_pool &executor, std::span<u8> setupResults,
                                           const ShrinkExpandSenderOfflineInput &input,
                                           ShrinkExpandSenderState &state, PRNG &prng, Socket &sock,
                                           ProtocolCacheScope cacheScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        cacheScope.mRole = ProtocolCacheRole::Sender;
        ShrinkExpandOfflineMessage message{};
        if (!co_await prepareShrinkExpandSenderOffline(executor, setupResults, input, prng, message, state,
                                                       cpuBenchmark, cacheScope))
        {
            throw std::runtime_error("LogVole sender could not prepare shrink/expand offline message");
        }

        auto payload = [&] {
            return encode(message, input.mParams.mNumWorkerThreads, input.mParams.mTransport.mEncoding,
                gpu::enabled(input.mRingFactoryOwner), hostProfiler(input.mRingFactoryOwner), cpuBenchmark);
        }();
        co_await sendOfflineFrame(sock, std::move(payload),
            hostProfiler(input.mRingFactoryOwner), cpuBenchmark);
    }

    task<> LogVoleRingSender::offline(macoro::thread_pool &executor, std::span<u8> setupResults,
                                      const SenderOfflineInput &input, SenderState &state, PRNG &prng,
                                      Socket &sock, ProtocolCacheScope cacheScope)
    {
        return offlineStart(executor, setupResults, input, state, prng, sock,
                            std::move(cacheScope));
    }

    task<> LogVoleRingSender::offlineStart(macoro::thread_pool &executor, std::span<u8> setupResults,
                                           const SenderOfflineInput &input, SenderState &state, PRNG &prng,
                                           Socket &sock, ProtocolCacheScope cacheScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        const ProtocolCacheRunId senderRunId = input.mSenderOwnerRunId ? input.mSenderOwnerRunId : cacheScope.mRunId;
        cacheScope = ProtocolCacheScope{senderRunId, ProtocolCacheRole::Sender};
        SenderOfflineOutput output{};
        {
            if (!co_await detail::prepareSenderOfflineForTransport(
                    executor, setupResults, input, prng, output, cpuBenchmark,
                    cacheScope))
            {
                throw std::runtime_error("LogVole sender could not prepare recursive offline state");
            }
        }

        co_await sendOfflineMessage(input.mParams, output.mMessage, sock, true, false,
                                    gpu::enabled(input.mRingFactoryOwner),
                                    hostProfiler(input.mRingFactoryOwner), cpuBenchmark);
        state = std::move(output.mState);
    }

    task<> LogVoleRingSender::keyDerive(
        const KeyDeriveSenderInput& input,
        KeyDeriveSenderOutput& output,
        Socket& sock, LogVoleEncodingOptions encoding, bool useGpu, HostStepProfiler* profile, ProtocolCacheScope scope,
        TimingStats* timing, RingOpsStats* totals)
    {
        CpuBenchmarkState cpuBenchmark{};

        scope.mRole = ProtocolCacheRole::Sender;
		u64 maxPayload = 0;
		if (input.mSk1.size() > std::numeric_limits<u32>::max())
			throw std::length_error("LogVole key-derive dimension is too large");
		const bool validPayloadSize =
			keyDerivePayloadSize(input.mParams, static_cast<u32>(input.mSk1.size()), maxPayload);
		const auto requestPayload =
			co_await detail::recvFrame<ProtocolCacheRole::Sender>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), encoding.mWire, useGpu, profile, timing);

        KeyDeriveRequest request{};
        if (!decode(requestPayload, request, encoding, useGpu, profile, cpuBenchmark))
        {
            throw std::runtime_error("LogVole sender could not decode key-derive request");
        }

        KeyDeriveResponse response{};
        {
            PendingRingOpsStats pending(totals);
            auto* stats = totals ? &pending : nullptr;
            if (!processKeyDeriveRequest(input, request, response, output, scope, stats))
                throw std::runtime_error("LogVole sender rejected key-derive request");
        }

        co_await detail::sendFrame(sock, encode(response, encoding, useGpu, profile, cpuBenchmark));
    }

    task<> LogVoleRingSender::online(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        SenderState& state, const SenderOnlineOptions& options,
        SenderOnlineOutput& output, PRNG& prng, Socket& sock, ProtocolCacheScope cacheScope)
    {
        return onlineStart(executor, buffers, state, options, output, prng, sock,
            std::move(cacheScope));
    }

    task<> LogVoleRingSender::onlineStart(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        SenderState& state, const SenderOnlineOptions& options,
        SenderOnlineOutput& output, PRNG& prng, Socket& sock, ProtocolCacheScope cacheScope)
    {
        if (!state.mShrinkExpandState.mRingFactoryOwner ||
            !state.mShrinkExpandState.mRingFactoryOwner->mFactory)
            throw std::runtime_error("LogVole online state has no identity resource owner");
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(state.mShrinkExpandState.mRingFactoryOwner)};
        if (cacheScope.mRunId == 0)
        {
            cacheScope = ProtocolCacheScope(state.mShrinkExpandState.mRingFactoryOwner->mFactory->protocolService()->allocate(),
                ProtocolCacheRole::Sender);
        }
        cacheScope.mRole = ProtocolCacheRole::Sender;
        HostStep onlineTotal(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "send: online TOTAL", &cpuBenchmark);
        {
            HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "send: clear cache + sid", &cpuBenchmark);
            if (!(options.mUsePrecomputed && senderHasPrecompute(state)))
            {
                clearSenderOnlineCache(state);
            }
            applySessionId(state, options.mSid);
        }

        std::exception_ptr serviceException{};
        CommunicationStats comm{};
        try
        {
            co_await senderOnlineService(state, state, sock, prng, comm, cacheScope, cpuBenchmark, executor, buffers);
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
        HostStep tailStep(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "send: online tail (tbk copy)", &cpuBenchmark);
        next.mSeed = state.mGoldenSeed;
        if (!options.mSkipTbkOutput)
        {
            next.mTbk = *state.mPrecomputedTbk;
            next.mTbkDevice = state.mPrecomputedTbkDevice;
            next.mTbkCount = state.mPrecomputedTbkCount;
        }
        next.mComm = comm;
        output = std::move(next);
    }

    task<> LogVoleRingSender::expand(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& output,
        Socket& sock, ProtocolCacheScope cacheScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(state.mRingFactoryOwner)};
        cacheScope.mRole = ProtocolCacheRole::Sender;
		u64 maxPayload = 0;
		const bool validPayloadSize = polyPayloadSize(state.mParams.mRing, maxPayload);
		const auto digestPayload =
			co_await detail::recvFrame<ProtocolCacheRole::Sender>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), state.mParams.mTransport.mEncoding.mWire, gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), timingStats(state.mRingFactoryOwner));

        RnsPoly digest{};
        Buffer responsePayload;
        {
            PolyMessage digestMessage{};
            if (!decode(digestPayload, digestMessage, state.mParams.mTransport.mEncoding, gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), cpuBenchmark))
            {
                throw std::runtime_error("LogVole sender received malformed shrink digest");
            }

            if (!readPolyMessage(state.mParams.mRing, digestMessage, digest))
            {
                throw std::runtime_error("LogVole sender rejected shrink digest metadata");
            }

            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mRing, ctx, state.mRingFactoryOwner, cacheScope))
            {
                throw std::runtime_error("LogVole sender could not build ring context");
            }

            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
            auto* stats = (ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr);
            RnsPoly skX{};
            bool skxOk = false;
            if (state.mParams.mTruncateOneGadgetDigit)
            {
                skxOk = deriveSkxTrunc(
                    ctx,
                    state.hostSk1(),
                    digest,
                    input.mTbkPrime,
                    state.mParams.mGadgetLogBase,
                    state.mParams.mTau,
                    skX, stats);
            }
            else
            {
                skxOk = deriveSkx(
                    ctx,
                    state.hostSk1(),
                    digest,
                    input.mTbkPrime,
                    state.mParams.mGadgetLogBase,
                    state.mParams.mTau,
                    skX, stats);
            }
            if (!skxOk)
            {
                throw std::runtime_error("LogVole sender could not derive shrink/expand key");
            }

            responsePayload = encode(makePolyMessage(state.mParams.mRing, skX), state.mParams.mTransport.mEncoding,
                gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), cpuBenchmark);
        }
        co_await detail::sendFrame(sock, std::move(responsePayload));

        ShrinkExpandExpandSenderInput expandInput = input;
        expandInput.mDigest = std::move(digest);
        bool expanded;
        if (gpu::enabled(state.mRingFactoryOwner))
        {
            expanded = detail::gpuLegacyExpandSender(state, expandInput, output,
                state.mParams.mNumWorkerThreads, cpuBenchmark, cacheScope);
        }
        else
            expanded = co_await shrinkExpandExpandSender(executor, buffers, state, expandInput, output, cpuBenchmark, cacheScope);
        if (!expanded)
        {
            throw std::runtime_error("LogVole sender could not expand");
        }
    }
}
