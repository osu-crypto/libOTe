#include <optional>
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"

#include "libOTe/config.h"

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleTransport.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
        bool setupMoveStateEnabled(bool requested, const std::shared_ptr<const RingNttContext>& owner)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            return requested && gpu::enabled(owner);
#else
            return false;
#endif
        }

        u64 countSeedInstances(const ReceiverState& state)
        {
            u32 tauHi = 0;
            if (!detail::computeTauHi(state.mParams, tauHi))
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

        const RnsPoly* resolveRootMaskDigest(const ReceiverState& state)
        {
            if (state.mRootDPrimeRt)
            {
                return state.mRootDPrimeRt.get();
            }

            return state.mNextLevelState ? resolveRootMaskDigest(*state.mNextLevelState) : nullptr;
        }

        const block* resolveRootMaskDigestHash(const ReceiverState& state)
        {
            if (state.mRootDPrimeRt && state.mRootDPrimeHashValid)
            {
                return &state.mRootDPrimeHash;
            }

            return state.mNextLevelState ? resolveRootMaskDigestHash(*state.mNextLevelState) : nullptr;
        }

        void applySessionId(ReceiverState& state, u64 sid)
        {
            state.mParams.mSessionId = sid;
            if (state.mNextLevelState)
            {
                applySessionId(*state.mNextLevelState, sid);
            }
        }

        void clearReceiverOnlineCache(ReceiverState& state)
        {
            state.mGoldenSeed.clear();
            state.mRootDPrimeRt.reset();
            state.mRootDPrimeHashValid = false;
            if (state.mNextLevelState)
            {
                clearReceiverOnlineCache(*state.mNextLevelState);
            }
        }

        // Root's 256 KiB digest hash is needed only after the response arrives.
        // Schedule the already-encoded digest first, then compute the hash while
        // the sender prepares its response. Disable mDeferRootDigestHash for
        // the exact historical call order; direct/Core callers remain eager.




#if defined(ENABLE_LOGVOLE_CUDA)
        void tryPrefetchRootFinalizeBase(
            const ReceiverState& state, RootDigestState& digestState, CpuBenchmarkState cpuBenchmark = {})
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const LogVoleGpuProtocolOptions gpuProtocolDefaults;
            const auto& gpuProtocolOptions = state.mShrinkExpandState.mRingFactoryOwner
                ? state.mShrinkExpandState.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : gpuProtocolDefaults;
#endif

            // The toggle check is first so default-off takes the exact legacy
            // path without constructing a context or touching a device cache.
            if (!gpu::rootFinalizeReceiverPrefetchEnabled(gpuProtocolOptions) || !gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner) ||
                digestState.mRootFinalizePrefetch ||
                !digestState.mLeftTreeGpu ||
                !digestState.mTopInputsNttGpu || !digestState.mGpuSession)
            {
                return;
            }

            u32 tauHi = 0u;
            RingNttContext ctx{};
            if (!detail::computeTauHi(state.mParams, tauHi) ||
                !makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx, state.mShrinkExpandState.mRingFactoryOwner))
            {
                return;
            }
            const u32 rho = static_cast<u32>(ringModulusCount(ctx));
            auto topInputs = std::static_pointer_cast<gpu::DeviceBatch>(
                digestState.mTopInputsNttGpu);
            auto dPrimeDevice = std::static_pointer_cast<gpu::DeviceBatch>(
                digestState.mDPrimeGpu);
            gpu::PreparedRootFinalizePtr prepared;
            {
                HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: prefetch finalize base", state.mParams.mW, &cpuBenchmark);
                (void)gpu::prefetchRootFinalizeReceiverDevice(
                    state,
                    ctx,
                    digestState.mDPrime,
                    topInputs,
                    digestState.mLeftTreeGpu,
                    tauHi,
                    rootLeftWidth(tauHi, rho),
                    prepared,
                    dPrimeDevice, cpuBenchmark);
            }

            // Even a failed enqueue can own partially queued work. Keep that
            // handle through recvFrame so cleanup never drains before the peer's
            // response computation has had a chance to overlap it.
            if (prepared)
            {
                digestState.mRootFinalizePrefetch = std::move(prepared);
            }
        }
#endif

        task<> recvOfflineMessage(
            const Params& params,
            OfflineMessage& message,
            Socket& sock,
            bool isTopLevel,
            bool hasReusableState, bool useGpu, std::shared_ptr<HostStepProfiler> profileOwner, CpuBenchmarkState cpuBenchmark = {})
        {
            auto* profile = profileOwner.get();
            RecursiveMode mode{};
            if (!detail::recursiveMode(params, mode))
            {
                throw std::runtime_error("LogVole receiver has invalid recursive offline parameters");
            }

            bool childHasReusableState = hasReusableState;
            if (hasReusableState)
            {
                message.mHasShrinkExpandMessage = false;
            }
            else
            {
                auto shrinkExpandSock = sock.fork();
				u64 maxPayload = 0;
				const bool validPayloadSize =
					shrinkExpandOfflinePayloadSize(params.mShrinkExpand, maxPayload);
				auto shrinkExpandPayload = co_await detail::recvFrame<ProtocolCacheRole::Receiver>(
					shrinkExpandSock, detail::requirePayloadSize(validPayloadSize, maxPayload), params.mShrinkExpand.mTransport.mEncoding.mWire, useGpu, profile);
                if (!decodeShrinkExpandOfflineForTransport(std::move(shrinkExpandPayload), message.mShrinkExpandMessage,
                        params.mShrinkExpand.mNumWorkerThreads, params.mShrinkExpand.mTransport.mEncoding, useGpu, profileOwner, cpuBenchmark))
                {
                    throw std::runtime_error("LogVole receiver could not decode shrink/expand offline message");
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
				u32 tauHi = 0;
				u64 maxPayload = 0;
				if (!detail::computeTauHi(params, tauHi))
					throw std::length_error("LogVole root dimension is invalid");
				const bool validPayloadSize =
					rootOfflinePayloadSize(params.mShrinkExpand, tauHi, maxPayload);
				auto rootPayload =
					co_await detail::recvFrame<ProtocolCacheRole::Receiver>(rootSock, detail::requirePayloadSize(validPayloadSize, maxPayload), params.mShrinkExpand.mTransport.mEncoding.mWire, useGpu, profile);
                if (!decodeRootOfflineForTransport(std::move(rootPayload),
                        message.mRootMessage, params.mShrinkExpand.mNumWorkerThreads, params.mShrinkExpand.mTransport.mEncoding, useGpu, profileOwner, cpuBenchmark))
                {
                    throw std::runtime_error("LogVole receiver could not decode root offline message");
                }
                co_return;
            }

            Params child{};
            if (!detail::childParams(params, child))
            {
                throw std::runtime_error("LogVole receiver could not derive child parameters");
            }

            message.mNextLevel = std::make_unique<OfflineMessage>();
            auto childSock = sock.fork();
            co_await recvOfflineMessage(child, *message.mNextLevel, childSock, false, childHasReusableState, useGpu, profileOwner, cpuBenchmark);
        }
    }

    struct LogVoleRingReceiver::OnlinePrefetchPlan
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::ReceiverFirstQueryAllocationsPtr mFirstQueryAllocations;
        const void* mFirstQueryOwner = nullptr;
        struct Target
        {
            const ShrinkExpandReceiverState* mState = nullptr;
            u64 mInstanceBase = 0;
            u32 mChunkCount = 0;
            bool mShrinkReady = false;
            gpu::PreparedReceiverCt2Ptr mPrepared;
        };

        std::vector<Target> mTargets; // outermost to innermost selected frame
        std::vector<u8> mSeed;
        block mMaskDigestHash{};
        u64 mSid = 0;
        bool mHashValid = false;
        bool mLaunchAttempted = false;

        void configure(ReceiverState& top, u64 sid)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const LogVoleGpuProtocolOptions gpuProtocolDefaults;
            const auto& gpuProtocolOptions = top.mShrinkExpandState.mRingFactoryOwner
                ? top.mShrinkExpandState.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : gpuProtocolDefaults;
#endif

            mSid = sid;
            if (!gpu::enabled(top.mShrinkExpandState.mRingFactoryOwner)) return;

            constexpr u32 kMaxPrefetchLevels = 3u;
            ReceiverState* cursor = &top;
            while (cursor && mTargets.size() < kMaxPrefetchLevels)
            {
                u32 tauHi = 0;
                RecursiveMode mode{};
                if (!detail::computeTauHi(cursor->mParams, tauHi) ||
                    !detail::recursiveMode(cursor->mParams, mode) || mode == RecursiveMode::Root ||
                    !cursor->mNextLevelState)
                {
                    break;
                }

                const u32 rho = static_cast<u32>(
                    cursor->mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
                const u32 muHi = cursor->mParams.mShrinkExpand.mAlpha * tauHi * rho;
                if (rho == 0u || muHi == 0u) break;
                const u32 chunkCount = (cursor->mParams.mW + muHi - 1u) / muHi;
                const u64 instanceBase = countSeedInstances(*cursor->mNextLevelState);
                if (chunkCount == 0u || instanceBase == 0u) break;

                mTargets.push_back(Target{
                    &cursor->mShrinkExpandState, instanceBase, chunkCount, false, nullptr });
                cursor = cursor->mNextLevelState.get();
            }

            std::array<const ShrinkExpandReceiverState*, kMaxPrefetchLevels> states{};
            std::array<u32, kMaxPrefetchLevels> chunkCounts{};
            for (std::size_t i = 0; i < mTargets.size(); ++i)
            {
                states[i] = mTargets[i].mState;
                chunkCounts[i] = mTargets[i].mChunkCount;
            }
            const u32 requested = gpu::receiverCt2PrefetchLevels(
                top.mParams.mTotalLabelCount,
                std::span<const ShrinkExpandReceiverState* const>(
                    states.data(), mTargets.size()),
                std::span<const u32>(chunkCounts.data(), mTargets.size()), gpuProtocolOptions);
            if (requested == 0u)
            {
                mTargets.clear();
                return;
            }
            if (mTargets.size() > requested) mTargets.resize(requested);
        }

        void markShrinkReady(
            const ShrinkExpandReceiverState& state, u32 chunkCount, bool ready)
        {
            for (auto& target : mTargets)
            {
                if (target.mState == &state)
                {
                    target.mShrinkReady = ready && target.mChunkCount == chunkCount;
                    return;
                }
            }
        }

        void launchAfterRoot(
            const ReceiverState& current,
            std::span<const u8> seed,
            u64 sid)
        {
            if (mLaunchAttempted) return;
            mLaunchAttempted = true;
            if (mTargets.empty() || sid != mSid || seed.empty()) return;
            const block* digestHash = resolveRootMaskDigestHash(current);
            if (!digestHash) return;
            mSeed.assign(seed.begin(), seed.end());
            mMaskDigestHash = *digestHash;
            mHashValid = true;

            // The recursion unwinds inner-to-outer. Queue W512 before W1024
            // before W2048 so every selected output gets the longest useful lead
            // before its matching expansion reaches the event wait.
            for (auto it = mTargets.rbegin(); it != mTargets.rend(); ++it)
            {
                if (!it->mShrinkReady || !it->mState) continue;
                (void)gpu::prefetchReceiverCt2(
                    *it->mState, seed, sid, it->mInstanceBase, *digestHash,
                    it->mChunkCount, it->mPrepared);
            }
        }

        gpu::PreparedReceiverCt2* preparedFor(
            const ShrinkExpandReceiverState& state,
            std::span<const u8> seed,
            u64 sid,
            u64 instanceBase,
            block maskDigestHash,
            u32 chunkCount)
        {
            const bool sameSeed = mSeed.size() == seed.size() &&
                                  std::equal(seed.begin(), seed.end(), mSeed.begin());
            if (!mLaunchAttempted || !mHashValid || sid != mSid || !sameSeed ||
                std::memcmp(
                    &mMaskDigestHash, &maskDigestHash, sizeof(maskDigestHash)) != 0)
            {
                return nullptr;
            }
            for (auto& target : mTargets)
            {
                if (target.mState == &state && target.mInstanceBase == instanceBase &&
                    target.mChunkCount == chunkCount)
                {
                    return target.mPrepared.get();
                }
            }
            return nullptr;
        }
#else
        void configure(ReceiverState&, u64) {}
#endif
    };

    task<> LogVoleRingReceiver::offline(
        const ShrinkExpandReceiverOfflineInput& input,
        ShrinkExpandReceiverState& state,
        Socket& sock)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
		u64 maxPayload = 0;
		const bool validPayloadSize = shrinkExpandOfflinePayloadSize(input.mParams, maxPayload);
		const auto payload = co_await detail::recvFrame<ProtocolCacheRole::Receiver>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), input.mParams.mTransport.mEncoding.mWire, gpu::enabled(input.mRingFactoryOwner), hostProfiler(input.mRingFactoryOwner));

        ShrinkExpandOfflineMessage message{};
        if (!decode(payload, message, input.mParams.mNumWorkerThreads, input.mParams.mTransport.mEncoding, gpu::enabled(input.mRingFactoryOwner), hostProfiler(input.mRingFactoryOwner), cpuBenchmark))
        {
            throw std::runtime_error("LogVole receiver received malformed shrink/expand offline message");
        }

        const bool finalized = setupMoveStateEnabled(input.mParams.mTransport.mMoveReceivedState, input.mRingFactoryOwner)
            ? finalizeShrinkExpandReceiverOffline(input, std::move(message), state)
            : finalizeShrinkExpandReceiverOffline(input, message, state);
        if (!finalized)
        {
            throw std::runtime_error("LogVole receiver rejected shrink/expand offline message");
        }
    }

    task<> LogVoleRingReceiver::offline(
        const ReceiverOfflineInput& input,
        ReceiverState& state,
        Socket& sock,
        std::shared_ptr<void>* firstQueryGpuAllocations)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
#if defined(ENABLE_LOGVOLE_CUDA)
        // The application total timer is already running when offline begins.
        // Reserve receiver-only first-query storage while the copied TCP setup
        // is still in flight; publication waits for the worker before online.
        auto firstQueryPlan = firstQueryGpuAllocations && gpu::enabled(input.mRingFactoryOwner)
            ? gpu::beginReceiverFirstQueryAllocations(input.mParams, input.mRingFactoryOwner)
            : gpu::ReceiverFirstQueryAllocationsPtr{};
#endif
        OfflineMessage message{};
        co_await recvOfflineMessage(input.mParams, message, sock, true, false, gpu::enabled(input.mRingFactoryOwner), hostProfilerOwner(input.mRingFactoryOwner), cpuBenchmark);

        ReceiverOfflineOutput output{};
        const bool finalized = setupMoveStateEnabled(input.mParams.mShrinkExpand.mTransport.mMoveReceivedState, input.mRingFactoryOwner)
            ? finalizeReceiverOffline(input, std::move(message), output, cpuBenchmark)
            : finalizeReceiverOffline(input, message, output, cpuBenchmark);
        if (!finalized)
        {
            throw std::runtime_error("LogVole receiver rejected recursive offline message");
        }

        state = std::move(output.mState);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (firstQueryPlan)
        {
            gpu::finishReceiverFirstQueryAllocations(firstQueryPlan);
            *firstQueryGpuAllocations = std::move(firstQueryPlan);
        }
#endif
    }

    task<> LogVoleRingReceiver::keyDerive(
        const KeyDeriveReceiverInput& input,
        KeyDeriveReceiverOutput& output,
        Socket& sock, LogVoleEncodingOptions encoding, bool useGpu, HostStepProfiler* profile)
    {
        CpuBenchmarkState cpuBenchmark{};
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        KeyDeriveRequest request{};
        if (!prepareKeyDeriveRequest(input, request))
        {
            throw std::runtime_error("LogVole receiver could not prepare key-derive request");
        }

        co_await detail::sendFrame(sock, encode(request, encoding, useGpu, profile, cpuBenchmark));

		u64 maxPayload = 0;
		const bool validPayloadSize = keyDerivePayloadSize(input.mParams, request.mTau, maxPayload);
		const auto responsePayload =
			co_await detail::recvFrame<ProtocolCacheRole::Receiver>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), encoding.mWire, useGpu, profile);

        KeyDeriveResponse response{};
        if (!decode(responsePayload, response, encoding, useGpu, profile, cpuBenchmark))
        {
            throw std::runtime_error("LogVole receiver could not decode key-derive response");
        }

        if (!finalizeKeyDeriveResponse(input, response, output))
        {
            throw std::runtime_error("LogVole receiver rejected key-derive response");
        }
    }

    task<> LogVoleRingReceiver::online(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers,
        ReceiverState& state, const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
        std::shared_ptr<void> firstQueryGpuAllocations, const void* firstQueryOwner)
    {
        return onlineStart(&executor, lheBuffers, lencBuffers, state, input, output,
            prng, sock, std::move(firstQueryGpuAllocations), firstQueryOwner);
    }

    task<> LogVoleRingReceiver::online(
        ReceiverState& state, const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
        const std::shared_ptr<void>& firstQueryGpuAllocations, const void* firstQueryOwner)
    {
        return onlineStart(nullptr, {}, {}, state, input, output, prng, sock,
            firstQueryGpuAllocations, firstQueryOwner);
    }

    task<> LogVoleRingReceiver::onlineStart(
        macoro::thread_pool* executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers,
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output,
        PRNG& prng,
        Socket& sock,
        std::shared_ptr<void> firstQueryGpuAllocations,
        const void* firstQueryOwner)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(state.mShrinkExpandState.mRingFactoryOwner)};
        OnlinePrefetchPlan prefetchPlan;
#if defined(ENABLE_LOGVOLE_CUDA)
        prefetchPlan.mFirstQueryAllocations =
            std::static_pointer_cast<gpu::ReceiverFirstQueryAllocations>(
                firstQueryGpuAllocations);
        prefetchPlan.mFirstQueryOwner = firstQueryOwner;
#endif
        prefetchPlan.configure(state, input.mSid);
        auto cacheScope = currentProtocolCacheScope();
        if (!cacheScope.mRunId) cacheScope.mRunId = allocateProtocolCacheRunId();
        cacheScope.mRole = ProtocolCacheRole::Receiver;
        co_await onlineImpl(state, input, output, prng, sock, prefetchPlan, 0u,
            cpuBenchmark, executor, lheBuffers, lencBuffers, cacheScope);
    }

    task<> LogVoleRingReceiver::onlineImpl(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output,
        PRNG& prng,
        Socket& sock,
        OnlinePrefetchPlan& prefetchPlan,
        u32 recursionDepth, CpuBenchmarkState cpuBenchmark,
        macoro::thread_pool* executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers, ProtocolCacheScope cacheScope)
    {
        // Active only during synchronous regions, never while this frame is suspended.
        std::optional<ScopedProtocolCacheScope> scopedCache(std::in_place, cacheScope);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (recursionDepth == 0u && prefetchPlan.mFirstQueryAllocations)
            gpu::bindReceiverFirstQueryOnlineRun(
                prefetchPlan.mFirstQueryAllocations,
                prefetchPlan.mFirstQueryOwner, input.mSid, cacheScope.mRunId);
#endif
        HostStep levelTotal(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "lvl: TOTAL", state.mParams.mW, &cpuBenchmark);
        clearReceiverOnlineCache(state);
        applySessionId(state, input.mSid);

        u32 tauHi = 0;
        if (!detail::computeTauHi(state.mParams, tauHi))
        {
            throw std::runtime_error("LogVole receiver has invalid recursive online parameters");
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 muHi = state.mParams.mShrinkExpand.mAlpha * tauHi * rho;
        RecursiveMode mode{};
        if (rho == 0 || muHi == 0 || !detail::recursiveMode(state.mParams, mode))
        {
            throw std::runtime_error("LogVole receiver has invalid recursive online shape");
        }

        if (mode == RecursiveMode::Root)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            // Since the Root's shrink runs on the device (5.2.17) its input can stay
            // there: prepareRootDigestReceiver takes the device batch directly. Only
            // fetch it when the GPU backend is unavailable and the host path will run,
            // otherwise this was a device -> host -> device round trip of the input.
            if (input.mX.empty() && input.mXDevice && !gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner))
            {
                auto dev = std::static_pointer_cast<gpu::DeviceBatch>(input.mXDevice);
                auto& mutableInput = const_cast<ReceiverOnlineInput&>(input);
                const auto& owner = state.mShrinkExpandState.mRingFactoryOwner;
                if (!owner || !owner->mGpuExecution ||
                    !gpu::download(*dev, mutableInput.mX, gpu::contextStream(*owner),
                        static_cast<std::size_t>(input.mXCount)))
                {
                    throw std::runtime_error("LogVole receiver could not fetch root input");
                }
            }
#endif
            Buffer digestPayload;
            Buffer responsePayload;
            u64 digestFrameSize = 0;
            const bool nonInteractive = state.mParams.mOnlineMode == OnlineMode::NonInteractive;
            {
                auto rootSock = sock.fork();
                const bool ownedFastPath = state.mParams.mShrinkExpand.mTransport.mOwnedRootMessages;
                RootDigestState digestState{};
                RootDigestMessage digest{};
                const bool deferDigestHash = state.mParams.mShrinkExpand.mTransport.mDeferRootDigestHash;
                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: prepare digest", state.mParams.mW, &cpuBenchmark);
                    AutoTimer rootTimer(globalTimingStats.mRootReceiverHostUs);
                    if (!prepareRootDigestReceiver(
                            state, input.mX, prng, digestState, digest,
                            input.mXDevice, input.mXCount, deferDigestHash, cpuBenchmark))
                    {
                        throw std::runtime_error("LogVole receiver could not prepare root digest");
                    }
                }

                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: encode digest", state.mParams.mW, &cpuBenchmark);
                    AutoTimer serTimer(globalTimingStats.mRootSerializeUs);
                    digestPayload = encode(digest, state.mParams.mShrinkExpand.mTransport.mEncoding, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), cpuBenchmark);
                }
                digestFrameSize = detail::frameBytes(digestPayload);
                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: send digest", state.mParams.mW, &cpuBenchmark);
                    scopedCache.reset();
                    if (ownedFastPath)
                    {
                        co_await detail::sendOwnedFrame(rootSock, std::move(digestPayload));
                    }
                    else
                    {
                        co_await detail::sendFrame(rootSock, digestPayload);
                    }
                    scopedCache.emplace(cacheScope);
                }

#if defined(ENABLE_LOGVOLE_CUDA)
                // The arithmetic prefix needs dPrime but not its transcript
                // hash. Queue it before the deferred CPU hash so those six
                // kernels can run under the hash. digestState owns dPrime and
                // every device input; its last-declared prepared handle drains
                // abandoned work first if hashing or the socket later fails.
                tryPrefetchRootFinalizeBase(state, digestState, cpuBenchmark);
#endif

                // sendFrame has handed an owned copy to coproto before it
                // resumes us. Hashing remains synchronous on this coroutine;
                // only after it succeeds does mDPrimeHash become authoritative
                // for response validation and the seed-dependent CT2 suffix.
                if (deferDigestHash && !finishRootDigestHash(digestState,
                        rootProfiler(state.mShrinkExpandState.mRingFactoryOwner)))
                {
                    throw std::runtime_error("LogVole receiver could not hash root digest");
                }

                RootResponseMessage response{};
                if (nonInteractive)
                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: derive public response", state.mParams.mW, &cpuBenchmark);
                    if (!deriveNonInteractiveRootResponse(state.mParams, digestState.mDPrime, response, state.mShrinkExpandState.mRingFactoryOwner))
                        throw std::runtime_error("LogVole receiver could not derive non-interactive response");
                }
                else
                {
                    {
                        HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: wait for sender response", state.mParams.mW, &cpuBenchmark);
                        u64 maxPayload = 0;
                        const bool validPayloadSize = rootResponsePayloadSize(state.mParams.mShrinkExpand.mRing, maxPayload);
                        scopedCache.reset();
                        responsePayload = co_await detail::recvFrame<ProtocolCacheRole::Receiver>(rootSock, detail::requirePayloadSize(validPayloadSize, maxPayload), state.mParams.mShrinkExpand.mTransport.mEncoding.mWire, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner));
                        scopedCache.emplace(cacheScope);
                    }
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: decode response", state.mParams.mW, &cpuBenchmark);
                    AutoTimer serTimer(globalTimingStats.mRootSerializeUs);
                    if (!decode(responsePayload, response, state.mParams.mShrinkExpand.mTransport.mEncoding, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), cpuBenchmark))
                        throw std::runtime_error("LogVole receiver could not decode root response");
                }

                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: finalize", state.mParams.mW, &cpuBenchmark);
                    AutoTimer rootTimer(globalTimingStats.mRootReceiverHostUs);
                    bool finalized;
                    if (executor)
                    {
                        auto operation = finalizeRootOnlineReceiver(*executor, lheBuffers, lencBuffers,
                            state, input, digestState,
                            ownedFastPath ? std::move(response) : RootResponseMessage(response), output, cpuBenchmark);
                        scopedCache.reset();
                        finalized = co_await std::move(operation);
                        scopedCache.emplace(cacheScope);
                    }
                    else
                        finalized = ownedFastPath
                            ? finalizeRootOnlineReceiver(state, input, digestState, std::move(response), output, cpuBenchmark)
                            : finalizeRootOnlineReceiver(state, input, digestState, response, output, cpuBenchmark);
                    if (!finalized)
                    {
                        throw std::runtime_error("LogVole receiver could not finalize root online");
                    }
                }
#if defined(ENABLE_LOGVOLE_CUDA)
                // Root is the first point where both the accepted online seed
                // and the exact mask-digest hash are authoritative. Queue the
                // selected ancestor batches here, deepest-needed-first, while
                // recursion still has W16..W256 work left to unwind.
                prefetchPlan.launchAfterRoot(
                    state,
                    std::span<const u8>(output.mSeed.data(), output.mSeed.size()),
                    input.mSid);
#endif
            }
            output.mComm.mBytesSent = digestFrameSize;
            output.mComm.mBytesReceived = nonInteractive ? 0 : detail::frameBytes(responsePayload);
            co_return;
        }

        if (!state.mNextLevelState || receiverInputCount(input) != state.mParams.mW)
        {
            throw std::runtime_error("LogVole receiver missing recursive child state");
        }

        const u32 wDoublePrime = (state.mParams.mW + muHi - 1u) / muHi;
        const u32 wNext = wDoublePrime * tauHi * rho;
        const u32 wPrime =
            (state.mParams.mW + state.mParams.mShrinkExpand.mAlpha - 1u) /
            state.mParams.mShrinkExpand.mAlpha;

        HostStep shrinkPhase(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu receiver: shrink", state.mParams.mW, &cpuBenchmark);

        std::vector<std::vector<RnsPoly>> dHatChunks(wDoublePrime);
        std::vector<RnsPoly> digests(wDoublePrime);
        std::vector<std::shared_ptr<DigestTree>> trees(wDoublePrime);

#if defined(ENABLE_LOGVOLE_CUDA)
        // The GPU path batches every chunk of this level into single kernel
        // launches and keeps the digest trees device resident until the matching
        // expand below.
        gpu::LevelSession gpuSession;
        gpu::DeviceBatchPtr gpuDHat;
        bool gpuShrinkDone = false;
        if (gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner))
        {
            HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "lvl: gpu shrink", state.mParams.mW, &cpuBenchmark);
            const auto xDev = input.mXDevice
                ? std::static_pointer_cast<gpu::DeviceBatch>(input.mXDevice)
                : gpu::DeviceBatchPtr{};
            gpuShrinkDone = gpu::shrinkChunksDevice(
                state.mShrinkExpandState,
                xDev ? std::span<const RnsPoly>() : std::span<const RnsPoly>(input.mX.data(), input.mX.size()),
                xDev.get(),
                static_cast<u32>(receiverInputCount(input)),
                muHi,
                tauHi,
                gpuSession,
                gpuDHat,
                recursionDepth < 3u,
                recursionDepth == 0u ? prefetchPlan.mFirstQueryAllocations.get() : nullptr,
                recursionDepth == 0u ? prefetchPlan.mFirstQueryOwner : nullptr,
                recursionDepth == 0u ? input.mSid : 0);
        }
        prefetchPlan.markShrinkReady(
            state.mShrinkExpandState, wDoublePrime, gpuShrinkDone);
        if (!gpuShrinkDone)
        {
#endif
        const bool shrinkOk = detail::runParallelTasks(
            wDoublePrime,
            state.mParams.mShrinkExpand.mNumWorkerThreads,
            [&](std::size_t taskIdx, CpuBenchmarkState& cpuBenchmark) {
                const auto chunkIdx = static_cast<u32>(taskIdx);
                const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                const std::size_t end = std::min<std::size_t>(start + static_cast<std::size_t>(muHi), receiverInputCount(input));

                if (start > end)
                {
                    return false;
                }

                const std::size_t chunkSize = end - start;
                std::vector<RnsPoly> paddedChunk;
                std::span<const RnsPoly> chunk;
                if (chunkSize == static_cast<std::size_t>(muHi))
                {
                    chunk = std::span<const RnsPoly>(input.mX.data() + start, chunkSize);
                }
                else
                {
                    paddedChunk.resize(muHi);
                    for (std::size_t i = 0; i < chunkSize; ++i)
                    {
                        paddedChunk[i] = input.mX[start + i];
                    }
                    for (std::size_t i = chunkSize; i < paddedChunk.size(); ++i)
                    {
                        resizeZero(
                            paddedChunk[i].mCoeffs,
                            ringPolyCoeffCount(state.mParams.mShrinkExpand.mRing));
                    }
                    chunk = std::span<const RnsPoly>(paddedChunk.data(), paddedChunk.size());
                }

                ShrinkExpandShrinkOutput shrink{};
                std::vector<RnsPoly> decomposed;
                HostStep treeStep(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu shrink worker: digest tree", &cpuBenchmark);
                if (!shrinkExpandShrink(state.mShrinkExpandState, chunk, shrink)) return false;
                treeStep.stop();
                HostStep unbundleStep(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu shrink worker: unbundle", &cpuBenchmark);
                if (!seedLabelGadgetDecomposeHiAndUnbundle(
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
            }, false, &cpuBenchmark);
        if (!shrinkOk)
        {
            throw std::runtime_error("LogVole receiver could not prepare recursive child input");
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        }
#endif

        std::vector<RnsPoly> dHat;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!gpuShrinkDone)
#endif
        {
            dHat.resize(wNext);
            std::size_t dHatIdx = 0;
            for (auto& chunk : dHatChunks)
            {
                if (chunk.size() != static_cast<std::size_t>(tauHi) * rho ||
                    dHatIdx + chunk.size() > dHat.size())
                {
                    throw std::runtime_error("LogVole receiver recursive child input shape mismatch");
                }
                for (auto& poly : chunk)
                {
                    dHat[dHatIdx++] = std::move(poly);
                }
            }
            if (dHatIdx != dHat.size())
            {
                throw std::runtime_error("LogVole receiver recursive child input size mismatch");
            }
        }

        ReceiverOnlineInput childInput{};
        childInput.mSid = input.mSid;
        childInput.mXCount = wNext;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpuShrinkDone && gpuDHat && gpuDHat->count() == wNext)
        {
            childInput.mXDevice = gpuDHat;
        }
        else
#endif
        {
            childInput.mX = std::move(dHat);
        }

        ReceiverOnlineOutput childOutput{};
        auto childSock = sock.fork();
        shrinkPhase.stop();
        {
            HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "lvl: child online", state.mParams.mW, &cpuBenchmark);
            scopedCache.reset();
            co_await onlineImpl(
                *state.mNextLevelState, childInput, childOutput, prng, childSock,
                prefetchPlan, recursionDepth + 1u, cpuBenchmark,
                executor, lheBuffers, lencBuffers, cacheScope);
            scopedCache.emplace(cacheScope);
        }

        HostStep derivePhase(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu receiver: denoise and aggregate", state.mParams.mW, &cpuBenchmark);
        std::vector<RnsPoly> skXHat;
        std::vector<RnsPoly> skX;
#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::DeviceBatchPtr skXDev;
        if (gpuShrinkDone)
        {
            HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "lvl: denoiseAndAgg", state.mParams.mW, &cpuBenchmark);
            RingNttContext gpuCtx{};
            if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, gpuCtx, state.mShrinkExpandState.mRingFactoryOwner))
            {
                throw std::runtime_error("LogVole receiver could not build ring context");
            }

            auto childDev = childOutput.mTbmDevice
                ? std::static_pointer_cast<gpu::DeviceBatch>(childOutput.mTbmDevice)
                : gpu::DeviceBatchPtr{};
            if (!childDev && !childOutput.mTbm.empty())
            {
                // The root level runs on the host, so its (small) output is
                // lifted onto the device here. That is what lets every level
                // above the root keep its chain device resident.
                childDev = gpu::upload(
                    gpuCtx,
                    std::span<const RnsPoly>(childOutput.mTbm.data(), childOutput.mTbm.size()));
            }

            if (!childDev ||
                !gpu::denoiseAndAggDevice(
                    gpuCtx, *childDev, tauHi, skXDev, childOutput.mTbmCount) ||
                !skXDev || skXDev->count() != wDoublePrime)
            {
                throw std::runtime_error("LogVole receiver could not derive recursive expansion keys");
            }
        }
        else
#endif
        if (!seedLabelDenoiseTbm(
                childOutput.mTbm,
                wPrime,
                tauHi,
                state.mParams.mShrinkExpand.mRing,
                skXHat,
                state.mParams.mShrinkExpand.mNumWorkerThreads, cpuBenchmark) ||
            !seedLabelAgg(
                std::move(skXHat),
                wDoublePrime,
                tauHi,
                state.mParams.mShrinkExpand.mRing,
                skX) ||
            skX.size() != wDoublePrime)
        {
            throw std::runtime_error("LogVole receiver could not derive recursive expansion keys");
        }

        const u64 instanceBase = countSeedInstances(*state.mNextLevelState);
        const RnsPoly* rootMaskDigest = resolveRootMaskDigest(state);
        const block* rootMaskDigestHash = resolveRootMaskDigestHash(state);
        if (rootMaskDigest == nullptr || rootMaskDigestHash == nullptr)
        {
            throw std::runtime_error("LogVole receiver missing root mask digest");
        }

        std::vector<RnsPoly> finalTbm(state.mParams.mW);

#if defined(ENABLE_LOGVOLE_CUDA)
        auto* preparedReceiverCt2 = prefetchPlan.preparedFor(
            state.mShrinkExpandState,
            std::span<const u8>(childOutput.mSeed.data(), childOutput.mSeed.size()),
            input.mSid,
            instanceBase,
            *rootMaskDigestHash,
            wDoublePrime);
        bool gpuExpandDone = false;
        gpu::DeviceBatchPtr gpuTbm;
        if (gpuShrinkDone && skXDev)
        {
            HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "lvl: gpu expand", state.mParams.mW, &cpuBenchmark);
            // Fully device resident: skX came out of the child level without
            // touching the host and the result is handed to the parent the same
            // way.
            gpuExpandDone = gpu::expandReceiverChunksDevice(
                state.mShrinkExpandState,
                gpuSession,
                *skXDev,
                std::span<const u8>(childOutput.mSeed.data(), childOutput.mSeed.size()),
                input.mSid,
                instanceBase,
                *rootMaskDigestHash,
                muHi,
                state.mParams.mW,
                gpuTbm,
                preparedReceiverCt2);
            if (!gpuExpandDone)
            {
                throw std::runtime_error("LogVole receiver GPU expand failed");
            }
        }
        else if (gpuShrinkDone)
        {
            gpuExpandDone = gpu::expandReceiverChunks(
                state.mShrinkExpandState,
                gpuSession,
                std::span<const RnsPoly>(skX.data(), skX.size()),
                std::span<const u8>(childOutput.mSeed.data(), childOutput.mSeed.size()),
                input.mSid,
                instanceBase,
                *rootMaskDigestHash,
                muHi,
                state.mParams.mW,
                finalTbm,
                preparedReceiverCt2);
            if (!gpuExpandDone)
            {
                throw std::runtime_error("LogVole receiver GPU expand failed");
            }
        }
        if (!gpuExpandDone)
        {
#endif
        derivePhase.stop();
        HostStep expandPhase(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu receiver: expand", state.mParams.mW, &cpuBenchmark);
        // Parallelize across chunks; only a single chunk may start row workers.
        const u32 cpuRowWorkers = wDoublePrime > 1 ? 1 : state.mParams.mShrinkExpand.mNumWorkerThreads;
        const bool expandOk = detail::runParallelTasks(
            wDoublePrime,
            state.mParams.mShrinkExpand.mNumWorkerThreads,
            [&](std::size_t taskIdx, CpuBenchmarkState& cpuBenchmark) {
                const auto chunkIdx = static_cast<u32>(taskIdx);
                const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                const std::size_t end = std::min<std::size_t>(start + static_cast<std::size_t>(muHi), receiverInputCount(input));

                ShrinkExpandExpandReceiverInput expandInput{};
                expandInput.mSeed = childOutput.mSeed;
                expandInput.mSid = input.mSid;
                expandInput.mNonce = instanceBase + chunkIdx;
                expandInput.mDigest = digests[chunkIdx];
                expandInput.mMaskDigest = *rootMaskDigest;
                expandInput.mSkX = skX[chunkIdx];
                expandInput.mTree = trees[chunkIdx];

                ShrinkExpandReceiverExpandOutput expandOutput{};
                if (!shrinkExpandExpandReceiver(state.mShrinkExpandState, expandInput, expandOutput, cpuRowWorkers, cpuBenchmark) ||
                    expandOutput.mTbm.size() < end - start)
                {
                    return false;
                }

                for (std::size_t itemIdx = 0; itemIdx < end - start; ++itemIdx)
                {
                    finalTbm[start + itemIdx] = std::move(expandOutput.mTbm[itemIdx]);
                }
                return true;
            }, false, &cpuBenchmark);
        if (!expandOk)
        {
            throw std::runtime_error("LogVole receiver could not expand recursive chunk");
        }
        expandPhase.stop();
#if defined(ENABLE_LOGVOLE_CUDA)
        }
#endif

        ReceiverOnlineOutput next{};
        next.mSeed = childOutput.mSeed;
        next.mComm = childOutput.mComm;
        next.mTbmCount = state.mParams.mW;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpuTbm)
        {
            // Hand the level's output up as a device batch; only the outermost
            // caller (civoleReceiverSetX) materialises it on the host.
            next.mTbmDevice = gpuTbm;
        }
        else
#endif
        {
            next.mTbm = std::move(finalTbm);
        }
        output = std::move(next);
    }

    task<> LogVoleRingReceiver::expand(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers,
        const ShrinkExpandReceiverState& state,
        const ReceiverExpandInput& input,
        ShrinkExpandReceiverExpandOutput& output,
        Socket& sock)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(state.mRingFactoryOwner)};
        const ProtocolCacheScope cacheScope{currentProtocolCacheScope().mRunId, ProtocolCacheRole::Receiver};
        ShrinkExpandShrinkOutput shrink{};
        Buffer digestPayload;
        {
            ScopedProtocolCacheScope roleScope(cacheScope);
            if (!shrinkExpandShrink(state, input.mX, shrink))
            {
                throw std::runtime_error("LogVole receiver could not shrink");
            }

            digestPayload = encode(makePolyMessage(state.mParams.mRing, shrink.mDigest), state.mParams.mTransport.mEncoding,
                gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), cpuBenchmark);
        }
        co_await detail::sendFrame(sock, std::move(digestPayload));

		u64 maxPayload = 0;
		const bool validPayloadSize = polyPayloadSize(state.mParams.mRing, maxPayload);
		const auto skXPayload =
			co_await detail::recvFrame<ProtocolCacheRole::Receiver>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), state.mParams.mTransport.mEncoding.mWire, gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner));

        RnsPoly skX{};
        {
            ScopedProtocolCacheScope roleScope(cacheScope);
            PolyMessage skXMessage{};
            if (!decode(skXPayload, skXMessage, state.mParams.mTransport.mEncoding, gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), cpuBenchmark))
            {
                throw std::runtime_error("LogVole receiver received malformed shrink/expand key");
            }

            if (!readPolyMessage(state.mParams.mRing, skXMessage, skX))
            {
                throw std::runtime_error("LogVole receiver rejected shrink/expand key metadata");
            }

        }
        ShrinkExpandExpandReceiverInput coreInput{};
        coreInput.mNonce = input.mNonce;
        coreInput.mSeed = input.mSeed;
        coreInput.mSid = input.mSid;
        coreInput.mDigest = std::move(shrink.mDigest);
        coreInput.mSkX = std::move(skX);
        coreInput.mTree = std::move(shrink.mTree);

        bool expanded;
        if (gpu::enabled(state.mRingFactoryOwner))
        {
            ScopedProtocolCacheScope roleScope(cacheScope);
            expanded = shrinkExpandExpandReceiver(state, coreInput, output,
                state.mParams.mNumWorkerThreads, cpuBenchmark);
        }
        else
            expanded = co_await shrinkExpandExpandReceiver(executor, lheBuffers, lencBuffers,
                state, coreInput, output, cpuBenchmark);
        if (!expanded)
        {
            throw std::runtime_error("LogVole receiver could not expand");
        }
    }
}
