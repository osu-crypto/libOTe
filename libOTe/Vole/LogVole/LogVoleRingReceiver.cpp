#include "libOTe/Vole/LogVole/LogVoleGpuCompatibility.h"
#include <optional>
#include "macoro/when_all_scope.h"
#include "macoro/bulk.h"
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
        bool setupMoveStateEnabled(const std::shared_ptr<const RingNttContext>& owner)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            return gpu::enabled(owner);
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
        // the sender prepares its response; direct/Core callers remain eager.




#if defined(ENABLE_LOGVOLE_CUDA)
        void tryPrefetchRootFinalizeBase(
            const ReceiverState& state, RootDigestState& digestState, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView cacheScope)
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
                !makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx, state.mShrinkExpandState.mRingFactoryOwner, cacheScope))
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
                    dPrimeDevice, cpuBenchmark, cacheScope);
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
            bool hasReusableState, bool useGpu, std::shared_ptr<HostStepProfiler> profileOwner,
            TimingStats* timing, CpuBenchmarkState cpuBenchmark = {})
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
					shrinkExpandSock, detail::requirePayloadSize(validPayloadSize, maxPayload), params.mShrinkExpand.mTransport.mEncoding.mWire, useGpu, profile, timing);
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
					co_await detail::recvFrame<ProtocolCacheRole::Receiver>(rootSock, detail::requirePayloadSize(validPayloadSize, maxPayload), params.mShrinkExpand.mTransport.mEncoding.mWire, useGpu, profile, timing);
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
            co_await recvOfflineMessage(child, *message.mNextLevel, childSock, false, childHasReusableState, useGpu, profileOwner, timing, cpuBenchmark);
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
            u64 sid, ProtocolCacheScopeView scope)
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
                    it->mChunkCount, it->mPrepared, scope);
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
        Socket& sock, ProtocolCacheScope setupScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        setupScope.mRole = ProtocolCacheRole::Receiver;
		u64 maxPayload = 0;
		const bool validPayloadSize = shrinkExpandOfflinePayloadSize(input.mParams, maxPayload);
		const auto payload = co_await detail::recvFrame<ProtocolCacheRole::Receiver>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), input.mParams.mTransport.mEncoding.mWire, gpu::enabled(input.mRingFactoryOwner), hostProfiler(input.mRingFactoryOwner), timingStats(input.mRingFactoryOwner));

        ShrinkExpandOfflineMessage message{};
        if (!decode(payload, message, input.mParams.mNumWorkerThreads, input.mParams.mTransport.mEncoding, gpu::enabled(input.mRingFactoryOwner), hostProfiler(input.mRingFactoryOwner), cpuBenchmark))
        {
            throw std::runtime_error("LogVole receiver received malformed shrink/expand offline message");
        }

        const bool finalized = setupMoveStateEnabled(input.mRingFactoryOwner)
            ? finalizeShrinkExpandReceiverOffline(input, std::move(message), state, setupScope)
            : finalizeShrinkExpandReceiverOffline(input, message, state, setupScope);
        if (!finalized)
        {
            throw std::runtime_error("LogVole receiver rejected shrink/expand offline message");
        }
    }

    task<> LogVoleRingReceiver::offline(
        const ReceiverOfflineInput& input,
        ReceiverState& state,
        Socket& sock,
        std::shared_ptr<void>* firstQueryGpuAllocations, ProtocolCacheScope setupScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        setupScope.mRole = ProtocolCacheRole::Receiver;
#if defined(ENABLE_LOGVOLE_CUDA)
        // The application total timer is already running when offline begins.
        // Reserve receiver-only first-query storage while the copied TCP setup
        // is still in flight; publication waits for the worker before online.
        auto firstQueryPlan = firstQueryGpuAllocations && gpu::enabled(input.mRingFactoryOwner)
            ? gpu::beginReceiverFirstQueryAllocations(input.mParams, input.mRingFactoryOwner, setupScope)
            : gpu::ReceiverFirstQueryAllocationsPtr{};
#endif
        OfflineMessage message{};
        co_await recvOfflineMessage(input.mParams, message, sock, true, false, gpu::enabled(input.mRingFactoryOwner), hostProfilerOwner(input.mRingFactoryOwner), timingStats(input.mRingFactoryOwner), cpuBenchmark);

        ReceiverOfflineOutput output{};
        const bool finalized = setupMoveStateEnabled(input.mRingFactoryOwner)
            ? finalizeReceiverOffline(input, std::move(message), output, cpuBenchmark, setupScope)
            : finalizeReceiverOffline(input, message, output, cpuBenchmark, setupScope);
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
        Socket& sock, LogVoleEncodingOptions encoding, bool useGpu, HostStepProfiler* profile, ProtocolCacheScope scope,
        TimingStats* timing, RingOpsStats* totals)
    {
        CpuBenchmarkState cpuBenchmark{};
        if (useGpu) timing = &globalTimingStats;
        scope.mRole = ProtocolCacheRole::Receiver;
        KeyDeriveRequest request{};
        if (!prepareKeyDeriveRequest(input, request))
        {
            throw std::runtime_error("LogVole receiver could not prepare key-derive request");
        }

        co_await detail::sendFrame(sock, encode(request, encoding, useGpu, profile, cpuBenchmark));

		u64 maxPayload = 0;
		const bool validPayloadSize = keyDerivePayloadSize(input.mParams, request.mTau, maxPayload);
		const auto responsePayload =
			co_await detail::recvFrame<ProtocolCacheRole::Receiver>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), encoding.mWire, useGpu, profile, timing);

        KeyDeriveResponse response{};
        if (!decode(responsePayload, response, encoding, useGpu, profile, cpuBenchmark))
        {
            throw std::runtime_error("LogVole receiver could not decode key-derive response");
        }

        {
            PendingRingOpsStats pending(totals);
            auto* stats = useGpu ? legacyRingOpsThreadLocalStats() : totals ? &pending : nullptr;
            if (!finalizeKeyDeriveResponse(input, response, output, scope, stats))
                throw std::runtime_error("LogVole receiver rejected key-derive response");
        }
    }

    task<> LogVoleRingReceiver::online(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers, std::span<RootZetaBuffer> zetaBuffers,
        ReceiverState& state, const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
        std::shared_ptr<void> firstQueryGpuAllocations, const void* firstQueryOwner, ProtocolCacheScope cacheScope)
    {
        return onlineStart(executor, lheBuffers, lencBuffers, zetaBuffers, state, input, output,
            prng, sock, std::move(firstQueryGpuAllocations), firstQueryOwner,
            std::move(cacheScope));
    }

    task<> LogVoleRingReceiver::onlineStart(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers, std::span<RootZetaBuffer> zetaBuffers,
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output,
        PRNG& prng,
        Socket& sock,
        std::shared_ptr<void> firstQueryGpuAllocations,
        const void* firstQueryOwner, ProtocolCacheScope cacheScope)
    {
        if (!state.mShrinkExpandState.mRingFactoryOwner ||
            !state.mShrinkExpandState.mRingFactoryOwner->mFactory)
            throw std::runtime_error("LogVole online state has no identity resource owner");
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(state.mShrinkExpandState.mRingFactoryOwner)};
        OnlinePrefetchPlan prefetchPlan;
#if defined(ENABLE_LOGVOLE_CUDA)
        prefetchPlan.mFirstQueryAllocations =
            std::static_pointer_cast<gpu::ReceiverFirstQueryAllocations>(
                firstQueryGpuAllocations);
        prefetchPlan.mFirstQueryOwner = firstQueryOwner;
#endif
        prefetchPlan.configure(state, input.mSid);
        if (!cacheScope.mRunId)
            cacheScope = ProtocolCacheScope(state.mShrinkExpandState.mRingFactoryOwner->mFactory->protocolService()->allocate(),
                ProtocolCacheRole::Receiver);
        cacheScope.mRole = ProtocolCacheRole::Receiver;
        co_await onlineImpl(state, input, output, prng, sock, prefetchPlan, 0u,
            cpuBenchmark, executor, lheBuffers, lencBuffers, zetaBuffers, cacheScope);
    }

    task<> LogVoleRingReceiver::onlineImpl(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        ReceiverOnlineOutput& output,
        PRNG& prng,
        Socket& sock,
        OnlinePrefetchPlan& prefetchPlan,
        u32 recursionDepth, CpuBenchmarkState cpuBenchmark,
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers, std::span<RootZetaBuffer> zetaBuffers, ProtocolCacheScope cacheScope)
    {
        // Active only during synchronous regions, never while this frame is suspended.
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
                RootDigestState digestState{};
                RootDigestMessage digest{};
                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: prepare digest", state.mParams.mW, &cpuBenchmark);
                    auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                    AutoTimer rootTimer(timing ? &timing->mRootReceiverHostUs : nullptr);
                    const bool prepared = co_await prepareRootDigestReceiver(executor, zetaBuffers,
                        state, input.mX, prng, digestState, digest,
                        input.mXDevice, input.mXCount, true, cpuBenchmark, cacheScope);
                    if (!prepared)
                    {
                        throw std::runtime_error("LogVole receiver could not prepare root digest");
                    }
                }

                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: encode digest", state.mParams.mW, &cpuBenchmark);
                    auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                    AutoTimer serTimer(timing ? &timing->mRootSerializeUs : nullptr);
                    digestPayload = encode(digest, state.mParams.mShrinkExpand.mTransport.mEncoding, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), cpuBenchmark);
                }
                digestFrameSize = detail::frameBytes(digestPayload);
                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: send digest", state.mParams.mW, &cpuBenchmark);
                    co_await detail::sendOwnedFrame(rootSock, std::move(digestPayload));
                }

#if defined(ENABLE_LOGVOLE_CUDA)
                // The arithmetic prefix needs dPrime but not its transcript
                // hash. Queue it before the deferred CPU hash so those six
                // kernels can run under the hash. digestState owns dPrime and
                // every device input; its last-declared prepared handle drains
                // abandoned work first if hashing or the socket later fails.
                tryPrefetchRootFinalizeBase(state, digestState, cpuBenchmark, cacheScope);
#endif

                // sendOwnedFrame has handed the buffer to coproto before it
                // resumes us. Hashing remains synchronous on this coroutine;
                // only after it succeeds does mDPrimeHash become authoritative
                // for response validation and the seed-dependent CT2 suffix.
                if (!finishRootDigestHash(digestState,
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
                        responsePayload = co_await detail::recvFrame<ProtocolCacheRole::Receiver>(rootSock, detail::requirePayloadSize(validPayloadSize, maxPayload), state.mParams.mShrinkExpand.mTransport.mEncoding.mWire, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), timingStats(state.mShrinkExpandState.mRingFactoryOwner));
                    }
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: decode response", state.mParams.mW, &cpuBenchmark);
                    auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                    AutoTimer serTimer(timing ? &timing->mRootSerializeUs : nullptr);
                    if (!decode(responsePayload, response, state.mParams.mShrinkExpand.mTransport.mEncoding, gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner), hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), cpuBenchmark))
                        throw std::runtime_error("LogVole receiver could not decode root response");
                }

                {
                    HostStep step(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "root: finalize", state.mParams.mW, &cpuBenchmark);
                    auto* timing = timingStats(state.mShrinkExpandState.mRingFactoryOwner);
                    AutoTimer rootTimer(timing ? &timing->mRootReceiverHostUs : nullptr);
                    auto operation = finalizeRootOnlineReceiver(executor, lheBuffers, lencBuffers,
                        state, input, digestState,
                        std::move(response), output, cpuBenchmark, cacheScope);
                    const bool finalized = co_await std::move(operation);
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
                    input.mSid, cacheScope);
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
                recursionDepth == 0u ? input.mSid : 0, cacheScope);
        }
        prefetchPlan.markShrinkReady(
            state.mShrinkExpandState, wDoublePrime, gpuShrinkDone);
        if (!gpuShrinkDone)
        {
#endif
        auto shrinkChunk = [&](std::size_t taskIdx, CpuBenchmarkState& cpuBenchmark,
            PendingRingOpsStats* stats) {
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
            if (!shrinkExpandShrink(state.mShrinkExpandState, chunk, shrink, cacheScope, stats)) return false;
            treeStep.stop();
            HostStep unbundleStep(hostProfiler(state.mShrinkExpandState.mRingFactoryOwner), "cpu shrink worker: unbundle", &cpuBenchmark);
            if (!seedLabelGadgetDecomposeHiAndUnbundle(
                    shrink.mDigest,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    tauHi,
                    state.mParams.mShrinkExpand.mRing,
                    decomposed, stats) ||
                decomposed.size() != static_cast<std::size_t>(tauHi) * rho)
            {
                return false;
            }

            digests[chunkIdx] = std::move(shrink.mDigest);
            trees[chunkIdx] = std::move(shrink.mTree);
            dHatChunks[chunkIdx] = std::move(decomposed);
            return true;
        };
        if (!gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner))
        {
            auto partitions = std::min({std::size_t(wDoublePrime), lheBuffers.size(), lencBuffers.size()});
            if (const auto limit = state.mParams.mShrinkExpand.mNumWorkerThreads)
                partitions = std::min<std::size_t>(partitions, limit);
            if (!partitions) throw std::runtime_error("LogVole receiver needs CPU shrink resources");
            auto shrinkRange = [&](std::size_t first, std::size_t last, CpuBenchmarkState& worker) {
                CpuBenchmarkWorkerScope timing(partitions > 1 ? worker.mContext : nullptr);
                CpuBenchmarkTaskScope metrics(worker);
                auto* totals = state.mShrinkExpandState.mRingFactoryOwner
                    ? state.mShrinkExpandState.mRingFactoryOwner->mExecutionOptions.mRingOpsStats : nullptr;
                PendingRingOpsStats pending(totals);
                auto* stats = totals ? &pending : nullptr;
                for (auto chunk = first; chunk != last; ++chunk)
                    if (!shrinkChunk(chunk, worker, stats))
                        throw std::runtime_error("LogVole receiver could not prepare recursive child input");
            };
            if (partitions == 1) shrinkRange(0, wDoublePrime, cpuBenchmark);
            else
            {
                // Per-phase instrumentation only; numerical outputs are owned
                // by this frame and every callback finishes before resumption.
                std::vector<CpuBenchmarkState> workers(partitions, {cpuBenchmark.mContext, true});
                co_await macoro::bulk_chunked(executor, wDoublePrime, std::span(workers), shrinkRange);
            }
        }
        else if (!detail::runParallelTasks(wDoublePrime, state.mParams.mShrinkExpand.mNumWorkerThreads,
                [&](std::size_t row, CpuBenchmarkState& worker) {
                    return shrinkChunk(row, worker, legacyRingOpsThreadLocalStats());
                }, false, &cpuBenchmark))
            throw std::runtime_error("LogVole receiver could not prepare recursive child input");
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
            co_await onlineImpl(
                *state.mNextLevelState, childInput, childOutput, prng, childSock,
                prefetchPlan, recursionDepth + 1u, cpuBenchmark,
                executor, lheBuffers, lencBuffers, zetaBuffers, cacheScope);
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
            if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, gpuCtx, state.mShrinkExpandState.mRingFactoryOwner, cacheScope))
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
        {
            bool denoised;
            if (!gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner))
            {
                RingNttContext ctx;
                if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx,
                        state.mShrinkExpandState.mRingFactoryOwner, cacheScope))
                    throw std::runtime_error("LogVole receiver could not build denoise context");
                auto allowance = std::min(lheBuffers.size(), lencBuffers.size());
                if (const auto limit = state.mParams.mShrinkExpand.mNumWorkerThreads)
                    allowance = std::min<std::size_t>(allowance, limit);
                denoised = co_await shrinkExpandDenoiseComb(executor, allowance, ctx,
                    childOutput.mTbm, skXHat, cpuBenchmark);
            }
            else
                denoised = detail::gpuLegacySeedLabelDenoiseTbm(childOutput.mTbm, wPrime, tauHi,
                    state.mParams.mShrinkExpand.mRing, skXHat,
                    state.mParams.mShrinkExpand.mNumWorkerThreads, cpuBenchmark);
            auto* totals = state.mShrinkExpandState.mRingFactoryOwner
                ? state.mShrinkExpandState.mRingFactoryOwner->mExecutionOptions.mRingOpsStats : nullptr;
            PendingRingOpsStats pending(totals);
            auto* stats = gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner)
                ? legacyRingOpsThreadLocalStats() : totals ? &pending : nullptr;
            if (!denoised || !seedLabelAgg(std::move(skXHat), wDoublePrime, tauHi,
                    state.mParams.mShrinkExpand.mRing, skX, stats) || skX.size() != wDoublePrime)
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
                preparedReceiverCt2, cacheScope);
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
                preparedReceiverCt2, cacheScope);
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
        auto chunkInput = [&](u32 chunkIdx) {
            ShrinkExpandExpandReceiverInput value;
            value.mSeed = childOutput.mSeed;
            value.mSid = input.mSid;
            value.mNonce = instanceBase + chunkIdx;
            value.mDigest = digests[chunkIdx];
            value.mMaskDigest = *rootMaskDigest;
            value.mSkX = skX[chunkIdx];
            value.mTree = trees[chunkIdx];
            return value;
        };
        auto storeChunk = [&](u32 chunkIdx, ShrinkExpandReceiverExpandOutput& value) {
            const auto start = std::size_t(chunkIdx) * muHi;
            const auto count = std::min<std::size_t>(muHi, receiverInputCount(input) - start);
            if (value.mTbm.size() < count) return false;
            for (std::size_t i = 0; i < count; ++i)
                finalTbm[start + i] = std::move(value.mTbm[i]);
            return true;
        };
        if (!gpu::enabled(state.mShrinkExpandState.mRingFactoryOwner))
        {
            auto allowance = std::min(lheBuffers.size(), lencBuffers.size());
            if (const auto limit = state.mParams.mShrinkExpand.mNumWorkerThreads)
                allowance = std::min<std::size_t>(allowance, limit);
            if (!allowance) throw std::runtime_error("LogVole receiver needs CPU expansion buffers");
            const auto partitions = std::min<std::size_t>(wDoublePrime, allowance);
            // These closures and all borrowed inputs live in the parent until
            // the scope joins every child, including on a child failure.
            auto expandPartition = [&](std::size_t partition) -> macoro::task<> {
                if (partitions > 1) co_await executor.schedule();
                const auto first = std::size_t(wDoublePrime) * partition / partitions;
                const auto last = std::size_t(wDoublePrime) * (partition + 1) / partitions;
                auto products = wDoublePrime == 1 ? lheBuffers.first(allowance) : lheBuffers.subspan(partition, 1);
                auto leaves = wDoublePrime == 1 ? lencBuffers.first(allowance) : lencBuffers.subspan(partition, 1);
                CpuBenchmarkState worker{cpuBenchmark.mContext, partitions > 1 || cpuBenchmark.mIsWorker};
                // Multi-partition children have one buffer: both async kernels
                // run inline, so this thread timer ends on its starting worker.
                // Single-chunk row parallelism may suspend and has its own timers.
                CpuBenchmarkWorkerScope timing(partitions > 1 ? worker.mContext : nullptr);
                for (auto chunk = first; chunk != last; ++chunk)
                {
                    auto expandInput = chunkInput(static_cast<u32>(chunk));
                    ShrinkExpandReceiverExpandOutput expandOutput;
                    if (!co_await shrinkExpandExpandReceiver(executor, products, leaves,
                            state.mShrinkExpandState, expandInput, expandOutput, worker, cacheScope) ||
                        !storeChunk(static_cast<u32>(chunk), expandOutput))
                        throw std::runtime_error("LogVole receiver could not expand recursive chunk");
                }
            };
            if (partitions == 1) co_await expandPartition(0);
            else
            {
                auto launch = [&]() -> macoro::when_all_scope {
                    for (std::size_t i = 0; i < partitions; ++i)
                        co_await macoro::scoped(expandPartition(i));
                };
                co_await launch();
            }
        }
        else
        {
            // Existing host fallback for GPU sessions; CPU sessions use the async branch.
            const u32 cpuRowWorkers = wDoublePrime > 1 ? 1 : state.mParams.mShrinkExpand.mNumWorkerThreads;
            if (!detail::runParallelTasks(wDoublePrime, state.mParams.mShrinkExpand.mNumWorkerThreads,
                [&](std::size_t taskIdx, CpuBenchmarkState& worker) {
                    const auto chunk = static_cast<u32>(taskIdx);
                    auto expandInput = chunkInput(chunk);
                    ShrinkExpandReceiverExpandOutput expandOutput;
                    return detail::gpuLegacyExpandReceiver(state.mShrinkExpandState, expandInput,
                        expandOutput, cpuRowWorkers, worker, cacheScope) && storeChunk(chunk, expandOutput);
                }, false, &cpuBenchmark))
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
        Socket& sock, ProtocolCacheScope cacheScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(state.mRingFactoryOwner)};
        cacheScope.mRole = ProtocolCacheRole::Receiver;
        ShrinkExpandShrinkOutput shrink{};
        Buffer digestPayload;
        {
            auto* totals = state.mRingFactoryOwner ? state.mRingFactoryOwner->mExecutionOptions.mRingOpsStats : nullptr;
            PendingRingOpsStats pending(totals);
            auto* stats = gpu::enabled(state.mRingFactoryOwner) ? legacyRingOpsThreadLocalStats() :
                totals ? &pending : nullptr;
            if (!shrinkExpandShrink(state, input.mX, shrink, cacheScope, stats))
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
			co_await detail::recvFrame<ProtocolCacheRole::Receiver>(sock, detail::requirePayloadSize(validPayloadSize, maxPayload), state.mParams.mTransport.mEncoding.mWire, gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), timingStats(state.mRingFactoryOwner));

        RnsPoly skX{};
        {
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
            expanded = detail::gpuLegacyExpandReceiver(state, coreInput, output,
                state.mParams.mNumWorkerThreads, cpuBenchmark, cacheScope);
        }
        else
            expanded = co_await shrinkExpandExpandReceiver(executor, lheBuffers, lencBuffers,
                state, coreInput, output, cpuBenchmark, cacheScope);
        if (!expanded)
        {
            throw std::runtime_error("LogVole receiver could not expand");
        }
    }
}
