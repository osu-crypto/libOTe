#include "libOTe/Vole/LogVole/LogVoleRingSender.h"
#include <chrono>

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include <cuda_runtime_api.h>
#endif

#include <array>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
        constexpr u64 kFrameHeaderSize = sizeof(u64);

        std::mutex rootWirePinEvidenceMutex;
        RootWirePinOverlapEvidence lastRootWirePinEvidence{};

        void publishRootWirePinEvidence(const RootWirePinOverlapEvidence& evidence)
        {
            std::lock_guard lock(rootWirePinEvidenceMutex);
            lastRootWirePinEvidence = evidence;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        u64 steadyClockNs()
        {
            return static_cast<u64>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        }

        // The reserved wire Buffer outlives this worker, including on socket
        // cancellation. Only its owning sender process can register the span.
        struct RootWirePinWorker
        {
            std::thread mThread;
            u64 mBeginNs = 0;
            u64 mEndNs = 0;
            u64 mCpuNs = 0;
            bool mPinned = false;

            bool start(const Buffer& wire, u64 runId, int device,
                CpuBenchmarkContext* benchmarkContext)
            {
                const void* const pointer = wire.data();
                const std::size_t bytes = wire.size();
                try
                {
                    mThread = std::thread([this, pointer, bytes, runId, device,
                        benchmarkContext] {
                        try
                        {
                            CpuBenchmarkWorkerScope benchmarkWorker(benchmarkContext);
                            CpuBenchmarkTaskScope benchmarkTask;
                            ScopedProtocolCacheScope senderScope(
                                ProtocolCacheRole::Sender, runId);
                            HostStep phase("setup: root wire preregistration");
                            mBeginNs = steadyClockNs();
                            const u64 cpuBegin = cpuBenchmarkThreadNs();
                            bool pinned = false;
                            mPinned = cudaSetDevice(device) == cudaSuccess &&
                                gpu::gpuTryPinSetupWireHostRange(pointer, bytes, pinned) &&
                                pinned;
                            mCpuNs = cpuBenchmarkThreadNs() - cpuBegin;
                            mEndNs = steadyClockNs();
                        }
                        catch (...)
                        {
                            mPinned = false;
                            mEndNs = steadyClockNs();
                        }
                    });
                }
                catch (...) { return false; }
                return true;
            }

            void join() noexcept
            {
                if (mThread.joinable()) mThread.join();
            }

            ~RootWirePinWorker() { join(); }
        };

        // Reserve sender-owned CUDA pages concurrently with recursive GPU
        // setup. The buffer is never read or moved until the worker joins; its
        // destruction joins on a setup exception or coroutine cancellation.
        struct RootWireEarlyCudaWorker
        {
            std::thread mThread;
            Buffer mReserved;
            bool mCudaOwned = false;

            bool start(std::size_t forecastBytes, u64 runId, int device,
                CpuBenchmarkContext* benchmarkContext)
            {
                try
                {
                    mThread = std::thread([this, forecastBytes, runId, device,
                        benchmarkContext] {
                        try
                        {
                            CpuBenchmarkWorkerScope benchmarkWorker(
                                benchmarkContext);
                            CpuBenchmarkTaskScope benchmarkTask;
                            ScopedProtocolCacheScope senderScope(
                                ProtocolCacheRole::Sender, runId);
                            HostStep phase(
                                "setup: early CUDA-owned Root wire reservation");
                            if (cudaSetDevice(device) != cudaSuccess ||
                                !gpu::enabled()) return;
                            mReserved = reserveRootCudaWireBuffer(
                                forecastBytes, runId, mCudaOwned, false);
                        }
                        catch (...) { mCudaOwned = false; }
                    });
                }
                catch (...) { return false; }
                return true;
            }

            void join() noexcept
            {
                if (mThread.joinable()) mThread.join();
            }
            ~RootWireEarlyCudaWorker() { join(); }
        };

#endif

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

        // Offline messages and the production Root reply are single-use.
        // Taking the encoded payload by value makes its lifetime part of this
        // coroutine frame, so coproto can own it without a defensive copy.
        // Keep the generic const helper above for public/retry paths.
        task<> sendOwnedFrame(Socket& sock, Buffer payload)
        {
            std::array<u8, kFrameHeaderSize> header{};
            writeU64(header, static_cast<u64>(payload.size()));

            co_await sock.send(coproto::copy(header));
            if (!payload.empty())
            {
                co_await sock.send(std::move(payload));
            }
        }

        bool setupOwnedSendEnabled()
        {
            static const bool ownPayload = [] {
                const char* value = std::getenv("LV_SETUP_OWNED_SEND");
                return !(value && value[0] == '0');
            }();
            return ownPayload;
        }

        task<> sendOfflineFrame(Socket& sock, Buffer payload)
        {
            HostStep phase("setup transport: send offline frame");
            // Encoding creates a fresh, single-use buffer. Keep ownership in
            // the coroutine and hand it to coproto, avoiding a second complete
            // copy of the (potentially hundreds of MB) offline message.
            if (setupOwnedSendEnabled())
            {
                co_await sendOwnedFrame(sock, std::move(payload));
            }
            else
            {
                co_await sendFrame(sock, payload);
            }
        }

        bool ownedRootMessageFastPathEnabled()
        {
            static const bool on = [] {
                const char* value = std::getenv("LV_ROOT_OWNED_MESSAGE_FASTPATH");
                // Set to zero to restore the const-message path and its defensive
                // frame/message copies exactly.
                return !(value && value[0] == '0');
            }();
            return on;
        }

        task<Buffer> recvFrame(Socket& sock, u64 maxPayloadSize)
        {
            std::array<u8, kFrameHeaderSize> header{};
            const auto waitStart = std::chrono::steady_clock::now();
            co_await sock.recv(header);
            globalTimingStats.mSenderWaitUs.fetch_add(
                static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                                     std::chrono::steady_clock::now() - waitStart)
                                     .count()),
                std::memory_order_relaxed);

            const auto size = readU64(header);
            if (size > maxPayloadSize ||
				size > static_cast<u64>(std::numeric_limits<std::size_t>::max()))
            {
                throw std::length_error("LogVole frame is too large");
            }

            Buffer payload(static_cast<std::size_t>(size));
            adviseGpuSetupWireBuffer(payload);
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

		u64 requirePayloadSize(bool valid, u64 size)
		{
			if (!valid)
				throw std::length_error("LogVole could not derive a frame size bound");
			return size;
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

        RootOfflineMessage* terminalRootMessage(
            const Params& params, OfflineMessage& message)
        {
            Params levelParams = params;
            OfflineMessage* level = &message;
            while (level)
            {
                RecursiveMode mode{};
                if (!recursiveMode(levelParams, mode)) return nullptr;
                if (mode == RecursiveMode::Root) return &level->mRootMessage;
                Params nextParams{};
                if (!level->mNextLevel || !childParams(levelParams, nextParams))
                    return nullptr;
                level = level->mNextLevel.get();
                levelParams = std::move(nextParams);
            }
            return nullptr;
        }

        // The complete message tree is prepared before transport. Keep the
        // final Root wire in the top-level sender coroutine so the worker can
        // register it during an ancestor's actual TCP send, even when Root
        // later reuses shrink state and sends no local shrink frame.
        struct RootWirePinPlan
        {
            RootWirePinOverlapEvidence mEvidence{};
            RootOfflineMessage* mRoot = nullptr;
            Buffer mReserved;
            bool mCudaRequested = false;
            bool mCudaAttempted = false;
            bool mCudaSelected = false;
#if defined(ENABLE_LOGVOLE_CUDA)
            // Destruct before mReserved on cancellation or an exception.
            RootWirePinWorker mWorker;
#endif

            RootWirePinPlan(u64 senderRunId, bool requested,
                bool cudaRequested,
                RootOfflineMessage* root)
                : mRoot(root), mCudaRequested(cudaRequested)
            {
                mEvidence.mSenderRunId = senderRunId;
                mEvidence.mRequested = requested;
            }

            bool prepareCudaWireEligibility()
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!mCudaRequested || !mRoot) return false;
                mEvidence.mWireBytes = rootOfflineWireSize(*mRoot);
                noteRootWireCudaExpectedDownloads(
                    mEvidence.mSenderRunId, *mRoot);
                const bool deviceExport = mRoot->mLazyCtR ||
                    mRoot->mLazyLacctLeft || mRoot->mLazyTopCt;
                const char* pinnedWire = std::getenv("LV_GPU_SETUP_PINNED_WIRE");
                const char* directWire = std::getenv(
                    "LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD");
                const bool eligible = mEvidence.mSenderRunId != 0 &&
                    deviceExport && mEvidence.mWireBytes >=
                        (std::size_t{1} << 20) &&
                    gpu::enabled() && gpu::currentDeviceOrdinal() >= 0 &&
                    setupOwnedSendEnabled() &&
                    (!pinnedWire || pinnedWire[0] != '0') &&
                    (!directWire || directWire[0] != '0');
                noteRootWireCudaAllocEligibility(mEvidence.mSenderRunId,
                    static_cast<std::size_t>(mEvidence.mWireBytes), eligible);
                return eligible;
#else
                return false;
#endif
            }

#if defined(ENABLE_LOGVOLE_CUDA)
            void adoptEarlyCudaWire(RootWireEarlyCudaWorker& early,
                std::size_t forecastBytes)
            {
                if (!early.mThread.joinable()) return;
                HostStep waitStep("setup: early Root wire reservation join");
                const u64 waitBegin = steadyClockNs();
                early.join();
                const u64 joinWaitNs = steadyClockNs() - waitBegin;
                bool adopted = false;
                if (early.mCudaOwned && prepareCudaWireEligibility() &&
                    mEvidence.mWireBytes <= forecastBytes &&
                    early.mReserved.size() == forecastBytes &&
                    shrinkRootCudaWireBuffer(early.mReserved,
                        static_cast<std::size_t>(mEvidence.mWireBytes)))
                {
                    mReserved = std::move(early.mReserved);
                    mCudaSelected = true;
                    mCudaAttempted = true;
                    adopted = true;
                }
                else
                {
                    // A size mismatch or allocation decline must never send
                    // stale/short bytes. Release the worker span before the
                    // existing exact-size late reservation fallback.
                    early.mReserved = Buffer{};
                }
                noteRootWireCudaEarlyJoin(mEvidence.mSenderRunId,
                    joinWaitNs, adopted);
            }
#endif

            void reserveCudaWireIfRequested()
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!mCudaRequested || mCudaAttempted || !mRoot) return;
                mCudaAttempted = true;
                if (!prepareCudaWireEligibility()) return;
                ScopedProtocolCacheScope senderScope(
                    ProtocolCacheRole::Sender, mEvidence.mSenderRunId);
                mReserved = reserveRootCudaWireBuffer(
                    static_cast<std::size_t>(mEvidence.mWireBytes),
                    mEvidence.mSenderRunId, mCudaSelected);
#endif
            }

            void startBeforeFrame()
            {
                reserveCudaWireIfRequested();
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!mEvidence.mRequested || !mRoot || mCudaSelected ||
                    mEvidence.mLaunched || mEvidence.mAlreadyPinned)
                    return;
                if (!mEvidence.mWireBytes)
                    mEvidence.mWireBytes = rootOfflineWireSize(*mRoot);
                const bool deviceExport = mRoot->mLazyCtR ||
                    mRoot->mLazyLacctLeft || mRoot->mLazyTopCt;
                const char* pinnedWire = std::getenv("LV_GPU_SETUP_PINNED_WIRE");
                const char* directWire = std::getenv(
                    "LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD");
                const int device = gpu::currentDeviceOrdinal();
                if (!deviceExport || mEvidence.mWireBytes <
                        (std::size_t{1} << 20) || !gpu::enabled() || device < 0 ||
                    (pinnedWire && pinnedWire[0] == '0') ||
                    (directWire && directWire[0] == '0'))
                    return;

                if (mReserved.empty())
                    mReserved.resize(static_cast<std::size_t>(
                        mEvidence.mWireBytes));
                mEvidence.mEligible = gpu::gpuIsSetupWireHostRange(
                    mReserved.data(), mReserved.size());
                if (!mEvidence.mEligible) return;
                mEvidence.mAlreadyPinned = gpu::gpuIsSetupWirePinnedHostRange(
                    mReserved.data(), mReserved.size());
                mEvidence.mPinSucceeded = mEvidence.mAlreadyPinned;
                if (!mEvidence.mAlreadyPinned)
                    mEvidence.mLaunched = mWorker.start(mReserved,
                        mEvidence.mSenderRunId, device, tCpuBenchmarkContext);
#endif
            }

            void joinBeforeRootEncode() noexcept
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!mEvidence.mLaunched) return;
                HostStep waitStep("setup: root wire preregistration join");
                const u64 waitBegin = steadyClockNs();
                mWorker.join();
                mEvidence.mJoinWaitNs = steadyClockNs() - waitBegin;
                mEvidence.mPinBeginNs = mWorker.mBeginNs;
                mEvidence.mPinEndNs = mWorker.mEndNs;
                mEvidence.mPinCpuNs = mWorker.mCpuNs;
                mEvidence.mPinSucceeded = mWorker.mPinned;
#endif
            }
        };

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
            u64 senderRunId,
            RootWirePinPlan& rootPin)
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
                Buffer payload;
                {
                    ScopedProtocolCacheScope senderScope(
                        ProtocolCacheRole::Sender, senderRunId);
                    payload = message.mEncodedShrinkExpandMessage.empty()
                        ? encode(message.mShrinkExpandMessage,
                            params.mShrinkExpand.mNumWorkerThreads)
                        : std::move(message.mEncodedShrinkExpandMessage);
                }
                rootPin.startBeforeFrame();
                co_await sendOfflineFrame(shrinkExpandSock, std::move(payload));
                if (!isTopLevel)
                {
                    childHasReusableState = true;
                }
            }

            if (mode == RecursiveMode::Root)
            {
                // A standalone Root has no preceding frame to overlap, but
                // can still use the CUDA-owned final Buffer directly.
                rootPin.reserveCudaWireIfRequested();
                if (rootPin.mEvidence.mRequested &&
                    !rootPin.mEvidence.mWireBytes)
                    rootPin.mEvidence.mWireBytes =
                        rootOfflineWireSize(message.mRootMessage);
                rootPin.joinBeforeRootEncode();
                auto rootSock = sock.fork();
                Buffer payload;
                {
                    ScopedProtocolCacheScope senderScope(
                        ProtocolCacheRole::Sender, senderRunId);
                    payload = rootPin.mReserved.empty()
                        ? encode(message.mRootMessage,
                            params.mShrinkExpand.mNumWorkerThreads)
                        : encodeRootOfflineIntoBuffer(message.mRootMessage,
                            std::move(rootPin.mReserved),
                            params.mShrinkExpand.mNumWorkerThreads);
                }
                rootPin.mEvidence.mSelected = rootPin.mEvidence.mEligible &&
                    rootPin.mEvidence.mPinSucceeded;
                publishRootWirePinEvidence(rootPin.mEvidence);
                co_await sendOfflineFrame(rootSock, std::move(payload));
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
            co_await sendOfflineMessage(child, *message.mNextLevel,
                childSock, false, childHasReusableState, senderRunId, rootPin);
        }

        task<> senderOnlineService(
            SenderState& state,
            SenderState& precomputeRoot,
            Socket& sock,
            PRNG& prng,
            CommunicationStats& comm,
            ProtocolCacheScope senderScope)
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
                u64 responseFrameSize = 0;
                const bool nonInteractive = state.mParams.mOnlineMode == OnlineMode::NonInteractive;
                {
                    auto rootSock = sock.fork();
                    const bool ownedFastPath = ownedRootMessageFastPathEnabled();
                    // k'_Rt is fresh sender randomness that does not depend on the
                    // digest, so it is drawn while the digest is still in flight.
                    // Supported GPU paths draw only the small parent seed on
                    // the host and finish device sampling before the suspension.
                    RnsPoly preKPrime{};
                    std::shared_ptr<void> preKPrimeDevice;
                    bool havePreK = false;
                    {
                        // Install the captured sender/SID scope only around
                        // synchronous work, never across a socket suspension.
                        ScopedProtocolCacheScope activeSender(senderScope);
                        havePreK = !nonInteractive && sampleRootResponseKPrime(
                            state, prng, preKPrime, &preKPrimeDevice);
                        if (havePreK || nonInteractive)
                        {
                            // Prepare the immutable SK cache and, if requested,
                            // a legacy host-key upload without replacing a
                            // freshly device-generated key.
                            std::shared_ptr<void> uploadedKPrime;
                            (void)prepareRootResponseDeviceOperands(
                                state, preKPrime, uploadedKPrime);
                            if (!preKPrimeDevice)
                                preKPrimeDevice = std::move(uploadedKPrime);
                        }
                    }
                    {
                        HostStep step("send: recv root digest");
                        u64 maxPayload = 0;
                        const bool validPayloadSize = rootDigestPayloadSize(state.mParams.mShrinkExpand.mRing, maxPayload);
                        digestPayload = co_await recvFrame(rootSock, requirePayloadSize(validPayloadSize, maxPayload));
                    }

                    RootDigestMessage digest{};
                    RootResponseMessage response{};
                    {
                        ScopedProtocolCacheScope activeSender(senderScope);
                        // recvFrame may resume on a receiver worker. Restore
                        // the exact captured scope before validating secrets.
                        {
                            AutoTimer serTimer(globalTimingStats.mRootSerializeUs);
                            if (!decode(digestPayload, digest))
                            {
                                throw std::runtime_error("LogVole sender could not decode root digest");
                            }
                        }
                        {
                            HostStep step("send: root response");
                            AutoTimer rootTimer(globalTimingStats.mRootSenderHostUs);
                            const bool prepared = ownedFastPath
                                ? prepareRootResponseSender(
                                      state, std::move(digest), prng, response,
                                      &precomputeRoot,
                                      havePreK ? &preKPrime : nullptr,
                                      /*deferPrecompute=*/true,
                                      preKPrimeDevice)
                                : prepareRootResponseSender(
                                      state, digest, prng, response,
                                      &precomputeRoot,
                                      havePreK ? &preKPrime : nullptr,
                                      /*deferPrecompute=*/true,
                                      preKPrimeDevice);
                            if (!prepared)
                            {
                                throw std::runtime_error("LogVole sender could not prepare root response");
                            }
                        }

                        if (!nonInteractive)
                        {
                            AutoTimer serTimer(globalTimingStats.mRootSerializeUs);
                            responsePayload = encode(response);
                        }
                    }
                    if (!nonInteractive)
                    {
                        responseFrameSize = frameBytes(responsePayload);
                        HostStep step("send: send root response");
                        if (ownedFastPath)
                        {
                            co_await sendOwnedFrame(rootSock, std::move(responsePayload));
                        }
                        else
                        {
                            co_await sendFrame(rootSock, responsePayload);
                        }
                    }

                    // Deferred by prepareRootResponseSender: the reply is already
                    // on the wire, so the receiver runs its finalize while this
                    // runs instead of waiting for it.
                    {
                        ScopedProtocolCacheScope activeSender(senderScope);
                        HostStep step("cpu sender: post-response precompute");
                        AutoTimer rootTimer(globalTimingStats.mRootSenderHostUs);
                        if (!finishRootSenderPrecompute(state, prng, &precomputeRoot))
                        {
                            throw std::runtime_error("LogVole sender could not prepare root response");
                        }
                    }
                }
                comm.mBytesSent += responseFrameSize;
                comm.mBytesReceived += frameBytes(digestPayload);
                co_return;
            }

            if (!state.mNextLevelState)
            {
                throw std::runtime_error("LogVole sender missing recursive child state");
            }

            auto childSock = sock.fork();
            co_await senderOnlineService(*state.mNextLevelState,
                precomputeRoot, childSock, prng, comm, senderScope);
            if (!state.mPrecomputedTbk)
            {
                throw std::runtime_error("LogVole sender could not prepare recursive online cache");
            }
        }
    }

    RootWirePinOverlapEvidence rootWirePinOverlapEvidenceSnapshot()
    {
        std::lock_guard lock(rootWirePinEvidenceMutex);
        return lastRootWirePinEvidence;
    }

    std::size_t forecastRootOfflineWireSize(const Params& params,
        bool leafInputsAreGadget) noexcept
    {
        // Root ciphertext geometry depends on the ring and truncated LENC
        // widths, not on sampled coefficients, seeds, or recursive W. Walk W
        // only to validate that the sender reaches a terminal Root and to
        // identify whether its leaf input is already a gadget digit.
        const auto& se = params.mShrinkExpand;
        const u64 rho = se.mRing.mCoeffModulusBits.size();
        const u64 n = se.mRing.mPolyModulusDegree;
        const u64 t = se.mTau > 1u ? se.mTau - 1u : 0u;
        const u64 alpha = se.mAlpha;
        if (!rho || rho > std::numeric_limits<u32>::max() ||
            n < 2u || (n & (n - 1u)) || !t || !alpha ||
            !params.mW || !se.mGadgetLogBase ||
            !se.mPlaintextModulusBits)
            return 0;
        const auto checkedMul = [](u64 left, u64 right,
                                   u64& result) noexcept {
            if (right && left > std::numeric_limits<u64>::max() / right)
                return false;
            result = left * right;
            return true;
        };
        const auto checkedAdd = [](u64 left, u64 right,
                                   u64& result) noexcept {
            if (left > std::numeric_limits<u64>::max() - right)
                return false;
            result = left + right;
            return true;
        };
        u64 leftWidth = 0, mu = 0;
        if (!checkedMul(t, rho, leftWidth) ||
            !checkedMul(alpha, leftWidth, mu) || !mu ||
            leftWidth > std::numeric_limits<u32>::max() ||
            mu > std::numeric_limits<u32>::max())
            return 0;
        u64 w = params.mW;
        for (u32 level = 0; w > mu; ++level)
        {
            if (level >= 64u) return 0;
            const u64 childGroups = (w + mu - 1u) / mu;
            u64 childW = 0;
            if (!checkedMul(childGroups, leftWidth, childW) ||
                childW >= w || childW > std::numeric_limits<u32>::max())
                return 0;
            w = childW;
            leafInputsAreGadget = true;
        }
        const u64 leafTau = leafInputsAreGadget ? 1u :
            (static_cast<u64>(se.mPlaintextModulusBits) +
                se.mGadgetLogBase - 1u) / se.mGadgetLogBase;
        const u64 fullTau = t + 1u;
        if (!leafTau || leafTau > fullTau) return 0;
        const u64 ctTauMax = std::max(t, leafTau);
        u64 paddedWidth = 1u, levels = 0u;
        while (paddedWidth < leftWidth)
        {
            if (paddedWidth > std::numeric_limits<u32>::max() / 2u)
                return 0;
            paddedWidth *= 2u;
            ++levels;
        }
        const u64 randomizer = rootRandomizerWidth(se);
        if (!randomizer || randomizer > std::numeric_limits<u32>::max())
            return 0;

        u64 wordsPerPoly = 0, ctRCount = 0, lacctRows = 0,
            lacctCount = 0, topCtCount = 0, batchCount = 0,
            totalPolys = 0, coefficientBytes = 0, metadataBytes = 0,
            totalBytes = 0;
        if (!checkedMul(n, rho, wordsPerPoly) ||
            !checkedMul(leftWidth, t, ctRCount) ||
            !checkedMul(levels, paddedWidth, lacctRows) ||
            !checkedMul(lacctRows, 2u * ctTauMax, lacctCount) ||
            !checkedMul(leftWidth, t + randomizer, topCtCount) ||
            !checkedAdd(ctRCount, lacctCount, totalPolys) ||
            !checkedAdd(totalPolys, topCtCount, totalPolys) ||
            !checkedAdd(totalPolys, randomizer, totalPolys) ||
            !checkedMul(totalPolys, wordsPerPoly, coefficientBytes) ||
            !checkedMul(coefficientBytes, sizeof(u64), coefficientBytes) ||
            !checkedMul(rho, sizeof(u16), metadataBytes) ||
            !checkedAdd(metadataBytes, 80u, metadataBytes) ||
            !checkedAdd(metadataBytes, coefficientBytes, totalBytes) ||
            !checkedMul(randomizer, wordsPerPoly, batchCount) ||
            totalBytes > std::numeric_limits<std::size_t>::max() ||
            ctRCount > std::numeric_limits<u32>::max() ||
            lacctRows > std::numeric_limits<u32>::max() ||
            lacctCount > std::numeric_limits<u32>::max() ||
            topCtCount > std::numeric_limits<u32>::max() ||
            ctTauMax > std::numeric_limits<u32>::max() / 2u ||
            ctRCount * wordsPerPoly > std::numeric_limits<u32>::max() ||
            lacctCount * wordsPerPoly > std::numeric_limits<u32>::max() ||
            topCtCount * wordsPerPoly > std::numeric_limits<u32>::max() ||
            batchCount > std::numeric_limits<u32>::max())
            return 0;
        return static_cast<std::size_t>(totalBytes);
    }

    task<> LogVoleRingSender::offline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandSenderState& state,
        PRNG& prng,
        Socket& sock)
    {
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
        ShrinkExpandOfflineMessage message{};
        if (!prepareShrinkExpandSenderOffline(input, prng, message, state))
        {
            throw std::runtime_error("LogVole sender could not prepare shrink/expand offline message");
        }

        co_await sendOfflineFrame(sock, encode(message, input.mParams.mNumWorkerThreads));
    }

    task<> LogVoleRingSender::offline(
        const SenderOfflineInput& input,
        SenderState& state,
        PRNG& prng,
        Socket& sock)
    {
        const u64 senderRunId = input.mSenderOwnerRunId
            ? input.mSenderOwnerRunId : currentProtocolCacheScope().mRunId;
        RootWirePinOverlapEvidence initialPinEvidence{};
        initialPinEvidence.mSenderRunId = senderRunId;
        publishRootWirePinEvidence(initialPinEvidence);
        const char* rootPinOption = std::getenv("LV_GPU_ROOT_WIRE_PIN_OVERLAP");
        const bool rootPinRequested = rootPinOption && rootPinOption[0] == '1';
        const char* rootCudaOption = std::getenv("LV_GPU_ROOT_WIRE_CUDA_ALLOC");
        const bool rootCudaRequested = rootCudaOption &&
            rootCudaOption[0] == '1';
        const char* rootEarlyOption = std::getenv(
            "LV_GPU_ROOT_WIRE_CUDA_ALLOC_EARLY");
        const bool earlyRequested = rootCudaRequested && rootEarlyOption &&
            rootEarlyOption[0] == '1';
        resetRootWireCudaAllocEvidence(senderRunId, rootCudaRequested);
        std::size_t forecastBytes = 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        RootWireEarlyCudaWorker earlyWorker;
        if (earlyRequested)
        {
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Sender, senderRunId);
            forecastBytes = forecastRootOfflineWireSize(
                input.mParams, input.mLeafInputsAreGadget);
            const char* pinnedWire = std::getenv("LV_GPU_SETUP_PINNED_WIRE");
            const char* directWire = std::getenv(
                "LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD");
            const char* lazyWire = std::getenv(
                "LV_GPU_SETUP_LAZY_CIPHERTEXTS");
            const char* directEncoding = std::getenv("LV_GPU_SETUP_DIRECT_WIRE");
            const int device = gpu::currentDeviceOrdinal();
            const bool eligible = senderRunId != 0 &&
                input.mUseGpuResidentInternalState &&
                forecastBytes >= (std::size_t{1} << 20) &&
                gpu::enabled() && device >= 0 &&
                setupOwnedSendEnabled() &&
                (!pinnedWire || pinnedWire[0] != '0') &&
                (!directWire || directWire[0] != '0') &&
                (!lazyWire || lazyWire[0] != '0') &&
                (!directEncoding || directEncoding[0] != '0');
            const bool launched = eligible && earlyWorker.start(forecastBytes,
                senderRunId, device, tCpuBenchmarkContext);
            noteRootWireCudaEarlyPlan(senderRunId, earlyRequested,
                eligible, forecastBytes, launched);
        }
#else
        noteRootWireCudaEarlyPlan(senderRunId, earlyRequested,
            false, 0, false);
#endif
        SenderOfflineOutput output{};
        {
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Sender, senderRunId);
            if (!detail::prepareSenderOfflineForTransport(input, prng, output))
            {
                throw std::runtime_error(
                    "LogVole sender could not prepare recursive offline state");
            }
        }

        RootWirePinPlan rootPin(senderRunId, rootPinRequested,
            rootCudaRequested,
            (rootPinRequested || rootCudaRequested)
                ? terminalRootMessage(input.mParams, output.mMessage) : nullptr);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (earlyRequested)
            rootPin.adoptEarlyCudaWire(earlyWorker, forecastBytes);
#endif
        co_await sendOfflineMessage(input.mParams, output.mMessage,
            sock, true, false, senderRunId, rootPin);
        state = std::move(output.mState);
    }

    task<> LogVoleRingSender::keyDerive(
        const KeyDeriveSenderInput& input,
        KeyDeriveSenderOutput& output,
        Socket& sock)
    {
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
		u64 maxPayload = 0;
		if (input.mSk1.size() > std::numeric_limits<u32>::max())
			throw std::length_error("LogVole key-derive dimension is too large");
		const bool validPayloadSize =
			keyDerivePayloadSize(input.mParams, static_cast<u32>(input.mSk1.size()), maxPayload);
		const auto requestPayload =
			co_await recvFrame(sock, requirePayloadSize(validPayloadSize, maxPayload));

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
        }
        cacheScope.mRole = ProtocolCacheRole::Sender;
        ScopedProtocolCacheScope scopedCache(cacheScope);
        HostStep onlineTotal("send: online TOTAL");
        {
            HostStep step("send: clear cache + sid");
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
            co_await senderOnlineService(state, state, sock, prng, comm, cacheScope);
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
        HostStep tailStep("send: online tail (tbk copy)");
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
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& output,
        Socket& sock)
    {
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
		u64 maxPayload = 0;
		const bool validPayloadSize = polyPayloadSize(state.mParams.mRing, maxPayload);
		const auto digestPayload =
			co_await recvFrame(sock, requirePayloadSize(validPayloadSize, maxPayload));

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
                state.hostSk1(),
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
                state.hostSk1(),
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
