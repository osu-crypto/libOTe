#include "libOTe/Vole/LogVole/LogVoleRingSender.h"
#include <chrono>

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleTransport.h"
#include "libOTe/config.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include <cuda_runtime_api.h>
#endif

#include <cstddef>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <thread>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
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

            bool start(const Buffer& wire, ProtocolCacheRunId runId, int device,
                CpuBenchmarkContext* benchmarkContext, HostStepProfiler* profile)
            {
                const auto view = wire.wireView();
                try
                {
                    mThread = std::thread([this, view, identityService = runId.serviceOwner(), device,
                        benchmarkContext, profile] {
                        try
                        {
                            CpuBenchmarkWorkerScope benchmarkWorker(benchmarkContext);
                CpuBenchmarkState cpuBenchmark{benchmarkContext, true};
                            CpuBenchmarkTaskScope benchmarkTask(cpuBenchmark);
                            HostStep phase(profile, "setup: root wire preregistration");
                            mBeginNs = steadyClockNs();
                            const u64 cpuBegin = cpuBenchmarkThreadNs();
                            bool pinned = false;
                            mPinned = cudaSetDevice(device) == cudaSuccess &&
                                view.mMemory && view.mMemory->pin(view.data(), view.size(), pinned) &&
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

            bool start(std::size_t forecastBytes, ProtocolCacheRunId runId, int device,
                CpuBenchmarkContext* benchmarkContext, const LogVoleWireOptions& options, HostStepProfiler* profile)
            {
                try
                {
                    mThread = std::thread([this, forecastBytes, runId, identityService = runId.serviceOwner(), device,
                        benchmarkContext, &options, profile] {
                        try
                        {
                            CpuBenchmarkWorkerScope benchmarkWorker(
                                benchmarkContext);
                CpuBenchmarkState cpuBenchmark{benchmarkContext, true};
                            CpuBenchmarkTaskScope benchmarkTask(cpuBenchmark);
                            HostStep phase(profile,
                                "setup: early CUDA-owned Root wire reservation");
                            if (cudaSetDevice(device) != cudaSuccess ||
                                !gpu::available()) return;
                            mReserved = reserveRootCudaWireBuffer(
                                forecastBytes, runId, mCudaOwned, false, {}, options, profile);
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



        task<> sendOfflineFrame(Socket& sock, Buffer payload, bool ownedSend, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark = {})
        {
            HostStep phase(profile, "setup transport: send offline frame", &cpuBenchmark);
            // Encoding creates a fresh, single-use buffer. Keep ownership in
            // the coroutine and hand it to coproto, avoiding a second complete
            // copy of the (potentially hundreds of MB) offline message.
            if (ownedSend)
            {
                co_await detail::sendOwnedFrame(sock, std::move(payload));
            }
            else
            {
                co_await detail::sendFrame(sock, payload);
            }
        }



        RootOfflineMessage* terminalRootMessage(
            const Params& params, OfflineMessage& message)
        {
            Params levelParams = params;
            OfflineMessage* level = &message;
            while (level)
            {
                RecursiveMode mode{};
                if (!detail::recursiveMode(levelParams, mode)) return nullptr;
                if (mode == RecursiveMode::Root) return &level->mRootMessage;
                Params nextParams{};
                if (!level->mNextLevel || !detail::childParams(levelParams, nextParams))
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
            const LogVoleWireOptions& mWireOptions;
            HostStepProfiler* const mProfile;
            CpuBenchmarkState mCpuBenchmark;
            Buffer mReserved;
            bool mCudaRequested = false;
            bool mOwnedSend = true;
            bool mCudaAttempted = false;
            bool mCudaSelected = false;
#if defined(ENABLE_LOGVOLE_CUDA)
            // Destruct before mReserved on cancellation or an exception.
            RootWirePinWorker mWorker;
#endif

            RootWirePinPlan(ProtocolCacheRunId senderRunId, bool requested,
                bool cudaRequested,
                RootOfflineMessage* root, bool ownedSend, const LogVoleWireOptions& options, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
                : mRoot(root), mWireOptions(options), mProfile(profile), mCpuBenchmark(cpuBenchmark),
                  mCudaRequested(cudaRequested), mOwnedSend(ownedSend)
            {
                mEvidence.mSenderRunId = senderRunId;
                mEvidence.mIdentityService = senderRunId.serviceOwner();
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
                const bool eligible = mEvidence.mSenderRunId != 0 &&
                    deviceExport && mEvidence.mWireBytes >=
                        (std::size_t{1} << 20) &&
                    gpu::available() && gpu::currentDeviceOrdinal() >= 0 &&
                    mOwnedSend &&
                    mWireOptions.mPinned &&
                    mWireOptions.mDirectDownload;
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
                HostStep waitStep(mProfile, "setup: early Root wire reservation join");
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
                mReserved = reserveRootCudaWireBuffer(
                    static_cast<std::size_t>(mEvidence.mWireBytes),
                    mEvidence.mSenderRunId, mCudaSelected, true, {}, mWireOptions, mProfile);
#endif
            }

            void startBeforeFrame()
            {
                auto cpuBenchmark = mCpuBenchmark;
                reserveCudaWireIfRequested();
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!mEvidence.mRequested || !mRoot || mCudaSelected ||
                    mEvidence.mLaunched || mEvidence.mAlreadyPinned)
                    return;
                if (!mEvidence.mWireBytes)
                    mEvidence.mWireBytes = rootOfflineWireSize(*mRoot);
                const bool deviceExport = mRoot->mLazyCtR ||
                    mRoot->mLazyLacctLeft || mRoot->mLazyTopCt;
                const int device = gpu::currentDeviceOrdinal();
                if (!deviceExport || mEvidence.mWireBytes <
                        (std::size_t{1} << 20) || !gpu::available() || device < 0 ||
                    !mWireOptions.mPinned ||
                    !mWireOptions.mDirectDownload)
                    return;

                if (mReserved.empty())
                    mReserved.resize(static_cast<std::size_t>(
                        mEvidence.mWireBytes), AllocType::Uninitialized, mWireOptions);
                mEvidence.mEligible = mReserved.memory() && mReserved.memory()->contains(
                    mReserved.data(), mReserved.size());
                if (!mEvidence.mEligible) return;
                mEvidence.mAlreadyPinned = mReserved.memory()->isPinned(
                    mReserved.data(), mReserved.size());
                mEvidence.mPinSucceeded = mEvidence.mAlreadyPinned;
                if (!mEvidence.mAlreadyPinned)
                    mEvidence.mLaunched = mWorker.start(mReserved,
                        mEvidence.mSenderRunId, device, cpuBenchmark.mContext, mProfile);
#endif
            }

            void joinBeforeRootEncode() noexcept
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!mEvidence.mLaunched) return;
                HostStep waitStep(mProfile, "setup: root wire preregistration join");
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
            RootWirePinPlan& rootPin, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark = {})
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
                rootPin.startBeforeFrame();
                co_await sendOfflineFrame(shrinkExpandSock, std::move(payload), params.mShrinkExpand.mTransport.mOwnedSetupSend, profile, cpuBenchmark);
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
                    payload = rootPin.mReserved.empty()
                        ? encode(message.mRootMessage,
                            params.mShrinkExpand.mNumWorkerThreads, params.mShrinkExpand.mTransport.mEncoding, useGpu, profile, cpuBenchmark)
                        : encodeRootOfflineIntoBuffer(message.mRootMessage,
                            std::move(rootPin.mReserved),
                            params.mShrinkExpand.mNumWorkerThreads, params.mShrinkExpand.mTransport.mEncoding, useGpu, profile);
                }
                rootPin.mEvidence.mSelected = rootPin.mEvidence.mEligible &&
                    rootPin.mEvidence.mPinSucceeded;
                co_await sendOfflineFrame(rootSock, std::move(payload), params.mShrinkExpand.mTransport.mOwnedSetupSend, profile, cpuBenchmark);
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
                childSock, false, childHasReusableState, rootPin, useGpu, profile, cpuBenchmark);
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
                    const bool ownedFastPath = state.mParams.mShrinkExpand.mTransport.mOwnedRootMessages;
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
                        auto preparation = ownedFastPath
                                ? prepareRootResponseSender(executor, buffers, state, std::move(digest),
                                    prng, response, &precomputeRoot, havePreK ? &preKPrime : nullptr,
                                    true, preKPrimeDevice, cpuBenchmark, senderScope)
                                : prepareRootResponseSender(executor, buffers, state, digest,
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
                        if (ownedFastPath)
                        {
                            co_await detail::sendOwnedFrame(rootSock, std::move(responsePayload));
                        }
                        else
                        {
                            co_await detail::sendFrame(rootSock, responsePayload);
                        }
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
            input.mParams.mTransport.mOwnedSetupSend, hostProfiler(input.mRingFactoryOwner), cpuBenchmark);
    }

    task<> LogVoleRingSender::offline(macoro::thread_pool &executor, std::span<u8> setupResults,
                                      const SenderOfflineInput &input, SenderState &state, PRNG &prng,
                                      Socket &sock, RootWirePinOverlapEvidence &rootWirePin, ProtocolCacheScope cacheScope)
    {
        return offlineStart(executor, setupResults, input, state, prng, sock, rootWirePin,
                            std::move(cacheScope));
    }

    task<> LogVoleRingSender::offlineStart(macoro::thread_pool &executor, std::span<u8> setupResults,
                                           const SenderOfflineInput &input, SenderState &state, PRNG &prng,
                                           Socket &sock, RootWirePinOverlapEvidence &rootWirePin,
                                           ProtocolCacheScope cacheScope)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(input.mRingFactoryOwner)};
        const ProtocolCacheRunId senderRunId = input.mSenderOwnerRunId ? input.mSenderOwnerRunId : cacheScope.mRunId;
        cacheScope = ProtocolCacheScope{senderRunId, ProtocolCacheRole::Sender};
        rootWirePin = {};
        rootWirePin.mSenderRunId = senderRunId;
        rootWirePin.mIdentityService = senderRunId.serviceOwner();
        const auto &encoding = input.mParams.mShrinkExpand.mTransport.mEncoding;
        const bool rootPinRequested = encoding.mRootWirePinOverlap;
        const bool rootCudaRequested = encoding.mRootWireCudaAlloc;
        const bool earlyRequested = rootCudaRequested && encoding.mRootWireCudaAllocEarly;
        resetRootWireCudaAllocEvidence(senderRunId, rootCudaRequested);
        std::size_t forecastBytes = 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        RootWireEarlyCudaWorker earlyWorker;
        if (earlyRequested)
        {
            forecastBytes = forecastRootOfflineWireSize(input.mParams, input.mLeafInputsAreGadget);
            const int device = gpu::currentDeviceOrdinal();
            const bool eligible = senderRunId != 0 && input.mUseGpuResidentInternalState &&
                                  forecastBytes >= (std::size_t{1} << 20) &&
                                  gpu::enabled(input.mRingFactoryOwner) && device >= 0 &&
                                  input.mParams.mShrinkExpand.mTransport.mOwnedSetupSend &&
                                  encoding.mWire.mPinned && encoding.mWire.mDirectDownload &&
                                  input.mParams.mShrinkExpand.mGpuSetup.mLazyCiphertexts &&
                                  input.mParams.mShrinkExpand.mGpuSetup.mDirectWire;
            const bool launched =
                eligible && earlyWorker.start(forecastBytes, senderRunId, device, cpuBenchmark.mContext,
                                              encoding.mWire, hostProfiler(input.mRingFactoryOwner));
            noteRootWireCudaEarlyPlan(senderRunId, earlyRequested, eligible, forecastBytes, launched);
        }
#else
        noteRootWireCudaEarlyPlan(senderRunId, earlyRequested, false, 0, false);
#endif
        SenderOfflineOutput output{};
        {
            if (!co_await detail::prepareSenderOfflineForTransport(
                    executor, setupResults, input, prng, output, cpuBenchmark,
                    cacheScope))
            {
                throw std::runtime_error("LogVole sender could not prepare recursive offline state");
            }
        }

        RootWirePinPlan rootPin(senderRunId, rootPinRequested, rootCudaRequested,
                                (rootPinRequested || rootCudaRequested)
                                    ? terminalRootMessage(input.mParams, output.mMessage)
                                    : nullptr,
                                input.mParams.mShrinkExpand.mTransport.mOwnedSetupSend, encoding.mWire,
                                hostProfiler(input.mRingFactoryOwner), cpuBenchmark);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (earlyRequested) rootPin.adoptEarlyCudaWire(earlyWorker, forecastBytes);
#endif
        co_await sendOfflineMessage(input.mParams, output.mMessage, sock, true, false, rootPin,
                                    gpu::enabled(input.mRingFactoryOwner),
                                    hostProfiler(input.mRingFactoryOwner), cpuBenchmark);
        // sendOfflineMessage joins the pinning worker before encoding the root.
        rootWirePin = rootPin.mEvidence;
        state = std::move(output.mState);
    }

    task<> LogVoleRingSender::keyDerive(
        const KeyDeriveSenderInput& input,
        KeyDeriveSenderOutput& output,
        Socket& sock, LogVoleEncodingOptions encoding, bool useGpu, HostStepProfiler* profile, ProtocolCacheScope scope,
        TimingStats* timing)
    {
        CpuBenchmarkState cpuBenchmark{};
        if (useGpu) timing = &globalTimingStats;
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
        if (!processKeyDeriveRequest(input, request, response, output, scope))
        {
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

            responsePayload = encode(makePolyMessage(state.mParams.mRing, skX), state.mParams.mTransport.mEncoding,
                gpu::enabled(state.mRingFactoryOwner), hostProfiler(state.mRingFactoryOwner), cpuBenchmark);
        }
        co_await detail::sendFrame(sock, std::move(responsePayload));

        ShrinkExpandExpandSenderInput expandInput = input;
        expandInput.mDigest = std::move(digest);
        bool expanded;
        if (gpu::enabled(state.mRingFactoryOwner))
        {
            expanded = shrinkExpandExpandSender(state, expandInput, output,
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
