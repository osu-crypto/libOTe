#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"

#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <utility>

#if defined(ENABLE_LOGVOLE_CUDA)
namespace osuCrypto::LogVole::gpu
{
    bool setupSeedLabelRepBatchMatches(const RingNttContext&,
        const DeviceBatch&, std::size_t expectedCount, u64 ownerRunId);
}
#endif

namespace osuCrypto::LogVole
{
    namespace detail
    {
        namespace
        {
            class LazyLacctTensor final : public LazyLacctHostState
            {
            public:
                LazyLacctTensor(const ShrinkExpandLacct& metadata,
                    std::shared_ptr<const LazyRingTensorHostState> tensor)
                    : mTensor(std::move(tensor))
                {
                    mValue.mWidthPadded = metadata.mWidthPadded;
                    mValue.mLevels = metadata.mLevels;
                    mValue.mCt.mRows = metadata.mCt.mRows;
                    mValue.mCt.mCols = metadata.mCt.mCols;
                }
                const ShrinkExpandLacct& get() const override
                {
                    std::call_once(mOnce, [&] { mValue.mCt = mTensor->get(); });
                    return mValue;
                }
                bool copyCoefficientsTo(std::span<u8> destination) const override
                {
                    return mTensor->copyCoefficientsTo(destination);
                }
                std::span<const u8> encodedCoefficients() const override
                {
                    return mTensor->encodedCoefficients();
                }
            private:
                std::shared_ptr<const LazyRingTensorHostState> mTensor;
                mutable std::once_flag mOnce;
                mutable ShrinkExpandLacct mValue;
            };
        }

        std::shared_ptr<const LazyLacctHostState> makeLazyLacctHostState(
            const ShrinkExpandLacct& metadata,
            std::shared_ptr<const LazyRingTensorHostState> tensor)
        {
            return tensor ? std::make_shared<LazyLacctTensor>(metadata, std::move(tensor)) : nullptr;
        }
    }

    namespace
    {
        constexpr double kNoiseStdS = 3.19;
        constexpr double kNoiseLambda = 128.0;

        bool setupBatchNttEnabled()
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_BATCH_NTT");
            return (!value || value[0] != '0') && gpu::enabled();
#else
            return false;
#endif
        }

        bool setupParallelMessageCopyEnabled()
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_PARALLEL_MESSAGE_COPY");
            return (!value || value[0] != '0') && gpu::enabled();
#else
            return false;
#endif
        }

        u32 logQBits(const RingParams& params)
        {
            u32 logQ = 0;
            for (int bits : params.mCoeffModulusBits)
            {
                logQ += static_cast<u32>(bits);
            }
            return logQ;
        }

        double computeSigma(double factor)
        {
            const double normalizedFactor = (factor > 1.0) ? factor : 1.0;
            return kNoiseStdS * normalizedFactor;
        }

        bool isValidShrinkExpandMode(ShrinkExpandMode mode)
        {
            switch (mode)
            {
            case ShrinkExpandMode::FullNoise:
                return true;
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
            case ShrinkExpandMode::Deterministic:
                return true;
#endif
            default:
                return false;
            }
        }

        bool usesFullNoise(const ShrinkExpandParams& params)
        {
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
            return params.mMode == ShrinkExpandMode::FullNoise;
#else
            (void)params;
            return true;
#endif
        }

        bool receiverPublicHosts(const RingNttContext& ctx,
            const ShrinkExpandReceiverState& state,
            std::shared_ptr<const std::vector<RnsPoly>>& publicA,
            std::shared_ptr<const std::vector<RnsPoly>>& publicB)
        {
            publicA = state.mPublicANtt;
            publicB = state.mPublicBNtt;
            if ((!publicA || !publicB) && state.mLazyPublicUniformHosts)
            {
                std::shared_ptr<const std::vector<RnsPoly>> cachedA, cachedB;
                if (!state.mLazyPublicUniformHosts->get(cachedA, cachedB)) return false;
                if (!publicA) publicA = std::move(cachedA);
                if (!publicB) publicB = std::move(cachedB);
            }
#if defined(ENABLE_LOGVOLE_CUDA)
            if (!publicA && state.mPublicANttDevice &&
                !gpu::materializeRetainedPublicUniform(ctx, state.mPublicANttDevice, publicA))
                return false;
            if (!publicB && state.mPublicBNttDevice &&
                !gpu::materializeRetainedPublicUniform(ctx, state.mPublicBNttDevice, publicB))
                return false;
#endif
            if (!publicA) publicA = sharedLhePublicANtt(ctx, state.mParams.mMu);
            const u32 publicBTau = state.mParams.mTruncateOneGadgetDigit
                ? state.mParams.mTau + 1u : state.mParams.mTau;
            if (!publicB) publicB = sharedLencPublicBNtt(ctx, publicBTau);
            return publicA && publicB && publicA->size() == state.mParams.mMu &&
                publicB->size() == 2u * static_cast<std::size_t>(publicBTau) &&
                validateRingBatchShape(*publicA, ctx.mParams) &&
                validateRingBatchShape(*publicB, ctx.mParams);
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        class LazyPublicUniformHosts final : public LazyPublicUniformHostState
        {
        public:
            LazyPublicUniformHosts(
                RingNttContext ctx,
                gpu::RetainedPublicUniformPtr publicA,
                gpu::RetainedPublicUniformPtr publicB,
                ProtocolCacheScope scope)
                : mCtx(std::move(ctx)),
                  mPublicADevice(std::move(publicA)),
                  mPublicBDevice(std::move(publicB)),
                  mScope(scope)
            {
            }

            bool get(
                std::shared_ptr<const std::vector<RnsPoly>>& publicA,
                std::shared_ptr<const std::vector<RnsPoly>>& publicB) const override
            {
                std::lock_guard<std::mutex> lock(mMutex);
                if (!mPublicA || !mPublicB)
                {
                    ScopedProtocolCacheScope roleScope(mScope);
                    std::shared_ptr<const std::vector<RnsPoly>> nextA, nextB;
                    if (!gpu::materializeRetainedPublicUniform(
                            mCtx, mPublicADevice, nextA) ||
                        !gpu::materializeRetainedPublicUniform(
                            mCtx, mPublicBDevice, nextB)) return false;
                    // Publish the pair only after both exact snapshots exist.
                    mPublicA = std::move(nextA);
                    mPublicB = std::move(nextB);
                }
                publicA = mPublicA;
                publicB = mPublicB;
                return true;
            }

        private:
            RingNttContext mCtx;
            gpu::RetainedPublicUniformPtr mPublicADevice;
            gpu::RetainedPublicUniformPtr mPublicBDevice;
            ProtocolCacheScope mScope{};
            mutable std::mutex mMutex;
            mutable std::shared_ptr<const std::vector<RnsPoly>> mPublicA;
            mutable std::shared_ptr<const std::vector<RnsPoly>> mPublicB;
        };
#endif

        bool buildReceiverDigestTree(
            const RingNttContext& ctx,
            const ShrinkExpandReceiverState& state,
            std::span<const RnsPoly> x,
            DigestTree& out)
        {
            std::shared_ptr<const std::vector<RnsPoly>> publicA, publicB;
            if (!receiverPublicHosts(ctx, state, publicA, publicB)) return false;
            const std::vector<RnsPoly>* publicBNtt = publicB.get();
            if (state.mParams.mTruncateOneGadgetDigit)
            {
                return buildDigestTreeTrunc(
                    ctx,
                    x,
                    state.mParams.mTau,
                    state.mParams.mGadgetLogBase,
                    state.mParams.mPlaintextModulusBits,
                    out,
                    state.mLacct.mWidthPadded,
                    state.mParams.mLeafInputsAreGadget,
                    publicBNtt,
                    state.mParams.mNumWorkerThreads);
            }

            return buildDigestTree(
                ctx,
                x,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                out,
                state.mLacct.mWidthPadded,
                publicBNtt,
                state.mParams.mNumWorkerThreads);
        }

        bool ensureReceiverDigestTree(
            const RingNttContext& ctx,
            const ShrinkExpandReceiverState& state,
            const ShrinkExpandExpandReceiverInput& input,
            std::shared_ptr<DigestTree>& out)
        {
            if (input.mTree)
            {
                out = input.mTree;
                return true;
            }

            if (input.mX.size() != state.mParams.mMu)
            {
                return false;
            }

            DigestTree tree{};
            if (!buildReceiverDigestTree(ctx, state, input.mX, tree) ||
                !rangesEqual(tree.mDigest.mCoeffs, input.mDigest.mCoeffs))
            {
                return false;
            }

            out = std::make_shared<DigestTree>(std::move(tree));
            return true;
        }

        bool validateStateParamsMatch(const ShrinkExpandParams& expected, const ShrinkExpandParams& actual)
        {
            return expected.mRing == actual.mRing &&
                   expected.mPlaintextModulusBits == actual.mPlaintextModulusBits &&
                   expected.mAlpha == actual.mAlpha &&
                   expected.mMu == actual.mMu &&
                   expected.mGadgetLogBase == actual.mGadgetLogBase &&
                   expected.mTau == actual.mTau &&
                   expected.mTruncateOneGadgetDigit == actual.mTruncateOneGadgetDigit &&
                   expected.mLeafInputsAreGadget == actual.mLeafInputsAreGadget &&
                   expected.mMode == actual.mMode &&
                   expected.mNoiseBound == actual.mNoiseBound;
        }

    }

    bool validateShrinkExpandParams(const ShrinkExpandParams& params)
    {
        if (!validateRingParams(params.mRing) ||
            params.mAlpha == 0 ||
            params.mMu == 0 ||
            params.mTau == 0 ||
            params.mPlaintextModulusBits == 0 ||
            params.mGadgetLogBase == 0 ||
            !isValidShrinkExpandMode(params.mMode) ||
            params.mNoiseBound < 0)
        {
            return false;
        }

        if (logQBits(params.mRing) <= params.mPlaintextModulusBits)
        {
            return false;
        }

        if (params.mTruncateOneGadgetDigit && !params.mLeafInputsAreGadget)
        {
            const u32 supportedPlaintextBits = params.mTau * params.mGadgetLogBase;
            if (supportedPlaintextBits < params.mPlaintextModulusBits)
            {
                return false;
            }
        }

        return true;
    }

    bool validateShrinkExpandSenderOfflineInput(const ShrinkExpandSenderOfflineInput& input)
    {
        const bool residentSeedLabels = input.mS.empty() &&
            input.mSDevice && input.mLazyS &&
            input.mParams.mTruncateOneGadgetDigit;
        if (!validateShrinkExpandParams(input.mParams) ||
            (!residentSeedLabels && (input.mS.size() != input.mParams.mMu ||
                !validateRingBatchShape(input.mS, input.mParams.mRing))) ||
            (input.mSDevice && !residentSeedLabels) ||
            (residentSeedLabels && (input.mLazyS->count() != input.mParams.mMu ||
                !input.mLazyS->matches(input.mParams.mRing))))
        {
            return false;
        }

        const bool residentFixedSk1 = input.mFixedSk1.empty() &&
            input.mFixedSk1Device && input.mLazyFixedSk1 &&
            input.mDeferTopSk1Host && input.mParams.mTruncateOneGadgetDigit;
        if ((input.mFixedSk1Device && !residentFixedSk1) ||
            (input.mLazyFixedSk1 && !residentFixedSk1) ||
            (residentFixedSk1 && (input.mLazyFixedSk1->count() !=
                input.mParams.mTau ||
                !input.mLazyFixedSk1->matches(input.mParams.mRing)))) return false;
        if (!input.mFixedSk1.empty() &&
            (input.mFixedSk1.size() != input.mParams.mTau ||
             !validateRingBatchShape(input.mFixedSk1, input.mParams.mRing)))
        {
            return false;
        }

        return true;
    }

    bool validateShrinkExpandReceiverOfflineInput(const ShrinkExpandReceiverOfflineInput& input)
    {
        return validateShrinkExpandParams(input.mParams);
    }

    std::vector<RnsPoly> sampleUniformBatch(const RingNttContext& ctx, u32 count, PRNG& prng)
    {
        return sampleUniformPolyBatch(ctx, count, prng);
    }

    static bool prepareShrinkExpandSenderOfflineImpl(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandOfflineMessage* message,
        ShrinkExpandSenderState& senderState)
    {
        HostStep setupStep("setup sender: shrink expand total");
        // A direct caller must not promote a receiver scope into a sender
        // capability merely by invoking the sender API with a private token.
        if (input.mFixedSk1Device &&
            (currentProtocolCacheScope().mRole != ProtocolCacheRole::Sender ||
             currentProtocolCacheScope().mRunId != input.mFixedSk1OwnerRunId))
            return false;
        ScopedProtocolCacheScope senderScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
        if (!validateShrinkExpandSenderOfflineInput(input))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams.mRing, ctx))
        {
            return false;
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (input.mFixedSk1Device &&
            (!gpu::topSecretUniformBatchMatches(ctx,
                *input.mFixedSk1Device, input.mParams.mTau,
                input.mFixedSk1OwnerRunId) ||
             currentProtocolCacheScope().mRunId != input.mFixedSk1OwnerRunId))
            return false;
#else
        if (input.mFixedSk1Device) return false;
#endif

        if (input.mSDevice)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (message || !gpu::enabled() ||
                !gpu::setupSeedLabelRepBatchMatches(ctx,
                    *input.mSDevice, input.mParams.mMu,
                    currentProtocolCacheScope().mRunId)) return false;
#else
            return false;
#endif
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        // Join before leaving this timed setup scope. Independent CPU sampling
        // can overlap first-use GPU initialization without excluding its cost.
        gpu::GpuRingSetupPrefetch ringPrefetch(ctx, gpu::enabled());
#endif

        ShrinkExpandSenderState next{};
        next.mParams = input.mParams;
        next.mS = input.mS;
        next.mLazyS = input.mLazyS;
        if (input.mFixedSk1Device)
        {
            next.mTopSk1Device = input.mFixedSk1Device;
            next.mLazyTopSk1 = input.mLazyFixedSk1;
            next.mTopSk1OwnerRunId = input.mFixedSk1OwnerRunId;
        }
        else if (!input.mFixedSk1.empty())
        {
            next.mSk1 = input.mFixedSk1;
        }
        else
        {
            HostStep sk1Step("setup sender: top sk1 uniform sampling");
            if (input.mDeferTopSk1Host && !message &&
                input.mParams.mTruncateOneGadgetDigit)
            {
                std::shared_ptr<gpu::DeviceBatch> resident;
                std::shared_ptr<const LazyRootSecretHostState> lazy;
                if (!sampleTopSecretUniformBatch(ctx, input.mParams.mTau,
                        prng, next.mSk1, resident, lazy)) return false;
                next.mTopSk1Device = std::move(resident);
                next.mLazyTopSk1 = std::move(lazy);
                if (next.mTopSk1Device)
                    next.mTopSk1OwnerRunId = currentProtocolCacheScope().mRunId;
            }
            else next.mSk1 = sampleUniformBatch(ctx, input.mParams.mTau, prng);
        }

        HostStep publicDataStep("setup sender: public data");
        const u32 publicBTau = input.mParams.mTruncateOneGadgetDigit ? (input.mParams.mTau + 1u) : input.mParams.mTau;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (input.mDeferHostCiphertexts && !message && gpu::enabled() &&
            gpu::publicUniformRetentionEnabled())
        {
            next.mPublicANttDevice = retainedLhePublicANtt(ctx, input.mParams.mMu);
            next.mPublicBNttDevice = retainedLencPublicBNtt(ctx, publicBTau);
            if (!next.mPublicANttDevice || !next.mPublicBNttDevice)
            {
                next.mPublicANttDevice.reset();
                next.mPublicBNttDevice.reset();
            }
            else
            {
                next.mPublicUniformRunId = currentProtocolCacheScope().mRunId;
                next.mLazyPublicUniformHosts =
                    std::make_shared<const LazyPublicUniformHosts>(
                        ctx, next.mPublicANttDevice, next.mPublicBNttDevice,
                        currentProtocolCacheScope());
            }
        }
#endif
        if (!next.mPublicANttDevice)
        {
            next.mPublicANtt = sharedLhePublicANtt(ctx, input.mParams.mMu);
            next.mPublicBNtt = sharedLencPublicBNtt(ctx, publicBTau);
        }
        if ((!next.mPublicANtt && !next.mPublicANttDevice) ||
            (!next.mPublicBNtt && !next.mPublicBNttDevice)) return false;
        publicDataStep.stop();

        const bool fullNoise = usesFullNoise(input.mParams);
        const double lencSigma = fullNoise ? computeSigma(std::sqrt(static_cast<double>(input.mParams.mTau))) : 0.0;
        const double lencMaxDev = fullNoise ? std::sqrt(kNoiseLambda) * lencSigma : 0.0;

        LencEncodeOutput lenc{};
        bool lencOk = false;
        if (input.mParams.mTruncateOneGadgetDigit)
        {
            lencOk = lencEncTrunc(
                ctx,
                input.mS,
                input.mParams.mTau,
                input.mParams.mGadgetLogBase,
                input.mParams.mPlaintextModulusBits,
                prng,
                lenc,
                lencSigma,
                lencMaxDev,
                0,
                true,
                input.mParams.mLeafInputsAreGadget,
                next.mPublicBNtt.get(),
                input.mParams.mNumWorkerThreads,
                input.mDeferHostCiphertexts && !message,
                input.mDeferHostCiphertexts && !message,
                input.mSDevice.get(), input.mLazyS.get());
        }
        else
        {
            lencOk = lencEnc(
                ctx,
                input.mS,
                input.mParams.mTau,
                input.mParams.mGadgetLogBase,
                prng,
                lenc,
                lencSigma,
                lencMaxDev,
                0,
                true,
                next.mPublicBNtt.get(),
                input.mParams.mNumWorkerThreads,
                input.mDeferHostCiphertexts && !message);
        }
        if (!lencOk)
        {
            return false;
        }

        next.mR = std::move(lenc.mR);
        next.mLazyRandomizers = lenc.mLazyRandomizers;
        next.mLacct.mWidthPadded = lenc.mLacct.mWidthPadded;
        next.mLacct.mLevels = lenc.mLacct.mLevels;
        next.mLacct.mCt = std::move(lenc.mLacct.mCt);
        next.mLazyLacct = detail::makeLazyLacctHostState(next.mLacct, std::move(lenc.mLazyCt));

        const double lheSigma = fullNoise ? computeSigma(std::sqrt(static_cast<double>(next.mLacct.mWidthPadded))) : 0.0;
        const double lheMaxDev = fullNoise ? std::sqrt(kNoiseLambda) * lheSigma : 0.0;

        bool ct1Ok = false;
        if (input.mParams.mTruncateOneGadgetDigit)
        {
            ct1Ok = lheEnc1Trunc(
                ctx,
                lenc.mRNtt,
                next.mSk1,
                input.mParams.mGadgetLogBase,
                next.mCt1,
                lheSigma,
                lheMaxDev,
                &prng,
                true,
                next.mPublicANtt.get(),
                input.mParams.mNumWorkerThreads,
                input.mDeferHostCiphertexts && !message ? &next.mLazyCt1 : nullptr,
                lenc.mLazyRandomizers, nullptr, nullptr,
                next.mTopSk1Device.get(), next.mLazyTopSk1.get(),
                next.mTopSk1OwnerRunId, static_cast<bool>(next.mTopSk1Device));
        }
        else
        {
            ct1Ok = lheEnc1(
                ctx,
                lenc.mRNtt,
                next.mSk1,
                input.mParams.mGadgetLogBase,
                next.mCt1,
                lheSigma,
                lheMaxDev,
                &prng,
                true,
                next.mPublicANtt.get(),
                input.mParams.mNumWorkerThreads,
                input.mDeferHostCiphertexts && !message ? &next.mLazyCt1 : nullptr,
                lenc.mLazyRandomizers);
        }
        if (!ct1Ok)
        {
            return false;
        }

        // The state-only/transport path has no independently mutable message
        // to publish. Keep the one complete state and encode its const tensors
        // directly when the socket caller needs bytes.
        if (!message)
        {
            senderState = std::move(next);
            return true;
        }

        ShrinkExpandOfflineMessage nextMessage{};
        nextMessage.mParams = next.mParams;
        HostStep messageCopyStep("setup sender: offline message copy");
        if (setupParallelMessageCopyEnabled())
        {
            nextMessage.mCt1.mRows = next.mCt1.mRows;
            nextMessage.mCt1.mCols = next.mCt1.mCols;
            nextMessage.mLacct.mWidthPadded = next.mLacct.mWidthPadded;
            nextMessage.mLacct.mLevels = next.mLacct.mLevels;
            nextMessage.mLacct.mCt.mRows = next.mLacct.mCt.mRows;
            nextMessage.mLacct.mCt.mCols = next.mLacct.mCt.mCols;
            const std::size_t ct1Count = next.mCt1.mPolys.size();
            const std::size_t lacctCount = next.mLacct.mCt.mPolys.size();
            nextMessage.mCt1.mPolys.resize(ct1Count);
            nextMessage.mLacct.mCt.mPolys.resize(lacctCount);
            // Each worker allocates and copies its own polynomial. Message and
            // state remain independently mutable, exactly as with assignment.
            if (!detail::runParallelTasks(ct1Count + lacctCount,
                    input.mParams.mNumWorkerThreads, [&](std::size_t index) {
                        if (index < ct1Count)
                            nextMessage.mCt1.mPolys[index] = next.mCt1.mPolys[index];
                        else
                            nextMessage.mLacct.mCt.mPolys[index - ct1Count] =
                                next.mLacct.mCt.mPolys[index - ct1Count];
                        return true;
                    })) return false;
        }
        else
        {
            nextMessage.mCt1 = next.mCt1;
            nextMessage.mLacct = next.mLacct;
        }
        messageCopyStep.stop();

        *message = std::move(nextMessage);
        senderState = std::move(next);
        return true;
    }

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& senderState)
    {
        return prepareShrinkExpandSenderOfflineImpl(input, prng, &message, senderState);
    }

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandSenderState& senderState)
    {
        return prepareShrinkExpandSenderOfflineImpl(input, prng, nullptr, senderState);
    }

    template <typename Message>
    static bool finalizeShrinkExpandReceiverOfflineImpl(
        const ShrinkExpandReceiverOfflineInput& input,
        Message&& message,
        ShrinkExpandReceiverState& receiverState)
    {
        HostStep setupStep("setup receiver: shrink expand total");
        if (!validateShrinkExpandReceiverOfflineInput(input) ||
            !validateStateParamsMatch(input.mParams, message.mParams))
        {
            return false;
        }

        // Encoded owners retain validated immutable wire bytes. Their dimensions
        // are still checked here before any device allocation or consumption.
        const auto validTensor = [&](const RingTensor& tensor, const auto& lazy) {
            if (!lazy)
                return ringTensorSize(tensor) == tensor.mPolys.size() &&
                    validateRingBatchShape(tensor.mPolys, input.mParams.mRing);
            const u64 words = ringPolyCoeffCount(input.mParams.mRing);
            const auto bytes = lazy->encodedCoefficients();
            return tensor.mPolys.empty() && words && bytes.size() % sizeof(u64) == 0 &&
                ringTensorSize(tensor) <= (bytes.size() / sizeof(u64)) / words &&
                ringTensorSize(tensor) * words == bytes.size() / sizeof(u64);
        };
        // Validate the complete message before consuming any owned storage.
        if (message.mCt1.mRows != input.mParams.mMu ||
            message.mCt1.mCols != input.mParams.mTau ||
            !validTensor(message.mCt1, message.mLazyCt1) ||
            message.mLacct.mWidthPadded == 0 ||
            message.mLacct.mLevels == 0 ||
            message.mLacct.mCt.mRows != static_cast<u64>(message.mLacct.mLevels) * message.mLacct.mWidthPadded ||
            !validTensor(message.mLacct.mCt, message.mLazyLacct))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams.mRing, ctx))
        {
            return false;
        }

        ShrinkExpandReceiverState next{};
        next.mParams = input.mParams;
        HostStep publicDataStep("setup receiver: public data");
        const u32 publicBTau = input.mParams.mTruncateOneGadgetDigit ? (input.mParams.mTau + 1u) : input.mParams.mTau;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (input.mDeferHostSnapshot)
        {
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
            next.mPublicANttDevice = retainedLhePublicANtt(ctx, input.mParams.mMu);
            next.mPublicBNttDevice = retainedLencPublicBNtt(ctx, publicBTau);
            // Publish retained-only state only as a complete A/B pair. A
            // partial device attempt falls back to two exact eager owners.
            if (!next.mPublicANttDevice || !next.mPublicBNttDevice)
            {
                next.mPublicANttDevice.reset();
                next.mPublicBNttDevice.reset();
            }
            else
            {
                next.mLazyPublicUniformHosts =
                    std::make_shared<const LazyPublicUniformHosts>(
                        ctx, next.mPublicANttDevice, next.mPublicBNttDevice,
                        currentProtocolCacheScope());
            }
        }
#endif
        if (!next.mPublicANttDevice)
        {
            next.mPublicANtt = sharedLhePublicANtt(ctx, input.mParams.mMu);
            next.mPublicBNtt = sharedLencPublicBNtt(ctx, publicBTau);
        }
        if ((!next.mPublicANtt && !next.mPublicANttDevice) ||
            (!next.mPublicBNtt && !next.mPublicBNttDevice)) return false;
        publicDataStep.stop();

        next.mCt1 = std::forward<Message>(message).mCt1;
        next.mLacct = std::forward<Message>(message).mLacct;

#if defined(ENABLE_LOGVOLE_CUDA)
        const char* residentNtt = std::getenv("LV_GPU_SETUP_RECEIVER_RESIDENT_NTT");
        if (!residentNtt || residentNtt[0] != '0')
        {
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
            if (gpu::enabled())
            {
                if (gpu::finalizeReceiverSetupDevice(ctx, next, input.mDeferHostSnapshot,
                        message.mLazyCt1, message.mLazyLacct))
                {
                    receiverState = std::move(next);
                    return true;
                }
                const char* strict = std::getenv("LV_GPU_SETUP_RECEIVER_RESIDENT_NTT_STRICT");
                if (strict && strict[0] == '1') return false;
            }
        }
#endif

        if (!next.mPublicANtt || !next.mPublicBNtt)
        {
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
            std::shared_ptr<const std::vector<RnsPoly>> publicA, publicB;
            if (!receiverPublicHosts(ctx, next, publicA, publicB)) return false;
            // Materialize both local owners completely before publishing either
            // one to the state consumed by the CPU rollback.
            next.mPublicANtt = std::move(publicA);
            next.mPublicBNtt = std::move(publicB);
            next.mPublicANttDevice.reset();
            next.mPublicBNttDevice.reset();
            next.mLazyPublicUniformHosts.reset();
        }

        if (message.mLazyCt1) next.mCt1 = message.mLazyCt1->get();
        if (message.mLazyLacct) next.mLacct = message.mLazyLacct->get();

        // These ciphertext transforms are independent. Batching lets setup use
        // the existing device NTT instead of serial host transforms per cell.
        if (setupBatchNttEnabled())
        {
            if (!forwardNttBatch(next.mCt1.mPolys, ctx)) return false;
        }
        else
        {
            for (auto& poly : next.mCt1.mPolys)
            {
                if (!forwardNtt(poly, ctx)) return false;
            }
        }
        receiverState = std::move(next);
        return true;
    }

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& receiverState)
    {
        return finalizeShrinkExpandReceiverOfflineImpl(input, message, receiverState);
    }

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        ShrinkExpandOfflineMessage&& message,
        ShrinkExpandReceiverState& receiverState)
    {
        return finalizeShrinkExpandReceiverOfflineImpl(input, std::move(message), receiverState);
    }

    void materializeShrinkExpandHostState(ShrinkExpandSenderState& state)
    {
        if (!state.mSharedHostState && !state.mLazyCt1 && !state.mLazyLacct &&
            !state.mLazyRandomizers && !state.mPublicANttDevice &&
            !state.mPublicBNttDevice && !state.mLazyPublicUniformHosts &&
            !state.mTopSk1Device && !state.mLazyTopSk1)
        {
            state.mGpuCache.reset();
            return;
        }
        ShrinkExpandSenderState next = state;
        if ((!next.mPublicANtt || !next.mPublicBNtt) &&
            (state.mPublicANttDevice || state.mPublicBNttDevice ||
                state.mLazyPublicUniformHosts))
        {
            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mRing, ctx)) return;
            ScopedProtocolCacheScope senderScope(
                ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
            std::shared_ptr<const std::vector<RnsPoly>> publicA, publicB;
            if (state.mLazyPublicUniformHosts)
            {
                if (!state.mLazyPublicUniformHosts->get(publicA, publicB)) return;
            }
#if defined(ENABLE_LOGVOLE_CUDA)
            else
            {
                if (state.mPublicANttDevice &&
                    !gpu::materializeRetainedPublicUniform(ctx,
                        state.mPublicANttDevice, publicA)) return;
                if (state.mPublicBNttDevice &&
                    !gpu::materializeRetainedPublicUniform(ctx,
                        state.mPublicBNttDevice, publicB)) return;
            }
#endif
            if (!publicA) publicA = sharedLhePublicANtt(ctx, state.mParams.mMu);
            const u32 publicBTau = state.mParams.mTruncateOneGadgetDigit
                ? state.mParams.mTau + 1u : state.mParams.mTau;
            if (!publicB) publicB = sharedLencPublicBNtt(ctx, publicBTau);
            if (!publicA || !publicB || publicA->size() != state.mParams.mMu ||
                publicB->size() != 2u * static_cast<std::size_t>(publicBTau) ||
                !validateRingBatchShape(*publicA, ctx.mParams) ||
                !validateRingBatchShape(*publicB, ctx.mParams)) return;
            next.mPublicANtt = std::move(publicA);
            next.mPublicBNtt = std::move(publicB);
        }
        next.mS = state.hostS();
        next.mSk1 = state.hostSk1();
        next.mTopSk1Device.reset();
        next.mLazyTopSk1.reset();
        next.mTopSk1OwnerRunId = 0;
        next.mLazyS.reset();
        next.mR = state.hostR();
        next.mCt1 = state.hostCt1();
        next.mLacct = state.hostLacct();
        next.mSharedHostState.reset();
        next.mLazyCt1.reset();
        next.mLazyLacct.reset();
        next.mLazyRandomizers.reset();
        next.mPublicANttDevice.reset();
        next.mPublicBNttDevice.reset();
        next.mLazyPublicUniformHosts.reset();
        next.mPublicUniformRunId = 0;
        next.mGpuCache.reset();
        state = std::move(next);
    }

    void materializeShrinkExpandHostState(ShrinkExpandReceiverState& state)
    {
        if (!state.mSharedHostState && !state.mLazyCt1Ntt && !state.mLazyLacct &&
            !state.mPublicANttDevice && !state.mPublicBNttDevice &&
            !state.mLazyPublicUniformHosts)
        {
            state.mGpuCache.reset();
            return;
        }
        ShrinkExpandReceiverState next = state;
        if (!next.mPublicANtt || !next.mPublicBNtt)
        {
            RingNttContext ctx{};
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
            std::shared_ptr<const std::vector<RnsPoly>> publicA, publicB;
            if (!makeRingNttContext(state.mParams.mRing, ctx) ||
                !receiverPublicHosts(ctx, state, publicA, publicB)) return;
            next.mPublicANtt = std::move(publicA);
            next.mPublicBNtt = std::move(publicB);
        }
        next.mCt1 = state.hostCt1();
        next.mLacct = state.hostLacct();
        next.mSharedHostState.reset();
        next.mLazyCt1Ntt.reset();
        next.mLazyLacct.reset();
        next.mPublicANttDevice.reset();
        next.mPublicBNttDevice.reset();
        next.mLazyPublicUniformHosts.reset();
        next.mGpuCache.reset();
        state = std::move(next);
    }

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        ShrinkExpandShrinkOutput& out)
    {
        return shrinkExpandShrink(state, std::span<const RnsPoly>(x.data(), x.size()), out);
    }

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        ShrinkExpandShrinkOutput& out)
    {
        if (x.size() != state.mParams.mMu || !validateRingBatchShape(x, state.mParams.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        DigestTree tree{};
        if (!buildReceiverDigestTree(ctx, state, x, tree))
        {
            return false;
        }

        ShrinkExpandShrinkOutput next{};
        next.mDigest = tree.mDigest;
        next.mTree = std::make_shared<DigestTree>(std::move(tree));
        out = std::move(next);
        return true;
    }

    bool shrinkExpandExpandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& out)
    {
        if (!validateRingPolyShape(input.mTbkPrime, state.mParams.mRing) ||
            !validateRingPolyShape(input.mDigest, state.mParams.mRing) ||
            (!input.mMaskDigest.mCoeffs.empty() &&
                !validateRingPolyShape(input.mMaskDigest, state.mParams.mRing)) ||
            input.mSeed.empty())
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        const RnsPoly& maskDigest = input.mMaskDigest.mCoeffs.empty() ? input.mDigest : input.mMaskDigest;
        // Reuse storage only; query-bound coefficients are always rebuilt.
        thread_local std::vector<RnsPoly> senderCt2;
        if (!buildHashedCt2(
                ctx,
                state.mParams.mMu,
                input.mSeed,
                input.mSid,
                maskDigest,
                input.mNonce,
                senderCt2))
        {
            return false;
        }

        ShrinkExpandSenderExpandOutput next{};
        if (!lheDec(
                ctx,
                senderCt2,
                input.mTbkPrime,
                next.mTbk,
                state.mPublicANtt ? state.mPublicANtt.get() : nullptr,
                false,
                false,
                state.mParams.mNumWorkerThreads))
        {
            return false;
        }

        out = std::move(next);
        return true;
    }

    bool shrinkExpandExpandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandExpandReceiverInput& input,
        ShrinkExpandReceiverExpandOutput& out)
    {
        if ((!input.mTree && input.mX.size() != state.mParams.mMu) ||
            !validateRingPolyShape(input.mDigest, state.mParams.mRing) ||
            (!input.mMaskDigest.mCoeffs.empty() &&
                !validateRingPolyShape(input.mMaskDigest, state.mParams.mRing)) ||
            !validateRingPolyShape(input.mSkX, state.mParams.mRing) ||
            input.mSeed.empty())
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        std::shared_ptr<const std::vector<RnsPoly>> publicA, publicB;
        if (!receiverPublicHosts(ctx, state, publicA, publicB)) return false;

        std::shared_ptr<DigestTree> tree;
        if (!ensureReceiverDigestTree(ctx, state, input, tree))
        {
            return false;
        }

        const RnsPoly& maskDigest = input.mMaskDigest.mCoeffs.empty() ? input.mDigest : input.mMaskDigest;
        // Keep a separate reusable allocation for the receiver's coefficients.
        thread_local std::vector<RnsPoly> receiverCt2;
        const bool senderRole = currentProtocolCacheScope().mRole == ProtocolCacheRole::Sender;
        HostStep sampleStep(senderRole ? "cpu sender expand detail: sampling" : "cpu receiver expand detail: sampling");
        if (!buildHashedCt2(
                ctx,
                state.mParams.mMu,
                input.mSeed,
                input.mSid,
                maskDigest,
                input.mNonce,
                receiverCt2))
        {
            return false;
        }

        sampleStep.stop();
        HostStep applyStep(senderRole ? "cpu sender expand detail: apply" : "cpu receiver expand detail: apply");
        std::vector<RnsPoly> ct1AppliedNtt;
        bool applyOk = false;
        if (state.mParams.mTruncateOneGadgetDigit)
        {
            applyOk = lheApplyCt1Trunc(
                ctx,
                state.hostCt1(),
                input.mDigest,
                state.mParams.mGadgetLogBase,
                state.mParams.mTau,
                ct1AppliedNtt,
                true,
                state.mParams.mNumWorkerThreads);
        }
        else
        {
            applyOk = lheApplyCt1(
                ctx,
                state.hostCt1(),
                input.mDigest,
                state.mParams.mGadgetLogBase,
                state.mParams.mTau,
                ct1AppliedNtt,
                true,
                state.mParams.mNumWorkerThreads);
        }
        if (!applyOk)
        {
            return false;
        }

        applyStep.stop();
        HostStep decryptStep(senderRole ? "cpu sender expand detail: decrypt" : "cpu receiver expand detail: decrypt");
        std::vector<RnsPoly> decPartialNtt;
        if (!lheDec(
                ctx,
                std::move(ct1AppliedNtt),
                input.mSkX,
                decPartialNtt,
                publicA.get(),
                true,
                true,
                state.mParams.mNumWorkerThreads))
        {
            return false;
        }

        decryptStep.stop();
        HostStep evalStep(senderRole ? "cpu sender expand detail: tree eval" : "cpu receiver expand detail: tree eval");
        std::vector<RnsPoly> evalNtt;
        bool evalOk = false;
        static const bool fusedEvalEnabled = [] {
            const char* value = std::getenv("LV_CPU_FUSED_EXPAND_EVAL");
            return !value || value[0] != '0';
        }();
        const bool fusedEval = fusedEvalEnabled && state.mParams.mTruncateOneGadgetDigit;
        if (fusedEval)
        {
            evalOk = lencSubtractEvalTruncNttInplace(
                ctx, state.hostLacct(), *tree, state.mParams.mMu, state.mParams.mTau,
                state.mParams.mGadgetLogBase, state.mParams.mPlaintextModulusBits,
                decPartialNtt, state.mParams.mNumWorkerThreads, state.mParams.mLeafInputsAreGadget);
        }
        else if (state.mParams.mTruncateOneGadgetDigit)
        {
            evalOk = lencEvalTrunc(
                ctx,
                state.hostLacct(),
                *tree,
                state.mParams.mMu,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                state.mParams.mPlaintextModulusBits,
                evalNtt,
                true,
                state.mParams.mNumWorkerThreads,
                state.mParams.mLeafInputsAreGadget);
        }
        else
        {
            evalOk = lencEval(
                ctx,
                state.hostLacct(),
                *tree,
                state.mParams.mMu,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                evalNtt,
                true,
                state.mParams.mNumWorkerThreads);
        }
        if (!evalOk ||
            decPartialNtt.size() != state.mParams.mMu ||
            (!fusedEval && evalNtt.size() != state.mParams.mMu) ||
            receiverCt2.size() != state.mParams.mMu)
        {
            return false;
        }

        evalStep.stop();
        HostStep finishStep(senderRole ? "cpu sender expand detail: finish" : "cpu receiver expand detail: finish");
        ShrinkExpandReceiverExpandOutput next{};
        next.mTbm.resize(state.mParams.mMu);
        for (u32 row = 0; row < state.mParams.mMu; ++row)
        {
            RnsPoly tbm = std::move(decPartialNtt[row]);
            if ((!fusedEval && !ringSubInplace(tbm, evalNtt[row], ctx)) ||
                !inverseNtt(tbm, ctx) ||
                !ringAddInplace(tbm, receiverCt2[row], ctx))
            {
                return false;
            }
            next.mTbm[row] = std::move(tbm);
        }

        out = std::move(next);
        return true;
    }

    bool shrinkExpandDenoiseComb(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        if (ctx.mParams.mCoeffModulusBits.empty() ||
            tbaPrime.size() % ctx.mParams.mCoeffModulusBits.size() != 0 ||
            !validateRingBatchShape(tbaPrime, ctx.mParams))
        {
            return false;
        }

        const auto hostContext = getRingHostContext(ctx);
        auto keyContextData = hostContext ? hostContext->key_context_data() : nullptr;
        if (!keyContextData)
        {
            return false;
        }
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty()) return false;

        const std::size_t rho = ctx.mParams.mCoeffModulusBits.size();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t wPrime = tbaPrime.size() / rho;

        auto pool = seal::MemoryManager::GetPool();
        seal::util::RNSBase fullBase(keyContextData->parms().coeff_modulus(), pool);

        AlignedUnVec<u64> q(rho);
        for (std::size_t i = 0; i < rho; ++i)
        {
            q[i] = fullBase.base()[i].value();
        }

        struct RecoveryConstants
        {
            AlignedUnVec<std::size_t> mSrcLimbIndices;
            std::vector<seal::util::MultiplyUIntModOperand> mCrtInvPunctured;
            std::vector<seal::util::MultiplyUIntModOperand> mPuncturedProdModTarget;
            AlignedUnVec<wideU64> mFracInvModulus;
            seal::util::MultiplyUIntModOperand mCrtLiftModTarget;
            seal::util::MultiplyUIntModOperand mInvCrtLiftModTarget;
        };

        std::vector<RecoveryConstants> recovery(rho);
        for (std::size_t j = 0; j < rho; ++j)
        {
            const auto& modJ = moduli[j];
            auto& constants = recovery[j];
            constants.mSrcLimbIndices.resize((rho > 0) ? (rho - 1) : 0);
            std::size_t srcLimbIdx = 0;

            std::vector<seal::Modulus> baseExcludingJ;
            baseExcludingJ.reserve((rho > 0) ? (rho - 1) : 0);

            u64 crtLiftModQj = 1;
            for (std::size_t w = 0; w < rho; ++w)
            {
                if (w == j)
                {
                    continue;
                }
                constants.mSrcLimbIndices[srcLimbIdx++] = w;
                baseExcludingJ.push_back(moduli[w]);
                crtLiftModQj = seal::util::multiply_uint_mod(crtLiftModQj, q[w], modJ);
            }
            constants.mCrtLiftModTarget.set(crtLiftModQj, modJ);

            u64 invCrtLiftModQj = 0;
            if (!seal::util::try_invert_uint_mod(crtLiftModQj, modJ, invCrtLiftModQj))
            {
                return false;
            }
            constants.mInvCrtLiftModTarget.set(invCrtLiftModQj, modJ);

            if (baseExcludingJ.empty())
            {
                continue;
            }

            seal::util::RNSBase reducedBase(baseExcludingJ, pool);
            auto reducedInvPunct = reducedBase.inv_punctured_prod_mod_base_array();

            const std::size_t reducedCount = constants.mSrcLimbIndices.size();
            constants.mCrtInvPunctured.resize(reducedCount);
            constants.mPuncturedProdModTarget.resize(reducedCount);
            resizeZero(constants.mFracInvModulus, reducedCount);

            for (std::size_t idx = 0; idx < reducedCount; ++idx)
            {
                const std::size_t w = constants.mSrcLimbIndices[idx];
                constants.mCrtInvPunctured[idx] = reducedInvPunct[idx];
                constants.mFracInvModulus[idx] = reciprocal2Pow128Wide(q[w]);

                u64 puncturedModQj = 1;
                for (std::size_t u = 0; u < rho; ++u)
                {
                    if (u == j || u == w)
                    {
                        continue;
                    }
                    puncturedModQj = seal::util::multiply_uint_mod(puncturedModQj, q[u], modJ);
                }
                constants.mPuncturedProdModTarget[idx].set(puncturedModQj, modJ);
            }
        }

        std::vector<RnsPoly> result(wPrime);
        const wideU64 half = wideU64OneShift(127);

        // Each output owns its allocation and reads disjoint input polynomials.
        // Shared recovery constants are immutable. The common worker budget also
        // applies when denoising runs inside a seed-search worker.
        if (!detail::runParallelTasks(wPrime, requestedWorkers, [&](std::size_t i) {
            RnsPoly polyOut{};
            resizeZero(polyOut.mCoeffs, n * rho);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto& polyIn = tbaPrime[i * rho + j];
                const u64 qj = q[j];
                const auto& modJ = moduli[j];
                const auto& constants = recovery[j];
                const std::size_t reducedCount = constants.mSrcLimbIndices.size();

                if (detail::cpuDenoiseRns(polyIn.mCoeffs.data(), polyOut.mCoeffs.data() + j*n,
                    n, fullBase, j)) continue;

                for (std::size_t k = 0; k < n; ++k)
                {
                    wideU64 sumFrac = half;
                    u64 alpha = 0;
                    u64 eModQj = 0;

                    auto consumeIdx = [&](std::size_t idx) {
                        const std::size_t w = constants.mSrcLimbIndices[idx];
                        const u64 vw = polyIn.mCoeffs[w * n + k];
                        const u64 xw = seal::util::multiply_uint_mod(vw, constants.mCrtInvPunctured[idx], moduli[w]);

                        unsigned char carry = 0;
                        sumFrac = wideU64Add(
                            sumFrac,
                            wideU64MulLow(xw, constants.mFracInvModulus[idx]),
                            &carry);
                        if (carry)
                        {
                            ++alpha;
                        }

                        const u64 xwModQj = seal::util::barrett_reduce_64(xw, modJ);
                        const u64 proj =
                            seal::util::multiply_uint_mod(xwModQj, constants.mPuncturedProdModTarget[idx], modJ);
                        eModQj += proj;
                        if (eModQj >= qj)
                        {
                            eModQj -= qj;
                        }
                    };

                    switch (reducedCount)
                    {
                    case 0:
                        break;
                    case 1:
                        consumeIdx(0);
                        break;
                    case 2:
                        consumeIdx(0);
                        consumeIdx(1);
                        break;
                    case 3:
                        consumeIdx(0);
                        consumeIdx(1);
                        consumeIdx(2);
                        break;
                    case 4:
                        consumeIdx(0);
                        consumeIdx(1);
                        consumeIdx(2);
                        consumeIdx(3);
                        break;
                    default:
                        for (std::size_t idx = 0; idx < reducedCount; ++idx)
                        {
                            consumeIdx(idx);
                        }
                        break;
                    }

                    const u64 alphaTerm =
                        seal::util::multiply_uint_mod(alpha, constants.mCrtLiftModTarget, modJ);
                    if (eModQj >= alphaTerm)
                    {
                        eModQj -= alphaTerm;
                    }
                    else
                    {
                        eModQj += qj - alphaTerm;
                    }

                    const u64 vj = polyIn.mCoeffs[j * n + k];
                    const u64 diff = (vj >= eModQj) ? (vj - eModQj) : (vj + qj - eModQj);
                    polyOut.mCoeffs[j * n + k] =
                        seal::util::multiply_uint_mod(diff, constants.mInvCrtLiftModTarget, modJ);
                }
            }

            result[i] = std::move(polyOut);
            return true;
        })) return false;

        out = std::move(result);
        return true;
    }
}
