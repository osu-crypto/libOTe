#pragma once
#include <cstdint>
#include "libOTe/Vole/LogVole/LogVoleEncodingOptions.h"
#include "libOTe/Vole/LogVole/LogVoleKernelOptions.h"

namespace osuCrypto
{
    namespace LogVole { struct CpuBenchmarkContext; struct RingOpsStats; struct TimingStats; }
    struct LogVoleTransportOptions
    {
        LogVoleEncodingOptions mEncoding;
        bool operator==(const LogVoleTransportOptions&) const = default;
    };

    struct LogVoleGpuSetupOptions
    {
        // Device paths retain their existing eligibility checks and CPU fallbacks.
        bool mDirectWire = true;
        bool mLazyCiphertexts = true;
        bool mRootPublicBToken = true;
        bool mRootBStarDevice = true;
        bool mRootBStarDeviceStrict = false;
        bool mRootR1Device = true;
        bool mRootR1DeviceStrict = false;
        bool mRootSecretDevice = true;
        bool mRootSecretDeviceStrict = false;
        LogVoleChoice mParallelLhe = LogVoleChoice::Automatic;
        LogVoleChoice mParallelLenc = LogVoleChoice::Automatic;
        bool mLheDevice = true;
        bool mLheDeviceStrict = false;
        bool mLencDevice = true;
        bool mLencDeviceStrict = false;
        bool mLencDevicePadding = true;
        bool mCompactNoise = true;
        bool mCompactNoiseStrict = false;
        bool mLencRandomizerOutput = true;
        bool mLencRandomizerOutputStrict = false;
        bool mDeltaDevice = true;
        bool mDeltaDeviceStrict = false;
        bool mReceiverResidentNtt = true;
        bool mReceiverResidentNttStrict = false;
        bool mBatchNtt = true;
        bool mParallelCopy = true;
        bool mParallelMessageCopy = true;
        bool mSharedState = true;
        bool mRootDevice = true;
        bool mRootDeviceStrict = false;
        bool mRootCompactNoise = true;
        bool mRootCompactNoiseStrict = false;
        bool mTopSecretConsumerStrict = false;
        bool mDeltaChainDevice = true;
        bool mDeltaChainStrict = false;
        bool mTopSecretRepDevice = true;
        // -1 selects the existing geometry-based automatic policy; 0 disables it.
        int mPublicSenderCt2PrefetchLevels = -1;
        bool operator==(const LogVoleGpuSetupOptions&) const = default;
    };

    struct LogVoleGpuStreamOptions
    {
        bool mDebug = false;
        LogVoleChoice mLazyIndexScratch = LogVoleChoice::Automatic;
        std::uint32_t mIndexScratchKiB = 4096;
        bool mPipelinedUpload = false;
        std::uint32_t mPolyStageMiB = 8;
        std::uint32_t mDownloadSlotMiB = 8;
        bool mReuseDownloadStaging = true;

        bool valid() const noexcept
        {
            return (mLazyIndexScratch == LogVoleChoice::Automatic ||
                    mLazyIndexScratch == LogVoleChoice::Disabled ||
                    mLazyIndexScratch == LogVoleChoice::Enabled) &&
                mIndexScratchKiB >= 256 && mIndexScratchKiB <= 4096 &&
                (mIndexScratchKiB & (mIndexScratchKiB - 1)) == 0 &&
                mPolyStageMiB >= 1 && mPolyStageMiB <= 64 &&
                mDownloadSlotMiB >= 1 && mDownloadSlotMiB <= 32;
        }
        bool operator==(const LogVoleGpuStreamOptions&) const = default;
    };

    struct LogVoleGpuContextOptions
    {
        bool mFullModChain = false;
        bool mLightweightRing = true;
        bool mLightweightCrt = true;
        bool mBatchingSingleLimb = true;
        bool mNativeSealBundle = false;
        bool mInitOverlap = true;
        bool operator==(const LogVoleGpuContextOptions&) const = default;
    };

    // Explicit fault injection for exercising exact fallback and rollback paths.
    enum class LogVoleFailureStage { None, BeforeWork, AfterWork };
    struct LogVoleFailureOptions
    {
        bool mReceiverFirstQueryAlloc = false;
        bool mRootKPrime = false;
        bool mRootSkX = false;
        bool mRootZetaReject = false;
        bool mDeltaChain = false;
        bool mDeltaDevice = false;
        bool mGaussianPrg = false;
        bool mGaussianResident = false;
        bool mGaussianTransform = false;
        bool mLencDevice = false;
        bool mLencRandomizerOutput = false;
        bool mLheDevice = false;
        LogVoleFailureStage mNttCanonicalize = LogVoleFailureStage::None;
        bool mPublicRetain = false;
        LogVoleFailureStage mReceiverResidentNtt = LogVoleFailureStage::None;
        bool mRootBStarDevice = false;
        bool mRootCompactNoise = false;
        bool mRootDevice = false;
        bool mRootR1Device = false;
        bool mRootSkRRDevice = false;
        bool mTopSk1Device = false;
        bool mTopSk1Lenc = false;
        bool mTopSk1Lhe = false;
        bool mTopSk1Rep = false;
        bool mTopSk1Root = false;
        bool mUniform = false;
        bool operator==(const LogVoleFailureOptions&) const = default;
    };

    struct LogVoleGpuProtocolOptions
    {
        bool mRootProfile = false;
        LogVoleFailureOptions mFailures;
        bool mNttCanonicalize = true;
        bool mNttCanonicalizeStrict = false;
        bool mSeedLabelRep = true;
        bool mSeedLabelRepStrict = false;
        bool mTopSecretDevice = true;
        bool mTopSecretDeviceStrict = false;
        bool mGaussianTransform = true;
        bool mGaussianTransformStrict = false;
        std::uint64_t mGaussianTransformPrefixBlocks = 0;
        bool mGaussianPrg = true;
        bool mGaussianPrgStrict = false;
        // Zero retains the coefficient-count-based prefix selection.
        std::uint64_t mGaussianPrgPrefixBlocks = 0;
        bool mGaussianResident = true;
        bool mGaussianResidentStrict = false;
        bool mPublicUniformRetention = true;
        bool mUniformSampling = true;
        bool mUniformSamplingStrict = false;
        bool mShareCache = true;
        bool mShareSenderCache = true;
        LogVoleChoice mReceiverPipelinedDownload = LogVoleChoice::Automatic;
        bool mReceiverLazyNtt = true;
        bool mReceiverFirstQueryAllocationOverlap = false;
        bool mLeafBDevice = true;
        bool mSenderPublicAOnly = true;
        bool mExtraPipelinedDownload = true;
        bool mPipelinedDownload = true;
        bool mDirectDownload = true;
        bool mNttReuseHost = true;
        bool mCompactExpandDirect = true;
        bool mCompactPipelinedDownload = true;
        bool mGarbledFusedInput = true;
        bool mDeltaConstantDirect = true;
        bool mDeltaLightweight = true;
        bool mDeltaSmallDownload = true;
        bool mRootSkNttResident = true;
        bool mRootDPrimeResident = true;
        bool mRootFinalizePriorityPrefetch = true;
        bool mIdentityLeaf = true;
        bool mPlainBroadcastSingleLimb = true;
        bool mReuseHiDigits = true;
        bool mDirectRecursiveLeaf = true;
        bool mRecursiveDiagonal = true;
        bool mRecursiveLeafSelfZero = true;
        bool mRecursiveLeafSparseInverse = true;
        bool mFusedUnwrap = true;
        bool mFusedScaleUnwrap = true;
        bool mFusedWrap = true;
        bool mRootZeta = true;
        bool mNoGoldRootZeta = true;
        bool mNoGoldRootPinnedSeeds = true;
        bool mSenderInplaceKey = true;
        bool mTopSenderCt2Prefetch = true;
        LogVoleChoice mReceiverCt2Prefetch = LogVoleChoice::Automatic;
        bool mDeferredGoldenValidation = true;
        bool mInplaceHiDigit = true;
        bool mLencRandomizerResidency = true;
        bool mRootKPrimeSampling = true;
        bool mNoGoldRootPriorityPrefetch = true;
        // -1 retains the request-dependent level selection; explicit values are 1..3.
        int mSenderCt2PrefetchLevels = -1;
        int mReceiverCt2PrefetchLevels = -1;

        bool valid() const noexcept
        {
            return (mReceiverPipelinedDownload == LogVoleChoice::Automatic ||
                    mReceiverPipelinedDownload == LogVoleChoice::Disabled ||
                    mReceiverPipelinedDownload == LogVoleChoice::Enabled) &&
                (mReceiverCt2Prefetch == LogVoleChoice::Automatic ||
                    mReceiverCt2Prefetch == LogVoleChoice::Disabled ||
                    mReceiverCt2Prefetch == LogVoleChoice::Enabled) &&
                (mSenderCt2PrefetchLevels == -1 ||
                    (mSenderCt2PrefetchLevels >= 1 && mSenderCt2PrefetchLevels <= 3)) &&
                (mReceiverCt2PrefetchLevels == -1 ||
                    (mReceiverCt2PrefetchLevels >= 1 && mReceiverCt2PrefetchLevels <= 3));
        }
        bool operator==(const LogVoleGpuProtocolOptions&) const = default;
    };

    // Supplied at construction and retained by each resource owner.
    // A cache owner has one configuration for its entire lifetime.
    struct LogVoleAdvancedOptions
    {
        LogVoleGpuSetupOptions mGpuSetup;
        LogVoleTransportOptions mTransport;
        bool mHostStepProfile = false;
        LogVoleGpuStreamOptions mStreams;
        LogVoleGpuKernelOptions mKernels;
        LogVoleGpuProtocolOptions mProtocol;
        LogVoleGpuContextOptions mContexts;
        bool valid() const noexcept { return mStreams.valid() && mKernels.valid() && mProtocol.valid(); }
        bool operator==(const LogVoleAdvancedOptions&) const = default;
    };
    // Backend and tuning shared by protocol objects and their resource owners.
    // Protocol dimensions are supplied separately by LogVoleOptions.
    struct LogVoleExecutionOptions
    {
        bool mUseGpu = false;
        // Optional borrowed diagnostics. The caller keeps this alive until all
        // operations (including deferred materialization) using these options finish.
        LogVole::CpuBenchmarkContext* mCpuBenchmark = nullptr;
        // Optional borrowed arithmetic totals, retained by the caller
        // through all operations using this immutable selection.
        LogVole::RingOpsStats* mRingOpsStats = nullptr;
        // Optional borrowed timing totals, retained by the caller through
        // all operations (including deferred materialization) using these options.
        LogVole::TimingStats* mTimingStats = nullptr;
        LogVoleAdvancedOptions mAdvanced;
        bool valid() const noexcept { return mAdvanced.valid(); }
        bool operator==(const LogVoleExecutionOptions&) const = default;
    };
}
