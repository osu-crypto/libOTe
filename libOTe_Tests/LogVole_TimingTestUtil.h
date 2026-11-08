#pragma once
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include <array>

namespace tests_libOTe::logvole_test
{
    inline auto timingSnapshot(const osuCrypto::LogVole::TimingStats& stats)
    {
        return std::array<osuCrypto::u64, 31>{
            stats.mSenderWaitTimeUs.load(std::memory_order_relaxed),
            stats.mReceiverWaitTimeUs.load(std::memory_order_relaxed),
            stats.mSenderAsyncWaitTimeUs.load(std::memory_order_relaxed),
            stats.mReceiverAsyncWaitTimeUs.load(std::memory_order_relaxed),
            stats.mSenderComputeTimeUs.load(std::memory_order_relaxed),
            stats.mReceiverComputeTimeUs.load(std::memory_order_relaxed),
            stats.mLencEncTimeUs.load(std::memory_order_relaxed),
            stats.mLencDecTimeUs.load(std::memory_order_relaxed),
            stats.mLheEncTimeUs.load(std::memory_order_relaxed),
            stats.mLheDecTimeUs.load(std::memory_order_relaxed),
            stats.mShrinkTimeUs.load(std::memory_order_relaxed),
            stats.mExpandTimeUs.load(std::memory_order_relaxed),
            stats.mPolySamplingTimeUs.load(std::memory_order_relaxed),
            stats.mGoldSamplingTimeUs.load(std::memory_order_relaxed),
            stats.mSeedSamplingTimeUs.load(std::memory_order_relaxed),
            stats.mSeedAttemptTimeUs.load(std::memory_order_relaxed),
            stats.mSeedAttemptCount.load(std::memory_order_relaxed),
            stats.mGdecompUnbundleTimeUs.load(std::memory_order_relaxed),
            stats.mDenoiseTbmTimeUs.load(std::memory_order_relaxed),
            stats.mAggTimeUs.load(std::memory_order_relaxed),
            stats.mWrapTimeUs.load(std::memory_order_relaxed),
            stats.mUnwrapTimeUs.load(std::memory_order_relaxed),
            stats.mGpuShrinkTimeUs.load(std::memory_order_relaxed),
            stats.mGpuExpandTimeUs.load(std::memory_order_relaxed),
            stats.mGpuSenderTimeUs.load(std::memory_order_relaxed),
            stats.mGpuMiscTimeUs.load(std::memory_order_relaxed),
            stats.mSenderWaitUs.load(std::memory_order_relaxed),
            stats.mReceiverWaitUs.load(std::memory_order_relaxed),
            stats.mRootReceiverHostUs.load(std::memory_order_relaxed),
            stats.mRootSenderHostUs.load(std::memory_order_relaxed),
            stats.mRootSerializeUs.load(std::memory_order_relaxed)};
    }
}
