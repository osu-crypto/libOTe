#pragma once

#include <cryptoTools/Common/Defines.h>
#include <atomic>
#include <chrono>

namespace osuCrypto::LogVole
{
    struct RingOpsStats
    {
        std::atomic<u64> resetEpoch{ 0u };

        std::atomic<u64> mNttCount{ 0 };
        std::atomic<u64> mInttCount{ 0 };
        std::atomic<u64> mAddCount{ 0 };
        std::atomic<u64> mSubCount{ 0 };
        std::atomic<u64> mMulCount{ 0 };
        std::atomic<u64> mMulScalarCount{ 0 };
        std::atomic<u64> mDyadicMulAddCount{ 0 };
        std::atomic<u64> mGadgetDecomposeCount{ 0 };
        std::atomic<u64> mGadgetRecomposeCount{ 0 };
        std::atomic<u64> mPrngPolyCount{ 0 };
        std::atomic<u64> mErrorAddCount{ 0 };

        void reset();
    };

    struct TimingStats
    {
        std::atomic<u64> mSenderWaitTimeUs{ 0 };
        std::atomic<u64> mReceiverWaitTimeUs{ 0 };
        std::atomic<u64> mSenderAsyncWaitTimeUs{ 0 };
        std::atomic<u64> mReceiverAsyncWaitTimeUs{ 0 };
        std::atomic<u64> mSenderComputeTimeUs{ 0 };
        std::atomic<u64> mReceiverComputeTimeUs{ 0 };
        std::atomic<u64> mLencEncTimeUs{ 0 };
        std::atomic<u64> mLencDecTimeUs{ 0 };
        std::atomic<u64> mLheEncTimeUs{ 0 };
        std::atomic<u64> mLheDecTimeUs{ 0 };
        std::atomic<u64> mShrinkTimeUs{ 0 };
        std::atomic<u64> mExpandTimeUs{ 0 };
        std::atomic<u64> mPolySamplingTimeUs{ 0 };
        std::atomic<u64> mGoldSamplingTimeUs{ 0 };
        std::atomic<u64> mSeedSamplingTimeUs{ 0 };
        std::atomic<u64> mSeedAttemptTimeUs{ 0 };
        std::atomic<u64> mSeedAttemptCount{ 0 };
        std::atomic<u64> mGdecompUnbundleTimeUs{ 0 };
        std::atomic<u64> mDenoiseTbmTimeUs{ 0 };
        std::atomic<u64> mAggTimeUs{ 0 };

        // Zp <-> ring CRT packing, and the GPU fast paths.
        std::atomic<u64> mWrapTimeUs{ 0 };
        std::atomic<u64> mUnwrapTimeUs{ 0 };
        std::atomic<u64> mGpuShrinkTimeUs{ 0 };
        std::atomic<u64> mGpuExpandTimeUs{ 0 };
        std::atomic<u64> mGpuSenderTimeUs{ 0 };
        std::atomic<u64> mGpuMiscTimeUs{ 0 };

        // Time each party spends blocked in recvFrame, i.e. waiting for the peer.
        // This is what separates a party's own cost from the cost the protocol's
        // round structure imposes on it.
        std::atomic<u64> mSenderWaitUs{ 0 };
        std::atomic<u64> mReceiverWaitUs{ 0 };

        // Ablation counters: host time spent inside the Root recursion level, and
        // time spent serialising / deserialising the Root's two wire messages.
        // Subtracting these from a party's wall time gives the ceiling that would
        // be reached if the Root were device resident and the exchange free.
        std::atomic<u64> mRootReceiverHostUs{ 0 };
        std::atomic<u64> mRootSenderHostUs{ 0 };
        std::atomic<u64> mRootSerializeUs{ 0 };

        void reset();
    };

    struct AutoTimer
    {
        std::atomic<u64>& mStat;
        std::chrono::steady_clock::time_point mStart;

        AutoTimer(std::atomic<u64>& stat);
        ~AutoTimer();
    };

}
