#pragma once
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include <stdexcept>

namespace tests_libOTe::logvole_test
{
    template<class T>
    T withAdvancedOptions(T input, const osuCrypto::LogVoleExecutionOptions& options,
        osuCrypto::LogVole::ProtocolCacheRole role,
        osuCrypto::LogVole::ProtocolCacheScopeView callerScope = {})
    {
        using namespace osuCrypto::LogVole;
        const ProtocolCacheScopeView scope{callerScope.mRunId, role};
        if constexpr (requires { input.mCrtFactoryOwner; })
        {
            ZpCrtContext context;
            const auto& params = input.mParams.mLogVole.mShrinkExpand;
            if (!makeZpCrtContext(params.mRing, params.mPlaintextModulusBits,
                    context, std::make_shared<ZpContextFactory>(
                        std::make_shared<RingContextFactory>(options, scope.mRunId.serviceOwner())), scope))
                throw std::runtime_error("Failed to construct test CRT context");
            input.mCrtFactoryOwner = context.mFactoryOwner;
        }
        else
        {
            RingNttContext context;
            const auto& ring = [&]() -> const RingParams& {
                if constexpr (requires { input.mParams.mShrinkExpand; })
                    return input.mParams.mShrinkExpand.mRing;
                else
                    return input.mParams.mRing;
            }();
            if (!makeRingNttContext(ring, context,
                    std::make_shared<RingContextFactory>(options, scope.mRunId.serviceOwner()), scope))
                throw std::runtime_error("Failed to construct test context");
            if constexpr (requires { input.mShrinkExpandState; })
                input.mShrinkExpandState.mRingFactoryOwner = context.mFactoryOwner;
            else
                input.mRingFactoryOwner = context.mFactoryOwner;
        }
        return input;
    }

    template<class T>
    class ScopedOptionValue
    {
        T& mTarget;
        T mPrevious;
    public:
        ScopedOptionValue(T& target, T value) : mTarget(target), mPrevious(target) { mTarget = value; }
        ~ScopedOptionValue() { mTarget = mPrevious; }
        ScopedOptionValue(const ScopedOptionValue&) = delete;
        ScopedOptionValue& operator=(const ScopedOptionValue&) = delete;
    };
    template<class T>
    T& withSetupOptions(T& value, const osuCrypto::LogVoleGpuSetupOptions& options)
    {
        auto& target = [&]() -> osuCrypto::LogVoleGpuSetupOptions& {
            if constexpr (requires { value.mParams.mLogVole; })
                return value.mParams.mLogVole.mShrinkExpand.mGpuSetup;
            else if constexpr (requires { value.mParams.mShrinkExpand; })
                return value.mParams.mShrinkExpand.mGpuSetup;
            else
                return value.mParams.mGpuSetup;
        }();
        target.mBatchNtt = options.mBatchNtt;
        target.mParallelCopy = options.mParallelCopy;
        target.mParallelMessageCopy = options.mParallelMessageCopy;
        target.mSharedState = options.mSharedState;
        target.mRootDevice = options.mRootDevice;
        target.mRootDeviceStrict = options.mRootDeviceStrict;
        target.mRootCompactNoise = options.mRootCompactNoise;
        target.mRootCompactNoiseStrict = options.mRootCompactNoiseStrict;
        target.mTopSecretConsumerStrict = options.mTopSecretConsumerStrict;
        target.mDeltaChainDevice = options.mDeltaChainDevice;
        target.mDeltaChainStrict = options.mDeltaChainStrict;
        target.mTopSecretRepDevice = options.mTopSecretRepDevice;
        target.mParallelLhe = options.mParallelLhe;
        target.mLheDevice = options.mLheDevice;
        target.mLheDeviceStrict = options.mLheDeviceStrict;
        target.mParallelLenc = options.mParallelLenc;
        target.mLencDevice = options.mLencDevice;
        target.mLencDeviceStrict = options.mLencDeviceStrict;
        target.mLencDevicePadding = options.mLencDevicePadding;
        target.mCompactNoise = options.mCompactNoise;
        target.mCompactNoiseStrict = options.mCompactNoiseStrict;
        target.mLencRandomizerOutput = options.mLencRandomizerOutput;
        target.mLencRandomizerOutputStrict = options.mLencRandomizerOutputStrict;
        target.mDeltaDevice = options.mDeltaDevice;
        target.mDeltaDeviceStrict = options.mDeltaDeviceStrict;
        target.mReceiverResidentNtt = options.mReceiverResidentNtt;
        target.mReceiverResidentNttStrict = options.mReceiverResidentNttStrict;
        return value;
    }

    template<class T>
    T withSetupOptions(const T& value, const osuCrypto::LogVoleGpuSetupOptions& options)
    {
        T copy = value;
        withSetupOptions(copy, options);
        return copy;
    }
}
