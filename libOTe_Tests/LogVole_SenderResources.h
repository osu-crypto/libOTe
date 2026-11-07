#pragma once
#include "libOTe/Vole/LogVole/LogVole.h"
#include "macoro/thread_pool.h"
#include "macoro/sync_wait.h"

namespace tests_libOTe::logvole_test
{
    // Test/application boundary only. Resources are reused for sequential queries.
    struct SenderResources
    {
        macoro::thread_pool executor;
        macoro::thread_pool::work work = executor.make_work();
        std::vector<osuCrypto::LogVole::LheDecryptBuffer> buffers;

        SenderResources(const osuCrypto::LogVole::RingParams& ring, bool gpu = false,
            std::size_t workers = 3)
        {
            if (gpu) return;
            buffers.resize(workers);
            for (auto& b : buffers)
                b.mProduct.mCoeffs.resize(osuCrypto::LogVole::ringPolyCoeffCount(ring));
            executor.create_threads(1);
        }
        explicit SenderResources(const osuCrypto::LogVoleOptions& options)
        {
            if (options.mUseGpu) return;
            osuCrypto::LogVole::CivoleParams params;
            if (!osuCrypto::LogVole::makeCivoleParams(options.mSetting, params, options.mNumThreads))
                throw std::runtime_error("invalid sender test parameters");
            buffers.resize(std::max(1u, options.mNumThreads));
            for (auto& b : buffers)
                b.mProduct.mCoeffs.resize(osuCrypto::LogVole::ringPolyCoeffCount(params.mLogVole.mShrinkExpand.mRing));
            executor.create_threads(1);
        }
    };

    template<class Request, class... Args>
    bool prepareRootResponse(const osuCrypto::LogVole::SenderState& state,
        Request&& request, Args&&... args)
    {
        const auto& owner = state.mShrinkExpandState.mRingFactoryOwner;
        SenderResources resources(state.mParams.mShrinkExpand.mRing,
            owner && owner->mExecutionOptions.mUseGpu);
        return macoro::sync_wait(osuCrypto::LogVole::prepareRootResponseSender(
            resources.executor, resources.buffers, state, std::forward<Request>(request),
            std::forward<Args>(args)...));
    }
}
