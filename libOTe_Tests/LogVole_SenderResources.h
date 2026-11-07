#pragma once
#include "libOTe/Vole/LogVole/LogVole.h"
#include "macoro/thread_pool.h"
#include "macoro/sync_wait.h"
#include <bit>

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

    struct ReceiverBuffers
    {
        std::vector<osuCrypto::LogVole::LheDecryptBuffer> lhe;
        std::vector<osuCrypto::LogVole::LencEvalBuffer> lenc;

        ReceiverBuffers(const osuCrypto::LogVole::ShrinkExpandParams& params,
            bool gpu = false, std::size_t workers = 3)
        {
            if (gpu) return;
            lhe.resize(workers);
            lenc.resize(workers);
            // Recursion only reduces tau/mu. Include root-left and full-width
            // ciphertexts; ceil(log2(width)) accounts for tree padding.
            const auto width = std::max<std::size_t>(params.mMu,
                std::size_t(params.mAlpha) * params.mTau * params.mRing.mCoeffModulusBits.size());
            const auto terms = 2 * std::bit_width(width ? width - 1 : 0) * (params.mTau + 1);
            for (auto& b : lhe)
                b.mProduct.mCoeffs.resize(osuCrypto::LogVole::ringPolyCoeffCount(params.mRing));
            for (auto& b : lenc)
            {
                b.mCiphertexts.reserve(terms);
                b.mNodes.reserve(terms);
            }
        }
        explicit ReceiverBuffers(const osuCrypto::LogVoleOptions& options)
        {
            if (options.mUseGpu) return;
            osuCrypto::LogVole::CivoleParams params;
            if (!osuCrypto::LogVole::makeCivoleParams(options.mSetting, params, options.mNumThreads))
                throw std::runtime_error("invalid receiver test parameters");
            *this = ReceiverBuffers(params.mLogVole.mShrinkExpand, false, std::max(1u, options.mNumThreads));
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
