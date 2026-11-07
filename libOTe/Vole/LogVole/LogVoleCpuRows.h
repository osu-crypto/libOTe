#pragma once

#include "libOTe/Vole/LogVole/LogVoleTypes.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"
#include "libOTe/Vole/LogVole/LogVoleCpuExecutor.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include <span>

namespace osuCrypto::LogVole
{
    namespace detail
    {
        class CpuExecutor;

        // Exclusive operation scratch. Empty until a CPU row phase needs it;
        // the VOLE scratch lease keeps it alive through the synchronous join.
        class CpuRowScratch
        {
            struct Impl;
            std::unique_ptr<Impl> mImpl;
        public:
            struct Local
            {
                RnsPoly mProduct;
                std::vector<const RnsPoly*> mCiphertexts, mNodes;
                bool mOk = true;
            };
            CpuRowScratch() noexcept;
            ~CpuRowScratch();
            CpuRowScratch(const CpuRowScratch&) = delete;
            CpuRowScratch& operator=(const CpuRowScratch&) = delete;
            std::span<Local> prepare(std::size_t workers, std::size_t words,
                CpuBenchmarkContext* benchmark, std::size_t terms = 0);
            CpuExecutor* executor() noexcept;

            // Synchronous setup chunks using this exclusive workspace. The
            // callback owns its arithmetic loop and returns its chunk's result.
            // Serial calls use no pool or partition-storage allocation.
            template<typename ChunkFn>
            bool runBulkChunked(std::size_t tasks, u32 allowance, ChunkFn&& fn,
                CpuBenchmarkState& benchmark)
            {
                static_assert(std::is_same_v<std::invoke_result_t<ChunkFn&,
                    std::size_t, std::size_t, CpuBenchmarkState&>, bool>);
                if (!tasks) return true;
                const auto workers = setupWorkers(tasks, allowance, benchmark.mContext);
                struct FlushStats
                {
                    ~FlushStats() { flushRingOpsThreadLocalStats(); }
                };
                if (workers == 1)
                {
                    CpuBenchmarkTaskScope metrics(benchmark);
                    FlushStats flush;
                    return fn(0, tasks, benchmark);
                }
                auto locals = prepare(workers, 0, benchmark.mContext);
                const auto cacheScope = currentProtocolCacheScope();
                executor()->runBulkChunked(tasks, locals,
                    [&](std::size_t begin, std::size_t end, Local& local) {
                        ScopedProtocolCacheScope scope(cacheScope);
                        FlushStats flush;
                        // The executor already accounts for this chunk.
                        CpuBenchmarkState worker{benchmark.mContext,
                            &local != locals.data() || benchmark.mIsWorker, 1};
                        local.mOk = fn(begin, end, worker);
                    });
                return std::all_of(locals.begin(), locals.end(),
                    [](const auto& local) { return local.mOk; });
            }

            // Item form of the same chunk operation. A failed item ends its
            // chunk; all other chunks still join before returning false.
            template<typename ItemFn>
            bool runBulk(std::size_t tasks, u32 allowance, ItemFn&& fn,
                CpuBenchmarkState& benchmark)
            {
                return runBulkChunked(tasks, allowance,
                    [&](std::size_t begin, std::size_t end, CpuBenchmarkState& worker) {
                        for (auto i = begin; i != end; ++i)
                        {
                            if constexpr (std::is_invocable_v<ItemFn&, std::size_t, CpuBenchmarkState&>)
                            {
                                if (!fn(i, worker)) return false;
                            }
                            else if (!fn(i)) return false;
                        }
                        return true;
                    }, benchmark);
            }
        private:
            static std::size_t setupWorkers(std::size_t tasks, u32 allowance,
                const CpuBenchmarkContext* benchmark);

        };
    }

}
