#pragma once

#include <cryptoTools/Common/Defines.h>

#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include "macoro/task.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "macoro/when_all.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <thread>
#include <vector>

namespace osuCrypto::LogVole::detail
{
    inline std::size_t hardwareWorkerSlots(CpuBenchmarkContext* benchmarkContext = nullptr,
        ExecutionContext* execution = nullptr)
    {
        if (benchmarkContext) return benchmarkContext->mWorkerLimit
            ? std::min(benchmarkContext->mWorkerLimit, benchmarkContext->mCpus.size())
            : benchmarkContext->mCpus.size();
        struct HardwareLimit
        {
            const std::size_t mValue = [] {
                const auto hw = static_cast<std::size_t>(std::thread::hardware_concurrency());
                return hw == 0 ? std::size_t{1} : hw;
            }();
        };
        return execution ? execution->sharedResources<HardwareLimit>().mValue : HardwareLimit{}.mValue;
    }

    struct ParallelWorkerBudget
    {
        std::atomic<std::size_t> mSlotsInUse{0};
    };

    class ParallelWorkerSlotGuard
    {
    public:
        explicit ParallelWorkerSlotGuard(std::size_t requestedWorkers, CpuBenchmarkContext* benchmarkContext = nullptr,
            ExecutionContext* execution = nullptr)
        {
            if (requestedWorkers <= 1) return;
            // Ordinary calls own their worker budget. Contention with an
            // unrelated session must not change the number of workers granted.
            // Benchmark callers can explicitly share their own accounting.
            if (!benchmarkContext && !execution)
            {
                mGrantedWorkers = std::max<std::size_t>(1,
                    std::min(requestedWorkers, hardwareWorkerSlots(benchmarkContext)));
                return;
            }
            mCounter = benchmarkContext ? &benchmarkContext->mWorkerSlots
                : &execution->resources<ParallelWorkerBudget>().mSlotsInUse;
            const std::size_t maxSlots = hardwareWorkerSlots(benchmarkContext, execution);
            while (true)
            {
                std::size_t used = mCounter->load(std::memory_order_acquire);
                if (used >= maxSlots)
                {
                    return;
                }

                const std::size_t available = maxSlots - used;
                const std::size_t grant = std::min(requestedWorkers, available);
                if (mCounter->compare_exchange_weak(
                        used,
                        used + grant,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    mGrantedWorkers = grant;
                    mReservedWorkers = grant;
                    return;
                }
            }
        }

        ParallelWorkerSlotGuard(const ParallelWorkerSlotGuard&) = delete;
        ParallelWorkerSlotGuard& operator=(const ParallelWorkerSlotGuard&) = delete;

        ~ParallelWorkerSlotGuard()
        {
            if (mReservedWorkers != 0)
            {
                mCounter->fetch_sub(mReservedWorkers, std::memory_order_release);
            }
        }

        std::size_t grantedWorkers() const
        {
            return mGrantedWorkers;
        }

    private:
        std::atomic<std::size_t>* mCounter = nullptr;
        std::size_t mGrantedWorkers = 1;
        std::size_t mReservedWorkers = 0;
    };

    inline std::size_t resolveWorkerCount(u32 requestedWorkers, std::size_t taskCount,
        ExecutionContext* execution = nullptr)
    {
        if (taskCount <= 1)
        {
            return 1;
        }

        std::size_t workers = requestedWorkers;
        if (requestedWorkers == 0)
        {
            workers = hardwareWorkerSlots(execution ? execution->mCpuBenchmark : nullptr, execution);
        }
        if (workers == 0)
        {
            workers = 1;
        }
        return std::min(workers, taskCount);
    }

    template<typename Worker>
    macoro::task<> runPoolWorker(
        macoro::thread_pool& pool,
        Worker& worker,
        std::size_t workerIdx,
        CpuBenchmarkContext* benchmarkContext)
    {
        co_await pool.schedule();

        CpuBenchmarkWorkerScope benchmarkScope(benchmarkContext);
        worker(workerIdx);
    }

    template<typename TaskFn>
    bool runParallelTasks(std::size_t taskCount, u32 requestedWorkers, TaskFn&& taskFn,
        bool dynamic = false, ExecutionContext* execution = nullptr)
    {
        if (taskCount == 0)
        {
            return true;
        }

        auto* benchmarkContext = execution ? execution->mCpuBenchmark : nullptr;
        const std::size_t requested = resolveWorkerCount(requestedWorkers, taskCount, execution);
        ParallelWorkerSlotGuard slotGuard(requested, benchmarkContext, execution);
        const std::size_t workerCount = std::min(requested, slotGuard.grantedWorkers());
        if (workerCount <= 1)
        {
            CpuBenchmarkTaskScope taskScope(benchmarkContext);
            for (std::size_t taskIdx = 0; taskIdx < taskCount; ++taskIdx)
            {
                if (!taskFn(taskIdx))
                {
                    return false;
                }
            }
            return true;
        }

        std::atomic<bool> failed{ false };
        std::atomic<std::size_t> nextTask{ 0 };


        auto worker = [&](std::size_t workerIdx) {
            CpuBenchmarkTaskScope taskScope(benchmarkContext);

            if (dynamic)
            {
                // Opt-in for tasks whose randomness and outputs are indexed by
                // task, so changing the worker assignment preserves semantics.
                // Short tasks let a slower NUMA core finish without holding up
                // the other workers for an entire static partition.
                while (!failed.load(std::memory_order_acquire))
                {
                    const auto taskIdx = nextTask.fetch_add(1, std::memory_order_relaxed);
                    if (taskIdx >= taskCount) break;
                    if (!taskFn(taskIdx))
                    {
                        failed.store(true, std::memory_order_release);
                        break;
                    }
                }
                return;
            }
            const std::size_t taskBegin = workerIdx * taskCount / workerCount;
            const std::size_t taskEnd = (workerIdx + 1) * taskCount / workerCount;
            for (std::size_t taskIdx = taskBegin; taskIdx < taskEnd; ++taskIdx)
            {
                if (failed.load(std::memory_order_acquire))
                {
                    break;
                }
                if (!taskFn(taskIdx))
                {
                    failed.store(true, std::memory_order_release);
                    break;
                }
            }
        };

        macoro::thread_pool::work work;
        macoro::thread_pool pool(workerCount - 1, work);
        std::vector<macoro::eager_task<>> tasks;
        tasks.reserve(workerCount - 1);
        for (std::size_t i = 1; i < workerCount; ++i)
        {
            tasks.push_back(runPoolWorker(pool, worker, i, benchmarkContext) | macoro::make_eager());
        }

        worker(0);

        auto results = macoro::sync_wait(macoro::when_all_ready(std::move(tasks)));
        work.reset();
        for (auto& result : results)
        {
            result.result();
        }

        return !failed.load(std::memory_order_acquire);
    }
}
