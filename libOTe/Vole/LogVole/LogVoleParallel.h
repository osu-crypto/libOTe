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
#include <exception>
#include <thread>
#include <vector>
#include <type_traits>

namespace osuCrypto::LogVole::detail
{
    inline std::size_t hardwareWorkerSlots(CpuBenchmarkContext* benchmark = nullptr)
    {
        if (benchmark) return benchmark->mWorkerLimit
            ? std::min(benchmark->mWorkerLimit, benchmark->mCpus.size())
            : benchmark->mCpus.size();
        const auto hw = static_cast<std::size_t>(std::thread::hardware_concurrency());
        return hw == 0 ? 1 : hw;
    }

    inline std::atomic<std::size_t> gParallelWorkerSlotsInUse{ 0 };
    inline thread_local std::size_t tParallelWorkerCap = 0;

    class ParallelWorkerSlotGuard
    {
    public:
        explicit ParallelWorkerSlotGuard(std::size_t requestedWorkers, CpuBenchmarkContext* benchmark = nullptr)
        {
            mCounter = benchmark
                ? &benchmark->mWorkerSlots : &gParallelWorkerSlotsInUse;
            mGrantedWorkers = 1;
            if (requestedWorkers <= 1)
            {
                return;
            }

            const std::size_t maxSlots = hardwareWorkerSlots(benchmark);
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

    class ParallelWorkerCapScope
    {
    public:
        explicit ParallelWorkerCapScope(std::size_t workerCap)
            : mPreviousCap(tParallelWorkerCap)
        {
            if (workerCap == 0)
            {
                return;
            }

            if (mPreviousCap == 0)
            {
                tParallelWorkerCap = workerCap;
            }
            else
            {
                tParallelWorkerCap = std::min(mPreviousCap, workerCap);
            }
        }

        ParallelWorkerCapScope(const ParallelWorkerCapScope&) = delete;
        ParallelWorkerCapScope& operator=(const ParallelWorkerCapScope&) = delete;

        ~ParallelWorkerCapScope()
        {
            tParallelWorkerCap = mPreviousCap;
        }

    private:
        std::size_t mPreviousCap = 0;
    };

    inline std::size_t resolveWorkerCount(u32 requestedWorkers, std::size_t taskCount)
    {
        if (taskCount <= 1)
        {
            return 1;
        }

        std::size_t workers = requestedWorkers;
        if (requestedWorkers == 0)
        {
            workers = static_cast<std::size_t>(std::thread::hardware_concurrency());
        }
        if (workers == 0)
        {
            workers = 1;
        }
        if (tParallelWorkerCap != 0)
        {
            workers = std::min(workers, tParallelWorkerCap);
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
        CpuBenchmarkState state{benchmarkContext, true};
        worker(workerIdx, state);
    }

    template<typename TaskFn>
    bool runParallelTasks(std::size_t taskCount, u32 requestedWorkers, TaskFn&& taskFn,
        bool dynamic = false, CpuBenchmarkState* benchmarkState = nullptr)
    {
        if (taskCount == 0)
        {
            return true;
        }

        CpuBenchmarkState localState;
        auto& state = benchmarkState ? *benchmarkState : localState;
        auto* benchmark = state.mContext;
        const auto invoke = [&](std::size_t index, CpuBenchmarkState& workerState) {
            if constexpr (std::is_invocable_v<TaskFn&, std::size_t, CpuBenchmarkState&>)
                return taskFn(index, workerState);
            else
                return taskFn(index);
        };
        const std::size_t requested = resolveWorkerCount(requestedWorkers, taskCount);
        ParallelWorkerSlotGuard slotGuard(requested, benchmark);
        const std::size_t workerCount = std::min(requested, slotGuard.grantedWorkers());
        if (workerCount <= 1)
        {
            CpuBenchmarkTaskScope taskScope(state);
            for (std::size_t taskIdx = 0; taskIdx < taskCount; ++taskIdx)
            {
                if (!invoke(taskIdx, state))
                {
                    return false;
                }
            }
            return true;
        }

        ParallelWorkerCapScope capScope(workerCount);
        std::atomic<bool> failed{ false };
        std::atomic<std::size_t> nextTask{ 0 };

        auto worker = [&](std::size_t workerIdx, CpuBenchmarkState& workerState) {
            CpuBenchmarkTaskScope taskScope(workerState);
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
                    if (!invoke(taskIdx, workerState))
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
                if (!invoke(taskIdx, workerState))
                {
                    failed.store(true, std::memory_order_release);
                    break;
                }
            }
        };

        macoro::thread_pool::work work;
        macoro::thread_pool pool(workerCount - 1, work);
        try
        {
            // Construct every lazy child and the blocking join before any
            // child starts. Allocation failure during setup cannot abandon a
            // running task that borrows worker or this function's locals.
            std::vector<macoro::task<>> tasks;
            tasks.reserve(workerCount - 1);
            for (std::size_t i = 1; i < workerCount; ++i)
                tasks.push_back(runPoolWorker(pool, worker, i, benchmark));
            auto joined = macoro::make_blocking(macoro::when_all_ready(std::move(tasks)));

            std::exception_ptr callerError;
            try { worker(0, state); }
            catch (...)
            {
                failed.store(true, std::memory_order_release);
                callerError = std::current_exception();
            }
            auto results = joined.get();
            work.reset();
            if (callerError) std::rethrow_exception(callerError);
            for (auto& result : results) result.result();
        }
        catch (...)
        {
            // Release the work guard before the pool joins, including failures
            // while constructing the still-lazy children and join state.
            work.reset();
            throw;
        }

        return !failed.load(std::memory_order_acquire);
    }
}
