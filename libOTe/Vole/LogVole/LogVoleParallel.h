#pragma once

#include <cryptoTools/Common/Defines.h>

#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

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
    inline std::size_t hardwareWorkerSlots()
    {
        const auto hw = static_cast<std::size_t>(std::thread::hardware_concurrency());
        return hw == 0 ? 1 : hw;
    }

    inline std::atomic<std::size_t> gParallelWorkerSlotsInUse{ 0 };
    inline thread_local std::size_t tParallelWorkerCap = 0;

    class ParallelWorkerSlotGuard
    {
    public:
        explicit ParallelWorkerSlotGuard(std::size_t requestedWorkers)
        {
            mGrantedWorkers = 1;
            if (requestedWorkers <= 1)
            {
                return;
            }

            const std::size_t maxSlots = hardwareWorkerSlots();
            while (true)
            {
                std::size_t used = gParallelWorkerSlotsInUse.load(std::memory_order_acquire);
                if (used >= maxSlots)
                {
                    return;
                }

                const std::size_t available = maxSlots - used;
                const std::size_t grant = std::min(requestedWorkers, available);
                if (gParallelWorkerSlotsInUse.compare_exchange_weak(
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
                gParallelWorkerSlotsInUse.fetch_sub(mReservedWorkers, std::memory_order_release);
            }
        }

        std::size_t grantedWorkers() const
        {
            return mGrantedWorkers;
        }

    private:
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
        ProtocolCacheScope cacheScope)
    {
        co_await pool.schedule();
        ScopedProtocolCacheScope scopedCache(cacheScope);
        worker(workerIdx);
    }

    template<typename TaskFn>
    bool runParallelTasks(std::size_t taskCount, u32 requestedWorkers, TaskFn&& taskFn)
    {
        if (taskCount == 0)
        {
            return true;
        }

        const std::size_t requested = resolveWorkerCount(requestedWorkers, taskCount);
        ParallelWorkerSlotGuard slotGuard(requested);
        const std::size_t workerCount = std::min(requested, slotGuard.grantedWorkers());
        if (workerCount <= 1)
        {
            for (std::size_t taskIdx = 0; taskIdx < taskCount; ++taskIdx)
            {
                if (!taskFn(taskIdx))
                {
                    return false;
                }
            }
            return true;
        }

        ParallelWorkerCapScope capScope(workerCount);
        std::atomic<bool> failed{ false };

        const ProtocolCacheScope cacheScope = currentProtocolCacheScope();
        auto worker = [&](std::size_t workerIdx) {
            ScopedProtocolCacheScope scopedCache(cacheScope);
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
            tasks.push_back(runPoolWorker(pool, worker, i, cacheScope) | macoro::make_eager());
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
