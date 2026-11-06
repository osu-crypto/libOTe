#pragma once

#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"
#include "macoro/bulk.h"
#include "macoro/task.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "macoro/when_all.h"

#include <algorithm>
#include <atomic>
#include <exception>
#include <span>
#include <thread>
#include <type_traits>
#include <vector>

namespace osuCrypto::LogVole::detail
{
    // One exclusive executor partition, created while its owning session is
    // idle. Logical worker zero runs on the caller. Callbacks receive the
    // logical worker index; they never discover scratch by OS thread ID.
    // Nested work uses that worker's serial workspace, not this executor.
    class CpuExecutor
    {
        macoro::thread_pool mPool;
        macoro::thread_pool::work mWork;
        std::size_t mWorkers;
        CpuBenchmarkContext* mBenchmark;
        std::atomic<bool> mRunning{false};

        // Preserve the caller's share of the work and the existing W-1 pool.
        // Queue insertion is all-or-none; inline execution cannot throw.
        struct CallerAndPool
        {
            macoro::thread_pool& mPool;
            void post_batch(const macoro::work_item* items, std::size_t count)
            {
                if (!count) return;
                mPool.post_batch(items + 1, count - 1);
                items[0]();
            }
        };

        class Phase
        {
            std::atomic<bool>& mRunning;
        public:
            explicit Phase(std::atomic<bool>& running) : mRunning(running)
            {
                if (mRunning.exchange(true, std::memory_order_acquire))
                    throw std::logic_error("LogVole CPU executor is already running a phase");
            }
            ~Phase() { mRunning.store(false, std::memory_order_release); }
        };

        // Ordinary scope after the scheduling suspension. No TLS propagation
        // or lock is held across an await. The caller's CPU clock is already
        // measured by its enclosing diagnostic region.
        class TaskMetrics
        {
            CpuBenchmarkContext* mContext;
            bool mBackground;
            std::uint64_t mStart = 0;
        public:
            TaskMetrics(CpuBenchmarkContext* context, bool background)
                : mContext(context), mBackground(background)
            {
                if (!mContext) return;
                mContext->checkThread();
                mStart = cpuBenchmarkThreadNs();
                const auto active = mContext->mActiveTaskThreads.fetch_add(1) + 1;
                auto peak = mContext->mPeakTaskThreads.load();
                while (active > peak && !mContext->mPeakTaskThreads.compare_exchange_weak(peak, active)) {}
            }
            ~TaskMetrics()
            {
                if (!mContext) return;
                if (mBackground)
                    mContext->mWorkerCpuNs.fetch_add(cpuBenchmarkThreadNs() - mStart);
                mContext->checkThread();
                mContext->mActiveTaskThreads.fetch_sub(1);
            }
        };

        template<typename Worker>
        static macoro::task<> scheduledWorker(macoro::thread_pool& pool,
            Worker& worker, std::size_t workerIdx)
        {
            co_await pool.schedule();
            worker(workerIdx);
        }

    public:
        explicit CpuExecutor(std::size_t workers, CpuBenchmarkContext* benchmark = nullptr)
            : mWork(mPool.make_work()), mWorkers(std::max<std::size_t>(1, workers)),
              mBenchmark(benchmark)
        {
            // Release work before pool destruction if thread creation fails
            // part way through. The pool then joins every thread it did start.
            try { mPool.create_threads(mWorkers - 1); }
            catch (...) { mWork.reset(); throw; }
        }

        CpuExecutor(const CpuExecutor&) = delete;
        CpuExecutor& operator=(const CpuExecutor&) = delete;
        CpuExecutor(CpuExecutor&&) = delete;
        CpuExecutor& operator=(CpuExecutor&&) = delete;

        std::size_t workers() const noexcept { return mWorkers; }

        // One exclusive caller-owned local per partition, reused across its
        // contiguous range. Numerical storage and executor outlive the join.
        template<typename Local, std::size_t Extent, typename TaskFn>
        void runBulk(std::size_t taskCount, std::span<Local, Extent> locals, TaskFn&& taskFn)
        {
            static_assert(std::is_same_v<std::invoke_result_t<TaskFn&, std::size_t, Local&>, void>);
            Phase phase(mRunning);
            if (!taskCount) return;
            if (locals.empty()) throw std::invalid_argument("LogVole CPU bulk requires local storage");
            const auto count = std::min({taskCount, mWorkers, locals.size()});
            if (count == 1)
            {
                TaskMetrics metrics(mBenchmark, false);
                for (std::size_t i = 0; i < taskCount; ++i) taskFn(i, locals[0]);
                return;
            }
            CallerAndPool executor{mPool};
            macoro::sync_wait(macoro::bulk(executor, taskCount, locals.first(count),
                [&](std::size_t i, Local& local) {
                    TaskMetrics metrics(mBenchmark, &local != locals.data());
                    taskFn(i, local);
                }));
        }

        // The callable and everything it borrows remain live until all children
        // join, including when caller/background work throws or returns false.
        // Task containers and macoro frames are the explicit scheduling
        // allocation exception; the pool and numerical buffers are reused.
        template<typename TaskFn>
        bool run(std::size_t taskCount, TaskFn&& taskFn, bool dynamic = false)
        {
            Phase phase(mRunning);
            if (taskCount == 0) return true;
            const auto workerCount = std::min(taskCount, mWorkers);
            std::atomic<bool> failed{false};
            std::atomic<std::size_t> nextTask{0};
            auto worker = [&](std::size_t workerIdx) {
                TaskMetrics metrics(mBenchmark, workerIdx != 0);
                try
                {
                    if (dynamic)
                    {
                        while (!failed.load(std::memory_order_acquire))
                        {
                            const auto taskIdx = nextTask.fetch_add(1, std::memory_order_relaxed);
                            if (taskIdx >= taskCount) break;
                            if (!taskFn(workerIdx, taskIdx))
                            {
                                failed.store(true, std::memory_order_release);
                                break;
                            }
                        }
                        return;
                    }
                    const auto begin = workerIdx * taskCount / workerCount;
                    const auto end = (workerIdx + 1) * taskCount / workerCount;
                    for (auto taskIdx = begin; taskIdx < end; ++taskIdx)
                    {
                        if (failed.load(std::memory_order_acquire)) break;
                        if (!taskFn(workerIdx, taskIdx))
                        {
                            failed.store(true, std::memory_order_release);
                            break;
                        }
                    }
                }
                catch (...) { failed.store(true, std::memory_order_release); throw; }
            };

            if (workerCount == 1)
            {
                worker(0);
                return !failed.load(std::memory_order_acquire);
            }
            // All children and the join are constructed before any child can
            // run. An allocation failure cannot strand borrowed parent locals.
            std::vector<macoro::task<>> tasks;
            tasks.reserve(workerCount - 1);
            for (std::size_t i = 1; i < workerCount; ++i)
                tasks.push_back(scheduledWorker(mPool, worker, i));
            auto joined = macoro::make_blocking(macoro::when_all_ready(std::move(tasks)));
            std::exception_ptr callerError;
            try { worker(0); }
            catch (...) { callerError = std::current_exception(); }
            auto results = joined.get();
            if (callerError) std::rethrow_exception(callerError);
            for (auto& result : results) result.result();
            return !failed.load(std::memory_order_acquire);
        }
    };
}
