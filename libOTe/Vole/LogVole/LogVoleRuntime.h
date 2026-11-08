#pragma once
#include "libOTe/Vole/LogVole/LogVoleIdentity.h"

#include <cryptoTools/Common/Defines.h>
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace osuCrypto::LogVole
{
    enum class ProtocolCacheRole : u8
    {
        Unspecified = 0,
        Sender = 1,
        Receiver = 2
    };

    struct ProtocolCacheScopeView
    {
        ProtocolCacheRunId mRunId;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
    };

    // Owned operation context. Copy only at operation/chunk boundaries; hot
    // current-scope reads and ID/hash comparisons use the cheap view above.
    struct ProtocolCacheScope : ProtocolCacheScopeView
    {
        std::shared_ptr<const ProtocolCacheService> mServiceOwner;
        ProtocolCacheScope() = default;
        ProtocolCacheScope(ProtocolCacheRunId id, ProtocolCacheRole role)
            : ProtocolCacheScopeView{id, role}, mServiceOwner(id.serviceOwner()) {}
        ProtocolCacheScope(ProtocolCacheScopeView view)
            : ProtocolCacheScope(view.mRunId, view.mRole) {}
    };

    // Root diagnostics belong to the ring factory reuse domain.
    // Disabled factories allocate no profiler; there is no process-wide table.
    struct RootStepProfiler
    {
        struct Entry
        {
            const char* mName;
            std::atomic<u64> mUs{ 0 };
            std::atomic<u64> mCount{ 0 };
            // First call and worst call, because a one-time device cache
            // upload inside a step is indistinguishable from a per-query cost
            // in the mean.
            std::atomic<u64> mFirstUs{ 0 };
            std::atomic<u64> mMaxUs{ 0 };
        };
        static constexpr u32 kMax = 32;
        Entry mEntries[kMax]{};
        std::atomic<u32> mUsed{ 0 };
        std::mutex mMutex;

        ~RootStepProfiler()
        {
            if (!mUsed.load()) return;
            const u32 n = mUsed.load();
            std::fprintf(stderr, "\n[root] per-step host time\n");
            u64 total = 0;
            for (u32 i = 0; i < n; ++i) total += mEntries[i].mUs.load();
            for (u32 i = 0; i < n; ++i)
            {
                const u64 us = mEntries[i].mUs.load();
                const u64 cnt = mEntries[i].mCount.load();
                const u64 first = mEntries[i].mFirstUs.load();
                const double rest =
                    cnt > 1 ? double(us - first) / double(cnt - 1) / 1000.0 : 0.0;
                std::fprintf(
                    stderr,
                    "[root] %-34s %8.3f ms  x%-4llu %5.1f%%  first %7.3f  max %7.3f  "
                    "mean-after-first %7.3f\n",
                    mEntries[i].mName, double(us) / 1000.0, (unsigned long long)cnt,
                    total ? 100.0 * double(us) / double(total) : 0.0, double(first) / 1000.0,
                    double(mEntries[i].mMaxUs.load()) / 1000.0, rest);
            }
            std::fprintf(stderr, "[root] %-34s %8.3f ms\n", "TOTAL", double(total) / 1000.0);
        }

        // Names are string literals; callers join all steps before destruction.
        Entry& slot(const char* name)
        {
            std::lock_guard<std::mutex> lock(mMutex);
            const u32 n = mUsed.load(std::memory_order_acquire);
            for (u32 i = 0; i < n; ++i)
            {
                if (mEntries[i].mName == name) return mEntries[i];
            }
            if (n >= kMax) return mEntries[kMax - 1];
            mEntries[n].mName = name;
            mUsed.store(n + 1, std::memory_order_release);
            return mEntries[n];
        }
    };


    // ---- host step timing -------------------------------------------------
    //
    // Wall-clock and current-thread CPU accounting for named regions, enabled
    // explicitly by the caller. Each execution domain owns its table and reports
    // it when the last owner is released.
    //
    // The first call is reported apart from the rest because a one-time device
    // cache upload or NTT-table build inside a step is otherwise
    // indistinguishable from a steady-state per-query cost in the mean, which is
    // exactly the mistake this profiler exists to stop.
    struct HostStepProfiler
    {
        struct Entry
        {
            // Copied, not aliased, so callers can build a name that carries the
            // recursion level. Without that every level of a recursive protocol
            // lands in one bucket and the mean is meaningless.
            char mName[56]{};
            std::atomic<u64> mNs{ 0 };
            std::atomic<u64> mCpuNs{ 0 };
            std::atomic<u64> mCpuCount{ 0 };
            std::atomic<u64> mCount{ 0 };
            std::atomic<u64> mFirstNs{ 0 };
            std::atomic<u64> mMaxNs{ 0 };
        };
        static constexpr u32 kMax = 256;
        Entry mEntries[kMax]{};
        std::atomic<u32> mUsed{ 0 };
        std::mutex mMutex;

        struct Sample
        {
            std::string mName;
            double mMs = 0;
            u64 mCount = 0;
            double mCpuMs = 0;
            u64 mCpuCount = 0;
        };

        // Call only between complete protocol queries, with workers joined.
        void reset()
        {
            std::lock_guard<std::mutex> lock(mMutex);
            for (u32 i = 0; i < mUsed.load(); ++i)
            {
                mEntries[i].mNs.store(0);
                mEntries[i].mCpuNs.store(0);
                mEntries[i].mCpuCount.store(0);
                mEntries[i].mCount.store(0);
                mEntries[i].mFirstNs.store(0);
                mEntries[i].mMaxNs.store(0);
            }
        }

        std::vector<Sample> snapshot()
        {
            std::lock_guard<std::mutex> lock(mMutex);
            std::vector<Sample> samples;
            for (u32 i = 0; i < mUsed.load(); ++i)
            {
                const auto count = mEntries[i].mCount.load();
                if (count) samples.push_back({mEntries[i].mName,
                    double(mEntries[i].mNs.load()) / 1e6, count,
                    double(mEntries[i].mCpuNs.load()) / 1e6, mEntries[i].mCpuCount.load()});
            }
            return samples;
        }

        ~HostStepProfiler()
        {
            const u32 n = mUsed.load();
            if (!n) return;
            std::fprintf(stderr, "\n[step] host wall and thread CPU time per named region\n");
            for (u32 i = 0; i < n; ++i)
            {
                const u64 ns = mEntries[i].mNs.load();
                const u64 cnt = mEntries[i].mCount.load();
                const u64 first = mEntries[i].mFirstNs.load();
                std::fprintf(
                    stderr, "[step] %-44s %9.3f ms x%-5llu first %8.3f  after %8.3f  max %8.3f  cpu %8.3f ms x%-5llu\n",
                    mEntries[i].mName, double(ns) / 1e6, (unsigned long long)cnt, double(first) / 1e6,
                    cnt > 1 ? double(ns - first) / double(cnt - 1) / 1e6 : 0.0,
                    double(mEntries[i].mMaxNs.load()) / 1e6,
                    double(mEntries[i].mCpuNs.load()) / 1e6,
                    (unsigned long long)mEntries[i].mCpuCount.load());
            }
        }

        Entry& slot(const char* name)
        {
            std::lock_guard<std::mutex> lock(mMutex);
            const u32 n = mUsed.load(std::memory_order_relaxed);
            for (u32 i = 0; i < n; ++i)
            {
                if (std::strcmp(mEntries[i].mName, name) == 0) return mEntries[i];
            }
            if (n >= kMax) return mEntries[kMax - 1];
            std::snprintf(mEntries[n].mName, sizeof(mEntries[n].mName), "%s", name);
            mUsed.store(n + 1, std::memory_order_relaxed);
            return mEntries[n];
        }
    };

    class HostStep
    {
    public:
        HostStep(HostStepProfiler* profiler, const char* name, const CpuBenchmarkState* benchmark = nullptr)
        {
            if (!profiler) return;
            mEntry = &profiler->slot(name);
            startCpu(benchmark);
            mStart = std::chrono::steady_clock::now();
        }

        // `tag` is appended to the name, so a recursive caller can keep its
        // levels apart (pass the level's width, for instance).
        HostStep(HostStepProfiler* profiler, const char* name, u64 tag, const CpuBenchmarkState* benchmark = nullptr)
        {
            if (!profiler) return;
            char buf[56];
            std::snprintf(buf, sizeof(buf), "%s w=%llu", name, static_cast<unsigned long long>(tag));
            mEntry = &profiler->slot(buf);
            startCpu(benchmark);
            mStart = std::chrono::steady_clock::now();
        }

        HostStep(const HostStep&) = delete;
        HostStep& operator=(const HostStep&) = delete;

        ~HostStep()
        {
            if (!mEntry) return;
            stop();
        }

        void stop()
        {
            if (!mEntry) return;
            const auto ns = static_cast<u64>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                 std::chrono::steady_clock::now() - mStart)
                                                 .count());
            mEntry->mNs.fetch_add(ns);
            if (mCpuThread == std::this_thread::get_id())
            {
                // Coordinator regions must join their workers before stopping.
                // Worker regions measure only their own thread; summing the
                // shared counter there would count unrelated sibling work.
                const auto workerNs = mIncludeWorkers ? mCpuContext->mWorkerCpuNs.load() - mWorkerStart : 0;
                mEntry->mCpuNs.fetch_add(cpuBenchmarkThreadNs() - mCpuStart + workerNs);
                mEntry->mCpuCount.fetch_add(1);
            }
            // A coroutine may resume on another thread. Its CPU clocks are
            // incomparable; keep wall time but omit that CPU sample.
            if (mEntry->mCount.fetch_add(1) == 0) mEntry->mFirstNs.store(ns);
            u64 seen = mEntry->mMaxNs.load();
            while (ns > seen && !mEntry->mMaxNs.compare_exchange_weak(seen, ns))
            {
            }
            mEntry = nullptr;
        }

    private:
        void startCpu(const CpuBenchmarkState* benchmark)
        {
            mCpuContext = benchmark ? benchmark->mContext : nullptr;
            mCpuThread = std::this_thread::get_id();
            mCpuStart = cpuBenchmarkThreadNs();
            if (!mCpuContext) return;
            // The coordinating thread also executes task zero. Inside that
            // task, completed siblings belong to the enclosing parallel region,
            // not to this task's local timer.
            mIncludeWorkers = !benchmark->mIsWorker && benchmark->mTaskDepth == 0;
            mWorkerStart = mCpuContext->mWorkerCpuNs.load();
        }

        std::thread::id mCpuThread;
        CpuBenchmarkContext* mCpuContext = nullptr;
        bool mIncludeWorkers = false;
        u64 mCpuStart = 0;
        u64 mWorkerStart = 0;
        HostStepProfiler::Entry* mEntry = nullptr;
        std::chrono::steady_clock::time_point mStart{};
    };
}
