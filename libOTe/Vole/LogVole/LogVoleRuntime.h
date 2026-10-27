#pragma once

#include <cryptoTools/Common/Defines.h>
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace osuCrypto::LogVole
{
    enum class ProtocolCacheRole : u8
    {
        Unspecified = 0,
        Sender = 1,
        Receiver = 2
    };

    struct ProtocolCacheScope
    {
        u64 mRunId = 0;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
    };

    inline std::atomic<u64> gProtocolCacheRunCounter{ 1 };
    inline thread_local ProtocolCacheScope tProtocolCacheScope{};

    inline u64 allocateProtocolCacheRunId()
    {
        return gProtocolCacheRunCounter.fetch_add(1, std::memory_order_relaxed);
    }

    inline ProtocolCacheScope currentProtocolCacheScope()
    {
        return tProtocolCacheScope;
    }

    inline void setProtocolCacheScope(ProtocolCacheRole role, u64 runId)
    {
        tProtocolCacheScope.mRole = role;
        tProtocolCacheScope.mRunId = runId;
    }

    class ScopedProtocolCacheScope
    {
    public:
        ScopedProtocolCacheScope(ProtocolCacheRole role, u64 runId)
            : mPrevious(tProtocolCacheScope)
        {
            setProtocolCacheScope(role, runId);
        }

        ScopedProtocolCacheScope(ProtocolCacheScope scope)
            : mPrevious(tProtocolCacheScope)
        {
            tProtocolCacheScope = scope;
        }

        ScopedProtocolCacheScope(const ScopedProtocolCacheScope&) = delete;
        ScopedProtocolCacheScope& operator=(const ScopedProtocolCacheScope&) = delete;

        ~ScopedProtocolCacheScope()
        {
            tProtocolCacheScope = mPrevious;
        }

    private:
        ProtocolCacheScope mPrevious{};
    };

    // ---- host step timing -------------------------------------------------
    //
    // Wall-clock and current-thread CPU accounting for named regions, enabled with
    // LV_STEP_PROFILE=1 and dumped at exit. Header only so every translation
    // unit can use the same table.
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

    inline HostStepProfiler& hostStepProfiler()
    {
        static HostStepProfiler p;
        return p;
    }

    inline bool hostStepEnabled()
    {
        static const bool on = [] {
            const char* v = std::getenv("LV_STEP_PROFILE");
            return v && v[0] != '\0' && v[0] != '0';
        }();
        return on;
    }

    class HostStep
    {
    public:
        explicit HostStep(const char* name)
        {
            if (!hostStepEnabled()) return;
            mEntry = &hostStepProfiler().slot(name);
            startCpu();
            mStart = std::chrono::steady_clock::now();
        }

        // `tag` is appended to the name, so a recursive caller can keep its
        // levels apart (pass the level's width, for instance).
        HostStep(const char* name, u64 tag)
        {
            if (!hostStepEnabled()) return;
            char buf[56];
            std::snprintf(buf, sizeof(buf), "%s w=%llu", name, static_cast<unsigned long long>(tag));
            mEntry = &hostStepProfiler().slot(buf);
            startCpu();
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
            if (mCpuContext && mCpuContext == tCpuBenchmarkContext)
            {
                // Coordinator regions must join their workers before stopping.
                // Worker regions measure only their own thread; summing the
                // shared counter there would count unrelated sibling work.
                const auto workerNs = mIncludeWorkers ? mCpuContext->mWorkerCpuNs.load() - mWorkerStart : 0;
                mEntry->mCpuNs.fetch_add(cpuBenchmarkThreadNs() - mCpuStart + workerNs);
                mEntry->mCpuCount.fetch_add(1);
            }
            else if (!mCpuContext)
            {
                // GPU benchmark workers have no CPU benchmark context. Measure
                // the executing thread so blocking socket wall time can be
                // separated from the worker's actual CPU service.
                mEntry->mCpuNs.fetch_add(cpuBenchmarkThreadNs() - mCpuStart);
                mEntry->mCpuCount.fetch_add(1);
            }
            if (mEntry->mCount.fetch_add(1) == 0) mEntry->mFirstNs.store(ns);
            u64 seen = mEntry->mMaxNs.load();
            while (ns > seen && !mEntry->mMaxNs.compare_exchange_weak(seen, ns))
            {
            }
            mEntry = nullptr;
        }

    private:
        void startCpu()
        {
            mCpuContext = tCpuBenchmarkContext;
            mCpuStart = cpuBenchmarkThreadNs();
            if (!mCpuContext) return;
            // The coordinating thread also executes task zero. Inside that
            // task, completed siblings belong to the enclosing parallel region,
            // not to this task's local timer.
            mIncludeWorkers = !tCpuBenchmarkIsWorker && tCpuBenchmarkTaskDepth == 0;
            mWorkerStart = mCpuContext->mWorkerCpuNs.load();
        }

        CpuBenchmarkContext* mCpuContext = nullptr;
        bool mIncludeWorkers = false;
        u64 mCpuStart = 0;
        u64 mWorkerStart = 0;
        HostStepProfiler::Entry* mEntry = nullptr;
        std::chrono::steady_clock::time_point mStart{};
    };
}
