#pragma once

#include <cryptoTools/Common/Defines.h>
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include "libOTe/Vole/LogVole/LogVoleDiagnostics.h"

#include <atomic>
#include <memory>
#include <cstdint>
#include <utility>
#include <typeindex>
#include <unordered_map>
#include <thread>
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

    // ---- host step timing -------------------------------------------------
    //
    // Wall-clock and current-thread CPU accounting for named regions, enabled with
    // LV_STEP_PROFILE=1 and reported when its execution owner is released.
    // Every translation unit receives that same explicit owner.
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
        std::unique_ptr<Entry[]> mEntries;
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
            if (!mEntries) mEntries = std::make_unique<Entry[]>(kMax);
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

    // Explicit owner of execution settings, diagnostics, and reusable resources.
    // Copies of protocol parameters share this owner; independent sessions get
    // distinct owners. No state is installed on the executing thread.
    class ExecutionContext : public std::enable_shared_from_this<ExecutionContext>
    {
        struct Diagnostics
        {
            RingOpsStats mRingOps;
            TimingStats mTiming;
            HostStepProfiler mHostSteps;
        };
        std::shared_ptr<Diagnostics> mDiagnostics;

    public:
        ExecutionContext() : ExecutionContext(std::make_shared<Diagnostics>()) {}
        explicit ExecutionContext(std::shared_ptr<Diagnostics> diagnostics)
            : mDiagnostics(std::move(diagnostics)), mRingOps(mDiagnostics->mRingOps),
              mTiming(mDiagnostics->mTiming), mHostSteps(mDiagnostics->mHostSteps) {}

        bool mUseGpu = false;
        ProtocolCacheScope mScope{};
        CpuBenchmarkContext* mCpuBenchmark = nullptr;
        RingOpsStats& mRingOps;
        TimingStats& mTiming;
        HostStepProfiler& mHostSteps;

        u64 ownerId() const
        {
            return static_cast<u64>(reinterpret_cast<std::uintptr_t>(mIdentity.get()));
        }

        // Tables retain metadata and GPU resources without retaining the cache
        // that refers to those tables. Streams and scratch never own tables.
        std::shared_ptr<ExecutionContext> resourceOwner(bool shareDeviceResources = true) const
        {
            auto owner = std::make_shared<ExecutionContext>(mDiagnostics);
            owner->mUseGpu = mUseGpu;
            owner->mScope = mScope;
            owner->mCpuBenchmark = mCpuBenchmark;
            owner->mIdentity = mIdentity;
            owner->mWireResources = mWireResources;
            if (shareDeviceResources) owner->mDeviceResources = mDeviceResources;
            return owner;
        }

        template<class T, class... Args>
        T& resources(Args&&... args) const
        {
            return mResources.get<T>(std::forward<Args>(args)...);
        }

        template<class T, class... Args>
        T& deviceResources(Args&&... args) const
        {
            std::shared_ptr<ResourceStorage> resources;
            {
                std::lock_guard lock(mDeviceResources->mMutex);
                auto& worker = mDeviceResources->mWorkers[std::this_thread::get_id()];
                if (!worker) worker = std::make_shared<ResourceStorage>();
                resources = worker;
            }
            return resources->get<T>(std::forward<Args>(args)...);
        }

        template<class T, class... Args>
        T& wireResources(Args&&... args) const
        {
            return mWireResources->get<T>(std::forward<Args>(args)...);
        }

    private:
        struct ResourceStorage
        {
            template<class T, class... Args>
            T& get(Args&&... args)
            {
                std::lock_guard lock(mMutex);
                auto& entry = mEntries[std::type_index(typeid(T))];
                if (!entry) entry = std::make_shared<T>(std::forward<Args>(args)...);
                return *static_cast<T*>(entry.get());
            }
            std::mutex mMutex;
            std::unordered_map<std::type_index, std::shared_ptr<void>> mEntries;
        };
        struct DeviceResourceStorage
        {
            std::mutex mMutex;
            std::unordered_map<std::thread::id, std::shared_ptr<ResourceStorage>> mWorkers;
        };
        std::shared_ptr<u8> mIdentity = std::make_shared<u8>(0);
        mutable ResourceStorage mResources;
        std::shared_ptr<ResourceStorage> mWireResources = std::make_shared<ResourceStorage>();
        std::shared_ptr<DeviceResourceStorage> mDeviceResources = std::make_shared<DeviceResourceStorage>();

    };

    using ExecutionContextPtr = std::shared_ptr<ExecutionContext>;

    class HostStep
    {
    public:
        HostStep(ExecutionContext& execution, const char* name)
        {
            const char* value = std::getenv("LV_STEP_PROFILE");
            if (!value || !value[0] || value[0] == '0') return;
            mEntry = &execution.mHostSteps.slot(name);
            mStart = std::chrono::steady_clock::now();
            mCpuStart = cpuBenchmarkThreadNs();
        }

        HostStep(ExecutionContext& execution, const char* name, u64 tag)
        {
            const char* value = std::getenv("LV_STEP_PROFILE");
            if (!value || !value[0] || value[0] == '0') return;
            char buffer[56];
            std::snprintf(buffer, sizeof(buffer), "%s w=%llu", name,
                static_cast<unsigned long long>(tag));
            mEntry = &execution.mHostSteps.slot(buffer);
            mStart = std::chrono::steady_clock::now();
            mCpuStart = cpuBenchmarkThreadNs();
        }

        HostStep(ExecutionContext* execution, const char* name)
        {
            if (!execution) return;
            const char* value = std::getenv("LV_STEP_PROFILE");
            if (!value || !value[0] || value[0] == '0') return;
            mEntry = &execution->mHostSteps.slot(name);
            mStart = std::chrono::steady_clock::now();
            mCpuStart = cpuBenchmarkThreadNs();
        }

        HostStep(const HostStep&) = delete;
        HostStep& operator=(const HostStep&) = delete;
        ~HostStep() { stop(); }

        void stop()
        {
            if (!mEntry) return;
            const auto ns = static_cast<u64>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - mStart).count());
            mEntry->mNs.fetch_add(ns);
            mEntry->mCpuNs.fetch_add(cpuBenchmarkThreadNs() - mCpuStart);
            mEntry->mCpuCount.fetch_add(1);
            if (mEntry->mCount.fetch_add(1) == 0) mEntry->mFirstNs.store(ns);
            u64 seen = mEntry->mMaxNs.load();
            while (ns > seen && !mEntry->mMaxNs.compare_exchange_weak(seen, ns)) {}
            mEntry = nullptr;
        }

    private:
        u64 mCpuStart = 0;
        HostStepProfiler::Entry* mEntry = nullptr;
        std::chrono::steady_clock::time_point mStart{};
    };
}
