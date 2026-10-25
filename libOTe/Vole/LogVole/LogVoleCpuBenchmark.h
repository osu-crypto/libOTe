#pragma once

// Optional diagnostics used by the CPU benchmark. Normal library callers leave
// the thread-local context null, so their scheduling policy is unchanged.
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <vector>

#if defined(__linux__)
#include <sched.h>
#include <time.h>
#endif

namespace osuCrypto::LogVole
{
    struct CpuBenchmarkContext
    {
        std::vector<int> mCpus;
        std::size_t mWorkerLimit = 0;
        std::atomic<std::size_t> mWorkerSlots{0};
        std::atomic<std::uint64_t> mWorkerCpuNs{0};
        std::atomic<std::uint64_t> mWorkersChecked{0};
        std::atomic<std::uint64_t> mAffinityFailures{0};
        std::atomic<std::size_t> mActiveTaskThreads{0};
        std::atomic<std::size_t> mPeakTaskThreads{0};
        std::array<std::atomic<std::uint64_t>, 16> mObservedCpus{};

        void reset()
        {
            mWorkerCpuNs.store(0);
            mWorkersChecked.store(0);
            mAffinityFailures.store(0);
            mActiveTaskThreads.store(0);
            mPeakTaskThreads.store(0);
            for (auto& word : mObservedCpus) word.store(0);
        }

        void checkThread()
        {
#if defined(__linux__)
            cpu_set_t mask;
            CPU_ZERO(&mask);
            bool ok = sched_getaffinity(0, sizeof(mask), &mask) == 0;
            ok = ok && CPU_COUNT(&mask) == static_cast<int>(mCpus.size());
            for (int cpu : mCpus) ok = ok && CPU_ISSET(cpu, &mask);
            const int cpu = sched_getcpu();
            if (cpu >= 0 && cpu < 1024)
                mObservedCpus[cpu / 64].fetch_or(std::uint64_t(1) << (cpu % 64));
            mWorkersChecked.fetch_add(1);
            if (!ok) mAffinityFailures.fetch_add(1);
#endif
        }
    };

    inline thread_local CpuBenchmarkContext* tCpuBenchmarkContext = nullptr;
    inline thread_local bool tCpuBenchmarkIsWorker = false;
    inline thread_local std::size_t tCpuBenchmarkTaskDepth = 0;

    // Counts distinct threads inside task bodies, without counting nested
    // serial regions twice. CPU clocks separately establish actual CPU use.
    class CpuBenchmarkTaskScope
    {
    public:
        CpuBenchmarkTaskScope() : mContext(tCpuBenchmarkContext)
        {
            if (!mContext || tCpuBenchmarkTaskDepth++ != 0) return;
            const auto active = mContext->mActiveTaskThreads.fetch_add(1) + 1;
            auto peak = mContext->mPeakTaskThreads.load();
            while (active > peak && !mContext->mPeakTaskThreads.compare_exchange_weak(peak, active)) {}
        }
        ~CpuBenchmarkTaskScope()
        {
            if (mContext && --tCpuBenchmarkTaskDepth == 0)
                mContext->mActiveTaskThreads.fetch_sub(1);
        }
    private:
        CpuBenchmarkContext* mContext;
    };

    inline std::uint64_t cpuBenchmarkThreadNs()
    {
#if defined(__linux__)
        timespec value{};
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) != 0)
            throw std::runtime_error("could not read thread CPU clock");
        return std::uint64_t(value.tv_sec) * 1000000000ull + value.tv_nsec;
#else
        return 0;
#endif
    }

    class CpuBenchmarkWorkerScope
    {
    public:
        explicit CpuBenchmarkWorkerScope(CpuBenchmarkContext* context)
            : mPrevious(tCpuBenchmarkContext), mContext(context), mPreviousIsWorker(tCpuBenchmarkIsWorker)
        {
            tCpuBenchmarkContext = context;
            tCpuBenchmarkIsWorker = true;
            if (mContext)
            {
                mContext->checkThread();
                mStart = cpuBenchmarkThreadNs();
            }
        }
        ~CpuBenchmarkWorkerScope()
        {
            if (mContext)
            {
                mContext->mWorkerCpuNs.fetch_add(cpuBenchmarkThreadNs() - mStart);
                mContext->checkThread();
            }
            tCpuBenchmarkContext = mPrevious;
            tCpuBenchmarkIsWorker = mPreviousIsWorker;
        }
    private:
        CpuBenchmarkContext* mPrevious;
        CpuBenchmarkContext* mContext;
        bool mPreviousIsWorker;
        std::uint64_t mStart = 0;
    };
}
