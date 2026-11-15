#include "libOTe/Vole/LogVole/LogVoleGpuCompatibility.h"
#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe_Tests/WideArithmeticOracle.h"
#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZkArith.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZk.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"
#include "libOTe/Vole/LogVole/LogVoleCpuExecutor.h"
#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleZk.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "seal/util/ntt.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarith.h"
#include "seal/util/clipnormal.h"
#include "seal/randomtostd.h"

#include <array>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <future>
#include <thread>
#include <string>
#include <tuple>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

void LogVole_Cpu_ParallelFailureJoinsChildren(const oc::CLP&)
{
    // Explicit state must preserve same-thread nesting, isolate independent
    // contexts, and unwind counters when an inner task throws.
    CpuBenchmarkContext telemetry, other;
    telemetry.mCpus.resize(2);
    telemetry.mWorkerLimit = 2;
    other.mCpus.resize(1);
    CpuBenchmarkState state{&telemetry};
    LogVole::detail::CpuRowScratch scratch;
    for (unsigned repeat = 0; repeat != 2; ++repeat)
    {
        telemetry.reset();
        LOGVOLE_REQUIRE_TRUE(scratch.runBulk(4, 2,
            [&](std::size_t, CpuBenchmarkState& workerState) {
                LOGVOLE_REQUIRE_TRUE(workerState.mContext == &telemetry);
                LOGVOLE_REQUIRE_EQ(workerState.mTaskDepth, 1u);
                LogVole::detail::CpuRowScratch serial;
                const bool ok = serial.runBulk(3, 1,
                    [&](std::size_t, CpuBenchmarkState& nestedState) {
                        LOGVOLE_REQUIRE_EQ(nestedState.mTaskDepth, 2u);
                        LOGVOLE_REQUIRE_EQ(other.mActiveTaskThreads.load(), 0u);
                        return true;
                    }, workerState);
                LOGVOLE_REQUIRE_TRUE(serial.executor() == nullptr);
                return ok;
            }, state));
        LOGVOLE_REQUIRE_EQ(state.mTaskDepth, 0u);
        LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 0u);
        LOGVOLE_REQUIRE_TRUE(telemetry.mPeakTaskThreads.load() <= 2u);
        LOGVOLE_REQUIRE_TRUE(telemetry.mPeakTaskThreads.load() > 0u);
    }
    {
        CpuBenchmarkTaskScope outer(state);
        CpuBenchmarkState otherState{&other};
        LOGVOLE_REQUIRE_TRUE(scratch.runBulk(1, 1,
            [&](std::size_t, CpuBenchmarkState& independent) {
                LOGVOLE_REQUIRE_EQ(independent.mTaskDepth, 1u);
                LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 1u);
                LOGVOLE_REQUIRE_EQ(other.mActiveTaskThreads.load(), 1u);
                return true;
            }, otherState));
        bool innerThrew = false;
        try
        {
            scratch.runBulk(1, 1,
                [](std::size_t) -> bool { throw std::runtime_error("instrumented task"); },
                state);
        }
        catch (const std::runtime_error&) { innerThrew = true; }
        LOGVOLE_REQUIRE_TRUE(innerThrew);
        LOGVOLE_REQUIRE_EQ(state.mTaskDepth, 1u);
        LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 1u);
        LOGVOLE_REQUIRE_EQ(other.mActiveTaskThreads.load(), 0u);
    }
    LOGVOLE_REQUIRE_EQ(state.mTaskDepth, 0u);
    LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 0u);

    // A timer stopped on a different thread must not subtract unrelated CPU clocks.
    HostStepProfiler profiler;
    HostStep migrated(&profiler, "thread migration", &state);
    std::thread finish([&] { migrated.stop(); });
    finish.join();
    const auto samples = profiler.snapshot();
    LOGVOLE_REQUIRE_EQ(samples.size(), 1u);
    LOGVOLE_REQUIRE_EQ(samples[0].mCount, 1u);
    LOGVOLE_REQUIRE_EQ(samples[0].mCpuCount, 0u);

    struct Failure {};
    bool propagated = false;
    try
    {
        scratch.runBulk(1, 1, [](std::size_t) -> bool { throw Failure{}; }, state);
    }
    catch (const Failure&) { propagated = true; }
    LOGVOLE_REQUIRE_TRUE(propagated);
    if (std::thread::hardware_concurrency() < 2) return;

    for (bool callerThrows : {true, false})
    {
        std::atomic<bool> childStarted{false}, childFinished{false};
        propagated = false;
        bool joinedBeforeThrow = false;
        try
        {
            (void)scratch.runBulk(2, 2, [&](std::size_t task) -> bool {
                if (task == 1)
                {
                    childStarted.store(true, std::memory_order_release);
                    childStarted.notify_all();
                    // Leave a child actively using its parent's captures when
                    // the caller throws. This is a lifetime test, not load.
                    if (callerThrows) std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    childFinished.store(true, std::memory_order_release);
                    if (!callerThrows) throw Failure{};
                    return true;
                }
                childStarted.wait(false, std::memory_order_acquire);
                if (callerThrows) throw Failure{};
                return true;
            }, state);
        }
        catch (const Failure&)
        {
            propagated = true;
            joinedBeforeThrow = childFinished.load(std::memory_order_acquire);
        }
        LOGVOLE_REQUIRE_TRUE(propagated);
        LOGVOLE_REQUIRE_TRUE(joinedBeforeThrow);
    }
    std::atomic<bool> completed{false};
    const bool ok = scratch.runBulk(2, 2, [&](std::size_t task) {
        if (task == 0) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        completed.store(true, std::memory_order_release);
        return true;
    }, state);
    LOGVOLE_REQUIRE_FALSE(ok);
    LOGVOLE_REQUIRE_TRUE(completed.load(std::memory_order_acquire));
    LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 0u);
}


void LogVole_Cpu_OfflineSetupExecution(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    auto onPool = [&](macoro::task<bool> operation) -> macoro::task<bool> {
        co_await setupResources.executor.schedule();
        const bool ok = co_await std::move(operation);
        co_return ok;
    };
    LogVole::detail::CpuRowScratch scratch;
    CpuBenchmarkContext telemetry;
    telemetry.mCpus = {0, 1, 2};
    telemetry.mWorkerLimit = 3;
    CpuBenchmarkState benchmark{&telemetry};
    LogVole::detail::CpuExecutor* executor = nullptr;
    for (u32 allowance : {1u, 3u, 2u, 1u})
    {
        telemetry.reset();
        std::array<unsigned, 7> visits{};
        LOGVOLE_REQUIRE_TRUE(scratch.runBulk(visits.size(), allowance, [&](std::size_t i, CpuBenchmarkState& worker) {
                LOGVOLE_REQUIRE_TRUE(worker.mContext == &telemetry);
                // Serial children borrow the partition, without another pool
                // or double-counting the active worker.
                return scratch.runBulk(1, 1, [&](std::size_t) { ++visits[i]; return true; }, worker);
            }, benchmark));
        for (auto count : visits) LOGVOLE_REQUIRE_EQ(count, 1u);
        LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 0u);
        LOGVOLE_REQUIRE_TRUE(telemetry.mPeakTaskThreads.load() <= allowance);
        if (!executor && allowance == 1) LOGVOLE_REQUIRE_TRUE(scratch.executor() == nullptr);
        else if (!executor) { executor = scratch.executor(); LOGVOLE_REQUIRE_TRUE(executor); }
        else LOGVOLE_REQUIRE_TRUE(scratch.executor() == executor);
    }
    telemetry.mWorkerLimit = 1;
    telemetry.reset();
    LOGVOLE_REQUIRE_TRUE(scratch.runBulk(7, 8, [](std::size_t) { return true; }, benchmark));
    LOGVOLE_REQUIRE_EQ(telemetry.mPeakTaskThreads.load(), 1u);
    LOGVOLE_REQUIRE_TRUE(scratch.executor() == executor);
    telemetry.mWorkerLimit = 3;
    struct Failure {};
    for (unsigned failure : {0u, 1u, 2u, 3u}) // caller/child throw, caller/child false
    {
        std::atomic<bool> childStarted{false}, releaseChild{false}, childCleaned{false};
        bool propagated = false, ok = true;
        try
        {
            ok = scratch.runBulk(2, 2, [&](std::size_t i) -> bool {
                if (i == 1)
                {
                    struct Cleanup {
                        std::atomic<bool>& flag;
                        ~Cleanup() { flag.store(true, std::memory_order_release); }
                    } cleanup{childCleaned};
                    childStarted.store(true, std::memory_order_release);
                    childStarted.notify_all();
                    releaseChild.wait(false, std::memory_order_acquire);
                    if (failure == 1) throw Failure{};
                    return failure != 3;
                }
                childStarted.wait(false, std::memory_order_acquire);
                releaseChild.store(true, std::memory_order_release);
                releaseChild.notify_all();
                if (failure == 0) throw Failure{};
                return failure != 2;
            }, benchmark);
        }
        catch (const Failure&) { propagated = true; }
        LOGVOLE_REQUIRE_TRUE(childCleaned.load(std::memory_order_acquire));
        LOGVOLE_REQUIRE_EQ(propagated, failure < 2);
        if (failure >= 2) LOGVOLE_REQUIRE_FALSE(ok);
        LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 0u);
        LOGVOLE_REQUIRE_TRUE(scratch.runBulk(2, 2, [](std::size_t) { return true; }, benchmark));
    }

    RingParams params{};
    params.mPolyModulusDegree = 1024;
    assignValues<int>(params.mCoeffModulusBits, {30, 30});
    RingNttContext ctx;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
    const auto equalBatch = [](const auto& a, const auto& b) {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(a[i].mCoeffs, b[i].mCoeffs));
    };
    PRNG random(toBlock(723, 1));
    std::array<seal::prng_seed_type, 5> seeds;
    for (auto& seed : seeds) random.get(seed.data(), seed.size());
    std::array<u8, 5> active{1, 0, 1, 1, 1};
    std::vector<u64> expectedNoise(5 * 1024, 0);
    for (std::size_t i = 0; i < seeds.size(); ++i)
        if (active[i]) LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
            std::span<u64>(expectedNoise).subspan(i * 1024, 1024), 3.2, 19.2, seeds[i], ctx));
    std::vector<RnsPoly> inputs{sampleUniformPoly(ctx, random), sampleUniformPoly(ctx, random)};
    LogVoleGpuSetupOptions serialOptions, parallelOptions;
    serialOptions.mParallelLenc = serialOptions.mParallelLhe = LogVoleChoice::Disabled;
    parallelOptions.mParallelLenc = parallelOptions.mParallelLhe = LogVoleChoice::Enabled;
    serialOptions.mLencDevice = serialOptions.mLheDevice = false;
    parallelOptions.mLencDevice = parallelOptions.mLheDevice = false;
    PRNG referencePrng(toBlock(723, 2), 3);
    LencEncodeOutput reference;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, inputs, 1, 30, 29, referencePrng,
        reference, 3.2, 19.2, 2, true, false, nullptr, 1, false, false,
        nullptr, nullptr, serialOptions)));
    RingTensor referenceLhe;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheEnc1Trunc(setupResources.executor, setupResources.results, ctx, reference.mRNtt, inputs, 30, referenceLhe,
        3.2, 19.2, &referencePrng, true, nullptr, 1, nullptr, {}, nullptr, nullptr,
        nullptr, nullptr, 0, false, serialOptions)));
    const auto expectedNext = referencePrng.get<block>();
    PRNG rejectedLencPrng(toBlock(723, 12)), savedLencPrng(toBlock(723, 12));
    LencEncodeOutput rejectedLenc;
    rejectedLenc.mLacct.mCt.mRows = 777;
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lencEncTrunc(setupResources.executor,
        std::span(setupResources.results).first(1), ctx, inputs, 1, 30, 29, rejectedLencPrng,
        rejectedLenc, 3.2, 19.2, 2, true, false, nullptr, 3, false, false,
        nullptr, nullptr, parallelOptions, benchmark)));
    LOGVOLE_REQUIRE_EQ(rejectedLenc.mLacct.mCt.mRows, 777u);
    LOGVOLE_REQUIRE_TRUE(rejectedLencPrng.get<block>() == savedLencPrng.get<block>());
    PRNG rejectedLhePrng(toBlock(723, 13)), savedLhePrng(toBlock(723, 13));
    RingTensor rejectedLhe;
    rejectedLhe.mRows = 777;
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lheEnc1Trunc(setupResources.executor,
        std::span(setupResources.results).first(1), ctx, reference.mRNtt, inputs, 30, rejectedLhe,
        3.2, 19.2, &rejectedLhePrng, true, nullptr, 3, nullptr, {}, nullptr, nullptr,
        nullptr, nullptr, 0, false, parallelOptions, benchmark)));
    LOGVOLE_REQUIRE_EQ(rejectedLhe.mRows, 777u);
    LOGVOLE_REQUIRE_TRUE(rejectedLhePrng.get<block>() == savedLhePrng.get<block>());
    std::array<block, 6> zetaSeeds;
    random.get(zetaSeeds.data(), zetaSeeds.size());
    std::array<RootZetaBuffer, 3> zetaBuffers;
    std::array<const u64*, 3> wordStorage;
    std::array<const block*, 3> prngStorage;
    for (std::size_t i = 0; i != zetaBuffers.size(); ++i)
    {
        zetaBuffers[i].mWords.resize(16);
        zetaBuffers[i].mPrng.SetSeed(ZeroBlock);
        wordStorage[i] = zetaBuffers[i].mWords.data();
        prngStorage[i] = zetaBuffers[i].mPrng.mBuffer.data();
    }
    std::vector<RnsPoly> referenceZeta;
    // Explicit compatibility reference preserves the independent seed-replay
    // orchestration; its serial allowance creates no worker pool.
    LOGVOLE_REQUIRE_TRUE(LogVole::detail::gpuLegacySampleRootZetaFromTaskSeeds(
        ctx, 2, 65, zetaSeeds, 3, referenceZeta, 1, true));
    RingOpsStats setupOwners[2];
    for (u32 allowance : {1u, 3u, 2u, 1u})
    {
        std::vector<RnsPoly> zeta;
        // Diagnostics cannot reduce the independent CPU setup task count.
        telemetry.mWorkerLimit = 1;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(sampleRootZetaFromTaskSeeds(setupResources.executor,
            std::span(zetaBuffers).first(allowance), ctx, 2, 65, zetaSeeds, 3,
            zeta, allowance, true, benchmark)));
        equalBatch(zeta, referenceZeta);
        std::vector<u64> noise;
        std::shared_ptr<gpu::DeviceScalars> device;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results, noise, device,
            3.2, 19.2, seeds, ctx, allowance, active, benchmark)));
        LOGVOLE_REQUIRE_TRUE(noise == expectedNoise && !device);
        // Force the independent seed-replay path by supplying no host data.
        noise.clear();
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(materializePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results, noise, device,
            3.2, 19.2, seeds, ctx, allowance, active, benchmark)));
        LOGVOLE_REQUIRE_TRUE(noise == expectedNoise);
        const auto selection = allowance == 2 ? 2u : allowance == 3 ? 1u : 0u;
        ctx.mExecutionOptions.mRingOpsStats = selection < 2 ? &setupOwners[selection] : nullptr;
        if (selection < 2) setupOwners[selection].reset();
        const auto firstCount = setupOwners[0].mErrorAddCount.load();
        const auto secondCount = setupOwners[1].mErrorAddCount.load();
        PRNG actualPrng(toBlock(723, 2), 3);
        LencEncodeOutput actual;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(lencEncTrunc(setupResources.executor, setupResources.results, ctx, inputs, 1, 30, 29, actualPrng,
            actual, 3.2, 19.2, 2, true, false, nullptr, allowance, false, false,
            nullptr, nullptr, parallelOptions, benchmark))));
        equalBatch(actual.mRNtt, reference.mRNtt);
        equalBatch(actual.mR, reference.mR);
        equalBatch(actual.mLacct.mCt.mPolys, reference.mLacct.mCt.mPolys);
        RingTensor actualLhe;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(lheEnc1Trunc(setupResources.executor, setupResources.results, ctx, actual.mRNtt, inputs, 30, actualLhe,
            3.2, 19.2, &actualPrng, true, nullptr, allowance, nullptr, {}, nullptr, nullptr,
            nullptr, nullptr, 0, false, parallelOptions, benchmark))));
        equalBatch(actualLhe.mPolys, referenceLhe.mPolys);
        LOGVOLE_REQUIRE_TRUE(actualPrng.get<block>() == expectedNext);
        if (selection < 2)
        {
            // Two randomizer rows, four LENC cells and four LHE cells.
            LOGVOLE_REQUIRE_EQ(setupOwners[selection].mDyadicMulAddCount.load(), 8u);
            LOGVOLE_REQUIRE_EQ(setupOwners[selection].mErrorAddCount.load(), 10u);
            LOGVOLE_REQUIRE_EQ(setupOwners[selection].mNttCount.load(), 10u);
            LOGVOLE_REQUIRE_EQ(setupOwners[selection].mInttCount.load(), 6u);
            LOGVOLE_REQUIRE_EQ(setupOwners[selection].mPrngPolyCount.load(), 0u); // Public cache hits.
        }
        if (selection != 0) LOGVOLE_REQUIRE_EQ(setupOwners[0].mErrorAddCount.load(), firstCount);
        if (selection != 1) LOGVOLE_REQUIRE_EQ(setupOwners[1].mErrorAddCount.load(), secondCount);
        LOGVOLE_REQUIRE_TRUE(scratch.executor() == executor);
    }
    ctx.mExecutionOptions.mRingOpsStats = nullptr;
    PRNG rootReferencePrng(toBlock(723, 44));
    std::vector<RnsPoly> rootReference;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(sampleRootErrorBatch(
        setupResources.executor, setupResources.results, ctx, 2, rootReferencePrng,
        3.2, 19.2, true, rootReference))));
    const auto rootNext = rootReferencePrng.get<block>();
    for (auto* sink : {&setupOwners[0], static_cast<RingOpsStats*>(nullptr)})
    {
        ctx.mExecutionOptions.mRingOpsStats = sink;
        if (sink) sink->reset();
        PRNG rootPrng(toBlock(723, 44));
        std::vector<RnsPoly> rootActual;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(sampleRootErrorBatch(
            setupResources.executor, setupResources.results, ctx, 2, rootPrng,
            3.2, 19.2, true, rootActual))));
        equalBatch(rootActual, rootReference);
        LOGVOLE_REQUIRE_TRUE(rootPrng.get<block>() == rootNext);
        if (sink)
        {
            LOGVOLE_REQUIRE_EQ(sink->mNttCount.load(), 2u);
            LOGVOLE_REQUIRE_EQ(sink->mErrorAddCount.load(), 2u);
        }
    }
    ctx.mExecutionOptions.mRingOpsStats = nullptr;

    // Start the controller on the same single worker that executes its chunks.
    // Cache misses count actual generation; hits reuse the same immutable data.
    for (auto* sink : {&setupOwners[0], static_cast<RingOpsStats*>(nullptr)})
    {
        LogVoleExecutionOptions options;
        options.mRingOpsStats = sink;
        RingNttContext cacheContext;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, cacheContext,
            std::make_shared<RingContextFactory>(options)));
        if (sink) sink->reset();
        {
            PendingRingOpsStats pending(sink);
            auto* stats = sink ? &pending : nullptr;
            const auto a = sharedLhePublicANtt(cacheContext, 2, {}, stats);
            const auto b = sharedLencPublicBNtt(cacheContext, 2, {}, stats);
            LOGVOLE_REQUIRE_TRUE(a && b);
            pending.flush();
            if (sink)
            {
                LOGVOLE_REQUIRE_EQ(sink->mPrngPolyCount.load(), 6u);
                LOGVOLE_REQUIRE_EQ(sink->mNttCount.load(), 4u);
            }
            LOGVOLE_REQUIRE_TRUE(a == sharedLhePublicANtt(cacheContext, 2, {}, stats));
            LOGVOLE_REQUIRE_TRUE(b == sharedLencPublicBNtt(cacheContext, 2, {}, stats));
        }
        if (sink)
        {
            LOGVOLE_REQUIRE_EQ(sink->mPrngPolyCount.load(), 6u);
            LOGVOLE_REQUIRE_EQ(sink->mNttCount.load(), 4u);
        }
    }

    // Start the controller on the same single worker that executes its chunks.
    // Task creation is lazy and neither changes outputs nor borrows TLS state
    // from the thread that eventually resumes it.
    std::vector<u64> lazyNoise{123};
    std::shared_ptr<gpu::DeviceScalars> lazyDevice;
    std::fill(setupResources.results.begin(), setupResources.results.end(), u8{0xA5});
    macoro::task<bool> pending;
    {
        pending = samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
            lazyNoise, lazyDevice, 3.2, 19.2, seeds, ctx, 3, active, benchmark);
    }
    LOGVOLE_REQUIRE_TRUE(lazyNoise == std::vector<u64>{123});
    for (auto status : setupResources.results) LOGVOLE_REQUIRE_EQ(status, u8{0xA5});
    // Setup kernels capture their explicit phase before lazy start. Cache
    // selection and arithmetic must agree when a worker resumes the task.
    const ProtocolCacheScope phase(ctx.mFactory->protocolService()->allocate(), ProtocolCacheRole::Sender);
    PRNG phaseReferencePrng(toBlock(813, 1)), phaseActualPrng(toBlock(813, 1));
    LencEncodeOutput phaseReference, phaseActual;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results,
        ctx, inputs, 1, 30, 29, phaseReferencePrng, phaseReference, 0, 0, 2, true, false,
        nullptr, 3, false, false, nullptr, nullptr, parallelOptions, benchmark, phase)));
    macoro::task<bool> pendingLenc;
    {
        pendingLenc = lencEncTrunc(setupResources.executor, setupResources.results,
            ctx, inputs, 1, 30, 29, phaseActualPrng, phaseActual, 0, 0, 2, true, false,
            nullptr, 3, false, false, nullptr, nullptr, parallelOptions, benchmark, phase);
    }
    {
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(pendingLenc))));
    }
    equalBatch(phaseActual.mRNtt, phaseReference.mRNtt);
    equalBatch(phaseActual.mLacct.mCt.mPolys, phaseReference.mLacct.mCt.mPolys);
    LOGVOLE_REQUIRE_TRUE(phaseActualPrng.get<block>() == phaseReferencePrng.get<block>());
    RingTensor phaseReferenceLhe, phaseActualLhe;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheEnc1Trunc(setupResources.executor, setupResources.results,
        ctx, phaseReference.mRNtt, inputs, 30, phaseReferenceLhe, 0, 0, nullptr, true, nullptr,
        3, nullptr, {}, nullptr, nullptr, nullptr, nullptr, 0, false, parallelOptions, benchmark, phase)));
    macoro::task<bool> pendingLhe;
    {
        pendingLhe = lheEnc1Trunc(setupResources.executor, setupResources.results,
            ctx, phaseActual.mRNtt, inputs, 30, phaseActualLhe, 0, 0, nullptr, true, nullptr,
            3, nullptr, {}, nullptr, nullptr, nullptr, nullptr, 0, false, parallelOptions, benchmark, phase);
    }
    {
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(pendingLhe))));
    }
    equalBatch(phaseActualLhe.mPolys, phaseReferenceLhe.mPolys);
    ShrinkExpandSenderOfflineInput shrinkInput;
    shrinkInput.mRingFactoryOwner = ctx.mFactoryOwner;
    shrinkInput.mS = inputs;
    shrinkInput.mParams.mRing = params;
    shrinkInput.mParams.mAlpha = 1;
    shrinkInput.mParams.mMu = 2;
    shrinkInput.mParams.mTau = 1;
    shrinkInput.mParams.mGadgetLogBase = 30;
    shrinkInput.mParams.mPlaintextModulusBits = 29;
    shrinkInput.mParams.mTruncateOneGadgetDigit = true;
    shrinkInput.mParams.mNumWorkerThreads = 3;
    shrinkInput.mParams.mGpuSetup = parallelOptions;
    PRNG shrinkReferencePrng(toBlock(814, 1)), shrinkActualPrng(toBlock(814, 1));
    ShrinkExpandSenderState shrinkReference, shrinkActual;
    ShrinkExpandOfflineMessage shrinkMessage;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(prepareShrinkExpandSenderOffline(
        setupResources.executor, setupResources.results, shrinkInput, shrinkReferencePrng,
        shrinkMessage, shrinkReference, benchmark, phase)));
    macoro::task<bool> pendingShrink;
    shrinkActual.mCt1.mRows = 777;
    {
        pendingShrink = prepareShrinkExpandSenderOffline(setupResources.executor,
            setupResources.results, shrinkInput, shrinkActualPrng, shrinkActual, benchmark, phase);
    }
    LOGVOLE_REQUIRE_EQ(shrinkActual.mCt1.mRows, 777u);
    {
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(pendingShrink))));
    }
    equalBatch(shrinkActual.mSk1, shrinkReference.mSk1);
    equalBatch(shrinkActual.mR, shrinkReference.mR);
    equalBatch(shrinkActual.mCt1.mPolys, shrinkReference.mCt1.mPolys);
    equalBatch(shrinkActual.mLacct.mCt.mPolys, shrinkReference.mLacct.mCt.mPolys);
    LOGVOLE_REQUIRE_TRUE(shrinkActualPrng.get<block>() == shrinkReferencePrng.get<block>());
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(pending))));
    LOGVOLE_REQUIRE_TRUE(lazyNoise == expectedNoise && !lazyDevice);
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(onPool(samplePolyErrorCompactBatchForSetup(
        setupResources.executor, setupResources.results, lazyNoise, lazyDevice,
        3.2, 19.2, seeds, ctx, 3, std::span<const u8>(active).first(1), benchmark))));
    LOGVOLE_REQUIRE_TRUE(lazyNoise == expectedNoise && !lazyDevice);

    telemetry.mWorkerLimit = 1;
    telemetry.reset();
    std::fill(setupResources.results.begin(), setupResources.results.end(), u8{0xA5});
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(
        setupResources.executor, setupResources.results, lazyNoise,
        3.2, 19.2, seeds, ctx, 3, active, benchmark)));
    LOGVOLE_REQUIRE_TRUE(lazyNoise == expectedNoise);
    LOGVOLE_REQUIRE_EQ(telemetry.mPeakTaskThreads.load(), 1u);
    LOGVOLE_REQUIRE_EQ(setupResources.results[1], u8{1});
    LOGVOLE_REQUIRE_EQ(setupResources.results[2], u8{1});
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(
        setupResources.executor, std::span(setupResources.results).first(1), lazyNoise,
        3.2, 19.2, seeds, ctx, 3, active, benchmark)));
    LOGVOLE_REQUIRE_TRUE(lazyNoise == expectedNoise);
    std::vector<u64> rejectedNoise{123};
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(
        setupResources.executor, std::span(setupResources.results).first(1), rejectedNoise, lazyDevice,
        3.2, 19.2, seeds, ctx, 3, active, benchmark)));
    LOGVOLE_REQUIRE_TRUE(rejectedNoise == std::vector<u64>{123});
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(materializePolyErrorCompactBatchForSetup(
        setupResources.executor, std::span(setupResources.results).first(1), rejectedNoise, lazyDevice,
        3.2, 19.2, seeds, ctx, 3, active, benchmark)));
    LOGVOLE_REQUIRE_TRUE(rejectedNoise == std::vector<u64>{123});

    PRNG untouched(toBlock(723, 99)), rejected(toBlock(723, 99));
    std::vector<RnsPoly> unpublished;
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(sampleRootErrorBatch(
        setupResources.executor, {}, ctx, 2, rejected, 3.2, 19.2, false, unpublished)));
    LOGVOLE_REQUIRE_TRUE(unpublished.empty());
    LOGVOLE_REQUIRE_TRUE(untouched.get<block>() == rejected.get<block>());

    // Zeta ranges keep their seed layout when the execution allowance changes.
    // Run the controller and every chunk on one thread; storage is reused across
    // widths, rejection, and queries rather than allocated for each range.
    telemetry.mWorkerLimit = 3;
    for (u32 bits : {1u, 63u, 65u, 127u, 208u})
    for (bool forceReject : {false, true})
    {
        std::vector<RnsPoly> expected, actual;
        LOGVOLE_REQUIRE_TRUE(LogVole::detail::gpuLegacySampleRootZetaFromTaskSeeds(
            ctx, 2, bits, zetaSeeds, 3, expected, 1, forceReject));
        for (std::size_t allowance : {1u, 3u, 2u})
        {
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(sampleRootZetaFromTaskSeeds(
                setupResources.executor, std::span(zetaBuffers).first(allowance), ctx,
                2, bits, zetaSeeds, 3, actual, static_cast<u32>(allowance), forceReject, benchmark))));
            equalBatch(actual, expected);
        }
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(sampleRootZetaFromTaskSeeds(
            setupResources.executor, std::span(zetaBuffers).first(1), ctx,
            2, bits, zetaSeeds, 3, actual, 3, forceReject, benchmark)));
        equalBatch(actual, expected);
        for (std::size_t i = 0; i != zetaBuffers.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(zetaBuffers[i].mWords.data() == wordStorage[i]);
            LOGVOLE_REQUIRE_TRUE(zetaBuffers[i].mPrng.mBuffer.data() == prngStorage[i]);
        }
    }
    for (u32 ranges : {0u, 1u, 3u})
    {
        PRNG expectedPrng(toBlock(723, 101)), actualPrng(toBlock(723, 101));
        std::vector<RnsPoly> expected, actual;
        if (ranges > 1)
        {
            // Parent draws are fixed by the protocol's [poly][range] layout,
            // independently of the async sampler's execution allowance.
            std::vector<block> replaySeeds(2 * ranges);
            expectedPrng.get(replaySeeds.data(), replaySeeds.size());
            LOGVOLE_REQUIRE_TRUE(LogVole::detail::gpuLegacySampleRootZetaFromTaskSeeds(
                ctx, 2, 208, replaySeeds, ranges, expected, 1));
        }
        else
            LOGVOLE_REQUIRE_TRUE(LogVole::detail::gpuLegacySampleRootZeta(
                ctx, 2, 208, expectedPrng, expected, 1));
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(sampleRootZeta(
            setupResources.executor, std::span(zetaBuffers).first(std::max(1u, ranges)), ctx,
            2, 208, actualPrng, actual, ranges, benchmark))));
        equalBatch(actual, expected);
        LOGVOLE_REQUIRE_TRUE(expectedPrng.get<block>() == actualPrng.get<block>());
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(sampleRootZetaFromTaskSeeds(
            setupResources.executor, zetaBuffers, ctx, 2, 208,
            std::span(zetaSeeds).first(1), 3, actual, 3)));
        equalBatch(actual, expected);
    }
    PRNG lazyZetaPrng(toBlock(723, 102)), lazyZetaReference(toBlock(723, 102));
    std::vector<RnsPoly> lazyZeta;
    auto zetaOperation = sampleRootZeta(setupResources.executor, zetaBuffers,
        ctx, 2, 208, lazyZetaPrng, lazyZeta, 3);
    LOGVOLE_REQUIRE_TRUE(lazyZeta.empty());
    LOGVOLE_REQUIRE_TRUE(lazyZetaPrng.get<block>() == lazyZetaReference.get<block>());
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(zetaOperation))));
    PRNG emptyActual(toBlock(723, 103)), emptyExpected(toBlock(723, 103));
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(sampleRootZeta(setupResources.executor,
        {}, ctx, 2, 208, emptyActual, lazyZeta, 3)));
    LOGVOLE_REQUIRE_TRUE(emptyActual.get<block>() == emptyExpected.get<block>());
    PRNG shortActual(toBlock(723, 104)), shortExpected(toBlock(723, 104));
    const auto savedZeta = lazyZeta;
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(sampleRootZeta(setupResources.executor,
        std::span(zetaBuffers).first(1), ctx, 2, 208, shortActual, lazyZeta, 3)));
    LOGVOLE_REQUIRE_TRUE(shortActual.get<block>() == shortExpected.get<block>());
    equalBatch(lazyZeta, savedZeta);
    telemetry.mWorkerLimit = 1;
    telemetry.reset();
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(sampleRootZetaFromTaskSeeds(
        setupResources.executor, zetaBuffers, ctx, 2, 208,
        zetaSeeds, 3, lazyZeta, 3, false, benchmark))));
    LOGVOLE_REQUIRE_EQ(telemetry.mPeakTaskThreads.load(), 1u);
}

void LogVole_Cpu_PreparedExecutionLifetime(const oc::CLP&)
{
    macoro::thread_pool proofExecutor;
    auto proofWork = proofExecutor.make_work();
    proofExecutor.create_threads(1);
    struct Failure {};
    LogVole::detail::CpuExecutor executor(2);
    std::array<std::thread::id, 2> threads;
    std::array<std::size_t, 2> counts{};
    for (unsigned phase = 0; phase < 3; ++phase)
    {
        LOGVOLE_REQUIRE_TRUE(executor.run(2, [&](std::size_t worker, std::size_t task) {
            LOGVOLE_REQUIRE_EQ(worker, task);
            if (phase == 0) threads[worker] = std::this_thread::get_id();
            else LOGVOLE_REQUIRE_TRUE(threads[worker] == std::this_thread::get_id());
            ++counts[worker];
            return true;
        }));
    }
    LOGVOLE_REQUIRE_TRUE(threads[0] != threads[1]);
    LOGVOLE_REQUIRE_EQ(counts[0], 3u);
    LOGVOLE_REQUIRE_EQ(counts[1], 3u);
    for (bool dynamic : {false, true})
    {
        std::array<unsigned, 19> visits{};
        LOGVOLE_REQUIRE_TRUE(executor.run(visits.size(), [&](std::size_t worker, std::size_t task) {
            LOGVOLE_REQUIRE_TRUE(worker < counts.size());
            ++counts[worker];
            ++visits[task];
            return true;
        }, dynamic));
        for (auto visitsToTask : visits) LOGVOLE_REQUIRE_EQ(visitsToTask, 1u);
    }
    for (unsigned failure : {0u, 1u, 2u}) // caller throw, child throw, caller false
    {
        std::atomic<bool> childStarted{false}, childFinished{false};
        bool propagated = false, completed = true;
        try
        {
            completed = executor.run(2, [&](std::size_t worker, std::size_t) -> bool {
                if (worker == 1)
                {
                    childStarted.store(true, std::memory_order_release);
                    childStarted.notify_all();
                    if (failure != 1) std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    childFinished.store(true, std::memory_order_release);
                    if (failure == 1) throw Failure{};
                    return true;
                }
                childStarted.wait(false, std::memory_order_acquire);
                if (failure == 0) throw Failure{};
                return failure != 2;
            });
        }
        catch (const Failure&) { propagated = true; }
        LOGVOLE_REQUIRE_TRUE(childFinished.load(std::memory_order_acquire));
        LOGVOLE_REQUIRE_EQ(propagated, failure != 2);
        if (failure == 2) LOGVOLE_REQUIRE_FALSE(completed);
        LOGVOLE_REQUIRE_TRUE(executor.run(2, [](std::size_t, std::size_t) { return true; }));
    }
    bool nestedRejected = false;
    LOGVOLE_REQUIRE_TRUE(executor.run(1, [&](std::size_t, std::size_t) {
        try { executor.run(1, [](std::size_t, std::size_t) { return true; }); }
        catch (const std::logic_error&) { nestedRejected = true; }
        return true;
    }));
    LOGVOLE_REQUIRE_TRUE(nestedRejected);
    LOGVOLE_REQUIRE_TRUE(executor.run(0, [](std::size_t, std::size_t) { return false; }));

    // Pilot bulk path: explicit reusable locals, caller participation, exact
    // coverage, and synchronous cleanup even when either partition throws.
    std::array<std::size_t, 2> bulkLocals{};
    const auto caller = std::this_thread::get_id();
    for (std::size_t count : {0u, 1u, 3u, 19u})
    {
        bulkLocals.fill(0);
        std::array<unsigned, 19> visits{};
        executor.runBulk(count, std::span{bulkLocals}, [&](std::size_t i, std::size_t& local) {
            LOGVOLE_REQUIRE_TRUE((std::this_thread::get_id() == caller) == (&local == &bulkLocals[0]));
            ++local;
            ++visits[i];
        });
        LOGVOLE_REQUIRE_EQ(bulkLocals[0], (count + 1) / 2);
        LOGVOLE_REQUIRE_EQ(bulkLocals[1], count / 2);
        for (std::size_t i = 0; i < visits.size(); ++i)
            LOGVOLE_REQUIRE_EQ(visits[i], i < count ? 1u : 0u);
    }
    for (bool callerThrows : {false, true})
    {
        std::atomic<bool> childStarted{false}, releaseChild{false}, childFinished{false};
        bool propagated = false;
        try
        {
            executor.runBulk(2, std::span{bulkLocals}, [&](std::size_t i, std::size_t&) {
                if (i == 1)
                {
                    struct Finish
                    {
                        std::atomic<bool>& flag;
                        ~Finish() { flag.store(true, std::memory_order_release); }
                    } finish{childFinished};
                    childStarted.store(true, std::memory_order_release);
                    childStarted.notify_all();
                    releaseChild.wait(false, std::memory_order_acquire);
                    if (!callerThrows) throw Failure{};
                }
                else
                {
                    childStarted.wait(false, std::memory_order_acquire);
                    releaseChild.store(true, std::memory_order_release);
                    releaseChild.notify_all();
                    if (callerThrows) throw Failure{};
                }
            });
        }
        catch (const Failure&) { propagated = true; }
        LOGVOLE_REQUIRE_TRUE(propagated && childFinished.load(std::memory_order_acquire));
        executor.runBulk(2, std::span{bulkLocals}, [](std::size_t, std::size_t& local) { ++local; });
    }
    nestedRejected = false;
    executor.runBulk(1, std::span{bulkLocals}, [&](std::size_t, std::size_t&) {
        try { executor.run(1, [](std::size_t, std::size_t) { return true; }); }
        catch (const std::logic_error&) { nestedRejected = true; }
    });
    LOGVOLE_REQUIRE_TRUE(nestedRejected);

    ZkMulCircuit circuit;
    LOGVOLE_REQUIRE_TRUE(makeZkMulCircuit(51, 3, toBlock(0x50524550, 1), circuit));
    ZkMulCpuWorkspace serial(circuit, 1), parallel(circuit, 3), automatic(circuit, 0);
    LOGVOLE_REQUIRE_TRUE(serial.prepared() && parallel.prepared());
    LOGVOLE_REQUIRE_EQ(serial.workers(), 1u);
    LOGVOLE_REQUIRE_TRUE(automatic.workers() >= 1);
    LOGVOLE_REQUIRE_EQ(automatic.workers(), 1u);
    CpuBenchmarkContext partition;
    partition.mCpus = {0};
    partition.mWorkerLimit = 1;
    ZkMulCpuWorkspace limited(circuit, 0, &partition);
    LOGVOLE_REQUIRE_EQ(limited.workers(), 1u);
    // Diagnostics do not reduce the explicit logical task count.
    ZkMulCpuWorkspace limitedChunks(circuit, 3, &partition);
    LOGVOLE_REQUIRE_EQ(limitedChunks.workers(), 3u);
    PRNG random(toBlock(0x50524550, 2));
    macoro::thread_pool witnessExecutor;
    constexpr u64 q = 65537, delta = 19;
    const seal::Modulus mod(q);
    AlignedUnVec<u64> wires;
    std::vector<u64> macs(circuit.voleCount()), keys(circuit.voleCount());
    for (unsigned query = 0; query < 4; ++query)
    {
        // Alternate witness ranges and proof accumulators in the same workspace.
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulWitness(
            witnessExecutor, circuit, q, random, wires, 0, serial)));
        for (std::size_t i = 0; i < macs.size(); ++i)
        {
            macs[i] = random.get<u64>() % q;
            keys[i] = (macs[i] + q - mulMod(wires[i], delta, mod)) % q;
        }
        const u64 chi = query == 0 ? 0 : random.get<u64>();
        ZkProof expected, actual;
        u64 expectedValue = 0, actualValue = 0;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, chi, q, serial, expected)));
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, chi, q, limitedChunks, actual)));
        LOGVOLE_REQUIRE_EQ(actual.mU, expected.mU);
        LOGVOLE_REQUIRE_EQ(actual.mV, expected.mV);
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(proofExecutor, circuit, keys, chi, delta, q, serial, expectedValue)));
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, chi, q, parallel, actual)));
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(proofExecutor, circuit, keys, chi, delta, q, parallel, actualValue)));
        LOGVOLE_REQUIRE_EQ(actual.mU, expected.mU);
        LOGVOLE_REQUIRE_EQ(actual.mV, expected.mV);
        LOGVOLE_REQUIRE_EQ(actualValue, expectedValue);
        LOGVOLE_REQUIRE_TRUE(zkAccept(actual, actualValue, delta, q));
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, chi, q, automatic, actual)));
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(proofExecutor, circuit, keys, chi, delta, q, automatic, actualValue)));
        LOGVOLE_REQUIRE_EQ(actual.mU, expected.mU);
        LOGVOLE_REQUIRE_EQ(actual.mV, expected.mV);
        LOGVOLE_REQUIRE_EQ(actualValue, expectedValue);
    }
    // A workspace does not freeze its caller-owned circuit. Revalidate every
    // direct boundary before touching outputs, scheduling, or drawing randomness.
    const auto originalOperand = circuit.mOperands[1];
    for (u32 bad : {static_cast<u32>(circuit.outputWire(0)),
            static_cast<u32>(circuit.maskIndex()), std::numeric_limits<u32>::max()})
    {
        circuit.mOperands[1] = bad;
        ZkProof proof{123, 456};
        u64 value = 789;
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulProverResponse(
            proofExecutor, circuit, wires, macs, 1, q, serial, proof)));
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulVerifierValue(
            proofExecutor, circuit, keys, 1, delta, q, serial, value)));
        LOGVOLE_REQUIRE_FALSE(LogVole::detail::gpuLegacyZkMulProverResponse(
            circuit, wires, macs, 1, q, serial, proof));
        LOGVOLE_REQUIRE_FALSE(LogVole::detail::gpuLegacyZkMulVerifierValue(
            circuit, keys, 1, delta, q, serial, value));
        LOGVOLE_REQUIRE_EQ(proof.mU, 123u);
        LOGVOLE_REQUIRE_EQ(proof.mV, 456u);
        LOGVOLE_REQUIRE_EQ(value, 789u);
        PRNG rejected(toBlock(123)), saved(toBlock(123));
        const std::vector<u64> savedWires(wires.begin(), wires.end());
        LOGVOLE_REQUIRE_FALSE(zkMulWitness(circuit, q, rejected, wires));
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulWitness(
            witnessExecutor, circuit, q, rejected, wires, 0, serial)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, savedWires));
        LOGVOLE_REQUIRE_TRUE(rejected.get<block>() == saved.get<block>());
        bool rejectedWorkspace = false;
        try { ZkMulCpuWorkspace invalid(circuit, 1); }
        catch (const std::invalid_argument&) { rejectedWorkspace = true; }
        LOGVOLE_REQUIRE_TRUE(rejectedWorkspace);
    }
    circuit.mOperands[1] = originalOperand;
    // Overflow-adjacent depths must fail without dividing by a wrapped zero.
    ZkMulCircuit budgetCircuit;
    constexpr auto max = std::numeric_limits<u64>::max();
    LOGVOLE_REQUIRE_FALSE(makeZkMulCircuit(max, max, ZeroBlock, budgetCircuit));
    LOGVOLE_REQUIRE_FALSE(makeZkMulCircuitForBudget(max, max, ZeroBlock, budgetCircuit));
    LOGVOLE_REQUIRE_FALSE(makeZkMulCircuitForBudget(max, max - 1, ZeroBlock, budgetCircuit));
    LOGVOLE_REQUIRE_FALSE(makeZkMulCircuitForBudget(max, max - 2, ZeroBlock, budgetCircuit));
    LOGVOLE_REQUIRE_TRUE(makeZkMulCircuitForBudget(7, 2, ZeroBlock, budgetCircuit));
    LOGVOLE_REQUIRE_EQ(budgetCircuit.mWidth, 2u);
    LOGVOLE_REQUIRE_EQ(budgetCircuit.voleCount(), 7u);
    // Move only while quiescent: the stable heap owner retains pool and scratch.
    ZkMulCpuWorkspace moved(std::move(parallel));
    LOGVOLE_REQUIRE_TRUE(moved.prepared());
    LOGVOLE_REQUIRE_FALSE(parallel.prepared());
    LOGVOLE_REQUIRE_EQ(parallel.workers(), 0u);
    ZkProof untouched{123, 456};
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, 1, q, parallel, untouched)));
    ZkMulCircuit wrongGeometry = circuit;
    ++wrongGeometry.mDepth;
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulProverResponse(proofExecutor, wrongGeometry, wires, macs, 1, q, moved, untouched)));
    LOGVOLE_REQUIRE_EQ(untouched.mU, 123u);
    LOGVOLE_REQUIRE_EQ(untouched.mV, 456u);
    PRNG rejectedRandom(toBlock(0x574954, 1)), untouchedRandom(toBlock(0x574954, 1));
    const std::vector<u64> savedWires(wires.begin(), wires.end());
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulWitness(
        witnessExecutor, circuit, q, rejectedRandom, wires, 0, parallel)));
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulWitness(
        witnessExecutor, wrongGeometry, q, rejectedRandom, wires, 0, moved)));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, savedWires));
    LOGVOLE_REQUIRE_TRUE(rejectedRandom.get<block>() == untouchedRandom.get<block>());
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, 1, q, moved, untouched)));
    bool invalidRejected = false;
    try { ZkMulCpuWorkspace invalid(ZkMulCircuit{}, 2); }
    catch (const std::invalid_argument&) { invalidRejected = true; }
    LOGVOLE_REQUIRE_TRUE(invalidRejected);
}

void LogVole_Cpu_FusedExpandEvalMatchesSeparateOperations(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    PRNG random(toBlock(0x4556414c, 0x46555345));
    macoro::thread_pool pool;
    auto work = pool.make_work();
    pool.create_threads(1);
    std::array<LencEvalBuffer, 3> buffers;
    auto onWorker = [](macoro::thread_pool& executor, macoro::task<bool> operation) -> macoro::task<bool> {
        co_await executor.schedule();
        const auto ok = co_await std::move(operation);
        co_return ok;
    };
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    for (unsigned mu : {3, 9})
    for (bool gadget : {false, true})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const unsigned digitBits = limbs*bits/2, plaintextBits = bits-1;
        std::vector<RnsPoly> keys(mu), inputs(mu), initial(mu);
        for (unsigned row = 0; row < mu; ++row)
        {
            keys[row] = sampleUniformPoly(ctx, random);
            inputs[row] = sampleUniformPoly(ctx, random);
            initial[row] = sampleUniformPoly(ctx, random);
            if (gadget)
                for (unsigned j = 0; j < limbs; ++j)
                    if (j != row%limbs)
                        std::fill_n(inputs[row].mCoeffs.data()+j*1024, 1024, u64{0});
        }
        LencEncodeOutput enc{};
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, keys, 1, digitBits, plaintextBits,
            random, enc, 0, 0, 0, false, gadget)));
        DigestTree tree{};
        LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, inputs, 1, digitBits, plaintextBits,
            tree, enc.mLacct.mWidthPadded, gadget));
        // Independent scalar modular path sum: no batched evaluator or fused
        // product kernel participates in this arithmetic oracle.
        const auto hostModuli = getRingHostModuli(ctx);
        const auto ctTau = enc.mLacct.mCt.mCols / 2;
        std::vector<RnsPoly> eval(mu);
        u64 products = 0;
        for (unsigned leaf = 0; leaf < mu; ++leaf)
        {
            auto& acc = eval[leaf];
            resizeZero(acc.mCoeffs, ringPolyCoeffCount(params));
            unsigned parent = 0;
            for (unsigned level = 0; level < enc.mLacct.mLevels; ++level)
            {
                const unsigned left = 2 * parent + 1, right = left + 1;
                const auto row = level * enc.mLacct.mWidthPadded + leaf;
                const auto terms = tree.mNodeDecompNtt[left].size();
                for (unsigned side = 0; side < 2; ++side)
                for (unsigned digit = 0; digit < terms; ++digit)
                {
                    const auto& ct = enc.mLacct.mCt.mPolys[
                        ringTensorIndex(enc.mLacct.mCt, row, side * ctTau + digit)];
                    const auto& node = tree.mNodeDecompNtt[side ? right : left][digit];
                    for (unsigned j = 0; j < limbs; ++j)
                    for (unsigned k = 0; k < 1024; ++k)
                    {
                        const auto i = j * 1024 + k;
                        const auto& q = hostModuli[j];
                        acc.mCoeffs[i] = seal::util::add_uint_mod(acc.mCoeffs[i],
                            seal::util::multiply_uint_mod(ct.mCoeffs[i], node.mCoeffs[i], q), q);
                    }
                    ++products;
                }
                parent = (leaf >> (enc.mLacct.mLevels - 1 - level)) & 1 ? right : left;
            }
            LOGVOLE_REQUIRE_TRUE(inverseNtt(acc, ctx));
            for (unsigned j = 0; j < limbs; ++j)
            for (unsigned k = 0; k < 1024; ++k)
            {
                auto& value = acc.mCoeffs[j * 1024 + k];
                value = value ? ringModulusValue(ctx, j) - value : 0;
            }
        }
        const auto evalCoefficient = eval;
        LOGVOLE_REQUIRE_TRUE(forwardNttBatch(eval, ctx));
        auto expected = initial;
        for (unsigned row = 0; row < mu; ++row)
            LOGVOLE_REQUIRE_TRUE(ringSubInplace(expected[row], eval[row], ctx));
        const auto capacity = std::size_t{2} * enc.mLacct.mLevels * ctTau;
        std::array<LencEvalBuffer, 8> reusableBuffers;
        for (auto& buffer : reusableBuffers)
        {
            buffer.mCiphertexts.reserve(capacity);
            buffer.mNodes.reserve(capacity);
        }
        RingOpsStats repeatedStats;
        auto repeatedCtx = ctx;
        repeatedCtx.mExecutionOptions.mRingOpsStats = &repeatedStats;
        for (u32 tasks : {1, 2, 4, 8, 1})
        {
            auto actual = initial;
            repeatedStats.reset();
            auto locals = std::span(reusableBuffers).first(tasks);
            auto* ciphertextAllocation = locals[0].mCiphertexts.data();
            auto* nodeAllocation = locals[0].mNodes.data();
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEvalTrunc(pool, locals,
                repeatedCtx, enc.mLacct, tree, mu, 1, digitBits, plaintextBits,
                actual, LencEvalMode::SubtractNtt, gadget)));
            LOGVOLE_REQUIRE_EQ(repeatedStats.mDyadicMulAddCount.load(), products);
            LOGVOLE_REQUIRE_EQ(repeatedStats.mSubCount.load(), mu);
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, expected[row].mCoeffs));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEvalTrunc(pool, locals,
                repeatedCtx, enc.mLacct, tree, mu, 1, digitBits, plaintextBits,
                actual, LencEvalMode::Coefficient, gadget)));
            LOGVOLE_REQUIRE_TRUE(forwardNttBatch(actual, ctx));
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, eval[row].mCoeffs));
            LOGVOLE_REQUIRE_TRUE(locals[0].mCiphertexts.data() == ciphertextAllocation);
            LOGVOLE_REQUIRE_TRUE(locals[0].mNodes.data() == nodeAllocation);
            for (const auto& local : locals)
                LOGVOLE_REQUIRE_TRUE(local.mCiphertexts.empty() && local.mNodes.empty());
        }
        for (auto& buffer : buffers)
        {
            buffer.mCiphertexts.reserve(capacity);
            buffer.mNodes.reserve(capacity);
        }
        RingOpsStats owners[2];
        unsigned operationIndex = 0;
        for (const auto mode : {LencEvalMode::Coefficient, LencEvalMode::Ntt, LencEvalMode::SubtractNtt})
        for (unsigned chunks : {1u, 3u, 1u})
        {
            auto cpu = ctx;
            const auto selection = (operationIndex++ + (mode == LencEvalMode::SubtractNtt ? 1u : 0u)) % 3;
            cpu.mExecutionOptions.mRingOpsStats = selection < 2 ? &owners[selection] : nullptr;
            if (selection < 2) owners[selection].reset();
            const auto firstCount = owners[0].mDyadicMulAddCount.load();
            const auto secondCount = owners[1].mDyadicMulAddCount.load();
            auto actual = initial;
            auto* batchAllocation = actual.data();
            std::vector<const u64*> coefficientAllocations;
            for (const auto& row : actual) coefficientAllocations.push_back(row.mCoeffs.data());
            std::array<const RnsPoly* const*, 3> ciphertextAllocations{}, nodeAllocations{};
            for (std::size_t i = 0; i < buffers.size(); ++i)
            {
                ciphertextAllocations[i] = buffers[i].mCiphertexts.data();
                nodeAllocations[i] = buffers[i].mNodes.data();
                buffers[i].mOk = false;
            }
            auto locals = std::span(buffers).first(chunks);
            auto operation = lencEvalTrunc(pool, locals, cpu, enc.mLacct, tree, mu, 1,
                digitBits, plaintextBits, actual, mode, gadget);
            for (const auto& buffer : locals) LOGVOLE_REQUIRE_FALSE(buffer.mOk);
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, initial[row].mCoeffs));
            auto moved = std::move(operation);
            // Exercise suspension from a worker of the target pool.
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onWorker(pool, std::move(moved))));
            if (selection < 2)
            {
                LOGVOLE_REQUIRE_EQ(owners[selection].mDyadicMulAddCount.load(), products);
                LOGVOLE_REQUIRE_EQ(owners[selection].mInttCount.load(), mode == LencEvalMode::Coefficient ? mu : 0u);
                LOGVOLE_REQUIRE_EQ(owners[selection].mSubCount.load(), mode == LencEvalMode::SubtractNtt ? mu : 0u);
                LOGVOLE_REQUIRE_EQ(owners[selection].mNttCount.load(), 0u);
            }
            if (selection != 0) LOGVOLE_REQUIRE_EQ(owners[0].mDyadicMulAddCount.load(), firstCount);
            if (selection != 1) LOGVOLE_REQUIRE_EQ(owners[1].mDyadicMulAddCount.load(), secondCount);
            const auto& reference = mode == LencEvalMode::Coefficient ? evalCoefficient :
                mode == LencEvalMode::Ntt ? eval : expected;
            LOGVOLE_REQUIRE_TRUE(actual.data() == batchAllocation);
            for (unsigned row = 0; row < mu; ++row)
            {
                LOGVOLE_REQUIRE_TRUE(actual[row].mCoeffs.data() == coefficientAllocations[row]);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
            }
            for (std::size_t i = 0; i < locals.size(); ++i)
            {
                LOGVOLE_REQUIRE_TRUE(locals[i].mOk);
                LOGVOLE_REQUIRE_TRUE(locals[i].mCiphertexts.empty() && locals[i].mNodes.empty());
                LOGVOLE_REQUIRE_TRUE(locals[i].mCiphertexts.data() == ciphertextAllocations[i]);
                LOGVOLE_REQUIRE_TRUE(locals[i].mNodes.data() == nodeAllocations[i]);
            }
        }
        if (limbs == 2 && bits == 30 && mu == 3 && !gadget)
        {
            auto actual = initial;
            macoro::thread_pool idle;
            auto idleWork = idle.make_work();
            { auto unstarted = lencEvalTrunc(idle, buffers, ctx, enc.mLacct, tree,
                mu, 1, digitBits, plaintextBits, actual, LencEvalMode::SubtractNtt); }
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, initial[row].mCoeffs));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEvalTrunc(idle, std::span(buffers).first(1),
                ctx, enc.mLacct, tree, mu, 1, digitBits, plaintextBits, actual, LencEvalMode::SubtractNtt)));
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, expected[row].mCoeffs));
            // Multiple chunks must also complete when called from the sole worker.
            idle.create_threads(1);
            actual = initial;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onWorker(idle, lencEvalTrunc(idle, buffers,
                ctx, enc.mLacct, tree, mu, 1, digitBits, plaintextBits, actual, LencEvalMode::SubtractNtt))));
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, expected[row].mCoeffs));
            actual = initial;
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lencEvalTrunc(pool, {}, ctx, enc.mLacct,
                tree, mu, 1, digitBits, plaintextBits, actual, LencEvalMode::Ntt)));
            LencEvalBuffer undersized;
            undersized.mNodes.reserve(capacity);
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lencEvalTrunc(pool, std::span(&undersized, 1),
                ctx, enc.mLacct, tree, mu, 1, digitBits, plaintextBits, actual, LencEvalMode::Ntt)));
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, initial[row].mCoeffs));
        }
        auto invalid = initial;
        invalid.pop_back();
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lencEvalTrunc(pool, buffers, ctx, enc.mLacct, tree,
            mu, 1, digitBits, plaintextBits, invalid, LencEvalMode::SubtractNtt, gadget)));
        for (unsigned row = 0; row < invalid.size(); ++row)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(invalid[row].mCoeffs, initial[row].mCoeffs));
    }
}

void LogVole_Cpu_GoldenMarginMatchesIntegerReference(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    PRNG random(toBlock(0x474f4c44, 0x4d415247));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        auto moduli = seal::CoeffModulus::Create(1024, std::vector<int>(limbs, bits));
        for (unsigned target = 0; target < limbs; ++target)
        {
            std::vector<seal::Modulus> reduced;
            std::vector<std::size_t> indices;
            std::vector<wideU64> fractions;
            for (unsigned j = 0; j < limbs; ++j) if (j != target)
            {
                indices.push_back(j);
                reduced.push_back(moduli[j]);
                const auto fraction = (~host_oracle::Uint128{0}) / moduli[j].value();
                fractions.push_back({static_cast<u64>(fraction), static_cast<u64>(fraction >> 64)});
            }
            seal::util::RNSBase base(reduced, seal::MemoryPoolHandle::ThreadLocal());
            std::span<const seal::util::MultiplyUIntModOperand> inverse(
                base.inv_punctured_prod_mod_base_array(), reduced.size());
            for (std::size_t count : {0, 1, 7, 8, 9, 33, 129})
            {
                std::vector<u64> input(count * limbs + 2);
                random.get(input.data(), input.size());
                for (unsigned j = 0; j < limbs; ++j)
                {
                    const u64 q = moduli[j].value();
                    const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, 2*q, ~u64{0}};
                    for (std::size_t i = 0; i < std::min(count, edges.size()); ++i)
                        input[1+j*count+i] = edges[i];
                }
                const auto original = input;
                host_oracle::Uint128 closest = ~host_oracle::Uint128{0};
                for (std::size_t i = 0; i < count; ++i)
                {
                    host_oracle::Uint128 sum = host_oracle::Uint128{1} << 127;
                    for (std::size_t j = 0; j < indices.size(); ++j)
                    {
                        const u64 q = reduced[j].value();
                        const u64 residue = (static_cast<host_oracle::Uint128>(input[1+indices[j]*count+i] % q) *
                            inverse[j].operand) % q;
                        sum += residue * ((~host_oracle::Uint128{0}) / q);
                    }
                    closest = std::min(closest, std::min(sum, host_oracle::Uint128{0} - sum));
                }
                for (const auto margin : {host_oracle::Uint128{0}, host_oracle::Uint128{1},
                    (host_oracle::Uint128{1} << 127), ~host_oracle::Uint128{0}, closest, closest-1, closest+1})
                {
                    bool accepted = false;
                    const bool used = LogVole::cpuCheckRoundingMargin(cpu, input.data()+1, count,
                        moduli, indices, inverse, fractions,
                        {static_cast<u64>(margin), static_cast<u64>(margin >> 64)}, accepted);
                    LOGVOLE_REQUIRE_EQ(accepted, used && (count == 0 || closest >= margin));
                    LOGVOLE_REQUIRE_TRUE(input == original);
                    LOGVOLE_REQUIRE_EQ(used, (bits == 52 || bits == 55) && cpu.ifma());
                }
                bool accepted = true;
                const std::vector<std::size_t> invalid{moduli.size()};
                LOGVOLE_REQUIRE_FALSE(LogVole::cpuCheckRoundingMargin(cpu, input.data()+1, count,
                    moduli, invalid, inverse, fractions, {}, accepted));
                LOGVOLE_REQUIRE_TRUE(accepted);
            }
        }
    }
}

void LogVole_Cpu_ReduceMatchesReference(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    const osuCrypto::CpuCapabilities scalar(osuCrypto::CpuCapabilities::Mode::Scalar);
    std::array<u64, 8> source{}, destination;
    destination.fill(123);
    LOGVOLE_REQUIRE_FALSE(LogVole::cpuReduceMod(
        scalar, source.data(), destination.data(), source.size(), seal::Modulus((u64{1} << 52) - 1)));
    LOGVOLE_REQUIRE_TRUE(std::all_of(destination.begin(), destination.end(), [](u64 x) { return x == 123; }));
    PRNG random(toBlock(0x52454455, 0x4345));
    for (int bits : {30, 52, 55, 60})
    for (u64 gap : {1ULL, 32767ULL, 16777215ULL, 16777216ULL})
    for (std::size_t count : {0, 1, 7, 8, 9, 127, 1024})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus modulus(q);
        std::vector<u64> input(count + 2), actual(count + 2, 123), expected = actual;
        random.get(input.data(), input.size());
        const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, 2*q, ~u64{0}};
        for (std::size_t i = 0; i < count; ++i)
        {
            if (i < edges.size()) input[i+1] = edges[i];
            expected[i+1] = input[i+1] % q;
        }
        const auto original = actual;
        const bool used = LogVole::cpuReduceMod(cpu, input.data()+1, actual.data()+1, count, modulus);
        LOGVOLE_REQUIRE_TRUE(actual == (used ? expected : original));
        const bool expectedFast = (bits == 52 || bits == 55) && gap < (u64{1} << 24) && cpu.avx512();
        LOGVOLE_REQUIRE_EQ(used, expectedFast);
        auto alias = input;
        LOGVOLE_REQUIRE_EQ(LogVole::cpuReduceMod(cpu, alias.data()+1, alias.data()+1, count, modulus), used);
        if (used) for (std::size_t i = 0; i < count; ++i) LOGVOLE_REQUIRE_EQ(alias[i+1], expected[i+1]);
        LOGVOLE_REQUIRE_EQ(alias.front(), input.front());
        LOGVOLE_REQUIRE_EQ(alias.back(), input.back());
        if (count)
        {
            // A rejection at the last coefficient must leave earlier outputs
            // untouched too, so a caller can replay the complete scalar pass.
            const u64 limit = ~u64{0};
            input[count] = limit;
            actual = original;
            LOGVOLE_REQUIRE_TRUE(!LogVole::cpuReduceMod(cpu,
                input.data()+1, actual.data()+1, count, modulus, &limit));
            LOGVOLE_REQUIRE_TRUE(actual == original);
        }
    }
}

void LogVole_Cpu_ScaleAndRoundMatchesReference(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    PRNG random(toBlock(0x5343414c, 0x45524e44));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        auto moduli = seal::CoeffModulus::Create(1024, std::vector<int>(limbs, bits));
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        const seal::util::RNSBase base(moduli, pool);
        for (u64 p : {u64{17}, (u64{1} << (bits - 1)) - 33, moduli[0].value() - 1,
            moduli[0].value(), moduli.back().value(), (u64{1} << bits) - 1})
        for (std::size_t count : {0, 1, 7, 8, 9, 127, 1024})
        {
            std::vector<u64> input(limbs * count), actual(count+2, 123), expected = actual;
            random.get(input.data(), input.size());
            if (count >= 8)
            {
                std::vector<u64> boundaries(limbs * count, 0);
                for (unsigned k = 0; k < 8; ++k)
                {
                    auto* x = boundaries.data() + k * limbs;
                    if (k >= 2) std::copy_n(base.base_prod(), limbs, x);
                    if (k >= 4) seal::util::right_shift_uint(x, 1, limbs, x);
                    if (k == 1 || k == 6) seal::util::add_uint(x, limbs, u64{1}, x);
                    if (k == 2 || k == 5) seal::util::sub_uint(x, limbs, u64{1}, x);
                }
                base.decompose_array(boundaries.data(), count, pool);
                for (unsigned j = 0; j < limbs; ++j)
                    std::copy_n(boundaries.data()+j*count, 8, input.data()+j*count);
            }
            for (std::size_t k = 0; k < count; ++k)
            {
                // Independent wide division, with the same specified 128-bit
                // fractional rounding as the production scalar implementation.
                host_oracle::Uint128 fraction = host_oracle::Uint128{1} << 127;
                u64 result = 0;
                for (unsigned j = 0; j < limbs; ++j)
                {
                    const u64 q = moduli[j].value();
                    const u64 x = static_cast<u64>((static_cast<host_oracle::Uint128>(input[j*count+k] % q) *
                        base.inv_punctured_prod_mod_base_array()[j].operand) % q);
                    const host_oracle::Uint128 numerator = static_cast<host_oracle::Uint128>(x) * p;
                    const auto term = (numerator % q) * (~host_oracle::Uint128{0} / q);
                    const auto next = fraction + term;
                    result = (result + static_cast<u64>(numerator / q) + (next < fraction)) % p;
                    fraction = next;
                }
                expected[k+1] = result;
            }
            const auto original = actual;
            const bool used = LogVole::cpuScaleAndRoundRns(cpu, input.data(), actual.data()+1, count, base, p);
            LOGVOLE_REQUIRE_TRUE(actual == (used ? expected : original));
            const bool expectedFast = (limbs == 4 || limbs == 8) && (bits == 52 || bits == 55) && cpu.ifma();
            LOGVOLE_REQUIRE_EQ(used, expectedFast);
        }
        std::vector<u64> unchanged(16, 123), input(8 * limbs);
        LOGVOLE_REQUIRE_TRUE(!LogVole::cpuScaleAndRoundRns(cpu, input.data(), unchanged.data(), 8,
            base, u64{1} << bits));
        LOGVOLE_REQUIRE_TRUE(std::all_of(unchanged.begin(), unchanged.end(), [](u64 x) { return x == 123; }));
    }
}

void LogVole_Cpu_FusedGadgetMatchesBalancedReference(const oc::CLP&)
{
    PRNG random(toBlock(0x47414447, 0x4554));
    for (unsigned limbs : {4, 8})
    {
        const unsigned bits = limbs == 4 ? 55 : 52, digitBits = limbs * bits / 2;
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        for (unsigned trial = 0; trial < 16; ++trial)
        {
            auto poly = sampleUniformPoly(ctx, random);
            // Exact integer boundary cases, converted to RNS by SEAL: around
            // Q/2, the low digit's rounding tie, and the high digit's sign bit.
            std::vector<u64> integers(limbs * 1024, 0);
            for (unsigned i = 0; i < 24; ++i)
            {
                auto* value = integers.data() + i * limbs;
                const unsigned bit = i < 12 ? digitBits - 1 : 2 * digitBits - 2;
                value[bit / 64] = u64{1} << (bit % 64);
                if (i % 3 == 0) seal::util::sub_uint(value, limbs, u64{1}, value);
                if (i % 3 == 2) seal::util::add_uint(value, limbs, u64{1}, value);
                if (i % 12 >= 6) seal::util::sub_uint(base.base_prod(), value, limbs, value);
            }
            for (unsigned i = 24; i < 30; ++i)
            {
                auto* value = integers.data() + i * limbs;
                seal::util::right_shift_uint(base.base_prod(), 1, limbs, value);
                if (i % 3 == 0) seal::util::sub_uint(value, limbs, u64{1}, value);
                if (i % 3 == 2) seal::util::add_uint(value, limbs, u64{1}, value);
            }
            base.decompose_array(integers.data(), 1024, seal::MemoryPoolHandle::ThreadLocal());
            for (unsigned j = 0; j < limbs; ++j)
                std::copy_n(integers.data() + j * 1024, 32, poly.mCoeffs.data() + j * 1024);
            std::vector<RnsPoly> reference, actual;
            // Asking for both digits uses the general signed-integer path.
            LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, digitBits, 0, 2, ctx, reference));
            LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, digitBits, 1, 1, ctx, actual));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, reference[1].mCoeffs));
            const bool fused = LogVole::cpuCenteredHighDigit(ctx.mCpuCapabilities, poly.mCoeffs.data(),
                actual[0].mCoeffs.data(), 1024, digitBits, base);
            LOGVOLE_REQUIRE_EQ(fused, ctx.mCpuCapabilities.ifma());
            if (fused) LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, reference[1].mCoeffs));
            RnsPoly recomposed;
            LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(reference, digitBits, ctx, recomposed));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(recomposed.mCoeffs, poly.mCoeffs));
            // Unsupported shape must decline before changing any destination.
            std::vector<u64> untouched(limbs * 1024, 123);
            LOGVOLE_REQUIRE_TRUE(!LogVole::cpuCenteredHighDigit(ctx.mCpuCapabilities,
                poly.mCoeffs.data(), untouched.data(), 1023, digitBits, base));
            LOGVOLE_REQUIRE_TRUE(std::all_of(untouched.begin(), untouched.end(), [](u64 x) { return x == 123; }));
        }
    }
}

void LogVole_Cpu_LowDigitMatchesIntegerReference(const oc::CLP&)
{
    PRNG random(toBlock(0x4c4f5744, 0x49474954));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    for (unsigned digitBits : {63, 110, 208, 256})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        auto poly = sampleUniformPoly(ctx, random);
        // CRT integers 0, 1, 2, Q-1 and Q-2 exercise a quotient estimate
        // immediately below an integer, including its final correction.
        for (unsigned j = 0; j < limbs; ++j)
        {
            const u64 q = ringModulusValue(ctx, j);
            for (unsigned k = 0; k < 3; ++k) poly.mCoeffs[j*1024+k] = k;
            poly.mCoeffs[j*1024+3] = q-1;
            poly.mCoeffs[j*1024+4] = q-2;
        }
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        std::vector<u64> expected(poly.mCoeffs.begin(), poly.mCoeffs.end());
        base.compose_array(expected.data(), 1024, pool);
        for (unsigned i = 0; i < 1024; ++i)
        for (unsigned w = 0; w < limbs; ++w)
        {
            if (w*64 >= digitBits) expected[i*limbs+w] = 0;
            else if ((w+1)*64 > digitBits)
                expected[i*limbs+w] &= (u64{1} << (digitBits-w*64))-1;
        }
        base.decompose_array(expected.data(), 1024, pool);
        std::vector<RnsPoly> actual;
        LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, digitBits, 0, 1, ctx, actual));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, expected));
        std::vector<u64> direct(limbs*1024+2, 123);
        const bool used = LogVole::cpuLowDigitRns(ctx.mCpuCapabilities, poly.mCoeffs.data(), direct.data()+1,
            1024, digitBits, base);
        const bool supported = ((limbs==4 && bits==55 && digitBits==110) ||
            (limbs==8 && bits==52 && digitBits==208)) && ctx.mCpuCapabilities.ifma();
        LOGVOLE_REQUIRE_EQ(used, supported);
        if (used) LOGVOLE_REQUIRE_TRUE(std::equal(expected.begin(), expected.end(), direct.begin()+1));
        else LOGVOLE_REQUIRE_TRUE(std::all_of(direct.begin(), direct.end(), [](u64 x) { return x==123; }));
        LOGVOLE_REQUIRE_EQ(direct.front(), u64{123});
        LOGVOLE_REQUIRE_EQ(direct.back(), u64{123});
        for (std::size_t count : {0, 1, 7, 9, 1023})
        {
            std::fill(direct.begin(), direct.end(), 123);
            LOGVOLE_REQUIRE_TRUE(!LogVole::cpuLowDigitRns(ctx.mCpuCapabilities,
                poly.mCoeffs.data(), direct.data()+1, count, digitBits, base));
            LOGVOLE_REQUIRE_TRUE(std::all_of(direct.begin(), direct.end(), [](u64 x) { return x==123; }));
        }
    }
}

void LogVole_Cpu_LheDecryptMatchesTransformReference(const oc::CLP&)
{
    // Independent reset epochs invalidate pending work, including at destruction.
    RingOpsStats firstStats, secondStats;
    {
        PendingRingOpsStats first(&firstStats), second(&secondStats), disabled(nullptr);
        for (unsigned i = 0; i != 255; ++i) first.bump(RingOp::Ntt);
        LOGVOLE_REQUIRE_EQ(firstStats.mNttCount.load(), 0u);
        first.bump(RingOp::Ntt);
        LOGVOLE_REQUIRE_EQ(firstStats.mNttCount.load(), 256u);
        first.bump(RingOp::Ntt);
        second.bump(RingOp::Sub);
        firstStats.reset();
        first.flush();
        LOGVOLE_REQUIRE_EQ(firstStats.mNttCount.load(), 0u);
        second.flush();
        LOGVOLE_REQUIRE_EQ(secondStats.mSubCount.load(), 1u);
        first.bump(RingOp::Intt);
        disabled.bump(RingOp::Ntt);
        disabled.flush();
    }
    LOGVOLE_REQUIRE_EQ(firstStats.mInttCount.load(), 1u);
    {
        PendingRingOpsStats stale(&firstStats);
        stale.bump(RingOp::Ntt);
        firstStats.reset();
    }
    LOGVOLE_REQUIRE_EQ(firstStats.mNttCount.load(), 0u);
    PRNG random(toBlock(0x4c4845, 0x444543));
    // The application owns compute and memory independently. A fixed pool is
    // reused across shapes, calls, and different chunk counts.
    macoro::thread_pool lhePool;
    auto lheWork = lhePool.make_work();
    lhePool.create_threads(1);
    std::array<LheDecryptBuffer, 8> lheBuffers;
    CpuBenchmarkContext lheTelemetry;
    lheTelemetry.mCpus = {0, 1, 2};
    lheTelemetry.mWorkerLimit = 1; // Diagnostics must not select execution capacity.
    CpuBenchmarkState lheBenchmark{&lheTelemetry};
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto& hostModuli = getRingHostModuli(ctx);
        LOGVOLE_REQUIRE_EQ(hostModuli.size(), static_cast<std::size_t>(limbs));
        for (auto& buffer : lheBuffers)
            buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params));
        constexpr unsigned rows = 9;
        auto sk = sampleUniformPoly(ctx, random);
        auto skNtt = sk;
        LOGVOLE_REQUIRE_TRUE(forwardNtt(skNtt, ctx));
        std::vector<RnsPoly> publicA(rows), cipher(rows), expected(rows);
        for (unsigned row = 0; row < rows; ++row)
        {
            publicA[row] = sampleUniformPolyNtt(ctx, random);
            auto& ct = cipher[row];
            ct.mCoeffs.resize(limbs * 1024);
            random.get(ct.mCoeffs.data(), ct.mCoeffs.size());
            // The optimized coefficient path must preserve the original
            // arbitrary-u64 canonicalization, including wraparound boundaries.
            ct.mCoeffs[0] = 0;
            ct.mCoeffs[1] = ~u64{0};
            ct.mCoeffs[2] = ringModulusValue(ctx, 0);
            auto& result = expected[row];
            result = ct;
            LOGVOLE_REQUIRE_TRUE(forwardNtt(result, ctx));
            for (unsigned j = 0; j < limbs; ++j)
            for (unsigned k = 0; k < 1024; ++k)
            {
                const auto i = j * 1024 + k;
                const auto& q = hostModuli[j];
                result.mCoeffs[i] = seal::util::sub_uint_mod(result.mCoeffs[i],
                    seal::util::multiply_uint_mod(publicA[row].mCoeffs[i], skNtt.mCoeffs[i], q), q);
            }
            LOGVOLE_REQUIRE_TRUE(inverseNtt(result, ctx));
        }
        for (u32 workers : {1, 3, 8})
        for (bool inputNtt : {false, true})
        for (bool outputNtt : {false, true})
        {
            auto input = cipher;
            auto reference = expected;
            if (inputNtt) LOGVOLE_REQUIRE_TRUE(forwardNttBatch(input, ctx));
            if (outputNtt) LOGVOLE_REQUIRE_TRUE(forwardNttBatch(reference, ctx));
            const auto domain = inputNtt ? LheDomain::Ntt : LheDomain::Coefficient;
            auto chunks = std::span(lheBuffers).first(workers);
            auto actual = input;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ctx,
                actual, sk, publicA, domain)));
            if (inputNtt != outputNtt)
                LOGVOLE_REQUIRE_TRUE(outputNtt ? forwardNttBatch(actual, ctx) : inverseNttBatch(actual, ctx));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
            auto consumed = input;
            auto* consumedBatch = consumed.data();
            const auto* consumedCoefficients = consumed[0].mCoeffs.data();
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ctx,
                consumed, sk, publicA, domain)));
            if (inputNtt != outputNtt)
                LOGVOLE_REQUIRE_TRUE(outputNtt ? forwardNttBatch(consumed, ctx) : inverseNttBatch(consumed, ctx));
            LOGVOLE_REQUIRE_TRUE(consumed.data() == consumedBatch);
            LOGVOLE_REQUIRE_TRUE(consumed[0].mCoeffs.data() == consumedCoefficients);
            actual = std::move(consumed);
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
            consumed = input;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ctx,
                consumed, sk, publicA, domain)));
            if (inputNtt != outputNtt)
                LOGVOLE_REQUIRE_TRUE(outputNtt ? forwardNttBatch(consumed, ctx) : inverseNttBatch(consumed, ctx));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(consumed[row].mCoeffs, reference[row].mCoeffs));
            if (!inputNtt && !outputNtt)
            {
                RingOpsStats totals;
                auto ownedCtx = ctx;
                ownedCtx.mExecutionOptions.mRingOpsStats = &totals;
                auto* productAllocation = chunks[0].mProduct.mCoeffs.data();
                for (unsigned repeat = 0; repeat < 2; ++repeat)
                {
                    totals.reset();
                    actual = input;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ownedCtx,
                        actual, sk, publicA, LheDomain::Coefficient)));
                    LOGVOLE_REQUIRE_EQ(totals.mDyadicMulAddCount.load(), rows);
                    LOGVOLE_REQUIRE_EQ(totals.mInttCount.load(), rows);
                    LOGVOLE_REQUIRE_TRUE(chunks[0].mProduct.mCoeffs.data() == productAllocation);
                    for (unsigned row = 0; row < rows; ++row)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
                }
                consumed = input;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ctx,
                    consumed, sk, publicA, LheDomain::Coefficient)));
                for (unsigned row = 0; row < rows; ++row)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(consumed[row].mCoeffs, reference[row].mCoeffs));
            }
            if (inputNtt == outputNtt)
            {
                const auto domain = inputNtt ? LheDomain::Ntt : LheDomain::Coefficient;
                auto cpu = ctx;
                RingOpsStats owners[2];
                auto chunks = std::span(lheBuffers).first(workers);
                std::array<const u64*, 8> products{};
                for (std::size_t i = 0; i < chunks.size(); ++i)
                    products[i] = chunks[i].mProduct.mCoeffs.data();
                for (unsigned repeat = 0; repeat < 2; ++repeat)
                {
                    actual = input; // Keeping ciphertext is an explicit caller copy.
                    auto* batchAllocation = actual.data();
                    std::array<const u64*, rows> coefficients{};
                    for (unsigned row = 0; row < rows; ++row)
                        coefficients[row] = actual[row].mCoeffs.data();
                    lheTelemetry.reset();
                    cpu.mExecutionOptions.mRingOpsStats = &owners[repeat];
                    owners[repeat].reset();
                    for (auto& chunk : chunks)
                    {
                        std::fill(chunk.mProduct.mCoeffs.begin(), chunk.mProduct.mCoeffs.end(), ~u64{0});
                        chunk.mOk = false;
                    }
                    auto operation = lheDec(lhePool, chunks, cpu, actual, sk, publicA, domain, lheBenchmark);
                    // Creation is lazy and borrows the caller's unchanged storage.
                    for (unsigned row = 0; row < rows; ++row)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, input[row].mCoeffs));
                    for (const auto& chunk : chunks) LOGVOLE_REQUIRE_FALSE(chunk.mOk);
                    auto moved = std::move(operation);
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(std::move(moved)));
                    LOGVOLE_REQUIRE_TRUE(actual.data() == batchAllocation);
                    for (unsigned row = 0; row < rows; ++row)
                    {
                        LOGVOLE_REQUIRE_TRUE(actual[row].mCoeffs.data() == coefficients[row]);
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
                    }
                    for (std::size_t i = 0; i < chunks.size(); ++i)
                    {
                        LOGVOLE_REQUIRE_TRUE(chunks[i].mProduct.mCoeffs.data() == products[i]);
                        LOGVOLE_REQUIRE_TRUE(chunks[i].mOk);
                    }
                    LOGVOLE_REQUIRE_EQ(owners[repeat].mNttCount.load(), 1u);
                    LOGVOLE_REQUIRE_EQ(owners[repeat].mDyadicMulAddCount.load(), rows);
                    LOGVOLE_REQUIRE_EQ(owners[repeat].mSubCount.load(), inputNtt ? rows : 0u);
                    LOGVOLE_REQUIRE_EQ(owners[repeat].mInttCount.load(), inputNtt ? 0u : rows);
                    LOGVOLE_REQUIRE_EQ(lheTelemetry.mActiveTaskThreads.load(), 0u);
                    LOGVOLE_REQUIRE_TRUE(lheTelemetry.mPeakTaskThreads.load() <= std::min(workers, 3u));
                }
                LOGVOLE_REQUIRE_EQ(owners[0].mDyadicMulAddCount.load(), rows);
                cpu.mExecutionOptions.mRingOpsStats = nullptr;
                actual = input;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, cpu,
                    actual, sk, publicA, domain, lheBenchmark)));
                if (limbs == 2 && bits == 30 && workers == 3)
                {
                    macoro::thread_pool oneWorker;
                    auto work = oneWorker.make_work();
                    actual = input;
                    {
                        auto unstarted = lheDec(oneWorker, chunks, cpu, actual, sk, publicA, domain);
                    } // Dropping an unstarted task leaves borrowed storage alone.
                    for (unsigned row = 0; row < rows; ++row)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, input[row].mCoeffs));
                    // A single chunk needs no executor thread.
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(oneWorker, chunks.first(1), cpu,
                        actual, sk, publicA, domain, lheBenchmark)));
                    for (unsigned row = 0; row < rows; ++row)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
                    oneWorker.create_threads(1);
                    actual = input;
                    auto onWorker = [](macoro::thread_pool& pool, macoro::task<bool> operation)
                        -> macoro::task<bool> {
                        co_await pool.schedule();
                        co_return co_await std::move(operation);
                    };
                    // All borrowed data stays in this scope until the join.
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onWorker(oneWorker,
                        lheDec(oneWorker, chunks, cpu, actual, sk, publicA, domain, lheBenchmark))));
                    for (unsigned row = 0; row < rows; ++row)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
                    LOGVOLE_REQUIRE_EQ(lheTelemetry.mActiveTaskThreads.load(), 0u);
                }
                actual = input;
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lheDec(lhePool, {}, cpu,
                    actual, sk, publicA, domain, lheBenchmark)));
                if (!inputNtt)
                {
                    chunks[0].mProduct.mCoeffs.resize(ringPolyCoeffCount(params) - 1);
                    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lheDec(lhePool, chunks, cpu,
                        actual, sk, publicA, domain, lheBenchmark)));
                    chunks[0].mProduct.mCoeffs.resize(ringPolyCoeffCount(params));
                }
                for (unsigned row = 0; row < rows; ++row)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, input[row].mCoeffs));
            }

            if (inputNtt && outputNtt)
            {
                // A caller may use the ciphertext batch as its public A too.
                // Independent scalar modular subtraction specifies that alias.
                auto aliasReference = input;
                for (unsigned row = 0; row < rows; ++row)
                for (unsigned j = 0; j < limbs; ++j)
                for (unsigned k = 0; k < 1024; ++k)
                {
                    const auto i = j * 1024 + k;
                    const auto& q = hostModuli[j];
                    aliasReference[row].mCoeffs[i] = seal::util::sub_uint_mod(input[row].mCoeffs[i],
                        seal::util::multiply_uint_mod(input[row].mCoeffs[i], skNtt.mCoeffs[i], q), q);
                }
                auto aliasCpu = ctx;
                consumed = input;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, aliasCpu,
                    consumed, sk, consumed, LheDomain::Ntt, lheBenchmark)));
                for (unsigned row = 0; row < rows; ++row)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(consumed[row].mCoeffs, aliasReference[row].mCoeffs));
                consumed = input;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ctx,
                    consumed, sk, consumed, LheDomain::Ntt)));
                for (unsigned row = 0; row < rows; ++row)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(consumed[row].mCoeffs, aliasReference[row].mCoeffs));
                // Repeated NTT queries publish counts without allocating product scratch.
                auto separate = ctx;
                RingOpsStats totals;
                separate.mExecutionOptions.mRingOpsStats = &totals;
                const auto* productAllocation = chunks[0].mProduct.mCoeffs.data();
                for (unsigned repeat = 0; repeat < 2; ++repeat)
                {
                    totals.reset();
                    actual = input;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, separate,
                        actual, sk, publicA, LheDomain::Ntt)));
                    // Counts are published at the join while the pool stays alive.
                    LOGVOLE_REQUIRE_EQ(totals.mDyadicMulAddCount.load(), rows);
                    LOGVOLE_REQUIRE_EQ(totals.mSubCount.load(), rows);
                    LOGVOLE_REQUIRE_TRUE(chunks[0].mProduct.mCoeffs.data() == productAllocation);
                    for (unsigned row = 0; row < rows; ++row)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
                }
                // Another caller-owned buffer set has independent allocations.
                std::array<LheDecryptBuffer, 8> secondBuffers;
                for (auto& buffer : secondBuffers)
                    buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params));
                LOGVOLE_REQUIRE_TRUE(secondBuffers[0].mProduct.mCoeffs.data() != productAllocation);
                actual = input;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool,
                    std::span(secondBuffers).first(workers), separate, actual, sk, publicA, LheDomain::Ntt)));
                for (unsigned row = 0; row < rows; ++row)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
            }
            // The owning output may alias the input batch.
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheDec(lhePool, chunks, ctx, input, sk, publicA, domain)));
            if (inputNtt != outputNtt)
                LOGVOLE_REQUIRE_TRUE(outputNtt ? forwardNttBatch(input, ctx) : inverseNttBatch(input, ctx));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(input[row].mCoeffs, reference[row].mCoeffs));
        }
    }
}

void LogVole_Cpu_DenoiseMatchesIntegerRounding(const oc::CLP&)
{
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    PRNG random(toBlock(0x44454e4f, 0x495345));
    for (unsigned limbs : {1, 2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& hostModuli = getRingHostModuli(ctx);
        LOGVOLE_REQUIRE_EQ(hostModuli.size(), static_cast<std::size_t>(limbs));
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        auto pool = seal::MemoryManager::GetPool();
        constexpr std::size_t count = 9, n = 1024;
        std::vector<RnsPoly> input(count * limbs), expected(count);
        for (auto& poly : expected) resizeZero(poly.mCoeffs, n * limbs);
        for (std::size_t i = 0; i < count; ++i)
        for (std::size_t j = 0; j < limbs; ++j)
        {
            auto& poly = input[i * limbs + j];
            resizeZero(poly.mCoeffs, n * limbs);
            for (std::size_t w = 0; w < limbs; ++w)
            for (std::size_t k = 0; k < n; ++k)
            {
                const u64 q = ringModulusValue(ctx, w);
                poly.mCoeffs[w*n+k] = k == 0 ? 0 : k == 1 ? q-1 : random.get<u64>() % q;
            }
            // Independent oracle: reconstruct the full integer, then divide by
            // Q/q_j with nearest-integer rounding. This exercises the entire
            // residue range and uses neither Shoup operands nor fixed-point CRT.
            auto composed = poly.mCoeffs;
            base.compose_array(composed.data(), n, pool);
            const u64* divisor = base.punctured_prod_array() + j * limbs;
            std::vector<u64> half(limbs), value(limbs), quotient(limbs), remainder(limbs);
            seal::util::right_shift_uint(divisor, 1, limbs, half.data());
            for (std::size_t k = 0; k < n; ++k)
            {
                seal::util::add_uint(composed.data() + k*limbs, half.data(), limbs, value.data());
                seal::util::divide_uint(value.data(), divisor, limbs, quotient.data(), remainder.data(), pool);
                expected[i].mCoeffs[j*n+k] = seal::util::modulo_uint(quotient.data(), limbs, hostModuli[j]);
            }
        }
        for (u32 workers : {1, 3, 8})
        {
            std::vector<RnsPoly> actual;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandDenoiseComb(executor, workers, ctx, input, actual)));
            LOGVOLE_REQUIRE_EQ(actual.size(), expected.size());
            for (std::size_t i = 0; i < count; ++i)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected[i].mCoeffs));
        }
        auto alias = input;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandDenoiseComb(executor, 3, ctx, alias, alias)));
        for (std::size_t i = 0; i < count; ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(alias[i].mCoeffs, expected[i].mCoeffs));
        std::vector<RnsPoly> moved;
        auto* originalAllocation = alias[0].mCoeffs.data();
        LOGVOLE_REQUIRE_TRUE(seedLabelAgg(std::move(alias), count, 1, params, moved));
        LOGVOLE_REQUIRE_TRUE(moved[0].mCoeffs.data() == originalAllocation);
        LOGVOLE_REQUIRE_TRUE(seedLabelAgg(std::move(moved), count, 1, params, moved));
        LOGVOLE_REQUIRE_TRUE(moved[0].mCoeffs.data() == originalAllocation);
        auto malformed = input;
        malformed[0].mCoeffs.resize(1);
        LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(shrinkExpandDenoiseComb(executor, 8, ctx, malformed, moved)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(moved[0].mCoeffs, expected[0].mCoeffs));
    }
}

void LogVole_Cpu_NttMatchesReference(const oc::CLP&)
{
    PRNG random(toBlock(0x4845584c, 0x4e5454));
    struct Case { std::size_t degree; int bits; unsigned limbs; };
    const std::array<Case, 9> cases = {{{1024, 30, 2}, {1024, 49, 2},
        {1024, 50, 2}, {1024, 51, 2}, {1024, 52, 2}, {1024, 55, 2},
        {1024, 60, 2}, {8192, 55, 4}, {16384, 52, 8}}};
    for (const auto& test : cases)
    {
        RingParams params{};
        params.mPolyModulusDegree = test.degree;
        params.mCoeffModulusBits.resize(test.limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), test.bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto* tables = hostContext->key_context_data()->small_ntt_tables();
        for (unsigned limb = 0; limb < test.limbs; ++limb)
        for (unsigned inverse = 0; inverse < 2; ++inverse)
        for (unsigned trial = 0; trial < 4; ++trial)
        {
            const auto& table = tables[limb];
            const u64 q = table.modulus().value();
            const u64 bound = (inverse ? 2 : 4) * q;
            std::vector<u64> actual(test.degree);
            for (auto& value : actual) value = random.get<u64>() % bound;
            const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, bound-2, bound-1};
            std::copy(edges.begin(), edges.end(), actual.begin());
            auto expected = actual;
            // Invoke SEAL's original Harvey implementation directly, bypassing
            // the public NTT entry points that dispatch to HEXL when enabled.
            if (inverse)
            {
                const auto invDegree = table.inv_degree_modulo();
                table.ntt_handler().transform_from_rev(expected.data(), table.coeff_count_power(),
                    table.get_from_inv_root_powers(), &invDegree);
                seal::util::inverse_ntt_negacyclic_harvey(actual.data(), table);
            }
            else
            {
                table.ntt_handler().transform_to_rev(expected.data(), table.coeff_count_power(),
                    table.get_from_root_powers());
                seal::util::ntt_negacyclic_harvey(actual.data(), table);
            }
            for (auto& value : expected) value %= q;
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }
        RnsPoly raw{}, canonical{}, expected{};
        raw.mCoeffs.resize(test.degree*test.limbs);
        random.get(raw.mCoeffs.data(), raw.mCoeffs.size());
        canonical = raw;
        for (unsigned limb = 0; limb < test.limbs; ++limb)
            for (std::size_t i = 0; i < test.degree; ++i)
                canonical.mCoeffs[limb*test.degree+i] %= ringModulusValue(ctx, limb);
        expected = canonical;
        for (unsigned limb = 0; limb < test.limbs; ++limb)
        {
            const auto& table = tables[limb];
            table.ntt_handler().transform_to_rev(expected.mCoeffs.data()+limb*test.degree,
                table.coeff_count_power(), table.get_from_root_powers());
            for (std::size_t i = 0; i < test.degree; ++i)
                expected.mCoeffs[limb*test.degree+i] %= ringModulusValue(ctx, limb);
        }
        LOGVOLE_REQUIRE_TRUE(forwardNtt(raw, ctx));
        LOGVOLE_REQUIRE_TRUE(forwardNttCanonical(canonical, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(raw.mCoeffs, expected.mCoeffs));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(canonical.mCoeffs, expected.mCoeffs));
    }
}

void LogVole_Cpu_AsyncInputWrapping(const oc::CLP& cmd)
{
    RingParams params;
    params.mPolyModulusDegree = 1024;
    assignValues<int>(params.mCoeffModulusBits, {30, 30});
    ZpCrtContext ctx;
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, ctx));
    const auto slots = zpSlotCount(ctx);
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(cmd.getOr("executor_threads", 1));
    std::array<ZpEncodeBuffer, 3> buffers;
    std::array<const u64*, 3> slotStorage, plainStorage;
    for (std::size_t i = 0; i != buffers.size(); ++i)
    {
        buffers[i].mSlots.resize(slots);
        buffers[i].mPlain.resize(slots);
        slotStorage[i] = buffers[i].mSlots.data();
        plainStorage[i] = buffers[i].mPlain.data();
    }
    auto onPool = [&](macoro::task<bool> operation) -> macoro::task<bool> {
        co_await executor.schedule();
        co_return co_await std::move(operation);
    };
    auto equal = [](const auto& a, const auto& b) {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i != a.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(a[i].mCoeffs, b[i].mCoeffs));
    };
    for (std::size_t count : {std::size_t(0), std::size_t(1), std::size_t(slots), std::size_t(2 * slots + 7)})
    for (bool lift : {false, true})
    for (u64 pad : {u64(0), ctx.mPlaintextModulus - 1})
    {
        std::vector<u64> labels(count);
        for (std::size_t i = 0; i != count; ++i) labels[i] = i % ctx.mPlaintextModulus;
        std::vector<RnsPoly> expected, actual;
        // Independent per-ring encoding oracle, outside the async batch scheduler.
        expected.resize(zpRingLabelCount(ctx, labels.size()));
        for (std::size_t i = 0; i != expected.size(); ++i)
        {
            const auto offset = i * slots;
            const auto size = std::min<std::size_t>(slots, labels.size() - offset);
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(ctx,
                std::span<const u64>(labels).subspan(offset, size), lift, pad, 1, expected[i]));
        }
        auto operation = wrapZpLabelsCrt(executor, buffers, ctx, labels, lift, pad, 3, actual);
        LOGVOLE_REQUIRE_TRUE(actual.empty());
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(operation))));
        equal(actual, expected);
        std::vector<const u64*> outputs;
        for (const auto& poly : actual) outputs.push_back(poly.mCoeffs.data());
        for (std::size_t allowance : {1u, 2u, 3u})
        {
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(wrapZpLabelsCrt(executor,
                std::span(buffers).first(allowance), ctx, labels, lift, pad, static_cast<u32>(allowance), actual))));
            equal(actual, expected);
            for (std::size_t i = 0; i != outputs.size(); ++i)
                LOGVOLE_REQUIRE_TRUE(outputs[i] == actual[i].mCoeffs.data());
        }
        for (std::size_t i = 0; i != buffers.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(slotStorage[i] == buffers[i].mSlots.data());
            LOGVOLE_REQUIRE_TRUE(plainStorage[i] == buffers[i].mPlain.data());
        }
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(wrapZpLabelsCrt(executor, buffers,
            ctx, labels, lift, ctx.mPlaintextModulus, 3, actual)));
        equal(actual, expected);
        if (count > slots)
        {
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(wrapZpLabelsCrt(executor,
                std::span(buffers).first(1), ctx, labels, lift, pad, 3, actual)));
            equal(actual, expected);
        }
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(wrapZpLabelsCrt(executor, {},
            ctx, labels, lift, pad, 3, actual)));
        equal(actual, expected);
    }
    // One chunk must complete without any running worker threads.
    macoro::thread_pool idle;
    std::vector<u64> labels(2 * slots + 7, 1);
    std::vector<RnsPoly> actual;
    CpuBenchmarkContext telemetry;
    telemetry.mCpus = {0, 1, 2};
    telemetry.mWorkerLimit = 1;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(wrapZpLabelsCrt(executor, buffers,
        ctx, labels, false, 0, 3, actual, CpuBenchmarkState{&telemetry}))));
    telemetry.reset();
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(wrapZpLabelsCrt(idle, buffers,
        ctx, labels, false, 0, 1, actual, CpuBenchmarkState{&telemetry})));
    LOGVOLE_REQUIRE_EQ(telemetry.mPeakTaskThreads.load(), 1u);
}

void LogVole_Cpu_AsyncOutputUnwrapping(const oc::CLP& cmd)
{
    std::array<ZpEncodeBuffer, 3> crtEncodeBuffers;
    std::array<ZpDecodeBuffer, 3> crtDecodeBuffers;
    RingParams params;
    params.mPolyModulusDegree = 1024;
    assignValues<int>(params.mCoeffModulusBits, {52, 52, 52, 52});
    ZpCrtContext ctx;
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, ctx));
    auto scalar = ctx;
    scalar.mRing.mCpuCapabilities = osuCrypto::CpuCapabilities(osuCrypto::CpuCapabilities::Mode::Scalar);
    const auto slots = zpSlotCount(ctx);
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(cmd.getOr("executor_threads", 1));
    std::array<ZpDecodeBuffer, 3> buffers;
    std::array<std::array<const u64*, 4>, 3> storage;
    for (std::size_t i = 0; i != buffers.size(); ++i)
    {
        auto& b = buffers[i];
        b.mPlain.resize(slots);
        b.mSlots.resize(slots);
        b.mCanonical.mCoeffs.resize(ringPolyCoeffCount(params));
        b.mComposed.resize(ringPolyCoeffCount(params));
        storage[i] = {b.mPlain.data(), b.mSlots.data(), b.mCanonical.mCoeffs.data(), b.mComposed.data()};
    }
    auto onPool = [&](macoro::task<bool> operation) -> macoro::task<bool> {
        co_await executor.schedule();
        co_return co_await std::move(operation);
    };
    for (std::size_t count : {std::size_t(0), std::size_t(1), std::size_t(slots), std::size_t(2 * slots + 7)})
    for (bool rounded : {false, true})
    {
        std::vector<u64> labels(count);
        for (std::size_t i = 0; i != count; ++i) labels[i] = (i * 137) % ctx.mPlaintextModulus;
        std::vector<RnsPoly> ring;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(wrapZpLabelsCrt(executor, crtEncodeBuffers, ctx, labels, rounded, 0, 1, ring)));
        // Noncanonical residues exercise the existing canonical fallback as well
        // as SIMD dispatch; both must retain exactly the same scalar outputs.
        for (auto& poly : ring)
            for (std::size_t j = 0; j != ctx.mRing.mModuli.size(); ++j)
                for (std::size_t i = 0; i != slots; ++i)
                    poly.mCoeffs[j * slots + i] += ringModulusValue(ctx.mRing, j);
        AlignedUnVec<u64> expected, actual;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(executor, crtDecodeBuffers, scalar, ring, count, rounded, 1, expected)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, labels));
        for (const auto* selected : {&ctx, &scalar})
        for (std::size_t allowance : {1u, 2u, 3u})
        {
            auto operation = unwrapRingLabelsCrt(executor, std::span(buffers).first(allowance),
                *selected, ring, count, rounded, static_cast<u32>(allowance), actual);
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(operation))));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
            const auto outputStorage = actual.data();
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(unwrapRingLabelsCrt(executor,
                std::span(buffers).first(allowance), *selected, ring, count, rounded, static_cast<u32>(allowance), actual))));
            LOGVOLE_REQUIRE_TRUE(actual.data() == outputStorage);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
        }
        for (std::size_t i = 0; i != buffers.size(); ++i)
        {
            const auto& b = buffers[i];
            LOGVOLE_REQUIRE_TRUE(storage[i] == (std::array<const u64*, 4>{b.mPlain.data(),
                b.mSlots.data(), b.mCanonical.mCoeffs.data(), b.mComposed.data()}));
        }
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(unwrapRingLabelsCrt(executor, {},
            ctx, ring, count, rounded, 3, actual)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
        if (count > slots)
        {
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(unwrapRingLabelsCrt(executor,
                std::span(buffers).first(1), ctx, ring, count, rounded, 3, actual)));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
        }
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(unwrapRingLabelsCrt(executor, buffers,
            ctx, ring, ring.size() * slots + 1, rounded, 3, actual)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
        if (!ring.empty())
        {
            ring[0].mCoeffs.resize(1);
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(unwrapRingLabelsCrt(executor, buffers,
                ctx, ring, count, rounded, 3, actual)));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
        }
    }
    // Explicit budget of one runs inline even with several available buffers.
    macoro::thread_pool idle;
    std::vector<u64> labels(2 * slots + 7, 1);
    std::vector<RnsPoly> ring;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(wrapZpLabelsCrt(executor, crtEncodeBuffers, ctx, labels, false, 0, 1, ring)));
    AlignedUnVec<u64> actual;
    CpuBenchmarkContext telemetry;
    telemetry.mCpus = {0, 1, 2};
    telemetry.mWorkerLimit = 1;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(unwrapRingLabelsCrt(executor, buffers, ctx,
        ring, labels.size(), false, 3, actual, CpuBenchmarkState{&telemetry}))));
    telemetry.reset();
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(idle, buffers, ctx,
        ring, labels.size(), false, 1, actual, CpuBenchmarkState{&telemetry})));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, labels));
    LOGVOLE_REQUIRE_EQ(telemetry.mPeakTaskThreads.load(), 1u);
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(idle,
        std::span(buffers).first(1), ctx, ring, labels.size(), false, 0, actual)));
}

void LogVole_Cpu_CrtMatchesSeal(const oc::CLP&)
{
    PRNG random(toBlock(0xA18, 0x671));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        for (std::size_t count : {7, 8, 9, 127, 1024})
        for (unsigned trial = 0; trial < 8; ++trial)
        {
            std::vector<u64> source(limbs * count), actual(source.size(), 12345);
            for (unsigned j = 0; j < limbs; ++j)
            for (unsigned i = 0; i < count; ++i)
            {
                const u64 q = ringModulusValue(ctx, j);
                source[j * count + i] = i < 4 ? std::array<u64,4>{0,1,q-1,q/2}[i]
                    : random.get<u64>() % q;
            }
            auto expected = source;
            base.compose_array(expected.data(), count, seal::MemoryManager::GetPool());
            const bool used = LogVole::cpuComposeRns(ctx.mCpuCapabilities, source.data(), actual.data(), count, base);
            if (used) LOGVOLE_REQUIRE_TRUE(actual == expected);
            else LOGVOLE_REQUIRE_TRUE(std::all_of(actual.begin(), actual.end(), [](u64 v) { return v == 12345; }));
        }
    }
}

void LogVole_Cpu_CrtMixedWidthsMatchSeal(const oc::CLP&)
{
    PRNG random(toBlock(0x435254, 0x20260910));
    for (unsigned limbs : {4, 8})
    for (int topBits : {52, 55})
    {
        const std::size_t count = 1024;
        RingParams params{};
        params.mPolyModulusDegree = count;
        params.mCoeffModulusBits.resize(limbs);
        for (unsigned j = 0; j < limbs; ++j) params.mCoeffModulusBits[j] = j%2 ? topBits : 30+j;
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        std::vector<u64> input(limbs*count), actual(input.size(), 12345);
        for (unsigned j = 0; j < limbs; ++j)
        {
            const u64 q = ringModulusValue(ctx, j);
            for (std::size_t i = 0; i < count; ++i)
                input[j*count+i] = i < 2 ? (i ? q-1 : 0) : random.get<u64>() % q;
        }
        auto expected = input;
        base.compose_array(expected.data(), count, seal::MemoryPoolHandle::ThreadLocal());
        if (LogVole::cpuComposeRns(ctx.mCpuCapabilities, input.data(), actual.data(), count, base))
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        else LOGVOLE_REQUIRE_TRUE(std::all_of(actual.begin(), actual.end(), [](u64 x) { return x == 12345; }));
        const osuCrypto::CpuCapabilities scalar(osuCrypto::CpuCapabilities::Mode::Scalar);
        LOGVOLE_REQUIRE_FALSE(scalar.avx512());
        LOGVOLE_REQUIRE_FALSE(scalar.ifma());
        // Alternate independent dispatch objects; both must reconstruct exactly
        // the same integers, without changing the other object's selection.
        for (const auto* dispatch : std::array<const osuCrypto::CpuCapabilities*, 3>{
            &ctx.mCpuCapabilities, &scalar, &ctx.mCpuCapabilities})
        {
            std::fill(actual.begin(), actual.end(), u64{12345});
            LOGVOLE_REQUIRE_TRUE(LogVole::cpuComposeRns(
                *dispatch, input.data(), actual.data(), count, base));
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }

        auto manual = ctx;
        manual.mCpuCapabilities = scalar;
        RnsPoly poly;
        poly.mCoeffs.resize(input.size());
        std::copy(input.begin(), input.end(), poly.mCoeffs.begin());
        std::vector<RnsPoly> cachedDigits, manualDigits;
        LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, topBits, 0, 1, ctx, cachedDigits));
        LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, topBits, 0, 1, manual, manualDigits));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(cachedDigits[0].mCoeffs, manualDigits[0].mCoeffs));
        LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, topBits, 1, 1, ctx, cachedDigits));
        LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, topBits, 1, 1, manual, manualDigits));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(cachedDigits[0].mCoeffs, manualDigits[0].mCoeffs));

    }
}

void LogVole_Cpu_WitnessMatchesSequentialReference(const oc::CLP& cmd)
{
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(cmd.getOr("executor_threads", 1));
    auto onPool = [&](macoro::task<bool> operation) -> macoro::task<bool> {
        co_await executor.schedule();
        co_return co_await std::move(operation);
    };
    for (u64 width : {1, 7, 8, 9, 1031})
    for (u64 depth : {1, 3})
    for (u64 modulus : {u64{257}, u64{2251799813554177}, u64{18014398508400641}})
    {
        const block circuitSeed = toBlock(0x7472, width);
        ZkMulCircuit circuit{};
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuit(width*depth, depth, circuitSeed, circuit));
        PRNG wiring(circuitSeed);
        for (u64 g = 0; g < circuit.gateCount(); ++g)
        {
            LOGVOLE_REQUIRE_EQ(circuit.mOperands[2*g], (g/width)*width+wiring.get<u64>()%width);
            LOGVOLE_REQUIRE_EQ(circuit.mOperands[2*g+1], (g/width)*width+wiring.get<u64>()%width);
        }
        const std::vector<u32> originalOperands(circuit.mOperands.begin(), circuit.mOperands.end());
        // No dependent layers, a dependent first layer followed by parallel
        // work, and entirely dependent layers (which must stay serial).
        for (u64 dependentLayers : {u64{0}, u64{1}, depth})
        {
            std::copy(originalOperands.begin(), originalOperands.end(), circuit.mOperands.begin());
            for (u64 g = 0; g < width * dependentLayers; ++g)
                circuit.mOperands[2*g] = static_cast<u32>(circuit.outputWire(g)-1);
            PRNG original(toBlock(0x7878, width));
            std::vector<u64> expected(circuit.voleCount()+13, 0);
            for (u64 i = 0; i < width; ++i) expected[i] = original.get<u64>() % modulus;
            for (u64 g = 0; g < circuit.gateCount(); ++g)
                expected[circuit.outputWire(g)] = static_cast<host_oracle::Uint128>(expected[circuit.mOperands[2*g]]) *
                    expected[circuit.mOperands[2*g+1]] % modulus;
            expected[circuit.maskIndex()] = original.get<u64>() % modulus;
            const auto next = original.get<block>();
            for (u32 workers : {0, 1, 2, 4})
            {
                PRNG optimized(toBlock(0x7878, width));
                AlignedUnVec<u64> actual;
                actual.resize(expected.size());
                const auto* storage = actual.data();
                LOGVOLE_REQUIRE_TRUE(zkMulWitness(circuit, modulus, optimized, actual, expected.size()));
                LOGVOLE_REQUIRE_TRUE(actual.data() == storage);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
                LOGVOLE_REQUIRE_TRUE(optimized.get<block>() == next);
                ZkMulCpuWorkspace workspace(circuit, workers);
                for (unsigned repeat = 0; repeat < 2; ++repeat)
                {
                    PRNG replay(toBlock(0x7878, width));
                    std::fill(actual.begin(), actual.end(), ~u64{0});
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(zkMulWitness(executor,
                        circuit, modulus, replay, actual, expected.size(), workspace))));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
                    LOGVOLE_REQUIRE_TRUE(replay.get<block>() == next);
                }
            }
        }
    }
}

void LogVole_Cpu_GpuZkSeededPreparationMatchesReference(const oc::CLP& cmd)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)

    const bool wantGpu = cmd.getOr("gpu", 0) != 0;
    if (wantGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!wantGpu || !gpu::available()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    PRNG pairedProofRoots(sysRandomSeed());
    // Exact raw Barrett generation, including non-primes and both endpoints
    // of the supported interval. CPU SEAL is the independent oracle here.
    for (auto role : {ProtocolCacheRole::Sender, ProtocolCacheRole::Receiver})
    {
        (void)role; // Raw ZK arithmetic owns its streams and has no protocol identity.
        if (!gpu::available()) continue;
        gpu::GpuExecutionContext constantsExecution;
        auto& constantsStream = constantsExecution.mainStream();
        for (u64 modulus : {2ULL, 4ULL, 257ULL, 1000ULL, 2251799813554177ULL,
                18014398508400641ULL, (1ULL << 61u) - 1u})
        {
            const seal::Modulus reference(modulus);
            gpu::HostModulus actual;
            LOGVOLE_REQUIRE_TRUE(gpu::prepareZkModulusDevice(modulus, actual, constantsStream));
            LOGVOLE_REQUIRE_EQ(actual.mValue, modulus);
            LOGVOLE_REQUIRE_EQ(actual.mRatio0, reference.const_ratio()[0]);
            LOGVOLE_REQUIRE_EQ(actual.mRatio1, reference.const_ratio()[1]);
            gpu::HostModulus cached;
            LOGVOLE_REQUIRE_TRUE(gpu::prepareZkModulusDevice(modulus, cached, constantsStream));
            LOGVOLE_REQUIRE_EQ(cached.mRatio0, actual.mRatio0);
            LOGVOLE_REQUIRE_EQ(cached.mRatio1, actual.mRatio1);
            for (u64 delta : std::array<u64, 4>{0, 1, modulus - 1u, ~u64(0)})
            for (const auto proof : {ZkProof{0, 0}, ZkProof{modulus - 1u, modulus - 1u},
                    ZkProof{~u64(0), ~u64(0)}})
            {
                const u64 expected = host_oracle::remainder(host_oracle::add(
                    host_oracle::multiply(proof.mV, delta), {proof.mU % modulus, 0}), modulus);
                bool accepted = false;
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, expected, delta, modulus, accepted, constantsStream));
                LOGVOLE_REQUIRE_TRUE(accepted && zkAccept(proof, expected, delta, modulus));
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, modulus, delta, modulus, accepted, constantsStream));
                LOGVOLE_REQUIRE_TRUE(!accepted && !zkAccept(proof, modulus, delta, modulus));
            }
        }
    }
    for (u64 invalid : {0ULL, 1ULL, 1ULL << 61u, ~0ULL})
    {
        gpu::HostModulus retained{17, 23, 31};
        bool accepted = true;
        LOGVOLE_REQUIRE_TRUE(!gpu::prepareZkModulusDevice(invalid, retained, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(retained.mValue == 17 && retained.mRatio0 == 23 && retained.mRatio1 == 31);
        LOGVOLE_REQUIRE_TRUE(!gpu::zkAcceptDevice(ZkProof{}, 0, 0, invalid, accepted, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(accepted);
    }
    for (u64 width : {1, 7, 8, 1031})
    for (u64 depth : {1, 3})
    {
        const u64 budget = width * (depth + 1) + 1;
        const block circuitSeed = toBlock(0x5647, width + depth);
        ZkMulCircuit reference, actual;
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuitForBudget(budget, depth, circuitSeed, reference));
        LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(budget, depth, circuitSeed, actual, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_EQ(actual.mWidth, reference.mWidth);
        LOGVOLE_REQUIRE_EQ(actual.mDepth, reference.mDepth);
        LOGVOLE_REQUIRE_TRUE(actual.mOperands.empty());
        LOGVOLE_REQUIRE_TRUE(actual.mOperandsDevice != nullptr);
        ZkMulCircuit copied = actual;
        LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());
        LOGVOLE_REQUIRE_TRUE(copied.mOperandsDevice == actual.mOperandsDevice);
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulUploadOperands(actual, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(!gpu::makeZkMulCircuitForBudgetDevice(1, depth, circuitSeed, actual, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(actual.mOperandsDevice == copied.mOperandsDevice);

        ZkMulCircuit detached = copied;
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulDetachOperands(detached, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(detached.mOperands.empty());
        LOGVOLE_REQUIRE_TRUE(detached.mOperandsDevice != copied.mOperandsDevice);
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(detached, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(detached.mOperands, reference.mOperands));
        const auto detachedOwner = detached.mOperandsDevice;
        detached.mDepth = std::numeric_limits<u64>::max();
        LOGVOLE_REQUIRE_TRUE(!gpu::zkMulDetachOperands(detached, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(detached.mOperandsDevice == detachedOwner);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(detached.mOperands, reference.mOperands));
        detached.mDepth = depth;

        if (width == 7 && depth == 3)
        {
            const auto configureService = ProtocolCacheService::create();
            const ProtocolCacheScope configureScope(configureService->allocate(), ProtocolCacheRole::Sender);
            // Role ablations may intentionally disable the verifier's GPU.
            if (gpu::available())
            for (auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
            {
                const u32 bits = setting == CivoleSetting::GoldenSeed ? 55 : 52;
                LogVoleOptions sessionOptions;
                sessionOptions.mPlaintextModulusBits = bits;
                sessionOptions.mSetting = setting;
                sessionOptions.mRequestSize = budget;
                ZkMulProver reconfiguredProver({}, sessionOptions);
                reconfiguredProver.mUseDevice = true;
                reconfiguredProver.mDeviceState = gpu::makeZkMulDeviceState(copied, operationExecution.mainStream());
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mDeviceState != nullptr);
                reconfiguredProver.prepare(copied, nullptr, configureScope);
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mCircuit.mOperandsDevice == copied.mOperandsDevice);
                ZkMulVerifier verifier({}, sessionOptions);
                verifier.mUseDevice = true;
                verifier.mDeviceState = std::make_shared<int>(1);
                verifier.prepare(copied, nullptr, configureScope);
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != copied.mOperandsDevice);
                const auto firstOwner = verifier.mCircuit.mOperandsDevice;

                ZkMulCircuit invalid = copied;
                invalid.mDepth += 1;
                const auto priorState = std::make_shared<int>(2);
                verifier.mDeviceState = priorState;
                bool threw = false;
                try { verifier.prepare(invalid, nullptr, configureScope); }
                catch (const std::runtime_error&) { threw = true; }
                LOGVOLE_REQUIRE_TRUE(threw);
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == priorState);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice == firstOwner);

                verifier.prepare(copied, nullptr, configureScope);
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != firstOwner);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != copied.mOperandsDevice);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(verifier.mCircuit, operationExecution.mainStream()));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(verifier.mCircuit.mOperands, reference.mOperands));

                // CPU configuration retains the public API's eager host access,
                // while leaving the caller's device-only snapshot unchanged.
                ZkMulVerifier hostVerifier({}, sessionOptions);
                hostVerifier.prepare(copied, nullptr, configureScope);
                LOGVOLE_REQUIRE_TRUE(hostVerifier.mCircuit.mOperandsDevice == nullptr);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(hostVerifier.mCircuit.mOperands, reference.mOperands));
                LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());

                // A public host edit supersedes an older device snapshot.
                ZkMulCircuit edited = copied;
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(edited, operationExecution.mainStream()));
                edited.mOperands[0] = (edited.mOperands[0] + 1) % width;
                verifier.prepare(edited, nullptr, configureScope);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice == nullptr);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(verifier.mCircuit.mOperands, edited.mOperands));
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.data() != edited.mOperands.data());

                // A circuit independently generated by this role transfers its
                // unique allocation without a D2D clone or host round trip.
                ZkMulCircuit unique;
                LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(
                    budget, depth, circuitSeed, unique, operationExecution.mainStream()));
                LOGVOLE_REQUIRE_EQ(unique.mOperandsDevice.use_count(), 1);
                const void* uniqueOwner = unique.mOperandsDevice.get();
                verifier.mDeviceState = std::make_shared<int>(3);
                verifier.prepare(std::move(unique), nullptr, configureScope);
                LOGVOLE_REQUIRE_TRUE(unique.mOperandsDevice == nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice.get() == uniqueOwner);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(verifier.mCircuit, operationExecution.mainStream()));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(verifier.mCircuit.mOperands, reference.mOperands));

                ZkMulCircuit invalidUnique;
                LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(
                    budget, depth, circuitSeed, invalidUnique, operationExecution.mainStream()));
                LOGVOLE_REQUIRE_EQ(invalidUnique.mOperandsDevice.use_count(), 1);
                invalidUnique.mDepth += 1;
                threw = false;
                try { verifier.prepare(std::move(invalidUnique), nullptr, configureScope); }
                catch (const std::runtime_error&) { threw = true; }
                LOGVOLE_REQUIRE_TRUE(threw);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice.get() == uniqueOwner);

                if (setting == CivoleSetting::GoldenSeed)
                {
                    // Configuration can precede a decision to run the proof
                    // on the CPU. Exercise both real protocol fallbacks before
                    // their first host access, using a CPU VOLE session.
                    auto fallbackOptions = sessionOptions;
                    fallbackOptions.mNumThreads = 2;
                    ZkMulVerifier fallbackVerifier({}, fallbackOptions);
                    fallbackVerifier.mUseDevice = true;
                    fallbackVerifier.prepare(copied, nullptr, configureScope);
                    tests_libOTe::logvole_test::SenderResources fallbackVerifierResources(fallbackVerifier.mVole.options());
                    tests_libOTe::logvole_test::ReceiverBuffers fallbackVerifierResourcesReceiverBuffers(fallbackVerifier.mVole.options());
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mCircuit.mOperands.empty());
                    const auto fallbackOwner = fallbackVerifier.mCircuit.mOperandsDevice;
                    ZkMulProver fallbackProver({}, fallbackOptions);
                    fallbackProver.mUseDevice = true;
                    fallbackProver.prepare(copied, nullptr, configureScope);
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperands.empty());
                    const auto fallbackProverOwner = fallbackProver.mCircuit.mOperandsDevice;
                    fallbackVerifier.mUseDevice = false;
                    fallbackProver.mUseDevice = false;
                    PRNG witnessPrng(toBlock(0x46414c4c, 1));
                    AlignedUnVec<u64> witness;
                    LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, fallbackProver.modulus(),
                        witnessPrng, witness, budget));
                    PRNG senderPrng(toBlock(0x46414c4c, 2));
                    PRNG receiverPrng(toBlock(0x46414c4c, 3));
                    auto sockets = coproto::LocalAsyncSocket::makePair();
                    auto offline = macoro::sync_wait(macoro::when_all_ready(
                        fallbackVerifier.offline(setupResources.executor, setupResources.results, 19, senderPrng, sockets[0]),
                        fallbackProver.offline(sockets[1])));
                    std::get<0>(offline).result();
                    std::get<1>(offline).result();
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mCircuit.mOperands.empty());
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperands.empty());
                    auto online = macoro::sync_wait(macoro::when_all_ready(
                        fallbackVerifier.verify(fallbackVerifierResources.executor, fallbackVerifierResources.buffers, fallbackVerifierResources.unwrap, senderPrng, sockets[0]),
                        fallbackProver.prove(fallbackVerifierResources.executor, fallbackVerifierResourcesReceiverBuffers.lhe, fallbackVerifierResourcesReceiverBuffers.lenc, fallbackVerifierResourcesReceiverBuffers.zeta, fallbackVerifierResourcesReceiverBuffers.wrap, fallbackVerifierResourcesReceiverBuffers.unwrap, witness, receiverPrng, sockets[1])));
                    std::get<0>(online).result();
                    std::get<1>(online).result();
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mAccepted);
                    LOGVOLE_REQUIRE_TRUE(!fallbackVerifier.mCheckOnDevice);
                    LOGVOLE_REQUIRE_TRUE(!fallbackProver.mCheckOnDevice);
                    LOGVOLE_REQUIRE_TRUE(!fallbackVerifier.mAcceptOnDevice);
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(fallbackVerifier.mCircuit.mOperands, reference.mOperands));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(fallbackProver.mCircuit.mOperands, reference.mOperands));
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mCircuit.mOperandsDevice == fallbackOwner);
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperandsDevice == fallbackProverOwner);
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperands.data() !=
                        fallbackVerifier.mCircuit.mOperands.data());
                    LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());
                    LOGVOLE_REQUIRE_TRUE(fallbackOwner != copied.mOperandsDevice);
                    ZkMulCpuWorkspace hostWorkspace(reference, 1);
                    ZkProof hostProof;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(
                        setupResources.executor, reference, witness, fallbackProver.mMacs,
                        fallbackProver.mLastChallenge, fallbackProver.modulus(), hostWorkspace, hostProof)));
                    LOGVOLE_REQUIRE_EQ(fallbackProver.mLastProof.mU, hostProof.mU);
                    LOGVOLE_REQUIRE_EQ(fallbackProver.mLastProof.mV, hostProof.mV);
                    u64 hostValue = 0;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(setupResources.executor, reference, fallbackVerifier.mKeys,
                        fallbackVerifier.mLastChallenge, 19, fallbackVerifier.modulus(), hostWorkspace, hostValue)));
                    LOGVOLE_REQUIRE_EQ(fallbackVerifier.mLastValue, hostValue);
                }

                bool receiverGpu = false;
                {
                    receiverGpu = gpu::available();
                }
                if (setting == CivoleSetting::GoldenSeed && receiverGpu)
                for (bool acceptOnDevice : {true, false})
                {
                    // The protocol wrapper must use GPU acceptance by default
                    // and preserve its explicit host rollback on a separately configured pair.
                    LogVoleZkOptions proofSettings;
                    proofSettings.mDeviceAcceptance = acceptOnDevice;
                    LogVoleOptions voleOptions = sessionOptions;
                    voleOptions.mUseGpu = true;
                    ZkMulVerifier gpuVerifier(proofSettings, voleOptions);
                    ZkMulProver gpuProver(proofSettings, voleOptions);
                    gpuVerifier.mUseDevice = gpuProver.mUseDevice = true;
                    gpuVerifier.prepare(copied, nullptr, configureScope);
                    tests_libOTe::logvole_test::SenderResources gpuVerifierResources(gpuVerifier.mVole.options());
                    tests_libOTe::logvole_test::ReceiverBuffers gpuVerifierResourcesReceiverBuffers(gpuVerifier.mVole.options());
                    gpuProver.prepare(copied, nullptr, configureScope);
                    // Each fixture has fresh party seeds. The host witness and
                    // its GPU token intentionally share one seed for exact parity.
                    const block witnessSeed = pairedProofRoots.get<block>();
                    PRNG witnessPrng(witnessSeed),
                        senderPrng(pairedProofRoots.get<block>()),
                        receiverPrng(pairedProofRoots.get<block>());
                    AlignedUnVec<u64> witness;
                    LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, gpuProver.modulus(), witnessPrng, witness, budget));
                    gpuProver.mWiresDevice = gpu::zkMulWitnessDevice(copied, gpuProver.modulus(), witnessSeed, budget, operationExecution.mainStream());
                    LOGVOLE_REQUIRE_TRUE(gpuProver.mWiresDevice != nullptr);
                    auto sockets = coproto::LocalAsyncSocket::makePair();
                    auto offline = macoro::sync_wait(macoro::when_all_ready(
                        gpuVerifier.offline(setupResources.executor, setupResources.results, 19, senderPrng, sockets[0]), gpuProver.offline(sockets[1])));
                    std::get<0>(offline).result();
                    std::get<1>(offline).result();
                    {
                        const bool deviceOnly = !acceptOnDevice;
                        gpuVerifier.mDeviceOnlyHostSpans = deviceOnly;
                        gpuProver.mDeviceOnlyHostSpans = deviceOnly;
                        gpuProver.mVoleDeviceInput = deviceOnly;
                        if (deviceOnly)
                        {
                            // A present but undersized device handle must fail
                            // before either socket or query seed is consumed.
                            auto prior = gpuProver.mWiresDevice;
                            auto undersized = std::make_shared<gpu::DeviceScalars>();
                            LOGVOLE_REQUIRE_TRUE(undersized->resize(budget - 1u, operationExecution.mainStream()));
                            gpuProver.mWiresDevice = undersized;
                            bool rejected = false;
                            try
                            {
                                macoro::sync_wait(gpuProver.prove(gpuVerifierResources.executor, gpuVerifierResourcesReceiverBuffers.lhe, gpuVerifierResourcesReceiverBuffers.lenc, gpuVerifierResourcesReceiverBuffers.zeta, gpuVerifierResourcesReceiverBuffers.wrap, gpuVerifierResourcesReceiverBuffers.unwrap,
                                    std::span<u64>{}, receiverPrng, sockets[1]));
                            }
                            catch (const std::runtime_error&) { rejected = true; }
                            gpuProver.mWiresDevice = std::move(prior);
                            LOGVOLE_REQUIRE_TRUE(rejected);
                        }
                        auto online = macoro::sync_wait(macoro::when_all_ready(
                            gpuVerifier.verify(gpuVerifierResources.executor, gpuVerifierResources.buffers, gpuVerifierResources.unwrap, senderPrng, sockets[0]),
                            gpuProver.prove(gpuVerifierResources.executor, gpuVerifierResourcesReceiverBuffers.lhe, gpuVerifierResourcesReceiverBuffers.lenc, gpuVerifierResourcesReceiverBuffers.zeta, gpuVerifierResourcesReceiverBuffers.wrap, gpuVerifierResourcesReceiverBuffers.unwrap, deviceOnly ? std::span<u64>{}
                                : std::span<u64>(witness.data(), witness.size()),
                                receiverPrng, sockets[1])));
                        std::get<0>(online).result();
                        std::get<1>(online).result();
                        LOGVOLE_REQUIRE_TRUE(gpuVerifier.mAccepted);
                        LOGVOLE_REQUIRE_TRUE(gpuVerifier.mCheckOnDevice && gpuProver.mCheckOnDevice);
                        LOGVOLE_REQUIRE_EQ(gpuVerifier.mAcceptOnDevice, acceptOnDevice);
                        LOGVOLE_REQUIRE_EQ(gpuVerifier.mKeys.empty(), deviceOnly);
                        LOGVOLE_REQUIRE_EQ(gpuProver.mMacs.empty(), deviceOnly);
                        if (deviceOnly)
                        {
                            LOGVOLE_REQUIRE_EQ(gpuVerifier.mVole.outputDeviceCount(), budget);
                            LOGVOLE_REQUIRE_EQ(gpuProver.mVole.outputDeviceCount(), budget);
                            auto keysDevice = std::static_pointer_cast<gpu::DeviceScalars>(
                                gpuVerifier.mVole.outputDevice());
                            auto macsDevice = std::static_pointer_cast<gpu::DeviceScalars>(
                                gpuProver.mVole.outputDevice());
                            auto witnessDevice = std::static_pointer_cast<gpu::DeviceScalars>(
                                gpuProver.mWiresDevice);
                            LOGVOLE_REQUIRE_TRUE(keysDevice && macsDevice && witnessDevice);
                            AlignedUnVec<u64> keys, macs, downloadedWitness;
                            keys.resize(budget);
                            macs.resize(budget);
                            downloadedWitness.resize(budget);
                            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*keysDevice, keys, readbackExecution.readbackStream()));
                            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*macsDevice, macs, readbackExecution.readbackStream()));
                            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*witnessDevice, downloadedWitness, readbackExecution.readbackStream()));
                            witness[reference.maskIndex()] = downloadedWitness[reference.maskIndex()];
                            LOGVOLE_REQUIRE_TRUE(rangesEqual(downloadedWitness, witness));
                            const seal::Modulus modulus(gpuProver.modulus());
                            for (std::size_t i = 0; i < budget; ++i)
                                LOGVOLE_REQUIRE_EQ(macs[i], mulAddMod(witness[i], 19u, keys[i], modulus));
                            ZkMulCpuWorkspace hostWorkspace(reference, 1);
                            ZkProof hostProof;
                            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(setupResources.executor, reference, witness, macs,
                                gpuProver.mLastChallenge, gpuProver.modulus(), hostWorkspace, hostProof)));
                            LOGVOLE_REQUIRE_EQ(gpuProver.mLastProof.mU, hostProof.mU);
                            LOGVOLE_REQUIRE_EQ(gpuProver.mLastProof.mV, hostProof.mV);
                        }
                    }
                }
            }
        }
        for (u64 modulus : {257ULL, 2251799813554177ULL, 18014398508400641ULL})
        {
            const block witnessSeed = toBlock(modulus, width);
            PRNG referencePrng(witnessSeed);
            AlignedUnVec<u64> expected, fetched;
            LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, modulus, referencePrng, expected, budget + 13));
            // Exercise host-empty wiring before materializing any CPU copy.
            auto device = gpu::zkMulWitnessDevice(copied, modulus, witnessSeed, budget + 13, operationExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(device != nullptr);
            fetched.resize(expected.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, std::span<u64>(fetched.data(), fetched.size()), readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, fetched));
            // Host witness preparation uploads only the input scalars to the
            // host, then evaluates the same circuit through this GPU overload.
            PRNG hostInputPrng(witnessSeed);
            AlignedUnVec<u64> hostInputs;
            hostInputs.resize(static_cast<std::size_t>(width + 1));
            for (auto& value : hostInputs) value = hostInputPrng.get<u64>() % modulus;
            LOGVOLE_REQUIRE_TRUE(hostInputPrng.get<block>() == referencePrng.get<block>());
            auto hostPrepared = gpu::zkMulWitnessDevice(reference, modulus,
                std::span<const u64>(hostInputs.data(), hostInputs.size()), budget + 13, operationExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(hostPrepared != nullptr);
            AlignedUnVec<u64> hostPreparedWitness;
            hostPreparedWitness.resize(expected.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*hostPrepared,
                std::span<u64>(hostPreparedWitness.data(), hostPreparedWitness.size()), readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, hostPreparedWitness));
            LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(actual, operationExecution.mainStream()));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mOperands, reference.mOperands));
            LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());

            PRNG labelPrng(toBlock(width, modulus));
            std::vector<u64> macs(budget), keys(budget);
            const seal::Modulus mod(modulus);
            for (u64 i = 0; i < budget; ++i)
            {
                macs[i] = labelPrng.get<u64>() % modulus;
                keys[i] = (macs[i] + modulus - mulMod(expected[i], 19, mod)) % modulus;
            }
            ZkMulCpuWorkspace referenceWorkspace(reference, 1), actualWorkspace(actual, 4);
            ZkProof referenceProof, actualProof;
            u64 referenceValue = 0, actualValue = 0;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(
                setupResources.executor, reference, expected, macs, 73, modulus, referenceWorkspace, referenceProof)));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(
                setupResources.executor, actual, fetched, macs, 73, modulus, actualWorkspace, actualProof)));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(
                setupResources.executor, reference, keys, 73, 19, modulus, referenceWorkspace, referenceValue)));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(
                setupResources.executor, actual, keys, 73, 19, modulus, actualWorkspace, actualValue)));
            LOGVOLE_REQUIRE_EQ(referenceProof.mU, actualProof.mU);
            LOGVOLE_REQUIRE_EQ(referenceProof.mV, actualProof.mV);
            LOGVOLE_REQUIRE_EQ(referenceValue, actualValue);
            LOGVOLE_REQUIRE_TRUE(zkAccept(actualProof, actualValue, 19, modulus));

            // Exercise the production GPU proof helpers in both constant/power
            // modes, rather than testing only the witness kernel.
            auto deviceMacs = gpu::uploadScalars(macs, operationExecution.mainStream());
            auto deviceKeys = gpu::uploadScalars(keys, operationExecution.mainStream());
            auto proverState = gpu::makeZkMulDeviceState(copied, operationExecution.mainStream());
            auto verifierState = gpu::makeZkMulDeviceState(copied, operationExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(deviceMacs && deviceKeys && proverState && verifierState);
            for (const char* mode : {"1", "0"})
            {
                LogVoleZkOptions proofSettings;
                proofSettings.mDeviceConstants = mode[0] == '1';
                proofSettings.mGpuPseudoReduce = mode[0] == '1';
                ZkProof proof;
                u64 value = 0;
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulProverResponseDevice(
                    copied, *device, *deviceMacs, 73, modulus, *proverState, proof, operationExecution.mainStream(), proofSettings));
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulVerifierValueDevice(
                    copied, *deviceKeys, 73, 19, modulus, *verifierState, value, operationExecution.mainStream(), proofSettings));
                LOGVOLE_REQUIRE_EQ(proof.mU, referenceProof.mU);
                LOGVOLE_REQUIRE_EQ(proof.mV, referenceProof.mV);
                LOGVOLE_REQUIRE_EQ(value, referenceValue);
                bool accepted = false;
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, value, 19, modulus, accepted, operationExecution.mainStream()));
                LOGVOLE_REQUIRE_TRUE(accepted);
                proof.mU = (proof.mU + 1) % modulus;
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, value, 19, modulus, accepted, operationExecution.mainStream()));
                LOGVOLE_REQUIRE_TRUE(!accepted);
            }
        }
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(copied, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_TRUE(copied.mOperands.data() != actual.mOperands.data());
        actual.mOperands[0] ^= 1;
        LOGVOLE_REQUIRE_TRUE(rangesEqual(copied.mOperands, reference.mOperands));
    }
#else
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_Cpu_GpuZkBufferOwnership(const oc::CLP& cmd)
{
    macoro::thread_pool proofExecutor;
    auto proofWork = proofExecutor.make_work();
    proofExecutor.create_threads(1);
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool wantGpu = cmd.getOr("gpu", 0) != 0;
    if (!wantGpu || !gpu::available()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    std::weak_ptr<gpu::OwnedGpuStream> constantsOwner;
    {
        gpu::GpuExecutionContext execution;
        auto& stream = execution.mainStream();
        constantsOwner = stream.allocationOwner();
        for (u64 modulus : {2ULL, 65537ULL, (1ULL << 61) - 1})
        {
            const seal::Modulus expected(modulus);
            for (unsigned repeat = 0; repeat != 2; ++repeat)
            {
                gpu::HostModulus actual{};
                LOGVOLE_REQUIRE_TRUE(gpu::prepareZkModulusDevice(modulus, actual, stream));
                LOGVOLE_REQUIRE_EQ(actual.mValue, modulus);
                LOGVOLE_REQUIRE_EQ(actual.mRatio0, expected.const_ratio()[0]);
                LOGVOLE_REQUIRE_EQ(actual.mRatio1, expected.const_ratio()[1]);
            }
        }
        gpu::HostModulus unchanged{17, 23, 31};
        LOGVOLE_REQUIRE_FALSE(gpu::prepareZkModulusDevice(1, unchanged, stream));
        LOGVOLE_REQUIRE_EQ(unchanged.mValue, 17ULL);
    }
    LOGVOLE_REQUIRE_TRUE(constantsOwner.expired());

    constexpr u64 width = 7, depth = 3, count = width * (depth + 1) + 4;
    constexpr u64 modulus = 65537, delta = 19, chi = 73;
    const block seed = toBlock(0x5a4b4f574e, 7);
    ZkMulCircuit reference;
    LOGVOLE_REQUIRE_TRUE(makeZkMulCircuitForBudget(count, depth, seed, reference));
    PRNG random(toBlock(0x5a4b4f574e, 8));
    AlignedUnVec<u64> witness;
    LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, modulus, random, witness, count));
    std::vector<u64> macs(count), keys(count);
    const seal::Modulus mod(modulus);
    for (u64 i = 0; i < count; ++i)
    {
        macs[i] = random.get<u64>() % modulus;
        keys[i] = (macs[i] + modulus - mulMod(witness[i], delta, mod)) % modulus;
    }
    ZkMulCpuWorkspace expectedWorkspace(reference, 1);
    ZkProof expectedProof;
    u64 expectedValue = 0;
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(
        proofExecutor, reference, witness, macs, chi, modulus, expectedWorkspace, expectedProof)));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(
        proofExecutor, reference, keys, chi, delta, modulus, expectedWorkspace, expectedValue)));

    using Packet = std::tuple<ZkMulCircuit, std::shared_ptr<gpu::ZkMulDeviceState>,
        std::shared_ptr<gpu::ZkMulDeviceState>, gpu::DeviceScalarsPtr,
        gpu::DeviceScalarsPtr, gpu::DeviceScalarsPtr>;
    std::weak_ptr<gpu::OwnedGpuStream> producer, receiver;
    std::weak_ptr<gpu::GpuExecutionContext> producerContext, receiverContext;
    std::packaged_task<Packet()> setup([&] {
        auto execution = std::make_shared<gpu::GpuExecutionContext>();
        producerContext = execution;
        auto& stream = execution->mainStream();
        producer = stream.allocationOwner();
        ZkMulCircuit circuit;
        LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(count, depth, seed, circuit, stream));
        auto x = gpu::uploadScalars(witness, stream);
        auto m = gpu::uploadScalars(macs, stream);
        auto k = gpu::uploadScalars(keys, stream);
        // Queue scratch allocation after the completed input uploads. The
        // first foreign proof must establish its own allocation dependencies.
        auto prover = gpu::makeZkMulDeviceState(circuit, stream);
        auto verifier = gpu::makeZkMulDeviceState(circuit, stream);
        LOGVOLE_REQUIRE_TRUE(prover && verifier && x && m && k);
        return Packet{std::move(circuit), std::move(prover), std::move(verifier),
            std::move(x), std::move(m), std::move(k)};
    });
    auto ready = setup.get_future();
    std::thread worker(std::move(setup));
    worker.join();
    auto [circuit, prover, verifier, x, m, k] = ready.get();
    LOGVOLE_REQUIRE_TRUE(producerContext.expired());
    LOGVOLE_REQUIRE_FALSE(producer.expired());
    auto check = [&](gpu::GpuStream& stream) {
        ZkProof proof;
        u64 value = 0;
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulProverResponseDevice(circuit, *x, *m, chi, modulus, *prover, proof, stream));
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulVerifierValueDevice(circuit, *k, chi, delta, modulus, *verifier, value, stream));
        LOGVOLE_REQUIRE_EQ(proof.mU, expectedProof.mU);
        LOGVOLE_REQUIRE_EQ(proof.mV, expectedProof.mV);
        LOGVOLE_REQUIRE_EQ(value, expectedValue);
        bool accepted = false;
        LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, value, delta, modulus, accepted, stream));
        LOGVOLE_REQUIRE_TRUE(accepted);
    };
    {
        check(operationExecution.mainStream());
        auto wrong = circuit;
        wrong.mWidth = 3;
        wrong.mDepth = 7; // Same gate count, different compiled statement.
        ZkProof unchanged{11, 13};
        LOGVOLE_REQUIRE_FALSE(gpu::zkMulProverResponseDevice(wrong, *x, *m, chi, modulus, *prover, unchanged, operationExecution.mainStream()));
        LOGVOLE_REQUIRE_EQ(unchanged.mU, 11ULL);
        LOGVOLE_REQUIRE_EQ(unchanged.mV, 13ULL);
    }
    LOGVOLE_REQUIRE_FALSE(producer.expired());
    std::packaged_task<void()> reuse([&] {
        auto execution = std::make_shared<gpu::GpuExecutionContext>();
        receiverContext = execution;
        auto& stream = execution->mainStream();
        receiver = stream.allocationOwner();
        check(stream);
    });
    auto completed = reuse.get_future();
    std::thread consumer(std::move(reuse));
    consumer.join();
    completed.get();
    LOGVOLE_REQUIRE_TRUE(receiverContext.expired());
    LOGVOLE_REQUIRE_FALSE(receiver.expired());
    LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(circuit, operationExecution.mainStream()));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(circuit.mOperands, reference.mOperands));
    circuit = {};
    prover.reset(); verifier.reset(); x.reset(); m.reset(); k.reset();
    LOGVOLE_REQUIRE_TRUE(producer.expired() && receiver.expired());
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_Cpu_GpuZkMatMulSeededInputsMatchReference(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool wantGpu = cmd.getOr("gpu", 0) != 0;
    if (wantGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!wantGpu || !gpu::available()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    const u64 largePrime = seal::PlainModulus::Batching(1024, 52).value();
    for (u64 dim : { 1u, 3u, 7u, 16u, 33u, 128u })
    for (u64 modulus : { u64{2}, u64{65537}, largePrime })
    {
        ZkMatMulStatement statement{};
        statement.mDim = dim;
        statement.mReps = 3;
        std::vector<u64> sizes{ 0, statement.voleCount(), zkVoleRequestSize(statement.voleCount()),
            statement.voleCount() + 13 };
        std::sort(sizes.begin(), sizes.end());
        sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
        for (u64 requested : sizes)
        {
            const u64 count = requested ? requested : statement.voleCount();
            const block seed = toBlock(0x4d41544d554c, dim ^ modulus);
            PRNG cpuPrng(seed, 3);
            AlignedUnVec<u64> expected;
            LOGVOLE_REQUIRE_TRUE(zkMatMulWitnessInputs(statement, modulus, cpuPrng, expected, requested));

            // Independent placement oracle: exactly 2*d*d AES words populate
            // A then B; the next words are independent repetition masks.
            // The padded request consumes no additional parent randomness.
            PRNG stream(seed, 256);
            std::vector<u64> oracle(static_cast<std::size_t>(count), 0);
            for (u64 i = 0; i < 2 * dim * dim; ++i) oracle[i] = stream.get<u64>() % modulus;
            for (u32 rep = 0; rep < statement.repetitions(); ++rep)
                oracle[statement.maskIndex(rep)] = stream.get<u64>() % modulus;
            LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, oracle));
            for (unsigned i = 0; i < 4; ++i)
                LOGVOLE_REQUIRE_EQ(cpuPrng.get<u64>(), stream.get<u64>());

            auto device = gpu::zkMatMulWitnessInputsDevice(statement, modulus, seed, operationExecution.mainStream(), requested);
            LOGVOLE_REQUIRE_TRUE(device != nullptr);
            LOGVOLE_REQUIRE_EQ(device->count(), count);
            AlignedUnVec<u64> fetched;
            fetched.resize(static_cast<std::size_t>(count));
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));

            // Keep two independently owned device results alive at once. A
            // repeated seeded call must neither reuse nor overwrite the first.
            auto replay = gpu::zkMatMulWitnessInputsDevice(statement, modulus, seed, operationExecution.mainStream(), requested);
            LOGVOLE_REQUIRE_TRUE(replay != nullptr);
            LOGVOLE_REQUIRE_TRUE(replay->data() != device->data());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*replay, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));
            auto another = gpu::zkMatMulWitnessInputsDevice(statement, modulus, toBlock(1, dim), operationExecution.mainStream(), requested);
            LOGVOLE_REQUIRE_TRUE(another != nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));

            // The existing product kernel must accept the returned placement,
            // including odd dimensions on both sides of its tile boundary.
            if (dim <= 33)
            {
                AlignedUnVec<u64> expectedProduct, actualProduct;
                macoro::thread_pool productExecutor;
                std::array<u8, 1> productResults{};
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMatMulFillProduct(productExecutor,
                    productResults, statement, modulus, 1, expected, expectedProduct)));
                gpu::DeviceScalars product;
                LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulFillProductDevice(*device, statement,
                    modulus, product, operationExecution.mainStream()));
                actualProduct.resize(statement.entries());
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(product, actualProduct, readbackExecution.readbackStream()));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actualProduct, expectedProduct));
                // Public product evaluation writes a separate destination;
                // neither live private witness, mask nor padding may change.
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched, readbackExecution.readbackStream()));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*replay, fetched, readbackExecution.readbackStream()));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));
            }
        }
    }

    ZkMatMulStatement valid{};
    valid.mDim = 7;
    const block seed = toBlock(0x494e56414c4944, 7);
    auto retained = gpu::zkMatMulWitnessInputsDevice(valid, largePrime, seed, operationExecution.mainStream());
    LOGVOLE_REQUIRE_TRUE(retained != nullptr);
    AlignedUnVec<u64> before, after;
    before.resize(retained->count());
    after.resize(retained->count());
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, before, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, 0, seed, operationExecution.mainStream()) == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, 1, seed, operationExecution.mainStream()) == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, largePrime, seed, operationExecution.mainStream(), valid.voleCount() - 1) == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, largePrime, seed, operationExecution.mainStream(), std::numeric_limits<u64>::max()) == nullptr);
    for (u64 dim : { u64{0}, std::numeric_limits<u64>::max(),
            static_cast<u64>(std::numeric_limits<u32>::max()), u64{1} << 32 })
    {
        auto invalid = valid;
        invalid.mDim = dim;
        LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(invalid, largePrime, seed, operationExecution.mainStream()) == nullptr);
    }
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, after, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(before, after));
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_Cpu_DyadicMatchesReference(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    PRNG random(toBlock(0x398, 0x8941));
    for (unsigned bits : {52, 55})
    for (u64 gap : {1, 81919, 16777215, 16777217})
    for (std::size_t count : {7, 8, 9, 127, 1024, 65537})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus mod(q);
        std::vector<u64> a(count+1), b(count+1), c(count+1), expected(count+1);
        random.get(a.data(), a.size());
        random.get(b.data(), b.size());
        random.get(c.data(), c.size());
        const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, (u64{1} << bits)-1, ~u64{0}};
        for (std::size_t i = 1; i <= count; ++i)
        {
            if (i <= 64)
            {
                a[i] = edges[(i-1) % 8];
                b[i] = edges[(i-1) / 8];
                c[i] = edges[(i+2) % 8];
            }
            // Include canonical values and all 64-bit values in the same call.
            else if (i & 1) { a[i] %= q; b[i] %= q; c[i] %= q; }
        }
        for (bool subtract : {false, true})
        for (unsigned alias = 0; alias < 3; ++alias)
        {
            auto result = alias == 0 ? c : a;
            const auto& x = alias == 0 ? a : result;
            const auto& y = alias == 2 ? result : b;
            expected = result;
            for (std::size_t i = 1; i <= count; ++i)
                expected[i] = subtract
                    ? seal::util::sub_uint_mod(result[i] % q, mulMod(x[i] % q, y[i] % q, mod), mod)
                    : mulAddMod(x[i] % q, y[i] % q, result[i] % q, mod);
            const auto original = result;
            const auto operation = subtract ? LogVole::cpuDyadicMultiplySubtract
                : LogVole::cpuDyadicMultiplyAdd;
            const bool used = operation(
                cpu, x.data()+1, y.data()+1, result.data()+1, count, mod);
            LOGVOLE_REQUIRE_TRUE(result == (used ? expected : original));
            LOGVOLE_REQUIRE_EQ(used, count>=8 && gap<(u64{1}<<24) && cpu.ifma());
        }
    }
}

void LogVole_Cpu_FusedDotMatchesReference(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    PRNG random(toBlock(0x444f54, 0x49464d41));
    for (int bits : {30, 52, 55, 60})
    for (u64 gap : {1ULL, 32767ULL, 16777215ULL, 16777216ULL})
    for (std::size_t terms : {1, 2, 5, 16, 32, 33})
    for (std::size_t count : {0, 1, 7, 8, 9, 127})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus modulus(q);
        std::vector<std::vector<u64>> a(terms, std::vector<u64>(count+2)), b = a;
        std::vector<const u64*> ap(terms), bp(terms);
        std::vector<u64> c(count+2), expected;
        random.get(c.data(), c.size());
        for (std::size_t t = 0; t < terms; ++t)
        {
            random.get(a[t].data(), a[t].size());
            random.get(b[t].data(), b[t].size());
            for (std::size_t i = 0; i < count; ++i)
            {
                if (i == 0) a[t][i+1] = b[t][i+1] = q-1;
                else if (i == 1) a[t][i+1] = b[t][i+1] = ~u64{0};
                else if (i & 1) { a[t][i+1] %= q; b[t][i+1] %= q; }
            }
            ap[t] = a[t].data()+1;
            bp[t] = b[t].data()+1;
        }
        expected = c;
        for (std::size_t i = 0; i < count; ++i)
        {
            host_oracle::Uint128 sum = c[i+1] % q;
            for (std::size_t t = 0; t < terms; ++t)
                sum += static_cast<host_oracle::Uint128>(ap[t][i] % q) * (bp[t][i] % q);
            expected[i+1] = static_cast<u64>(sum % q);
        }
        const auto original = c;
        const bool used = LogVole::cpuDyadicInnerProduct(cpu, ap.data(), bp.data(), terms, c.data()+1, count, modulus);
        LOGVOLE_REQUIRE_TRUE(c == (used ? expected : original));
        const bool expectedFast = (bits == 52 || bits == 55) && gap < (u64{1} << 24) &&
            terms >= 3 && terms <= 32 && cpu.ifma();
        LOGVOLE_REQUIRE_EQ(used, expectedFast);
    }
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, {bits, bits});
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        // More than one block of 32, with generic-modulus fallback coverage.
        std::vector<RnsPoly> a(65), b(65);
        std::vector<const RnsPoly*> ap, bp;
        auto actual = sampleUniformPoly(ctx, random), expected = actual;
        for (unsigned t = 0; t < a.size(); ++t)
        {
            a[t] = sampleUniformPoly(ctx, random);
            b[t] = sampleUniformPoly(ctx, random);
            ap.push_back(&a[t]); bp.push_back(&b[t]);
            LOGVOLE_REQUIRE_TRUE(dyadicMultiplyAddNttInplace(a[t], b[t], expected, ctx));
        }
        LOGVOLE_REQUIRE_TRUE(dyadicInnerProductNttInplace(ap, bp, actual, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
        ap[0] = &actual;
        LOGVOLE_REQUIRE_TRUE(!dyadicInnerProductNttInplace(ap, bp, actual, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
    }
}

void LogVole_Cpu_RecursiveLeafMatchesIntegerReference(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    PRNG random(toBlock(0x1eaf, 0x20260910));
    for (int bits : {52, 55})
    {
        const auto moduli = seal::CoeffModulus::Create(1024, std::vector<int>(8, bits));
        for (unsigned selected = 0; selected < moduli.size(); ++selected)
        for (u64 inverse : {u64{0}, u64{1}, moduli[selected].value()-1,
                            random.get<u64>() % moduli[selected].value()})
        for (std::size_t count : {1, 7, 8, 9, 63, 1024})
        {
            const auto q = moduli[selected].value();
            std::vector<u64> input(count+1), output(count*moduli.size()+2, 0x12345678), expected=output;
            for (std::size_t i = 0; i < count; ++i)
            {
                const std::array<u64, 7> edges{0, 1, q/2-1, q/2, q/2+1, q-2, q-1};
                input[i+1] = i < edges.size() ? edges[i] : random.get<u64>() % q;
                const u64 residue = static_cast<host_oracle::Uint128>(input[i+1]) * inverse % q;
                for (std::size_t j = 0; j < moduli.size(); ++j)
                    expected[1+j*count+i] = residue > q/2 ? moduli[j].value()-(q-residue) : residue;
            }
            const bool dispatched = LogVole::cpuUnliftCenteredRns(cpu, input.data()+1, output.data()+1,
                count, moduli[selected], inverse, moduli);
            if (dispatched) LOGVOLE_REQUIRE_TRUE(output == expected);
            else LOGVOLE_REQUIRE_TRUE(std::all_of(output.begin(), output.end(), [](u64 x) { return x == 0x12345678; }));
            for (u64 value : {q, q+1, ~u64{0}})
            {
                const auto before = output;
                input[count] = value;
                LOGVOLE_REQUIRE_FALSE(LogVole::cpuUnliftCenteredRns(cpu, input.data()+1,
                    output.data()+1, count, moduli[selected], inverse, moduli));
                LOGVOLE_REQUIRE_TRUE(output == before);
            }
        }
        std::array<u64, 8> input{}, output;
        output.fill(0x12345678);
        const std::array<seal::Modulus, 1> small{seal::Modulus(257)};
        LOGVOLE_REQUIRE_TRUE(!LogVole::cpuUnliftCenteredRns(cpu, input.data(), output.data(), 8, moduli[0], 1, small));
        LOGVOLE_REQUIRE_TRUE(!LogVole::cpuUnliftCenteredRns(cpu, input.data(), output.data(), 8, small[0], 1, small));
        LOGVOLE_REQUIRE_TRUE(std::all_of(output.begin(), output.end(), [](u64 x) { return x == 0x12345678; }));

        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(8);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        std::vector<RnsPoly> raw(2), canonical(2);
        for (unsigned leaf = 0; leaf < 2; ++leaf)
        {
            raw[leaf].mCoeffs.resize(8192);
            random.get(raw[leaf].mCoeffs.data(), raw[leaf].mCoeffs.size());
            canonical[leaf] = raw[leaf];
            for (std::size_t i = 0; i < 8192; ++i)
                canonical[leaf].mCoeffs[i] %= ringModulusValue(ctx, i/1024);
        }
        DigestTree actual{}, expected{};
        LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, raw, 1, 4*bits, bits-1, actual, 2, true));
        LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, canonical, 1, 4*bits, bits-1, expected, 2, true));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mDigest.mCoeffs, expected.mDigest.mCoeffs));
    }
}

void LogVole_Cpu_ErrorSamplingMatchesSeal(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    for (unsigned limbs : {2, 4, 8})
    for (double deviation : {0.0, 3.2, 64.0})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), limbs == 4 ? 55 : 52);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        PRNG random(toBlock(0x6677, limbs));
        RnsPoly actual{};
        actual.mCoeffs.resize(1024*limbs);
        random.get(actual.mCoeffs.data(), actual.mCoeffs.size());
        auto expected = actual;
        PRNG original(toBlock(0x9abc, limbs)), optimized(toBlock(0x9abc, limbs));
        seal::prng_seed_type seed{};
        original.get(seed.data(), seed.size());
        auto generator = LogVole::detail::makeAesPrngFactory()->create(seed);
        seal::RandomToStandardAdapter engine(generator);
        seal::util::ClippedNormalDistribution distribution(0, deviation, 6*deviation);
        for (std::size_t i = 0; i < 1024; ++i)
        {
            const i64 noise = static_cast<i64>(distribution(engine));
            for (unsigned j = 0; j < limbs; ++j)
            {
                const u64 q = ringModulusValue(ctx, j);
                const u64 addend = noise < 0 ? q-static_cast<u64>(-noise) : static_cast<u64>(noise);
                expected.mCoeffs[j*1024+i] = (expected.mCoeffs[j*1024+i] % q + addend) % q;
            }
        }
        LOGVOLE_REQUIRE_TRUE(addPolyError(actual, deviation, 6*deviation, optimized, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
        std::array<u64, 16> before{}, after{};
        original.get(before.data(), before.size());
        optimized.get(after.data(), after.size());
        LOGVOLE_REQUIRE_TRUE(before == after);
    }
    // Custom clipping bounds can exceed a ring modulus. The error-NTT
    // shortcut must then preserve the general normalization path.
    for (bool wideNoise : {false, true})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, {30, 30});
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        PRNG inputPrng(toBlock(0x57494445, 0x4e4f4953));
        std::vector<RnsPoly> inputs{sampleUniformPoly(ctx, inputPrng), sampleUniformPoly(ctx, inputPrng)};
        const double deviation = wideNoise ? double(ringModulusValue(ctx, 0))*0.75 : 3.2;
        PRNG actualPrng(toBlock(123,456)), expectedPrng(toBlock(123,456));
        std::vector<RnsPoly> expected(2);
        bool noncanonical = false;
        for (auto& poly : expected)
        {
            resizeZero(poly.mCoeffs, 2048);
            LOGVOLE_REQUIRE_TRUE(addPolyError(poly, deviation, 4*deviation, expectedPrng, ctx));
            for (std::size_t i = 0; i < poly.mCoeffs.size(); ++i)
                noncanonical |= poly.mCoeffs[i] >= ringModulusValue(ctx, i/1024);
            LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
        }
        LOGVOLE_REQUIRE_EQ(noncanonical, wideNoise);
        LencEncodeOutput actual{};
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, inputs, 1, 30, 29, actualPrng, actual,
            deviation, 4*deviation, 2, false, false)));
        LOGVOLE_REQUIRE_EQ(actual.mRNtt.size(), expected.size());
        for (unsigned i = 0; i < 2; ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mRNtt[i].mCoeffs, expected[i].mCoeffs));
    }
}

void LogVole_Cpu_ResamplingOverwritesPreviousQuery(const oc::CLP&)
{
    PRNG random(toBlock(0x52455341, 0x4d504c45));
    std::vector<RnsPoly> actual;
    for (unsigned limbs : {2, 4, 8, 2})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            limbs == 4 ? 55 : 52);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        auto digest = sampleUniformPoly(ctx, random);
        std::array<u8, 16> seed{};
        random.get(seed.data(), seed.size());
        u64 sid = 17, instance = 2;
        for (unsigned query = 0; query < 12; ++query)
        {
            switch (query % 4)
            {
            case 0: seed[query % seed.size()] ^= 0x80; break;
            case 1: ++sid; break;
            case 2: ++instance; break;
            case 3: digest.mCoeffs[query] ^= 1; break;
            }
            const u32 mu = query < 6 ? 3 : 5;
            const auto previous = actual;
            const auto ct2Seed = deriveSeedInstanceBlock(seed, sid, digest, instance, mu);
            LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, mu, seed, sid, digest, instance, actual));
            LOGVOLE_REQUIRE_EQ(actual.size(), mu);
            for (u32 i = 0; i < mu; ++i)
            {
                // A fresh single-polynomial draw defines the expected stream;
                // reused buffers must not retain a prior query or index.
                const auto expected = deriveUniformPolyFromSeed(ctx, ct2Seed, 0xC720AA55u, i);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected.mCoeffs));
            }
            if (previous.size() == actual.size())
                LOGVOLE_REQUIRE_FALSE(rangesEqual(previous[0].mCoeffs, actual[0].mCoeffs));
        }
        const auto previous = actual;
        LOGVOLE_REQUIRE_FALSE(buildHashedCt2(ctx, 0, seed, sid, digest, instance, actual));
        LOGVOLE_REQUIRE_EQ(actual.size(), previous.size());
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, previous[0].mCoeffs));

        for (unsigned query = 0; query < 4; ++query)
        {
            std::array<block, 3> seeds{};
            random.get(seeds.data(), seeds.size());
            LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromSeedListInplace(ctx, seeds, 77, 2, actual));
            for (unsigned i = 0; i < 6; ++i)
            {
                const auto expected = deriveUniformPolyFromSeed(ctx, seeds[i/2], 77, i%2);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected.mCoeffs));
            }
        }
        deriveUniformPolyBatchFromSeedInplace(ctx, ZeroBlock, 77, 0, actual);
        LOGVOLE_REQUIRE_TRUE(actual.empty());
    }
}

void LogVole_Cpu_SamplerMatchesSeal(const oc::CLP&)
{
    const osuCrypto::CpuCapabilities cpu;
    // The direct, reusable PRNG and SEAL's optional boundary adapter use the
    // same AES stream. The independent counter-mode oracle checks byte order.
    {
        auto factory = LogVole::detail::makeAesPrngFactory();
        PRNG reusable(ZeroBlock);
        const auto* backing = reusable.mBuffer.data();
        for (unsigned trial = 0; trial < 4; ++trial)
        {
            seal::prng_seed_type seed{};
            for (unsigned i = 0; i < seed.size(); ++i) seed[i] = 17u * i + trial;
            const auto key = LogVole::detail::aesPrngKey(seed);
            reusable.SetSeed(key);
            LOGVOLE_REQUIRE_TRUE(reusable.mBuffer.data() == backing);
            auto bridge = factory->create(seed);
            AES cipher(key);
            std::vector<block> oracle(2048);
            cipher.ecbEncCounterMode(0, oracle.size(), oracle.data());
            std::size_t offset = 0;
            for (std::size_t bytes : {0, 1, 15, 16, 17, 4095, 4096, 4097})
            {
                std::vector<u8> direct(bytes), adapted(bytes);
                reusable.get(direct.data(), bytes);
                bridge->generate(bytes, reinterpret_cast<seal::seal_byte*>(adapted.data()));
                LOGVOLE_REQUIRE_TRUE(direct == adapted);
                LOGVOLE_REQUIRE_TRUE(std::equal(direct.begin(), direct.end(),
                    reinterpret_cast<const u8*>(oracle.data()) + offset));
                offset += bytes;
            }
            // Explicit reseeding after a partial refill keeps the allocation.
            reusable.SetSeed(key);
            LOGVOLE_REQUIRE_TRUE(reusable.mBuffer.data() == backing);
            LOGVOLE_REQUIRE_EQ(reusable.get<u64>(), reinterpret_cast<const u64*>(oracle.data())[0]);

            seal::EncryptionParameters parms(seal::scheme_type::ckks);
            parms.set_poly_modulus_degree(1024);
            const u64 q = (u64{3} << 58) + 123;
            parms.set_coeff_modulus({seal::Modulus(q), seal::Modulus(q + 128)});
            std::vector<u64> direct(2048), expected(2048);
            reusable.SetSeed(key);
            auto reference = factory->create(seed);
            LogVole::detail::cpuSamplePolyUniform(cpu, reusable, parms, direct.data());
            seal::util::sample_poly_uniform(reference, parms, expected.data());
            LOGVOLE_REQUIRE_TRUE(direct == expected);
            std::array<u8, 31> a{}, b{};
            reusable.get(a.data(), a.size());
            reference->generate(b.size(), reinterpret_cast<seal::seal_byte*>(b.data()));
            LOGVOLE_REQUIRE_TRUE(a == b);
        }
        seal::prng_seed_type seed{};
        const auto original = LogVole::detail::aesPrngKey(seed);
        for (unsigned i = 0; i < seed.size(); ++i)
        {
            seed[i] = 1;
            LOGVOLE_REQUIRE_FALSE(eq(LogVole::detail::aesPrngKey(seed), original));
            seed[i] = 0;
        }
    }
    PRNG random(toBlock(0x739182, 0x193));
    auto reference = LogVole::detail::makeAesPrngFactory();
    PRNG source(ZeroBlock);
    for (unsigned trial = 0; trial < 4; ++trial)
    {
        seal::prng_seed_type seed{};
        random.get(seed.data(), seed.size());
        for (int bits : {30, 52, 55, 60})
        {
            RingParams params{};
            params.mPolyModulusDegree = 1024;
            assignValues<int>(params.mCoeffModulusBits, {bits, bits});
            RingNttContext ctx{};
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
            std::vector<u64> actual(2048), expected(2048);
            const auto hostContext = getRingHostContext(ctx);
            LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
            const auto& parms = hostContext->key_context_data()->parms();
            source.SetSeed(LogVole::detail::aesPrngKey(seed));
            LogVole::detail::cpuSamplePolyUniform(cpu, source, parms, actual.data());
            seal::util::sample_poly_uniform(reference->create(seed), parms, expected.data());
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }
    }

    // Force rare rejections in the vector-supported rings, then several
    // replacement rejections across a refill. Also compare the next PRNG bytes.
    class ScriptedGenerator final : public seal::UniformRandomGenerator
    {
    public:
        ScriptedGenerator() : UniformRandomGenerator({}) {}
    private:
        seal::prng_type type() const noexcept override { return seal::prng_type::unknown; }
        void refill_buffer() override
        {
            for (std::size_t i = 0; i < buffer_size_ / sizeof(u64); ++i, ++mIndex)
            {
                const u64 value = (mIndex < 2048 ? mIndex % 32 == 31 : mIndex < 2560 || mIndex % 2 == 0)
                    ? ~u64{0} : mIndex;
                std::memcpy(buffer_begin_ + i * sizeof(u64), &value, sizeof(value));
            }
        }
        u64 mIndex = 0;
    };
    for (int bits : {52, 55})
    {
        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(seal::CoeffModulus::Create(1024, {bits, bits}));
        auto a = std::make_shared<ScriptedGenerator>(), b = std::make_shared<ScriptedGenerator>();
        std::vector<u64> actual(2048), expected(2048);
        LogVole::detail::cpuSamplePolyUniform(cpu, a, parms, actual.data());
        seal::util::sample_poly_uniform(b, parms, expected.data());
        LOGVOLE_REQUIRE_TRUE(actual == expected);
        std::array<seal::seal_byte, 4099> nextA{}, nextB{};
        a->generate(nextA.size(), nextA.data());
        b->generate(nextB.size(), nextB.data());
        LOGVOLE_REQUIRE_TRUE(nextA == nextB);
    }
}

void LogVole_Cpu_ZkArithmeticMatchesReference(const oc::CLP&)
{
    const auto configured = LogVole::detail::captureCpuZkOptions();
    for (bool scalar : {false, true})
    {
        auto options = configured;
        if (scalar)
        {
            options.mPseudoReduce = false;
            options.mVectorGates = false;
            options.mVectorWitness = false;
            options.mVectorMatMul = false;
        }
        PRNG random(toBlock(0x738, 0x514));
        const std::array<u64, 9> moduli = {257, (u64{1} << 50) + 27,
            (u64{1} << 51) - 1, (u64{1} << 51) - 16777215,
            2251799813554177ULL, 18014398508400641ULL,
            (u64{1} << 54) - 1, (u64{1} << 54) - 16777215,
            (u64{1} << 54) - 16777217};
        for (u64 q : moduli)
        {
            const seal::Modulus mod(q);
            LogVole::detail::withCpuZkArithmetic(mod, options.mPseudoReduce, [&](const auto& arithmetic) {
                const std::array<u64, 7> edges = {0, 1, 2, q/2, q-1, q, ~u64{0}};
                for (u64 a : edges) for (u64 b : edges)
                    LOGVOLE_REQUIRE_EQ(arithmetic.multiply(a, b), mulMod(a, b, mod));
                for (unsigned i = 0; i < 100000; ++i)
                {
                    const u64 a = random.get<u64>() % q;
                    const u64 b = random.get<u64>() % q;
                    const u64 c = random.get<u64>() % q;
                    LOGVOLE_REQUIRE_EQ(arithmetic.multiplyAdd(a, b, c), mulAddMod(a, b, c, mod));
                }
            });
        }
    }
}

void LogVole_Cpu_ZkVectorMatchesReference(const oc::CLP&)
{
    const auto configured = LogVole::detail::captureCpuZkOptions();
    for (bool scalar : {false, true})
    {
        auto options = configured;
        if (scalar)
        {
            options.mPseudoReduce = false;
            options.mVectorGates = false;
            options.mVectorWitness = false;
            options.mVectorMatMul = false;
        }
        PRNG random(toBlock(0x5a4b5645, 0x43544f52));
        for (int bits : {30, 51, 54, 60})
        for (u64 gap : {1ULL, 32767ULL, 16777215ULL, 16777216ULL})
        for (std::size_t count : {0, 1, 7, 8, 9, 15, 17, 1024})
        {
            const u64 q = (u64{1} << bits) - gap;
            const seal::Modulus mod(q);
            const auto multiply = [q](u64 a, u64 b) {
                return static_cast<u64>((static_cast<host_oracle::Uint128>(a) * b) % q);
            };
            std::vector<u64> wires(1026), labels(1026), outputs(count + 2);
            std::vector<u32> operands(2 * count + 2);
            random.get(wires.data(), wires.size());
            random.get(labels.data(), labels.size());
            random.get(outputs.data(), outputs.size());
            const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, 2*q, ~u64{0}};
            for (std::size_t i = 0; i < edges.size(); ++i)
            {
                wires[i+1] = edges[i];
                labels[i+1] = edges[edges.size()-i-1];
                if (i < count) outputs[i+1] = edges[i];
            }
            for (std::size_t i = 0; i < 2 * count; ++i)
                operands[i+1] = i < 16 ? (i/2 + (i%2)*3) % 8 : random.get<u32>() % 1024;
            for (u64 chi : {u64{0}, u64{1}, q-1, ~u64{0}, random.get<u64>()})
            for (u64 delta : {u64{0}, u64{1}, q-1, ~u64{0}})
            {
                const u64 firstPower = random.get<u64>();
                std::array<u64, 2> expected{0, 0}, actual{123, 456};
                u64 verifier = 0, actualVerifier = 789, power = firstPower % q;
                for (std::size_t i = 0; i < count; ++i)
                {
                    const u32 x = operands[2*i+1]+1, y = operands[2*i+2]+1;
                    const u64 a0 = multiply(labels[x], labels[y]);
                    const u64 a1 = (outputs[i+1] % q + 2*q - multiply(wires[x], labels[y])
                        - multiply(wires[y], labels[x])) % q;
                    const u64 b = (a0 + multiply(delta, outputs[i+1])) % q;
                    expected[0] = (expected[0] + multiply(power, a0)) % q;
                    expected[1] = (expected[1] + multiply(power, a1)) % q;
                    verifier = (verifier + multiply(power, b)) % q;
                    power = multiply(power, chi);
                }
                const bool used = LogVole::detail::cpuZkProverRange(operands.data()+1, wires.data()+1,
                    labels.data()+1, outputs.data()+1, count, firstPower, chi, mod, actual, options);
                LOGVOLE_REQUIRE_EQ(LogVole::detail::cpuZkVerifierRange(operands.data()+1, labels.data()+1,
                    outputs.data()+1, count, firstPower, chi, delta, mod, actualVerifier, options), used);
                const std::array<u64, 2> original{123, 456};
                LOGVOLE_REQUIRE_TRUE(actual == (used ? expected : original));
                LOGVOLE_REQUIRE_EQ(actualVerifier, used ? verifier : u64{789});
                const bool expectedFast = options.mVectorGates &&
                    (bits == 51 || bits == 54) && gap < (u64{1} << 24) && count >= 8;
                LOGVOLE_REQUIRE_EQ(used, expectedFast);
            }
        }
    }
}

void LogVole_Cpu_ProtocolIdentityService(const oc::CLP&)
{
    const auto first = ProtocolCacheService::create(), second = ProtocolCacheService::create();
    const auto a = first->allocate(), b = second->allocate(), next = first->allocate();
    LOGVOLE_REQUIRE_EQ(a.mValue, 1u);
    LOGVOLE_REQUIRE_EQ(b.mValue, 1u);
    LOGVOLE_REQUIRE_FALSE(a == b);
    LOGVOLE_REQUIRE_FALSE(a == next);
    LOGVOLE_REQUIRE_TRUE(first->qualify(0) == ProtocolCacheRunId{});
    LOGVOLE_REQUIRE_EQ(first->qualify(0).hash(), ProtocolCacheRunId{}.hash());
    ProtocolCacheScope sender(a, ProtocolCacheRole::Sender), receiver(next, ProtocolCacheRole::Receiver);
    LOGVOLE_REQUIRE_TRUE(sender.mServiceOwner == receiver.mServiceOwner);
    PublicPolynomialCache::Key ka{}, kb{};
    ka.mRunId = a; kb.mRunId = b;
    ka.mRole = kb.mRole = ProtocolCacheRole::Sender;
    LOGVOLE_REQUIRE_FALSE(ka == kb);
    auto otherRole = ka;
    otherRole.mRole = ProtocolCacheRole::Receiver;
    LOGVOLE_REQUIRE_FALSE(ka == otherRole);
    std::unordered_map<PublicPolynomialCache::Key, int, PublicPolynomialCache::Hash> keys;
    keys.emplace(ka, 1); keys.emplace(kb, 2); keys.emplace(otherRole, 3);
    LOGVOLE_REQUIRE_EQ(keys.size(), 3u);
    std::weak_ptr<const ProtocolCacheService> retainedWeak;
    auto retained = std::make_shared<PublicPolynomialCache::Entry>();
    {
        const auto service = ProtocolCacheService::create();
        retainedWeak = service;
        retained->mIdentityService = service->allocate().serviceOwner();
    }
    LOGVOLE_REQUIRE_FALSE(retainedWeak.expired());
    auto moved = std::move(retained);
    LOGVOLE_REQUIRE_FALSE(retainedWeak.expired());
    moved.reset();
    LOGVOLE_REQUIRE_TRUE(retainedWeak.expired());
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    auto operation = [&](ProtocolCacheScope context) -> macoro::task<bool> {
        co_await executor.schedule();
        co_return context.mRole == ProtocolCacheRole::Receiver &&
            context.mRunId.mService == context.mServiceOwner.get();
    };
    macoro::task<bool> pending;
    std::weak_ptr<const ProtocolCacheService> pendingWeak;
    {
        const auto service = ProtocolCacheService::create();
        pendingWeak = service;
        pending = operation(ProtocolCacheScope(service->allocate(), ProtocolCacheRole::Receiver));
    }
    // Context is captured before lazy start and independently retains the
    // service after both the originating scope and caller owner disappear.
    LOGVOLE_REQUIRE_FALSE(pendingWeak.expired());
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(std::move(pending)));
    pending = {}; // Completed task frames retain their parameters until destruction.
    LOGVOLE_REQUIRE_TRUE(pendingWeak.expired());
    RingParams params;
    params.mPolyModulusDegree = 1024;
    assignValues<int>(params.mCoeffModulusBits, {30, 30});
    {
        RingContextFactory isolated;
        ZpContextFactory isolatedCrt;
        LOGVOLE_REQUIRE_TRUE(isolated.protocolService() != first);
        LOGVOLE_REQUIRE_TRUE(isolatedCrt.ringFactory()->protocolService() != first);
#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::GpuSetupContext isolatedSetup;
        gpu::GpuExecutionContext isolatedExecution;
        LOGVOLE_REQUIRE_TRUE(isolatedSetup.protocolService() != first);
        LOGVOLE_REQUIRE_TRUE(isolatedExecution.protocolService() != first);
#endif
        // Phase entrypoints receive the selected scope explicitly; resource
        // constructors allocate independent services unless supplied one.
        RingNttContext selected;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, selected, std::shared_ptr<RingContextFactory>{}, sender));
        LOGVOLE_REQUIRE_TRUE(selected.mFactory->protocolService() == first);
        LOGVOLE_REQUIRE_EQ(selected.mResourceScope.mRole, ProtocolCacheRole::Sender);
        ZpCrtContext selectedCrt;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, selectedCrt, {}, sender));
        LOGVOLE_REQUIRE_TRUE(selectedCrt.mFactory->ringFactory()->protocolService() == first);
        LOGVOLE_REQUIRE_EQ(selectedCrt.mRing.mResourceScope.mRole, ProtocolCacheRole::Sender);
    }
    auto factory = std::make_shared<RingContextFactory>(LogVoleExecutionOptions{}, first);
    RingNttContext ring;
    {
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ring, factory, sender));
    }
    {
        RingNttContext rejected;
        LOGVOLE_REQUIRE_FALSE(makeRingNttContext(params, rejected, factory, {b, ProtocolCacheRole::Sender}));
    }
    auto crtFactory = std::make_shared<ZpContextFactory>(factory);
    RingNttContext explicitReceiverRing;
    ZpCrtContext explicitReceiverCrt;
    {
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, explicitReceiverRing, factory, receiver));
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, explicitReceiverCrt, crtFactory, receiver));
        LOGVOLE_REQUIRE_EQ(explicitReceiverRing.mResourceScope.mRole, ProtocolCacheRole::Receiver);
        LOGVOLE_REQUIRE_EQ(explicitReceiverCrt.mRing.mResourceScope.mRole, ProtocolCacheRole::Receiver);
        LOGVOLE_REQUIRE_TRUE(explicitReceiverRing.mFactoryOwner != ring.mFactoryOwner);
    }
    {
        // Receiver selection and cache reuse remain in the explicit service domain.
        RingNttContext again;
        ZpCrtContext againCrt;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, again, factory, receiver));
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, againCrt, crtFactory, receiver));
        LOGVOLE_REQUIRE_TRUE(again.mFactoryOwner == explicitReceiverRing.mFactoryOwner);
        LOGVOLE_REQUIRE_TRUE(againCrt.mFactoryOwner == explicitReceiverCrt.mFactoryOwner);
        RingNttContext combinedRing;
        ZpCrtContext combinedCrt;
        LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(params, 20, combinedRing,
            combinedCrt, crtFactory, receiver));
        LOGVOLE_REQUIRE_TRUE(combinedCrt.mFactoryOwner == explicitReceiverCrt.mFactoryOwner);
        LOGVOLE_REQUIRE_EQ(combinedRing.mResourceScope.mRole, ProtocolCacheRole::Receiver);
        const ProtocolCacheScopeView foreignReceiver{b, ProtocolCacheRole::Receiver};
        LOGVOLE_REQUIRE_FALSE(makeRingNttContext(params, again, factory, foreignReceiver));
        LOGVOLE_REQUIRE_FALSE(makeZpCrtContext(params, 20, againCrt, crtFactory, foreignReceiver));
        LOGVOLE_REQUIRE_TRUE(again.mFactoryOwner == explicitReceiverRing.mFactoryOwner);
        LOGVOLE_REQUIRE_TRUE(againCrt.mFactoryOwner == explicitReceiverCrt.mFactoryOwner);
    }
    std::shared_ptr<const std::vector<RnsPoly>> cachedA, cachedB;
    {
        cachedA = sharedLhePublicANtt(ring, 2, receiver);
        cachedB = sharedLencPublicBNtt(ring, 1, receiver);
        LOGVOLE_REQUIRE_TRUE(cachedA && cachedB);
        LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(ring, 2, receiver) == cachedA);
        LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(ring, 1, receiver) == cachedB);
        const ProtocolCacheScope anotherRun(first->allocate(), ProtocolCacheRole::Receiver);
        const auto otherA = sharedLhePublicANtt(ring, 2, anotherRun);
        const auto otherB = sharedLencPublicBNtt(ring, 1, anotherRun);
        // Existing A keys include the run even on CPU; host-only B deliberately
        // shares run-zero entries across same-role runs when retention is off.
        LOGVOLE_REQUIRE_TRUE(otherA != cachedA);
        LOGVOLE_REQUIRE_TRUE(otherB == cachedB);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(otherA->front().mCoeffs, cachedA->front().mCoeffs));
        const auto senderA = sharedLhePublicANtt(ring, 2, sender);
        const auto senderB = sharedLencPublicBNtt(ring, 1, sender);
        LOGVOLE_REQUIRE_TRUE(senderA != cachedA && senderB != cachedB);
    }
    {
        LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(ring, 2, receiver) == cachedA);
        LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(ring, 1, receiver) == cachedB);
        std::vector<RnsPoly> copiedA;
        LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ring, 2, copiedA, receiver));
        const auto copiedB = buildLencPublicBNtt(ring, 1, receiver);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(copiedA.front().mCoeffs, cachedA->front().mCoeffs));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(copiedB.front().mCoeffs, cachedB->front().mCoeffs));
    }
    // LHE consumes protocol identity for public-A cache selection. Its lazy
    // task must retain the phase service even when the borrowed math context
    // belongs to another service; the resulting cache entry then owns it.
    PRNG samplingRandom(toBlock(0x1d, 1));
    const std::vector<RnsPoly> identityR{sampleUniformPoly(ring, samplingRandom), sampleUniformPoly(ring, samplingRandom)};
    const std::vector<RnsPoly> identitySk{sampleUniformPoly(ring, samplingRandom)};
    auto encodingRing = ring;
    encodingRing.mPublicCache = std::make_shared<PublicPolynomialCache>();
    RingTensor encoded;
    std::array<u8, 2> results{};
    macoro::task<bool> encoding;
    std::weak_ptr<const ProtocolCacheService> encodingWeak;
    {
        const auto encodingService = ProtocolCacheService::create();
        encodingWeak = encodingService;
        const ProtocolCacheScope scope(encodingService->allocate(), ProtocolCacheRole::Sender);
        encoding = lheEnc1(executor, results, encodingRing, identityR, identitySk, 30, encoded, 0, 0, nullptr, false, nullptr, 1, nullptr, {}, {}, {}, scope);
    }
    LOGVOLE_REQUIRE_TRUE(encoded.mPolys.empty());
    LOGVOLE_REQUIRE_FALSE(encodingWeak.expired());
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(std::move(encoding)));
    LOGVOLE_REQUIRE_EQ(encoded.mPolys.size(), 2u);
    encoding = {};
    LOGVOLE_REQUIRE_FALSE(encodingWeak.expired());
    encodingRing.mPublicCache.reset();
    LOGVOLE_REQUIRE_TRUE(encodingWeak.expired());
#if defined(ENABLE_LOGVOLE_CUDA)
    auto same = std::make_shared<gpu::GpuExecutionContext>(LogVoleExecutionOptions{}, nullptr, first);
    auto foreign = std::make_shared<gpu::GpuExecutionContext>(LogVoleExecutionOptions{}, nullptr, second);
    LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(ring, same));
    LOGVOLE_REQUIRE_FALSE(gpu::bindContextExecution(ring, foreign));
#endif
    std::array<ProtocolCacheRunId, 128> allocated;
    std::thread left([&] { for (std::size_t i = 0; i != 64; ++i) allocated[i] = first->allocate(); });
    std::thread right([&] { for (std::size_t i = 64; i != 128; ++i) allocated[i] = first->allocate(); });
    left.join(); right.join();
    std::vector<u64> numbers;
    for (auto id : allocated) { LOGVOLE_REQUIRE_TRUE(id.mService == first.get()); numbers.push_back(id.mValue); }
    std::sort(numbers.begin(), numbers.end());
    LOGVOLE_REQUIRE_TRUE(std::adjacent_find(numbers.begin(), numbers.end()) == numbers.end());
}

void LogVole_Cpu_AsyncMatMulProof(const oc::CLP& cmd)
{
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(cmd.getOr("executor_threads", 1));
    auto onPool = [&](macoro::task<bool> operation) -> macoro::task<bool> {
        co_await executor.schedule();
        co_return co_await std::move(operation);
    };
    ZkMatMulStatement st;
    st.mDim = 9;
    st.mReps = 3;
    constexpr u64 delta = 19;
    for (bool optimized : {false, true})
    for (u32 limit : {1u, 3u})
    {
        LogVoleZkOptions settings;
        settings.mCpuPseudoReduce = optimized;
        settings.mCpuVectorMatMul = optimized;
        CpuBenchmarkContext budget;
        budget.mCpus = {0, 1, 2};
        budget.mWorkerLimit = limit;
        ZkMatMulProverWorkspace prover(st, 3, &budget, settings);
        ZkMatMulVerifierWorkspace verifier(st, 3, &budget, settings);
        LOGVOLE_REQUIRE_EQ(prover.workers(), 3u);
        LOGVOLE_REQUIRE_EQ(verifier.workers(), 3u);
        std::vector<ZkProof> proofs(st.repetitions());
        std::vector<u64> values(st.repetitions());
        const auto proofStorage = proofs.data();
        const auto valueStorage = values.data();
        for (u64 q : {257ULL, 2251799813554177ULL})
        for (u64 query = 0; query != 2; ++query)
        {
            const seal::Modulus mod(q);
            PRNG random(toBlock(0x4d4154, query)), oracleRandom(toBlock(0x4d4154, query));
            AlignedUnVec<u64> wires, product;
            std::array<u8, 3> results{};
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(zkMatMulWitness(executor,
                results, st, q, 3, random, wires, product, st.voleCount() + 7))));
            std::vector<u64> expectedWires(wires.size(), 0);
            for (std::size_t i = 0; i != st.voleCount(); ++i) expectedWires[i] = oracleRandom.get<u64>() % q;
            LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, expectedWires));
            LOGVOLE_REQUIRE_TRUE(random.get<block>() == oracleRandom.get<block>());
            std::vector<u64> expectedProduct(st.entries(), 0);
            for (u64 i = 0; i != st.mDim; ++i)
                for (u64 j = 0; j != st.mDim; ++j)
                    for (u64 k = 0; k != st.mDim; ++k)
                        expectedProduct[i*st.mDim+j] = mulAddMod(wires[i*st.mDim+k],
                            wires[st.offsetB()+k*st.mDim+j], expectedProduct[i*st.mDim+j], mod);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(product, expectedProduct));
            std::vector<u64> macs(st.voleCount()), keys(st.voleCount());
            for (std::size_t i = 0; i != macs.size(); ++i)
            {
                macs[i] = random.get<u64>() % q;
                keys[i] = (macs[i] + q - mulMod(wires[i], delta, mod)) % q;
                // Repeated noncanonical calls reuse the workspace's lazy copies.
                wires[i] += q;
                macs[i] += q;
                keys[i] += q;
            }
            ZkMatMulChallenge challenge;
            zkMatMulChallenge(st, toBlock(0x4348, query), q, challenge);
            std::vector<ZkProof> expected(st.repetitions());
            std::vector<u64> expectedValues(st.repetitions());
            for (u32 rep = 0; rep != st.repetitions(); ++rep)
            {
                for (u64 i = 0; i != st.mDim; ++i)
                    for (u64 j = 0; j != st.mDim; ++j)
                    {
                        u64 a0 = 0, cross = 0, keyProduct = 0;
                        for (u64 k = 0; k != st.mDim; ++k)
                        {
                            const auto a = i*st.mDim+k, b = st.offsetB()+k*st.mDim+j;
                            a0 = mulAddMod(macs[a]%q, macs[b]%q, a0, mod);
                            cross = mulAddMod(wires[a]%q, macs[b]%q, cross, mod);
                            cross = mulAddMod(wires[b]%q, macs[a]%q, cross, mod);
                            keyProduct = mulAddMod(keys[a]%q, keys[b]%q, keyProduct, mod);
                        }
                        const auto entry = i*st.mDim+j;
                        const auto coefficient = challenge.mCoefficients[rep*st.entries()+entry];
                        expected[rep].mU = mulAddMod(coefficient, a0, expected[rep].mU, mod);
                        expected[rep].mV = (expected[rep].mV + q - mulMod(coefficient, cross, mod)) % q;
                        const auto residual = (keyProduct + q - mulMod(product[entry], mulMod(delta, delta, mod), mod)) % q;
                        expectedValues[rep] = mulAddMod(coefficient, residual, expectedValues[rep], mod);
                    }
                expected[rep].mU = addMod(expected[rep].mU, macs[st.maskIndex(rep)]%q, mod);
                expected[rep].mV = (expected[rep].mV + q - wires[st.maskIndex(rep)]%q) % q;
                expectedValues[rep] = addMod(expectedValues[rep], keys[st.maskIndex(rep)]%q, mod);
            }
            // Controller and workers share one pool thread in the default run.
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(zkMatMulProverResponse(executor,
                st, wires, macs, challenge, q, prover, proofs))));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(zkMatMulVerifierValue(executor,
                st, keys, product, challenge, delta, q, verifier, values))));
            for (u32 rep = 0; rep != st.repetitions(); ++rep)
            {
                LOGVOLE_REQUIRE_EQ(proofs[rep].mU, expected[rep].mU);
                LOGVOLE_REQUIRE_EQ(proofs[rep].mV, expected[rep].mV);
                LOGVOLE_REQUIRE_EQ(values[rep], expectedValues[rep]);
            }
            LOGVOLE_REQUIRE_TRUE(zkMatMulAccept(proofs, values, delta, q));
            LOGVOLE_REQUIRE_TRUE(proofs.data() == proofStorage && values.data() == valueStorage);
            auto badChallenge = challenge;
            badChallenge.mCoefficients[0] = q;
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMatMulProverResponse(executor,
                st, wires, macs, badChallenge, q, prover, proofs)));
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMatMulVerifierValue(executor,
                st, keys, product, badChallenge, delta, q, verifier, values)));
            auto wrongShape = st;
            ++wrongShape.mDim;
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMatMulProverResponse(executor,
                wrongShape, wires, macs, challenge, q, prover, proofs)));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(values, expectedValues));
            for (u32 rep = 0; rep != st.repetitions(); ++rep)
            {
                LOGVOLE_REQUIRE_EQ(proofs[rep].mU, expected[rep].mU);
                LOGVOLE_REQUIRE_EQ(proofs[rep].mV, expected[rep].mV);
            }
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMatMulFillProduct(executor, {},
                st, q, 3, wires, product)));
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMatMulFillProduct(executor,
                std::span(results).first(1), st, q, 3, wires, product)));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(product, expectedProduct));
            PRNG rejected(toBlock(0x52454a)), saved(toBlock(0x52454a));
            const auto savedWires = wires;
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMatMulWitness(executor,
                std::span(results).first(1), st, q, 3, rejected, wires, product)));
            LOGVOLE_REQUIRE_TRUE(rejected.get<block>() == saved.get<block>());
            LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, savedWires));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(product, expectedProduct));
            if (limit == 1)
            {
                macoro::thread_pool idle;
                ZkMatMulProverWorkspace serialProver(st, 1, &budget, settings);
                ZkMatMulVerifierWorkspace serialVerifier(st, 1, &budget, settings);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMatMulProverResponse(idle,
                    st, wires, macs, challenge, q, serialProver, proofs)));
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMatMulVerifierValue(idle,
                    st, keys, product, challenge, delta, q, serialVerifier, values)));
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMatMulFillProduct(idle,
                    std::span(results).first(1), st, q, 1, expectedWires, product)));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(product, expectedProduct));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(values, expectedValues));
            }
        }
        LOGVOLE_REQUIRE_TRUE(budget.mPeakTaskThreads.load() <= 3u);
    }
}

void LogVole_Cpu_AsyncMulProof(const oc::CLP& cmd)
{
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(cmd.getOr("executor_threads", 1));
    auto onPool = [&](macoro::task<bool> operation) -> macoro::task<bool> {
        co_await executor.schedule();
        co_return co_await std::move(operation);
    };
    for (u64 q : {257ULL, 2251799813554177ULL})
    for (bool optimized : {false, true})
    for (bool dependent : {false, true})
    {
        const seal::Modulus mod(q);
        ZkMulCircuit circuit;
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuit(51, 3, toBlock(0x4153594e43, 1), circuit));
        if (dependent) circuit.mOperands[4] = static_cast<u32>(circuit.outputWire(1));
        LogVoleZkOptions settings;
        settings.mCpuPseudoReduce = optimized;
        settings.mCpuVectorGates = optimized;
        settings.mCpuVectorWitness = optimized;
        for (u32 workers : {1u, 3u})
        {
            ZkMulCpuWorkspace workspace(circuit, workers, nullptr, settings);
            AlignedUnVec<u64> wires;
            wires.resize(circuit.voleCount() + 7);
            const auto storage = wires.data();
            for (u64 query = 0; query != 2; ++query)
            {
                PRNG random(toBlock(0x574954, query)), referenceRandom(toBlock(0x574954, query));
                std::vector<u64> expected(wires.size(), 0);
                for (u64 i = 0; i != circuit.mWidth; ++i) expected[i] = referenceRandom.get<u64>() % q;
                for (u64 g = 0; g != circuit.gateCount(); ++g)
                    expected[circuit.outputWire(g)] = mulMod(expected[circuit.mOperands[2*g]],
                        expected[circuit.mOperands[2*g+1]], mod);
                expected[circuit.maskIndex()] = referenceRandom.get<u64>() % q;
                auto operation = zkMulWitness(executor, circuit, q, random, wires, wires.size(), workspace);
                LOGVOLE_REQUIRE_TRUE(wires.data() == storage);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(std::move(operation))));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, expected));
                LOGVOLE_REQUIRE_TRUE(random.get<block>() == referenceRandom.get<block>());
                LOGVOLE_REQUIRE_TRUE(wires.data() == storage);
                std::vector<u64> macs(circuit.voleCount()), keys(circuit.voleCount());
                constexpr u64 delta = 19;
                for (std::size_t i = 0; i != macs.size(); ++i)
                {
                    macs[i] = random.get<u64>() % q;
                    keys[i] = (macs[i] + q - mulMod(wires[i], delta, mod)) % q;
                }
                ZkProof reference73{};
                u64 referenceValue73 = 0;
                for (u64 chi : {u64{0}, u64{73}, ~u64{0}})
                {
                    ZkProof reference{}, actual{};
                    u64 expectedValue = 0, actualValue = 0, pw = chi % q;
                    for (u64 g = 0; g != circuit.gateCount(); ++g)
                    {
                        const auto x = circuit.mOperands[2*g], y = circuit.mOperands[2*g+1];
                        const auto z = circuit.outputWire(g);
                        const auto a0 = mulMod(macs[x], macs[y], mod);
                        const auto a1 = (macs[z] + 2*q - mulMod(wires[x], macs[y], mod)
                            - mulMod(wires[y], macs[x], mod)) % q;
                        reference.mU = mulAddMod(pw, a0, reference.mU, mod);
                        reference.mV = mulAddMod(pw, a1, reference.mV, mod);
                        expectedValue = mulAddMod(pw, mulAddMod(keys[z], delta,
                            mulMod(keys[x], keys[y], mod), mod), expectedValue, mod);
                        pw = mulMod(pw, chi, mod);
                    }
                    reference.mU = addMod(reference.mU, macs[circuit.maskIndex()], mod);
                    reference.mV = (reference.mV + q - wires[circuit.maskIndex()]) % q;
                    expectedValue = addMod(expectedValue, keys[circuit.maskIndex()], mod);
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(zkMulProverResponse(executor,
                        circuit, wires, macs, chi, q, workspace, actual))));
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(zkMulVerifierValue(executor,
                        circuit, keys, chi, delta, q, workspace, actualValue))));
                    LOGVOLE_REQUIRE_EQ(actual.mU, reference.mU);
                    LOGVOLE_REQUIRE_EQ(actual.mV, reference.mV);
                    LOGVOLE_REQUIRE_EQ(actualValue, expectedValue);
                    LOGVOLE_REQUIRE_TRUE(zkAccept(actual, actualValue, delta, q));
                    if (chi == 73) { reference73 = reference; referenceValue73 = expectedValue; }
                }
                ZkProof untouched{123, 456};
                u64 untouchedValue = 789;
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulProverResponse(executor,
                    circuit, wires, {}, 1, q, workspace, untouched)));
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulVerifierValue(executor,
                    circuit, {}, 1, delta, q, workspace, untouchedValue)));
                LOGVOLE_REQUIRE_EQ(untouched.mU, 123u);
                LOGVOLE_REQUIRE_EQ(untouched.mV, 456u);
                LOGVOLE_REQUIRE_EQ(untouchedValue, 789u);
                auto invalid = circuit;
                invalid.mOperands.resize(1);
                PRNG rejected(toBlock(123)), saved(toBlock(123));
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulWitness(executor,
                    invalid, q, rejected, wires, wires.size(), workspace)));
                LOGVOLE_REQUIRE_TRUE(rejected.get<block>() == saved.get<block>());
                LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, expected));
                // An explicit one-worker partition executes inline with no pool threads.
                if (workers == 1 && query == 0)
                {
                    macoro::thread_pool idle;
                    CpuBenchmarkContext budget;
                    budget.mCpus = {0, 1, 2};
                    budget.mWorkerLimit = 1;
                    ZkMulCpuWorkspace capped(circuit, 1, &budget, settings);
                    LOGVOLE_REQUIRE_EQ(capped.workers(), 1u);
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(idle,
                        circuit, wires, macs, 73, q, capped, untouched)));
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(idle,
                        circuit, keys, 73, delta, q, capped, untouchedValue)));
                    LOGVOLE_REQUIRE_EQ(untouched.mU, reference73.mU);
                    LOGVOLE_REQUIRE_EQ(untouched.mV, reference73.mV);
                    LOGVOLE_REQUIRE_EQ(untouchedValue, referenceValue73);
                    PRNG replay(toBlock(0x574954, query));
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulWitness(idle,
                        circuit, q, replay, wires, wires.size(), capped)));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(wires, expected));
                    LOGVOLE_REQUIRE_EQ(budget.mPeakTaskThreads.load(), 1u);
                }
            }
            // Reject an unevaluated forward edge only after the same preceding
            // layers and input draws as the legacy evaluator.
            auto invalidLayer = circuit;
            invalidLayer.mOperands[2 * circuit.mWidth] =
                static_cast<u32>(invalidLayer.outputWire(circuit.mWidth));
            PRNG rejected(toBlock(0x424144)), referenceRejected(toBlock(0x424144));
            AlignedUnVec<u64> expectedPartial, actualPartial;
            expectedPartial.resize(wires.size());
            actualPartial.resize(wires.size());
            std::fill(expectedPartial.begin(), expectedPartial.end(), 777);
            std::fill(actualPartial.begin(), actualPartial.end(), 777);
            LOGVOLE_REQUIRE_FALSE(zkMulWitness(invalidLayer, q, referenceRejected,
                expectedPartial, expectedPartial.size(), settings));
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(onPool(zkMulWitness(executor,
                invalidLayer, q, rejected, actualPartial, actualPartial.size(), workspace))));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actualPartial, expectedPartial));
            LOGVOLE_REQUIRE_TRUE(rejected.get<block>() == referenceRejected.get<block>());
            ZkMulCpuWorkspace empty;
            PRNG random(toBlock(123));
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(zkMulWitness(executor,
                circuit, q, random, wires, 0, empty)));
        }
    }
}

void LogVole_Cpu_ZkProofMatchesReference(const oc::CLP&)
{
    macoro::thread_pool proofExecutor;
    auto proofWork = proofExecutor.make_work();
    proofExecutor.create_threads(1);
    PRNG random(toBlock(0x819, 0x514));
    for (u64 q : {257ULL, 2251799813554177ULL, 18014398508400641ULL})
    for (u64 budget : {3ULL, 83ULL, 4096ULL})
    {
        const seal::Modulus mod(q);
        ZkMulCircuit circuit;
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuitForBudget(budget, budget == 3 ? 1 : 7, random.get<block>(), circuit));
        AlignedUnVec<u64> wires;
        LOGVOLE_REQUIRE_TRUE(zkMulWitness(circuit, q, random, wires));
        std::vector<u64> macs(circuit.voleCount()), keys(circuit.voleCount());
        const u64 delta = 19;
        for (std::size_t i = 0; i < macs.size(); ++i)
        {
            macs[i] = random.get<u64>() % q;
            keys[i] = (macs[i] + q - mulMod(wires[i], delta, mod)) % q;
        }
        for (u64 chi : {u64{0}, u64{1}, u64{73}, ~u64{0}})
        {
            ZkProof reference{};
            u64 bReference = 0, pw = chi % q;
            for (u64 g = 0; g < circuit.gateCount(); ++g)
            {
                const u64 x = circuit.mOperands[2*g], y = circuit.mOperands[2*g+1];
                const u64 z = circuit.outputWire(g);
                const u64 a0 = mulMod(macs[x], macs[y], mod);
                const u64 a1 = (macs[z] + 2*q - mulMod(wires[x], macs[y], mod)
                    - mulMod(wires[y], macs[x], mod)) % q;
                const u64 b = mulAddMod(keys[z], delta, mulMod(keys[x], keys[y], mod), mod);
                reference.mU = mulAddMod(pw, a0, reference.mU, mod);
                reference.mV = mulAddMod(pw, a1, reference.mV, mod);
                bReference = mulAddMod(pw, b, bReference, mod);
                pw = mulMod(pw, chi, mod);
            }
            reference.mU = addMod(reference.mU, macs[circuit.maskIndex()], mod);
            reference.mV = (reference.mV + q - wires[circuit.maskIndex()]) % q;
            bReference = addMod(bReference, keys[circuit.maskIndex()], mod);
            for (u32 threads : {1, 2, 3, 4, 8, 12, 16})
            {
                LogVoleZkOptions proofSettings;
                proofSettings.mCpuPseudoReduce = threads != 1;
                proofSettings.mCpuVectorGates = threads != 1;
                proofSettings.mCpuVectorWitness = threads != 1;
                proofSettings.mCpuVectorMatMul = threads != 1;
                ZkMulCpuWorkspace workspace(circuit, threads, nullptr, proofSettings);
                ZkProof proof;
                u64 b = 0;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulProverResponse(proofExecutor, circuit, wires, macs, chi, q, workspace, proof)));
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(zkMulVerifierValue(proofExecutor, circuit, keys, chi, delta, q, workspace, b)));
                LOGVOLE_REQUIRE_EQ(proof.mU, reference.mU);
                LOGVOLE_REQUIRE_EQ(proof.mV, reference.mV);
                LOGVOLE_REQUIRE_EQ(b, bReference);
                LOGVOLE_REQUIRE_TRUE(zkAccept(proof, b, delta, q));
                proof.mU = (proof.mU + 1) % q;
                LOGVOLE_REQUIRE_TRUE(!zkAccept(proof, b, delta, q));
            }
        }
    }
}

void LogVole_Cpu_GadgetDigitWidths(const oc::CLP&)
{
    for (int bits : {52, 55})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, {bits, bits, bits, bits, bits, bits, bits, bits});
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x325, 0x786, 1);
        for (u32 digitBits : {31, 63, 64, 65, 110, 128, 208, 256, 416})
        for (bool centered : {false, true})
        {
            const u32 levels = (8 * bits + digitBits - 1) / digitBits + 1;
            std::vector<RnsPoly> digits;
            LOGVOLE_REQUIRE_TRUE(centered
                ? gadgetDecomposeBitsRangeCentered(poly, digitBits, 0, levels, ctx, digits)
                : gadgetDecomposeBitsRange(poly, digitBits, 0, levels, ctx, digits));
            RnsPoly actual;
            LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, digitBits, ctx, actual));
            LOGVOLE_REQUIRE_TRUE(std::equal(poly.mCoeffs.begin(), poly.mCoeffs.end(), actual.mCoeffs.begin()));
        }
    }
}
