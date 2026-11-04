#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include <cuda_runtime_api.h>
#endif

#include <algorithm>
#include <array>
#include <barrier>
#include <future>
#include <tuple>
#include <vector>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

namespace
{
    struct SessionResult
    {
        std::vector<u64> mKeys, mMacs;
        std::array<u64, 4> mSenderRandom{}, mReceiverRandom{};
    };

    SessionResult runSession(u64 seed, u32 threads, bool useGpu, std::barrier<>* start = nullptr)
    {
        constexpr u64 count = 1u << 16, delta = 19;
        LogVoleSender sender;
        LogVoleReceiver receiver;
        sender.mUseGpu = useGpu;
        receiver.mUseGpu = useGpu;
        sender.configure(count, 55, threads);
        receiver.configure(count, 55, threads);
        PRNG senderPrng(toBlock(0x53454e44, seed));
        PRNG receiverPrng(toBlock(0x52454356, seed));
        if (start) start->arrive_and_wait();
        auto offline = coproto::LocalAsyncSocket::makePair();
        auto setup = macoro::sync_wait(macoro::when_all_ready(
            sender.offline(delta, senderPrng, offline[0]), receiver.offline(offline[1])));
        std::get<0>(setup).result();
        std::get<1>(setup).result();
        SessionResult result;
        result.mKeys.resize(2 * count);
        result.mMacs.resize(2 * count);
        std::vector<u64> x(count);
        const seal::Modulus modulus(sender.modulus());
        for (u64 query = 0; query != 2; ++query)
        {
            for (u64 i = 0; i != count; ++i) x[i] = (i * 7 + query) % modulus.value();
            auto online = coproto::LocalAsyncSocket::makePair();
            auto keys = span<u64>(result.mKeys).subspan(query * count, count);
            auto macs = span<u64>(result.mMacs).subspan(query * count, count);
            auto outputs = macoro::sync_wait(macoro::when_all_ready(
                sender.send(keys, senderPrng, online[0]),
                receiver.receive(x, macs, receiverPrng, online[1])));
            std::get<0>(outputs).result();
            std::get<1>(outputs).result();
            for (u64 i = 0; i != count; ++i)
                LOGVOLE_REQUIRE_EQ(macs[i], mulAddMod(x[i], delta, keys[i], modulus));
        }
        senderPrng.get(result.mSenderRandom.data(), result.mSenderRandom.size());
        receiverPrng.get(result.mReceiverRandom.data(), result.mReceiverRandom.size());
        return result;
    }

    void sameResult(const SessionResult& first, const SessionResult& second, const char* stage)
    {
        LOGVOLE_REQUIRE_TRUE(first.mKeys == second.mKeys) << stage;
        LOGVOLE_REQUIRE_TRUE(first.mMacs == second.mMacs) << stage;
        LOGVOLE_REQUIRE_TRUE(first.mSenderRandom == second.mSenderRandom) << stage;
        LOGVOLE_REQUIRE_TRUE(first.mReceiverRandom == second.mReceiverRandom) << stage;
    }
}

void LogVole_Core_IndependentExecutionContexts(const CLP&)
{
    std::weak_ptr<ExecutionContext> lifetime;
    {
        RingParams params;
        params.mPolyModulusDegree = 1024;
        assignValues(params.mCoeffModulusBits, {30, 30});
        RingParams other = params;
        other.mExecutionContext = std::make_shared<ExecutionContext>();
        RingNttContext first, repeated, independent;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, first));
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, repeated));
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(other, independent));
        LOGVOLE_REQUIRE_TRUE(first.mContext == repeated.mContext);
        LOGVOLE_REQUIRE_TRUE(first.mContext != independent.mContext);
        ZpCrtContext firstZp, repeatedZp, independentZp;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, firstZp));
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, repeatedZp));
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(other, 20, independentZp));
        LOGVOLE_REQUIRE_TRUE(firstZp.mBatchEncoder == repeatedZp.mBatchEncoder);
        LOGVOLE_REQUIRE_TRUE(firstZp.mBatchEncoder != independentZp.mBatchEncoder);
        const auto firstA = sharedLhePublicANtt(first, 2);
        const auto firstB = sharedLencPublicBNtt(first, 2);
        LOGVOLE_REQUIRE_TRUE(firstA == sharedLhePublicANtt(repeated, 2));
        LOGVOLE_REQUIRE_TRUE(firstA != sharedLhePublicANtt(independent, 2));
        LOGVOLE_REQUIRE_TRUE(firstB == sharedLencPublicBNtt(repeated, 2));
        LOGVOLE_REQUIRE_TRUE(firstB != sharedLencPublicBNtt(independent, 2));
        lifetime = params.mExecutionContext;
        executionContext(params).mRingOps.reset();
        RnsPoly zero, output;
        resizeZero(zero.mCoeffs, ringPolyCoeffCount(params));
        LOGVOLE_REQUIRE_TRUE(ringAdd(zero, zero, first, output));
        LOGVOLE_REQUIRE_EQ(executionContext(params).mRingOps.mAddCount.load(), 1u);
        LOGVOLE_REQUIRE_EQ(executionContext(other).mRingOps.mAddCount.load(), 0u);
        const auto quota = osuCrypto::LogVole::detail::hardwareWorkerSlots();
        osuCrypto::LogVole::detail::ParallelWorkerSlotGuard one(
            quota, nullptr, params.mExecutionContext.get());
        osuCrypto::LogVole::detail::ParallelWorkerSlotGuard two(
            quota, nullptr, other.mExecutionContext.get());
        LOGVOLE_REQUIRE_EQ(one.grantedWorkers(), quota);
        LOGVOLE_REQUIRE_EQ(two.grantedWorkers(), quota);
        struct WorkerTag { const std::thread::id thread = std::this_thread::get_id(); };
        struct SharedTag { std::atomic<u32> count{0}; };
        std::barrier start(3);
        auto exerciseWorker = [&] {
            start.arrive_and_wait();
            WorkerTag* tag = nullptr;
            for (u32 repeat = 0; repeat != 1000; ++repeat)
            {
                auto& current = executionContext(params).deviceResources<WorkerTag>();
                executionContext(params).resources<SharedTag>().count.fetch_add(1);
                LOGVOLE_REQUIRE_TRUE(current.thread == std::this_thread::get_id());
                LOGVOLE_REQUIRE_TRUE(!tag || tag == &current);
                tag = &current;
            }
            return tag;
        };
        auto workerOne = std::async(std::launch::async, exerciseWorker);
        auto workerTwo = std::async(std::launch::async, exerciseWorker);
        auto* local = exerciseWorker();
        auto* remoteOne = workerOne.get();
        auto* remoteTwo = workerTwo.get();
        LOGVOLE_REQUIRE_TRUE(local != remoteOne && local != remoteTwo && remoteOne != remoteTwo);
        LOGVOLE_REQUIRE_EQ(executionContext(params).resources<SharedTag>().count.load(), 3000u);
    }
    LOGVOLE_REQUIRE_TRUE(lifetime.expired());
}

void LogVole_Core_SeededSessionIsolation(const CLP& cmd)
{
    const auto serial = runSession(91, 1, false);
    sameResult(serial, runSession(91, 1, false), "repeat with one worker");
    const auto expected = runSession(91, 2, false);
    (void)runSession(92, 1, false);
    sameResult(expected, runSession(91, 2, false), "repeat with two workers");
    std::barrier start(2);
    auto unrelated = std::async(std::launch::async, [&] {
        return runSession(93, 1, cmd.getOr("gpu", 0) != 0, &start);
    });
    sameResult(expected, runSession(91, 2, false, &start), "concurrent independent session");
    (void)unrelated.get();
}

void LogVole_Core_GpuMemoryPoolIsolation(const CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) { LOGVOLE_SKIP() << "requires CUDA device"; return; }
    std::weak_ptr<ExecutionContext> lifetime;
    {
        auto first = std::make_shared<ExecutionContext>();
        auto second = std::make_shared<ExecutionContext>();
        lifetime = first;
        gpu::GpuStream producer(*first), consumer(*second);
        auto pool = gpu::deviceMemoryPool(*first);
        LOGVOLE_REQUIRE_TRUE(pool != gpu::deviceMemoryPool(*second));
        LOGVOLE_REQUIRE_TRUE(pool == gpu::deviceMemoryPool(*first->resourceOwner(false)));
        {
            gpu::GpuPolyBuffer transfers;
            std::vector<RnsPoly> input(2), output;
            for (auto& poly : input) resizeZero(poly.mCoeffs, 1024);
            input[0].mCoeffs[5] = 17;
            input[1].mCoeffs[19] = 23;
            LOGVOLE_REQUIRE_TRUE(transfers.resizeWords(1024, 2, producer));
            LOGVOLE_REQUIRE_TRUE(transfers.upload(input, producer));
            LOGVOLE_REQUIRE_TRUE(transfers.download(output, producer));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(output[0].mCoeffs, input[0].mCoeffs));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(output[1].mCoeffs, input[1].mCoeffs));
            LOGVOLE_REQUIRE_TRUE(transfers.upload(input[1], 0, producer));
            LOGVOLE_REQUIRE_TRUE(transfers.downloadAsync(output[0], 0, producer));
            LOGVOLE_REQUIRE_TRUE(producer.sync());
            LOGVOLE_REQUIRE_TRUE(rangesEqual(output[0].mCoeffs, input[1].mCoeffs));
        }
        constexpr std::size_t words = 1u << 21;
        const std::size_t bytes = words * sizeof(u64);
        std::vector<u64> input(words), output(words);
        for (std::size_t i = 0; i < words; ++i) input[i] = i * 0x9e3779b97f4a7c15ull;
        gpu::GpuPolyBuffer source, destination, replacement;
        LOGVOLE_REQUIRE_TRUE(destination.resizeWords(words, 1, consumer));
        auto ready = std::shared_ptr<void>(gpu::gpuEventCreate(), gpu::gpuEventDestroy);
        LOGVOLE_REQUIRE_TRUE(ready != nullptr);
        for (u32 repeat = 0; repeat != 8; ++repeat)
        {
            LOGVOLE_REQUIRE_TRUE(source.resizeWords(words, 1, producer));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(source.data(producer), input.data(), bytes, producer.raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuEventRecord(ready.get(), producer.raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuStreamWaitEvent(consumer.raw(), ready.get()));
            const auto* pointer = source.data(consumer);
            for (u32 copy = 0; copy != 32; ++copy)
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2D(destination.data(consumer), pointer, bytes, consumer.raw()));
            source.release();
            // Reusing this allocation on the producer must wait for the
            // foreign consumer, including all copies queued before release.
            LOGVOLE_REQUIRE_TRUE(replacement.resizeWords(words, 1, producer));
            LOGVOLE_REQUIRE_TRUE(replacement.zero(producer));
            LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(output.data(), destination.data(consumer), bytes, consumer));
            LOGVOLE_REQUIRE_TRUE(consumer.sync());
            LOGVOLE_REQUIRE_TRUE(output == input);
            replacement.release();
        }
        LOGVOLE_REQUIRE_TRUE(producer.sync());
        LOGVOLE_REQUIRE_TRUE(pool->stats().mCacheHits >= 8);
        LOGVOLE_REQUIRE_EQ(pool->stats().mUntrackedUses, 0u);
        // Legacy raw access remains safe when its stream cannot be recorded.
        LOGVOLE_REQUIRE_TRUE(source.resizeWords(words, 1, producer));
        LOGVOLE_REQUIRE_TRUE(source.zero(producer));
        LOGVOLE_REQUIRE_TRUE(producer.sync());
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2D(destination.data(consumer), source.data(), bytes, consumer.raw()));
        source.release();
        LOGVOLE_REQUIRE_TRUE(source.resizeWords(words, 1, producer));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(source.data(producer), input.data(), bytes, producer.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(output.data(), destination.data(consumer), bytes, consumer));
        LOGVOLE_REQUIRE_TRUE(consumer.sync());
        LOGVOLE_REQUIRE_TRUE(std::all_of(output.begin(), output.end(), [](u64 value) { return value == 0; }));
        LOGVOLE_REQUIRE_TRUE(pool->stats().mUntrackedUses != 0);
    }
    LOGVOLE_REQUIRE_TRUE(lifetime.expired());
    gpu::GpuPolyBuffer retained;
    {
        auto execution = std::make_shared<ExecutionContext>();
        lifetime = execution;
        gpu::GpuStream temporary(*execution);
        LOGVOLE_REQUIRE_TRUE(retained.resizeWords(1024, 1, temporary));
        LOGVOLE_REQUIRE_TRUE(retained.zero(temporary));
    }
    LOGVOLE_REQUIRE_TRUE(lifetime.expired());
    retained.release();
#else
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_Core_GpuSeededSessionIsolation(const CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) { LOGVOLE_SKIP() << "requires CUDA device"; return; }
    const auto expected = runSession(91, 2, true);
    sameResult(expected, runSession(91, 2, true), "repeat GPU session");
    std::barrier start(2);
    auto unrelated = std::async(std::launch::async, [&] {
        return runSession(93, 1, true, &start);
    });
    sameResult(expected, runSession(91, 2, true, &start), "concurrent GPU session");
    (void)unrelated.get();
#else
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_Core_GpuOptionIsolation(const CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    using namespace tests_libOTe::logvole_test;
    if (!gpu::available()) { LOGVOLE_SKIP() << "requires CUDA device"; return; }
    struct RestoreEnvironment
    {
        const char* name;
        bool present;
        std::string value;
        explicit RestoreEnvironment(const char* key) : name(key), present(std::getenv(key))
        { if (present) value = std::getenv(key); }
        ~RestoreEnvironment()
        {
            if (present) setEnvironment(name, value.c_str(), 1);
            else unsetEnvironment(name);
        }
    } restoreEnabled("LOGVOLE_GPU_FUSED_SAMPLE"), restoreMinimum("LV_FUSED_SAMPLE_MIN_POLYS"),
      restoreGadgetMode("LV_GPU_NOGOLD_H200_GADGET_GARNER");
    setEnvironment("LOGVOLE_GPU_FUSED_SAMPLE", "1", 1);
    setEnvironment("LV_FUSED_SAMPLE_MIN_POLYS", "1", 1);
    setEnvironment("LV_GPU_NOGOLD_H200_GADGET_GARNER", "12", 1);
    gpu::KernelConfiguration first;
    setEnvironment("LOGVOLE_GPU_FUSED_SAMPLE", "0", 1);
    setEnvironment("LV_GPU_NOGOLD_H200_GADGET_GARNER", "4", 1);
    gpu::KernelConfiguration second;
    constexpr u32 n = 8192, words = 4 * n + gpu::kSampleSlackWords, count = 1024;
    LOGVOLE_REQUIRE_TRUE(gpu::gpuFusedSamplerActive(n, words, count, &first));
    LOGVOLE_REQUIRE_FALSE(gpu::gpuFusedSamplerActive(n, words, count, &second));
    LOGVOLE_REQUIRE_FALSE(gpu::gpuFusedSamplerActive(n, words, count));
    LOGVOLE_REQUIRE_TRUE(gpu::h200Fp52GadgetConstantsEnabled(&first));
    LOGVOLE_REQUIRE_TRUE(gpu::h200Fp52GadgetPredivEnabled(&first));
    LOGVOLE_REQUIRE_FALSE(gpu::h200Fp52GadgetConstantsEnabled(&second));
    LOGVOLE_REQUIRE_FALSE(gpu::h200Fp52GadgetPredivEnabled(&second));
    LOGVOLE_REQUIRE_FALSE(gpu::h200Fp52GadgetConstantsEnabled());
    first.setOptionsCaching(false);
    LOGVOLE_REQUIRE_FALSE(gpu::gpuFusedSamplerActive(n, words, count, &first));
    LOGVOLE_REQUIRE_FALSE(gpu::h200Fp52GadgetConstantsEnabled(&first));
    LOGVOLE_REQUIRE_FALSE(gpu::h200Fp52GadgetPredivEnabled(&first));
    first.setOptionsCaching(true);
    LOGVOLE_REQUIRE_TRUE(gpu::gpuFusedSamplerActive(n, words, count, &first));
    LOGVOLE_REQUIRE_TRUE(gpu::h200Fp52GadgetConstantsEnabled(&first));
    LOGVOLE_REQUIRE_TRUE(gpu::h200Fp52GadgetPredivEnabled(&first));
    setEnvironment("LV_GPU_NOGOLD_H200_GADGET_GARNER", "10", 1);
    gpu::KernelConfiguration constantsOnly;
    LOGVOLE_REQUIRE_TRUE(gpu::h200Fp52GadgetConstantsEnabled(&constantsOnly));
    LOGVOLE_REQUIRE_FALSE(gpu::h200Fp52GadgetPredivEnabled(&constantsOnly));
    LOGVOLE_REQUIRE_TRUE(gpu::h200Fp52GadgetPredivEnabled(&first));
    RestoreEnvironment restoreValidation("LV_GPU_DEFER_GOLDEN_VALIDATION");
    setEnvironment("LV_GPU_DEFER_GOLDEN_VALIDATION", "1", 1);
    ExecutionContext firstExecution;
    LOGVOLE_REQUIRE_TRUE(gpu::deferredGoldenValidationEnabled(firstExecution));
    setEnvironment("LV_GPU_DEFER_GOLDEN_VALIDATION", "0", 1);
    ExecutionContext secondExecution;
    LOGVOLE_REQUIRE_TRUE(gpu::deferredGoldenValidationEnabled(firstExecution));
    LOGVOLE_REQUIRE_FALSE(gpu::deferredGoldenValidationEnabled(secondExecution));
    firstExecution.mCacheGpuOptions = false;
    LOGVOLE_REQUIRE_FALSE(gpu::deferredGoldenValidationEnabled(firstExecution));

#if CUDART_VERSION >= 11000
    if (gpu::gpuDeviceIsH200())
    {
        std::size_t originalLimit = 0;
        const auto queried = cudaDeviceGetLimit(&originalLimit, cudaLimitPersistingL2CacheSize);
        if (queried == cudaErrorUnsupportedLimit || queried == cudaErrorNotSupported)
        {
            (void)cudaGetLastError();
            return;
        }
        LOGVOLE_REQUIRE_EQ(queried, cudaSuccess);
        struct RestoreL2Limit
        {
            std::size_t mOriginal;
            ~RestoreL2Limit() { (void)cudaDeviceSetLimit(cudaLimitPersistingL2CacheSize, mOriginal); }
        } restoreLimit{originalLimit};
        const auto disabled = cudaDeviceSetLimit(cudaLimitPersistingL2CacheSize, 0);
        if (disabled == cudaErrorUnsupportedLimit || disabled == cudaErrorNotSupported)
        {
            (void)cudaGetLastError();
            return;
        }
        LOGVOLE_REQUIRE_EQ(disabled, cudaSuccess);
        RestoreEnvironment restoreRootL2("LV_GPU_NOGOLD_H200_ROOT_L2"),
            restoreH200Ntt("LV_GPU_NTT_LOG14_H200");
        setEnvironment("LV_GPU_NOGOLD_H200_ROOT_L2", "3", 1);
        setEnvironment("LV_GPU_NTT_LOG14_H200", "1", 1);
        gpu::KernelConfiguration rootOptions;
        gpu::RingConstView view{};
        view.mN = 16384;
        view.mLogN = 14;
        view.mRho = 8;
        view.mKernelConfiguration = &rootOptions;
        LOGVOLE_REQUIRE_TRUE(gpu::prepareH200RootPersistence(view));
        std::size_t afterLimit = 0;
        LOGVOLE_REQUIRE_EQ(cudaDeviceGetLimit(&afterLimit, cudaLimitPersistingL2CacheSize), cudaSuccess);
        LOGVOLE_REQUIRE_EQ(afterLimit, 0u);
        LOGVOLE_REQUIRE_EQ(view.mH200RootL2MaxWindow, 0u);

        // The application may reserve capacity explicitly; ring preparation may
        // use that capacity without resizing the shared CUDA-context set-aside.
        LOGVOLE_REQUIRE_EQ(cudaDeviceSetLimit(cudaLimitPersistingL2CacheSize, std::size_t{1} << 20), cudaSuccess);
        std::size_t configuredLimit = 0;
        LOGVOLE_REQUIRE_EQ(cudaDeviceGetLimit(&configuredLimit, cudaLimitPersistingL2CacheSize), cudaSuccess);
        LOGVOLE_REQUIRE_TRUE(gpu::prepareH200RootPersistence(view));
        LOGVOLE_REQUIRE_EQ(cudaDeviceGetLimit(&afterLimit, cudaLimitPersistingL2CacheSize), cudaSuccess);
        LOGVOLE_REQUIRE_EQ(afterLimit, configuredLimit);
        LOGVOLE_REQUIRE_TRUE(view.mH200RootL2MaxWindow <= configuredLimit);
        LOGVOLE_REQUIRE_TRUE(view.mH200RootL2MaxWindow != 0);
    }
#endif
#else
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}
