#include "libOTe_Tests/LogVole_RingStatsTestUtil.h"
#include "libOTe/Vole/LogVole/LogVoleGpuCompatibility.h"
#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe_Tests/LogVole_TestOptions.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVoleGarbled.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "seal/util/ntt.h"
#include "seal/util/rns.h"
#include "seal/util/rlwe.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cfenv>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <future>
#include <thread>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#if defined(ENABLE_LOGVOLE_CUDA) && defined(__linux__) && defined(__x86_64__)
#include <xmmintrin.h>
#endif

using namespace osuCrypto::LogVole;

namespace
{



    void swap_moduli_for_test(RingNttContext& ctx, std::size_t first, std::size_t second)
    {
        if (ctx.mGpuLightweight)
        {
            auto changed = std::make_shared<RingModulusMetadata>(*ctx.mRawModuli);
            std::swap(changed->mValues[first], changed->mValues[second]);
            std::swap(changed->mBitCounts[first], changed->mBitCounts[second]);
            ctx.mRawModuli = std::move(changed);
        }
        else std::swap(ctx.mModuli[first], ctx.mModuli[second]);
    }

    RingParams make_small_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30 });
        return params;
    }

    RingParams make_four_limb_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30, 30, 30 });
        return params;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << " coeff index " << i;
        }
    }

    RingNttContext cpuReferenceContext(const RingNttContext& source)
    {
        auto options = source.mExecutionOptions;
        options.mUseGpu = false;
        RingNttContext result;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(source.mParams, result,
            std::make_shared<RingContextFactory>(options, source.mFactory->protocolService()),
            ProtocolCacheScope({}, source.mResourceScope.mRole)));
        return result;
    }

    void expect_batch_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    // Raw backend tests keep their CPU oracle dispatch while explicitly owning
    // GPU tables. Discovery belongs to this cold fixture boundary.
    void prepareGpuTableOwners(RingNttContext& ctx)
    {
        ctx.mResourceScope.mTables = std::make_shared<gpu::GpuTableCache>(ctx.mExecutionOptions);
        ctx.mGpuSetup = std::make_shared<gpu::GpuSetupContext>(ctx.mExecutionOptions,
            ctx.mHostProfiler, ctx.mFactory->protocolService(), ctx.mResourceScope.mTables->gpuAvailable());
    }

    void expect_single_limb_batching_parity(const RingParams& ring, std::uint32_t plaintextBits)
    {
        macoro::thread_pool crtExecutor;
        std::array<ZpDecodeBuffer, 3> crtDecodeBuffers;
        // Compare two explicitly owned eager SEAL representations.
        osuCrypto::LogVoleExecutionOptions options;
        options.mUseGpu = true;
        options.mAdvanced.mContexts.mLightweightRing = false;
        options.mAdvanced.mContexts.mLightweightCrt = false;
        options.mAdvanced.mContexts.mBatchingSingleLimb = false;
        ZpCrtContext reference, candidate;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(ring, plaintextBits, reference,
            std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(options, nullptr))));
        options.mAdvanced.mContexts.mBatchingSingleLimb = true;
        auto factory = std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(options, nullptr));
        {
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(ring, plaintextBits, candidate, factory));
            ZpCrtContext again;
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(ring, plaintextBits, again, factory));
            LOGVOLE_EXPECT_TRUE(again.mBatchingContext == candidate.mBatchingContext);
        }
        // Separate owners preserve the exact ring parameters and full-Q plaintext lift.
        LOGVOLE_EXPECT_TRUE(reference.mRing.mContext->key_context_data()->parms() ==
            candidate.mRing.mContext->key_context_data()->parms());
        LOGVOLE_EXPECT_TRUE(reference.mBatchingContext != candidate.mBatchingContext);
        LOGVOLE_REQUIRE_EQ(ringModulusCount(candidate.mRing), ring.mCoeffModulusBits.size());
        LOGVOLE_REQUIRE_EQ(candidate.mBatchingContext->key_context_data()->parms().coeff_modulus().size(), 1u);
        LOGVOLE_REQUIRE_TRUE(candidate.mBatchingContext->parameters_set());
        LOGVOLE_REQUIRE_TRUE(candidate.mBatchingContext->first_context_data()->qualifiers().using_batching);
        LOGVOLE_EXPECT_EQ(reference.mPlaintextModulus, candidate.mPlaintextModulus);
        LOGVOLE_EXPECT_EQ(reference.mPlaintextModulusBits, candidate.mPlaintextModulusBits);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(reference.mPlaintextLiftModQj, candidate.mPlaintextLiftModQj));
        const auto* fullTables = reference.mBatchingContext->first_context_data()->plain_ntt_tables();
        const auto* singleTables = candidate.mBatchingContext->first_context_data()->plain_ntt_tables();
        LOGVOLE_REQUIRE_TRUE(fullTables && singleTables);
        LOGVOLE_REQUIRE_EQ(fullTables->get_root(), singleTables->get_root());
        LOGVOLE_REQUIRE_EQ(fullTables->inv_degree_modulo().operand, singleTables->inv_degree_modulo().operand);
        LOGVOLE_REQUIRE_EQ(fullTables->inv_degree_modulo().quotient, singleTables->inv_degree_modulo().quotient);
        for (std::size_t i = 0; i < ring.mPolyModulusDegree; ++i)
        {
            const auto fullRoot = fullTables->get_from_root_powers(i);
            const auto singleRoot = singleTables->get_from_root_powers(i);
            const auto fullInverse = fullTables->get_from_inv_root_powers(i);
            const auto singleInverse = singleTables->get_from_inv_root_powers(i);
            LOGVOLE_REQUIRE_TRUE(fullRoot.operand == singleRoot.operand && fullRoot.quotient == singleRoot.quotient);
            LOGVOLE_REQUIRE_TRUE(fullInverse.operand == singleInverse.operand && fullInverse.quotient == singleInverse.quotient);
        }
        std::vector<std::uint64_t> labels(ring.mPolyModulusDegree - 3u);
        for (std::size_t i = 0; i < labels.size(); ++i)
            labels[i] = i % 3u ? i % reference.mPlaintextModulus : reference.mPlaintextModulus - 1u;
        seal::Plaintext fullPlain, singlePlain;
        reference.mBatchEncoder->encode(labels, fullPlain);
        candidate.mBatchEncoder->encode(labels, singlePlain);
        LOGVOLE_REQUIRE_EQ(fullPlain.coeff_count(), singlePlain.coeff_count());
        LOGVOLE_REQUIRE_TRUE(std::equal(fullPlain.data(), fullPlain.data() + fullPlain.coeff_count(), singlePlain.data()));
        std::vector<std::uint64_t> fullDecoded, singleDecoded;
        reference.mBatchEncoder->decode(fullPlain, fullDecoded);
        candidate.mBatchEncoder->decode(singlePlain, singleDecoded);
        LOGVOLE_REQUIRE_TRUE(fullDecoded == singleDecoded);
        auto expectedLabels = labels;
        expectedLabels.resize(ring.mPolyModulusDegree, 0u);
        LOGVOLE_REQUIRE_TRUE(singleDecoded == expectedLabels);
        for (bool scaleAndRound : {false, true})
        {
            RnsPoly fullEncoded, singleEncoded;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(reference, labels, scaleAndRound, 7u, 1u, fullEncoded));
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(candidate, labels, scaleAndRound, 7u, 1u, singleEncoded));
            expect_poly_equal(fullEncoded, singleEncoded);
            AlignedUnVec<std::uint64_t> fullUnwrapped, singleUnwrapped;
            // Force the CPU CRT/decode path here. GPU plaintext tables have
            // already been checked word for word, without its shared cache.
            auto fullHost = reference, singleHost = candidate;
            fullHost.mRing = cpuReferenceContext(reference.mRing);
            singleHost.mRing = cpuReferenceContext(candidate.mRing);
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtExecutor, crtDecodeBuffers, fullHost, {fullEncoded}, labels.size(), scaleAndRound, 1u, fullUnwrapped)));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtExecutor, crtDecodeBuffers, singleHost, {singleEncoded}, labels.size(), scaleAndRound, 1u, singleUnwrapped)));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fullUnwrapped, singleUnwrapped));
            // A toy one-limb ring can have Q/p too small for exact rounded
            // recovery, independently of the batching helper. Production
            // multi-limb rings retain the original exact round trip.
            if (!scaleAndRound || ring.mCoeffModulusBits.size() > 1u)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(singleUnwrapped, labels));
        }
    }
#endif
}

void LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch(const oc::CLP& cmd)
{
    const auto identityService = ProtocolCacheService::create();
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    const std::vector<std::uint64_t> input{1, 2, 3, 0xffffffffffffffffull};
    // Destroy the producer's execution context before consuming its token.
    // MSVC std::async may retain a pool worker after future.get().
    std::packaged_task<std::shared_ptr<gpu::DeviceScalars>()> task(
        [&] {
            gpu::GpuExecutionContext execution;
            return gpu::uploadScalars(input, execution.mainStream());
        });
    auto result = task.get_future();
    std::thread worker(std::move(task));
    worker.join();
    auto uploaded = result.get();
    LOGVOLE_REQUIRE_TRUE(uploaded);
    LOGVOLE_REQUIRE_TRUE(uploaded->producerStream() == nullptr);
    std::vector<std::uint64_t> fetched(input.size());
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*uploaded, fetched, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(fetched == input);
    {
        GarbledLabelBatch labels;
        labels.mLayout = GarbledLabelLayout(1, 4);
        labels.mModulus = 257;
        labels.mDevice = uploaded;
        labels.fetch(readbackExecution.readbackStream());
        LOGVOLE_REQUIRE_TRUE(rangesEqual(labels.mScalars, input));
        const auto label = labels.label(0);
        for (unsigned j = 0; j != 3; ++j) LOGVOLE_REQUIRE_EQ(label[j], input[j]);
    }

    // The exported scalar owns its allocation stream after the original
    // GpuStream wrapper has drained and released its own scratch. Neither a
    // global allocator nor TLS retirement may be needed to release the result.
    auto detached = std::make_shared<gpu::DeviceScalars>();
    std::weak_ptr<gpu::OwnedGpuStream> detachedStream;
    std::weak_ptr<gpu::GpuMemoryPool> detachedMemory;
    {
        gpu::GpuStream producer;
        LOGVOLE_REQUIRE_TRUE(detached->resize(input.size(), producer));
        detachedStream = producer.allocationOwner();
        detachedMemory = producer.allocationOwner()->memory();
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(detached->data(), input.data(),
            input.size() * sizeof(std::uint64_t), producer.raw()));
        LOGVOLE_REQUIRE_TRUE(!detached->resize(std::numeric_limits<std::size_t>::max(), producer));
        LOGVOLE_REQUIRE_TRUE(detached->count() == input.size());
    }
    LOGVOLE_REQUIRE_TRUE(!detachedStream.expired() && !detachedMemory.expired());
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*detached, fetched, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(fetched == input);
    auto readerOutput = std::make_shared<gpu::DeviceScalars>();
    std::weak_ptr<gpu::OwnedGpuStream> readerOwner;
    {
        gpu::GpuStream reader;
        LOGVOLE_REQUIRE_TRUE(readerOutput->resize(input.size(), reader));
        readerOwner = reader.allocationOwner();
        const auto& source = *detached;
        LOGVOLE_REQUIRE_TRUE(source.prepareUse(reader));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2D(readerOutput->data(), source.data(),
            input.size() * sizeof(std::uint64_t), reader.raw()));
        // Release the source with an asynchronous reader still queued. A const
        // borrow also participates in completion ownership.
        detached.reset();
        LOGVOLE_REQUIRE_TRUE(detachedStream.expired() && detachedMemory.expired());
    }
    LOGVOLE_REQUIRE_TRUE(!readerOwner.expired());
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*readerOutput, fetched, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(fetched == input);
    std::weak_ptr<gpu::OwnedGpuStream> foreignWriter;
    {
        gpu::GpuStream writer;
        LOGVOLE_REQUIRE_TRUE(readerOutput->prepareUse(writer));
        foreignWriter = writer.allocationOwner();
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(readerOutput->data(),
            input.size() * sizeof(std::uint64_t), writer.raw()));
        // Release while the foreign write may still be pending. The original
        // allocation cannot return to its pool until that write completes.
        readerOutput.reset();
        LOGVOLE_REQUIRE_TRUE(!foreignWriter.expired());
    }
    LOGVOLE_REQUIRE_TRUE(foreignWriter.expired());
    LOGVOLE_REQUIRE_TRUE(readerOwner.expired());

    const auto runId = identityService->allocate();
    // Each party owns its execution and pool, including when both parties
    // submit work from the same host worker.
    gpu::GpuExecutionContext senderExecution, receiverExecution;
    LOGVOLE_REQUIRE_TRUE(senderExecution.mainStream().raw() != receiverExecution.mainStream().raw());
    LOGVOLE_REQUIRE_TRUE(senderExecution.mainStream().allocationOwner()->memory() !=
        receiverExecution.mainStream().allocationOwner()->memory());
    std::vector<std::uint64_t> expected(1u << 18, 0x9e3779b97f4a7c15ull);
    for (unsigned iteration = 0; iteration < 8; ++iteration)
    {
        void* previous = nullptr;
        {
            auto& stream = senderExecution.mainStream();
            previous = stream.raw();
            gpu::DeviceScalars retired;
            LOGVOLE_REQUIRE_TRUE(retired.resize(expected.size(), stream));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(retired.data(),
                expected.size() * sizeof(std::uint64_t), stream.raw()));
        }
        {
            uploaded = gpu::uploadScalars(expected, receiverExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(uploaded);
            LOGVOLE_REQUIRE_TRUE(gpu::gpuStreamSync(previous));
            fetched.resize(expected.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*uploaded, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_GpuImmediateErrors(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }

    gpu::GpuStream failedStream;
    std::uint64_t value = 0x123456789abcdef0ull;
    std::string firstMessage;
    std::exception_ptr firstError;
    try
    {
        (void)gpu::gpuMemcpyH2D(nullptr, &value, sizeof(value), failedStream.raw());
    }
    catch (const std::runtime_error& error)
    {
        firstMessage = error.what();
        firstError = std::current_exception();
    }
    LOGVOLE_REQUIRE_TRUE(firstMessage.find("H2D") != std::string::npos);
    LOGVOLE_REQUIRE_TRUE(firstMessage.find("CUDA 1") != std::string::npos);
    LOGVOLE_REQUIRE_TRUE(firstMessage.find("invalid argument") != std::string::npos);
    std::string secondMessage;
    try
    {
        (void)gpu::gpuMemcpyD2H(&value, nullptr, sizeof(value), failedStream.raw());
    }
    catch (const std::runtime_error& error)
    {
        secondMessage = error.what();
    }
    LOGVOLE_REQUIRE_TRUE(secondMessage.find("D2H") != std::string::npos);
    LOGVOLE_REQUIRE_TRUE(secondMessage.find("CUDA 1") != std::string::npos);
    LOGVOLE_REQUIRE_TRUE(secondMessage.find("invalid argument") != std::string::npos);
    try { std::rethrow_exception(firstError); }
    catch (const std::runtime_error& error)
    {
        LOGVOLE_REQUIRE_TRUE(firstMessage == error.what());
    }

    // Argument errors do not poison an unrelated owner or leave sticky history.
    gpu::GpuStream validStream;
    gpu::OwnedGpuBuffer storage(validStream.allocationOwner(), 4 * sizeof(std::uint32_t));
    std::uint64_t fetched = 0;
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(storage.data(), &value, sizeof(value), validStream.raw()));
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(&fetched, storage.data(), sizeof(fetched), validStream.raw()));
    LOGVOLE_REQUIRE_TRUE(validStream.sync());
    LOGVOLE_REQUIRE_EQ(fetched, value);
    // An unsupported geometry remains a normal decline before any submission.
    auto* map = static_cast<std::uint32_t*>(storage.data());
    LOGVOLE_REQUIRE_TRUE(!gpu::launchPrepareRawSlotMaps(3, map, map, validStream.raw()));
    LOGVOLE_REQUIRE_TRUE(gpu::launchPrepareRawSlotMaps(2, map, map + 2, validStream.raw()));
    std::array<std::uint32_t, 4> maps{};
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(maps.data(), map, sizeof(maps), validStream.raw()));
    LOGVOLE_REQUIRE_TRUE(validStream.sync());
    const std::array<std::uint32_t, 4> expectedMaps{0, 1, 0, 1};
    LOGVOLE_REQUIRE_TRUE(maps == expectedMaps);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_GpuBufferResizeBounds(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    RingNttContext smallContext{}, largeContext{};
    auto largeParams = make_four_limb_params();
    largeParams.mPolyModulusDegree = 4096;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), smallContext));
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(largeParams, largeContext));
    prepareGpuTableOwners(smallContext);
    prepareGpuTableOwners(largeContext);
    auto small = gpu::GpuRing::get(smallContext);
    auto large = gpu::GpuRing::get(largeContext);
    LOGVOLE_REQUIRE_TRUE(small && large);
    auto& stream = operationExecution.mainStream();
    gpu::GpuPolyBuffer buffer;
    LOGVOLE_REQUIRE_TRUE(buffer.resize(*small, 1, stream));
    const auto oldData = buffer.data(stream);
    LOGVOLE_REQUIRE_TRUE(buffer.resize(*large, 1, stream));
    // A geometry change needs a new allocation while the smaller one is live.
    LOGVOLE_REQUIRE_TRUE(buffer.data(stream) != oldData);
    std::vector<std::uint64_t> expected(large->polyWords()), fetched(expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
        expected[i] = 0xfedcba9876543210ull ^ i;
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(buffer.data(stream), expected.data(), buffer.bytes(), stream.raw()));
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), buffer.data(stream), buffer.bytes(), stream.raw()));
    LOGVOLE_REQUIRE_TRUE(stream.sync());
    LOGVOLE_REQUIRE_TRUE(fetched == expected);
    const auto preserved = buffer.data(stream);
    const auto invalid = std::numeric_limits<std::size_t>::max() / large->polyBytes() + 2;
    LOGVOLE_REQUIRE_TRUE(!buffer.resize(*large, invalid, stream));
    LOGVOLE_REQUIRE_TRUE(buffer.data(stream) == preserved);
    LOGVOLE_REQUIRE_EQ(buffer.count(), 1ull);
    LOGVOLE_REQUIRE_EQ(buffer.polyWords(), large->polyWords());
    LOGVOLE_REQUIRE_TRUE(buffer.resize(*large, 1, stream));
    LOGVOLE_REQUIRE_TRUE(buffer.data(stream) == preserved);
    LOGVOLE_REQUIRE_TRUE(buffer.resize(*small, 0, stream));
    LOGVOLE_REQUIRE_TRUE(buffer.data(stream) == nullptr);
    LOGVOLE_REQUIRE_EQ(buffer.count(), 0ull);
    LOGVOLE_REQUIRE_EQ(buffer.polyWords(), small->polyWords());

    // The exported allocation retains its producer after the wrapper dies.
    gpu::GpuPolyBuffer exported;
    std::weak_ptr<gpu::OwnedGpuStream> producerOwner;
    std::weak_ptr<gpu::GpuMemoryPool> allocationOwner;
    {
        gpu::GpuStream producer;
        producerOwner = producer.allocationOwner();
        allocationOwner = producer.allocationOwner()->memory();
        LOGVOLE_REQUIRE_TRUE(exported.resize(*large, 1, producer));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(exported.data(producer),
            expected.data(), exported.bytes(), producer.raw()));
    }
    LOGVOLE_REQUIRE_TRUE(!producerOwner.expired() && !allocationOwner.expired());
    gpu::GpuStream consumer;
    gpu::GpuPolyBuffer copied(*large, 1, consumer);
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2D(copied.data(consumer), exported.data(consumer),
        exported.bytes(), consumer.raw()));
    // Move preserves the pending read and both owners; replacing that moved
    // allocation must wait for the read before returning it to its origin pool.
    gpu::GpuPolyBuffer moved(std::move(exported));
    LOGVOLE_REQUIRE_TRUE(exported.empty() && !exported.address());
    LOGVOLE_REQUIRE_TRUE(!moved.resize(*large, invalid, consumer));
    LOGVOLE_REQUIRE_TRUE(moved.resize(*small, 1, consumer));
    LOGVOLE_REQUIRE_TRUE(producerOwner.expired() && allocationOwner.expired());
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), copied.data(consumer),
        copied.bytes(), consumer.raw()));
    LOGVOLE_REQUIRE_TRUE(consumer.sync());
    LOGVOLE_REQUIRE_TRUE(fetched == expected);
    // Reusing capacity on another stream must order the new write after reads
    // already queued on the previous stream.
    LOGVOLE_REQUIRE_TRUE(copied.resize(*large, 1, stream));
    LOGVOLE_REQUIRE_TRUE(copied.zero(stream));
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), copied.data(consumer),
        copied.bytes(), consumer.raw()));
    LOGVOLE_REQUIRE_TRUE(consumer.sync());
    LOGVOLE_REQUIRE_TRUE(std::all_of(fetched.begin(), fetched.end(), [](auto x) { return x == 0; }));
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_GpuMemoryPoolLifecycle(const oc::CLP& cmd)
{
    const auto identityService = ProtocolCacheService::create();
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    osuCrypto::LogVoleExecutionOptions deviceOptions;
    deviceOptions.mUseGpu = true;
    {
        RingNttContext math;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), math));
        auto firstExecution = std::make_shared<gpu::GpuExecutionContext>(math.mExecutionOptions, nullptr, math.mFactory->protocolService());
        auto secondExecution = std::make_shared<gpu::GpuExecutionContext>(math.mExecutionOptions, nullptr, math.mFactory->protocolService());
        std::weak_ptr<gpu::GpuExecutionContext> firstLifetime = firstExecution;
        auto first = math, second = math, again = math;
        LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(first, firstExecution));
        LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(second, secondExecution));
        LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(again, firstExecution));
        LOGVOLE_REQUIRE_TRUE(first.mFactoryOwner == again.mFactoryOwner);
        LOGVOLE_REQUIRE_TRUE(first.mFactoryOwner != second.mFactoryOwner);
        LOGVOLE_REQUIRE_TRUE(first.mFactoryOwner->mFactoryOwner == math.mFactoryOwner);
        LOGVOLE_REQUIRE_TRUE(first.mPublicCache == again.mPublicCache);
        LOGVOLE_REQUIRE_TRUE(first.mPublicCache != second.mPublicCache && first.mPublicCache != math.mPublicCache);
        LOGVOLE_REQUIRE_TRUE(first.mResourceScope.mTables == math.mResourceScope.mTables);
        LOGVOLE_REQUIRE_TRUE(gpu::contextStream(first).raw() != gpu::contextStream(second).raw());
        // A live bound record is reused across workers and role changes.
        std::packaged_task<void()> task([&] {
            auto workerContext = math;
            LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(workerContext, firstExecution));
            LOGVOLE_REQUIRE_TRUE(workerContext.mFactoryOwner == first.mFactoryOwner);
        });
        auto completed = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        completed.get();
        {
            auto host = math;
            LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(host, firstExecution));
            LOGVOLE_REQUIRE_TRUE(host.mFactoryOwner == first.mFactoryOwner);
            LOGVOLE_REQUIRE_TRUE(host.mContext && !host.mGpuLightweight);
            LOGVOLE_REQUIRE_TRUE(validateRingContextMetadata(host));
        }
        auto& stream = gpu::contextStream(first);
        std::weak_ptr<gpu::OwnedGpuStream> native = stream.allocationOwner();
        gpu::OwnedGpuBuffer exported(stream.allocationOwner(), 4 * sizeof(std::uint64_t));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(exported.data(), exported.size(), stream.raw()));
        first = {}; again = {}; firstExecution.reset();
        LOGVOLE_REQUIRE_TRUE(firstLifetime.expired());
        // The weak binding index cannot form a cycle. Exported storage keeps
        // only the native producer alive after its session domain disappears.
        LOGVOLE_REQUIRE_FALSE(native.expired());
        {
            std::array<std::uint64_t, 4> fetched{1, 1, 1, 1};
            const auto producer = native.lock();
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), exported.data(), exported.size(), producer->raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuStreamSync(producer->raw()));
            for (auto value : fetched) LOGVOLE_REQUIRE_EQ(value, std::uint64_t{0});
        }
        exported.reset();
        LOGVOLE_REQUIRE_TRUE(native.expired());
        // Sharing an immutable table must not keep completed session streams
        // or their private allocation pools alive across successive sessions.
        prepareGpuTableOwners(math);
        const auto tables = gpu::GpuRing::get(math);
        LOGVOLE_REQUIRE_TRUE(tables);
        for (unsigned round = 0; round != 2; ++round)
        {
            std::weak_ptr<gpu::OwnedGpuStream> reader;
            std::weak_ptr<gpu::GpuMemoryPool> memory;
            {
                auto execution = std::make_shared<gpu::GpuExecutionContext>(
                    math.mExecutionOptions, nullptr, math.mFactory->protocolService());
                auto selected = math;
                LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(selected, execution));
                auto& compute = gpu::contextStream(selected);
                reader = compute.allocationOwner();
                memory = compute.allocationOwner()->memory();
                gpu::OwnedGpuBuffer values(compute.allocationOwner(), tables->polyBytes());
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(values.data(), values.size(), compute.raw()));
                LOGVOLE_REQUIRE_TRUE(gpu::launchNttForward(tables->view(compute),
                    static_cast<std::uint64_t*>(values.data()), 1, nullptr, compute.raw()));
            }
            LOGVOLE_REQUIRE_TRUE(reader.expired() && memory.expired());
        }
    }
    {
        RingParams params{};
        params.mPolyModulusDegree = 2048;
        assignValues<int>(params.mCoeffModulusBits, {29, 30});
        RingNttContext original;
        {
            const ProtocolCacheScope sender({}, ProtocolCacheRole::Sender);
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, original,
                std::make_shared<RingContextFactory>(deviceOptions), sender));
        }
        LOGVOLE_REQUIRE_TRUE(original.mGpuLightweight && original.mFactoryOwner);
        LOGVOLE_REQUIRE_TRUE(original.mFactory->gpuAvailable() && original.mGpuAvailable);
        LOGVOLE_REQUIRE_TRUE(original.mGpuSetup->gpuAvailable() && original.mGpuExecution->gpuAvailable());
        {
            auto forcedCpu = original;
            forcedCpu.mExecutionOptions.mUseGpu = false;
            LOGVOLE_REQUIRE_FALSE(gpu::enabled(forcedCpu));
        }
        LOGVOLE_REQUIRE_TRUE(gpu::enabled(original));
        auto retained = original.mFactoryOwner;
        std::weak_ptr<const RingNttContext> record = retained;
        std::weak_ptr<gpu::GpuExecutionContext> domain = original.mGpuExecution;
        std::weak_ptr<gpu::GpuTableCache> tableCache = original.mResourceScope.mTables;
        std::weak_ptr<gpu::GpuSetupContext> setup = original.mGpuSetup;
        auto& main = gpu::contextSampleStream(original);
        std::weak_ptr<gpu::OwnedGpuStream> mainOwner = main.allocationOwner();
        auto tables = gpu::GpuRing::get(original);
        const auto p = seal::PlainModulus::Batching(params.mPolyModulusDegree, 17).value();
        auto plain = gpu::GpuPlainNtt::getRaw(params.mPolyModulusDegree,
            p, original.mResourceScope, original.mGpuSetup);
        LOGVOLE_REQUIRE_TRUE(tables && plain);
        {
            auto unavailable = original.mResourceScope;
            unavailable.mTables = std::make_shared<gpu::GpuTableCache>(
                original.mExecutionOptions, nullptr, false);
            LOGVOLE_REQUIRE_FALSE(gpu::GpuRing::getRaw(params, tables->hostModuli(),
                unavailable, original.mGpuSetup));
            LOGVOLE_REQUIRE_FALSE(gpu::GpuPlainNtt::getRaw(params.mPolyModulusDegree,
                p, unavailable, original.mGpuSetup));
        }
        std::weak_ptr<gpu::GpuRing> ringTable = tables;
        std::weak_ptr<gpu::GpuPlainNtt> plainTable = plain;
        {
            auto isolated = original.mResourceScope;
            isolated.mTables = std::make_shared<gpu::GpuTableCache>(original.mExecutionOptions);
            const auto otherRing = gpu::GpuRing::getRaw(params, tables->hostModuli(),
                isolated, original.mGpuSetup);
            const auto otherPlain = gpu::GpuPlainNtt::getRaw(params.mPolyModulusDegree,
                p, isolated, original.mGpuSetup);
            LOGVOLE_REQUIRE_TRUE(otherRing && otherRing != tables);
            LOGVOLE_REQUIRE_TRUE(otherPlain && otherPlain != plain);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(original) == tables);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(params.mPolyModulusDegree,
                p, original.mResourceScope, original.mGpuSetup) == plain);
        }
        original = {};
        std::weak_ptr<gpu::OwnedGpuStream> workerOwner;
        std::packaged_task<void()> task([&] {
            const ProtocolCacheScope receiver(identityService->qualify(1), ProtocolCacheRole::Receiver);
            auto otherOptions = deviceOptions;
            otherOptions.mAdvanced.mContexts.mNativeSealBundle = true;
            otherOptions.mAdvanced.mContexts.mLightweightRing = false;
            RingNttContext other;
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, other,
                std::make_shared<RingContextFactory>(otherOptions, identityService), receiver));
            LOGVOLE_REQUIRE_FALSE(other.mGpuLightweight);
            for (unsigned round = 0; round != 2; ++round)
            {
                RingNttContext reused;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, reused, retained));
                LOGVOLE_REQUIRE_TRUE(reused.mFactoryOwner == retained);
                LOGVOLE_REQUIRE_TRUE(reused.mGpuExecution == domain.lock());
                LOGVOLE_REQUIRE_TRUE(reused.mResourceScope.mRole == ProtocolCacheRole::Sender);
                LOGVOLE_REQUIRE_FALSE(reused.mResourceScope.mNativeGpuTables);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(reused) == tables);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(params, reused.mRawModuli->mValues,
                    reused.mResourceScope, reused.mGpuSetup) == tables);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(params.mPolyModulusDegree,
                    p, reused.mResourceScope, reused.mGpuSetup) == plain);
                auto& stream = gpu::contextSampleStream(reused);
                workerOwner = stream.allocationOwner();
                LOGVOLE_REQUIRE_TRUE(stream.raw() != mainOwner.lock()->raw());
                LOGVOLE_REQUIRE_TRUE(stream.allocationOwner()->memory() == mainOwner.lock()->memory());
                gpu::OwnedGpuBuffer buffer(stream.allocationOwner(), 31);
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(buffer.data(), buffer.size(), stream.raw()));
            }
        });
        auto completed = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        completed.get();
        LOGVOLE_REQUIRE_FALSE(workerOwner.expired());
        {
            auto host = cpuReferenceContext(*retained);
            LOGVOLE_REQUIRE_FALSE(host.mGpuLightweight);
            LOGVOLE_REQUIRE_TRUE(host.mContext && !host.mRawModuli);
            LOGVOLE_REQUIRE_TRUE(host.mFactoryOwner != retained && !gpu::enabled(host));
            RingNttContext reused;
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, reused, retained));
            LOGVOLE_REQUIRE_TRUE(reused.mGpuLightweight && reused.mFactoryOwner == retained);
            LOGVOLE_REQUIRE_TRUE(reused.mGpuExecution == domain.lock());
            LOGVOLE_REQUIRE_EQ(host.mModuli.size(), retained->mRawModuli->mValues.size());
            for (std::size_t i = 0; i < host.mModuli.size(); ++i)
                LOGVOLE_REQUIRE_EQ(host.mModuli[i].value(), retained->mRawModuli->mValues[i]);
        }
        retained.reset();
        LOGVOLE_REQUIRE_TRUE(record.expired() && domain.expired());
        LOGVOLE_REQUIRE_TRUE(mainOwner.expired() && workerOwner.expired());
        LOGVOLE_REQUIRE_TRUE(tableCache.expired());
        // Exported tables retain their setup stream, without retaining the
        // table cache or compute domain. They remain usable after root release.
        gpu::ScaleRoundConstView scale{};
        LOGVOLE_REQUIRE_TRUE(tables->scaleRoundConstants(p, scale));
        LOGVOLE_REQUIRE_TRUE(scale.mQ && scale.mCrtInvPunctured);
        // An exported table can be used on an independent stream after its
        // context has gone. Destroy both table owners before reading results.
        gpu::GpuStream reader;
        gpu::OwnedGpuBuffer ringValues(reader.allocationOwner(), tables->polyBytes());
        gpu::OwnedGpuBuffer plainValues(reader.allocationOwner(), params.mPolyModulusDegree * sizeof(std::uint64_t));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(ringValues.data(), ringValues.size(), reader.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(plainValues.data(), plainValues.size(), reader.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::launchNttForward(tables->view(reader),
            static_cast<std::uint64_t*>(ringValues.data()), 1, nullptr, reader.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::launchNttForward(plain->view(reader),
            static_cast<std::uint64_t*>(plainValues.data()), 1, nullptr, reader.raw()));
        tables.reset();
        plain.reset();
        LOGVOLE_REQUIRE_TRUE(ringTable.expired() && plainTable.expired() && setup.expired());
        std::vector<std::uint64_t> ringResult(ringValues.size() / sizeof(std::uint64_t), 1);
        std::vector<std::uint64_t> plainResult(plainValues.size() / sizeof(std::uint64_t), 1);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(ringResult.data(), ringValues.data(), ringValues.size(), reader.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(plainResult.data(), plainValues.data(), plainValues.size(), reader.raw()));
        LOGVOLE_REQUIRE_TRUE(reader.sync());
        LOGVOLE_REQUIRE_TRUE(std::all_of(ringResult.begin(), ringResult.end(), [](auto x) { return x == 0; }));
        LOGVOLE_REQUIRE_TRUE(std::all_of(plainResult.begin(), plainResult.end(), [](auto x) { return x == 0; }));
    }
    {
        std::shared_ptr<gpu::GpuRing> ring;
        std::shared_ptr<gpu::GpuPlainNtt> plain;
        std::weak_ptr<gpu::GpuTableCache> cache;
        std::weak_ptr<const ZpCrtContext> record;
        {
            ZpCrtContext context;
            {
                RingParams params{};
                params.mPolyModulusDegree = 2048;
                assignValues<int>(params.mCoeffModulusBits, {25, 26});
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 17, context));
            }
            LOGVOLE_REQUIRE_FALSE(context.mGpuLightweight);
            prepareGpuTableOwners(context.mRing);
            ring = gpu::GpuRing::get(context.mRing);
            plain = gpu::GpuPlainNtt::get(*context.mBatchingContext,
                *context.mBatchEncoder, context.mRing.mResourceScope);
            LOGVOLE_REQUIRE_TRUE(ring && plain);
            cache = context.mRing.mResourceScope.mTables;
            record = context.mFactoryOwner;
        }
        LOGVOLE_REQUIRE_TRUE(cache.expired() && record.expired());
        const auto* factors = ring->pow2Factors(5);
        LOGVOLE_REQUIRE_TRUE(factors && ring->pow2Factors(5) == factors);
        gpu::GpuStream reader;
        std::vector<std::uint64_t> hostFactors(ring->rho());
        // The direct constant-buffer copy is also an asynchronous table read.
        (void)ring->view(reader);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(hostFactors.data(), factors,
            hostFactors.size() * sizeof(std::uint64_t), reader.raw()));
        gpu::OwnedGpuBuffer values(reader.allocationOwner(), plain->n() * sizeof(std::uint64_t));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(values.data(), values.size(), reader.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::launchNttForward(plain->view(reader),
            static_cast<std::uint64_t*>(values.data()), 1, nullptr, reader.raw()));
        // Both eager allocation owners end before the queued read is observed.
        ring.reset();
        plain.reset();
        std::vector<std::uint64_t> result(values.size() / sizeof(std::uint64_t), 1);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(result.data(), values.data(), values.size(), reader.raw()));
        LOGVOLE_REQUIRE_TRUE(reader.sync());
        LOGVOLE_REQUIRE_TRUE(std::all_of(hostFactors.begin(), hostFactors.end(), [](auto x) { return x == 32; }));
        LOGVOLE_REQUIRE_TRUE(std::all_of(result.begin(), result.end(), [](auto x) { return x == 0; }));
    }
    {
        auto execution = std::make_shared<gpu::GpuExecutionContext>();
        std::weak_ptr<gpu::GpuExecutionContext> domain = execution;
        auto& main = execution->mainStream();
        auto& sample = execution->sampleStream();
        LOGVOLE_REQUIRE_TRUE(&main == &execution->mainStream());
        LOGVOLE_REQUIRE_TRUE(main.raw() != sample.raw());
        LOGVOLE_REQUIRE_TRUE(main.allocationOwner()->memory() == sample.allocationOwner()->memory());
        std::weak_ptr<gpu::OwnedGpuStream> mainOwner = main.allocationOwner();
        std::weak_ptr<gpu::OwnedGpuStream> sampleOwner = sample.allocationOwner();
        std::weak_ptr<gpu::GpuMemoryPool> memory = main.allocationOwner()->memory();
        gpu::OwnedGpuBuffer exported(sample.allocationOwner(), 31);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(exported.data(), exported.size(), sample.raw()));
        exported.handoff(main.allocationOwner());
        std::weak_ptr<gpu::OwnedGpuStream> workerOwner;
        std::packaged_task<void()> task([&] {
            auto& stream = execution->mainStream();
            workerOwner = stream.allocationOwner();
            LOGVOLE_REQUIRE_TRUE(stream.raw() != main.raw());
            LOGVOLE_REQUIRE_TRUE(stream.allocationOwner()->memory() == main.allocationOwner()->memory());
        });
        auto completed = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        completed.get();
        execution.reset();
        LOGVOLE_REQUIRE_TRUE(domain.expired() && workerOwner.expired());
        LOGVOLE_REQUIRE_FALSE(mainOwner.expired() || sampleOwner.expired() || memory.expired());
        std::array<std::uint8_t, 31> fetched{};
        fetched.fill(0xff);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), exported.data(), fetched.size(), exported.stream()->raw()));
        exported.stream()->synchronize();
        LOGVOLE_REQUIRE_TRUE(std::all_of(fetched.begin(), fetched.end(), [](auto v) { return v == 0; }));
        exported.reset();
        LOGVOLE_REQUIRE_TRUE(mainOwner.expired() && sampleOwner.expired() && memory.expired());
    }
    {
        auto execution = std::make_shared<gpu::GpuSetupContext>(osuCrypto::LogVoleExecutionOptions{}, nullptr, nullptr);
        std::weak_ptr<gpu::GpuSetupContext> contextOwner = execution;
        auto first = execution->stream();
        LOGVOLE_REQUIRE_TRUE(execution->stream() == first);
        {
            gpu::GpuSetupContext independent;
            LOGVOLE_REQUIRE_TRUE(independent.stream()->raw() != first->raw());
        }
        gpu::OwnedGpuBuffer exported(first, 31);
        std::weak_ptr<gpu::OwnedGpuStream> producer = first;
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(exported.data(), exported.size(), first->raw()));
        first.reset();
        std::weak_ptr<gpu::OwnedGpuStream> workerStream;
        std::packaged_task<void()> task([&] {
            auto worker = execution->stream();
            workerStream = worker;
            LOGVOLE_REQUIRE_TRUE(worker != exported.stream());
            LOGVOLE_REQUIRE_TRUE(worker->memory() == exported.stream()->memory());
            std::vector<std::uint64_t> primes;
            LOGVOLE_REQUIRE_TRUE(gpu::selectSealCoeffModuliDevice(make_small_params(), primes, execution));
            LOGVOLE_REQUIRE_EQ(primes.size(), std::size_t(2));
        });
        auto completed = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        completed.get();
        // No TLS retirement/collection is involved. The context owns the idle
        // worker stream, and exported storage independently retains its producer.
        LOGVOLE_REQUIRE_TRUE(!workerStream.expired());
        execution.reset();
        LOGVOLE_REQUIRE_TRUE(contextOwner.expired() && workerStream.expired());
        LOGVOLE_REQUIRE_TRUE(!producer.expired());
        std::array<std::uint8_t, 31> fetched{};
        fetched.fill(0xff);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), exported.data(), fetched.size(), exported.stream()->raw()));
        exported.stream()->synchronize();
        LOGVOLE_REQUIRE_TRUE(std::all_of(fetched.begin(), fetched.end(), [](auto v) { return v == 0; }));
        exported.reset();
        LOGVOLE_REQUIRE_TRUE(producer.expired());
    }
    // An explicit weak lookup index must not keep factory resources alive.
    // Reuse is preserved while caller contexts retain their immutable record.
    std::weak_ptr<const RingNttContext> ringRecord;
    std::weak_ptr<const ZpCrtContext> crtRecord;
    std::weak_ptr<RingContextFactory> ringFactoryLifetime;
    std::weak_ptr<ZpContextFactory> crtFactoryLifetime;
    {
        RingParams unique{};
        unique.mPolyModulusDegree = 2048;
        assignValues<int>(unique.mCoeffModulusBits, {26, 27, 28});
        RingNttContext first, second;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(unique, first));
        auto ringFactory = first.mFactory;
        LOGVOLE_REQUIRE_FALSE(ringFactory->gpuAvailable());
        LOGVOLE_REQUIRE_FALSE(gpu::enabled(first));
        {
            auto cpuForced = first;
            cpuForced.mGpuAvailable = true;
            LOGVOLE_REQUIRE_FALSE(gpu::enabled(cpuForced));
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        LOGVOLE_REQUIRE_FALSE(first.mGpuSetup->gpuAvailable());
        LOGVOLE_REQUIRE_FALSE(first.mGpuExecution->gpuAvailable());
        LOGVOLE_REQUIRE_FALSE(first.mResourceScope.mTables->gpuAvailable());
#endif
        ringFactoryLifetime = ringFactory;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(unique, second, first.mFactory));
        LOGVOLE_REQUIRE_TRUE(first.mFactoryOwner && first.mFactoryOwner == second.mFactoryOwner);
        ringRecord = first.mFactoryOwner;
        second = {};
        {
            // An explicit record preserves its party selection when the
            // output also supplies its sole owner.
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(unique, first, first.mFactoryOwner));
            LOGVOLE_REQUIRE_TRUE(first.mFactoryOwner == ringRecord.lock());
        }
        ZpCrtContext crt, again;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(unique, 19, crt));
        auto crtFactory = crt.mFactory;
        crtFactoryLifetime = crtFactory;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(unique, 19, again, crt.mFactory));
        LOGVOLE_REQUIRE_TRUE(crt.mFactoryOwner && crt.mFactoryOwner == again.mFactoryOwner);
        crtRecord = crt.mFactoryOwner;
        // Indices remain alive after all records are released and must not
        // retain records, host tables, or execution resources through a cycle.
        first = {};
        crt = {};
        again = {};
        LOGVOLE_REQUIRE_TRUE(ringRecord.expired() && crtRecord.expired());
        LOGVOLE_REQUIRE_FALSE(ringFactoryLifetime.expired() || crtFactoryLifetime.expired());
    }
    LOGVOLE_REQUIRE_TRUE(ringRecord.expired() && crtRecord.expired());
    LOGVOLE_REQUIRE_TRUE(ringFactoryLifetime.expired() && crtFactoryLifetime.expired());
    for (unsigned round = 0; round != 2; ++round)
    {
        RingNttContext context;
        auto params = make_small_params();
        params.mPolyModulusDegree = 2048;
        assignValues<int>(params.mCoeffModulusBits, {31, 31 + static_cast<int>(round)});
        auto validationOptions = deviceOptions;
        validationOptions.mAdvanced.mContexts.mLightweightRing = false;
        {
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, context,
                std::make_shared<RingContextFactory>(validationOptions, nullptr)));
        }
        {
            gpu::GpuRingSetupPrefetch prefetch(context, true);
            if (!round)
            {
                LOGVOLE_REQUIRE_TRUE(prefetch.wait());
                LOGVOLE_REQUIRE_TRUE(prefetch.wait());
            }
            // The second cold initialization is joined by the destructor.
        }
        LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(context));
        // The attempt retains its execution domain after the input context is
        // released. Normal return and exception unwinding both drain its flag
        // and scratch without TLS registration or an explicit abort.
        struct Cancelled {};
        std::weak_ptr<gpu::GpuExecutionContext> validationLifetime;
        std::packaged_task<void()> validation([&] {
            auto ownedContext = context;
            ownedContext.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(ownedContext.mExecutionOptions, nullptr, ownedContext.mFactory->protocolService());
            validationLifetime = ownedContext.mGpuExecution;
            gpu::GoldenValidationAttempt attempt, competing;
            LOGVOLE_REQUIRE_TRUE(attempt.abort());
            LOGVOLE_REQUIRE_TRUE(attempt.begin(ownedContext));
            LOGVOLE_REQUIRE_FALSE(competing.begin(ownedContext));
            ownedContext = {};
            LOGVOLE_REQUIRE_FALSE(validationLifetime.expired());
            if (round) throw Cancelled{};
        });
        auto completed = validation.get_future();
        std::thread validator(std::move(validation));
        validator.join();
        bool cancelled = false;
        try { completed.get(); }
        catch (const Cancelled&) { cancelled = true; }
        LOGVOLE_REQUIRE_EQ(cancelled, round != 0);
        LOGVOLE_REQUIRE_TRUE(validationLifetime.expired());
    }
    // A worker can export an unfinished wrapped polynomial, then retire its
    // stream-owned lift cache. The exported allocation keeps the native stream
    // alive, but must not keep that scratch cache (or its pool) alive forever.
    ZpCrtContext plainContext;
    const std::array<std::uint64_t, 5> labels{1, 7, 19, 0, 31};
    RnsPoly expectedWrap;
    {
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(make_small_params(), 20, plainContext));
        LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(plainContext, labels, true, 0, 1, expectedWrap));
    }
    for (auto role : {ProtocolCacheRole::Sender, ProtocolCacheRole::Receiver})
    {
        std::weak_ptr<gpu::OwnedGpuStream> producer;
        std::weak_ptr<gpu::GpuMemoryPool> pool;
        std::packaged_task<gpu::DeviceBatchPtr()> task([&] {
            const ProtocolCacheScope scope(identityService->allocate(), role);
            auto wrapOptions = deviceOptions;
            wrapOptions.mAdvanced.mContexts.mLightweightRing = false;
            wrapOptions.mAdvanced.mContexts.mLightweightCrt = false;
            ZpCrtContext ownedContext;
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(plainContext.mRing.mParams,
                plainContext.mPlaintextModulusBits, ownedContext, std::make_shared<ZpContextFactory>(
                    std::make_shared<RingContextFactory>(wrapOptions, identityService)), scope));
            ownedContext.mFactoryOwner.reset();
            ownedContext.mRing.mFactoryOwner.reset();
            ownedContext.mRing.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(wrapOptions, nullptr, ownedContext.mRing.mFactory->protocolService());
            ownedContext.mRing.mResourceScope.mTables = std::make_shared<gpu::GpuTableCache>();
            auto& stream = gpu::contextStream(ownedContext.mRing);
            producer = stream.allocationOwner();
            pool = stream.allocationOwner()->memory();
            // Cold allocation and a cache hit both feed the ordinary wrap path.
            auto first = gpu::wrapLabelsDevice(ownedContext, labels, true, 0, 1, false, scope);
            LOGVOLE_REQUIRE_TRUE(first);
            auto second = gpu::wrapLabelsDevice(ownedContext, labels, true, 0, 1, false, scope);
            LOGVOLE_REQUIRE_TRUE(second);
            return second;
        });
        auto result = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        auto exported = result.get();
        LOGVOLE_REQUIRE_TRUE(!producer.expired() && !pool.expired());
        std::vector<RnsPoly> fetched;
        LOGVOLE_REQUIRE_TRUE(gpu::download(*exported, fetched, readbackExecution.readbackStream()));
        LOGVOLE_REQUIRE_EQ(fetched.size(), std::size_t(1));
        expect_poly_equal(expectedWrap, fetched[0]);
        exported.reset();
        LOGVOLE_REQUIRE_TRUE(producer.expired() && pool.expired());
    }
    // Repeated worker exit covers explicit stream/scratch destruction. Trim
    // while owners are live must preserve them, then release their idle blocks.
    for (unsigned round = 0; round != 3; ++round)
    {
        std::packaged_task<void()> task([round] {
            gpu::GpuExecutionContext execution;
            auto& stream = execution.mainStream();
            constexpr std::size_t count = 4099, bytes = count * sizeof(std::uint64_t);
            auto memory = stream.allocationOwner()->memory();
            gpu::OwnedGpuBuffer device(stream.allocationOwner(), bytes);
            gpu::PinnedHostBuffer host(bytes);
            WireMemoryPool wireMemory;
            auto* wire = wireMemory.allocate(bytes, 64);
            LOGVOLE_REQUIRE_TRUE(device && host.data() && wire);
            auto* source = static_cast<std::uint64_t*>(host.data());
            auto* fetched = static_cast<std::uint64_t*>(wire);
            for (std::size_t i = 0; i < count; ++i) source[i] = 0xfedcba9876543210ull ^ (i + round);
            bool pinned = false;
            LOGVOLE_REQUIRE_TRUE(wireMemory.pin(wire, bytes, pinned));
            gpu::StreamDrain drain{stream};
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(device.data(), source, bytes, stream.raw()));
            LOGVOLE_REQUIRE_TRUE(stream.sync());
            memory->trim();
            LOGVOLE_REQUIRE_TRUE(wireMemory.contains(wire, bytes));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched, device.data(), bytes, stream.raw()));
            LOGVOLE_REQUIRE_TRUE(stream.sync());
            LOGVOLE_REQUIRE_TRUE(std::equal(source, source + count, fetched));
            device.reset();
            host.reset();
            memory->trim();
        });
        auto result = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        result.get();
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_UniformSamplerScratchOwnership(const oc::CLP& cmd)
{
    const auto identityService = ProtocolCacheService::create();
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) == 0) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    LOGVOLE_REQUIRE_TRUE(gpu::available());
    {
        // Small AES stream and full polynomial oracle, including odd stream
        // lengths, mapped output rows and deliberately frequent rejection.
        using oc::u64;
        using oc::PRNG;
        constexpr gpu::u32 count = 3, streamWords = 1031;
        RingNttContext context;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), context));
        prepareGpuTableOwners(context);
        auto ring = gpu::GpuRing::get(context);
        LOGVOLE_REQUIRE_TRUE(ring);
        gpu::GpuExecutionContext execution;
        auto& stream = execution.mainStream();
        const auto words = ring->polyWords();
        std::array<seal::prng_seed_type, count> seeds{};
        std::vector<u64> raw(count * streamWords + 2), sampled((count + 2) * words);
        std::vector<u64> expected(count * streamWords);
        std::vector<u64> limits(ringModulusCount(context));
        const std::array<gpu::u32, count> destinations{2, 0, 1};
        gpu::OwnedGpuBuffer seedStorage(stream.allocationOwner(), sizeof(seeds));
        gpu::OwnedGpuBuffer keys(stream.allocationOwner(), count * 176u);
        gpu::OwnedGpuBuffer rawStorage(stream.allocationOwner(), raw.size() * sizeof(u64));
        gpu::OwnedGpuBuffer output(stream.allocationOwner(), sampled.size() * sizeof(u64));
        gpu::OwnedGpuBuffer thresholds(stream.allocationOwner(), limits.size() * sizeof(u64));
        gpu::OwnedGpuBuffer rows(stream.allocationOwner(), sizeof(destinations));
        gpu::OwnedGpuBuffer epochs(stream.allocationOwner(), count * sizeof(gpu::u32));
        gpu::StreamDrain drain{stream};
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(epochs.data(), epochs.size(), stream.raw()));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(rows.data(), destinations.data(), sizeof(destinations), stream.raw()));
        for (unsigned query = 0; query < 2; ++query)
        {
            for (unsigned row = 0; row < count; ++row)
            {
                for (unsigned i = 0; i < 8; ++i) seeds[row][i] = 101u * row + 17u * i + query;
                PRNG reference(osuCrypto::LogVole::detail::aesPrngKey(seeds[row]));
                reference.get(expected.data() + row * streamWords, streamWords);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(seedStorage.data(), seeds.data(), sizeof(seeds), stream.raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(rawStorage.data(), rawStorage.size(), stream.raw()));
            LOGVOLE_REQUIRE_FALSE(gpu::launchAesPrngStream(
                static_cast<const gpu::u64*>(seedStorage.data()), static_cast<gpu::u64*>(rawStorage.data()) + 1,
                streamWords, count, static_cast<unsigned char*>(keys.data()), keys.size() - 1, stream.raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::launchAesPrngStream(
                static_cast<const gpu::u64*>(seedStorage.data()), static_cast<gpu::u64*>(rawStorage.data()) + 1,
                streamWords, count, static_cast<unsigned char*>(keys.data()), keys.size(), stream.raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(raw.data(), rawStorage.data(), rawStorage.size(), stream.raw()));
            LOGVOLE_REQUIRE_TRUE(stream.sync());
            LOGVOLE_REQUIRE_EQ(raw.front(), 0u);
            LOGVOLE_REQUIRE_EQ(raw.back(), 0u);
            LOGVOLE_REQUIRE_TRUE(std::equal(expected.begin(), expected.end(), raw.begin() + 1));

            for (unsigned forced = 0; forced < 2; ++forced)
            {
                for (std::size_t limb = 0; limb < limits.size(); ++limb)
                {
                    const auto q = ringModulusValue(context, limb);
                    limits[limb] = ~u64{0} - (~u64{0} % q) - 1u;
                    if (forced) limits[limb] >>= 1u;
                }
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(thresholds.data(), limits.data(), thresholds.size(), stream.raw()));
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(output.data(), output.size(), stream.raw()));
                LOGVOLE_REQUIRE_TRUE(gpu::launchSampleUniformPolyAes(ring->view(stream),
                    static_cast<const gpu::u64*>(seedStorage.data()), static_cast<const gpu::u64*>(thresholds.data()),
                    static_cast<gpu::u64*>(output.data()) + words, static_cast<const gpu::u32*>(rows.data()), count,
                    static_cast<unsigned char*>(keys.data()), keys.size(), static_cast<gpu::u32*>(epochs.data()),
                    1u + query * 2u + forced, stream.raw()));
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(sampled.data(), output.data(), output.size(), stream.raw()));
                LOGVOLE_REQUIRE_TRUE(stream.sync());
                LOGVOLE_REQUIRE_TRUE(std::all_of(sampled.begin(), sampled.begin() + words, [](auto v) { return v == 0; }));
                LOGVOLE_REQUIRE_TRUE(std::all_of(sampled.end() - words, sampled.end(), [](auto v) { return v == 0; }));
                std::vector<u64> initial(words);
                for (unsigned row = 0; row < count; ++row)
                {
                    PRNG reference(osuCrypto::LogVole::detail::aesPrngKey(seeds[row]));
                    reference.get(initial.data(), initial.size());
                    for (std::size_t i = 0; i < words; ++i)
                    {
                        const auto limb = i / context.mParams.mPolyModulusDegree;
                        auto value = initial[i];
                        while (value >= limits[limb]) value = reference.get<u64>();
                        const auto index = (1u + destinations[row]) * words + i;
                        LOGVOLE_REQUIRE_EQ(sampled[index], value % ringModulusValue(context, limb));
                    }
                }
            }
        }
        LOGVOLE_REQUIRE_TRUE(drain.sync());
    }
    {
        osuCrypto::LogVoleExecutionOptions advanced;
        advanced.mUseGpu = true;
        RingNttContext base;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), base,
            std::make_shared<RingContextFactory>(advanced, nullptr)));
        std::vector<std::array<std::uint64_t, 8>> seeds(3);
        for (std::size_t row = 0; row < seeds.size(); ++row)
            for (std::size_t word = 0; word < seeds[row].size(); ++word)
                seeds[row][word] = 0x53545245414dull + row * 31u + word;
        std::vector<RnsPoly> expected;
        {
            auto cpu = cpuReferenceContext(base);
            for (const auto& seed : seeds) expected.push_back(sampleUniformPolyFromSeed(cpu, seed));
        }
        std::weak_ptr<gpu::GpuExecutionContext> firstLifetime, secondLifetime;
        gpu::RetainedPublicUniformPtr saved;
        {
            auto first = base, second = base;
            first.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(advanced, nullptr, first.mFactory->protocolService());
            second.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(advanced, nullptr, second.mFactory->protocolService());
            firstLifetime = first.mGpuExecution;
            secondLifetime = second.mGpuExecution;
            const auto firstStream = gpu::contextSampleStream(first).raw();
            const auto secondStream = gpu::contextSampleStream(second).raw();
            LOGVOLE_REQUIRE_TRUE(firstStream != secondStream);
            LOGVOLE_REQUIRE_TRUE(gpu::contextSampleStream(first).raw() == firstStream);
            std::packaged_task<void()> task([&] {
                std::vector<RnsPoly> actual;
                LOGVOLE_REQUIRE_TRUE(gpu::sampleUniformBatchFromSeedsDevice(first, seeds, false, actual, &saved));
                expect_batch_equal(actual, expected);
            });
            auto result = task.get_future();
            std::thread worker(std::move(task));
            worker.join();
            result.get();
            std::vector<RnsPoly> actual;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleUniformBatchFromSeedsDevice(second, seeds, false, actual));
            expect_batch_equal(actual, expected);
        }
        // Exporting a completed batch retains its native allocation and stream,
        // never the high-level execution domain or that domain's scratch.
        LOGVOLE_REQUIRE_TRUE(firstLifetime.expired() && secondLifetime.expired());
        LOGVOLE_REQUIRE_TRUE(saved);
        std::vector<RnsPoly> fetched;
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*saved, fetched, readbackExecution.readbackStream()));
        expect_batch_equal(fetched, expected);
    }
    for (bool production : {false, true})
    {
        auto params = make_small_params();
        if (production)
        {
            params.mPolyModulusDegree = 8192;
            assignValues<int>(params.mCoeffModulusBits, {55, 55, 55, 55});
        }
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        prepareGpuTableOwners(ctx);
        auto ring = gpu::GpuRing::get(ctx);
        LOGVOLE_REQUIRE_TRUE(ring != nullptr);
        const auto words = ring->polyWords();
        const auto host = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(host && host->key_context_data());
        auto referenceFactory = osuCrypto::LogVole::detail::makeAesPrngFactory();
        for (gpu::u32 count : {4u, 16u})
        {
            gpu::GpuExecutionContext execution;
            auto& stream = execution.mainStream();
            gpu::OwnedGpuBuffer seedsDevice(stream.allocationOwner(), count * sizeof(seal::prng_seed_type));
            gpu::OwnedGpuBuffer output(stream.allocationOwner(), count * words * sizeof(gpu::u64));
            gpu::OwnedGpuBuffer epochs(stream.allocationOwner(), count * sizeof(gpu::u32));
            gpu::OwnedGpuBuffer keys(stream.allocationOwner(), count * 176u);
            std::vector<seal::prng_seed_type> seeds(count);
            std::vector<std::uint64_t> expected(count * words), actual(expected.size());
            gpu::StreamDrain drain{stream};
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(epochs.data(), epochs.size(), stream.raw()));
            for (unsigned query = 0; query != 2; ++query)
            {
                for (gpu::u32 row = 0; row != count; ++row)
                {
                    seeds[row][0] = 0x53435241544348ull + row;
                    seeds[row][1] = query + 1;
                    seeds[row][2] = params.mPolyModulusDegree;
                    seal::util::sample_poly_uniform(referenceFactory->create(seeds[row]),
                        host->key_context_data()->parms(), expected.data() + row * words);
                    const auto cpu = sampleUniformPolyFromSeed(ctx, seeds[row]);
                    LOGVOLE_REQUIRE_TRUE(std::equal(cpu.mCoeffs.begin(), cpu.mCoeffs.end(),
                        expected.begin() + row * words));
                }
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(seedsDevice.data(), seeds.data(), seedsDevice.size(), stream.raw()));
                auto launch = [&](std::size_t keyCapacity) {
                    return gpu::launchSampleUniformPolyAes(ring->view(stream),
                        static_cast<const gpu::u64*>(seedsDevice.data()), ring->sampleMaxMultiple(),
                        static_cast<gpu::u64*>(output.data()), nullptr, count,
                        static_cast<unsigned char*>(keys.data()), keyCapacity,
                        static_cast<gpu::u32*>(epochs.data()), query + 1, stream.raw());
                };
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(output.data(), output.size(), stream.raw()));
                LOGVOLE_REQUIRE_FALSE(launch(keys.size() - 1));
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(actual.data(), output.data(), output.size(), stream.raw()));
                LOGVOLE_REQUIRE_TRUE(stream.sync());
                LOGVOLE_REQUIRE_TRUE(std::all_of(actual.begin(), actual.end(), [](auto word) { return word == 0; }));
                LOGVOLE_REQUIRE_TRUE(launch(keys.size()));
                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(actual.data(), output.data(), output.size(), stream.raw()));
                LOGVOLE_REQUIRE_TRUE(stream.sync());
                LOGVOLE_REQUIRE_TRUE(actual == expected);
            }
            LOGVOLE_REQUIRE_TRUE(drain.sync());
        }
    }
#else
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_RingOps_GpuStreamStagingLifetime(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    advanced.mAdvanced.mStreams.mLazyIndexScratch = osuCrypto::LogVoleChoice::Enabled;
    advanced.mAdvanced.mStreams.mIndexScratchKiB = 256;
    advanced.mAdvanced.mStreams.mPipelinedUpload = true;
    advanced.mAdvanced.mStreams.mPolyStageMiB = 1;
    advanced.mAdvanced.mStreams.mDownloadSlotMiB = 1;
    auto factory = std::make_shared<RingContextFactory>(advanced, nullptr);
    auto params = make_small_params();
    params.mPolyModulusDegree = 1024;
    RingNttContext configured, reused, defaults;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, configured, factory));
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, reused, factory));
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, defaults));
    LOGVOLE_REQUIRE_TRUE(configured.mFactoryOwner == reused.mFactoryOwner);
    LOGVOLE_REQUIRE_TRUE(configured.mResourceScope.mTables != defaults.mResourceScope.mTables);
    LOGVOLE_REQUIRE_TRUE(configured.mExecutionOptions == advanced);
    LOGVOLE_REQUIRE_TRUE(configured.mGpuSetup->executionOptions() == advanced);
    LOGVOLE_REQUIRE_TRUE(configured.mResourceScope.mTables->executionOptions() == advanced);
    auto execution = std::make_shared<gpu::GpuExecutionContext>(advanced, nullptr, factory->protocolService());
    advanced.mAdvanced.mStreams = {}; // The factory and execution own independent copies.
    LOGVOLE_REQUIRE_TRUE(gpu::bindContextExecution(configured, execution));
    for (auto* stream : {&execution->mainStream(), &execution->sampleStream(), &execution->readbackStream()})
        LOGVOLE_REQUIRE_TRUE(stream->options() == configured.mExecutionOptions.mAdvanced.mStreams);
    const auto savedExecution = configured.mGpuExecution;
    LOGVOLE_REQUIRE_FALSE(gpu::bindContextExecution(configured,
        std::make_shared<gpu::GpuExecutionContext>()));
    LOGVOLE_REQUIRE_TRUE(configured.mGpuExecution == savedExecution);
    LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(configured));
    prepareGpuTableOwners(defaults);
    LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(defaults));
    advanced.mAdvanced.mStreams.mIndexScratchKiB = 257;
    bool rejected = false;
    try { gpu::GpuStream invalid(advanced.mAdvanced.mStreams); }
    catch (const std::invalid_argument&) { rejected = true; }
    LOGVOLE_REQUIRE_TRUE(rejected);

    osuCrypto::LogVoleGpuStreamOptions streamOptions;
    streamOptions.mIndexScratchKiB = 256;
    for (const char* lazy : {"0", "1"})
    {
        streamOptions.mLazyIndexScratch = lazy[0] == '1' ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled;
        gpu::GpuStream stream(streamOptions);
        std::vector<std::uint32_t> indices(65533), fetched(indices.size());
        for (std::size_t i = 0; i != indices.size(); ++i) indices[i] = static_cast<std::uint32_t>(i ^ 0xa5a5u);
        auto* first = stream.uploadIdx(indices);
        LOGVOLE_REQUIRE_TRUE(first);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), first, indices.size() * 4, stream.raw()));
        const std::array<std::uint32_t, 9> tail{9, 8, 7, 6, 5, 4, 3, 2, 1};
        std::array<std::uint32_t, 9> fetchedTail{};
        auto* second = stream.uploadIdx(tail); // wraps while the first read is queued
        LOGVOLE_REQUIRE_TRUE(second == first);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetchedTail.data(), second, sizeof(tail), stream.raw()));
        LOGVOLE_REQUIRE_TRUE(stream.sync());
        LOGVOLE_REQUIRE_TRUE(fetched == indices && fetchedTail == tail);
    }

    streamOptions.mPipelinedUpload = true;
    streamOptions.mDownloadSlotMiB = 1;
    constexpr std::size_t bytes = (std::size_t(16) << 20) + 3;
    std::vector<std::uint8_t> source(bytes, 37), fetched(bytes);
    gpu::OwnedGpuBuffer pending;
    {
        gpu::GpuStream stream(streamOptions);
        LOGVOLE_REQUIRE_TRUE(stream.pipelinedUploadEnabled());
        pending = gpu::OwnedGpuBuffer(stream.allocationOwner(), bytes);
        for (unsigned round = 0; round != 2; ++round)
        {
            std::fill(source.begin(), source.end(), static_cast<std::uint8_t>(37 + round));
            LOGVOLE_REQUIRE_TRUE(gpu::uploadFromHost(pending.data(), source.data(), bytes, stream));
            LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(fetched.data(), pending.data(), bytes, stream));
            LOGVOLE_REQUIRE_TRUE(fetched == source);
        }

        auto* stage = stream.staging(4099);
        LOGVOLE_REQUIRE_TRUE(stage);
        std::fill_n(stage, 4099, std::uint8_t{71});
        LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(pending.data(), stage, 4099, stream.raw()));
        LOGVOLE_REQUIRE_TRUE(stream.staging((std::size_t(8) << 20) + 1)); // drains the borrowed old source
        LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(fetched.data(), pending.data(), 4099, stream));
        LOGVOLE_REQUIRE_TRUE(std::all_of(fetched.begin(), fetched.begin() + 4099, [](auto x) { return x == 71; }));
        const auto preserved = stream.existingStaging(1);
        LOGVOLE_REQUIRE_TRUE(!stream.staging(std::numeric_limits<std::size_t>::max()));
        LOGVOLE_REQUIRE_TRUE(stream.existingStaging(1) == preserved);

        // Three polynomial DMA chunks exercise both transfer slots, including
        // private pinned storage and the stream's borrowed shared staging.

        gpu::GpuPolyBuffer polynomials;
        LOGVOLE_REQUIRE_TRUE(polynomials.resizeWords(4096, 65, stream));
        LOGVOLE_REQUIRE_TRUE(polynomials.zero(stream));
        CpuBenchmarkContext telemetry;
        telemetry.mWorkerLimit = 2;
#if defined(__linux__)
        cpu_set_t mask;
        CPU_ZERO(&mask);
        LOGVOLE_REQUIRE_EQ(sched_getaffinity(0, sizeof(mask), &mask), 0);
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
            if (CPU_ISSET(cpu, &mask)) telemetry.mCpus.push_back(cpu);
#else
        telemetry.mCpus.resize(2);
#endif
        CpuBenchmarkState cpuBenchmark{&telemetry};
        for (const char* reuse : {"0", "1"})
        for (bool reuseWorkers : {false, true})
        {
            auto downloadOptions = streamOptions;
            downloadOptions.mReuseDownloadStaging = reuse[0] == '1';
            downloadOptions.mDownloadReuseWorkers = reuseWorkers;
            telemetry.reset();
            gpu::GpuStream downloadStream(downloadOptions);
            LOGVOLE_REQUIRE_TRUE(downloadStream.staging(std::size_t(2) << 20));
            std::vector<RnsPoly> host;
            LOGVOLE_REQUIRE_TRUE(polynomials.downloadPipelined(host, downloadStream, 2, 0, 0, cpuBenchmark));
            LOGVOLE_REQUIRE_EQ(telemetry.mWorkerSlots.load(), 0u);
            LOGVOLE_REQUIRE_EQ(telemetry.mActiveTaskThreads.load(), 0u);
            LOGVOLE_REQUIRE_TRUE(telemetry.mPeakTaskThreads.load() > 0u);
            LOGVOLE_REQUIRE_TRUE(telemetry.mPeakTaskThreads.load() <= 2u);
            LOGVOLE_REQUIRE_EQ(cpuBenchmark.mTaskDepth, 0u);
            LOGVOLE_REQUIRE_EQ(host.size(), 65u);
            for (const auto& poly : host)
                LOGVOLE_REQUIRE_TRUE(std::all_of(poly.mCoeffs.begin(), poly.mCoeffs.end(), [](auto x) { return x == 0; }));
        }
        // Destroy the stream wrapper with a pinned H2D source still in use.
        LOGVOLE_REQUIRE_TRUE(gpu::uploadFromHost(pending.data(), source.data(), bytes, stream));
    }
    LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyD2H(fetched.data(), pending.data(), bytes, pending.stream()->raw()));
    pending.stream()->synchronize();
    LOGVOLE_REQUIRE_TRUE(fetched == source);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_PartyCachesDoNotAlias(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool testGpuAvailable = gpu::available();
#endif

    const auto identityService = ProtocolCacheService::create();
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
    RingNttContext senderCtx{}, receiverCtx{};
    constexpr std::uint32_t count = 4;
    const auto runId = identityService->allocate();

    std::shared_ptr<const std::vector<RnsPoly>> senderA, senderB;
    std::shared_ptr<const std::vector<RnsPoly>> receiverA, receiverB;
#if defined(ENABLE_LOGVOLE_CUDA)
    std::shared_ptr<gpu::GpuRing> senderRing, receiverRing;
#endif
    {
        const ProtocolCacheScope scope(runId, ProtocolCacheRole::Sender);
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), senderCtx,
            std::make_shared<RingContextFactory>(advanced, identityService), scope));
        senderA = sharedLhePublicANtt(senderCtx, count, scope);
        senderB = sharedLencPublicBNtt(senderCtx, count / 2, scope);
#if defined(ENABLE_LOGVOLE_CUDA)
        if ((advanced.mUseGpu && testGpuAvailable)) senderRing = gpu::GpuRing::get(senderCtx);
#endif
    }
    {
        const ProtocolCacheScope scope(runId, ProtocolCacheRole::Receiver);
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), receiverCtx,
            std::make_shared<RingContextFactory>(advanced, identityService), scope));
        receiverA = sharedLhePublicANtt(receiverCtx, count, scope);
        receiverB = sharedLencPublicBNtt(receiverCtx, count / 2, scope);
#if defined(ENABLE_LOGVOLE_CUDA)
        if ((advanced.mUseGpu && testGpuAvailable)) receiverRing = gpu::GpuRing::get(receiverCtx);
#endif
    }

    LOGVOLE_REQUIRE_TRUE(senderA && senderB && receiverA && receiverB);
    LOGVOLE_EXPECT_TRUE(getRingHostContext(senderCtx) != getRingHostContext(receiverCtx));
    LOGVOLE_EXPECT_TRUE(senderA != receiverA);
    LOGVOLE_EXPECT_TRUE(senderB != receiverB);
    expect_batch_equal(*senderA, *receiverA);
    expect_batch_equal(*senderB, *receiverB);
#if defined(ENABLE_LOGVOLE_CUDA)
    if ((advanced.mUseGpu && testGpuAvailable))
    {
        LOGVOLE_REQUIRE_TRUE(senderRing && receiverRing);
        LOGVOLE_EXPECT_TRUE(senderRing != receiverRing);
    }
#endif
}

void LogVole_RingOps_LightweightProductionContexts(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool testGpuAvailable = gpu::available();
#endif

    tests_libOTe::logvole_test::SetupResources crtResources;
    std::array<ZpEncodeBuffer, 3> crtEncodeBuffers;
    std::array<ZpDecodeBuffer, 3> crtDecodeBuffers;
    const auto identityService = ProtocolCacheService::create();
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

    const bool requestGpu = cmd.getOr("gpu", 0) != 0;
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = requestGpu;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (requestGpu) LOGVOLE_REQUIRE_TRUE((advanced.mUseGpu && testGpuAvailable));
#else
    (void)requestGpu;
#endif
    struct Preset
    {
        std::uint32_t degree, bits;
        std::uint64_t plaintext;
        std::vector<std::uint64_t> primes, roots, lift;
    };
    // Independently extracted with the installed SEAL 4.1.1 CoeffModulus,
    // PlainModulus, NTTTables and RNSBase; preserve their exact limb order.
    const std::array<Preset, 2> presets{{
        {8192u, 55u, 18014398508400641ULL,
            {36028797017276417ULL, 36028797017456641ULL, 36028797017571329ULL, 36028797018652673ULL},
            {2122358902623ULL, 4991203289951ULL, 3055459936772ULL, 15372713853695ULL},
            {31167066492716324ULL, 21694619169948978ULL, 65560066590007ULL, 11186266514113866ULL}},
        {16384u, 52u, 2251799813554177ULL,
            {4503599623864321ULL, 4503599624716289ULL, 4503599624847361ULL, 4503599625404417ULL,
             4503599625535489ULL, 4503599625830401ULL, 4503599626321921ULL, 4503599626682369ULL},
            {62875005116ULL, 628540673523ULL, 20953053066ULL, 77888184398ULL,
             373971078837ULL, 439212745275ULL, 92204214445ULL, 186470750825ULL},
            {4387753181945957ULL, 2958736519422233ULL, 4311407244373363ULL, 2043635392656052ULL,
             3613420940470256ULL, 2606009313598ULL, 2340510748877534ULL, 2511146381739566ULL}}
    }};
    for (const auto& preset : presets)
    {
        RingParams params{};
        params.mPolyModulusDegree = preset.degree;
        params.mCoeffModulusBits.resize(preset.primes.size());
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), preset.bits);
        const auto run = identityService->allocate();
        std::array<RingNttContext, 2> lightweight;
        std::array<ZpCrtContext, 2> crt;
        std::array<bool, 2> roleGpu{};
#if defined(ENABLE_LOGVOLE_CUDA)
        std::array<std::shared_ptr<gpu::GpuRing>, 2> deviceRings;
#endif
        for (std::size_t party = 0; party < 2; ++party)
        {
            const ProtocolCacheScope roleScope(run,
                party ? ProtocolCacheRole::Receiver : ProtocolCacheRole::Sender);
#if defined(ENABLE_LOGVOLE_CUDA)
            roleGpu[party] = (advanced.mUseGpu && testGpuAvailable);
#endif
            auto& context = lightweight[party];
            LOGVOLE_REQUIRE_TRUE(makeGpuRingNttContext(params, context, roleScope));
            LOGVOLE_REQUIRE_TRUE(context.mGpuLightweight && context.mHostContextCache && !context.mContext);
            LOGVOLE_REQUIRE_TRUE(context.mModuli.empty() && context.mRawModuli);
            LOGVOLE_REQUIRE_TRUE(validateRingContextMetadata(context));
            RingNttContext again;
            again.mFactory = context.mFactory;
            LOGVOLE_REQUIRE_TRUE(makeGpuRingNttContext(params, again, roleScope));
            LOGVOLE_EXPECT_TRUE(again.mHostContextCache == context.mHostContextCache);
            LOGVOLE_EXPECT_TRUE(again.mRawModuli == context.mRawModuli);
            LOGVOLE_REQUIRE_EQ(ringModulusCount(context), preset.primes.size());
            for (std::size_t limb = 0; limb < preset.primes.size(); ++limb)
            {
                LOGVOLE_EXPECT_EQ(ringModulusValue(context, limb), preset.primes[limb]);
                LOGVOLE_EXPECT_EQ(ringModulusBitCount(context, limb), static_cast<int>(preset.bits));
            }

            RingNttContext selected;
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, selected,
                std::make_shared<RingContextFactory>(advanced, identityService), roleScope));
            LOGVOLE_EXPECT_EQ(selected.mGpuLightweight, roleGpu[party]);
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, crt[party],
                std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(advanced, identityService)), roleScope));
            LOGVOLE_EXPECT_EQ(crt[party].mGpuLightweight, roleGpu[party]);
            LOGVOLE_EXPECT_EQ(crt[party].mPlaintextModulus, preset.plaintext);
            LOGVOLE_EXPECT_EQ(crt[party].mPlaintextModulusBits, preset.bits - 1u);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(crt[party].mPlaintextLiftModQj, preset.lift));
            if (roleGpu[party])
            {
                LOGVOLE_REQUIRE_TRUE(!crt[party].mBatchingContext && !crt[party].mBatchEncoder);
                LOGVOLE_REQUIRE_TRUE(crt[party].mHostContextCache != nullptr);
#if defined(ENABLE_LOGVOLE_CUDA)
                deviceRings[party] = gpu::GpuRing::get(context);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party] != nullptr);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party]->hostModuli() == preset.primes);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party]->metadata().mRoots != nullptr);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party]->metadata().mInvRoots != nullptr);
#endif
                for (auto option : {&osuCrypto::LogVoleGpuContextOptions::mLightweightRing,
                        &osuCrypto::LogVoleGpuContextOptions::mLightweightCrt})
                {
                    auto options = advanced;
                    options.mAdvanced.mContexts.*option = false;
                    auto factory = std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(options, identityService));
                    ZpCrtContext eager;
                    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, eager, factory, roleScope));
                    LOGVOLE_REQUIRE_TRUE(!eager.mGpuLightweight && eager.mBatchingContext && eager.mBatchEncoder);
                    LOGVOLE_EXPECT_EQ(eager.mPlaintextModulus, preset.plaintext);
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(eager.mPlaintextLiftModQj, preset.lift));
                    if (option == &osuCrypto::LogVoleGpuContextOptions::mLightweightRing)
                    {
                        RingNttContext eagerRing;
                        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, eagerRing, factory->ringFactory(), roleScope));
                        LOGVOLE_REQUIRE_TRUE(!eagerRing.mGpuLightweight && eagerRing.mContext);
                    }
                }
                ZpCrtContext restored;
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, restored, crt[party].mFactory, roleScope));
                LOGVOLE_REQUIRE_TRUE(restored.mGpuLightweight);
                LOGVOLE_EXPECT_TRUE(restored.mHostContextCache == crt[party].mHostContextCache);
            }
        }
        LOGVOLE_EXPECT_TRUE(lightweight[0].mHostContextCache != lightweight[1].mHostContextCache);
        LOGVOLE_EXPECT_TRUE(lightweight[0].mRawModuli != lightweight[1].mRawModuli);
        if (roleGpu[0] && roleGpu[1])
        {
            LOGVOLE_EXPECT_TRUE(crt[0].mHostContextCache != crt[1].mHostContextCache);
#if defined(ENABLE_LOGVOLE_CUDA)
            LOGVOLE_EXPECT_TRUE(deviceRings[0] != deviceRings[1]);
            LOGVOLE_EXPECT_TRUE(deviceRings[0]->metadata().mRoots != deviceRings[1]->metadata().mRoots);
#endif
        }

        // A declined metadata factory must not consume or replace the caller's owner.
        auto unsupported = params;
        unsupported.mPolyModulusDegree = 262144u;
        auto unchanged = lightweight[0];
        LOGVOLE_REQUIRE_FALSE(makeGpuRingNttContext(unsupported, unchanged));
        LOGVOLE_EXPECT_TRUE(unchanged.mHostContextCache == lightweight[0].mHostContextCache);
        LOGVOLE_EXPECT_TRUE(unchanged.mParams == params && unchanged.mGpuLightweight && !unchanged.mContext);
        for (std::size_t limb = 0; limb < preset.primes.size(); ++limb)
            LOGVOLE_EXPECT_EQ(ringModulusValue(unchanged, limb), preset.primes[limb]);

        // Explicit CPU oracles stay on the host even in the GPU test invocation.
        RingNttContext eager;
        ZpCrtContext eagerCrt;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, eager));
        LOGVOLE_REQUIRE_TRUE(!eager.mGpuLightweight && eager.mContext);
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, eagerCrt));
        LOGVOLE_EXPECT_EQ(eagerCrt.mPlaintextModulus, preset.plaintext);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(eagerCrt.mPlaintextLiftModQj, preset.lift));
        // Concurrent copies resolve to a single immutable host fallback owner.
        std::array<std::future<std::shared_ptr<seal::SEALContext>>, 4> readers;
        for (auto& reader : readers)
            reader = std::async(std::launch::async, [context = lightweight[0]] {
                return getRingHostContext(context);
            });
        const auto senderHost = readers[0].get();
        for (std::size_t reader = 1; reader < readers.size(); ++reader)
            LOGVOLE_REQUIRE_TRUE(readers[reader].get() == senderHost);
        const auto receiverHost = getRingHostContext(lightweight[1]);
        LOGVOLE_REQUIRE_TRUE(senderHost && receiverHost && senderHost != receiverHost);
        const auto copied = lightweight[0];
        LOGVOLE_EXPECT_TRUE(getRingHostContext(copied) == senderHost);
        LOGVOLE_EXPECT_TRUE(!lightweight[0].mContext && !lightweight[1].mContext);
        LOGVOLE_EXPECT_TRUE(lightweight[0].mModuli.empty() && lightweight[1].mModuli.empty());
        const auto& hostModuli = getRingHostModuli(lightweight[0]);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(hostModuli, eager.mModuli));
        LOGVOLE_EXPECT_TRUE(getRingHostModuli(copied).data() == hostModuli.data());
        LOGVOLE_REQUIRE_TRUE(senderHost->key_parms_id() == eager.mContext->key_parms_id());
        const auto* tables = senderHost->key_context_data()->small_ntt_tables();
        for (std::size_t limb = 0; limb < preset.roots.size(); ++limb)
            LOGVOLE_EXPECT_EQ(tables[limb].get_root(), preset.roots[limb]);

        if (preset.degree == 8192u)
        {
            CivoleParams production;
            LOGVOLE_REQUIRE_TRUE(makeCivoleParams(CivoleSetting::GoldenSeed, production, 4u));
            LOGVOLE_REQUIRE_TRUE(production.mLogVole.mShrinkExpand.mRing == params);
            production.mLogVole.mW = (std::uint64_t{1} << 25) / params.mPolyModulusDegree;
            production.mLogVole.mTotalLabelCount = std::uint64_t{1} << 25;
            std::vector<std::uint64_t> expectedLo, expectedHi, lightweightLo, lightweightHi;
            LOGVOLE_REQUIRE_TRUE(goldenSeedRoundingMargins(
                production.mLogVole, eager, expectedLo, expectedHi));
            LOGVOLE_REQUIRE_TRUE(goldenSeedRoundingMargins(
                production.mLogVole, lightweight[0], lightweightLo, lightweightHi));
            LOGVOLE_REQUIRE_TRUE(expectedLo == lightweightLo);
            LOGVOLE_REQUIRE_TRUE(expectedHi == lightweightHi);
        }

        osuCrypto::PRNG expectedPrng(osuCrypto::block(0x5345414cu, preset.degree));
        osuCrypto::PRNG actualPrng(osuCrypto::block(0x5345414cu, preset.degree));
        auto expected = sampleUniformPoly(eager, expectedPrng);
        auto actual = sampleUniformPoly(lightweight[0], actualPrng);
        expect_poly_equal(actual, expected);
        LOGVOLE_EXPECT_EQ(actualPrng.get<std::uint64_t>(), expectedPrng.get<std::uint64_t>());
        LOGVOLE_REQUIRE_TRUE(addPolyError(expected, 3.2, 36.0, expectedPrng, eager));
        LOGVOLE_REQUIRE_TRUE(addPolyError(actual, 3.2, 36.0, actualPrng, lightweight[0]));
        expect_poly_equal(actual, expected);
        LOGVOLE_EXPECT_EQ(actualPrng.get<std::uint64_t>(), expectedPrng.get<std::uint64_t>());
        LOGVOLE_REQUIRE_TRUE(forwardNtt(expected, eager));
        LOGVOLE_REQUIRE_TRUE(forwardNtt(actual, lightweight[0]));
        expect_poly_equal(actual, expected);
        LOGVOLE_REQUIRE_TRUE(inverseNtt(expected, eager));
        LOGVOLE_REQUIRE_TRUE(inverseNtt(actual, lightweight[0]));
        expect_poly_equal(actual, expected);

        for (unsigned corruption = 0; corruption < 5; ++corruption)
        {
            auto malformed = lightweight[0];
            if (corruption == 0) malformed.mHostContextCache.reset();
            if (corruption == 1)
            {
                auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
                changed->mValues[0] = changed->mValues[1];
                malformed.mRawModuli = std::move(changed);
            }
            if (corruption == 2) --malformed.mParams.mCoeffModulusBits[0];
            if (corruption == 3) malformed.mRawModuli.reset();
            if (corruption == 4)
            {
                auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
                --changed->mBitCounts[0];
                malformed.mRawModuli = std::move(changed);
            }
            LOGVOLE_REQUIRE_TRUE(getRingHostContext(malformed) == nullptr);
            LOGVOLE_REQUIRE_TRUE(getRingHostModuli(malformed).empty());
            std::vector<RnsPoly> batch{actual};
            LOGVOLE_REQUIRE_FALSE(forwardNttBatch(batch, malformed));
            LOGVOLE_REQUIRE_FALSE(inverseNttBatch(batch, malformed));
            expect_poly_equal(batch[0], actual);
        }

        if (preset.degree == 8192u)
        {
            CivoleParams production;
            LOGVOLE_REQUIRE_TRUE(makeCivoleParams(CivoleSetting::GoldenSeed, production, 4u));
            production.mLogVole.mW = (std::uint64_t{1} << 25) / params.mPolyModulusDegree;
            production.mLogVole.mTotalLabelCount = std::uint64_t{1} << 25;
            auto malformed = lightweight[0];
            auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
            changed->mValues[0] = changed->mValues[1];
            malformed.mRawModuli = std::move(changed);
            std::vector<std::uint64_t> lo{17}, hi{23};
            LOGVOLE_REQUIRE_FALSE(goldenSeedRoundingMargins(production.mLogVole, malformed, lo, hi));
            LOGVOLE_REQUIRE_TRUE(lo == std::vector<std::uint64_t>{17});
            LOGVOLE_REQUIRE_TRUE(hi == std::vector<std::uint64_t>{23});
        }

        const std::vector<std::uint64_t> labels{0u, 1u, preset.plaintext - 1u, 7u};
        for (bool scaled : {false, true})
        {
            RnsPoly reference;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(eagerCrt, labels, scaled, 0u, 1u, reference));
            AlignedUnVec<std::uint64_t> expectedDecoded;
#if defined(ENABLE_LOGVOLE_CUDA)
            {
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, eagerCrt, {reference}, labels.size(), scaled, 1u,
                    expectedDecoded)));
            }
#else
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, eagerCrt, {reference}, labels.size(), scaled, 1u,
                expectedDecoded)));
#endif
            for (const auto& candidate : crt)
            {
                RnsPoly encoded;
                LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(candidate, labels, scaled, 0u, 1u, encoded));
                expect_poly_equal(encoded, reference);
                AlignedUnVec<std::uint64_t> decoded;
                LOGVOLE_REQUIRE_TRUE(((candidate).mGpuLightweight || (candidate).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(candidate, {encoded}, labels.size(), scaled, 1u, decoded)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, candidate, {encoded}, labels.size(), scaled, 1u, decoded))));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, labels));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, expectedDecoded));
                if (candidate.mGpuLightweight)
                    LOGVOLE_EXPECT_TRUE(!candidate.mBatchingContext && !candidate.mBatchEncoder && !candidate.mRing.mContext);
            }
        }
        {
            // Public input may be a shape-valid polynomial whose residues
            // were not canonicalized yet. SEAL reduces each q limb before
            // CRT compose; the device path must do the same without changing
            // its caller's host polynomial.
            RnsPoly raw;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                eagerCrt, labels, false, 0u, 1u, raw));
            for (std::size_t limb = 0; limb < preset.primes.size(); ++limb)
            {
                const auto offset = limb * static_cast<std::size_t>(preset.degree);
                raw.mCoeffs[offset] += preset.primes[limb];
            }
            AlignedUnVec<std::uint64_t> expected;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, eagerCrt, {raw}, labels.size(), false, 1u, expected)));
            for (const auto& candidate : crt)
            {
                AlignedUnVec<std::uint64_t> actual;
                LOGVOLE_REQUIRE_TRUE(((candidate).mGpuLightweight || (candidate).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(candidate, {raw}, labels.size(), false, 1u, actual)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, candidate, {raw}, labels.size(), false, 1u, actual))));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
            }
        }
        if (crt[0].mGpuLightweight)
        {
            // A copied lightweight context must not bypass metadata or owner
            // validation through the warm device table cache.
            RnsPoly validEncoded;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                eagerCrt, labels, false, 0u, 1u, validEncoded));
            for (unsigned corruption = 0; corruption < 5; ++corruption)
            {
                auto malformed = crt[0];
                if (corruption == 0) --malformed.mPlaintextModulus;
                if (corruption == 1) ++malformed.mPlaintextLiftModQj[0];
                if (corruption == 2) swap_moduli_for_test(malformed.mRing, 0, 1);
                if (corruption == 3) malformed.mRing.mHostContextCache = crt[1].mRing.mHostContextCache;
                if (corruption == 4) --malformed.mPlaintextModulusBits;
                RnsPoly encoded;
                assignValues<std::uint64_t>(encoded.mCoeffs, {0xdecafbadULL});
                LOGVOLE_REQUIRE_FALSE(wrapZpBatchCrt(
                    malformed, labels, false, 0u, 1u, encoded))
                    << " corruption " << corruption;
                AlignedUnVec<std::uint64_t> unchanged;
                assignValues<std::uint64_t>(unchanged,
                    {0xdecafbadULL, 0x12345678ULL});
                LOGVOLE_REQUIRE_FALSE(((malformed).mGpuLightweight || (malformed).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(malformed, {validEncoded}, labels.size(), false, 1u,
                    unchanged)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, malformed, {validEncoded}, labels.size(), false, 1u,
                    unchanged)))) << " corruption " << corruption;
                LOGVOLE_REQUIRE_TRUE(rangesEqual(unchanged,
                    std::vector<std::uint64_t>{0xdecafbadULL, 0x12345678ULL}));
            }
        }
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    if ((advanced.mUseGpu && testGpuAvailable))
    {
        // The production constants above remain the fast path. These tuples
        // force exact dynamic prime selection, mixed-width ordering, device
        // CRT/plaintext setup and a separate role-local raw-ring certificate.
        const std::array<std::pair<std::uint32_t, std::vector<int>>, 3> dynamicCases{{
            {1024u, {30, 30}}, {2048u, {30, 31, 30}},
            {65536u, {30, 31, 30, 31, 30, 31, 30, 31, 30}}
        }};
        for (const auto& [degree, widths] : dynamicCases)
        {
            // Ownership regressions select small dynamic tuples and both
            // production presets; the full setup/table matrix remains default.
            if (cmd.getOr("lvFactoryFast", 0) && degree == 65536u) continue;
            RingParams params{};
            params.mPolyModulusDegree = degree;
            params.mCoeffModulusBits.resize(widths.size());
            std::copy(widths.begin(), widths.end(), params.mCoeffModulusBits.begin());
            const auto expectedPrimes = seal::CoeffModulus::Create(degree, widths);
            const auto run = identityService->allocate();
            std::array<RingNttContext, 2> dynamicRing;
            std::array<ZpCrtContext, 2> dynamicCrt;
            std::array<std::shared_ptr<gpu::GpuPlainNtt>, 2> plainOwners;
            for (std::size_t party = 0; party < 2; ++party)
            {
                const ProtocolCacheScope roleScope(run,
                    party ? ProtocolCacheRole::Receiver : ProtocolCacheRole::Sender);
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, dynamicRing[party],
                    std::make_shared<RingContextFactory>(advanced, identityService), roleScope));
                const auto& selected = dynamicRing[party];
                LOGVOLE_REQUIRE_TRUE(selected.mGpuLightweight && selected.mRawModuli &&
                    selected.mRawModuli->mDynamicGpuCertificate && !selected.mContext);
                LOGVOLE_REQUIRE_TRUE(validateRingContextMetadata(selected));
                LOGVOLE_REQUIRE_EQ(ringModulusCount(selected), widths.size());
                for (std::size_t limb = 0; limb < widths.size(); ++limb)
                    LOGVOLE_EXPECT_EQ(ringModulusValue(selected, limb), expectedPrimes[limb].value());
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 30u, dynamicCrt[party],
                    std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(advanced, identityService)), roleScope));
                LOGVOLE_REQUIRE_TRUE(dynamicCrt[party].mGpuLightweight &&
                    !dynamicCrt[party].mBatchingContext && !dynamicCrt[party].mBatchEncoder);
                const auto certificate = selected.mRawModuli->mDynamicGpuCertificate;
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(selected) == certificate);

                ZpCrtContext eager;
                {
                    auto options = advanced;
                    options.mAdvanced.mContexts.mLightweightRing = false;
                    options.mAdvanced.mContexts.mLightweightCrt = false;
                    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 30u, eager,
                        std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(options, identityService)), roleScope));
                }
                LOGVOLE_REQUIRE_TRUE(!eager.mGpuLightweight && eager.mBatchEncoder);
                LOGVOLE_EXPECT_EQ(dynamicCrt[party].mPlaintextModulus, eager.mPlaintextModulus);
                LOGVOLE_EXPECT_EQ(dynamicCrt[party].mPlaintextModulusBits, eager.mPlaintextModulusBits);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(
                    dynamicCrt[party].mPlaintextLiftModQj, eager.mPlaintextLiftModQj));
                plainOwners[party] = gpu::GpuPlainNtt::getRaw(
                    degree, eager.mPlaintextModulus, selected.mResourceScope);
                LOGVOLE_REQUIRE_TRUE(plainOwners[party] && plainOwners[party]->slotCount() == degree);
                const auto lazyHost = getRingHostContext(selected);
                LOGVOLE_REQUIRE_TRUE(lazyHost &&
                    lazyHost->key_context_data()->parms().coeff_modulus() == expectedPrimes);

                const auto* sealTables = lazyHost->key_context_data()->small_ntt_tables();
                std::vector<gpu::HostShoupOperand> roots(static_cast<std::size_t>(degree) * widths.size());
                std::vector<gpu::HostShoupOperand> inverse(roots.size());
                auto& stream = operationExecution.mainStream();
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(roots.data(), certificate->metadata().mRoots,
                    roots.size() * sizeof(roots[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(inverse.data(), certificate->metadata().mInvRoots,
                    inverse.size() * sizeof(inverse[0]), stream));
                for (std::size_t limb = 0; limb < widths.size(); ++limb)
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto forward = sealTables[limb].get_from_root_powers(i);
                    const auto backward = sealTables[limb].get_from_inv_root_powers(i);
                    const auto offset = limb * degree + i;
                    LOGVOLE_EXPECT_EQ(roots[offset].mOperand, forward.operand);
                    LOGVOLE_EXPECT_EQ(roots[offset].mQuotient, forward.quotient);
                    LOGVOLE_EXPECT_EQ(inverse[offset].mOperand, backward.operand);
                    LOGVOLE_EXPECT_EQ(inverse[offset].mQuotient, backward.quotient);
                }

                // Compare the GPU's multiword CRT constants with SEAL's RNSBase,
                // including the ninth limb that formerly exceeded setup bounds.
                seal::util::RNSBase sealBase(expectedPrimes, seal::MemoryManager::GetPool());
                std::vector<std::uint64_t> baseProduct(widths.size());
                std::vector<std::uint64_t> punctured(widths.size() * widths.size());
                std::vector<gpu::HostShoupOperand> inversePunctured(widths.size());
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(baseProduct.data(),
                    certificate->metadata().mBaseProd, baseProduct.size() * sizeof(baseProduct[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(punctured.data(),
                    certificate->metadata().mPuncturedProd, punctured.size() * sizeof(punctured[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(inversePunctured.data(),
                    certificate->metadata().mInvPuncturedProd,
                    inversePunctured.size() * sizeof(inversePunctured[0]), stream));
                for (std::size_t i = 0; i < widths.size(); ++i)
                {
                    LOGVOLE_EXPECT_EQ(baseProduct[i], sealBase.base_prod()[i]);
                    const auto inverseOp = sealBase.inv_punctured_prod_mod_base_array()[i];
                    LOGVOLE_EXPECT_EQ(inversePunctured[i].mOperand, inverseOp.operand);
                    LOGVOLE_EXPECT_EQ(inversePunctured[i].mQuotient, inverseOp.quotient);
                }
                for (std::size_t i = 0; i < punctured.size(); ++i)
                    LOGVOLE_EXPECT_EQ(punctured[i], sealBase.punctured_prod_array()[i]);

                const auto batchData = eager.mBatchingContext->first_context_data();
                LOGVOLE_REQUIRE_TRUE(batchData && batchData->plain_ntt_tables());
                const auto& plainTables = *batchData->plain_ntt_tables();
                const auto& plainView = plainOwners[party]->view(stream);
                std::vector<gpu::HostShoupOperand> plainRoots(degree), plainInverse(degree);
                std::vector<std::uint32_t> slotMap(degree), inverseSlotMap(degree);
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(plainRoots.data(), plainView.mRoots,
                    plainRoots.size() * sizeof(plainRoots[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(plainInverse.data(), plainView.mInvRoots,
                    plainInverse.size() * sizeof(plainInverse[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(slotMap.data(), plainOwners[party]->slotMap(),
                    slotMap.size() * sizeof(slotMap[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(inverseSlotMap.data(),
                    plainOwners[party]->inverseSlotMap(),
                    inverseSlotMap.size() * sizeof(inverseSlotMap[0]), stream));
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto forward = plainTables.get_from_root_powers(i);
                    const auto backward = plainTables.get_from_inv_root_powers(i);
                    LOGVOLE_EXPECT_EQ(plainRoots[i].mOperand, forward.operand);
                    LOGVOLE_EXPECT_EQ(plainRoots[i].mQuotient, forward.quotient);
                    LOGVOLE_EXPECT_EQ(plainInverse[i].mOperand, backward.operand);
                    LOGVOLE_EXPECT_EQ(plainInverse[i].mQuotient, backward.quotient);
                }
                // A SEAL-encoded sequence has a unique NTT-domain value in
                // every slot. This checks the entire device map independently
                // of the device map-generation formula.
                std::vector<std::uint64_t> distinctSlots(degree);
                for (std::size_t i = 0; i < degree; ++i) distinctSlots[i] = i + 1u;
                seal::Plaintext encoded;
                eager.mBatchEncoder->encode(distinctSlots, encoded);
                LOGVOLE_REQUIRE_EQ(encoded.coeff_count(), degree);
                std::vector<std::uint64_t> eval(encoded.data(), encoded.data() + degree);
                seal::util::ntt_negacyclic_harvey(eval.data(), plainTables);
                for (std::size_t i = 0; i < degree; ++i)
                {
                    LOGVOLE_REQUIRE_TRUE(slotMap[i] < degree);
                    LOGVOLE_EXPECT_EQ(inverseSlotMap[slotMap[i]], i);
                    LOGVOLE_EXPECT_EQ(eval[slotMap[i]] % eager.mPlaintextModulus,
                        distinctSlots[i]);
                }

                if (degree == 65536u)
                {
                    RnsPoly input;
                    input.mCoeffs.resize(static_cast<std::size_t>(degree) * widths.size());
                    for (std::size_t limb = 0; limb < widths.size(); ++limb)
                    for (std::size_t i = 0; i < degree; ++i)
                        input.mCoeffs[limb * degree + i] =
                            (static_cast<std::uint64_t>(i) * 17u + limb * 23u + 1u) %
                            expectedPrimes[limb].value();
                    auto expectedNtt = input;
                    for (std::size_t limb = 0; limb < widths.size(); ++limb)
                        seal::util::ntt_negacyclic_harvey(
                            expectedNtt.mCoeffs.data() + limb * degree, sealTables[limb]);
                    gpu::GpuPolyBuffer device(*certificate, 1u, stream);
                    LOGVOLE_REQUIRE_TRUE(device.data(stream) && device.upload(input, 0u, stream));
                    LOGVOLE_REQUIRE_TRUE(gpu::nttForward(*certificate, device.data(stream), 1u, stream));
                    std::vector<RnsPoly> transformed;
                    LOGVOLE_REQUIRE_TRUE(device.download(transformed, stream));
                    LOGVOLE_REQUIRE_EQ(transformed.size(), 1u);
                    expect_poly_equal(transformed[0], expectedNtt);
                    LOGVOLE_REQUIRE_TRUE(gpu::nttInverse(*certificate, device.data(stream), 1u, stream));
                    std::vector<RnsPoly> roundTrip;
                    LOGVOLE_REQUIRE_TRUE(device.download(roundTrip, stream));
                    LOGVOLE_REQUIRE_EQ(roundTrip.size(), 1u);
                    expect_poly_equal(roundTrip[0], input);
                }

                const std::vector<std::uint64_t> labels{
                    0u, 1u, eager.mPlaintextModulus - 1u, 7u, 11u};
                for (bool scaled : {false, true})
                {
                    RnsPoly reference, actual;
                    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(eager, labels, scaled, 0u, 1u, reference));
                    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                        dynamicCrt[party], labels, scaled, 0u, 1u, actual));
                    expect_poly_equal(actual, reference);
                    AlignedUnVec<std::uint64_t> decoded;
                    LOGVOLE_REQUIRE_TRUE(((dynamicCrt[party]).mGpuLightweight || (dynamicCrt[party]).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(dynamicCrt[party], {actual}, labels.size(), scaled, 1u, decoded)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, dynamicCrt[party], {actual}, labels.size(), scaled, 1u, decoded))));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, labels));
                    if (!scaled)
                    {
                        AlignedUnVec<std::uint64_t> expectedDecoded;
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, eager, {actual}, labels.size(), false, 1u,
                            expectedDecoded)));
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, expectedDecoded));

                        // Force the path that reduces a full 64-bit host
                        // residue before the dynamic rho=2/3/9 CRT compose.
                        auto raw = actual;
                        for (std::size_t limb = 0; limb < widths.size(); ++limb)
                            raw.mCoeffs[limb * static_cast<std::size_t>(degree)] +=
                                expectedPrimes[limb].value();
                        AlignedUnVec<std::uint64_t> expectedRaw, actualRaw;
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, eager, {raw}, labels.size(), false, 1u,
                            expectedRaw)));
                        LOGVOLE_REQUIRE_TRUE(((dynamicCrt[party]).mGpuLightweight || (dynamicCrt[party]).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(dynamicCrt[party], {raw}, labels.size(), false,
                            1u, actualRaw)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, dynamicCrt[party], {raw}, labels.size(), false,
                            1u, actualRaw))));
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actualRaw, expectedRaw));
                    }
                }
                if (degree <= 2048u)
                {
                    std::vector<std::uint64_t> twoRings(degree + 5u);
                    for (std::size_t i = 0; i < twoRings.size(); ++i)
                        twoRings[i] = (i * 17u + 3u) % eager.mPlaintextModulus;
                    for (bool scaled : {false, true})
                    {
                        RnsPoly expectedConstant, actualConstant;
                        LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(
                            eager, 7u, scaled, 2u, expectedConstant));
                        LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(
                            dynamicCrt[party], 7u, scaled, 2u, actualConstant));
                        expect_poly_equal(actualConstant, expectedConstant);

                        RnsPoly expectedEmpty, actualEmpty;
                        LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                            eager, {}, scaled, 7u, 1u, expectedEmpty));
                        LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                            dynamicCrt[party], {}, scaled, 7u, 1u, actualEmpty));
                        expect_poly_equal(actualEmpty, expectedEmpty);

                        std::vector<RnsPoly> expectedLabels, actualLabels;
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(wrapZpLabelsCrt(crtResources.executor, crtEncodeBuffers, eager, twoRings, scaled, 7u, 2u, expectedLabels)));
                        LOGVOLE_REQUIRE_TRUE(((dynamicCrt[party]).mGpuLightweight || (dynamicCrt[party]).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyWrapZpLabelsCrt(dynamicCrt[party], twoRings, scaled, 7u, 2u, actualLabels)
                    : macoro::sync_wait(wrapZpLabelsCrt(crtResources.executor, crtEncodeBuffers, dynamicCrt[party], twoRings, scaled, 7u, 2u, actualLabels))));
                        LOGVOLE_REQUIRE_EQ(actualLabels.size(), 2u);
                        for (std::size_t i = 0; i < actualLabels.size(); ++i)
                            expect_poly_equal(actualLabels[i], expectedLabels[i]);
                    }
                }
                auto malformed = selected;
                auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
                changed->mValues[0] = changed->mValues[1];
                malformed.mRawModuli = std::move(changed);
                LOGVOLE_REQUIRE_FALSE(validateRingContextMetadata(malformed));
                LOGVOLE_REQUIRE_TRUE(getRingHostContext(malformed) == nullptr);
                {
                    auto invalidCrt = dynamicCrt[party];
                    ++invalidCrt.mPlaintextLiftModQj[0];
                    RnsPoly valid;
                    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                        eager, labels, false, 0u, 1u, valid));
                    AlignedUnVec<std::uint64_t> unchanged;
                    assignValues<std::uint64_t>(unchanged, {23u, 47u});
                    LOGVOLE_REQUIRE_FALSE(((invalidCrt).mGpuLightweight || (invalidCrt).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(invalidCrt, {valid}, labels.size(), false,
                        1u, unchanged)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, invalidCrt, {valid}, labels.size(), false,
                        1u, unchanged))));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(unchanged,
                        std::vector<std::uint64_t>{23u, 47u}));
                    RnsPoly invalidShape;
                    assignValues<std::uint64_t>(invalidShape.mCoeffs, {17u});
                    LOGVOLE_REQUIRE_FALSE(((dynamicCrt[party]).mGpuLightweight || (dynamicCrt[party]).mRing.mExecutionOptions.mUseGpu
                    ? osuCrypto::LogVole::detail::gpuLegacyUnwrapRingLabelsCrt(dynamicCrt[party], {invalidShape}, labels.size(),
                        false, 1u, unchanged)
                    : macoro::sync_wait(unwrapRingLabelsCrt(crtResources.executor, crtDecodeBuffers, dynamicCrt[party], {invalidShape}, labels.size(),
                        false, 1u, unchanged))));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(unchanged,
                        std::vector<std::uint64_t>{23u, 47u}));
                }

                if (degree == 65536u)
                {
                    // Native prime-selection failures return status in the
                    // consolidated metadata record. Every rejected setup
                    // must leave the caller's prior host results untouched.
                    auto noCoefficientPrime = params;
                    noCoefficientPrime.mCoeffModulusBits[0] = 2;
                    std::vector<std::uint64_t> unchangedPrimes{0xdecafbadULL};
                    LOGVOLE_REQUIRE_FALSE(gpu::selectSealCoeffModuliDevice(
                        noCoefficientPrime, unchangedPrimes));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(unchangedPrimes,
                        std::vector<std::uint64_t>{0xdecafbadULL}));
                    std::uint64_t unchangedPlain = 0xdecafbadULL;
                    std::uint32_t unchangedBits = 31u;
                    LOGVOLE_REQUIRE_FALSE(gpu::selectSealPlainModulusDevice(
                        degree, 2u, certificate->metadata().mMinModulus,
                        unchangedPlain, unchangedBits));
                    LOGVOLE_EXPECT_EQ(unchangedPlain, 0xdecafbadULL);
                    LOGVOLE_EXPECT_EQ(unchangedBits, 31u);
                    AlignedUnVec<std::uint64_t> unchangedLift;
                    unchangedLift.resize(1);
                    unchangedLift[0] = 0xdecafbadULL;
                    LOGVOLE_REQUIRE_FALSE(gpu::preparePlaintextLiftDevice(
                        *certificate, certificate->metadata().mMinModulus, unchangedLift));
                    LOGVOLE_REQUIRE_EQ(unchangedLift.size(), 1u);
                    LOGVOLE_EXPECT_EQ(unchangedLift[0], 0xdecafbadULL);

                    const std::uint64_t oneModFactor = 2u * static_cast<std::uint64_t>(degree) + 1u;
                    const std::uint64_t composite = oneModFactor * oneModFactor;
                    int compositeBits = 0;
                    for (auto q = composite; q; q >>= 1) ++compositeBits;
                    RingParams compositeParams{};
                    compositeParams.mPolyModulusDegree = degree;
                    compositeParams.mCoeffModulusBits.resize(1u);
                    compositeParams.mCoeffModulusBits[0] = compositeBits;
                    LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(compositeParams,
                        std::span<const std::uint64_t>(&composite, 1u), selected.mResourceScope) == nullptr);
                    LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(selected) == certificate);
                }
            }
            LOGVOLE_EXPECT_TRUE(dynamicRing[0].mRawModuli->mDynamicGpuCertificate !=
                dynamicRing[1].mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_EXPECT_TRUE(dynamicCrt[0].mHostContextCache != dynamicCrt[1].mHostContextCache);
            LOGVOLE_EXPECT_TRUE(plainOwners[0] != plainOwners[1]);
            LOGVOLE_EXPECT_TRUE(plainOwners[0]->slotMap() != plainOwners[1]->slotMap());
        }
    }
#endif
}

void LogVole_RingOps_NttRoundTrip(const oc::CLP& cmd)
{
    RingNttContext missingHost;
    missingHost.mGpuLightweight = true;
    LOGVOLE_REQUIRE_TRUE(getRingHostModuli(missingHost).empty());

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x1234u, 0x5678u, 0);
    RnsPoly expected = poly;
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(expected, ctx));

    LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(inverseNtt(poly, ctx));

    expect_poly_equal(poly, expected);

#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) == 0) return;
    LOGVOLE_REQUIRE_TRUE(gpu::available());
    // Keep the existing full/minimal-chain comparison independent of the
    // separate opt-in batching-context representation below.
    for (std::uint32_t limbs : {1u, 2u, 4u})
    {
        RingParams varied = make_small_params();
        varied.mCoeffModulusBits.resize(limbs);
        std::fill(varied.mCoeffModulusBits.begin(), varied.mCoeffModulusBits.end(), 30);
        for (std::uint32_t plaintextBits : {14u, 20u, 30u})
            expect_single_limb_batching_parity(varied, plaintextBits);
    }
    const bool expectReuse = cmd.getOr("ntt_reuse_host", 1) != 0;
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    advanced.mAdvanced.mProtocol.mNttReuseHost = expectReuse;

    for (bool eightLimbs : { false, true })
    {
        RingParams batchParams{};
        batchParams.mPolyModulusDegree = eightLimbs ? 16384 : 8192;
        batchParams.mCoeffModulusBits.resize(eightLimbs ? 8 : 4);
        std::fill(batchParams.mCoeffModulusBits.begin(), batchParams.mCoeffModulusBits.end(),
            eightLimbs ? 52 : 55);
        RingNttContext batchCtx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, batchCtx,
            std::make_shared<RingContextFactory>(advanced, nullptr)));
        expect_single_limb_batching_parity(batchParams, eightLimbs ? 52u : 55u);
        {
            auto options = advanced;
            options.mAdvanced.mContexts.mLightweightRing = false;
            options.mAdvanced.mContexts.mLightweightCrt = false;
            options.mAdvanced.mContexts.mBatchingSingleLimb = false;
            RingNttContext fullRing, minimalRing;
            ZpCrtContext fullCrt, minimalCrt;
            const auto plaintextBits = eightLimbs ? 52u : 55u;
            {
                options.mAdvanced.mContexts.mFullModChain = true;
                auto factory = std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(options, nullptr));
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, fullRing, factory->ringFactory()));
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(batchParams, plaintextBits, fullCrt, factory));
            }
            {
                options.mAdvanced.mContexts.mFullModChain = false;
                auto factory = std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(options, nullptr));
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, minimalRing, factory->ringFactory()));
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(batchParams, plaintextBits, minimalCrt, factory));
                RingNttContext again;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, again, minimalRing.mFactory));
                LOGVOLE_EXPECT_TRUE(again.mContext == minimalRing.mContext);
            }
            auto expectSameUsableContexts = [](const auto& full, const auto& minimal) {
                LOGVOLE_REQUIRE_TRUE(full != minimal);
                LOGVOLE_REQUIRE_TRUE(full->key_parms_id() == minimal->key_parms_id());
                LOGVOLE_REQUIRE_TRUE(full->first_parms_id() == minimal->first_parms_id());
                for (const auto& pair : { std::pair{full->key_context_data(), minimal->key_context_data()},
                                         std::pair{full->first_context_data(), minimal->first_context_data()} })
                {
                    LOGVOLE_REQUIRE_TRUE(pair.first && pair.second);
                    const auto expected = pair.first->qualifiers();
                    const auto actual = pair.second->qualifiers();
                    LOGVOLE_REQUIRE_TRUE(expected.parameters_set() && actual.parameters_set());
                    LOGVOLE_EXPECT_TRUE(expected.sec_level == actual.sec_level);
                    LOGVOLE_EXPECT_EQ(expected.using_ntt, actual.using_ntt);
                    LOGVOLE_EXPECT_EQ(expected.using_batching, actual.using_batching);
                    LOGVOLE_EXPECT_EQ(expected.using_fast_plain_lift, actual.using_fast_plain_lift);
                }
                LOGVOLE_EXPECT_TRUE(full->first_context_data()->next_context_data() != nullptr);
                LOGVOLE_EXPECT_TRUE(minimal->first_context_data()->next_context_data() == nullptr);
            };
            expectSameUsableContexts(fullRing.mContext, minimalRing.mContext);
            expectSameUsableContexts(fullCrt.mBatchingContext, minimalCrt.mBatchingContext);
            LOGVOLE_EXPECT_EQ(fullCrt.mPlaintextModulus, minimalCrt.mPlaintextModulus);
            LOGVOLE_EXPECT_EQ(fullCrt.mPlaintextModulusBits, minimalCrt.mPlaintextModulusBits);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fullCrt.mPlaintextLiftModQj, minimalCrt.mPlaintextLiftModQj));

            // Exercise the actual host samplers and NTT tables, independently
            // of any GPU ring cache shared by these identical parameter sets.
            auto fullPoly = deriveUniformPolyFromNonce(fullRing, 0x43484149u, 0x4e504152u, 1u);
            auto minimalPoly = deriveUniformPolyFromNonce(minimalRing, 0x43484149u, 0x4e504152u, 1u);
            expect_poly_equal(fullPoly, minimalPoly);
            osuCrypto::PRNG fullPrng(osuCrypto::block(0x43484149u, 0x4e4e4f49u));
            osuCrypto::PRNG minimalPrng(osuCrypto::block(0x43484149u, 0x4e4e4f49u));
            LOGVOLE_REQUIRE_TRUE(addPolyError(fullPoly, 3.2, 36.0, fullPrng, fullRing));
            LOGVOLE_REQUIRE_TRUE(addPolyError(minimalPoly, 3.2, 36.0, minimalPrng, minimalRing));
            expect_poly_equal(fullPoly, minimalPoly);
            LOGVOLE_REQUIRE_TRUE(forwardNtt(fullPoly, fullRing));
            LOGVOLE_REQUIRE_TRUE(forwardNtt(minimalPoly, minimalRing));
            expect_poly_equal(fullPoly, minimalPoly);
            LOGVOLE_REQUIRE_TRUE(inverseNtt(fullPoly, fullRing));
            LOGVOLE_REQUIRE_TRUE(inverseNtt(minimalPoly, minimalRing));
            expect_poly_equal(fullPoly, minimalPoly);

            std::vector<std::uint64_t> labels(batchParams.mPolyModulusDegree - 3u);
            for (std::size_t i = 0; i < labels.size(); ++i)
                labels[i] = i % 3u ? i : fullCrt.mPlaintextModulus - 1u;
            for (bool multiplyByDelta : {false, true})
            {
                RnsPoly fullEncoded, minimalEncoded;
                LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(fullCrt, labels, multiplyByDelta, 7u, 1u, fullEncoded));
                LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(minimalCrt, labels, multiplyByDelta, 7u, 1u, minimalEncoded));
                expect_poly_equal(fullEncoded, minimalEncoded);
            }
        }
        // The 65 MiB case exceeds the old 64 MiB transfer chunk. The smaller
        // cases exercise both NTT kernels without relying on batch dispatch.
        for (std::size_t count : { std::size_t(1), std::size_t(5), std::size_t(65) })
        {
            if (cmd.getOr("lvFactoryFast", 0) && count == 65) continue;
            if (!eightLimbs && count == 65) continue;
            std::vector<RnsPoly> actual(count + 2);
            for (std::size_t i = 0; i < actual.size(); ++i)
                actual[i] = deriveUniformPolyFromNonce(batchCtx, 0x4E545452u, 0x45555345u, i);
            auto reference = actual;
            for (std::size_t i = 1; i <= count; ++i)
                LOGVOLE_REQUIRE_TRUE(forwardNtt(reference[i], batchCtx));
            std::vector<const std::uint64_t*> allocations;
            for (const auto& item : actual) allocations.push_back(item.mCoeffs.data());
            auto window = std::span<RnsPoly>(actual).subspan(1, count);
            LOGVOLE_REQUIRE_TRUE(gpu::nttHostBatch(batchCtx, window, false));
            for (std::size_t i = 0; i < actual.size(); ++i)
            {
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, reference[i].mCoeffs));
                if (expectReuse) LOGVOLE_REQUIRE_TRUE(actual[i].mCoeffs.data() == allocations[i]);
            }
            for (std::size_t i = 1; i <= count; ++i)
                LOGVOLE_REQUIRE_TRUE(inverseNtt(reference[i], batchCtx));
            LOGVOLE_REQUIRE_TRUE(gpu::nttHostBatch(batchCtx, window, true));
            for (std::size_t i = 0; i < actual.size(); ++i)
            {
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, reference[i].mCoeffs));
                if (expectReuse) LOGVOLE_REQUIRE_TRUE(actual[i].mCoeffs.data() == allocations[i]);
            }

            // The 65-polynomial NoGolden case wraps both 32 MiB staging
            // slots and leaves a partial final chunk. Test a nonzero device
            // offset, cache reuse and exact output with one/four CPU workers.
            if (count == 5 || count == 65)
            {
                auto ring = gpu::GpuRing::get(batchCtx);
                LOGVOLE_REQUIRE_TRUE(ring != nullptr);
                auto& stream = operationExecution.mainStream();
                gpu::GpuPolyBuffer device;
                LOGVOLE_REQUIRE_TRUE(device.resize(*ring, actual.size(), stream));
                LOGVOLE_REQUIRE_TRUE(device.upload(actual, stream));
                gpu::GpuStream emptyStream;
                LOGVOLE_REQUIRE_EQ(emptyStream.stagingCapacity(), 0u);
                for (const char* slotSize : {"1", "32"})
                {
                    for (const char* reuse : {"0", "1"})
                    {
                        osuCrypto::LogVoleGpuStreamOptions downloadOptions;
                        downloadOptions.mDownloadSlotMiB = slotSize[0] == '1' ? 1 : 32;
                        downloadOptions.mReuseDownloadStaging = reuse[0] == '1';
                        gpu::GpuStream stream(downloadOptions);
                        const std::size_t slotBytes = std::size_t(slotSize[0] == '1' ? 1 : 32) << 20;
                        const std::size_t run = std::min(count, std::max<std::size_t>(1, slotBytes / ring->polyBytes()));
                        const std::size_t requiredBytes = 2u * run * ring->polyBytes();
                        auto* existing = stream.staging(requiredBytes);
                        LOGVOLE_REQUIRE_TRUE(existing != nullptr);
                        const auto capacity = stream.stagingCapacity();
                        LOGVOLE_REQUIRE_TRUE(stream.existingStaging(requiredBytes) == existing);
                        LOGVOLE_REQUIRE_TRUE(stream.existingStaging(capacity + 1u) == nullptr);
                        LOGVOLE_REQUIRE_EQ(stream.stagingCapacity(), capacity);

                        for (std::uint32_t workers : {1u, 4u})
                        {
                            if (reuse[0] == '1')
                            {
                                // The borrowed buffer still feeds an earlier
                                // H2D. Same-stream ordering must protect its
                                // bytes until that upload has consumed them.
                                std::memcpy(existing, actual.back().mCoeffs.data(), ring->polyBytes());
                                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(device.poly(0, stream), existing,
                                    ring->polyBytes(), stream.raw()));
                            }
                            std::vector<RnsPoly> downloaded{actual[0]};
                            LOGVOLE_REQUIRE_TRUE(device.downloadPipelined(downloaded, stream, workers, 1u, count));
                            LOGVOLE_REQUIRE_EQ(downloaded.size(), count);
                            for (std::size_t i = 0; i < count; ++i)
                                LOGVOLE_REQUIRE_TRUE(rangesEqual(downloaded[i].mCoeffs, actual[i + 1u].mCoeffs));
                            LOGVOLE_REQUIRE_TRUE(stream.existingStaging(requiredBytes) == existing);
                            LOGVOLE_REQUIRE_EQ(stream.stagingCapacity(), capacity);
                            if (reuse[0] == '1')
                            {
                                RnsPoly priorUpload;
                                LOGVOLE_REQUIRE_TRUE(device.downloadAsync(priorUpload, 0, stream));
                                LOGVOLE_REQUIRE_TRUE(stream.sync());
                                expect_poly_equal(priorUpload, actual.back());
                                // A different stream with no pinned capacity
                                // takes the private fallback without growing
                                // or borrowing this stream's staging.
                                std::vector<RnsPoly> privateDownload;
                                LOGVOLE_REQUIRE_TRUE(device.downloadPipelined(privateDownload, emptyStream, workers, 1u, count));
                                expect_batch_equal(privateDownload, downloaded);
                                LOGVOLE_REQUIRE_EQ(emptyStream.stagingCapacity(), 0u);
                            }
                            const auto expectedDownload = downloaded;
                            LOGVOLE_REQUIRE_FALSE(device.downloadPipelined(downloaded, stream, workers, actual.size() + 1u));
                            expect_batch_equal(downloaded, expectedDownload);
                            LOGVOLE_REQUIRE_FALSE(device.downloadPipelined(downloaded, stream, workers, 1u, actual.size()));
                            expect_batch_equal(downloaded, expectedDownload);
                        }
                    }
                }
                if (count == 65)
                {
                    // Reuse one bounded worker pool across eight full chunks
                    // and a one-polynomial tail, then release all worker state.

                    for (const char* reuseWorkers : {"0", "1"})
                    for (std::uint32_t workers : {1u, 4u})
                    {
                        osuCrypto::LogVoleGpuStreamOptions downloadOptions;
                        downloadOptions.mDownloadReuseWorkers = reuseWorkers[0] == '1';
                        gpu::GpuStream stream(downloadOptions);
                        LOGVOLE_REQUIRE_TRUE(stream.staging(std::size_t(16) << 20) != nullptr);
                        CpuBenchmarkContext context;
#if defined(__linux__)
                        cpu_set_t mask;
                        CPU_ZERO(&mask);
                        LOGVOLE_REQUIRE_EQ(sched_getaffinity(0, sizeof(mask), &mask), 0);
                        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
                            if (CPU_ISSET(cpu, &mask)) context.mCpus.push_back(cpu);
#else
                        context.mCpus.resize(workers);
#endif
                        context.mWorkerLimit = workers;
                        CpuBenchmarkState cpuBenchmark{&context};
                        const auto originalSlots = detail::gParallelWorkerSlotsInUse.load();
                        std::vector<RnsPoly> downloaded;
                        LOGVOLE_REQUIRE_TRUE(device.downloadPipelined(downloaded, stream, workers, 1u, count, cpuBenchmark));
                        LOGVOLE_REQUIRE_EQ(downloaded.size(), count);
                        for (std::size_t i = 0; i < count; ++i)
                            LOGVOLE_REQUIRE_TRUE(rangesEqual(downloaded[i].mCoeffs, actual[i + 1u].mCoeffs));
                        LOGVOLE_REQUIRE_EQ(context.mWorkerSlots.load(), 0u);
                        LOGVOLE_REQUIRE_EQ(context.mActiveTaskThreads.load(), 0u);
                        LOGVOLE_REQUIRE_TRUE(context.mPeakTaskThreads.load() <= workers);
                        LOGVOLE_REQUIRE_TRUE(context.mPeakTaskThreads.load() > 0u);
                        LOGVOLE_REQUIRE_EQ(context.mAffinityFailures.load(), 0u);
#if defined(__linux__)
                        if (workers > 1u && context.mCpus.size() > 1u)
                            LOGVOLE_REQUIRE_TRUE(context.mWorkersChecked.load() > 0u);
#endif
                        LOGVOLE_REQUIRE_EQ(detail::gParallelWorkerSlotsInUse.load(), originalSlots);
                    }
                }
            }

            if (count == 5)
            {
                // Failure must not transform any prefix: callers retry the
                // complete batch with the CPU implementation on false.
                actual[count].mCoeffs.resize(actual[count].mCoeffs.size() - 1);
                reference = actual;
                LOGVOLE_EXPECT_FALSE(gpu::nttHostBatch(batchCtx, window, false));
                for (std::size_t i = 0; i < actual.size(); ++i)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, reference[i].mCoeffs));
            }
        }
    }
#endif
}

void LogVole_RingOps_KernelOptions(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) != 0) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (cmd.getOr("gpu", 0) == 0) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    for (std::uint32_t degree : {8192u, 16384u})
    {
        RingParams params;
        params.mPolyModulusDegree = degree;
        params.mCoeffModulusBits.resize(degree == 8192u ? 4u : 8u);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            degree == 8192u ? 55 : 52);
        RingNttContext cpu;
        std::vector<RnsPoly> original(2), expected(2);
        {
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, cpu));
            for (std::size_t i = 0; i < original.size(); ++i)
            {
                original[i] = deriveUniformPolyFromNonce(cpu, 0x4b45524eu, degree, i);
                expected[i] = original[i];
                LOGVOLE_REQUIRE_TRUE(forwardNttCanonical(expected[i], cpu));
            }
        }
        std::array<RingNttContext, 3> owners;
        for (unsigned variant = 0; variant < owners.size(); ++variant)
        {
            osuCrypto::LogVoleExecutionOptions options;
            options.mUseGpu = true;
            auto& kernel = options.mAdvanced.mKernels;
            if (variant == 1)
            {
                kernel.mNttLog14H200 = false;
                kernel.mNttLog13Specialized = false;
                kernel.mNttLog13InverseSpecialized = false;
                kernel.mNttForwardThreads = 256;
                kernel.mNttInverseThreads = 256;
                kernel.mNttLog13InverseThreads = 256;
                kernel.mNoGoldH200PackedRoots = 0;
            }
            else if (variant == 2)
            {
                kernel.mNttForwardThreads = 512;
                kernel.mNttInverseThreads = 512;
                kernel.mNttLog13SimpleIndex = false;
                kernel.mNttLog13ForwardWarpStages712 = false;
                kernel.mNttLog13InverseFusedLastThreeStages = false;
                kernel.mNoGoldH200ForwardFp52Mode = 0;
                kernel.mNoGoldH200InverseFp52Threads = 0;
                kernel.mNoGoldH200PackedRoots = 3;
            }
            LOGVOLE_REQUIRE_TRUE(kernel.valid());
            auto factory = std::make_shared<RingContextFactory>(options, nullptr);
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, owners[variant], factory));
        }
        // Even diagnostic settings belong to the table owner. A differently
        // configured execution owner must not reuse this owner's tables.
        auto different = owners[0].mExecutionOptions;
        different.mAdvanced.mKernels.mNoGoldH200InverseOpTrace = true;
        LOGVOLE_REQUIRE_TRUE(owners[0].mRawModuli);
        LOGVOLE_REQUIRE_FALSE(gpu::GpuRing::getRaw(owners[0].mParams,
            owners[0].mRawModuli->mValues, owners[0].mResourceScope,
            std::make_shared<gpu::GpuSetupContext>(different, nullptr, nullptr)));

        // Alternate live owners, then return to the first: no first-use latch
        // may choose the other owner's configuration or device table layout.
        for (unsigned variant : {1u, 0u, 2u, 1u, 0u})
        {
            auto& ctx = owners[variant];
            auto ring = gpu::GpuRing::get(ctx);
            LOGVOLE_REQUIRE_TRUE(ring);
            LOGVOLE_REQUIRE_TRUE(ring->kernelOptions() == ctx.mExecutionOptions.mAdvanced.mKernels);
            auto& stream = gpu::contextStream(ctx);
            gpu::GpuPolyBuffer device;
            LOGVOLE_REQUIRE_TRUE(device.resize(*ring, original.size(), stream));
            LOGVOLE_REQUIRE_TRUE(device.upload(original, stream));
            // A borrowed view without its table owner's initialization state
            // must fail before launch, without poisoning the valid owner.
            auto detached = ring->view(stream);
            detached.mKernelInitialization = nullptr;
            LOGVOLE_REQUIRE_FALSE(gpu::launchNttForward(
                detached, device.data(stream), 2, nullptr, stream.raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::nttForward(*ring, device.data(stream), 2, stream));
            std::vector<RnsPoly> transformed;
            LOGVOLE_REQUIRE_TRUE(device.download(transformed, stream));
            for (auto& poly : transformed) LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, cpu));
            expect_batch_equal(transformed, expected);
            LOGVOLE_REQUIRE_TRUE(gpu::nttInverse(*ring, device.data(stream), 2, stream));
            std::vector<RnsPoly> restored;
            LOGVOLE_REQUIRE_TRUE(device.download(restored, stream));
            for (auto& poly : restored) LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, cpu));
            expect_batch_equal(restored, original);
        }
    }
    osuCrypto::LogVoleExecutionOptions invalid;
    invalid.mAdvanced.mKernels.mNttForwardThreads = 3;
    bool rejected = false;
    try { RingContextFactory owner(invalid); }
    catch (const std::invalid_argument&) { rejected = true; }
    LOGVOLE_REQUIRE_TRUE(rejected);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_NttTwoTileInPlaceParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) == 0) return;
    LOGVOLE_REQUIRE_TRUE(gpu::available());

    RingParams params{};
    params.mPolyModulusDegree = 16384u;
    params.mCoeffModulusBits.resize(8u);
    std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), 52);
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
    prepareGpuTableOwners(ctx);
    auto ring = gpu::GpuRing::get(ctx);
    LOGVOLE_REQUIRE_TRUE(ring && ring->n() == params.mPolyModulusDegree &&
        ring->rho() == params.mCoeffModulusBits.size());
    auto& stream = operationExecution.mainStream();
    const bool fast = cmd.getOr("lvFactoryFast", 0) != 0;
    for (std::size_t count : {std::size_t{1}, std::size_t{8}, std::size_t{16}})
    {
        // One row and an eight-row batch cover both layouts and warm reuse.
        // Keep the larger matrix available for an explicitly requested full run.
        if (fast && count == 16u) continue;
        std::vector<RnsPoly> original(count), expected(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            original[i] = deriveUniformPolyFromNonce(
                ctx, 0x54574f54u, 0x494c454eu, static_cast<std::uint64_t>(i));
            expected[i] = original[i];
            LOGVOLE_REQUIRE_TRUE(forwardNtt(expected[i], ctx));
        }

        gpu::GpuPolyBuffer inPlace(*ring, count, stream);
        gpu::GpuPolyBuffer outOfPlaceInput(*ring, count, stream);
        gpu::GpuPolyBuffer outOfPlace(*ring, count, stream);
        LOGVOLE_REQUIRE_TRUE(
            inPlace.data(stream) && outOfPlaceInput.data(stream) && outOfPlace.data(stream));
        for (unsigned iteration = 0; iteration < (fast ? 2u : 4u); ++iteration)
        {
            LOGVOLE_REQUIRE_TRUE(inPlace.upload(original, stream));
            LOGVOLE_REQUIRE_TRUE(outOfPlaceInput.upload(original, stream));
            LOGVOLE_REQUIRE_TRUE(gpu::nttForward(
                *ring, inPlace.data(stream), static_cast<std::uint32_t>(count), stream));
            LOGVOLE_REQUIRE_TRUE(gpu::launchNttForwardFrom(
                ring->view(stream), outOfPlaceInput.data(stream), nullptr,
                outOfPlace.data(stream), nullptr, static_cast<std::uint32_t>(count),
                stream.raw()));
            std::vector<RnsPoly> actualInPlace, actualOutOfPlace;
            LOGVOLE_REQUIRE_TRUE(inPlace.download(actualInPlace, stream));
            LOGVOLE_REQUIRE_TRUE(outOfPlace.download(actualOutOfPlace, stream));
            expect_batch_equal(actualInPlace, expected);
            expect_batch_equal(actualOutOfPlace, expected);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_NttBatchDeviceCanonicalization(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool testGpuAvailable = gpu::available();
#endif

    osuCrypto::LogVoleExecutionOptions testAdvanced;
    testAdvanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requestGpu = cmd.getOr("gpu", 0) != 0;
    if (requestGpu) LOGVOLE_REQUIRE_TRUE((testAdvanced.mUseGpu && testGpuAvailable));
#else
    (void)cmd;
#endif
    tests_libOTe::logvole_test::ScopedOptionValue strict(testAdvanced.mAdvanced.mProtocol.mNttCanonicalizeStrict, true);

    osuCrypto::PRNG random(osuCrypto::block(0x4e545443u, 0x414e4f4eu));
    for (std::uint32_t degree : {1024u, 8192u, 16384u})
    {
        if (cmd.getOr("lvFactoryFast", 0) && degree != 1024u) continue;
        RingParams params{};
        params.mPolyModulusDegree = degree;
        params.mCoeffModulusBits.resize(degree == 16384u ? 8u : degree == 8192u ? 4u : 2u);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            degree == 16384u ? 52 : degree == 8192u ? 55 : 30);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx,
            std::make_shared<RingContextFactory>(testAdvanced, nullptr)));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto* tables = hostContext->key_context_data()->small_ntt_tables();
        for (std::size_t count : {std::size_t(4), std::size_t(9)})
        {
            std::vector<RnsPoly> original(count);
            for (auto& poly : original)
            {
                poly.mCoeffs.resize(ringPolyCoeffCount(params));
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto q = ringModulusValue(ctx, limb);
                    const std::array<std::uint64_t, 8> values{
                        0u, q - 1u, q, 2u * q - 1u,
                        std::numeric_limits<std::uint64_t>::max(), std::uint64_t(1) << 63u,
                        random.get<std::uint64_t>(), random.get<std::uint64_t>()};
                    poly.mCoeffs[limb * degree + i] = values[i % values.size()];
                }
            }
            // The oracle uses scalar integer remainder and SEAL directly,
            // independently of both batch dispatch and CPU reduction helpers.
            auto canonical = original;
            auto transformed = original;
            for (std::size_t row = 0; row < count; ++row)
            for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
            {
                const auto q = ringModulusValue(ctx, limb);
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto index = limb * degree + i;
                    canonical[row].mCoeffs[index] %= q;
                    transformed[row].mCoeffs[index] %= q;
                }
                seal::util::ntt_negacyclic_harvey(
                    transformed[row].mCoeffs.data() + limb * degree, tables[limb]);
            }
            auto inverseReference = transformed;
            for (auto& poly : inverseReference)
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                    seal::util::inverse_ntt_negacyclic_harvey(
                        poly.mCoeffs.data() + limb * degree, tables[limb]);
            expect_batch_equal(inverseReference, canonical);

            for (const char* option : {"0", "1"})
            {
                tests_libOTe::logvole_test::ScopedOptionValue reduction(ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalize, option[0] != '0');
                auto actual = original;
                LOGVOLE_REQUIRE_TRUE(forwardNttBatch(actual, ctx));
                expect_batch_equal(actual, transformed);
                LOGVOLE_REQUIRE_TRUE(inverseNttBatch(actual, ctx));
                expect_batch_equal(actual, inverseReference);
                for (const auto& poly : actual)
                    for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                        for (std::size_t i = 0; i < degree; ++i)
                            LOGVOLE_REQUIRE_TRUE(poly.mCoeffs[limb * degree + i] < ringModulusValue(ctx, limb));

                // A malformed final member must leave every preceding member
                // untouched, in either direction and with either dispatch.
                for (bool inverse : {false, true})
                {
                    auto invalid = inverse ? transformed : original;
                    invalid.back().mCoeffs.resize(invalid.back().mCoeffs.size() - 1u);
                    const auto before = invalid;
                    LOGVOLE_REQUIRE_FALSE(inverse ? inverseNttBatch(invalid, ctx) : forwardNttBatch(invalid, ctx));
                    expect_batch_equal(invalid, before);
                }
            }

            tests_libOTe::logvole_test::ScopedOptionValue reduction(ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalize, true);
#if defined(ENABLE_LOGVOLE_CUDA)
            if ((testAdvanced.mUseGpu && testGpuAvailable) && count == 4u)
            {
                for (const char* declineAt : {"1", "2"})
                {
                    tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mNttCanonicalize, (declineAt)[0] == '1' ? osuCrypto::LogVoleFailureStage::BeforeWork : osuCrypto::LogVoleFailureStage::AfterWork);
                    for (bool inverse : {false, true})
                    {
                        auto rejected = inverse ? transformed : original;
                        const auto before = rejected;
                        LOGVOLE_REQUIRE_FALSE(inverse ? inverseNttBatch(rejected, ctx) : forwardNttBatch(rejected, ctx));
                        expect_batch_equal(rejected, before);
                        // Direct helper rejection also retains host data after
                        // the forced post-kernel failure and stream cleanup.
                        LOGVOLE_REQUIRE_FALSE(gpu::nttHostBatch(ctx, rejected, inverse, true));
                        expect_batch_equal(rejected, before);
                        {
                            tests_libOTe::logvole_test::ScopedOptionValue allowFallback(ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalizeStrict, false);
                            LOGVOLE_REQUIRE_TRUE(inverse ? inverseNttBatch(rejected, ctx) : forwardNttBatch(rejected, ctx));
                            expect_batch_equal(rejected, inverse ? inverseReference : transformed);
                        }
                        {
                            // An explicit rollback ignores this option's
                            // strict/debug controls and keeps the old path.
                            tests_libOTe::logvole_test::ScopedOptionValue disabled(ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalize, false);
                            auto rollback = before;
                            LOGVOLE_REQUIRE_TRUE(inverse ? inverseNttBatch(rollback, ctx) : forwardNttBatch(rollback, ctx));
                            expect_batch_equal(rollback, inverse ? inverseReference : transformed);
                        }
                    }
                }
            }
#endif
            if (count == 4u)
            {
                // Strict selection never lowers the established four-poly
                // GPU threshold, even if a device attempt would be declined.
                tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mNttCanonicalize, osuCrypto::LogVoleFailureStage::AfterWork);
                for (std::size_t smallCount : {std::size_t(1), std::size_t(3)})
                {
                    std::vector<RnsPoly> actual(original.begin(), original.begin() + smallCount);
                    const std::vector<RnsPoly> expectedNtt(transformed.begin(), transformed.begin() + smallCount);
                    const std::vector<RnsPoly> expectedCoeff(canonical.begin(), canonical.begin() + smallCount);
                    if (ctx.mGpuLightweight)
                    {
                        // Lightweight contexts deliberately select the GPU at
                        // every batch size. Strict forced decline must leave
                        // the host inputs untouched instead of materializing
                        // SEAL as an implicit fallback.
                        const auto before = actual;
                        LOGVOLE_REQUIRE_FALSE(forwardNttBatch(actual, ctx));
                        expect_batch_equal(actual, before);
                        continue;
                    }
                    LOGVOLE_REQUIRE_TRUE(forwardNttBatch(actual, ctx));
                    expect_batch_equal(actual, expectedNtt);
                    LOGVOLE_REQUIRE_TRUE(inverseNttBatch(actual, ctx));
                    expect_batch_equal(actual, expectedCoeff);
                }
            }
            auto invalidContext = ctx;
            invalidContext.mContext.reset();
            invalidContext.mGpuLightweight = false;
            invalidContext.mHostContextCache.reset();
            auto unchanged = original;
            LOGVOLE_REQUIRE_FALSE(forwardNttBatch(unchanged, invalidContext));
            LOGVOLE_REQUIRE_FALSE(inverseNttBatch(unchanged, invalidContext));
            expect_batch_equal(unchanged, original);
            LOGVOLE_REQUIRE_TRUE(forwardNttBatch({}, invalidContext));
            LOGVOLE_REQUIRE_TRUE(inverseNttBatch({}, invalidContext));
        }
    }
}

void LogVole_RingOps_GadgetDecomposeRecompose(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x55AAu, 0xCCDDu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecompose(poly, 1u << 10u, 4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecompose(digits, 1u << 10u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xAA55u, 0x11EEu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, 20u, 4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, 20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeBitsRangeMatchesSlice(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xBEEFu, 0xCAFEu, 1);

    std::vector<RnsPoly> full;
    std::vector<RnsPoly> range;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, 10u, 6u, ctx, full));
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, 10u, 2u, 3u, ctx, range));
    LOGVOLE_REQUIRE_EQ(range.size(), 3u);

    for (std::size_t i = 0; i < range.size(); ++i)
    {
        expect_poly_equal(range[i], full[i + 2]);
    }
}

void LogVole_RingOps_CenteredGadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_four_limb_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xA11CEu, 0xB0Bu, 2);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, 20u, 0u, 7u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 7u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, 20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_TensorPackUnpack(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RingTensor tensor{};
    tensor.mRows = 2;
    tensor.mCols = 3;
    for (std::uint32_t i = 0; i < tensor.mRows * tensor.mCols; ++i)
    {
        tensor.mPolys.push_back(deriveUniformPolyFromNonce(ctx, 0x77u, 0x99u, i));
    }

    auto packed = packRingTensor(tensor);
    RingTensor unpacked{};
    LOGVOLE_REQUIRE_TRUE(unpackRingTensor(
        tensor.mRows,
        tensor.mCols,
        params.mPolyModulusDegree,
        static_cast<std::uint32_t>(params.mCoeffModulusBits.size()),
        packed,
        unpacked));
    LOGVOLE_REQUIRE_EQ(unpacked.mRows, tensor.mRows);
    LOGVOLE_REQUIRE_EQ(unpacked.mCols, tensor.mCols);
    LOGVOLE_REQUIRE_EQ(unpacked.mPolys.size(), tensor.mPolys.size());

    for (std::size_t i = 0; i < tensor.mPolys.size(); ++i)
    {
        expect_poly_equal(tensor.mPolys[i], unpacked.mPolys[i]);
    }
}

void LogVole_RingOps_NonceBatchDeterminism(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mAdvanced.mProtocol.mUniformSampling = false;
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx, std::make_shared<RingContextFactory>(advanced, nullptr)));

    const std::vector<std::uint64_t> nonces{ 1, 2, 3, 4 };
    auto a = deriveUniformPolyBatchFromNonceList(ctx, nonces, 0xF00Du, 3u, 1u);
    auto b = deriveUniformPolyBatchFromNonceList(ctx, nonces, 0xF00Du, 3u, 1u);
    expect_batch_equal(a, b);

    std::vector<RnsPoly> c;
    LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromNonceListInplace(ctx, nonces, 0xF00Du, 3u, c, 1u));
    expect_batch_equal(a, c);

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool haveGpu = cmd.getOr("gpu", 0) != 0 && gpu::available();
    if (cmd.getOr("gpu", 0)) LOGVOLE_REQUIRE_TRUE(haveGpu);
#else
    const bool haveGpu = false;
#endif
    auto compareExact = [](const std::vector<RnsPoly>& expected, const std::vector<RnsPoly>& actual) {
        LOGVOLE_REQUIRE_EQ(actual.size(), expected.size());
        for (std::size_t i = 0; i < actual.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected[i].mCoeffs))
                << " sampled polynomial " << i;
    };
    auto checkSetupSampling = [&](const RingParams& ring) {
        RingNttContext sampleContext{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, sampleContext, std::make_shared<RingContextFactory>(advanced, nullptr)));
        constexpr std::uint64_t nonce = 0x534554555053414Dull, domain = 0x554E49464F524Dull;
        for (std::uint32_t count : { 1u, 4u, 32u })
        {
            if (cmd.getOr("lvFactoryFast", 0) && count == 32u) continue;
            std::vector<RnsPoly> expectedNonce, expectedNtt, expectedPrivate, expectedPublicB;
            oc::PRNG referencePrng(oc::block(0x53414D504C45ull, 7), 3);
            {
                for (std::uint32_t i = 0; i < count; ++i)
                {
                    expectedNonce.push_back(deriveUniformPolyFromNonce(sampleContext, nonce, domain, i));
                    expectedPrivate.push_back(sampleUniformPoly(sampleContext, referencePrng));
                }
                expectedNtt = expectedNonce;
                for (auto& poly : expectedNtt) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, sampleContext));
                for (std::uint32_t i = 0; i < 4; ++i)
                    expectedPublicB.push_back(deriveUniformPolyFromNonceNtt(
                        sampleContext, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }
            const auto nextReference = referencePrng.get<oc::block>();
            for (bool device : { false, true })
            {
                if (device && !haveGpu) continue;
                auto selectedOptions = advanced;
                selectedOptions.mUseGpu = haveGpu;
                selectedOptions.mAdvanced.mProtocol.mUniformSampling = device;
                selectedOptions.mAdvanced.mProtocol.mUniformSamplingStrict = true;
                RingNttContext selected;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, selected,
                    std::make_shared<RingContextFactory>(selectedOptions, nullptr)));

#if defined(ENABLE_LOGVOLE_CUDA)
                if (device) LOGVOLE_REQUIRE_TRUE(gpu::enabled(selected));
#endif
                compareExact(expectedNonce, deriveUniformPolyBatchFromNonce(selected, nonce, domain, count));
                // This established API's name is historical: its values are
                // coefficient-domain samples, not transformed polynomials.
                compareExact(expectedNonce, deriveUniformPolyBatchFromNonceNtt(selected, nonce, domain, count));
                compareExact(expectedNonce, deriveUniformPolyBatchFromNonce(selected, nonce, domain, count, false));
                compareExact(expectedNtt, deriveUniformPolyBatchFromNonce(selected, nonce, domain, count, true));
                oc::PRNG actualPrng(oc::block(0x53414D504C45ull, 7), 3);
                compareExact(expectedPrivate, sampleUniformPolyBatch(selected, count, actualPrng));
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                // Public B has actual NTT values, unlike the historical raw
                // BatchFromNonceNtt API. The direct explicit-transform call
                // above verifies device execution independently of this cache.
                compareExact(expectedPublicB, buildLencPublicBNtt(selected, 2));
            }
            if (haveGpu && count == 4)
            {
                tests_libOTe::logvole_test::ScopedOptionValue declineOption(advanced.mAdvanced.mProtocol.mFailures.mUniform, true);
                auto selectedOptions = advanced;
                selectedOptions.mUseGpu = haveGpu;
                selectedOptions.mAdvanced.mProtocol.mUniformSampling = true;
                RingNttContext fallback;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, fallback,
                    std::make_shared<RingContextFactory>(selectedOptions, nullptr)));
                oc::PRNG fallbackPrng(oc::block(0x53414D504C45ull, 7), 3);
                compareExact(expectedPrivate, sampleUniformPolyBatch(fallback, count, fallbackPrng));
                LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                compareExact(expectedNtt, deriveUniformPolyBatchFromNonce(fallback, nonce, domain, count, true));
                selectedOptions.mAdvanced.mProtocol.mUniformSamplingStrict = true;
                RingNttContext strict;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, strict,
                    std::make_shared<RingContextFactory>(selectedOptions, nullptr)));
                bool rejected = false;
                try { (void)deriveUniformPolyBatchFromNonce(strict, nonce, domain, count, true); }
                catch (const std::runtime_error&) { rejected = true; }
                LOGVOLE_REQUIRE_TRUE(rejected);
            }
        }
        oc::PRNG emptyPrng(oc::block(0x454D505459ull, 1), 3), emptyReference(oc::block(0x454D505459ull, 1), 3);
        LOGVOLE_REQUIRE_TRUE(sampleUniformPolyBatch(sampleContext, 0, emptyPrng).empty());
        LOGVOLE_EXPECT_EQ(emptyPrng.get<oc::block>(), emptyReference.get<oc::block>());
    };
    checkSetupSampling(params);
    RingParams production{};
    production.mPolyModulusDegree = 8192;
    assignValues<int>(production.mCoeffModulusBits, { 55, 55, 55, 55 });
    checkSetupSampling(production);
    production.mPolyModulusDegree = 16384;
    assignValues<int>(production.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    checkSetupSampling(production);
}

void LogVole_RingOps_PublicUniformRetentionParity(const oc::CLP& cmd)
{
    const auto identityService = ProtocolCacheService::create();
    tests_libOTe::logvole_test::SetupResources setupResources;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    // Exercise CPU cache construction before any GPU retention in this test.
    {
        RingParams params;
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(2);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), 30);
        RingNttContext context;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, context));
        const auto a = sharedLhePublicANtt(context, 4);
        const auto b = sharedLencPublicBNtt(context, 2);
        LOGVOLE_REQUIRE_TRUE(a && b && a->size() == 4 && b->size() == 4);
    }
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }

    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    advanced.mAdvanced.mProtocol.mUniformSamplingStrict = true;

    tests_libOTe::logvole_test::ScopedOptionValue lheDevice(setupOptions.mLheDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue lheStrict(setupOptions.mLheDeviceStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue compact(setupOptions.mCompactNoise, false);
    LOGVOLE_REQUIRE_TRUE(gpu::publicUniformRetentionEnabled(advanced, true));
    auto exact = [](const auto& a, const auto& b) {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(a[i].mCoeffs, b[i].mCoeffs)) << " polynomial " << i;
    };

    // Context copies share public operands. Exported host/device results keep
    // their own backing alive without retaining the cache or a context.
    {
        const ProtocolCacheScope role(identityService->allocate(), ProtocolCacheRole::Sender);
        std::weak_ptr<PublicPolynomialCache> lifetime;
        gpu::RetainedPublicUniformPtr deviceA, deviceB;
        std::shared_ptr<const std::vector<RnsPoly>> hostA, hostB;
        {
            RingParams params;
            params.mPolyModulusDegree = 1024;
            params.mCoeffModulusBits.resize(2);
            std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), 30);
            RingNttContext context;
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, context, std::make_shared<RingContextFactory>(advanced, identityService), role));
            LOGVOLE_REQUIRE_TRUE(context.mPublicCache);
            lifetime = context.mPublicCache;
            deviceA = retainedLhePublicANtt(context, 4, role);
            deviceB = retainedLencPublicBNtt(context, 2, role);
            hostA = sharedLhePublicANtt(context, 4, role);
            hostB = sharedLencPublicBNtt(context, 2, role);
            LOGVOLE_REQUIRE_TRUE(deviceA && deviceB && hostA && hostB);
            auto copy = context;
            context = {};
            LOGVOLE_REQUIRE_FALSE(lifetime.expired());
            LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(copy, 4, role) == hostA);
            LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(copy, 2, role) == hostB);
            copy = {};
        }
        LOGVOLE_REQUIRE_TRUE(lifetime.expired());
        std::vector<RnsPoly> fetched;
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*deviceA, fetched, readbackExecution.readbackStream(), role));
        exact(*hostA, fetched);
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*deviceB, fetched, readbackExecution.readbackStream(), role));
        exact(*hostB, fetched);
        const std::weak_ptr<const gpu::RetainedPublicUniform> deviceLifetimeA = deviceA;
        const std::weak_ptr<const gpu::RetainedPublicUniform> deviceLifetimeB = deviceB;
        deviceA.reset();
        deviceB.reset();
        // Live host snapshots cannot keep an expired context's index or its
        // device tokens alive after the explicit exports have been released.
        LOGVOLE_REQUIRE_TRUE(deviceLifetimeA.expired());
        LOGVOLE_REQUIRE_TRUE(deviceLifetimeB.expired());
    }

    for (const auto& shape : { std::pair{1024u, 2u}, {8192u, 4u}, {16384u, 8u} })
    {
        RingParams params;
        params.mPolyModulusDegree = shape.first;
        params.mCoeffModulusBits.resize(shape.second);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            shape.first == 1024u ? 30 : shape.first == 8192u ? 55 : 52);
        const auto run = identityService->allocate();
        const ProtocolCacheScope cacheScope(run, ProtocolCacheRole::Sender);
        // Dynamic GPU contexts carry a party-local certificate. Construct the
        // context in the same role that will sample from it.
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx, std::make_shared<RingContextFactory>(advanced, identityService), cacheScope));
        constexpr std::uint32_t count = 4;
        constexpr std::uint64_t nonce = 0x52455441494e4544ULL, domain = 0x5055424c4943ULL;

        for (bool actualNtt : {false, true})
        {
            std::vector<RnsPoly> expected;
            {
                auto cpuContext = cpuReferenceContext(ctx);
                expected = deriveUniformPolyBatchFromNonce(cpuContext, nonce, domain, count, actualNtt, cacheScope);
            }
            const auto before = gpu::publicUniformRetentionStats(ctx);
            gpu::RetainedPublicUniformPtr token;
            auto sampled = deriveUniformPolyBatchFromNonce(ctx, nonce, domain, count, actualNtt, &token, cacheScope);
            exact(expected, sampled);
            LOGVOLE_REQUIRE_TRUE(token && token->count() == count);
            LOGVOLE_REQUIRE_TRUE(gpu::publicUniformRetentionStats(ctx).mCaptures > before.mCaptures);
            auto owner = std::make_shared<const std::vector<RnsPoly>>(std::move(sampled));
            const std::span<const RnsPoly> span(*owner);
            LOGVOLE_REQUIRE_TRUE(gpu::registerPublicUniformRetention(ctx, owner, token, cacheScope));
            LOGVOLE_REQUIRE_TRUE(gpu::registerPublicUniformRetention(ctx, owner, token, cacheScope));
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span, cacheScope) == token);
            {
                auto shared = ctx;
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(shared, span, cacheScope) == token);
                const auto sharedStatsBefore = gpu::publicUniformRetentionStats(ctx);
                auto separate = ctx;
                separate.mPublicCache = std::make_shared<PublicPolynomialCache>();
                const auto isolatedBefore = gpu::publicUniformRetentionStats(separate);
                LOGVOLE_REQUIRE_EQ(isolatedBefore.mCaptures, 0u);
                LOGVOLE_REQUIRE_EQ(isolatedBefore.mMisses, 0u);
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(separate, span, cacheScope) == nullptr);
                LOGVOLE_REQUIRE_EQ(gpu::publicUniformRetentionStats(separate).mMisses, 1u);
                LOGVOLE_REQUIRE_EQ(gpu::publicUniformRetentionStats(ctx).mMisses, sharedStatsBefore.mMisses);
                LOGVOLE_REQUIRE_TRUE(gpu::registerPublicUniformRetention(separate, owner, token, cacheScope));
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(separate, span, cacheScope) == token);
                separate.mPublicCache.reset();
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(separate, span, cacheScope) == nullptr);
                LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(separate, owner, token, cacheScope));
            }
            std::vector<RnsPoly> fetched;
            LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*token, fetched, readbackExecution.readbackStream(), cacheScope));
            exact(expected, fetched);

            // Const ownership must originate from the captured allocations.
            // Merely copying the exact values never registers a mutable clone.
            auto copied = std::make_shared<const std::vector<RnsPoly>>(*owner);
            LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(ctx, copied, token, cacheScope));
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *copied, cacheScope) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span.first(count - 1), cacheScope) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span.subspan(1), cacheScope) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, {}, cacheScope) == nullptr);
            RingNttContext changed = ctx;
            swap_moduli_for_test(changed, 0, 1);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(changed, span, cacheScope) == nullptr);
            LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(changed, owner, token, cacheScope));
            changed = ctx;
            changed.mParams.mPolyModulusDegree *= 2;
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(changed, span, cacheScope) == nullptr);
            {
                const ProtocolCacheScope peer(run, ProtocolCacheRole::Receiver);
                // Party-local GPU caches and retained allocations must not be
                // visible through a peer role, even in this single-process test.
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span, peer) == nullptr);
                LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(ctx, owner, token, peer));
            }
            {
                const ProtocolCacheScope anotherRun(identityService->allocate(), ProtocolCacheRole::Sender);
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span, anotherRun) == nullptr);
                LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(ctx, owner, token, anotherRun));
            }
            {
                auto cpuContext = cpuReferenceContext(ctx);
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(cpuContext, span, cacheScope) == nullptr);
                auto capture = token;
                exact(expected, deriveUniformPolyBatchFromNonce(cpuContext, nonce, domain, count, actualNtt, &capture, cacheScope));
                LOGVOLE_REQUIRE_TRUE(capture == nullptr);
            }
            for (bool forcedDecline : {false, true})
            {
                tests_libOTe::logvole_test::ScopedOptionValue rollback(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mPublicRetain, (forcedDecline ? "1" : "0")[0] == '1');
                auto disabledOptions = advanced;
                disabledOptions.mAdvanced.mProtocol.mPublicUniformRetention = false;
                RingNttContext disabled;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, disabled,
                    std::make_shared<RingContextFactory>(disabledOptions, identityService), cacheScope));
                const auto& selected = forcedDecline ? ctx : disabled;
                LOGVOLE_REQUIRE_FALSE(gpu::publicUniformRetentionEnabled(selected.mExecutionOptions, gpu::enabled(selected)));
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(selected, span, cacheScope) == nullptr);
                auto capture = token;
                exact(expected, deriveUniformPolyBatchFromNonce(selected, nonce, domain, count, actualNtt, &capture, cacheScope));
                LOGVOLE_REQUIRE_TRUE(capture == nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span, cacheScope) == token);
            {
                auto capture = token;
                LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromNonce(
                    ctx, nonce, domain, 0, actualNtt, &capture, cacheScope).empty());
                LOGVOLE_REQUIRE_TRUE(capture == nullptr);
                std::vector<std::array<std::uint64_t, 8>> seeds(1);
                std::vector<RnsPoly> unchanged = expected;
                capture = token;
                tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mUniform, true);
                LOGVOLE_REQUIRE_FALSE(gpu::sampleUniformBatchFromSeedsDevice(
                    ctx, seeds, actualNtt, unchanged, &capture, cacheScope));
                exact(expected, unchanged);
                LOGVOLE_REQUIRE_TRUE(capture == token);
            }

            // Lookup must reject the saved span before touching freed host
            // storage; retaining the completed device owner remains safe.
            owner.reset();
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span, cacheScope) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*token, fetched, readbackExecution.readbackStream(), cacheScope));
            exact(expected, fetched);
        }

        // Production cache A is a legacy raw sample despite its Ntt name;
        // public B is actually transformed. Check both independent oracles.
        std::vector<RnsPoly> expectedA, expectedB;
        {
            auto cpuContext = cpuReferenceContext(ctx);
            expectedA = deriveUniformPolyBatchFromNonce(cpuContext, 0xA11ACE5Eull, 0xA110CA7Aull, count, cacheScope);
            expectedB = deriveUniformPolyBatchFromNonce(cpuContext, 0xC0DEC0DEull, 0x1EEC0DEu, count, true, cacheScope);
        }
        const auto beforeRetainOnly = gpu::publicUniformRetentionStats(ctx);
        const auto deviceA = retainedLhePublicANtt(ctx, count, cacheScope);
        const auto deviceB = retainedLencPublicBNtt(ctx, count / 2, cacheScope);
        const auto afterRetainOnly = gpu::publicUniformRetentionStats(ctx);
        LOGVOLE_REQUIRE_TRUE(deviceA && deviceB && deviceA != deviceB);
        LOGVOLE_REQUIRE_TRUE(gpu::retainedPublicUniformMatches(ctx, *deviceA, count, false, cacheScope));
        LOGVOLE_REQUIRE_TRUE(gpu::retainedPublicUniformMatches(ctx, *deviceB, count, true, cacheScope));
        LOGVOLE_REQUIRE_EQ(afterRetainOnly.mHostMaterializations,
            beforeRetainOnly.mHostMaterializations);
        std::shared_ptr<const std::vector<RnsPoly>> materializedA, materializedB;
        LOGVOLE_REQUIRE_TRUE(gpu::materializeRetainedPublicUniform(ctx, deviceA, materializedA, cacheScope));
        LOGVOLE_REQUIRE_TRUE(gpu::materializeRetainedPublicUniform(ctx, deviceB, materializedB, cacheScope));
        exact(expectedA, *materializedA);
        exact(expectedB, *materializedB);
        const auto afterMaterialize = gpu::publicUniformRetentionStats(ctx);
        LOGVOLE_REQUIRE_EQ(afterMaterialize.mHostMaterializations,
            afterRetainOnly.mHostMaterializations + 2u);
        auto sameA = materializedB;
        LOGVOLE_REQUIRE_TRUE(gpu::materializeRetainedPublicUniform(ctx, deviceA, sameA, cacheScope));
        LOGVOLE_REQUIRE_TRUE(sameA == materializedA);
        LOGVOLE_REQUIRE_EQ(gpu::publicUniformRetentionStats(ctx).mHostMaterializations,
            afterMaterialize.mHostMaterializations);
        {
            const ProtocolCacheScope peer(run, ProtocolCacheRole::Receiver);
            auto unchanged = materializedB;
            LOGVOLE_REQUIRE_FALSE(gpu::materializeRetainedPublicUniform(ctx, deviceA, unchanged, peer));
            LOGVOLE_REQUIRE_TRUE(unchanged == materializedB);
        }
        const auto publicA = sharedLhePublicANtt(ctx, count, cacheScope);
        const auto publicB = sharedLencPublicBNtt(ctx, count / 2, cacheScope);
        LOGVOLE_REQUIRE_TRUE(publicA && publicB);
        exact(expectedA, *publicA);
        exact(expectedB, *publicB);
        const auto retainedA = gpu::findPublicUniformRetention(ctx, *publicA, cacheScope);
        const auto retainedB = gpu::findPublicUniformRetention(ctx, *publicB, cacheScope);
        LOGVOLE_REQUIRE_TRUE(retainedA && retainedB && retainedA != retainedB);
        std::vector<RnsPoly> downloaded;
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*retainedA, downloaded, readbackExecution.readbackStream(), cacheScope));
        exact(expectedA, downloaded);
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*retainedB, downloaded, readbackExecution.readbackStream(), cacheScope));
        exact(expectedB, downloaded);
        LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(ctx, count, cacheScope) == publicA);
        LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(ctx, count / 2, cacheScope) == publicB);

        auto mutableA = *publicA;
        mutableA[0].mCoeffs[0] = (mutableA[0].mCoeffs[0] + 1) % ringModulusValue(ctx, 0);
        LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, mutableA, cacheScope) == nullptr);
        auto r = expectedA;
        const std::vector<RnsPoly> sk{expectedA.front()};
        for (const auto* a : {publicA.get(), static_cast<const std::vector<RnsPoly>*>(&mutableA)})
        {
            const oc::block seed(0x5055424c4845ULL, shape.first);
            oc::PRNG referencePrng(seed, 3), actualPrng(seed, 3);
            RingTensor expected, actual;
            {
                auto cpuContext = cpuReferenceContext(ctx);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheEnc1(setupResources.executor, setupResources.results, cpuContext, r, sk, 8, expected, 3.2, 19.2,
                    &referencePrng, false, a, 4, nullptr,  {}, setupOptions, {}, cacheScope)));
            }
            const auto before = gpu::publicUniformRetentionStats(ctx);
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheEnc1(setupResources.executor, setupResources.results, ctx, r, sk, 8, actual, 3.2, 19.2,
                &actualPrng, false, a, 4, nullptr,  {}, setupOptions, {}, cacheScope)));
            const auto after = gpu::publicUniformRetentionStats(ctx);
            LOGVOLE_REQUIRE_EQ(expected.mRows, actual.mRows);
            LOGVOLE_REQUIRE_EQ(expected.mCols, actual.mCols);
            exact(expected.mPolys, actual.mPolys);
            LOGVOLE_REQUIRE_EQ(referencePrng.get<oc::block>(), actualPrng.get<oc::block>());
            if (a == publicA.get())
            {
                LOGVOLE_REQUIRE_TRUE(after.mCopies > before.mCopies);
                LOGVOLE_REQUIRE_TRUE(after.mCopiedBytes >= before.mCopiedBytes + count * ringPolyCoeffCount(params) * sizeof(std::uint64_t));
            }
            else LOGVOLE_REQUIRE_EQ(after.mCopies, before.mCopies);
        }
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*retainedA, downloaded, readbackExecution.readbackStream(), cacheScope));
        exact(expectedA, downloaded);
        exact(expectedA, *publicA);
        exact(expectedB, *publicB);
        if (shape.first == 1024u)
        {
            std::weak_ptr<const std::vector<RnsPoly>> oldA, oldB;
            {
                const ProtocolCacheScope secondRun(identityService->allocate(), ProtocolCacheRole::Sender);
                const auto temporaryA = sharedLhePublicANtt(ctx, count, secondRun);
                const auto temporaryB = sharedLencPublicBNtt(ctx, count / 2, secondRun);
                oldA = temporaryA;
                oldB = temporaryB;
                LOGVOLE_REQUIRE_TRUE(temporaryA != publicA && temporaryB != publicB);
                exact(expectedA, *temporaryA);
                exact(expectedB, *temporaryB);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicA, cacheScope) == retainedA);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicB, cacheScope) == retainedB);
            {
                const ProtocolCacheScope thirdRun(identityService->allocate(), ProtocolCacheRole::Sender);
                LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(ctx, count, thirdRun) != nullptr);
                LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(ctx, count / 2, thirdRun) != nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(oldA.expired() && oldB.expired());
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicA, cacheScope) == retainedA);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicB, cacheScope) == retainedB);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_GaussianPrefixBatchParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool testGpuAvailable = gpu::available();
#endif

    tests_libOTe::logvole_test::SetupResources setupResources;
    osuCrypto::LogVoleExecutionOptions testAdvanced;
    tests_libOTe::logvole_test::ScopedOptionValue originalTransform(testAdvanced.mAdvanced.mProtocol.mGaussianTransform, false);
#if defined(ENABLE_LOGVOLE_CUDA)
    testAdvanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
    const bool haveGpu = (testAdvanced.mUseGpu && testGpuAvailable);
    if (testAdvanced.mUseGpu) LOGVOLE_REQUIRE_TRUE(haveGpu);
    if (haveGpu)
    {

        std::array<seal::prng_seed_type, 1> seeds{};
        seeds[0][0] = 0x50494E4E45445052ull;
        gpu::GpuExecutionContext execution;
        auto& stream = execution.sampleStream();
        gpu::GaussianPrngPrefixBuffer first, second;
        LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianPrngPrefixesDevice(stream, seeds, 512, first, testAdvanced.mAdvanced.mProtocol.mFailures));
        LOGVOLE_REQUIRE_TRUE(first.mData != nullptr);
        LOGVOLE_REQUIRE_EQ(first.mWords, std::size_t(512));
        const std::vector<std::uint64_t> saved(first.mData.get(), first.mData.get() + first.mWords);
        seeds[0][1] = 0x5345434F4E44ull;
        LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianPrngPrefixesDevice(stream, seeds, 512, second, testAdvanced.mAdvanced.mProtocol.mFailures));
        LOGVOLE_REQUIRE_TRUE(second.mData != nullptr);
        LOGVOLE_REQUIRE_TRUE(first.mData.get() != second.mData.get());
        LOGVOLE_REQUIRE_TRUE(std::equal(saved.begin(), saved.end(), first.mData.get()));
        // Pinned output survives its worker's execution context and OS thread.
        std::weak_ptr<gpu::OwnedGpuStream> producer;
        std::packaged_task<gpu::GaussianPrngPrefixBuffer()> task([&] {
            gpu::GpuExecutionContext workerExecution;
            auto& workerStream = workerExecution.sampleStream();
            auto workerSeeds = seeds;
            workerSeeds[0][1] = 0;
            gpu::GaussianPrngPrefixBuffer exported, grown;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianPrngPrefixesDevice(workerStream, workerSeeds, 512, exported, testAdvanced.mAdvanced.mProtocol.mFailures));
            producer = workerStream.allocationOwner();
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianPrngPrefixesDevice(workerStream, seeds, 1024, grown, testAdvanced.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_TRUE(exported.mData.get() != grown.mData.get());
            LOGVOLE_REQUIRE_TRUE(std::equal(saved.begin(), saved.end(), exported.mData.get()));
            return exported;
        });
        auto future = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        auto exported = future.get();
        LOGVOLE_REQUIRE_TRUE(producer.expired());
        LOGVOLE_REQUIRE_EQ(exported.mWords, saved.size());
        LOGVOLE_REQUIRE_TRUE(std::equal(saved.begin(), saved.end(), exported.mData.get()));
        exported = {};
        const auto previous = second.mData;
        const auto previousWords = second.mWords;
        tests_libOTe::logvole_test::ScopedOptionValue forceDecline(testAdvanced.mAdvanced.mProtocol.mFailures.mGaussianPrg, true);
        LOGVOLE_REQUIRE_TRUE(!gpu::sampleGaussianPrngPrefixesDevice(stream, seeds, 512, second, testAdvanced.mAdvanced.mProtocol.mFailures));
        LOGVOLE_REQUIRE_TRUE(second.mData == previous);
        LOGVOLE_REQUIRE_EQ(second.mWords, previousWords);
        LOGVOLE_REQUIRE_TRUE(std::equal(saved.begin(), saved.end(), first.mData.get()));
    }
#else
    const bool haveGpu = false;
#endif
    constexpr std::uint64_t sentinel = 0xBADC0FFEE0DDF00Dull;
    auto checkCase = [&](RingNttContext ctx, std::uint32_t count,
                         double sigma, double clip, const std::vector<std::uint8_t>& active) {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        std::vector<std::uint64_t> expected(count * n + 2, sentinel);
        std::vector<seal::prng_seed_type> seeds(count), referenceSeeds(count);
        oc::PRNG referenceParent(oc::block(0x4741555353505247ull, 19), 3);
        oc::PRNG batchParent(oc::block(0x4741555353505247ull, 19), 3);
        // The caller draws parent seeds only for active rows. Scalar sampling
        // between these draws must agree with preparing the complete seed list.
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!active.empty() && !active[i]) continue;
            referenceParent.get(referenceSeeds[i].data(), referenceSeeds[i].size());
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                std::span<std::uint64_t>(expected).subspan(1 + i * n, n),
                sigma, clip, referenceSeeds[i], ctx));
        }
        for (std::size_t i = 0; i < count; ++i)
            if (active.empty() || active[i]) batchParent.get(seeds[i].data(), seeds[i].size());
        LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);
        const auto nextParent = referenceParent.get<oc::block>();

        for (bool device : { false, true })
        {
            if (device && !haveGpu) continue;
            tests_libOTe::logvole_test::ScopedOptionValue enabled(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrg, (device));
            tests_libOTe::logvole_test::ScopedOptionValue strict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgStrict, true);
            tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianPrg, false);
            // One prefix block cannot supply even N=1024 normal samples; this
            // checks exact continuation after the GPU-generated prefix ends.
            for (const char* prefix : { "0", "1" })
            {
                if (!device && prefix[0] == '1') continue;
                tests_libOTe::logvole_test::ScopedOptionValue blocks(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgPrefixBlocks, static_cast<std::uint64_t>(std::strtoull(prefix, nullptr, 10)));
                std::vector<std::uint64_t> actual(expected.size(), sentinel);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
                    std::span<std::uint64_t>(actual).subspan(1, count * n),
                    sigma, clip, seeds, ctx, 3, active)));
                LOGVOLE_REQUIRE_TRUE(actual == expected)
                    << " N=" << n << " count=" << count << " sigma=" << sigma
                    << " GPU=" << device << " prefix=" << prefix;
                LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);
            }
        }
        LOGVOLE_EXPECT_EQ(batchParent.get<oc::block>(), nextParent);

        if (haveGpu && count == 4 && sigma > 0)
        {
            tests_libOTe::logvole_test::ScopedOptionValue enabled(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrg, true);
            tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianPrg, true);
            tests_libOTe::logvole_test::ScopedOptionValue strict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgStrict, false);
            std::vector<std::uint64_t> replay(expected.size(), sentinel);
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
                std::span<std::uint64_t>(replay).subspan(1, count * n),
                sigma, clip, seeds, ctx, 3, active)));
            LOGVOLE_REQUIRE_TRUE(replay == expected);
            tests_libOTe::logvole_test::ScopedOptionValue reject(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgStrict, true);
            std::vector<std::uint64_t> rejected(expected.size(), sentinel);
            LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
                std::span<std::uint64_t>(rejected).subspan(1, count * n),
                sigma, clip, seeds, ctx, 3, active)));
            LOGVOLE_REQUIRE_TRUE(std::all_of(rejected.begin(), rejected.end(),
                [&](std::uint64_t value) { return value == sentinel; }));
        }
    };

    for (std::uint32_t n : { 1024u, 8192u, 16384u })
    {
        RingParams params{};
        params.mPolyModulusDegree = n;
        params.mCoeffModulusBits.resize(n == 1024 ? 2 : n == 8192 ? 4 : 8);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            n == 1024 ? 30 : n == 8192 ? 55 : 52);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx,
            std::make_shared<RingContextFactory>(testAdvanced, nullptr)));
        for (std::uint32_t count : { 1u, 4u, 32u }) checkCase(ctx, count, 3.2, 19.2, {});
        checkCase(ctx, 4, 0.0, 19.2, {});
        checkCase(ctx, 4, 3.2, 19.2, { 1, 0, 2, 0 });
        if (n == 1024)
        {
            // Tight rejection clipping consumes substantially more randomness
            // than the prefix heuristic; the scalar stream must still match.
            checkCase(ctx, 1, 3.2, 0.125, {});
            auto cpuContext = cpuReferenceContext(ctx);
            tests_libOTe::logvole_test::ScopedOptionValue enabled(cpuContext.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrg, true);
            tests_libOTe::logvole_test::ScopedOptionValue strict(cpuContext.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgStrict, true);
            tests_libOTe::logvole_test::ScopedOptionValue decline(cpuContext.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianPrg, true);
            const std::vector<seal::prng_seed_type> seeds(2);
            std::vector<std::uint64_t> actual(2 * n, sentinel), expected(2 * n, sentinel);
            for (std::size_t i = 0; i < seeds.size(); ++i)
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                    std::span<std::uint64_t>(expected).subspan(i * n, n), 3.2, 19.2, seeds[i], cpuContext));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results, actual, 3.2, 19.2, seeds, cpuContext, 2)));
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }

        const std::vector<seal::prng_seed_type> seeds(4);
        std::vector<std::uint64_t> untouched(4 * n, sentinel);
        const auto initial = untouched;
        const std::array<std::uint8_t, 4> inactive{ 0, 0, 0, 0 };
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results, untouched, 3.2, 19.2, seeds, ctx, 3, inactive)));
        LOGVOLE_REQUIRE_TRUE(untouched == initial);
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results, {}, 3.2, 19.2, {}, ctx)));
        LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
            std::span<std::uint64_t>(untouched).subspan(1), 3.2, 19.2, seeds, ctx)));
        LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
            untouched, 3.2, 19.2, seeds, ctx, 3, std::span<const std::uint8_t>(inactive).first(3))));
        LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
            untouched, 3.2, std::numeric_limits<double>::infinity(), seeds, ctx)));
        LOGVOLE_REQUIRE_TRUE(untouched == initial);
    }
}

void LogVole_RingOps_GaussianHostCompatibility(const oc::CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    struct RestoreRounding
    {
        int mode = std::fegetround();
        ~RestoreRounding() { std::fesetround(mode); }
    } restore;
    LOGVOLE_REQUIRE_EQ(std::fesetround(FE_TONEAREST), 0);
    gpu::GaussianHostCompatibility baseline;
    const bool expected = baseline.compatible();
    LOGVOLE_REQUIRE_EQ(baseline.compatible(), expected);

    LOGVOLE_REQUIRE_EQ(std::fesetround(FE_UPWARD), 0);
    gpu::GaussianHostCompatibility initiallyDeclined;
    LOGVOLE_REQUIRE_TRUE(!initiallyDeclined.compatible());
    LOGVOLE_REQUIRE_TRUE(!baseline.compatible());
    LOGVOLE_REQUIRE_EQ(std::fesetround(FE_TONEAREST), 0);
    LOGVOLE_REQUIRE_EQ(initiallyDeclined.compatible(), expected);
    LOGVOLE_REQUIRE_EQ(baseline.compatible(), expected);

#if defined(__linux__) && defined(__x86_64__)
    struct RestoreMxcsr
    {
        unsigned mode = _mm_getcsr();
        ~RestoreMxcsr() { _mm_setcsr(mode); }
    } mxcsr;
    for (unsigned mode : {0x8000u, 0x40u})
    {
        _mm_setcsr(mxcsr.mode | mode);
        gpu::GaussianHostCompatibility declined;
        LOGVOLE_REQUIRE_TRUE(!declined.compatible());
        LOGVOLE_REQUIRE_TRUE(!baseline.compatible());
        _mm_setcsr(mxcsr.mode);
        LOGVOLE_REQUIRE_EQ(declined.compatible(), expected);
        LOGVOLE_REQUIRE_EQ(baseline.compatible(), expected);
    }
#endif

    gpu::GaussianHostCompatibility concurrent;
    std::array<bool, 4> results{};
    std::array<std::thread, 4> workers;
    for (std::size_t i = 0; i < workers.size(); ++i)
        workers[i] = std::thread([&, i] { results[i] = concurrent.compatible(); });
    for (auto& worker : workers) worker.join();
    for (bool result : results) LOGVOLE_REQUIRE_EQ(result, expected);
#else
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_RingOps_GaussianTransformBatchParity(const oc::CLP& cmd)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    osuCrypto::LogVoleExecutionOptions testAdvanced;
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    testAdvanced.mUseGpu = requested;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    gpu::GaussianHostCompatibility gaussianCompatibility;
    if (!gaussianCompatibility.compatible())
    {
        LOGVOLE_SKIP() << "requires recognized CPU compiler/libm arithmetic";
        return;
    }
    tests_libOTe::logvole_test::ScopedOptionValue transform(testAdvanced.mAdvanced.mProtocol.mGaussianTransform, true);
    tests_libOTe::logvole_test::ScopedOptionValue strict(testAdvanced.mAdvanced.mProtocol.mGaussianTransformStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue prefix(testAdvanced.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, std::uint64_t{0});
    tests_libOTe::logvole_test::ScopedOptionValue originalPrg(testAdvanced.mAdvanced.mProtocol.mGaussianPrg, false);
    tests_libOTe::logvole_test::ScopedOptionValue originalPrgStrict(testAdvanced.mAdvanced.mProtocol.mGaussianPrgStrict, false);
    constexpr std::uint64_t marker = 0xdeadbadc0ffef00dULL;

    for (const auto shape : {0, 1, 2})
    {
        RingParams params = make_small_params();
        if (shape == 1)
        {
            params.mPolyModulusDegree = 8192;
            assignValues<int>(params.mCoeffModulusBits, {55, 55, 55, 55});
        }
        if (shape == 2)
        {
            params.mPolyModulusDegree = 16384;
            assignValues<int>(params.mCoeffModulusBits, {52, 52, 52, 52, 52, 52, 52, 52});
        }
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx,
            std::make_shared<RingContextFactory>(testAdvanced, nullptr)));
        const std::size_t n = params.mPolyModulusDegree;
        for (std::uint32_t count : {1, 4, 32})
        for (double sigma : {0.0, 3.2})
        {
            const std::vector<std::uint8_t> active = count == 4
                ? std::vector<std::uint8_t>{1, 0, 2, 0} : std::vector<std::uint8_t>{};
            std::vector<seal::prng_seed_type> seeds(count), referenceSeeds(count);
            std::vector<std::uint64_t> expected(count * n + 2, marker);
            oc::PRNG parent(oc::block(0x4558414354474155ULL, count), 3);
            oc::PRNG referenceParent(oc::block(0x4558414354474155ULL, count), 3);
            for (std::size_t row = 0; row < count; ++row)
            {
                if (!active.empty() && !active[row]) continue;
                referenceParent.get(referenceSeeds[row].data(), referenceSeeds[row].size());
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                    std::span<std::uint64_t>(expected).subspan(1 + row * n, n),
                    sigma, 19.2, referenceSeeds[row], ctx));
                parent.get(seeds[row].data(), seeds[row].size());
            }
            LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);
            for (const char* blocks : {"0", "1"})
            {
                tests_libOTe::logvole_test::ScopedOptionValue finitePrefix(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, static_cast<std::uint64_t>(std::strtoull(blocks, nullptr, 10)));
                std::vector<std::uint64_t> actual(expected.size(), marker);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
                    std::span<std::uint64_t>(actual).subspan(1, count * n),
                    sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(actual == expected)
                    << "N=" << n << " count=" << count << " sigma=" << sigma << " prefix=" << blocks;
            }
            LOGVOLE_EXPECT_EQ(parent.get<oc::block>(), referenceParent.get<oc::block>());
            LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);

            gpu::GaussianSampleBuffer direct;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactDevice(gpu::contextSampleStream(ctx), seeds, static_cast<std::uint32_t>(n), sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_EQ(direct.mValues.mWords, count * n);
            for (std::size_t row = 0; row < count; ++row)
            {
                LOGVOLE_REQUIRE_TRUE(direct.mComplete[row]);
                if (!active.empty() && !active[row]) continue;
                LOGVOLE_REQUIRE_TRUE(std::equal(expected.begin() + 1 + row * n,
                    expected.begin() + 1 + (row + 1) * n, direct.mValues.mData.get() + row * n));
            }
            if (count == 4 && sigma > 0)
            {
                const auto retained = direct.mValues.mData;
                const std::vector<std::uint64_t> snapshot(retained.get(), retained.get() + count * n);
                const auto flags = direct.mComplete;
                gpu::GaussianSampleBuffer incomplete;
                LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactDevice(gpu::contextSampleStream(ctx), seeds, static_cast<std::uint32_t>(n),
                    sigma, 19.2, ringModulusValue(ctx, 0), incomplete, 512, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
                LOGVOLE_REQUIRE_TRUE(incomplete.mValues.mData != retained);
                LOGVOLE_REQUIRE_TRUE(std::all_of(incomplete.mComplete.begin(), incomplete.mComplete.end(),
                    [](auto complete) { return complete == 0; }));
                LOGVOLE_REQUIRE_TRUE(std::equal(snapshot.begin(), snapshot.end(), retained.get()));
                tests_libOTe::logvole_test::ScopedOptionValue forced(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianTransform, true);
                LOGVOLE_REQUIRE_TRUE(!gpu::sampleGaussianCompactDevice(gpu::contextSampleStream(ctx), seeds, static_cast<std::uint32_t>(n),
                    sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
                LOGVOLE_REQUIRE_TRUE(direct.mValues.mData == retained && direct.mComplete == flags);
                std::vector<std::uint64_t> fallback(expected.size(), marker);
                LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
                    std::span<std::uint64_t>(fallback).subspan(1, count * n), sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(std::all_of(fallback.begin(), fallback.end(), [](auto x) { return x == marker; }));
                tests_libOTe::logvole_test::ScopedOptionValue allowReplay(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformStrict, false);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchFromSeeds(setupResources.executor, setupResources.results,
                    std::span<std::uint64_t>(fallback).subspan(1, count * n), sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(fallback == expected);
            }
        }
    }
    {
        struct RestoreRounding { int mode = std::fegetround(); ~RestoreRounding() { std::fesetround(mode); } } rounding;
        LOGVOLE_REQUIRE_EQ(std::fesetround(FE_UPWARD), 0);
        LOGVOLE_REQUIRE_TRUE(!gaussianCompatibility.compatible());
    }
#else
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_RingOps_GaussianResidentBatchParity(const oc::CLP& cmd)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    osuCrypto::LogVoleExecutionOptions testAdvanced;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    testAdvanced.mUseGpu = requested;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    gpu::GaussianHostCompatibility gaussianCompatibility;
    if (!cmd.getOr("settings_only", 0) && !gaussianCompatibility.compatible())
    {
        LOGVOLE_SKIP() << "requires recognized CPU compiler/libm arithmetic";
        return;
    }
    tests_libOTe::logvole_test::ScopedOptionValue resident(testAdvanced.mAdvanced.mProtocol.mGaussianResident, true);
    tests_libOTe::logvole_test::ScopedOptionValue residentStrict(testAdvanced.mAdvanced.mProtocol.mGaussianResidentStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue transform(testAdvanced.mAdvanced.mProtocol.mGaussianTransform, true);
    tests_libOTe::logvole_test::ScopedOptionValue transformStrict(testAdvanced.mAdvanced.mProtocol.mGaussianTransformStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue prefix(testAdvanced.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, std::uint64_t{0});
    constexpr std::uint64_t marker = 0x5a5afedcba987654ULL;

    for (std::uint32_t degree : {1024u, 8192u, 16384u})
    {
        RingParams params = make_small_params();
        params.mPolyModulusDegree = degree;
        params.mCoeffModulusBits.resize(degree == 16384u ? 8u : degree == 8192u ? 4u : 2u);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            degree == 16384u ? 52 : degree == 8192u ? 55 : 30);
        RingNttContext ctx;
        auto advanced = testAdvanced;
        advanced.mAdvanced.mStreams.mDownloadSlotMiB = 1;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx,
            std::make_shared<RingContextFactory>(advanced, nullptr)));
        if (degree != 8192u)
        {
            // Check the expansion independently of the Gaussian generator,
            // including the centered sign boundary and a resident prefix.
            const std::uint32_t count = degree == 1024u ? 3u : 17u;
            const std::uint64_t q0 = ringModulusValue(ctx, 0);
            const std::array<std::uint64_t, 5> values{0u, 1u, q0 / 2u, q0 / 2u + 1u, q0 - 1u};
            for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                LOGVOLE_REQUIRE_TRUE(q0 / 2u < ringModulusValue(ctx, limb));
            std::vector<std::uint64_t> compactValues(std::size_t(count + 2u) * degree);
            for (std::size_t i = 0; i < compactValues.size(); ++i)
                compactValues[i] = values[(i + i / degree) % values.size()];
            const auto originalCompact = compactValues;
            auto device = gpu::uploadScalars(compactValues, operationExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(device != nullptr && gpu::waitScalars(*device));
            std::vector<RnsPoly> coefficients(count);
            for (std::size_t row = 0; row < count; ++row)
            {
                coefficients[row].mCoeffs.resize(ringPolyCoeffCount(params));
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                for (std::size_t column = 0; column < degree; ++column)
                {
                    const auto value = compactValues[row * degree + column];
                    coefficients[row].mCoeffs[limb * degree + column] = value <= q0 / 2u
                        ? value : ringModulusValue(ctx, limb) - (q0 - value);
                }
            }
            for (bool outputNtt : {false, true})
            {
                auto expected = coefficients;
                if (outputNtt)
                {
                    auto cpuContext = cpuReferenceContext(ctx);
                    for (auto& poly : expected) LOGVOLE_REQUIRE_TRUE(forwardNttCanonical(poly, cpuContext));
                }
                const auto checkExpansion = [&](std::uint32_t workers, bool direct, bool pipeline) {
                    auto selectedOptions = advanced;
                    selectedOptions.mAdvanced.mProtocol.mCompactExpandDirect = direct;
                    selectedOptions.mAdvanced.mProtocol.mCompactPipelinedDownload = pipeline;
                    RingNttContext selected;
                    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, selected,
                        std::make_shared<RingContextFactory>(selectedOptions, nullptr)));
                    std::vector<RnsPoly> hostOutput, residentOutput;
                    LOGVOLE_REQUIRE_TRUE(gpu::expandErrorCompactDevice(selected,
                        std::span<const std::uint64_t>(compactValues).first(std::size_t(count) * degree),
                        outputNtt, hostOutput, workers));
                    LOGVOLE_REQUIRE_TRUE(gpu::expandErrorCompactDevice(selected,
                        *device, outputNtt, residentOutput, count, workers));
                    LOGVOLE_REQUIRE_EQ(hostOutput.size(), expected.size());
                    LOGVOLE_REQUIRE_EQ(residentOutput.size(), expected.size());
                    for (std::size_t row = 0; row < expected.size(); ++row)
                    {
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(hostOutput[row].mCoeffs, expected[row].mCoeffs));
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(residentOutput[row].mCoeffs, expected[row].mCoeffs));
                    }
                };
                for (const char* direct : {"0", "1"})
                {
                    checkExpansion(1u, direct[0] == '1', false);
                }
                if (degree == 16384u && outputNtt)
                {
                    for (const char* pipelineValue : {"0", "1"})
                    for (std::uint32_t workers : {1u, 4u})
                    {
                        checkExpansion(workers, true, pipelineValue[0] == '1');
                    }
                }
            }
            LOGVOLE_REQUIRE_TRUE(compactValues == originalCompact);
            std::vector<std::uint64_t> fetched(compactValues.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(fetched == originalCompact);
            std::vector<RnsPoly> rejected = coefficients;
            const auto* storage = rejected.data();
            LOGVOLE_REQUIRE_FALSE(gpu::expandErrorCompactDevice(ctx, *device, false, rejected, count + 3u, 4u));
            LOGVOLE_REQUIRE_TRUE(rejected.data() == storage);
            for (std::size_t row = 0; row < coefficients.size(); ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(rejected[row].mCoeffs, coefficients[row].mCoeffs));
        }
        if (cmd.getOr("settings_only", 0)) continue;
        for (std::uint32_t count : {1u, 4u, 32u})
        for (double sigma : {0.0, 3.2})
        {
            const std::size_t words = static_cast<std::size_t>(count) * degree;
            const std::vector<std::uint8_t> active = count == 4u
                ? std::vector<std::uint8_t>{1u, 0u, 2u, 0u} : std::vector<std::uint8_t>{};
            oc::PRNG parent(oc::block(0x5245534944454e54ULL, count), 3);
            oc::PRNG referenceParent(oc::block(0x5245534944454e54ULL, count), 3);
            std::vector<seal::prng_seed_type> seeds(count), expectedSeeds(count);
            std::vector<std::uint64_t> expected(words, 0);
            for (std::size_t row = 0; row < count; ++row)
            {
                if (!active.empty() && !active[row]) continue;
                parent.get(seeds[row].data(), seeds[row].size());
                referenceParent.get(expectedSeeds[row].data(), expectedSeeds[row].size());
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                    std::span<std::uint64_t>(expected).subspan(row * degree, degree),
                    sigma, 19.2, expectedSeeds[row], ctx));
            }
            const auto unchangedSeeds = seeds;
            LOGVOLE_REQUIRE_TRUE(seeds == expectedSeeds);
            gpu::GaussianDeviceSampleBuffer direct;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, active, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_TRUE(direct.mValues != nullptr);
            LOGVOLE_REQUIRE_EQ(direct.mValues->count(), words);
            LOGVOLE_REQUIRE_EQ(direct.mComplete.size(), count);
            LOGVOLE_REQUIRE_TRUE(std::all_of(direct.mComplete.begin(), direct.mComplete.end(),
                [](auto complete) { return complete == 1u; }));
            std::vector<std::uint64_t> fetched(words, marker);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*direct.mValues, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
            const auto retained = direct.mValues;
            const auto retainedFlags = direct.mComplete;

            for (const char* blocks : {"0", "1"})
            {
                // Prefix1 must repair active positive-noise rows from their
                // original seeds and publish a completed device result.
                tests_libOTe::logvole_test::ScopedOptionValue finitePrefix(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, static_cast<std::uint64_t>(std::strtoull(blocks, nullptr, 10)));
                std::vector<std::uint64_t> host{marker};
                gpu::DeviceScalarsPtr device;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(host.empty() && device != nullptr);
                LOGVOLE_REQUIRE_EQ(device->count(), words);
                LOGVOLE_REQUIRE_TRUE(device != retained);
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched, readbackExecution.readbackStream()));
                LOGVOLE_REQUIRE_TRUE(fetched == expected);
                const auto materializedOwner = device;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(materializePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == materializedOwner);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
            LOGVOLE_REQUIRE_TRUE(seeds == unchangedSeeds);
            for (unsigned i = 0; i < 8u; ++i)
                LOGVOLE_EXPECT_EQ(parent.get<std::uint64_t>(), referenceParent.get<std::uint64_t>());

            if (count != 4u || sigma == 0.0) continue;
            gpu::GaussianDeviceSampleBuffer incomplete;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), incomplete, 512, active, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_TRUE(incomplete.mValues != retained);
            LOGVOLE_REQUIRE_EQ(incomplete.mComplete.size(), active.size());
            for (std::size_t row = 0; row < active.size(); ++row)
                LOGVOLE_EXPECT_EQ(incomplete.mComplete[row], active[row] ? 0u : 1u);

            std::vector<std::uint64_t> host{marker};
            gpu::DeviceScalarsPtr device = retained;
            {
                tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, true);
                LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, active, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
                LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
                tests_libOTe::logvole_test::ScopedOptionValue allowReplay(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, false);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == nullptr);
            }
            {
                // Explicit rollback and disabled GPU selection both retain
                // exact host output despite resident strict mode.
                tests_libOTe::logvole_test::ScopedOptionValue rollback(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResident, false);
                host.assign(1, marker);
                device = retained;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 1, active)));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == nullptr);
            }
            {
                auto cpuContext = cpuReferenceContext(ctx);
                host.assign(1, marker);
                device = retained;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, cpuContext, 1, active)));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == nullptr);
            }
            host.assign(1, marker);
            device = retained;
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results, host, device, sigma, 19.2,
                seeds, ctx, 4, std::span<const std::uint8_t>(active).first(3))));
            LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                host, device, sigma, std::numeric_limits<double>::infinity(), seeds, ctx, 4, active)));
            LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            {
                tests_libOTe::logvole_test::ScopedOptionValue incompatibleSelection(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransform, false);
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            }
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(materializePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results, host, device,
                sigma, 19.2, std::span<const seal::prng_seed_type>(seeds).first(3), ctx)));
            LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            {
                // An absent device result can be materialized by exact seeded
                // CPU replay without changing any retained device owner.
                gpu::DeviceScalarsPtr absent;
                std::vector<std::uint64_t> replayHost{marker};
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(materializePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    replayHost, absent, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(replayHost == expected && absent == nullptr);
            }
            {
                // A completed device owner remains valid across a CPU-only
                // consumer; materialization replays its original seeds without
                // fetching, replacing, or releasing that retained owner.
                auto cpuContext = cpuReferenceContext(ctx);
                const auto retainedOwner = device;
                std::vector<std::uint64_t> replayHost{marker};
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(materializePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    replayHost, device, sigma, 19.2, seeds, cpuContext, 4, active)));
                LOGVOLE_REQUIRE_TRUE(replayHost == expected && device == retainedOwner);
            }
            LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), seeds, 0u, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, {}, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
            LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0,
                std::span<const std::uint8_t>(active).first(3), ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
            LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), {}, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, {}, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
            LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
            {
                struct RestoreRounding
                {
                    int mode = std::fegetround();
                    ~RestoreRounding() { std::fesetround(mode); }
                } rounding;
                LOGVOLE_REQUIRE_EQ(std::fesetround(FE_UPWARD), 0);
                LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(gpu::contextSampleStream(ctx), seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, active, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures));
                LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                    host, device, sigma, 19.2, seeds, ctx, 4, active)));
                LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            }

            const std::vector<std::uint8_t> inactive(count, 0);
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results,
                host, device, sigma, 19.2, seeds, ctx, 4, inactive)));
            LOGVOLE_REQUIRE_TRUE(host.empty() && device != nullptr && device->count() == words);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(std::all_of(fetched.begin(), fetched.end(), [](auto x) { return x == 0u; }));
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(samplePolyErrorCompactBatchForSetup(setupResources.executor, setupResources.results, host, device, sigma, 19.2, {}, ctx)));
            LOGVOLE_REQUIRE_TRUE(host.empty() && device == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, fetched, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_BackendSelectionOwnership(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions cpuOptions, gpuOptions;
    gpuOptions.mUseGpu = true;
    const auto params = make_small_params();
    RingNttContext cpu;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, cpu,
        std::make_shared<RingContextFactory>(cpuOptions, nullptr)));
    LOGVOLE_REQUIRE_FALSE(gpu::enabled(cpu));
    LOGVOLE_REQUIRE_FALSE(cpu.mGpuLightweight);
    LOGVOLE_REQUIRE_TRUE(rootProfiler(cpu) == nullptr);
    {
        auto options = cpuOptions;
        options.mAdvanced.mProtocol.mRootProfile = true;
        auto factory = std::make_shared<RingContextFactory>(options, nullptr);
        std::weak_ptr<RingContextFactory> lifetime = factory;
        RingNttContext first, derived, independent;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, first, factory));
        auto childParams = params;
        childParams.mPolyModulusDegree *= 2;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(childParams, derived, first.mFactoryOwner));
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, independent,
            std::make_shared<RingContextFactory>(options, nullptr)));
        auto* profiler = rootProfiler(first);
        LOGVOLE_REQUIRE_TRUE(profiler != nullptr);
        LOGVOLE_REQUIRE_TRUE(rootProfiler(derived) == profiler);
        LOGVOLE_REQUIRE_TRUE(rootProfiler(independent) != profiler);
        LOGVOLE_REQUIRE_EQ(profiler->mUsed.load(), 0u);
        auto retained = first;
        first = {};
        derived = {};
        factory.reset();
        LOGVOLE_REQUIRE_FALSE(lifetime.expired());
        LOGVOLE_REQUIRE_TRUE(rootProfiler(retained) == profiler);
        // Independent digest states share only the explicitly owned diagnostic
        // table. Repeated finish calls must not count an already-complete hash.
        std::vector<std::future<void>> workers;
        for (unsigned worker = 0; worker < 4; ++worker)
            workers.push_back(std::async(std::launch::async, [profiler] {
                for (unsigned i = 0; i < 8; ++i)
                {
                    RootDigestState digest;
                    assignValues<osuCrypto::u64>(digest.mDPrime.mCoeffs, {1, 2, 3, 4});
                    LOGVOLE_REQUIRE_TRUE(finishRootDigestHash(digest, profiler));
                    LOGVOLE_REQUIRE_TRUE(finishRootDigestHash(digest, profiler));
                }
            }));
        for (auto& worker : workers) worker.get();
        LOGVOLE_REQUIRE_EQ(profiler->mUsed.load(), 1u);
        LOGVOLE_REQUIRE_EQ(profiler->mEntries[0].mCount.load(), 32ull);
        LOGVOLE_REQUIRE_EQ(rootProfiler(independent)->mUsed.load(), 0u);
        retained = {};
        LOGVOLE_REQUIRE_TRUE(lifetime.expired());
    }
    const auto profileCount = [](HostStepProfiler* profiler) {
        osuCrypto::u64 count = 0;
        if (!profiler) return count;
        for (const auto& sample : profiler->snapshot()) count += sample.mCount;
        return count;
    };
    auto profiledOptions = cpuOptions;
    profiledOptions.mAdvanced.mHostStepProfile = true;
    RingNttContext profiledCpu;
    const auto beforeProfiled = profileCount(hostProfiler(profiledCpu));
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, profiledCpu,
        std::make_shared<RingContextFactory>(profiledOptions, nullptr)));
    LOGVOLE_REQUIRE_TRUE(profileCount(hostProfiler(profiledCpu)) > beforeProfiled);
    LOGVOLE_REQUIRE_TRUE(hostProfiler(cpu) == nullptr);
    LOGVOLE_REQUIRE_TRUE(profiledCpu.mHostProfiler == profiledCpu.mFactory->hostProfilerOwner());
    RingNttContext child;
    auto childParams = params;
    childParams.mPolyModulusDegree *= 2;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(childParams, child, profiledCpu.mFactoryOwner));
    LOGVOLE_REQUIRE_TRUE(child.mHostProfiler == profiledCpu.mHostProfiler);
    RingNttContext independent;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, independent,
        std::make_shared<RingContextFactory>(profiledOptions, nullptr)));
    LOGVOLE_REQUIRE_TRUE(independent.mHostProfiler != profiledCpu.mHostProfiler);
    const auto independentBefore = profileCount(hostProfiler(independent));
    { HostStep step(hostProfiler(profiledCpu), "ownership test", 7); }
    LOGVOLE_REQUIRE_EQ(profileCount(hostProfiler(independent)), independentBefore);
    const auto beforeDisabled = profileCount(hostProfiler(profiledCpu));
    RingNttContext quietCpu;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, quietCpu,
        std::make_shared<RingContextFactory>(cpuOptions, nullptr)));
    LOGVOLE_REQUIRE_EQ(profileCount(hostProfiler(profiledCpu)), beforeDisabled);
#if defined(ENABLE_LOGVOLE_CUDA)
    LOGVOLE_REQUIRE_TRUE(cpu.mGpuExecution != nullptr);
    LOGVOLE_REQUIRE_FALSE(cpu.mGpuExecution->isH200());
    if (!cmd.getOr("gpu", 0)) return;
    LOGVOLE_REQUIRE_TRUE(gpu::available());
    gpuOptions.mAdvanced.mHostStepProfile = true;
    RingOpsStats deviceStats, independentStats;
    gpuOptions.mRingOpsStats = &deviceStats;
    RingNttContext device;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, device,
        std::make_shared<RingContextFactory>(gpuOptions, nullptr)));
    LOGVOLE_REQUIRE_TRUE(gpu::enabled(device));
    LOGVOLE_REQUIRE_EQ(device.mGpuExecution->isH200(),
        gpu::deviceDescription().find("H200") != std::string::npos);
    LOGVOLE_REQUIRE_TRUE(device.mGpuLightweight);
    LOGVOLE_REQUIRE_TRUE(device.mHostProfiler == device.mGpuExecution->hostProfilerOwner());
    LOGVOLE_REQUIRE_TRUE(device.mHostProfiler == device.mGpuSetup->hostProfilerOwner());
    LOGVOLE_REQUIRE_TRUE(device.mHostProfiler == device.mResourceScope.mTables->hostProfilerOwner());
    LOGVOLE_REQUIRE_TRUE(device.mHostProfiler == device.mGpuExecution->mainStream().hostProfilerOwner());
    LOGVOLE_REQUIRE_TRUE(device.mHostProfiler != profiledCpu.mHostProfiler);
    gpu::GpuExecutionContext disabledProfile(cpuOptions, device.mHostProfiler);
    LOGVOLE_REQUIRE_TRUE(disabledProfile.hostProfiler() == nullptr);
    LOGVOLE_REQUIRE_FALSE(disabledProfile.isH200());
    LOGVOLE_REQUIRE_FALSE(gpu::enabled(cpu));

    std::vector<RnsPoly> input(4);
    for (auto& poly : input)
    {
        poly.mCoeffs.resize(ringPolyCoeffCount(params));
        for (std::size_t i = 0; i < poly.mCoeffs.size(); ++i)
            poly.mCoeffs[i] = i * 3 + 1;
    }
    auto expected = input;
    LOGVOLE_REQUIRE_TRUE(forwardNttBatch(expected, cpu));
    auto actual = input;
    {
        PendingRingOpsStats pending(device.mExecutionOptions.mRingOpsStats);
        LOGVOLE_REQUIRE_TRUE(forwardNttBatch(actual, device, &pending));
    }
    LOGVOLE_REQUIRE_EQ(deviceStats.mNttCount.load(), input.size());
    RnsPoly firstDigest;
    LOGVOLE_REQUIRE_TRUE(lencDigest(device, input, 3, 20, firstDigest));
    LOGVOLE_REQUIRE_TRUE(deviceStats.mDyadicMulAddCount.load() > 0u);
    const auto firstCounts = tests_libOTe::logvole_test::ringStatsSnapshot(deviceStats);
    for (auto* owner : {&independentStats, static_cast<RingOpsStats*>(nullptr)})
    {
        auto options = gpuOptions;
        options.mRingOpsStats = owner;
        RingNttContext independentDevice;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, independentDevice,
            std::make_shared<RingContextFactory>(options, nullptr)));
        auto independentInput = input;
        {
            PendingRingOpsStats pending(independentDevice.mExecutionOptions.mRingOpsStats);
            LOGVOLE_REQUIRE_TRUE(forwardNttBatch(independentInput, independentDevice, &pending));
        }
        expect_batch_equal(actual, independentInput);
        RnsPoly independentDigest;
        LOGVOLE_REQUIRE_TRUE(lencDigest(independentDevice, input, 3, 20, independentDigest));
        LOGVOLE_REQUIRE_TRUE(tests_libOTe::logvole_test::ringStatsSnapshot(deviceStats) == firstCounts);
        LOGVOLE_REQUIRE_TRUE(tests_libOTe::logvole_test::ringStatsSnapshot(independentStats) == firstCounts);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(independentDigest.mCoeffs, firstDigest.mCoeffs));
    }

    expect_batch_equal(expected, actual);
    LOGVOLE_REQUIRE_TRUE(inverseNttBatch(actual, device));
    expect_batch_equal(input, actual);
    {
        // A real readback with tracing disabled must leave its own diagnostics
        // untouched and must never write another stream's totals.
        osuCrypto::LogVoleGpuStreamOptions quietOptions, tracedOptions;
        tracedOptions.mDebug = true;
        gpu::GpuStream quiet(quietOptions), traced(tracedOptions);
        using RegionKind = gpu::GpuStream::RegionKind;
        quiet.regionCounter(RegionKind::Download).store(17);
        traced.regionCounter(RegionKind::Download).store(23);
        auto batch = gpu::upload(device, input);
        LOGVOLE_REQUIRE_TRUE(batch != nullptr);
        std::vector<RnsPoly> fetched;
        LOGVOLE_REQUIRE_TRUE(gpu::download(*batch, fetched, quiet));
        expect_batch_equal(input, fetched);
        LOGVOLE_REQUIRE_EQ(quiet.regionCounter(RegionKind::Download).load(), 17ull);
        LOGVOLE_REQUIRE_EQ(traced.regionCounter(RegionKind::Download).load(), 23ull);
        LOGVOLE_REQUIRE_TRUE(gpu::download(*batch, fetched, traced));
        expect_batch_equal(input, fetched);
        LOGVOLE_REQUIRE_TRUE(traced.regionCounter(RegionKind::Download).load() > 23ull);
        LOGVOLE_REQUIRE_EQ(quiet.regionCounter(RegionKind::Download).load(), 17ull);
        // Avoid reporting the seeded test sentinel as an actual measurement.
        traced.regionCounter(RegionKind::Download).store(0);
    }
    const auto beforeSecondCpu = profileCount(hostProfiler(profiledCpu));
    RingNttContext secondCpu;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, secondCpu,
        std::make_shared<RingContextFactory>(cpuOptions, nullptr)));
    LOGVOLE_REQUIRE_FALSE(gpu::enabled(secondCpu));
    LOGVOLE_REQUIRE_EQ(profileCount(hostProfiler(profiledCpu)), beforeSecondCpu);
    LOGVOLE_REQUIRE_TRUE(gpu::enabled(device));

    // Allocation selection is an argument; neither buffer stores settings.
    const osuCrypto::LogVoleWireOptions wireOptions;
    Buffer cpuWire(std::size_t{1} << 20, wireOptions, false);
    const auto deviceBefore = profileCount(hostProfiler(device));
    Buffer gpuWire(std::size_t{1} << 20, wireOptions, true, hostProfiler(device));
    LOGVOLE_REQUIRE_TRUE(profileCount(hostProfiler(device)) > deviceBefore);
    LOGVOLE_REQUIRE_EQ(profileCount(hostProfiler(profiledCpu)), beforeSecondCpu);
    LOGVOLE_REQUIRE_TRUE(cpuWire.memory() == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpuWire.memory() != nullptr);
#else
    (void)cmd;
#endif
}

void LogVole_RingOps_StatisticsDefaultsAndCompatibility(const oc::CLP&)
{
    using tests_libOTe::logvole_test::ringStatsSnapshot;
    RingParams params;
    params.mPolyModulusDegree = 1024;
    assignValues<int>(params.mCoeffModulusBits, {30, 30});
    RingOpsStats owned;
    RingNttContext ctx;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
    ctx.mExecutionOptions.mRingOpsStats = &owned;
    const auto zeros = ringStatsSnapshot(owned);
    auto original = deriveUniformPolyFromNonce(ctx, 17, 19, 0);
    std::vector<RnsPoly> input{original, original}, publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, 2, publicA));
    RnsPoly zero;
    resizeZero(zero.mCoeffs, ringPolyCoeffCount(params));
    std::array<osuCrypto::u64, 8> seed{};
    osuCrypto::PRNG prng(osuCrypto::toBlock(71));
    auto roundtrip = original;
    LOGVOLE_REQUIRE_TRUE(forwardNtt(roundtrip, ctx));
    LOGVOLE_REQUIRE_TRUE(inverseNtt(roundtrip, ctx));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(roundtrip.mCoeffs, original.mCoeffs));
    auto batch = input;
    LOGVOLE_REQUIRE_TRUE(forwardNttBatch(batch, ctx));
    RnsPoly product = zero;
    LOGVOLE_REQUIRE_TRUE(dyadicMultiplyAddNttInplace(batch[0], batch[1], product, ctx));
    LOGVOLE_REQUIRE_TRUE(dyadicMultiplyAddNtt(batch[0], batch[1], zero, ctx, product));
    LOGVOLE_REQUIRE_TRUE(inverseNttBatch(batch, ctx));
    LOGVOLE_REQUIRE_TRUE(ringSubInplace(roundtrip, zero, ctx));
    auto uniform = sampleUniformPolyFromSeed(ctx, seed);
    LOGVOLE_REQUIRE_TRUE(forwardNttCanonical(uniform, ctx));
    auto sampled = sampleUniformBatch(ctx, 2, prng);
    auto nonceBatch = deriveUniformPolyBatchFromNonce(ctx, 21, 23, 2, true);
    std::array<osuCrypto::block, 1> seeds{osuCrypto::ZeroBlock};
    LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromSeedListInplace(ctx, seeds, 25, 2, sampled));
    LOGVOLE_REQUIRE_TRUE(addPolyErrorFromSeed(roundtrip, 3.2, 19.2, seed, ctx));
    std::vector<osuCrypto::u64> compact(params.mPolyModulusDegree);
    LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(compact, 3.2, 19.2, seed, ctx));
    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(original, 20, 3, ctx, digits));
    DigestTree tree, truncated;
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, input, 3, 20, tree));
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, input, 2, 20, 20, truncated));
    LencEncodeOutput encoded;
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, input, 3, 20, prng, encoded));
    std::vector<RnsPoly> evaluated, aggregated;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, encoded.mLacct, tree, 2, 3, 20, evaluated));
    LOGVOLE_REQUIRE_TRUE(seedLabelAgg(input, 1, 2, params, aggregated));
    LOGVOLE_REQUIRE_TRUE(seedLabelGadgetDecomposeAndUnbundle(original, 20, 3, params, digits));
    std::array<osuCrypto::u8, 16> seedBytes{};
    LOGVOLE_REQUIRE_TRUE(seedLabelSampleCt2FromSeed(seedBytes, 1, original, 0, 2, params, sampled));
    detail::CpuRowScratch scratch;
    CpuBenchmarkState benchmark;
    LOGVOLE_REQUIRE_TRUE(scratch.runBulk(2, 2, [](std::size_t) { return true; }, benchmark));
    LOGVOLE_REQUIRE_TRUE(ringStatsSnapshot(owned) == zeros);

    // Convenience digest boundaries must keep their configured CPU owner.
    RnsPoly digest;
    LOGVOLE_REQUIRE_TRUE(lencDigest(ctx, input, 3, 20, digest));
    LOGVOLE_REQUIRE_TRUE(owned.mDyadicMulAddCount.load() > 0);
    const auto afterDigest = ringStatsSnapshot(owned);
    ctx.mExecutionOptions.mRingOpsStats = nullptr;
    RnsPoly disabledDigest;
    LOGVOLE_REQUIRE_TRUE(lencDigest(ctx, input, 3, 20, disabledDigest));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(digest.mCoeffs, disabledDigest.mCoeffs));
    LOGVOLE_REQUIRE_TRUE(ringStatsSnapshot(owned) == afterDigest);

    // Compatibility workers publish to the explicitly selected owner before joining.
    for (osuCrypto::u32 workers : {1u, 2u})
    {
        owned.reset();
        ctx.mExecutionOptions.mRingOpsStats = &owned;
        std::vector<RnsPoly> decrypted;
        LOGVOLE_REQUIRE_TRUE(detail::gpuLegacyLheDec(ctx, input, zero, decrypted,
            &publicA, false, false, workers, {}, scratch, {}));
        auto expected = zeros;
        expected[0] = 1;
        expected[1] = 2;
        expected[6] = 2;
        LOGVOLE_REQUIRE_TRUE(ringStatsSnapshot(owned) == expected);
        for (std::size_t i = 0; i < input.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(decrypted[i].mCoeffs, input[i].mCoeffs));
    }
}
