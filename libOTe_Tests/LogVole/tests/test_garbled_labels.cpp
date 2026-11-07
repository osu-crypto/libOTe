#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe_Tests/LogVole_TestOptions.h"
#include "libOTe/Vole/LogVole/LogVoleGarbled.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <cstdlib>
#include <limits>
#include <string>
#include <tuple>
#include <vector>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

namespace
{

    template<class F> void rejects(F&& f)
    {
        bool rejected = false;
        try { f(); } catch (const std::exception&) { rejected = true; }
        LOGVOLE_REQUIRE_TRUE(rejected);
    }

    template<class A, class B> void together(A&& a, B&& b)
    {
        auto result = macoro::sync_wait(macoro::when_all_ready(std::move(a), std::move(b)));
        std::get<0>(result).result();
        std::get<1>(result).result();
    }

}

void LogVole_Garbled_LayoutAndValidation(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    for (u32 slots : {8192u, 16384u})
    {
        const u64 perRing = slots / 3;
        GarbledLabelLayout layout(perRing + 1, slots);
        LOGVOLE_REQUIRE_EQ(layout.ringCount(), 2ull);
        LOGVOLE_REQUIRE_EQ(layout.scalarCount(), 2ull * slots);
        LOGVOLE_REQUIRE_EQ(layout.scalarIndex(perRing), slots);
        LOGVOLE_REQUIRE_EQ(layout.scalarIndex(perRing - 1, 2), perRing * 3 - 1);
        rejects([&] { layout.scalarIndex(perRing + 1); });
        rejects([&] { layout.scalarIndex(0, 3); });
    }
    rejects([] { GarbledLabelLayout(0, 8192); });
    rejects([] { GarbledLabelLayout(1, 3); });
    rejects([] { GarbledLabelLayout(std::numeric_limits<u64>::max(), 8192); });

    rejects([&] { LogVoleGarbledSender invalid(LogVoleOptions{}); });
    rejects([&] { LogVoleOptions invalid; invalid.mRequestSize = 1; invalid.mSetting = static_cast<CivoleSetting>(255); LogVoleGarbledSender party(invalid); });

    // A mismatch is acknowledged, so both parties reject without hanging.
    osuCrypto::LogVoleOptions senderOptions;
    senderOptions.mRequestSize = 1;
    LogVoleGarbledSender sender(senderOptions);
    tests_libOTe::logvole_test::SenderResources senderResources(sender.options());
    tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(sender.options());
    rejects([&] { sender.deltas(); });

    osuCrypto::LogVoleOptions receiverOptions;
    receiverOptions.mRequestSize = 2;
    LogVoleGarbledReceiver receiver(receiverOptions);
    PRNG prng(block(91, 17));
    auto sockets = coproto::LocalAsyncSocket::makePair();
    auto result = macoro::sync_wait(macoro::when_all_ready(
        sender.offline(setupResources.executor, setupResources.results, prng, sockets[0]), receiver.offline(sockets[1])));
    rejects([&] { std::get<0>(result).result(); });
    rejects([&] { std::get<1>(result).result(); });
}

void LogVole_Garbled_SequentialRelation(const oc::CLP& cmd)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    gpu::GpuExecutionContext readbackExecution;
#endif
    tests_libOTe::logvole_test::ScopedOptionValue deltaDevice(setupOptions.mDeltaDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue deltaStrict(setupOptions.mDeltaDeviceStrict, true);

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool useGpu = cmd.getOr("gpu", 0) != 0;
    if (useGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
#endif
    for (auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
    {
        LogVoleOptions options;
        options.mUseGpu = cmd.getOr("gpu", 0) != 0;
        options.mAdvanced.mGpuSetup = setupOptions;

        const u64 n = (setting == CivoleSetting::GoldenSeed ? 8192 : 16384) / 3 + 3;
        osuCrypto::LogVoleOptions senderOptions = options;
        senderOptions.mRequestSize = n;
        senderOptions.mNumThreads = 2;
        senderOptions.mSetting = setting;
        LogVoleGarbledSender sender(senderOptions);
        tests_libOTe::logvole_test::SenderResources senderResources(sender.options());
        tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(sender.options());
        LogVoleGarbledReceiver receiver(senderOptions);
        PRNG sp(block(871, 12)), rp(block(913, 65));
        auto setup = coproto::LocalAsyncSocket::makePair();
        together(sender.offline(setupResources.executor, setupResources.results, sp, setup[0]), receiver.offline(setup[1]));
        const u64 p = sender.modulus();
        const auto otherSetting = setting == CivoleSetting::GoldenSeed
            ? CivoleSetting::NoGoldenSeed : CivoleSetting::GoldenSeed;
        rejects([&] { auto invalid = options; invalid.mRequestSize = 0; invalid.mSetting = otherSetting; LogVoleGarbledSender party(invalid); });
        rejects([&] { auto invalid = options; invalid.mRequestSize = 0; invalid.mSetting = otherSetting; LogVoleGarbledReceiver party(invalid); });
        LOGVOLE_REQUIRE_EQ(sender.modulus(), p);
        LOGVOLE_REQUIRE_EQ(receiver.modulus(), p);
        LOGVOLE_REQUIRE_TRUE(p > (u64{1} << 43));
        for (u64 d : sender.deltas()) LOGVOLE_REQUIRE_TRUE(d && d < p);
        GarbledLabelBatch a, b;
        for (u64 round = 0; round < 3; ++round)
        {
            std::vector<u64> x(n);
            for (u64 i = 0; i < n; ++i) x[i] = i % 3 == 0 ? 0 : i % 3 == 1 ? 1 : p - 1 - round;
            if (!round)
            {
                auto invalid = x;
                invalid[0] = p;
                auto sockets = coproto::LocalAsyncSocket::makePair();
                rejects([&] { macoro::sync_wait(receiver.receive(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc, receiverBuffers.zeta, receiverBuffers.wrap, invalid, a, rp, sockets[1])); });
                rejects([&] { macoro::sync_wait(receiver.receive(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc, receiverBuffers.zeta, receiverBuffers.wrap, {}, a, rp, sockets[1])); });
            }
            span<const u64> input(x.data(), x.size());
#if defined(ENABLE_LOGVOLE_CUDA)
            if (useGpu && round == 1)
            {
                sender.mKeepOutputOnDevice = receiver.mKeepOutputOnDevice = true;
                auto invalid = gpu::uploadScalars({x.data(), x.size() - 1}, operationExecution.mainStream());
                receiver.mInputDevice = invalid;
                auto invalidQuery = coproto::LocalAsyncSocket::makePair();
                rejects([&] { macoro::sync_wait(receiver.receive(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc, receiverBuffers.zeta, receiverBuffers.wrap, {}, a, rp, invalidQuery[1])); });
                receiver.mInputDevice = gpu::uploadScalars(input, operationExecution.mainStream());
                LOGVOLE_REQUIRE_TRUE(receiver.mInputDevice);
                input = {};
            }
            else
            {
                receiver.mInputDevice.reset();
                sender.mKeepOutputOnDevice = receiver.mKeepOutputOnDevice = false;
            }
#endif
            auto query = coproto::LocalAsyncSocket::makePair();
            const auto oldA = a.mScalars.data(), oldB = b.mScalars.data();
            together(sender.send(senderResources.executor, senderResources.buffers, b, sp, query[0]), receiver.receive(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc, receiverBuffers.zeta, receiverBuffers.wrap, input, a, rp, query[1]));
            if (oldA && !receiver.mKeepOutputOnDevice) LOGVOLE_REQUIRE_TRUE(a.mScalars.data() == oldA);
            if (oldB && !sender.mKeepOutputOnDevice) LOGVOLE_REQUIRE_TRUE(b.mScalars.data() == oldB);
            a.wait(); b.wait();
#if defined(ENABLE_LOGVOLE_CUDA)
            if (a.mDevice) a.fetch(readbackExecution.readbackStream());
            if (b.mDevice) b.fetch(readbackExecution.readbackStream());
#endif
            LOGVOLE_REQUIRE_EQ(a.mSid, round);
            LOGVOLE_REQUIRE_EQ(b.mSid, round);
            for (u64 i = 0; i < n; ++i)
            {
                auto av = a.label(i), bv = b.label(i);
                for (u32 j = 0; j < 3; ++j)
                {
                    // Exact two-limb arithmetic keeps this oracle portable to MSVC.
                    unsigned long long product[2];
                    seal::util::multiply_uint64(x[i], sender.deltas()[j], product);
                    const u64 low = product[0];
                    product[0] += bv[j];
                    product[1] += product[0] < low;
                    const u64 expected = seal::util::barrett_reduce_128(product, seal::Modulus(p));
                    LOGVOLE_REQUIRE_EQ(av[j], expected);
                }
                LOGVOLE_REQUIRE_TRUE(av == b.labelForValue(i, x[i], sender.deltas()));
            }
            // Unused slots and the entire final input tail have x' = 0.
            const auto& layout = a.mLayout;
            for (u64 c = 0; c < layout.ringCount(); ++c)
                for (u32 s = 0; s < layout.mSlotsPerRing; ++s)
                    if (s >= layout.labelsPerRing() * 3 || c * layout.labelsPerRing() + s / 3 >= n)
                        LOGVOLE_REQUIRE_EQ(a.mScalars[c * layout.mSlotsPerRing + s],
                            b.mScalars[c * layout.mSlotsPerRing + s]);
        }
    }
}

void LogVole_Garbled_GpuPackingMatchesCrt(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool useGpu = cmd.getOr("gpu", 0) != 0;
    if (useGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!useGpu) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    for (bool fusedInput : {true, false})
    for (auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
    {
        CivoleParams params;
        LOGVOLE_REQUIRE_TRUE(makeCivoleParams(setting, params));
        LogVoleExecutionOptions advanced;
        advanced.mUseGpu = true;
        advanced.mAdvanced.mProtocol.mGarbledFusedInput = fusedInput;
        ZpCrtContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mLogVole.mShrinkExpand.mRing,
            params.mLogVole.mShrinkExpand.mPlaintextModulusBits, ctx,
            std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(advanced))));
        const u32 slots = zpSlotCount(ctx);
        for (u64 count : {u64{1}, u64(slots / 3), u64(slots / 3 + 1), u64(2 * (slots / 3) + 7)})
        {
            GarbledLabelLayout layout(count, slots);
            std::vector<u64> x(count), repeated(layout.scalarCount(), 0);
            for (u64 i = 0; i < count; ++i)
            {
                x[i] = (ctx.mPlaintextModulus - 1 - i) % ctx.mPlaintextModulus;
                for (u32 j = 0; j < 3; ++j) repeated[layout.scalarIndex(i, j)] = x[i];
            }
            std::vector<RnsPoly> expected;
            LOGVOLE_REQUIRE_TRUE(wrapZpLabelsCrt(ctx, repeated, false, 0, 1, expected));
            auto input = gpu::uploadScalars(x, operationExecution.mainStream());
            for (bool deviceInput : {false, true})
            {
                auto wrapped = deviceInput
                    ? gpu::wrapDeviceLabels(ctx, *input, count, false, 0, layout.ringCount(), true)
                    : gpu::wrapLabelsDevice(ctx, x, false, 0, layout.ringCount(), true);
                LOGVOLE_REQUIRE_TRUE(wrapped);
                std::vector<RnsPoly> actual;
                LOGVOLE_REQUIRE_TRUE(gpu::download(*wrapped, actual, readbackExecution.readbackStream()));
                LOGVOLE_REQUIRE_EQ(actual.size(), expected.size());
                for (u64 c = 0; c < actual.size(); ++c)
                    LOGVOLE_REQUIRE_TRUE(std::equal(actual[c].mCoeffs.begin(), actual[c].mCoeffs.end(),
                        expected[c].mCoeffs.begin(), expected[c].mCoeffs.end()));
            }

            // Match the benchmark's original bulk AES draws followed by &1,
            // including odd lengths and partial final rings in both settings.
            const block bitSeed(0x696e707574, 3);
            PRNG bitPrng(bitSeed);
            std::vector<u64> expectedBits(count), actualBits(count);
            bitPrng.get(expectedBits.data(), expectedBits.size());
            for (auto& bit : expectedBits) bit &= 1u;
            auto generatedBits = gpu::sampleScalarsFromSeed(bitSeed, count, 2, operationExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(generatedBits);
            LOGVOLE_REQUIRE_EQ(generatedBits->count(), count);
            LOGVOLE_REQUIRE_TRUE(generatedBits->producerStream() == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*generatedBits, actualBits, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_TRUE(expectedBits == actualBits);
            std::fill(repeated.begin(), repeated.end(), 0);
            for (u64 i = 0; i < count; ++i)
                for (u32 j = 0; j < 3; ++j)
                    repeated[layout.scalarIndex(i, j)] = expectedBits[i];
            std::vector<RnsPoly> expectedBitPacking, actualBitPacking;
            LOGVOLE_REQUIRE_TRUE(wrapZpLabelsCrt(ctx, repeated, false, 0, 1, expectedBitPacking));
            auto wrappedBits = gpu::wrapDeviceLabels(ctx, *generatedBits,
                count, false, 0, layout.ringCount(), true);
            LOGVOLE_REQUIRE_TRUE(wrappedBits);
            LOGVOLE_REQUIRE_TRUE(gpu::download(*wrappedBits, actualBitPacking, readbackExecution.readbackStream()));
            LOGVOLE_REQUIRE_EQ(actualBitPacking.size(), expectedBitPacking.size());
            for (u64 c = 0; c < actualBitPacking.size(); ++c)
                LOGVOLE_REQUIRE_TRUE(std::equal(actualBitPacking[c].mCoeffs.begin(), actualBitPacking[c].mCoeffs.end(),
                    expectedBitPacking[c].mCoeffs.begin(), expectedBitPacking[c].mCoeffs.end()));
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}
