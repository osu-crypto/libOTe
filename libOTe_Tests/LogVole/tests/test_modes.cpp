#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif
#include <tuple>
#include <vector>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

namespace
{
    void checkMode(const CLP& cmd, CivoleSetting setting, OnlineMode mode)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

        const bool device = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device) LOGVOLE_REQUIRE_TRUE(gpu::available());
#else
        LOGVOLE_REQUIRE_FALSE(device);
#endif
        // Cross a complete recursive block and end with a partial CRT batch.
        const u64 count = cmd.getOr("lvCount", (u64{1} << 18) + 3);
        const u64 rounds = cmd.getOr("lvRounds", u64{2});
        const u64 seed = cmd.getOr("lvSeed", u64{0});
        const u32 threads = cmd.getOr("lvThreads", u32{2});
        const bool randomInputs = cmd.getOr("lvRandom", 0) != 0;
        LOGVOLE_REQUIRE_TRUE(count && rounds && threads);
        constexpr u64 delta = 19;
        CpuBenchmarkContext senderTelemetry, receiverTelemetry;
        const bool instrument = cmd.getOr("lvCpuTelemetry", 0) != 0;
        for (auto* telemetry : {&senderTelemetry, &receiverTelemetry})
        {
            telemetry->mWorkerLimit = threads;
#if defined(__linux__)
            cpu_set_t mask;
            CPU_ZERO(&mask);
            LOGVOLE_REQUIRE_EQ(sched_getaffinity(0, sizeof(mask), &mask), 0);
            for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
                if (CPU_ISSET(cpu, &mask)) telemetry->mCpus.push_back(cpu);
#else
            telemetry->mCpus.resize(threads);
#endif
        }
        LogVoleOptions options;
        options.mCpuBenchmark = instrument ? &senderTelemetry : nullptr;
        options.mUseGpu = device;
        options.mAdvanced.mProtocol.mRootProfile = cmd.getOr("lvRootProfile", 0) != 0;
        options.mAdvanced.mHostStepProfile = cmd.getOr("lvHostProfile", 0) != 0;

        auto senderReuse = std::make_shared<ZpContextFactory>(
            std::make_shared<RingContextFactory>(options));
        options.mCpuBenchmark = instrument ? &receiverTelemetry : nullptr;
        auto receiverReuse = std::make_shared<ZpContextFactory>(
            std::make_shared<RingContextFactory>(options));
        osuCrypto::LogVoleOptions originalSenderOptions = options;
        originalSenderOptions.mCpuBenchmark = instrument ? &senderTelemetry : nullptr;
        originalSenderOptions.mRequestSize = count;
        originalSenderOptions.mPlaintextModulusBits = 55;
        originalSenderOptions.mNumThreads = threads;
        originalSenderOptions.mSetting = setting;
        originalSenderOptions.mMode = mode;
        LogVoleSender originalSender(originalSenderOptions, senderReuse);
        auto receiverOptions = originalSenderOptions;
        receiverOptions.mCpuBenchmark = instrument ? &receiverTelemetry : nullptr;
        LogVoleReceiver originalReceiver(receiverOptions, receiverReuse);
        auto observeFactory = [](const CivoleParams& params, ProtocolCacheRole role,
            const std::shared_ptr<ZpContextFactory>& factory)
        {
            ScopedProtocolCacheScope scope(role, 0);
            ZpCrtContext context;
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mLogVole.mShrinkExpand.mRing,
                params.mLogVole.mShrinkExpand.mPlaintextModulusBits, context, factory));
            return std::weak_ptr<const ZpCrtContext>(context.mFactoryOwner);
        };
        const auto senderFactory = observeFactory(originalSender.mParams, ProtocolCacheRole::Sender, senderReuse);
        const auto receiverFactory = observeFactory(originalReceiver.mParams, ProtocolCacheRole::Receiver, receiverReuse);
        LOGVOLE_REQUIRE_FALSE(senderFactory.expired());
        LOGVOLE_REQUIRE_FALSE(receiverFactory.expired());
        originalSender.mKeepOutputOnDevice = device;
        originalReceiver.mKeepOutputOnDevice = device;
        PRNG senderPrng(toBlock(100 ^ seed, 200)), receiverPrng(toBlock(300 ^ seed, 400));
        PRNG inputPrng(toBlock(500 ^ seed, 600));
        auto offline = coproto::LocalAsyncSocket::makePair();
        {
            auto setup = macoro::sync_wait(macoro::when_all_ready(
                originalSender.offline(delta, senderPrng, offline[0]),
                originalReceiver.offline(offline[1])));
            std::get<0>(setup).result();
            std::get<1>(setup).result();
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        const auto checkExecution = [](const auto& state, const auto& mathFactory) {
            const auto& selected = state.mCrtFactoryOwner;
            LOGVOLE_REQUIRE_TRUE(selected && selected->mFactoryOwner == mathFactory.lock());
            const auto& execution = selected->mRing.mGpuExecution;
            LOGVOLE_REQUIRE_TRUE(execution && execution != selected->mFactoryOwner->mRing.mGpuExecution);
            for (auto* level = &state.mLogVoleState; level; level = level->mNextLevelState.get())
            {
                const auto& ring = level->mShrinkExpandState.mRingFactoryOwner;
                LOGVOLE_REQUIRE_TRUE(ring && ring->mGpuExecution == execution);
            }
        };
        checkExecution(originalSender.mOfflineState, senderFactory);
        checkExecution(originalReceiver.mOfflineState, receiverFactory);
        LOGVOLE_REQUIRE_TRUE(originalSender.mOfflineState.mCrtFactoryOwner->mRing.mGpuExecution !=
            originalReceiver.mOfflineState.mCrtFactoryOwner->mRing.mGpuExecution);
#else
        LOGVOLE_REQUIRE_TRUE(originalSender.mOfflineState.mCrtFactoryOwner == senderFactory.lock());
        LOGVOLE_REQUIRE_TRUE(originalReceiver.mOfflineState.mCrtFactoryOwner == receiverFactory.lock());
#endif

        if (mode == OnlineMode::Interactive)
        {
            auto saved = std::move(originalSender.mOfflineState.mCrtFactoryOwner);
            CivoleReleaseKOutput rejected;
            LOGVOLE_REQUIRE_FALSE(civoleSenderReleaseK(originalSender.mOfflineState, 0, rejected));
            originalSender.mOfflineState.mCrtFactoryOwner = originalReceiver.mOfflineState.mCrtFactoryOwner;
            LOGVOLE_REQUIRE_FALSE(civoleSenderReleaseK(originalSender.mOfflineState, 0, rejected));
            originalSender.mOfflineState.mCrtFactoryOwner = std::move(saved);
            LOGVOLE_REQUIRE_FALSE(originalSender.mOfflineState.mHasActiveSid);
        }

        // Moving an established session must retain the new backend/mode state.
        LogVoleSender sender(std::move(originalSender));
        tests_libOTe::logvole_test::SenderResources senderResources(sender.options());
        tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(sender.options());
        LogVoleReceiver receiver;
        receiver = std::move(originalReceiver);
        LOGVOLE_REQUIRE_FALSE(originalSender.isConfigured());
        LOGVOLE_REQUIRE_FALSE(originalReceiver.isConfigured());
        LOGVOLE_REQUIRE_EQ(sender.setting(), setting);
        LOGVOLE_REQUIRE_EQ(receiver.setting(), setting);
        LOGVOLE_REQUIRE_EQ(sender.mKeepOutputOnDevice, device);
        LOGVOLE_REQUIRE_EQ(receiver.mKeepOutputOnDevice, device);
        std::vector<u64> x(count), keys(count), macs(count);
        const seal::Modulus p(sender.modulus());
        std::vector<const std::uint64_t*> productStorage;
        for (auto& buffer : senderResources.buffers)
            productStorage.push_back(buffer.mProduct.mCoeffs.data());
        std::vector<const std::uint64_t*> receiverProducts;
        std::vector<const void*> ciphertextStorage, nodeStorage;
        for (auto& buffer : receiverBuffers.lhe)
            receiverProducts.push_back(buffer.mProduct.mCoeffs.data());
        for (auto& buffer : receiverBuffers.lenc)
        {
            ciphertextStorage.push_back(buffer.mCiphertexts.data());
            nodeStorage.push_back(buffer.mNodes.data());
        }
        auto onPool = [&](macoro::task<> operation) -> macoro::task<> {
            if (!device) co_await senderResources.executor.schedule();
            co_await std::move(operation);
        };
        for (u64 round = 0; round != rounds; ++round)
        {
            for (u64 i = 0; i != count; ++i)
                x[i] = i % 3 == 0 ? 0 : (i % 3 == 1 ? p.value() - 1 :
                    (randomInputs ? inputPrng.get<u64>() % p.value() : i + round));
            auto online = coproto::LocalAsyncSocket::makePair();
            auto query = macoro::sync_wait(macoro::when_all_ready(
                onPool(sender.send(senderResources.executor, senderResources.buffers,
                    device ? span<u64>{} : span<u64>(keys), senderPrng, online[0])),
                onPool(receiver.receive(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc,
                    x, device ? span<u64>{} : span<u64>(macs), receiverPrng, online[1]))));
            std::get<0>(query).result();
            std::get<1>(query).result();
            for (std::size_t i = 0; i < productStorage.size(); ++i)
                LOGVOLE_REQUIRE_TRUE(senderResources.buffers[i].mProduct.mCoeffs.data() == productStorage[i]);
            for (std::size_t i = 0; i < receiverProducts.size(); ++i)
            {
                LOGVOLE_REQUIRE_TRUE(receiverBuffers.lhe[i].mProduct.mCoeffs.data() == receiverProducts[i]);
                LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[i].mCiphertexts.data() == ciphertextStorage[i]);
                LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[i].mNodes.data() == nodeStorage[i]);
                LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[i].mCiphertexts.empty() && receiverBuffers.lenc[i].mNodes.empty());
            }
#if defined(ENABLE_LOGVOLE_CUDA)
            if (device)
            {
                LOGVOLE_REQUIRE_TRUE(sender.outputDevice());
                LOGVOLE_REQUIRE_TRUE(receiver.outputDevice());
                LOGVOLE_REQUIRE_EQ(sender.outputDeviceCount(), count);
                LOGVOLE_REQUIRE_EQ(receiver.outputDeviceCount(), count);
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *std::static_pointer_cast<gpu::DeviceScalars>(sender.outputDevice()), keys, readbackExecution.readbackStream()));
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *std::static_pointer_cast<gpu::DeviceScalars>(receiver.outputDevice()), macs, readbackExecution.readbackStream()));
            }
#endif
            for (u64 i = 0; i != count; ++i)
                LOGVOLE_REQUIRE_EQ(macs[i], mulAddMod(x[i], delta, keys[i], p));
            if (mode == OnlineMode::NonInteractive)
            {
                LOGVOLE_REQUIRE_EQ(sender.mLastOnlineComm.mBytesSent, 0u);
                LOGVOLE_REQUIRE_EQ(receiver.mLastOnlineComm.mBytesReceived, 0u);
            }
        }
        if (options.mAdvanced.mHostStepProfile)
        {
            LOGVOLE_REQUIRE_TRUE(receiver.hostProfiler() != nullptr);
            LOGVOLE_REQUIRE_TRUE(receiver.hostProfiler() != sender.hostProfiler());
            LOGVOLE_REQUIRE_TRUE(!receiver.hostProfiler()->snapshot().empty());
            LOGVOLE_REQUIRE_TRUE(!sender.hostProfiler()->snapshot().empty());
        }
        if (options.mAdvanced.mProtocol.mRootProfile)
        {
            const auto* profiler = receiverReuse->ringFactory()->rootProfiler();
            LOGVOLE_REQUIRE_TRUE(profiler != nullptr);
            LOGVOLE_REQUIRE_TRUE(profiler->mUsed.load() != 0);
            LOGVOLE_REQUIRE_TRUE(profiler != senderReuse->ringFactory()->rootProfiler());
        }
        if (instrument)
        {
            for (const auto* telemetry : {&senderTelemetry, &receiverTelemetry})
            {
                LOGVOLE_REQUIRE_EQ(telemetry->mActiveTaskThreads.load(), 0u);
                LOGVOLE_REQUIRE_EQ(telemetry->mWorkerSlots.load(), 0u);
                if (!device) LOGVOLE_REQUIRE_TRUE(telemetry->mPeakTaskThreads.load() > 0u);
            }
        }
        sender.clear();
        receiver.clear();
        LOGVOLE_REQUIRE_FALSE(sender.outputDevice());
        LOGVOLE_REQUIRE_FALSE(receiver.outputDevice());
        LOGVOLE_REQUIRE_TRUE(senderFactory.expired());
        LOGVOLE_REQUIRE_TRUE(receiverFactory.expired());
    }
}

void LogVole_Modes_InteractiveGolden(const CLP& cmd)
{
    checkMode(cmd, CivoleSetting::GoldenSeed, OnlineMode::Interactive);
}

void LogVole_Modes_NonInteractive(const CLP& cmd)
{
    checkMode(cmd, CivoleSetting::NoGoldenSeed, OnlineMode::NonInteractive);
}

void LogVole_Modes_InteractiveNoGolden(const CLP& cmd)
{
    checkMode(cmd, CivoleSetting::NoGoldenSeed, OnlineMode::Interactive);
}

void LogVole_Modes_ProtocolOptions(const CLP&)
{
    const auto check = []<typename Party>() {
        static_assert(!requires(Party& party) { party.configure(1); });
        const auto rejects = [](const LogVoleOptions& options) {
            bool rejected = false;
            try { Party party(options); }
            catch (const std::exception&) { rejected = true; }
            LOGVOLE_REQUIRE_TRUE(rejected);
        };
        LogVoleOptions invalid;
        rejects(invalid); // The constructor requires an explicit nonzero size.
        invalid.mRequestSize = 1;
        invalid.mPlaintextModulusBits = 1;
        rejects(invalid);
        invalid.mPlaintextModulusBits = 55;
        invalid.mMode = OnlineMode::NonInteractive;
        rejects(invalid); // NonInteractive requires NoGoldenSeed.
        LogVoleOptions options;
        options.mRequestSize = 7;
        options.mNumThreads = 2;
        LOGVOLE_REQUIRE_FALSE(options.mAdvanced.mAllowPartialRootWidth);
        options.mAdvanced.mAllowPartialRootWidth = true;
        LOGVOLE_REQUIRE_TRUE(options.mAdvanced.mEarlyGoldenCheck);
        options.mAdvanced.mEarlyGoldenCheck = false;
        const LogVoleGpuSetupOptions defaults;
        options.mAdvanced.mGpuSetup.mDirectWire = !defaults.mDirectWire;
        options.mAdvanced.mGpuSetup.mLazyCiphertexts = !defaults.mLazyCiphertexts;
        options.mAdvanced.mGpuSetup.mRootPublicBToken = !defaults.mRootPublicBToken;
        options.mAdvanced.mGpuSetup.mRootBStarDevice = !defaults.mRootBStarDevice;
        options.mAdvanced.mGpuSetup.mRootBStarDeviceStrict = !defaults.mRootBStarDeviceStrict;
        options.mAdvanced.mGpuSetup.mRootR1Device = !defaults.mRootR1Device;
        options.mAdvanced.mGpuSetup.mRootR1DeviceStrict = !defaults.mRootR1DeviceStrict;
        options.mAdvanced.mGpuSetup.mRootSecretDevice = !defaults.mRootSecretDevice;
        options.mAdvanced.mGpuSetup.mRootSecretDeviceStrict = !defaults.mRootSecretDeviceStrict;
        options.mAdvanced.mGpuSetup.mLheDevice = !defaults.mLheDevice;
        options.mAdvanced.mGpuSetup.mLheDeviceStrict = !defaults.mLheDeviceStrict;
        options.mAdvanced.mGpuSetup.mLencDevice = !defaults.mLencDevice;
        options.mAdvanced.mGpuSetup.mLencDeviceStrict = !defaults.mLencDeviceStrict;
        options.mAdvanced.mGpuSetup.mLencDevicePadding = !defaults.mLencDevicePadding;
        options.mAdvanced.mGpuSetup.mCompactNoise = !defaults.mCompactNoise;
        options.mAdvanced.mGpuSetup.mCompactNoiseStrict = !defaults.mCompactNoiseStrict;
        options.mAdvanced.mGpuSetup.mLencRandomizerOutput = !defaults.mLencRandomizerOutput;
        options.mAdvanced.mGpuSetup.mLencRandomizerOutputStrict = !defaults.mLencRandomizerOutputStrict;
        options.mAdvanced.mGpuSetup.mDeltaDevice = !defaults.mDeltaDevice;
        options.mAdvanced.mGpuSetup.mDeltaDeviceStrict = !defaults.mDeltaDeviceStrict;
        options.mAdvanced.mGpuSetup.mReceiverResidentNtt = !defaults.mReceiverResidentNtt;
        options.mAdvanced.mGpuSetup.mReceiverResidentNttStrict = !defaults.mReceiverResidentNttStrict;
        options.mAdvanced.mGpuSetup.mBatchNtt = !defaults.mBatchNtt;
        options.mAdvanced.mGpuSetup.mParallelCopy = !defaults.mParallelCopy;
        options.mAdvanced.mGpuSetup.mParallelMessageCopy = !defaults.mParallelMessageCopy;
        options.mAdvanced.mGpuSetup.mSharedState = !defaults.mSharedState;
        options.mAdvanced.mGpuSetup.mRootDevice = !defaults.mRootDevice;
        options.mAdvanced.mGpuSetup.mRootDeviceStrict = !defaults.mRootDeviceStrict;
        options.mAdvanced.mGpuSetup.mRootCompactNoise = !defaults.mRootCompactNoise;
        options.mAdvanced.mGpuSetup.mRootCompactNoiseStrict = !defaults.mRootCompactNoiseStrict;
        options.mAdvanced.mGpuSetup.mTopSecretConsumerStrict = !defaults.mTopSecretConsumerStrict;
        options.mAdvanced.mGpuSetup.mDeltaChainDevice = !defaults.mDeltaChainDevice;
        options.mAdvanced.mGpuSetup.mDeltaChainStrict = !defaults.mDeltaChainStrict;
        options.mAdvanced.mGpuSetup.mTopSecretRepDevice = !defaults.mTopSecretRepDevice;
        options.mAdvanced.mGpuSetup.mParallelLhe = LogVoleChoice::Disabled;
        options.mAdvanced.mGpuSetup.mParallelLenc = LogVoleChoice::Enabled;
        options.mAdvanced.mGpuSetup.mPublicSenderCt2PrefetchLevels = 3;
        const auto selectedGpu = options.mAdvanced.mGpuSetup;
        const auto checkGpu = [](const auto& actual, const auto& expected) {
            LOGVOLE_REQUIRE_TRUE(actual.mDirectWire == expected.mDirectWire);
            LOGVOLE_REQUIRE_TRUE(actual.mLazyCiphertexts == expected.mLazyCiphertexts);
            LOGVOLE_REQUIRE_TRUE(actual.mRootPublicBToken == expected.mRootPublicBToken);
            LOGVOLE_REQUIRE_TRUE(actual.mRootBStarDevice == expected.mRootBStarDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mRootBStarDeviceStrict == expected.mRootBStarDeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mRootR1Device == expected.mRootR1Device);
            LOGVOLE_REQUIRE_TRUE(actual.mRootR1DeviceStrict == expected.mRootR1DeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mRootSecretDevice == expected.mRootSecretDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mRootSecretDeviceStrict == expected.mRootSecretDeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mLheDevice == expected.mLheDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mLheDeviceStrict == expected.mLheDeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mLencDevice == expected.mLencDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mLencDeviceStrict == expected.mLencDeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mLencDevicePadding == expected.mLencDevicePadding);
            LOGVOLE_REQUIRE_TRUE(actual.mCompactNoise == expected.mCompactNoise);
            LOGVOLE_REQUIRE_TRUE(actual.mCompactNoiseStrict == expected.mCompactNoiseStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mLencRandomizerOutput == expected.mLencRandomizerOutput);
            LOGVOLE_REQUIRE_TRUE(actual.mLencRandomizerOutputStrict == expected.mLencRandomizerOutputStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mDeltaDevice == expected.mDeltaDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mDeltaDeviceStrict == expected.mDeltaDeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mReceiverResidentNtt == expected.mReceiverResidentNtt);
            LOGVOLE_REQUIRE_TRUE(actual.mReceiverResidentNttStrict == expected.mReceiverResidentNttStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mBatchNtt == expected.mBatchNtt);
            LOGVOLE_REQUIRE_TRUE(actual.mParallelCopy == expected.mParallelCopy);
            LOGVOLE_REQUIRE_TRUE(actual.mParallelMessageCopy == expected.mParallelMessageCopy);
            LOGVOLE_REQUIRE_TRUE(actual.mSharedState == expected.mSharedState);
            LOGVOLE_REQUIRE_TRUE(actual.mRootDevice == expected.mRootDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mRootDeviceStrict == expected.mRootDeviceStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mRootCompactNoise == expected.mRootCompactNoise);
            LOGVOLE_REQUIRE_TRUE(actual.mRootCompactNoiseStrict == expected.mRootCompactNoiseStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mTopSecretConsumerStrict == expected.mTopSecretConsumerStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mDeltaChainDevice == expected.mDeltaChainDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mDeltaChainStrict == expected.mDeltaChainStrict);
            LOGVOLE_REQUIRE_TRUE(actual.mTopSecretRepDevice == expected.mTopSecretRepDevice);
            LOGVOLE_REQUIRE_TRUE(actual.mParallelLhe == expected.mParallelLhe);
            LOGVOLE_REQUIRE_TRUE(actual.mParallelLenc == expected.mParallelLenc);
            LOGVOLE_REQUIRE_TRUE(actual.mPublicSenderCt2PrefetchLevels == expected.mPublicSenderCt2PrefetchLevels);
        };
        options.mAdvanced.mTransport.mOwnedSetupSend = false;
        options.mAdvanced.mTransport.mOwnedRootMessages = false;
        options.mAdvanced.mTransport.mDeferRootDigestHash = false;
        options.mAdvanced.mTransport.mMoveReceivedState = false;
        const auto checkTransport = [](const auto& party, bool expected) {
            LOGVOLE_REQUIRE_EQ(party.mParams.mLogVole.mShrinkExpand.mTransport.mOwnedSetupSend, expected);
            LOGVOLE_REQUIRE_EQ(party.mParams.mLogVole.mShrinkExpand.mTransport.mOwnedRootMessages, expected);
            LOGVOLE_REQUIRE_EQ(party.mParams.mLogVole.mShrinkExpand.mTransport.mDeferRootDigestHash, expected);
            LOGVOLE_REQUIRE_EQ(party.mParams.mLogVole.mShrinkExpand.mTransport.mMoveReceivedState, expected);
        };
        options.mAdvanced.mStreams.mIndexScratchKiB = 256;
        options.mAdvanced.mStreams.mPipelinedUpload = true;
        options.mAdvanced.mProtocol.mFusedWrap = false;
        options.mAdvanced.mProtocol.mCt2PrefixCache = true;
        const auto selectedOptions = options;
        auto factory = std::make_shared<ZpContextFactory>(
            std::make_shared<RingContextFactory>(options));
        Party original(options, factory);
        tests_libOTe::logvole_test::SenderResources senderResources(options);
        tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(options);
        LOGVOLE_REQUIRE_EQ(original.requestSize(), 7ull);
        LOGVOLE_REQUIRE_EQ(original.numThreads(), 2u);
        options.mRequestSize = 1;
        options.mNumThreads = 0; // Preserve the existing normalization to one.
        options.mAdvanced = {};
        options.mAdvanced.mGpuSetup = defaults;
        options.mAdvanced.mTransport = {};
        options.mAdvanced.mAllowPartialRootWidth = false; // Constructor owns its copy.
        options.mAdvanced.mEarlyGoldenCheck = true;
        Party strict(options);
        LOGVOLE_REQUIRE_EQ(strict.requestSize(), 1ull);
        LOGVOLE_REQUIRE_EQ(strict.numThreads(), 1u);
        LOGVOLE_REQUIRE_EQ(original.options().mRequestSize, 7ull);
        LOGVOLE_REQUIRE_EQ(original.options().mNumThreads, 2u);
        LOGVOLE_REQUIRE_FALSE(original.options() == strict.options());
        // A mismatch is rejected locally, before entering offline transport.
        auto sockets = coproto::LocalAsyncSocket::makePair();
        PRNG prng(toBlock(71, 29));
        AlignedUnVec<u64> wrongSize(2);
        bool sizeRejected = false;
        try
        {
            if constexpr (std::is_same_v<Party, LogVoleSender>)
                macoro::sync_wait(original.send(senderResources.executor, senderResources.buffers, 1, wrongSize, prng, sockets[0]));
            else
                macoro::sync_wait(original.receive(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc, wrongSize, wrongSize, prng, sockets[0]));
        }
        catch (const std::runtime_error&) { sizeRejected = true; }
        LOGVOLE_REQUIRE_TRUE(sizeRejected);
        LOGVOLE_REQUIRE_FALSE(original.hasOffline());
        LOGVOLE_REQUIRE_EQ(original.requestSize(), 7ull);
        bool rejected = false;
        try { Party incompatible(options, factory); }
        catch (const std::invalid_argument&) { rejected = true; }
        LOGVOLE_REQUIRE_TRUE(rejected);
        LOGVOLE_REQUIRE_TRUE(original.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_FALSE(original.mParams.mLogVole.mEarlyGoldenCheck);
        checkGpu(original.mParams.mLogVole.mShrinkExpand.mGpuSetup, selectedGpu);
        checkTransport(original, false);
        LOGVOLE_REQUIRE_FALSE(strict.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_TRUE(strict.mParams.mLogVole.mEarlyGoldenCheck);
        checkGpu(strict.mParams.mLogVole.mShrinkExpand.mGpuSetup, defaults);
        checkTransport(strict, true);

        Party moved(std::move(original));
        LOGVOLE_REQUIRE_TRUE(moved.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_FALSE(moved.mParams.mLogVole.mEarlyGoldenCheck);
        checkGpu(moved.mParams.mLogVole.mShrinkExpand.mGpuSetup, selectedGpu);
        checkTransport(moved, false);
        Party assigned;
        assigned = std::move(moved);
        LOGVOLE_REQUIRE_TRUE(assigned.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_FALSE(assigned.mParams.mLogVole.mEarlyGoldenCheck);
        checkGpu(assigned.mParams.mLogVole.mShrinkExpand.mGpuSetup, selectedGpu);
        checkTransport(assigned, false);
        assigned.clear();
        assigned = Party(selectedOptions, factory);
        LOGVOLE_REQUIRE_TRUE(assigned.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_FALSE(assigned.mParams.mLogVole.mEarlyGoldenCheck);
        checkGpu(assigned.mParams.mLogVole.mShrinkExpand.mGpuSetup, selectedGpu);
        checkTransport(assigned, false);
        LOGVOLE_REQUIRE_FALSE(strict.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_TRUE(strict.mParams.mLogVole.mEarlyGoldenCheck);
        checkGpu(strict.mParams.mLogVole.mShrinkExpand.mGpuSetup, defaults);
        checkTransport(strict, true);
    };
    // A derived ring with different dimensions retains the supplied owner's settings.
    {
        RingParams ring;
        ring.mPolyModulusDegree = 1024;
        ring.mCoeffModulusBits.resize(2);
        std::fill(ring.mCoeffModulusBits.begin(), ring.mCoeffModulusBits.end(), 30);
        LogVoleExecutionOptions advanced;
        advanced.mAdvanced.mProtocol.mUniformSampling = false;
        advanced.mAdvanced.mProtocol.mShareCache = false;
        RingNttContext first, second;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, first,
            std::make_shared<RingContextFactory>(advanced)));
        ring.mPolyModulusDegree = 2048;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, second, first.mFactoryOwner));
        LOGVOLE_REQUIRE_TRUE(second.mExecutionOptions == advanced);
        LOGVOLE_REQUIRE_TRUE(second.mFactory == first.mFactory);
    }
    check.operator()<LogVoleSender>();
    check.operator()<LogVoleReceiver>();
#if defined(ENABLE_LOGVOLE_CUDA)
    LogVoleGpuProtocolOptions policy;
    LOGVOLE_REQUIRE_TRUE(policy.valid());
    LOGVOLE_REQUIRE_TRUE(gpu::rootFinalizeReceiverPrefetchEnabled(policy));
    LOGVOLE_REQUIRE_TRUE(gpu::deferredGoldenValidationEnabled(policy));
    LOGVOLE_REQUIRE_EQ(gpu::topSenderCt2PrefetchLevels(0, policy), 1u);
    LOGVOLE_REQUIRE_EQ(gpu::topSenderCt2PrefetchLevels(99, policy), 3u);
    LOGVOLE_REQUIRE_EQ(gpu::receiverCt2PrefetchLevels(1, {}, {}, policy), 0u);
    for (int level : {1, 2, 3})
    {
        policy.mSenderCt2PrefetchLevels = level;
        policy.mReceiverCt2PrefetchLevels = level;
        policy.mReceiverCt2Prefetch = LogVoleChoice::Enabled;
        LOGVOLE_REQUIRE_TRUE(policy.valid());
        LOGVOLE_REQUIRE_EQ(gpu::topSenderCt2PrefetchLevels(3, policy), static_cast<u32>(level));
        LOGVOLE_REQUIRE_EQ(gpu::receiverCt2PrefetchLevels(1, {}, {}, policy), static_cast<u32>(level));
    }
    policy.mTopSenderCt2Prefetch = false;
    policy.mReceiverCt2Prefetch = LogVoleChoice::Disabled;
    policy.mRootFinalizePriorityPrefetch = false;
    policy.mDeferredGoldenValidation = false;
    LOGVOLE_REQUIRE_EQ(gpu::topSenderCt2PrefetchLevels(3, policy), 0u);
    LOGVOLE_REQUIRE_EQ(gpu::receiverCt2PrefetchLevels(1, {}, {}, policy), 0u);
    LOGVOLE_REQUIRE_FALSE(gpu::rootFinalizeReceiverPrefetchEnabled(policy));
    LOGVOLE_REQUIRE_FALSE(gpu::deferredGoldenValidationEnabled(policy));
    policy.mSenderCt2PrefetchLevels = 4;
    LOGVOLE_REQUIRE_FALSE(policy.valid());
#endif

}
