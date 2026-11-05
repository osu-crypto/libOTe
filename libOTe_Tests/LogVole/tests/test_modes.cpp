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
        struct RestoreBackend
        {
            bool previous = gpu::enabled();
            ~RestoreBackend() { gpu::setEnabled(previous); }
        } restore;
        gpu::setEnabled(device);
        if (device) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
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
        LogVoleSender originalSender;
        LogVoleReceiver originalReceiver;
        auto senderReuse = std::make_shared<ZpContextFactory>();
        auto receiverReuse = std::make_shared<ZpContextFactory>();
        originalSender.configure(count, 55, threads, setting, mode, senderReuse);
        originalReceiver.configure(count, 55, threads, setting, mode, receiverReuse);
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
        for (u64 round = 0; round != rounds; ++round)
        {
            for (u64 i = 0; i != count; ++i)
                x[i] = i % 3 == 0 ? 0 : (i % 3 == 1 ? p.value() - 1 :
                    (randomInputs ? inputPrng.get<u64>() % p.value() : i + round));
            auto online = coproto::LocalAsyncSocket::makePair();
            auto query = macoro::sync_wait(macoro::when_all_ready(
                sender.send(device ? span<u64>{} : span<u64>(keys), senderPrng, online[0]),
                receiver.receive(x, device ? span<u64>{} : span<u64>(macs), receiverPrng, online[1])));
            std::get<0>(query).result();
            std::get<1>(query).result();
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

void LogVole_Modes_PartialRootWidthOptions(const CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    struct RestoreBackend
    {
        bool previous = gpu::enabled();
        ~RestoreBackend() { gpu::setEnabled(previous); }
    } restore;
    gpu::setEnabled(false);
#endif
    const auto check = []<typename Party>() {
        LogVoleOptions options;
        LOGVOLE_REQUIRE_FALSE(options.mAllowPartialRootWidth);
        options.mAllowPartialRootWidth = true;
        Party original(options);
        options.mAllowPartialRootWidth = false; // Constructor owns its copy.
        Party strict;
        auto factory = std::make_shared<ZpContextFactory>();
        const auto configure = [&](Party& party) {
            party.configure(1, 55, 1, CivoleSetting::GoldenSeed,
                OnlineMode::Interactive, factory);
        };
        configure(original);
        configure(strict);
        LOGVOLE_REQUIRE_TRUE(original.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_FALSE(strict.mParams.mLogVole.mAllowPartialRootWidth);

        Party moved(std::move(original));
        LOGVOLE_REQUIRE_TRUE(moved.mParams.mLogVole.mAllowPartialRootWidth);
        Party assigned;
        assigned = std::move(moved);
        LOGVOLE_REQUIRE_TRUE(assigned.mParams.mLogVole.mAllowPartialRootWidth);
        assigned.clear();
        configure(assigned);
        LOGVOLE_REQUIRE_TRUE(assigned.mParams.mLogVole.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_FALSE(strict.mParams.mLogVole.mAllowPartialRootWidth);
    };
    check.operator()<LogVoleSender>();
    check.operator()<LogVoleReceiver>();
}
