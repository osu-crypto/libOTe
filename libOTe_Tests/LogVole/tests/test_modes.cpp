#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif
#include <tuple>
#include <vector>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

namespace
{
    void checkMode(const CLP& cmd, CivoleSetting setting, OnlineMode mode)
    {
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
        constexpr u64 count = (u64{1} << 18) + 3;
        constexpr u64 delta = 19;
        LogVoleSender originalSender;
        LogVoleReceiver originalReceiver;
        originalSender.configure(count, 55, 2, setting, mode);
        originalReceiver.configure(count, 55, 2, setting, mode);
        originalSender.mKeepOutputOnDevice = device;
        originalReceiver.mKeepOutputOnDevice = device;
        PRNG senderPrng(toBlock(100, 200)), receiverPrng(toBlock(300, 400));
        auto offline = coproto::LocalAsyncSocket::makePair();
        auto setup = macoro::sync_wait(macoro::when_all_ready(
            originalSender.offline(delta, senderPrng, offline[0]),
            originalReceiver.offline(offline[1])));
        std::get<0>(setup).result();
        std::get<1>(setup).result();

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
        for (u64 round = 0; round != 2; ++round)
        {
            for (u64 i = 0; i != count; ++i)
                x[i] = i % 3 == 0 ? 0 : (i % 3 == 1 ? p.value() - 1 : i + round);
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
                    *std::static_pointer_cast<gpu::DeviceScalars>(sender.outputDevice()), keys));
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *std::static_pointer_cast<gpu::DeviceScalars>(receiver.outputDevice()), macs));
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
