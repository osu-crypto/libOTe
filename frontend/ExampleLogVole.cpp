#include "ExampleLogVole.h"
#include "util.h"

#include "libOTe/config.h"

#include <iostream>
#include <vector>

#if defined(ENABLE_LOGVOLE)
#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <stdexcept>
#include <tuple>
#endif

#if defined(ENABLE_LOGVOLE) && defined(COPROTO_ENABLE_BOOST)
#include "coproto/Socket/AsioSocket.h"
#endif

namespace osuCrypto
{
    namespace
    {
        const std::vector<std::string> logvoleTags{ "lv", "logvole", "LogVole" };

#if defined(ENABLE_LOGVOLE)
        // The example exposes the public LogVole wrapper. It chooses the
        // batching prime by bit count and reports the concrete prime with
        // sender.modulus()/receiver.modulus().
        u32 logVoleExamplePlaintextModulusBits(const CLP& cmd)
        {
            const auto plaintextModulusBits = cmd.getOr("p", 55);
            if (plaintextModulusBits < 2 || plaintextModulusBits > 61)
                throw std::runtime_error("LogVole example requires -p in [2, 61]");
            return static_cast<u32>(plaintextModulusBits);
        }

        LogVole::AlignedUnVec<u64> makeLogVoleExampleX(u64 w, u64 modulus)
        {
            LogVole::AlignedUnVec<u64> x(w);
            for (u64 i = 0; i < w; ++i)
                x[i] = (3 * i + 5) % modulus;
            return x;
        }

        // LogVole relation: sender receives b, receiver receives a, and
        // a[i] = b[i] + x[i] * Delta mod p.
        void checkLogVoleExampleRelation(
            span<const u64> x,
            u64 delta,
            span<const u64> keys,
            span<const u64> macs,
            u64 modulus)
        {
            if (keys.size() != x.size() || macs.size() != x.size())
                throw std::runtime_error("LogVole example returned an unexpected output size");

            const seal::Modulus mod(modulus);
            for (u64 i = 0; i < x.size(); ++i)
            {
                const auto expected = LogVole::mulAddMod(x[i], delta, keys[i], mod);
                if (macs[i] != expected)
                    throw std::runtime_error("LogVole example relation check failed");
            }
        }

        void LogVole_local_example(int numVole, int numThreads, std::string tag, const CLP& cmd)
        {
            using namespace LogVole;

            if (numVole == 0)
                numVole = 16;

            if (numVole < 0)
                throw std::runtime_error("LogVole example requires non-negative -n");

            LogVoleSender sender{};
            LogVoleReceiver receiver{};
            const auto plaintextModulusBits = logVoleExamplePlaintextModulusBits(cmd);
            const auto workerThreads = static_cast<u32>(std::max(numThreads, 1));
            sender.configure(static_cast<u64>(numVole), plaintextModulusBits, workerThreads);
            receiver.configure(static_cast<u64>(numVole), plaintextModulusBits, workerThreads);
            const u64 modulus = sender.modulus();
            const auto w = static_cast<u64>(numVole);
            const auto delta = static_cast<u64>(cmd.getOr("delta", 7)) % modulus;
            if (delta == 0)
                throw std::runtime_error("LogVole example requires nonzero delta modulo p");

            auto x = makeLogVoleExampleX(w, modulus);
            auto offlineSockets = coproto::LocalAsyncSocket::makePair();
            PRNG senderPrng(sysRandomSeed());
            PRNG receiverPrng(sysRandomSeed());

            Timer timer;
            const auto begin = timer.setTimePoint("logvole.local.begin");
            // The offline phase fixes Delta and prepares reusable state for
            // sequential online calls with auto-incremented SIDs.
            auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
                sender.offline(delta, senderPrng, offlineSockets[0]),
                receiver.offline(offlineSockets[1])));
            std::get<0>(offlineResult).result();
            std::get<1>(offlineResult).result();

            auto onlineSockets = coproto::LocalAsyncSocket::makePair();
            LogVole::AlignedUnVec<u64> b(w);
            LogVole::AlignedUnVec<u64> a(w);
            // The online phase sends the receiver's digest and returns the
            // matching sender key. The parties then locally expand to w labels.
            auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
                sender.send(b, senderPrng, onlineSockets[0]),
                receiver.receive(x, a, receiverPrng, onlineSockets[1])));
            std::get<0>(onlineResult).result();
            std::get<1>(onlineResult).result();

            checkLogVoleExampleRelation(x, delta, b, a, modulus);

            const auto end = timer.setTimePoint("logvole.local.end");
            const auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
            lout << tag
                 << " local n:" << Color::Green << std::setw(6) << std::setfill(' ') << w << Color::Default
                 << " pbits:" << Color::Green << plaintextModulusBits << Color::Default
                 << " p:" << Color::Green << modulus << Color::Default
                 << " online-bytes:" << Color::Green
                 << (sender.mLastOnlineComm.mBytesSent + sender.mLastOnlineComm.mBytesReceived +
                     receiver.mLastOnlineComm.mBytesSent + receiver.mLastOnlineComm.mBytesReceived)
                 << Color::Default
                 << "   ||   " << Color::Green << milli << " ms" << Color::Default << std::endl;
        }
#endif
    }

    void LogVole_example(Role role, int numVole, int numThreads, std::string ip, std::string tag, const CLP& cmd)
    {
#if defined(ENABLE_LOGVOLE) && defined(COPROTO_ENABLE_BOOST)
        using namespace LogVole;

        if (numVole == 0)
            numVole = 16;

        if (numVole < 0)
            throw std::runtime_error("LogVole example requires non-negative -n");

        const auto plaintextModulusBits = logVoleExamplePlaintextModulusBits(cmd);
        const auto w = static_cast<u64>(numVole);
        const auto workerThreads = static_cast<u32>(std::max(numThreads, 1));

        LogVoleSender sender{};
        LogVoleReceiver receiver{};
        if (role == Role::Sender)
            sender.configure(w, plaintextModulusBits, workerThreads);
        else
            receiver.configure(w, plaintextModulusBits, workerThreads);

        const u64 modulus = role == Role::Sender ? sender.modulus() : receiver.modulus();
        const auto delta = static_cast<u64>(cmd.getOr("delta", 7)) % modulus;
        if (delta == 0)
            throw std::runtime_error("LogVole example requires nonzero delta modulo p");

        auto chl = cp::asioConnect(ip, role == Role::Sender);
        cp::sync_wait(sync(chl, role));

        Timer timer;
        const auto begin = timer.setTimePoint("logvole.begin");

        if (role == Role::Sender)
        {
            LogVole::AlignedUnVec<u64> b(w);
            PRNG prng(sysRandomSeed());
            // Split-role mode mirrors the local example over an asio socket.
            // The receiver must use the same n, plaintext bit count and port.
            cp::sync_wait(sender.offline(delta, prng, chl));
            cp::sync_wait(sender.send(b, prng, chl));

            const auto end = timer.setTimePoint("logvole.end");
            const auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
            lout << tag
                 << " sender n:" << Color::Green << std::setw(6) << std::setfill(' ') << w << Color::Default
                 << " pbits:" << Color::Green << plaintextModulusBits << Color::Default
                 << " p:" << Color::Green << modulus << Color::Default
                 << " online-bytes:" << Color::Green
                 << (sender.mLastOnlineComm.mBytesSent + sender.mLastOnlineComm.mBytesReceived) << Color::Default
                 << "   ||   " << Color::Green << milli << " ms" << Color::Default << std::endl;
        }
        else
        {
            auto x = makeLogVoleExampleX(w, modulus);
            LogVole::AlignedUnVec<u64> a(w);
            PRNG prng(sysRandomSeed());
            // The receiver chooses x locally; the sender receives only the
            // corresponding keys for its Delta.
            cp::sync_wait(receiver.offline(chl));
            cp::sync_wait(receiver.receive(x, a, prng, chl));

            const auto end = timer.setTimePoint("logvole.end");
            const auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
            lout << tag
                 << " receiver n:" << Color::Green << std::setw(6) << std::setfill(' ') << a.size() << Color::Default
                 << " pbits:" << Color::Green << plaintextModulusBits << Color::Default
                 << " p:" << Color::Green << modulus << Color::Default
                 << " online-bytes:" << Color::Green
                 << (receiver.mLastOnlineComm.mBytesSent + receiver.mLastOnlineComm.mBytesReceived) << Color::Default
                 << "   ||   " << Color::Green << milli << " ms" << Color::Default << std::endl;
        }

        cp::sync_wait(chl.flush());
#else
        (void)role;
        (void)numVole;
        (void)numThreads;
        (void)ip;
        (void)tag;
        (void)cmd;
        std::cout << "This example requires LogVole and coproto boost support. Please build libOTe with `-DENABLE_LOGVOLE=ON -DCOPROTO_ENABLE_BOOST=ON`. \n" << LOCATION << std::endl;
#endif
    }

    bool LogVole_Examples(const CLP& cmd)
    {
        if (!cmd.isSet(logvoleTags))
            return false;

        if (cmd.hasValue("r"))
            return runIf(LogVole_example, cmd, logvoleTags);

#if defined(ENABLE_LOGVOLE)
        // Local default:
        //   frontend_libOTe -logvole -n 16 [-p 55] [-delta 7] [-t 1]
        // Use -r 0/1 for the split sender/receiver asio example when
        // COPROTO_ENABLE_BOOST is available.
        const auto n = cmd.isSet("nn")
            ? (1 << cmd.get<int>("nn"))
            : cmd.getOr("n", 0);
        const auto t = cmd.getOr("t", 1);
        LogVole_local_example(n, t, logvoleTags.back(), cmd);
#else
        std::cout << "This example requires LogVole. Please build libOTe with `-DENABLE_LOGVOLE=ON`. \n" << LOCATION << std::endl;
#endif
        return true;
    }
}
