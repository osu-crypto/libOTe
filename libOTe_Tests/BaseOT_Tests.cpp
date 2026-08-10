#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"

#include "libOTe/Base/McRosRoyTwist.h"
#include "libOTe/Base/McRosRoy.h"

#include "libOTe/Tools/Popf/EKEPopf.h"
#include "libOTe/Tools/Popf/MRPopf.h"
#include "libOTe/Tools/Popf/FeistelPopf.h"
#include "libOTe/Tools/Popf/FeistelMulPopf.h"
#include "libOTe/Tools/Popf/FeistelRistPopf.h"
#include "libOTe/Tools/Popf/FeistelMulRistPopf.h"

#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Edwards25519/Curve25519Backend.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "Common.h"
#include <thread>
#include <vector>
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Common/BitVector.h>
#include "BaseOT_Tests.h"

#ifdef GetMessage
#undef GetMessage
#endif

using namespace osuCrypto;


namespace tests_libOTe
{

    void Bot_Simplest_Test()
    {
#ifdef ENABLE_SIMPLESTOT
        setThreadName("Sender");
        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        const auto run = [&](u64 numOTs, bool uniform)
        {
            auto sock = cp::LocalAsyncSocket::makePair();
            std::vector<block> recvMsg(numOTs);
            std::vector<std::array<block, 2>> sendMsg(numOTs);
            BitVector choices(numOTs);
            choices.randomize(prng0);

            SimplestOT sender;
            SimplestOT receiver;
            sender.mUniformOTs = uniform;
            receiver.mUniformOTs = uniform;
            auto p0 = sender.send(sendMsg, prng1, sock[0]);
            auto p1 = receiver.receive(choices, recvMsg, prng0, sock[1]);
            eval(p0, p1);

            for (u64 i = 0; i < numOTs; ++i)
            {
                if (neq(recvMsg[i], sendMsg[i][choices[i]]))
                {
                    std::cout << "SimplestOT failed at " << i
                        << " of " << numOTs << ", uniform=" << uniform
                        << std::endl;
                    throw UnitTestFail();
                }
            }
        };

        for (const auto numOTs : { 0ull, 1ull, 7ull, 8ull, 9ull, 50ull })
            run(numOTs, true);
        run(9, false);

        // Clearing the cofactor must erase an injected order-two component.
        // Without this, a malicious sender can distinguish the receiver's
        // choice from the torsion component of its response.
        {
            using Point = Edwards25519::Backend::Point;
            using Scalar = Edwards25519::Backend::Scalar;
            std::array<u8, 32> orderTwo;
            orderTwo.fill(0xff);
            orderTwo[0] = 0xec;
            orderTwo[31] = 0x7f;
            Point torsion;
            if (!torsion.fromBytes(orderTwo.data()) ||
                !torsion.clearCofactor().isNeutral())
                throw UnitTestFail(
                    "SimplestOT order-two regression point is invalid");

            std::array<u8, 32> scalarBytes;
            prng0.get(scalarBytes.data(), scalarBytes.size());
            const auto prime = Point::mulGenerator(Scalar(scalarBytes.data()));
            std::array<u8, 32> expected, actual;
            prime.clearCofactor().toBytes(expected.data());
            (prime + torsion).clearCofactor().toBytes(actual.data());
            if (expected != actual)
                throw UnitTestFail(
                    "SimplestOT cofactor clearing retained a torsion component");
        }

        // A pure small-order sender point must be rejected after clearing.
        {
            auto sock = cp::LocalAsyncSocket::makePair();
            std::vector<block> recvMsg(1);
            BitVector choices(1);
            SimplestOT receiver;
            receiver.mUniformOTs = false;
            auto honest = receiver.receive(choices, recvMsg, prng0, sock[1]);
            auto maliciousProtocol = [&]() -> task<> {
                std::vector<u8> orderTwo(32, 0xff);
                orderTwo[0] = 0xec;
                orderTwo[31] = 0x7f;
                co_await sock[0].send(std::move(orderTwo));
            };
            auto malicious = maliciousProtocol();

            bool rejected = false;
            try { eval(honest, malicious); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail(
                    "SimplestOT receiver accepted a small-order sender point");
        }

        // The sender must still reject malformed receiver encodings before
        // applying the cofactor map.
        {
            auto sock = cp::LocalAsyncSocket::makePair();
            std::vector<std::array<block, 2>> sendMsg(1);
            SimplestOT sender;
            sender.mUniformOTs = false;
            auto honest = sender.send(sendMsg, prng1, sock[0]);
            auto malformedProtocol = [&]() -> task<> {
                std::vector<u8> setup(32);
                co_await sock[1].recv(setup);
                std::vector<u8> invalidPoint(32, 0xff);
                co_await sock[1].send(std::move(invalidPoint));
            };
            auto malformed = malformedProtocol();

            bool rejected = false;
            try { eval(honest, malformed); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail(
                    "SimplestOT sender accepted an invalid receiver point");
        }
#else
        throw UnitTestSkipped("Simplest OT not enabled (ENABLE_SIMPLESTOT).");
#endif
    }


    template<template<typename> class PopfOT, typename DSPopf>
    static void Bot_PopfOT_Test_impl()
    {
        setThreadName("Sender");
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);

        DSPopf popfFactory;
        const char* test_domain = "Bot_PopfOT_Test()";
        popfFactory.Update(test_domain, std::strlen(test_domain));

        setThreadName("receiver");
        PopfOT<DSPopf> baseOTs0(popfFactory);
        auto proto0 = baseOTs0.send(sendMsg, prng1, sockets[0]);


        PopfOT<DSPopf> baseOTs1(popfFactory);
        auto proto1 = baseOTs1.receive(choices, recvMsg, prng0, sockets[1]);

        eval(proto0, proto1);

        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i << " exp = m[" << int(choices[i]) << "], act = " << recvMsg[i] << " true = " << sendMsg[i][0] << ", " << sendMsg[i][1] << std::endl;
                throw UnitTestFail();
            }
        }
        }

#if defined(ENABLE_MRR_TWIST) && defined(ENABLE_SSE)
    void Bot_McQuoidRR_Moeller_EKE_Test()
    {
        Bot_PopfOT_Test_impl<details::McRosRoyTwist, DomainSepEKEPopf>();
    }
#else 
    void Bot_McQuoidRR_Moeller_EKE_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST, ENABLE_SSE).");
    }
#endif

#ifdef ENABLE_MRR_TWIST

    void Bot_McQuoidRR_Moeller_MR_Test()
    {
        Bot_PopfOT_Test_impl<details::McRosRoyTwist, DomainSepMRPopf>();
    }

    void Bot_McQuoidRR_Moeller_F_Test()
    {
        Bot_PopfOT_Test_impl<details::McRosRoyTwist, DomainSepFeistelPopf>();
    }

    void Bot_McQuoidRR_Moeller_FM_Test()
    {
        Bot_PopfOT_Test_impl<details::McRosRoyTwist, DomainSepFeistelMulPopf>();
    }
#else 
    void Bot_McQuoidRR_Moeller_MR_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST).");
    }

    void Bot_McQuoidRR_Moeller_F_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST).");
    }

    void Bot_McQuoidRR_Moeller_FM_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST).");
    }
#endif

#ifdef ENABLE_MRR
    void Bot_McQuoidRR_Ristrestto_F_Test()
    {
        Bot_PopfOT_Test_impl<details::McRosRoy, DomainSepFeistelRistPopf>();
    }

    void Bot_McQuoidRR_Ristrestto_FM_Test()
    {
        Bot_PopfOT_Test_impl<details::McRosRoy, DomainSepFeistelMulRistPopf>();
    }
#else

    void Bot_McQuoidRR_Ristrestto_F_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR). Requires libsodium or Relic.");
    }

    void Bot_McQuoidRR_Ristrestto_FM_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR). Requires libsodium or Relic.");
    }
#endif

    void Bot_MasnyRindal_Test()
    {
#ifdef ENABLE_MR
        setThreadName("Sender");

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));
        constexpr std::array<u64, 12> sizes = {
            0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 50};
        for (const auto numOTs : sizes)
        {
            auto sock = cp::LocalAsyncSocket::makePair();
            std::vector<block> recvMsg(numOTs);
            std::vector<std::array<block, 2>> sendMsg(numOTs);
            BitVector choices(numOTs);
            choices.randomize(prng0);

            MasnyRindal sender;
            auto p0 = sender.send(sendMsg, prng1, sock[0]);
            MasnyRindal receiver;
            auto p1 = receiver.receive(choices, recvMsg, prng0, sock[1]);
            eval(p0, p1);

            for (u64 i = 0; i < numOTs; ++i)
            {
                if (neq(recvMsg[i], sendMsg[i][choices[i]]))
                {
                    std::cout << "failed size=" << numOTs << ", OT=" << i
                        << " exp=m[" << int(choices[i]) << "], act=" << recvMsg[i]
                        << " true=" << sendMsg[i][0] << ", " << sendMsg[i][1]
                        << std::endl;
                    throw UnitTestFail();
                }
            }
        }

        // Both wire directions reject non-canonical Edwards25519 encodings.
        {
            auto sock = cp::LocalAsyncSocket::makePair();
            std::vector<std::array<block, 2>> sendMsg(1);
            MasnyRindal sender;
            auto honest = sender.send(sendMsg, prng1, sock[0]);
            auto malformedProtocol = [&]() -> task<> {
                std::vector<u8> senderPoint(32);
                co_await sock[1].recv(senderPoint);
                std::vector<u8> invalidPair(64, 0xff);
                co_await sock[1].send(std::move(invalidPair));
            };
            auto malformed = malformedProtocol();

            bool rejected = false;
            try { eval(honest, malformed); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail("MasnyRindal sender accepted an invalid point");
        }
        {
            auto sock = cp::LocalAsyncSocket::makePair();
            std::vector<block> recvMsg;
            BitVector choices;
            MasnyRindal receiver;
            auto honest = receiver.receive(choices, recvMsg, prng0, sock[1]);
            auto malformedProtocol = [&]() -> task<> {
                std::vector<u8> invalidPoint(32, 0xff);
                co_await sock[0].send(std::move(invalidPoint));
            };
            auto malformed = malformedProtocol();

            bool rejected = false;
            try { eval(honest, malformed); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail("MasnyRindal receiver accepted an invalid point");
        }
#else
        throw UnitTestSkipped("MasnyRindal not enabled (ENABLE_MR).");
#endif
    }

    void Bot_MasnyRindal_Kyber_Test()
    {
#ifdef ENABLE_MR_KYBER
        setThreadName("Sender");


        auto sock = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(4253233465, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);


        MasnyRindalKyber baseOTs0;
        auto p0 = baseOTs0.send(sendMsg, prng1, sock[0]);

        MasnyRindalKyber baseOTs;
        auto p1 = baseOTs.receive(choices, recvMsg, prng0, sock[1]);

        eval(p0, p1);

        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i << " exp = m[" << int(choices[i]) << "], act = " << recvMsg[i] << " true = " << sendMsg[i][0] << ", " << sendMsg[i][1] << std::endl;
                throw UnitTestFail();
            }
        }
#else
        throw UnitTestSkipped("MasnyRindalKyber OT not enabled. Requires linux and Kyber");
#endif
    }

}
