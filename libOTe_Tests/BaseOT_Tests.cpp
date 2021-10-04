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

    void Bot_NaorPinkas_Test()
    {
#ifdef ENABLE_NP
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);

        std::thread thrd = std::thread([&]() {
            setThreadName("receiver");

            NaorPinkas baseOTs;
            baseOTs.send(sendMsg, prng1, recvChannel, 1);
        });

        NaorPinkas baseOTs;

        baseOTs.receive(choices, recvMsg, prng0, senderChannel, 1);

        thrd.join();


        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i << std::endl;
                throw UnitTestFail();
            }
        }
#else
        throw UnitTestSkipped("NaorPinkas OT not enabled. Requires libsodium or Relic");
#endif
    }


    void Bot_Simplest_Test()
    {
#ifdef ENABLE_SIMPLESTOT
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);


        std::thread thrd = std::thread([&]() {
            setThreadName("receiver");
            SimplestOT baseOTs;
            baseOTs.send(sendMsg, prng1, recvChannel);

        });

        SimplestOT baseOTs;
        baseOTs.receive(choices, recvMsg, prng0, senderChannel);

        thrd.join();

        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i <<" exp = m["<< int(choices[i]) <<"], act = " << recvMsg[i] <<" true = " << sendMsg[i][0] << ", " << sendMsg[i][1] <<std::endl;
                throw UnitTestFail();
            }
        }
#else
        throw UnitTestSkipped("Simplest OT not enabled. Requires libsodium, Relic, or the simplest OT ASM library");
#endif
    }


    template<template<typename> class PopfOT, typename DSPopf>
    static void Bot_PopfOT_Test_impl()
    {
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

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

        std::thread thrd = std::thread([&]() {
            setThreadName("receiver");
            PopfOT<DSPopf> baseOTs(popfFactory);
            baseOTs.send(sendMsg, prng1, recvChannel);

        });

        PopfOT<DSPopf> baseOTs(popfFactory);
        baseOTs.receive(choices, recvMsg, prng0, senderChannel);

        thrd.join();

        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i <<" exp = m["<< int(choices[i]) <<"], act = " << recvMsg[i] <<" true = " << sendMsg[i][0] << ", " << sendMsg[i][1] <<std::endl;
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
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST, ENABLE_SSE). Requires libsodium and SSE.");
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
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST). Requires libsodium.");
    }

    void Bot_McQuoidRR_Moeller_F_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST). Requires libsodium.");
    }

    void Bot_McQuoidRR_Moeller_FM_Test()
    {
        throw UnitTestSkipped("McQuoid Rosulek Roy not enabled (ENABLE_MRR_TWIST). Requires libsodium.");
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

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);


        std::thread thrd = std::thread([&]() {
            setThreadName("receiver");
            MasnyRindal baseOTs;
            baseOTs.send(sendMsg, prng1, recvChannel);

        });

        MasnyRindal baseOTs;
        baseOTs.receive(choices, recvMsg, prng0, senderChannel);

        thrd.join();

        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i << " exp = m[" << int(choices[i]) << "], act = " << recvMsg[i] << " true = " << sendMsg[i][0] << ", " << sendMsg[i][1] << std::endl;
                throw UnitTestFail();
            }
        }
#else
        throw UnitTestSkipped("MasnyRindal not enabled. Requires libsodium or Relic.");
#endif
    }

    void Bot_MasnyRindal_Kyber_Test()
    {
#ifdef ENABLE_MR_KYBER
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(4253233465, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);


        std::thread thrd = std::thread([&]() {
            setThreadName("receiver");
            MasnyRindalKyber baseOTs;
            baseOTs.send(sendMsg, prng1, recvChannel);

        });

        MasnyRindalKyber baseOTs;
        baseOTs.receive(choices, recvMsg, prng0, senderChannel);

        thrd.join();

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
