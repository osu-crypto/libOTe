#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MoellerPopfOT.h"
#include "libOTe/Base/RistrettoPopfOT.h"
#include "libOTe/Base/EKEPopf.h"
#include "libOTe/Base/MRPopf.h"
#include "libOTe/Base/FeistelPopf.h"
#include "libOTe/Base/FeistelMulPopf.h"
#include "libOTe/Base/FeistelRistPopf.h"
#include "libOTe/Base/FeistelMulRistPopf.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include <cryptoTools/Common/Log.h>

#include "Common.h"
#include <thread>
#include <vector>
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Common/BitVector.h>

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

    template<template<typename> class PopfOT, typename DSPopf,
             size_t Sfinae = sizeof(PopfOT<DSPopf>)>
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

    template<template<typename> class PopfOT, typename DSPopf, typename... Args>
    static void Bot_PopfOT_Test_impl(Args... args)
    {
        throw UnitTestSkipped("POPF OT not enabled. Requires libsodium.");
    }

    template<template<typename> class PopfOT, typename DSPopf>
    void Bot_PopfOT_Test() {
        Bot_PopfOT_Test_impl<PopfOT, DSPopf>();
    }

    template void Bot_PopfOT_Test<MoellerPopfOT, DomainSepEKEPopf>();
    template void Bot_PopfOT_Test<MoellerPopfOT, DomainSepMRPopf>();
    template void Bot_PopfOT_Test<MoellerPopfOT, DomainSepFeistelPopf>();
    template void Bot_PopfOT_Test<MoellerPopfOT, DomainSepFeistelMulPopf>();
    template void Bot_PopfOT_Test<RistrettoPopfOT, DomainSepFeistelRistPopf>();
    template void Bot_PopfOT_Test<RistrettoPopfOT, DomainSepFeistelMulRistPopf>();


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
