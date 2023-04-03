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

        auto sock = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);


        SimplestOT baseOTs0;
        auto p0 = baseOTs0.send(sendMsg, prng1, sock[0]);


        SimplestOT baseOTs;
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
        throw UnitTestSkipped("Simplest OT not enabled. Requires libsodium, or Relic");
#endif
    }


    void Bot_Simplest_asm_Test()
    {
#ifdef ENABLE_SIMPLESTOT_ASM
        setThreadName("Sender");

        setThreadName("Sender");

        auto sock = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;

        {
            AsmSimplestOTTest();
        }

        {

            std::vector<block> recvMsg(numOTs);
            std::vector<std::array<block, 2>> sendMsg(numOTs);
            BitVector choices(numOTs);
            choices.randomize(prng0);

            AsmSimplestOT baseOTs0;
            auto p0 = baseOTs0.send(sendMsg, prng1, sock[0]);

            AsmSimplestOT baseOTs;
            auto p1 = baseOTs.receive(choices, recvMsg, prng0, sock[1]);

            eval(p0, p1);

            for (u64 i = 0; i < numOTs; ++i)
            {
                if (neq(recvMsg[i], sendMsg[i][choices[i]]))
                {
                    std::cout << "***failed " << i << " exp = m[" << int(choices[i]) << "], act = " << recvMsg[i] << " true = " << sendMsg[i][0] << ", " << sendMsg[i][1] << std::endl;
                    throw UnitTestFail();
                }
    }
}
#else
        throw UnitTestSkipped("Simplest OT ASM not enabled");
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


        auto sock = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 50;
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);


        MasnyRindal baseOTs0;
        auto p0 = baseOTs0.send(sendMsg, prng1, sock[0]);

        MasnyRindal baseOTs1;
        auto p1 = baseOTs1.receive(choices, recvMsg, prng0, sock[1]);

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
        throw UnitTestSkipped("MasnyRindal not enabled. Requires libsodium or Relic.");
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
