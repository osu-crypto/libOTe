#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
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

    void NaorPinkasOt_Test_Impl()
    {
#ifdef NAOR_PINKAS
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
        PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

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
        throw UnitTestSkipped("NaorPinkas OT not enabled. Requires Relic or Miracl");
#endif
    }


    void SimplestOT_Test_Impl()
    {
#ifdef ENABLE_SIMPLESTOT
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
        PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

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
        throw UnitTestSkipped("Simplest OT not enabled.");
#endif

    }

}