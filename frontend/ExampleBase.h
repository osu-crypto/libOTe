#pragma once

#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include "libOTe/Base/naor-pinkas.h"



namespace osuCrypto
{

    template<typename BaseOT>
    void baseOT_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP&)
    {
        IOService ios;
        PRNG prng(sysRandomSeed());

        if (totalOTs == 0)
            totalOTs = 128;

        if (numThreads > 1)
            std::cout << "multi threading for the base OT example is not implemented.\n" << std::flush;

        if (role == Role::Receiver)
        {
            auto chl0 = Session(ios, ip, SessionMode::Server).addChannel();
            BaseOT recv;

            std::vector<block> msg(totalOTs);
            BitVector choice(totalOTs);
            choice.randomize(prng);


            Timer t;
            auto s = t.setTimePoint("base OT start");

            recv.receive(choice, msg, prng, chl0);

            auto e = t.setTimePoint("base OT end");
            auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

            std::cout << tag << " n=" << totalOTs << " " << milli << " ms" << std::endl;
        }
        else
        {

            auto chl1 = Session(ios, ip, SessionMode::Client).addChannel();

            BaseOT send;

            std::vector<std::array<block, 2>> msg(totalOTs);

            send.send(msg, prng, chl1);
        }
    }
}