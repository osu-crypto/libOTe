#pragma once

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
#include "libOTe/Base/naor-pinkas.h"

#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto
{

    template<typename BaseOT>
    void baseOT_example_from_ot(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP&, BaseOT ot)
    {
        IOService ios;
        PRNG prng(sysRandomSeed());

        if (totalOTs == 0)
            totalOTs = 128;

        if (numThreads > 1)
            std::cout << "multi threading for the base OT example is not implemented.\n" << std::flush;

        Timer t;
        Timer::timeUnit s;
        if (role == Role::Receiver)
        {
            auto chl0 = Session(ios, ip, SessionMode::Server).addChannel();
            chl0.waitForConnection();
            BaseOT recv = ot;

            std::vector<block> msg(totalOTs);
            BitVector choice(totalOTs);
            choice.randomize(prng);


            s = t.setTimePoint("base OT start");

            recv.receive(choice, msg, prng, chl0);
        }
        else
        {

            auto chl1 = Session(ios, ip, SessionMode::Client).addChannel();
            chl1.waitForConnection();

            BaseOT send = ot;

            std::vector<std::array<block, 2>> msg(totalOTs);

            s = t.setTimePoint("base OT start");

            send.send(msg, prng, chl1);
        }

        auto e = t.setTimePoint("base OT end");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        std::cout << tag << (role == Role::Receiver ? " (receiver)" : " (sender)")
            << " n=" << totalOTs << " " << milli << " ms" << std::endl;
    }

    template<typename BaseOT>
    void baseOT_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp)
    {
        return baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, BaseOT());
    }
}
