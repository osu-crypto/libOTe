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

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/CLP.h"
#include "util.h"
#include "coproto/Socket/AsioSocket.h"

namespace osuCrypto
{

    template<typename BaseOT>
    void baseOT_example_from_ot(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP&, BaseOT ot)
    {
#ifdef COPROTO_ENABLE_BOOST
        PRNG prng(sysRandomSeed());

        if (totalOTs == 0)
            totalOTs = 128;

        if (numThreads > 1)
            std::cout << "multi threading for the base OT example is not implemented.\n" << std::flush;

        Timer t;
        Timer::timeUnit s;
        if (role == Role::Receiver)
        {
            auto sock = cp::asioConnect(ip, false);
            BaseOT recv = ot;

            AlignedVector<block> msg(totalOTs);
            BitVector choice(totalOTs);
            choice.randomize(prng);


            s = t.setTimePoint("base OT start");

            coproto::sync_wait(recv.receive(choice, msg, prng, sock));

        }
        else
        {
            auto sock = cp::asioConnect(ip, true);

            BaseOT send = ot;

            AlignedVector<std::array<block, 2>> msg(totalOTs);

            s = t.setTimePoint("base OT start");

            coproto::sync_wait(send.send(msg, prng, sock));
        }

        auto e = t.setTimePoint("base OT end");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        std::cout << tag << (role == Role::Receiver ? " (receiver)" : " (sender)")
            << " n=" << totalOTs << " " << milli << " ms" << std::endl;
#endif
    }

    template<typename BaseOT>
    void baseOT_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp)
    {
        return baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, BaseOT());
    }
}
