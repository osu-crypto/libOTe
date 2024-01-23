
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
#include "cryptoTools/Common/Timer.h"

namespace osuCrypto
{

    template<typename BaseOT>
    void baseOT_example_from_ot(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const CLP&, BaseOT ot)
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

            // make sure all messages are sent.
            cp::sync_wait(sock.flush());
        }
        else
        {
            auto sock = cp::asioConnect(ip, true);

            BaseOT send = ot;

            AlignedVector<std::array<block, 2>> msg(totalOTs);

            s = t.setTimePoint("base OT start");

            coproto::sync_wait(send.send(msg, prng, sock));


            // make sure all messages are sent.
            cp::sync_wait(sock.flush());
        }



        auto e = t.setTimePoint("base OT end");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        std::cout << tag << (role == Role::Receiver ? " (receiver)" : " (sender)")
            << " n=" << totalOTs << " " << milli << " ms" << std::endl;
#endif
    }

    template<typename BaseOT>
    void baseOT_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const CLP& clp)
    {
        return baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, BaseOT());
    }

    bool baseOT_examples(const CLP& cmd)
    {
        bool flagSet = false;

#ifdef ENABLE_SIMPLESTOT
        flagSet |= runIf(baseOT_example<SimplestOT>, cmd, simple);
#endif

#ifdef ENABLE_SIMPLESTOT_ASM
        flagSet |= runIf(baseOT_example<AsmSimplestOT>, cmd, simpleasm);
#endif

#ifdef ENABLE_MRR_TWIST
#ifdef ENABLE_SSE
        flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const CLP& clp) {
            DomainSepEKEPopf factory;
            const char* domain = "EKE POPF OT example";
            factory.Update(domain, std::strlen(domain));
            baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwist(factory));
            }, cmd, moellerpopf, { "eke" });
#endif

        flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const CLP& clp) {
            DomainSepMRPopf factory;
            const char* domain = "MR POPF OT example";
            factory.Update(domain, std::strlen(domain));
            baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwistMR(factory));
            }, cmd, moellerpopf, { "mrPopf" });

        flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const CLP& clp) {
            DomainSepFeistelPopf factory;
            const char* domain = "Feistel POPF OT example";
            factory.Update(domain, std::strlen(domain));
            baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwistFeistel(factory));
            }, cmd, moellerpopf, { "feistel" });

        flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const  CLP& clp) {
            DomainSepFeistelMulPopf factory;
            const char* domain = "Feistel With Multiplication POPF OT example";
            factory.Update(domain, std::strlen(domain));
            baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwistMul(factory));
            }, cmd, moellerpopf, { "feistelMul" });
#endif

#ifdef ENABLE_MRR
        flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const  CLP& clp) {
            DomainSepFeistelRistPopf factory;
            const char* domain = "Feistel POPF OT example (Risretto)";
            factory.Update(domain, std::strlen(domain));
            baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoy(factory));
            }, cmd, ristrettopopf, { "feistel" });

        flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const  CLP& clp) {
            DomainSepFeistelMulRistPopf factory;
            const char* domain = "Feistel With Multiplication POPF OT example (Risretto)";
            factory.Update(domain, std::strlen(domain));
            baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyMul(factory));
            }, cmd, ristrettopopf, { "feistelMul" });
#endif

#ifdef ENABLE_MR
        flagSet |= runIf(baseOT_example<MasnyRindal>, cmd, mr);
#endif

        return flagSet;
    }

}
