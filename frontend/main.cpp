#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"
#include <cryptoTools/Common/Defines.h>
#include "cryptoTools/Crypto/RandomOracle.h"

using namespace osuCrypto;

#include <string.h>
#include <stdio.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>

#include <iomanip>
#include "util.h"
#include "benchmark.h"

#include "ExampleBase.h"
#include "benchmark.h"
#include "ExampleTwoChooseOne.h"
#include "ExampleNChooseOne.h"
#include "ExampleSilent.h"
#include "ExampleVole.h"
#include "ExampleMessagePassing.h"
#include "libOTe/Tools/LDPC/LdpcImpulseDist.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/Tools/EACode/EAChecker.h"

static const std::vector<std::string>
unitTestTag{ "u", "unitTest" },
kos{ "k", "kos" },
dkos{ "d", "dkos" },
ssdelta{ "ssd", "ssdelta" },
sshonest{ "ss", "sshonest" },
smleakydelta{ "smld", "smleakydelta" },
smalicious{ "sm", "smalicious" },
kkrt{ "kk", "kkrt" },
iknp{ "i", "iknp" },
diknp{ "diknp" },
oos{ "o", "oos" },
moellerpopf{ "p", "moellerpopf" },
ristrettopopf{ "r", "ristrettopopf" },
mr{ "mr" },
mrb{ "mrb" },
Silent{ "s", "Silent" },
vole{ "vole" },
akn{ "a", "akn" },
np{ "np" },
simple{ "simplest" },
simpleasm{ "simplest-asm" };

#ifdef ENABLE_IKNP
void minimal()
{
    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    auto sockets = coproto::LocalAsyncSocket::makePair();

    // The number of OTs.
    int n = 100;

    // The code to be run by the OT receiver.
    auto recverThread = std::thread([&]() {
        PRNG prng(sysRandomSeed());
        IknpOtExtReceiver recver;

        // Choose which messages should be received.
        BitVector choices(n);
        choices[0] = 1;
        //...

        // Receive the messages
        std::vector<block> messages(n);
        auto proto = recver.receiveChosen(choices, messages, prng, sockets[0]);

        coproto::sync_wait(proto);

        // messages[i] = sendMessages[i][choices[i]];
        });

    PRNG prng(sysRandomSeed());
    IknpOtExtSender sender;

    // Choose which messages should be sent.
    std::vector<std::array<block, 2>> sendMessages(n);
    sendMessages[0] = { toBlock(54), toBlock(33) };
    //...

    // Send the messages.
    auto proto = sender.sendChosen(sendMessages, prng, sockets[1]);

    auto r = coproto::sync_wait(macoro::wrap(proto));

    recverThread.join();

    r.value();
}
#endif

void exp(const CLP& cmd)
{
    auto n = cmd.getOr("n", 128);
    auto t = cmd.getOr("t", 16);
    auto t2 = cmd.getOr("t2", t);
    auto reg = cmd.isSet("reg");

    if (n % t)
    {
        std::cout << "t must divide n" << std::endl;
        throw RTE_LOC;
    }
    auto binSize = n / t;

    auto trials = cmd.getOr("trials", 1 << 16);

    PRNG prng(block(432354213, 235346235242));
    std::vector<u64> CTotal(2 * n - 1), C(2 * n - 1), A(n), B(n);
    std::vector<u64> a(t), b(t);
    std::vector<std::vector<u64>> cc(divCeil(CTotal.size(), t2));
    std::unordered_set<u64> ss;

    for (u64 i = 0; i < cc.size(); ++i)
        cc[i].reserve(40);
    for (u64 tt = 0; tt < trials; ++tt)
    {
        std::fill(C.begin(), C.end(), 0);
        if (reg)
        {
            for (u64 j = 0; j < t; ++j)
            {
                a[j] = prng.get<u64>() % binSize + j * binSize;
                ++A[a[j]];
            }
            for (u64 j = 0; j < t; ++j)
            {
                b[j] = prng.get<u64>() % binSize + j * binSize;
                ++B[a[j]];
            }
        }
        else
        {
            ss.clear();
            while (ss.size() != t)
                ss.insert(prng.get<u64>() % n);
            std::copy(ss.begin(), ss.end(), a.begin());
            ss.clear();
            while (ss.size() != t)
                ss.insert(prng.get<u64>() % n);
            std::copy(ss.begin(), ss.end(), b.begin());
        }

        for (u64 j = 0; j < t; ++j)
        {
            for (u64 k = 0; k < t; ++k)
            {
                auto idx = b[j] + a[k];
                ++C[idx];
                ++CTotal[idx];
            }
        }

        for (u64 i = 0; i < C.size(); i += t2)
        {
            u64 load = 0;
            for (u64 j = i; j < std::min<u64>(C.size(), i + t2); ++j)
                load += C[j];

            auto bucket = i / t2;
            auto& ci = cc[bucket];
            if (ci.size() <= load)
                ci.resize(load + 1);

            ++ci[load];
        }
    }


    u64 totalMaxLoad = 0;
    for (u64 j = 0; j < cc.size(); ++j)
    {
        u64 minLoad = 0;
        while (minLoad < cc[j].size() && cc[j][minLoad] == 0)
            ++minLoad;

        std::cout
            << std::setw(4) << std::setfill(' ') << j << ": "
            << std::setw(4) << std::setfill(' ') << minLoad << " "
            << std::setw(4) << std::setfill(' ') << cc[j].size();

        totalMaxLoad += cc[j].size();

        std::cout << " ~ ";
        for (u64 i = 0; i < cc[j].size(); ++i)
        {
            std::cout
                << std::setw(4) << std::setfill(' ') << cc[j][i] << " ";
        }

        std::cout << std::endl;
    }

    std::cout << t * t << " / " << totalMaxLoad << " = " << (t * t) / double(totalMaxLoad) << std::endl;
    std::cout << C.size() << " / " << totalMaxLoad * t2 << " = " << (C.size()) / double(totalMaxLoad * t2) << ", " << 1.0 / ((C.size()) / double(totalMaxLoad * t2)) << "x" << std::endl;
    //for (u64 j = 0; j < CTotal.size(); ++j)
    //{
    //	std::cout
    //		<< std::setw(4) << std::setfill(' ') << j << " "
    //		<< std::setw(10) << std::setfill(' ') << CTotal[j] / double(trials)
    //		<< std::setw(4) << std::setfill(' ') << cc[j].size();


    //	std::cout << " ~ ";
    //	for (u64 i = 0; i < cc[j].size(); ++i)
    //	{
    //		std::cout
    //			<< std::setw(4) << std::setfill(' ') << cc[j][i] << " ";
    //	}

    //	std::cout << std::endl;
    //}
}

int main(int argc, char** argv)
{

    CLP cmd;
    cmd.parse(argc, argv);
    bool flagSet = false;

    exp(cmd);
    return 0;

    // various benchmarks
    if (cmd.isSet("bench"))
    {
        if (cmd.isSet("silver"))
            encodeBench(cmd);
        else if (cmd.isSet("QC"))
            QCCodeBench(cmd);
        else if (cmd.isSet("silent"))
            SilentOtBench(cmd);
        else if (cmd.isSet("ea"))
            EACodeBench(cmd);
        else
            ExConvCodeBench(cmd);
        return 0;
    }


    // minimum distance checker for EA codes.
    if (cmd.isSet("ea"))
    {
        EAChecker(cmd);
        return 0;
    }
#ifdef ENABLE_LDPC
    if (cmd.isSet("ldpc"))
    {
        LdpcDecode_impulse(cmd);
        return 0;
    }
#endif

    // unit tests.
    if (cmd.isSet(unitTestTag))
    {
        flagSet = true;
        auto tests = tests_cryptoTools::Tests;
        tests += tests_libOTe::Tests;

        auto r = tests.runIf(cmd);
        return r == TestCollection::Result::passed ? 0 : -1;
    }

#ifdef ENABE_BOOST
    // compute the network latency.
    if (cmd.isSet("latency"))
    {
        getLatency(cmd);
        flagSet = true;
    }
#endif


    // run various examples.


#ifdef ENABLE_SIMPLESTOT
    flagSet |= runIf(baseOT_example<SimplestOT>, cmd, simple);
#endif

#ifdef ENABLE_SIMPLESTOT_ASM
    flagSet |= runIf(baseOT_example<AsmSimplestOT>, cmd, simpleasm);
#endif

#ifdef ENABLE_MRR_TWIST
#ifdef ENABLE_SSE
    flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp) {
        DomainSepEKEPopf factory;
        const char* domain = "EKE POPF OT example";
        factory.Update(domain, std::strlen(domain));
        baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwist(factory));
        }, cmd, moellerpopf, { "eke" });
#endif

    flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp) {
        DomainSepMRPopf factory;
        const char* domain = "MR POPF OT example";
        factory.Update(domain, std::strlen(domain));
        baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwistMR(factory));
        }, cmd, moellerpopf, { "mrPopf" });

    flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp) {
        DomainSepFeistelPopf factory;
        const char* domain = "Feistel POPF OT example";
        factory.Update(domain, std::strlen(domain));
        baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwistFeistel(factory));
        }, cmd, moellerpopf, { "feistel" });

    flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp) {
        DomainSepFeistelMulPopf factory;
        const char* domain = "Feistel With Multiplication POPF OT example";
        factory.Update(domain, std::strlen(domain));
        baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyTwistMul(factory));
        }, cmd, moellerpopf, { "feistelMul" });
#endif

#ifdef ENABLE_MRR
    flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp) {
        DomainSepFeistelRistPopf factory;
        const char* domain = "Feistel POPF OT example (Risretto)";
        factory.Update(domain, std::strlen(domain));
        baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoy(factory));
        }, cmd, ristrettopopf, { "feistel" });

    flagSet |= runIf([&](Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& clp) {
        DomainSepFeistelMulRistPopf factory;
        const char* domain = "Feistel With Multiplication POPF OT example (Risretto)";
        factory.Update(domain, std::strlen(domain));
        baseOT_example_from_ot(role, totalOTs, numThreads, ip, tag, clp, McRosRoyMul(factory));
    }, cmd, ristrettopopf, { "feistelMul" });
#endif

#ifdef ENABLE_MR
    flagSet |= runIf(baseOT_example<MasnyRindal>, cmd, mr);
#endif

#ifdef ENABLE_IKNP
    flagSet |= runIf(TwoChooseOne_example<IknpOtExtSender, IknpOtExtReceiver>, cmd, iknp);
#endif

#ifdef ENABLE_KOS
    flagSet |= runIf(TwoChooseOne_example<KosOtExtSender, KosOtExtReceiver>, cmd, kos);
#endif

#ifdef ENABLE_DELTA_KOS
    flagSet |= runIf(TwoChooseOne_example<KosDotExtSender, KosDotExtReceiver>, cmd, dkos);
#endif

#ifdef ENABLE_SOFTSPOKEN_OT
    flagSet |= runIf(TwoChooseOne_example<SoftSpokenShOtSender<>, SoftSpokenShOtReceiver<>>, cmd, sshonest);
    flagSet |= runIf(TwoChooseOne_example<SoftSpokenMalOtSender, SoftSpokenMalOtReceiver>, cmd, smalicious);
#endif

#ifdef ENABLE_KKRT
    flagSet |= runIf(NChooseOne_example<KkrtNcoOtSender, KkrtNcoOtReceiver>, cmd, kkrt);
#endif

#ifdef ENABLE_OOS
    flagSet |= runIf(NChooseOne_example<OosNcoOtSender, OosNcoOtReceiver>, cmd, oos);
#endif

    flagSet |= runIf(Silent_example, cmd, Silent);
    flagSet |= runIf(Vole_example, cmd, vole);


    if (cmd.isSet("messagePassing"))
    {
        messagePassingExample(cmd);
        flagSet = 1;
    }




    if (flagSet == false)
    {

        std::cout
            << "#######################################################\n"
            << "#                      - libOTe -                     #\n"
            << "#               A library for performing              #\n"
            << "#                  oblivious transfer.                #\n"
            << "#                     Peter Rindal                    #\n"
            << "#######################################################\n" << std::endl;


        std::cout
            << "Protocols:\n"
            << Color::Green << "  -simplest-asm   " << Color::Default << "  : to run the ASM-SimplestOT  active secure       1-out-of-2  base OT      " << Color::Red << (spaEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -simplest       " << Color::Default << "  : to run the SimplestOT      active secure       1-out-of-2  base OT      " << Color::Red << (spEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -moellerpopf    " << Color::Default << "  : to run the McRosRoyTwist   active secure       1-out-of-2  base OT      " << Color::Red << (popfotMoellerEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -ristrettopopf  " << Color::Default << "  : to run the McRosRoy        active secure       1-out-of-2  base OT      " << Color::Red << (popfotRistrettoEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -mr             " << Color::Default << "  : to run the MasnyRindal     active secure       1-out-of-2  base OT      " << Color::Red << (mrEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -np             " << Color::Default << "  : to run the NaorPinkas      active secure       1-out-of-2  base OT      " << Color::Red << (npEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -iknp           " << Color::Default << "  : to run the IKNP            passive secure      1-out-of-2       OT      " << Color::Red << (iknpEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -diknp          " << Color::Default << "  : to run the IKNP            passive secure      1-out-of-2 Delta-OT      " << Color::Red << (diknpEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -Silent         " << Color::Default << "  : to run the Silent          passive secure      1-out-of-2       OT      " << Color::Red << (silentEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -kos            " << Color::Default << "  : to run the KOS             active secure       1-out-of-2       OT      " << Color::Red << (kosEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -dkos           " << Color::Default << "  : to run the KOS             active secure       1-out-of-2 Delta-OT      " << Color::Red << (dkosEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -ssdelta        " << Color::Default << "  : to run the SoftSpoken      passive secure      1-out-of-2 Delta-OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -sshonest       " << Color::Default << "  : to run the SoftSpoken      passive secure      1-out-of-2       OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -smleakydelta   " << Color::Default << "  : to run the SoftSpoken      active secure leaky 1-out-of-2 Delta-OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -smalicious     " << Color::Default << "  : to run the SoftSpoken      active secure       1-out-of-2       OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -oos            " << Color::Default << "  : to run the OOS             active secure       1-out-of-N OT for N=2^76 " << Color::Red << (oosEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -kkrt           " << Color::Default << "  : to run the KKRT            passive secure      1-out-of-N OT for N=2^128" << Color::Red << (kkrtEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -messagePassing " << Color::Default << "  : to run the message passing example                                      " << Color::Red << (silentEnabled ? "" : "(disabled)") << "\n\n" << Color::Default

            << "POPF Options:\n"
            << Color::Green << "  -eke            " << Color::Default << "  : to run the EKE POPF (Moeller only)                                  " << "\n" << Color::Default
            << Color::Green << "  -mrPopf         " << Color::Default << "  : to run the MasnyRindal POPF (Moeller only)                          " << "\n" << Color::Default
            << Color::Green << "  -feistel        " << Color::Default << "  : to run the Feistel POPF                                             " << "\n" << Color::Default
            << Color::Green << "  -feistelMul     " << Color::Default << "  : to run the Feistel With Multiplication POPF                         " << "\n\n" << Color::Default

            << "SoftSpokenOT options:\n"
            << Color::Green << "  -f              " << Color::Default << "  : the number of bits in the finite field (aka the depth of the PPRF). " << "\n\n" << Color::Default

            << "Other Options:\n"
            << Color::Green << "  -n              " << Color::Default << ": the number of OTs to perform\n"
            << Color::Green << "  -r 0/1          " << Color::Default << ": Do not play both OT roles. r 1 -> OT sender and network server. r 0 -> OT receiver and network client.\n"
            << Color::Green << "  -ip             " << Color::Default << ": the IP and port of the netowrk server, default = localhost:1212\n"
            << Color::Green << "  -t              " << Color::Default << ": the number of threads that should be used\n"
            << Color::Green << "  -u              " << Color::Default << ": to run the unit tests\n"
            << Color::Green << "  -u -list        " << Color::Default << ": to list the unit tests\n"
            << Color::Green << "  -u 1 2 15       " << Color::Default << ": to run the unit tests indexed by {1, 2, 15}.\n"
            << std::endl;
    }

    return 0;
}
