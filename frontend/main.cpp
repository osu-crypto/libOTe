#include <iostream>

using namespace std;
#include "UnitTests.h" 
#include "cryptoTools/Common/Defines.h"
using namespace osuCrypto;

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include "cryptoTools/Network/BtChannel.h"
#include "cryptoTools/Network/BtEndpoint.h"
#include <numeric>
#include "cryptoTools/Common/Log.h"
int miraclTestMain();

#include "libOTe/Tools/LinearCode.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"
#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"

#include "CLP.h"
#include "main.h"



void kkrt_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 step = 1024;
    u64 numOTs = 1 << 24;
    u64 numThreads = 1;

    u64 otsPer = numOTs / numThreads;

    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, i, name);
    std::vector<Channel*> chls(numThreads);

    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = &ep0.addChannel(name + ToString(k), name + ToString(k));



    u64 ncoinputBlkSize = 1, baseCount = 4 * 128;
    u64 codeSize = (baseCount + 127) / 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    std::vector<block> choice(ncoinputBlkSize), correction(codeSize);
    prng0.get((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

    std::vector< thread> thds(numThreads);

    if (i == 0)
    {

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtReceiver r;
                r.setBaseOts(baseSend);
                auto& chl = *chls[k];

                r.init(otsPer);
                block encoding1;
                for (u64 i = 0; i < otsPer; i += step)
                {
                    for (u64 j = 0; j < step; ++j)
                    {
                        r.encode(i + j, choice, encoding1);
                    }

                    r.sendCorrection(chl, step);
                }
                r.check(chl, ZeroBlock);

                chl.close();
            });
        }
        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();
    }
    else
    {
        Timer time;
        time.setTimePoint("start");
        block encoding2;

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtSender s;
                s.setBaseOts(baseRecv, baseChoice);
                auto& chl = *chls[k];

                s.init(otsPer);
                for (u64 i = 0; i < otsPer; i += step)
                {

                    s.recvCorrection(chl, step);

                    for (u64 j = 0; j < step; ++j)
                    {
                        s.encode(i + j, choice, encoding2);
                    }
                }
                s.check(chl, ZeroBlock);
                chl.close();
            });
        }


        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();

        time.setTimePoint("finish");
        std::cout << time << std::endl;
    }


    //for (u64 k = 0; k < numThreads; ++k)
        //chls[k]->close();

    ep0.stop();
    ios.stop();
}


void oos_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 step = 1024;
    u64 numOTs = 1 << 24;
    u64 numThreads = 1;

    u64 otsPer = numOTs / numThreads;

    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, i, name);
    std::vector<Channel*> chls(numThreads);

    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = &ep0.addChannel(name + ToString(k), name + ToString(k));


    LinearCode code;
    code.loadBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");




    u64 ncoinputBlkSize = 1, baseCount = 4 * 128;
    u64 codeSize = (baseCount + 127) / 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    std::vector<block> choice(ncoinputBlkSize), correction(codeSize);
    prng0.get((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

    std::vector< thread> thds(numThreads);


    if (i == 0)
    {

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                OosNcoOtReceiver r(code, 40);
                r.setBaseOts(baseSend);
                auto& chl = *chls[k];

                r.init(otsPer);
                block encoding1;
                for (u64 i = 0; i < otsPer; i += step)
                {
                    for (u64 j = 0; j < step; ++j)
                    {
                        r.encode(i + j, choice, encoding1);
                    }

                    r.sendCorrection(chl, step);
                }
                r.check(chl, ZeroBlock);
            });
        }
        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();
    }
    else
    {
        Timer time;
        time.setTimePoint("start");
        block  encoding2;

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                OosNcoOtSender s(code, 40);// = sender[k];
                s.setBaseOts(baseRecv, baseChoice);
                auto& chl = *chls[k];

                s.init(otsPer);
                for (u64 i = 0; i < otsPer; i += step)
                {

                    s.recvCorrection(chl, step);

                    for (u64 j = 0; j < step; ++j)
                    {
                        s.encode(i + j, choice, encoding2);
                    }
                }
                s.check(chl, ZeroBlock);
            });
        }


        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();

        time.setTimePoint("finish");
        std::cout << time << std::endl;
    }


    for (u64 k = 0; k < numThreads; ++k)
        chls[k]->close();

    ep0.stop();
    ios.stop();
}


void kos_test(int iii)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 24;


    // get up the networking
    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, iii, name);

    u64 numThread = 1;
    std::vector<Channel*> chls(numThread);
    for (u64 i = 0; i < numThread; ++i)
        chls[i] = &ep0.addChannel(name + ToString(i), name + ToString(i));

    // cheat and compute the base OT in the clear.
    u64 baseCount = 128;
    std::vector<std::vector<block>> baseRecv(numThread);
    std::vector<std::vector<std::array<block, 2>>> baseSend(numThread);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    for (u64 j = 0; j < numThread; ++j)
    {
        baseSend[j].resize(baseCount);
        baseRecv[j].resize(baseCount);
        prng0.get((u8*)baseSend[j].data()->data(), sizeof(block) * 2 * baseSend[j].size());
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseRecv[j][i] = baseSend[j][i][baseChoice[i]];
        }
    } 


    std::vector<std::thread> thrds(numThread);
     
    if (iii)
    { 
        for (u64 i = 0; i < numThread; ++i)
        {
            thrds[i] = std::thread([&, i]()
            {
                PRNG prng(baseSend[i][0][0]);

                BitVector choice(numOTs);
                std::vector<block> msgs(numOTs);
                choice.randomize(prng);
                KosOtExtReceiver r;
                r.setBaseOts(baseSend[i]);

                r.receive(choice, msgs, prng, *chls[i]);
            });
        }
    }
    else
    {
        for (u64 i = 0; i < numThread; ++i)
        {
            thrds[i] = std::thread([&, i]()
            {
                PRNG prng(baseRecv[i][0]);
                std::vector<std::array<block, 2>> msgs(numOTs);
                gTimer.reset();
                gTimer.setTimePoint("start");
                KosOtExtSender s;
                s.setBaseOts(baseRecv[i], baseChoice);

                s.send(msgs, prng, *chls[i]);

                gTimer.setTimePoint("finish");
                std::cout << gTimer << std::endl;
            });
        }
    }

    for (u64 i = 0; i < numThread; ++i)
        thrds[i].join();


    for (u64 i = 0; i < numThread; ++i)
        chls[i]->close();

    ep0.stop();
    ios.stop();
}


void dkos_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 24;


    // get up the networking
    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, i, name);
    Channel& chl = ep0.addChannel(name, name);

    u64 s = 40;
    // cheat and compute the base OT in the clear.
    u64 baseCount = 128 + s;
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }




    if (i)
    {
        BitVector choice(numOTs);
        std::vector<block> msgs(numOTs);
        choice.randomize(prng0);
        KosDotExtReceiver r;
        r.setBaseOts(baseSend);

        r.receive(choice, msgs, prng0, chl);
    }
    else
    {
        std::vector<std::array<block, 2>> msgs(numOTs);
        gTimer.reset();
        gTimer.setTimePoint("start");
        KosDotExtSender s;
        s.setBaseOts(baseRecv, baseChoice);

        s.send(msgs, prng0, chl);

        gTimer.setTimePoint("finish");
        std::cout << gTimer << std::endl;

    }


    chl.close();

    ep0.stop();
    ios.stop();
}



void iknp_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 24;


    // get up the networking
    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, i, name);
    Channel& chl = ep0.addChannel(name, name);


    // cheat and compute the base OT in the clear.
    u64 baseCount = 128;
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }




    if (i)
    {
        BitVector choice(numOTs);
        std::vector<block> msgs(numOTs);
        choice.randomize(prng0);
        IknpOtExtReceiver r;
        r.setBaseOts(baseSend);

        r.receive(choice, msgs, prng0, chl);
    }
    else
    {
        std::vector<std::array<block, 2>> msgs(numOTs);

        Timer time;
        time.setTimePoint("start");
        IknpOtExtSender s;
        s.setBaseOts(baseRecv, baseChoice);

        s.send(msgs, prng0, chl);

        time.setTimePoint("finish");
        std::cout << time << std::endl;

    }


    chl.close();

    ep0.stop();
    ios.stop();
}


void akn_test(int i)
{

    u64 totalOts(149501);
    u64 minOnes(4028);
    u64 avgOnes(5028);
    u64 maxOnes(9363);
    u64 cncThreshold(724);
    double cncProb(0.0999);


    setThreadName("Recvr");

    BtIOService ios(0);
    BtEndpoint  ep0(ios, "127.0.0.1", 1212, i, "ep");

    u64 numTHreads(4);

    std::vector<Channel*> chls(numTHreads);
    for (u64 i = 0; i < numTHreads; ++i)
        chls[i] = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

    PRNG prng(ZeroBlock);

    if (i)
    {
        AknOtSender send;
        LzKosOtExtSender otExtSend;
        send.init(totalOts, cncThreshold, cncProb, otExtSend, chls, prng);
    }
    else
    {

        AknOtReceiver recv;
        LzKosOtExtReceiver otExtRecv;
        recv.init(totalOts, avgOnes, cncProb, otExtRecv, chls, prng);

        if (recv.mOnes.size() < minOnes)
            throw std::runtime_error("");

        if (recv.mOnes.size() > maxOnes)
            throw std::runtime_error("");

    }


    for (u64 i = 0; i < numTHreads; ++i)
        chls[i]->close();

    ep0.stop();
    ios.stop();
}

void code()
{
    PRNG prng(ZeroBlock);
    LinearCode code;
    code.random(prng, 128, 128 * 4);
    u64 n = 1 << 24;

    Timer t;
    t.setTimePoint("start");

    u8* in = new u8[code.plaintextU8Size()];
    u8* out = new u8[code.codewordU8Size()];

    for (u64 i = 0; i < n; ++i)
    {
        code.encode(in, out);
    }

    t.setTimePoint("end");
    std::cout << t << std::endl;
}

static const std::vector<std::string>
unitTestTag{ "u", "unitTest" },
kos{ "k", "kos" },
dkos{ "d", "dkos" },
kkrt{ "kk", "kkrt" },
iknp{ "i", "iknp" },
oos{ "o", "oos" },
akn{ "a", "akn" };

#include "cryptoTools/gsl/gsl.h"
#include "cryptoTools/Common/ByteStream.h"
#include "cryptoTools/Common/Matrix.h"

int main(int argc, char** argv)
{
    //std::vector<u8> data(16);
    //MatrixView<u8> v(data,4);
    ByteStream data(16);
    Matrix<int> mm(7,4);

     //v(data.data(), 4);

    //gsl::multi_span<int, gsl::dynamic_range, gsl::dynamic_range> vv = mm;

    //MatrixView<int> vv2(mm);
    //    gsl::as_multi_span(data.begin(), gsl::dim(4), gsl::dim(4));

    auto v = data.getMultiSpan<u16>(4);
    auto v2 = data.getMultiSpan<u16, 4>();

    auto row = v[0];
    u8 c = row[0];

    auto p = v.data();
    
    auto bb = mm.bounds().stride();
    auto ba = mm.bounds().size();
    auto bc = mm.bounds().index_bounds()[0];
    auto bd = mm.bounds().index_bounds()[1];
    //mm.bounds().index_bounds
    std::cout << v.length() << "  " << v2.length() << std::endl;
    std::cout << v.size() << "  " << v2.size() << std::endl;
    std::cout << row.size() << "  " << v.rank() << std::endl;
    //std::cout << row.size() << "  " << bb << std::endl;
    //ArrayView<u8> c(data);

    //code();
    return 0;
    CLP cmd;
    cmd.parse(argc, argv);


    if (cmd.isSet(unitTestTag))
    {
        run_all();
    }
    else if (cmd.isSet(kos))
    {
        if (cmd.hasValue(kos))
        {
            kos_test(cmd.getInt(kos));
        }
        else
        {
            auto thrd = std::thread([]() { kos_test(0); });
            kos_test(1);
            thrd.join();
        }
    }
    else if (cmd.isSet(dkos))
    {
        if (cmd.hasValue(dkos))
        {
            kos_test(cmd.getInt(dkos));
        }
        else
        {
            auto thrd = std::thread([]() { dkos_test(0); });
            dkos_test(1);
            thrd.join();
        }
    }
    else if (cmd.isSet(kkrt))
    {
        if (cmd.hasValue(kkrt))
        {
            kkrt_test(cmd.getInt(kkrt));
        }
        else
        {
            auto thrd = std::thread([]() { kkrt_test(0); });
            kkrt_test(1);
            thrd.join();
        }
    }
    else if (cmd.isSet(iknp))
    {
        if (cmd.hasValue(iknp))
        {
            iknp_test(cmd.getInt(iknp));
        }
        else
        {
            auto thrd = std::thread([]() { iknp_test(0); });
            iknp_test(1);
            thrd.join();
        }
    }
    else if (cmd.isSet(oos))
    {
        if (cmd.hasValue(oos))
        {
            oos_test(cmd.getInt(oos));
        }
        else
        {
            auto thrd = std::thread([]() { oos_test(0); });
            oos_test(1);
            thrd.join();
        }
    }
    else if (cmd.isSet(akn))
    {
        if (cmd.hasValue(akn))
        {
            akn_test(cmd.getInt(akn));
        }
        else
        {
            auto thrd = std::thread([]() { akn_test(0); });
            akn_test(1);
            thrd.join();
        }
    }
    else
    {
        std::cout << "this program takes a runtime argument.\n\nTo run the unit tests, run\n\n"
            << "    frontend.exe -unitTest\n\n"
            << "to run the OOS16 active secure 1-out-of-N OT for N=2^76, run\n\n"
            << "    frontend.exe -oos\n\n"
            << "to run the KOS active secure 1-out-of-2 OT, run\n\n"
            << "    frontend.exe -kos\n\n"
            << "to run the KOS active secure 1-out-of-2 Delta-OT, run\n\n"
            << "    frontend.exe -dkos\n\n"
            << "to run the IKNP passive secure 1-out-of-2 OT, run\n\n"
            << "    frontend.exe -iknp\n\n"
            << "to run the RR16 active secure approximate k-out-of-N OT, run\n\n"
            << "    frontend.exe -akn\n\n"
            << "all of these options can take a value in {0,1} in which case the program will\n"
            << "run between two terminals, where each one was set to the opposite value. e.g.\n\n"
            << "    frontend.exe -iknp 0\n\n"
            << "    frontend.exe -iknp 1\n\n"
            << "These programs are fully networked and try to connect at localhost:1212.\n"
            << std::endl;
    }

    return 0;
}