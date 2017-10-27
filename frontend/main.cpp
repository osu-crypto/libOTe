#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
int miraclTestMain();

#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/bch511.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

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

    auto rr = i ? EpMode::Server : EpMode::Client;
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);
    std::vector<Channel> chls(numThreads);

    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = ep0.addChannel(name + ToString(k), name + ToString(k));



    u64 baseCount = 4 * 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    block choice = prng0.get<block>();// ((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

    std::vector<std::thread> thds(numThreads);

    if (i == 0)
    {

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtReceiver r;
				r.configure(false, 40, 128);
                r.setBaseOts(baseSend);
                auto& chl = chls[k];

                r.init(otsPer, prng0, chl);
                block encoding1;
                for (u64 i = 0; i < otsPer; i += step)
                {
                    for (u64 j = 0; j < step; ++j)
                    {
                        r.encode(i + j, &choice, &encoding1);
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
				s.configure(false, 40, 128);
                s.setBaseOts(baseRecv, baseChoice);
                auto& chl = chls[k];

                s.init(otsPer, prng0, chl);
                for (u64 i = 0; i < otsPer; i += step)
                {

                    s.recvCorrection(chl, step);

                    for (u64 j = 0; j < step; ++j)
                    {
                        s.encode(i + j, &choice, &encoding2);
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
    auto rr = i ? EpMode::Server : EpMode::Client;

    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);
    std::vector<Channel> chls(numThreads);

    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = ep0.addChannel(name + ToString(k), name + ToString(k));


    LinearCode code;
    code.load(bch511_binary, sizeof(bch511_binary));




    u64 baseCount = 4 * 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    block choice = prng0.get<block>();

    std::vector<std::thread> thds(numThreads);


    if (i == 0)
    {

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                OosNcoOtReceiver r;
                r.configure(true, 40, 76);
                r.setBaseOts(baseSend);
                auto& chl = chls[k];

                r.init(otsPer, prng0, chl);
                block encoding1;
                for (u64 i = 0; i < otsPer; i += step)
                {
                    for (u64 j = 0; j < step; ++j)
                    {
                        r.encode(i + j, &choice, &encoding1);
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
                OosNcoOtSender s;// (code);// = sender[k];
				s.configure(true, 40, 76);
                s.setBaseOts(baseRecv, baseChoice);
                auto& chl = chls[k];

                s.init(otsPer, prng0, chl);
                for (u64 i = 0; i < otsPer; i += step)
                {

                    s.recvCorrection(chl, step);

                    for (u64 j = 0; j < step; ++j)
                    {
                        s.encode(i + j, &choice, &encoding2);
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
        chls[k].close();

    ep0.stop();
    ios.stop();
}


void kos_test(int iii)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 24;


    // get up the networking
    auto rr = iii ? EpMode::Server : EpMode::Client;
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);

    u64 numThread = 1;
    std::vector<Channel> chls(numThread);
    for (u64 i = 0; i < numThread; ++i)
        chls[i] = ep0.addChannel(name + ToString(i), name + ToString(i));

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

                r.receive(choice, msgs, prng, chls[i]);
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

                s.send(msgs, prng, chls[i]);

                gTimer.setTimePoint("finish");
                std::cout << gTimer << std::endl;
            });
        }
    }

    for (u64 i = 0; i < numThread; ++i)
        thrds[i].join();


    for (u64 i = 0; i < numThread; ++i)
        chls[i].close();

    ep0.stop();
    ios.stop();
}


void dkos_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 24;
    auto rr = i ? EpMode::Server : EpMode::Client;


    // get up the networking
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);
    Channel chl = ep0.addChannel(name, name);

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

    auto rr = i ? EpMode::Server : EpMode::Client;

    // get up the networking
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);
    Channel chl = ep0.addChannel(name, name);


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


    auto rr = i ? EpMode::Server : EpMode::Client;
    setThreadName("Recvr");

    IOService ios(0);
    Session   ep0(ios, "127.0.0.1", 1212, rr, "ep");

    u64 numTHreads(4);

    std::vector<Channel> chls(numTHreads);
    for (u64 i = 0; i < numTHreads; ++i)
        chls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

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
        chls[i].close();

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
#include "signalHandle.h"



//
//template<typename, typename T>
//struct has_resize {
//    static_assert(
//        std::integral_constant<T, false>::value,
//        "Second template parameter needs to be of function type.");
//};
//
//// specialization that does the checking
//
//template<typename C, typename Ret, typename... Args>
//struct has_resize<C, Ret(Args...)> {
//private:
//    template<typename T>
//    static constexpr auto check(T*)
//        -> typename
//        std::is_same<
//        decltype(std::declval<T>().resize(std::declval<Args>()...)),
//        Ret    // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//        >::type;  // attempt to call it and see if the return type is correct
//
//    template<typename>
//    static constexpr std::false_type check(...);
//
//    typedef decltype(check<C>(0)) type;
//
//public:
//    static constexpr bool value = type::value;
//};
//
//
//template<typename> struct int_ { typedef int type; };
//
//template <class Container,
//    class = std::enable_if_t<
//        std::is_convertible<typename Container::pointer,
//            decltype(std::declval<Container>().data())>::value &&
//        std::is_convertible<typename Container::size_type,
//            decltype(std::declval<Container>().size())>::value &&
//        has_resize<Container,void(u64)>::value
//    > // enable if
//    //,typename int_<decltype(Container::resize)>::type = 0
//> // template
//void recv(Container& c)
//{
//    //asyncRecv(c).get();
//}
//#include <iostream>
//#include <utility>
//#include <type_traits>
//
////template<typename C,
////    typename int_<decltype(C::resize)>::type = 0>
////    void recv(C&)
////{
////
////}
////
////&&
////std::is_same<int_<decltype(Container::resize)>::type, std::true_type>::value
//
//struct foo {
//    int    memfun1(int a) const { return a; }
//    double memfun2(double b) const { return b; }
//};
//

void base()
{

    IOService ios(0);
    Session   ep0(ios, "127.0.0.1", 1212, EpMode::Server, "ep");
    Session   ep1(ios, "127.0.0.1", 1212, EpMode::Client, "ep");

    auto chl1 = ep1.addChannel("s");
    auto chl0 = ep0.addChannel("s");


    NaorPinkas send, recv;


    auto thrd = std::thread([&]() {

        std::array<std::array<block, 2>, 128> msg;
        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < 10; ++i)
            send.send(msg, prng, chl0);
    });


    std::array<block, 128> msg;
    PRNG prng(ZeroBlock);
    BitVector choice(128);

    Timer t;
    t.setTimePoint("s");
    for (u64 i = 0; i < 10; ++i)
    {

        recv.receive(choice, msg, prng, chl1);
        t.setTimePoint("e");


    }
    std::cout << t << std::endl;


    thrd.join();

    chl1.close();
    chl0.close();

}

#include <cryptoTools/gsl/span>

#include <cryptoTools/Common/Matrix.h>

int main(int argc, char** argv)
{

    CLP cmd;
    cmd.parse(argc, argv);


    if (cmd.isSet(unitTestTag))
    {
        tests_cryptoTools::tests_all();
        tests_libOTe::tests_all();
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
			<< "to run the KKRT16 passive secure 1-out-of-N OT for N=2^128, run\n\n"
			<< "    frontend.exe -kkrt\n\n"
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
