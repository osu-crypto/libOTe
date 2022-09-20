#pragma once

#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "util.h"
#include <iomanip>

#include "cryptoTools/Network/IOService.h"
#include "coproto/Socket/AsioSocket.h"

namespace osuCrypto
{

#ifdef ENABLE_SILENTOT
    namespace {


        task<u64> senderProto(Socket& socket, Timer& timer, SilentBaseType type, u64 numOTs, bool fakeBase)
        {
            MC_BEGIN(task<u64>, &socket, numOTs, fakeBase, &timer,
                milli = u64{ 0 },
                // get a random number generator seeded from the system
                prng = PRNG(sysRandomSeed()),

                delta = block{},
                sender = std::unique_ptr<SilentOtExtSender>{new SilentOtExtSender},
                b = Timer::timeUnit{},
                e = Timer::timeUnit{}
            );

            sender->setTimer(timer);
            timer.setTimePoint("sender.thrd.begin");

            delta = prng.get<block>();

            sender->configure(numOTs);
            timer.setTimePoint("sender.config");


            if (fakeBase)
            {

                auto nn = sender->baseOtCount();
                BitVector bits(nn);
                bits.randomize(prng);
                std::vector<std::array<block, 2>> baseSendMsgs(bits.size());
                std::vector<block> baseRecvMsgs(bits.size());

                auto commonPrng = PRNG(ZeroBlock);
                commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
                for (u64 i = 0; i < bits.size(); ++i)
                    baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];

                sender->setBaseOts(baseRecvMsgs, bits);
            }

            timer.setTimePoint("sender.genBase");

            MC_AWAIT(sync(socket, Role::Sender));

            b = timer.setTimePoint("start");

            // perform the OTs and write the random OTs to msgs.
            MC_AWAIT(sender->silentSendInplace(delta, numOTs, prng, socket));

            e = timer.setTimePoint("finish");
            milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
            MC_RETURN(milli);
            MC_END();
        }

        task<u64> receiverProto(Socket& socket, Timer& timer, SilentBaseType type, u64 numOTs, bool fakeBase)
        {
            MC_BEGIN(task<u64>, &socket, numOTs, fakeBase, &timer,
                milli = u64{ 0 },
                // get a random number generator seeded from the system
                prng = PRNG(sysRandomSeed()),

                // a common prng for fake OTs
                commonPrng = PRNG(ZeroBlock),

                receiver = std::unique_ptr<SilentOtExtReceiver>{new SilentOtExtReceiver },

                // construct the choices that we want.
                choice = BitVector(numOTs),
                b = Timer::timeUnit{},
                e = Timer::timeUnit{}
            );


            receiver->setTimer(timer);

            timer.setTimePoint("recver.thrd.begin");

            receiver->configure(numOTs);

            timer.setTimePoint("recver.config");

            if (fakeBase)
            {
                auto nn = receiver->baseOtCount();
                std::vector<std::array<block, 2>> baseSendMsgs(nn);
                auto commonPrng = PRNG(ZeroBlock);
                commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
                receiver->setBaseOts(baseSendMsgs);
            }

            timer.setTimePoint("recver.genBase");

            MC_AWAIT(sync(socket, Role::Receiver));

            b = timer.setTimePoint("start");

            // perform  numOTs random OTs, the results will be written to msgs.
            MC_AWAIT(receiver->silentReceiveInplace(numOTs, prng, socket));

            e = timer.setTimePoint("finish");

            milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();

            MC_RETURN(milli);
            MC_END();
        }

        task<u64> multiThread(Socket& socket, Timer& timer, SilentBaseType type, u64 numOTs, u64 numThreads, macoro::thread_pool& tp, bool fakeBase, Role role)
        {
            MC_BEGIN(task<u64>, &socket, type, numOTs, fakeBase, &timer, numThreads, &tp, role,
                fu = std::vector<macoro::eager_task<u64>>{ numThreads },
                i = u64{},
                ret = u64{});

            for (i = 0; i < numThreads; ++i)
            {
                if (role == Role::Sender)
                {
                    fu[i] = senderProto(socket, timer, type, numOTs / numThreads, fakeBase) | macoro::start_on(tp);
                }
                else
                {
                    fu[i] = receiverProto(socket, timer, type, numOTs / numThreads, fakeBase) | macoro::start_on(tp);
                         
                }
            }

            for (i = 0; i < numThreads; ++i)
                MC_AWAIT_SET(ret, fu[i]);

            MC_RETURN(ret);
            MC_END();
        }
    }
#endif




    void Silent_example(Role role, u64 numOTs, u64 numThreads, std::string ip, std::string tag, CLP& cmd)
    {
#if defined(ENABLE_SILENTOT) && defined(COPROTO_ENABLE_BOOST)

        if (numOTs == 0)
            numOTs = 1 << 20;

        // get up the networking
        auto chl = cp::asioConnect(ip, role == Role::Sender);


        PRNG prng(sysRandomSeed());

        bool fakeBase = cmd.isSet("fakeBase");
        u64 trials = cmd.getOr("trials", 1);

        std::vector< SilentBaseType> types;
        if (cmd.isSet("base"))
            types.push_back(SilentBaseType::Base);
        else if (cmd.isSet("baseExtend"))
            types.push_back(SilentBaseType::BaseExtend);
        else
            types.push_back(SilentBaseType::BaseExtend);

        for (auto type : types)
        {
            for (u64 tt = 0; tt < trials; ++tt)
            {
                Timer timer;

                timer.setTimePoint("start");
                u64 milli;
                if (numThreads > 1)
                {
                    macoro::thread_pool tp;
                    auto work = tp.make_work();
                    tp.create_threads(numThreads);
                    auto protocol = multiThread(chl, timer, type, numOTs, numThreads, tp, fakeBase, role);
                    milli = coproto::sync_wait(protocol);
                }
                else
                {
                    if (role == Role::Sender)
                        milli = coproto::sync_wait(senderProto(chl, timer, type, numOTs, fakeBase));
                    else
                        milli = coproto::sync_wait(receiverProto(chl, timer, type, numOTs, fakeBase));
                }


                u64 com = 0/*(c.getTotalDataRecv() + c.getTotalDataSent())*/;

                std::string typeStr = "n ";
                switch (type)
                {
                case SilentBaseType::Base:
                    typeStr = "b ";
                    break;
                case SilentBaseType::BaseExtend:
                    typeStr = "be";
                    break;
                default:
                    break;
                }
                if (role == Role::Sender)
                {

                    lout << tag <<
                        " n:" << Color::Green << std::setw(6) << std::setfill(' ') << numOTs << Color::Default <<
                        " type: " << Color::Green << typeStr << Color::Default <<
                        "   ||   " << Color::Green <<
                        std::setw(6) << std::setfill(' ') << milli << " ms   " <<
                        std::setw(6) << std::setfill(' ') << com << " bytes" << std::endl << Color::Default;

                    if (cmd.getOr("v", 0) > 1)
                        lout << gTimer << std::endl;

                }
                if (cmd.isSet("v"))
                {
                    if (role == Role::Sender)
                        lout << " **** sender ****\n" << timer << std::endl;

                    if (role == Role::Receiver)
                        lout << " **** receiver ****\n" << timer << std::endl;
                }
            }

        }

#endif
	}


}
