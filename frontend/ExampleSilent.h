#pragma once

#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"
#include "util.h"
#include <iomanip>

#include "cryptoTools/Network/IOService.h"

namespace osuCrypto
{

    void Silent_example(Role role, u64 numOTs, u64 numThreads, std::string ip, std::string tag, CLP& cmd)
    {
#ifdef ENABLE_SILENTOT

        if (numOTs == 0)
            numOTs = 1 << 20;

        numOTs = numOTs / numThreads;


        // get up the networking
        auto rr = role == Role::Sender ? SessionMode::Server : SessionMode::Client;
        IOService ios;
        Session  ep0(ios, ip, rr);
        PRNG prng(sysRandomSeed());

        // for each thread we need to construct a channel (socket) for it to communicate on.
        std::vector<Channel> chls(numThreads);
        for (u64 i = 0; i < numThreads; ++i)
            chls[i] = ep0.addChannel();

        //bool mal = cmd.isSet("mal");
        SilentOtExtSender sender;
        SilentOtExtReceiver receiver;

        //auto otType = cmd.isSet("noHash") ?
        //    OTType::Correlated :
        //    OTType::Random;

        bool fakeBase = cmd.isSet("fakeBase");

        gTimer.setTimePoint("begin");

        auto routine = [&](int i, int s, SilentBaseType type)
        {
            Timer timer;
            u64 milli=0;
            try {

                if (i != 0)
                    throw RTE_LOC;

                // get a random number generator seeded from the system
                PRNG prng(sysRandomSeed());
                PRNG pp(ZeroBlock);


                if (role == Role::Receiver)
                {
                    gTimer.setTimePoint("recver.thrd.begin");

                    // construct the choices that we want.
                    BitVector choice(numOTs);
                    gTimer.setTimePoint("recver.msg.alloc0");

                    // construct a vector to stored the received messages. 
                    //std::vector<block> msgs(numOTs);
                    //std::unique_ptr<block[]> backing(new block[numOTs]);
                    //span<block> msgs(backing.get(), numOTs);
                    gTimer.setTimePoint("recver.msg.alloc1");


                    receiver.configure(numOTs, s, 1);
                    gTimer.setTimePoint("recver.config");

                    //sync(chls[0], role);
                    if (fakeBase)
                    {
                        auto nn = receiver.baseOtCount();
                        std::vector<std::array<block, 2>> baseSendMsgs(nn);
                        pp.get(baseSendMsgs.data(), baseSendMsgs.size());
                        receiver.setBaseOts(baseSendMsgs, prng, chls[0]);
                    }

                    gTimer.setTimePoint("recver.genBase");
                    sync(chls[i], role);

                    auto b = timer.setTimePoint("start");
                    receiver.setTimePoint("start");
                    // perform  numOTs random OTs, the results will be written to msgs.
                    receiver.silentReceiveInplace(numOTs, prng, chls[i]);

                    receiver.setTimePoint("finish");
                    auto e = timer.setTimePoint("finish");
                    milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
                }
                else
                {
                    gTimer.setTimePoint("sender.thrd.begin");

                    //std::vector<std::array<block, 2>> msgs(numOTs);
                    //std::unique_ptr<block[]> backing(new block[deltaOT ? numOTs : numOTs * 2]);
                    //MatrixView<block> msgs(backing.get(), numOTs, deltaOT ? 1 : 2);
                    gTimer.setTimePoint("sender.msg.alloc");

                    block delta = prng.get<block>();

                    sender.configure(numOTs, s, 1);
                    gTimer.setTimePoint("sender.config");


                    //sync(chls[0], role);
                    if (fakeBase)
                    {
                        auto nn = sender.baseOtCount();
                        BitVector bits(nn);
                        bits.randomize(prng);
                        std::vector<std::array<block, 2>> baseSendMsgs(bits.size());
                        std::vector<block> baseRecvMsgs(bits.size());
                        pp.get(baseSendMsgs.data(), baseSendMsgs.size());
                        for (u64 i = 0; i < bits.size(); ++i)
                            baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];
                        sender.setBaseOts(baseRecvMsgs, bits, chls[0]);
                    }

                    gTimer.setTimePoint("sender.genBase");

                    // construct a vector to stored the random send messages. 

                    // if delta OT is used, then the user can call the following 
                    // to set the desired XOR difference between the zero messages
                    // and the one messages.
                    //
                    //     senders[i].setDelta(some 128 bit delta);
                    //
                    sync(chls[i], role);

                    sender.setTimePoint("start");
                    auto b = timer.setTimePoint("start");
                    // perform the OTs and write the random OTs to msgs.
                    sender.silentSendInplace(delta, numOTs, prng, chls[i]);

                    sender.setTimePoint("finish");
                    auto e = timer.setTimePoint("finish");
                    milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();

                }
            }
            catch (std::exception& e)
            {
                std::cout << e.what() << std::endl;
            }
            catch (...)
            {
                std::cout << "unknown exception" << std::endl;

            }
            return milli;
        };

        cmd.setDefault("s", "2");
        cmd.setDefault("sec", "128");
        auto mulType = (MultType)cmd.getOr("multType", (int)MultType::QuasiCyclic);
        std::vector<int> ss = cmd.getMany<int>("s");
        //std::vector<int> secs = cmd.getMany<int>("sec");
        int sec = 128;
        u64 trials = cmd.getOr("trials", 1);
        std::vector< SilentBaseType> types;

        receiver.mMultType = mulType;
        sender.mMultType = mulType;


        if (cmd.isSet("base"))
            types.push_back(SilentBaseType::Base);
        else if (cmd.isSet("baseExtend"))
            types.push_back(SilentBaseType::BaseExtend);
        else
            types.push_back(SilentBaseType::BaseExtend);
        //if (cmd.isSet("extend"))
        //	types.push_back(SilentBaseType::Extend);
        //if (types.size() == 0 || cmd.isSet("none"))
        //	types.push_back(SilentBaseType::None);


        for (auto s : ss)
            for (auto type : types)
            {
                for (u64 tt = 0; tt < trials; ++tt)
                {

                    chls[0].resetStats();

                    Timer sendTimer, recvTimer;

                    sendTimer.setTimePoint("start");
                    recvTimer.setTimePoint("start");

                    sender.setTimer(sendTimer);
                    receiver.setTimer(recvTimer);


                    std::vector<std::thread> thrds;
                    for (u64 i = 1; i < numThreads; ++i)
                        thrds.emplace_back(routine, (int)i, (int)s, type);

                    auto milli = routine(0, s, type);

                    for (auto& tt : thrds)
                        tt.join();

                    u64 com = 0;
                    for (auto& c : chls)
                        com += (c.getTotalDataRecv() + c.getTotalDataSent());

                    std::string typeStr = "n ";
                    switch (type)
                    {
                    case SilentBaseType::Base:
                        typeStr = "b ";
                        break;
                        //case SilentBaseType::Extend:
                        //	typeStr = "e ";
                        //	break;
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
                            " sec: " << Color::Green << std::setw(3) << std::setfill(' ') << sec << Color::Default <<
                            " s: " << Color::Green << s << Color::Default <<
                            "   ||   " << Color::Green <<
                            std::setw(6) << std::setfill(' ') << milli << " ms   " <<
                            std::setw(6) << std::setfill(' ') << com << " bytes" << std::endl << Color::Default;

                        if (cmd.getOr("v", 0) > 1)
                            lout << gTimer << std::endl;

                    }
                    if (cmd.isSet("v"))
                    {
                        if (role == Role::Sender)
                            lout << " **** sender ****\n" << sendTimer << std::endl;

                        if (role == Role::Receiver)
                            lout << " **** receiver ****\n" << recvTimer << std::endl;
                    }
                }

            }

#endif
    }


}