
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDot/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDot/KosDotExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"


#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "util.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"

namespace osuCrypto
{
#ifdef ENABLE_IKNP
    void noHash(IknpOtExtSender& s, IknpOtExtReceiver& r)
    {
        s.mHash = false;
        r.mHash = false;
    }
#endif

    template<typename Sender, typename Receiver>
    void noHash(Sender&, Receiver&)
    {
        throw std::runtime_error("This protocol does not support noHash");
    }

#ifdef ENABLE_SOFTSPOKEN_OT
    // soft spoken takes an extra parameter as input what determines
    // the computation/communication trade-off.
    template <typename T>
    using is_SoftSpoken = typename std::conditional<
        std::is_same<T, SoftSpokenShOtSender<>>::value ||
        std::is_same<T, SoftSpokenShOtReceiver<>>::value ||
        std::is_same<T, SoftSpokenMalOtSender>::value ||
        std::is_same<T, SoftSpokenMalOtReceiver>::value,
        std::true_type,
        std::false_type>::type;
#else
    template <typename T>
    using is_SoftSpoken = std::false_type;
#endif

    template<typename T>
    typename std::enable_if<is_SoftSpoken<T>::value, T>::type
        construct(const CLP& cmd)
    {
        return T(cmd.getOr("f", 2));
    }

    template<typename T>
    typename std::enable_if<!is_SoftSpoken<T>::value, T>::type
        construct(const CLP& cmd)
    {
        return T{};
    }

    template<typename OtExtSender, typename OtExtRecver>
    void TwoChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, const CLP& cmd)
    {

#ifdef COPROTO_ENABLE_BOOST
        if (totalOTs == 0)
            totalOTs = 1 << 20;

        bool randomOT = true;

        // get up the networking
        auto chl = cp::asioConnect(ip, role == Role::Sender);

        PRNG prng(sysRandomSeed());

        OtExtSender sender = construct<OtExtSender>(cmd);
        OtExtRecver receiver = construct<OtExtRecver>(cmd);

#ifdef LIBOTE_HAS_BASE_OT
        // Now compute the base OTs, we need to set them on the first pair of extenders.
        // In real code you would only have a sender or reciever, not both. But we do
        // here just showing the example.
        if (role == Role::Receiver)
        {
            DefaultBaseOT base;
            std::vector<std::array<block, 2>> baseMsg(receiver.baseOtCount());

            // perform the base To, call sync_wait to block until they have completed.
            cp::sync_wait(base.send(baseMsg, prng, chl));
            receiver.setBaseOts(baseMsg);
        }
        else
        {

            DefaultBaseOT base;
            BitVector bv(sender.baseOtCount());
            std::vector<block> baseMsg(sender.baseOtCount());
            bv.randomize(prng);

            // perform the base To, call sync_wait to block until they have completed.
            cp::sync_wait(base.receive(bv, baseMsg, prng, chl));
            sender.setBaseOts(baseMsg, bv);
        }

#else
        if (!cmd.isSet("fakeBase"))
            std::cout << "warning, base ots are not enabled. Fake base OTs will be used. " << std::endl;
        PRNG commonPRNG(oc::CCBlock);
        if (role == Role::Receiver)
        {
            std::vector<std::array<block, 2>> sendMsgs(receiver.baseOtCount());
            commonPRNG.get(sendMsgs.data(), sendMsgs.size());
            receiver.setBaseOts(sendMsgs);
        }
        else
        {

            std::vector<std::array<block, 2>> sendMsgs(sender.baseOtCount());
            commonPRNG.get(sendMsgs.data(), sendMsgs.size());

            BitVector bv(sendMsgs.size());
            bv.randomize(commonPRNG);
            std::vector<block> recvMsgs(sendMsgs.size());
            for (u64 i = 0; i < sendMsgs.size(); ++i)
                recvMsgs[i] = sendMsgs[i][bv[i]];
            sender.setBaseOts(recvMsgs, bv);
        }
#endif

        if (cmd.isSet("noHash"))
            noHash(sender, receiver);

        Timer timer, sendTimer, recvTimer;
        sendTimer.setTimePoint("start");
        recvTimer.setTimePoint("start");
        auto s = timer.setTimePoint("start");

        if (numThreads == 1)
        {
            if (role == Role::Receiver)
            {
                // construct the choices that we want.
                BitVector choice(totalOTs);
                // in this case pick random messages.
                choice.randomize(prng);

                // construct a vector to stored the received messages.
                AlignedUnVector<block> rMsgs(totalOTs);

                try {

                    if (randomOT)
                    {
                        // perform  totalOTs random OTs, the results will be written to msgs.
                        cp::sync_wait(receiver.receive(choice, rMsgs, prng, chl));
                    }
                    else
                    {
                        // perform  totalOTs chosen message OTs, the results will be written to msgs.
                        cp::sync_wait(receiver.receiveChosen(choice, rMsgs, prng, chl));
                    }
                }
                catch (std::exception& e)
                {
                    std::cout << e.what() << std::endl;
                    chl.close();
                }
            }
            else
            {
                // construct a vector to stored the random send messages.
                AlignedUnVector<std::array<block, 2>> sMsgs(totalOTs);


                // if delta OT is used, then the user can call the following
                // to set the desired XOR difference between the zero messages
                // and the one messages.
                //
                //     senders[i].setDelta(some 128 bit delta);
                //
                try
                {
                    if (randomOT)
                    {
                        // perform the OTs and write the random OTs to msgs.
                        cp::sync_wait(sender.send(sMsgs, prng, chl));
                    }
                    else
                    {
                        // Populate msgs with something useful...
                        prng.get(sMsgs.data(), sMsgs.size());

                        // perform the OTs. The receiver will learn one
                        // of the messages stored in msgs.
                        cp::sync_wait(sender.sendChosen(sMsgs, prng, chl));
                    }
                }
                catch (std::exception& e)
                {
                    std::cout << e.what() << std::endl;
                    chl.close();
                }
            }

        }
        else
        {

            // for multi threading, we only show example for random OTs.
            // We first need to construct the inputs
            // that each thread will use. Note that the actual protocol 
            // is not thread safe so everything needs to be independent.
            std::vector<macoro::eager_task<>> tasks(numThreads);
            std::vector<PRNG> threadPrngs(numThreads);
            std::vector<cp::Socket> threadChls(numThreads);

            macoro::thread_pool::work work;
            macoro::thread_pool threadPool(numThreads, work);

            if (role == Role::Receiver)
            {
                std::vector<OtExtRecver> receivers(numThreads);
                std::vector<BitVector> threadChoices(numThreads);
                std::vector<AlignedUnVector<block>> threadMsgs(numThreads);

                for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
                {
                    u64 beginIndex = oc::roundUpTo(totalOTs * threadIndex / numThreads, 128);
                    u64 endIndex = oc::roundUpTo((totalOTs + 1) * threadIndex / numThreads, 128);

                    threadChoices[threadIndex].resize(endIndex - beginIndex);
                    threadChoices[threadIndex].randomize(prng);

                    threadMsgs[threadIndex].resize(endIndex - beginIndex);

                    // create a copy of the receiver so that each can run 
                    // independently. A single receiver is not thread safe.
                    receivers[threadIndex] = receiver.splitBase();

                    // create a PRNG for this thread.
                    threadPrngs[threadIndex].SetSeed(prng.get<block>());

                    // create a socket for this thread. This is done by calling fork().
                    threadChls[threadIndex] = chl.fork();

                    // start the receive protocol on the thread pool
                    tasks[threadIndex] =
                        receivers[threadIndex].receive(
                            threadChoices[threadIndex],
                            threadMsgs[threadIndex],
                            threadPrngs[threadIndex],
                            threadChls[threadIndex])
                        | macoro::start_on(threadPool);
                }

                // block this thread until the receive operations
                // have completed. 
                for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
                    cp::sync_wait(tasks[threadIndex]);
            }
            else
            {
                std::vector<OtExtSender> senders(numThreads);
                std::vector<AlignedUnVector<std::array<block, 2>>> threadMsgs(numThreads);

                for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
                {
                    u64 beginIndex = oc::roundUpTo(totalOTs * threadIndex / numThreads, 128);
                    u64 endIndex = oc::roundUpTo((totalOTs + 1) * threadIndex / numThreads, 128);

                    threadMsgs[threadIndex].resize(endIndex - beginIndex);

                    // create a copy of the receiver so that each can run 
                    // independently. A single receiver is not thread safe.
                    senders[threadIndex] = sender.splitBase();

                    // create a PRNG for this thread.
                    threadPrngs[threadIndex].SetSeed(prng.get<block>());

                    // create a socket for this thread. This is done by calling fork().
                    threadChls[threadIndex] = chl.fork();

                    // start the send protocol on the thread pool
                    tasks[threadIndex] =
                        senders[threadIndex].send(
                            threadMsgs[threadIndex],
                            threadPrngs[threadIndex],
                            threadChls[threadIndex])
                        | macoro::start_on(threadPool);
                }

                // block this thread until the receive operations
                // have completed. 
                for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
                    cp::sync_wait(tasks[threadIndex]);
            }

            work.reset();
        }


        // make sure all messages have been sent.
        cp::sync_wait(chl.flush());

        auto e = timer.setTimePoint("finish");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        auto com = 0;// (chls[0].getTotalDataRecv() + chls[0].getTotalDataSent())* numThreads;

        if (role == Role::Sender)
            lout << tag << " n=" << Color::Green << totalOTs << " " << milli << " ms  " << com << " bytes" << std::endl << Color::Default;


        if (cmd.isSet("v") && role == Role::Sender)
        {
            if (role == Role::Sender)
                lout << " **** sender ****\n" << sendTimer << std::endl;

            if (role == Role::Receiver)
                lout << " **** receiver ****\n" << recvTimer << std::endl;
        }

#else
        throw std::runtime_error("This example requires coproto to enable boost support. Please build libOTe with `-DCOPROTO_ENABLE_BOOST=ON`. " LOCATION);
#endif
    }




    bool TwoChooseOne_Examples(const CLP& cmd)
    {
        bool flagSet = false;
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
        return flagSet;
    }
}
