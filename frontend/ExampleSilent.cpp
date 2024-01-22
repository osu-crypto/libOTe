
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "util.h"
#include <iomanip>

#include "cryptoTools/Network/IOService.h"
#include "coproto/Socket/AsioSocket.h"

namespace osuCrypto
{

    void Silent_example(Role role, u64 numOTs, u64 numThreads, std::string ip, std::string tag, const CLP& cmd)
    {
#if defined(ENABLE_SILENTOT) && defined(COPROTO_ENABLE_BOOST)

        if (numOTs == 0)
            numOTs = 1 << 20;

        // get up the networking
        auto chl = cp::asioConnect(ip, role == Role::Sender);


        PRNG prng(sysRandomSeed());

        bool fakeBase = cmd.isSet("fakeBase");
        u64 trials = cmd.getOr("trials", 1);
        auto malicious = cmd.isSet("mal") ? SilentSecType::Malicious : SilentSecType::SemiHonest;

        auto multType = (MultType)cmd.getOr("multType", (int)DefaultMultType);

        std::vector<SilentBaseType> types;
        if (cmd.isSet("base"))
            types.push_back(SilentBaseType::Base);
        else
            types.push_back(SilentBaseType::BaseExtend);

        macoro::thread_pool threadPool;
        auto work = threadPool.make_work();
        if (numThreads > 1)
            threadPool.create_threads(numThreads);

        for (auto type : types)
        {
            for (u64 tt = 0; tt < trials; ++tt)
            {
                Timer timer;
                auto start = timer.setTimePoint("start");
                if (role == Role::Sender)
                {
                    SilentOtExtSender sender;

                    // optionally request the LPN encoding matrix.
                    sender.mMultType = multType;

                    // optionally configure the sender. default is semi honest security.
                    sender.configure(numOTs, 2, numThreads, malicious);

                    if (fakeBase)
                    {
                        auto nn = sender.baseOtCount();
                        BitVector bits(nn);
                        bits.randomize(prng);
                        std::vector<std::array<block, 2>> baseSendMsgs(bits.size());
                        std::vector<block> baseRecvMsgs(bits.size());

                        auto commonPrng = PRNG(ZeroBlock);
                        commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
                        for (u64 i = 0; i < bits.size(); ++i)
                            baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];

                        sender.setBaseOts(baseRecvMsgs, bits);
                    }
                    else
                    {
                        // optional. You can request that the base ot are generated either
                        // using just base OTs (few rounds, more computation) or 128 base OTs and then extend those.
                        // The default is the latter, base + extension.
                        cp::sync_wait(sender.genSilentBaseOts(prng, chl, type == SilentBaseType::BaseExtend));
                    }

                    std::vector<std::array<block, 2>> messages(numOTs);

                    // create the protocol object.
                    auto protocol = sender.silentSend(messages, prng, chl);

                    // run the protocol
                    if (numThreads <= 1)
                        cp::sync_wait(protocol);
                    else
                        // launch the protocol on the thread pool.
                        cp::sync_wait(std::move(protocol) | macoro::start_on(threadPool));

                    // messages has been populated with random OT messages.
                    // See the header for other options.
                }
                else
                {

                    SilentOtExtReceiver recver;

                    // optionally request the LPN encoding matrix.
                    recver.mMultType = multType;

                    // configure the sender. optional for semi honest security...
                    recver.configure(numOTs, 2, numThreads, malicious);

                    if (fakeBase)
                    {
                        auto nn = recver.baseOtCount();
                        BitVector bits(nn);
                        bits.randomize(prng);
                        std::vector<std::array<block, 2>> baseSendMsgs(bits.size());
                        std::vector<block> baseRecvMsgs(bits.size());

                        auto commonPrng = PRNG(ZeroBlock);
                        commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
                        for (u64 i = 0; i < bits.size(); ++i)
                            baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];

                        recver.setBaseOts(baseSendMsgs);
                    }
                    else
                    {
                        // optional. You can request that the base ot are generated either
                        // using just base OTs (few rounds, more computation) or 128 base OTs and then extend those.
                        // The default is the latter, base + extension.
                        cp::sync_wait(recver.genSilentBaseOts(prng, chl, type == SilentBaseType::BaseExtend));
                    }

                    std::vector<block> messages(numOTs);
                    BitVector choices(numOTs);

                    // create the protocol object.
                    auto protocol = recver.silentReceive(choices, messages, prng, chl);

                    // run the protocol
                    if (numThreads <= 1)
                        cp::sync_wait(protocol);
                    else
                        // launch the protocol on the thread pool.
                        cp::sync_wait(std::move(protocol) | macoro::start_on(threadPool));

                    // choices, messages has been populated with random OT messages.
                    // messages[i] = sender.message[i][choices[i]]
                    // See the header for other options.
                }
                auto end = timer.setTimePoint("end");
                auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                u64 com = chl.bytesReceived() + chl.bytesSent();

                if (role == Role::Sender)
                {
                    std::string typeStr = type == SilentBaseType::Base ? "b " : "be ";
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

        cp::sync_wait(chl.flush());

#endif
    }
    bool Silent_Examples(const CLP& cmd)
    {
        return runIf(Silent_example, cmd, Silent);
    }


}
