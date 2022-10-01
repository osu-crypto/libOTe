#include "OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <vector>
#include <cryptoTools/Network/Channel.h>

//void OtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
//{
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
//void OtExtReceiver::genBaseOts(OtSender& base, PRNG& prng, Channel& chl)
//{
//
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(base, prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
//void OtExtSender::genBaseOts(PRNG & prng, Channel & chl)
//{
//
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
//void OtExtSender::genBaseOts(OtReceiver& base, PRNG& prng, Channel& chl)
//{
// 
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(base, prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
namespace osuCrypto
{


    task<> OtExtReceiver::genBaseOts(PRNG& prng, Socket& chl)
    {
#ifdef LIBOTE_HAS_BASE_OT
        MC_BEGIN(task<>,this, &prng, &chl, base = DefaultBaseOT{});
        MC_AWAIT(genBaseOts(base, prng, chl));
        MC_END();
#else
        throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif
    }

    task<> OtExtReceiver::genBaseOts(OtSender& base, PRNG& prng, Socket& chl)
    {
        MC_BEGIN(task<>,&,
            count = baseOtCount(),
            msgs = std::vector<std::array<block, 2>>{}
        );
        msgs.resize(count);
        MC_AWAIT(base.send(msgs, prng, chl));
        setBaseOts(msgs);
        MC_END();
    }

    task<> OtExtSender::genBaseOts(PRNG& prng, Socket& chl)
    {
#ifdef LIBOTE_HAS_BASE_OT
        MC_BEGIN(task<>,&, base = DefaultBaseOT{});
        MC_AWAIT(genBaseOts(base, prng, chl));
        MC_END();
#else
        throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

    }

    task<> OtExtSender::genBaseOts(OtReceiver& base, PRNG& prng, Socket& chl)
    {
        MC_BEGIN(task<>,&,
            count = baseOtCount(),
            msgs = std::vector<block>{},
            bv = BitVector{}
        );
        msgs.resize(count);
        bv.resize(count);
        bv.randomize(prng);
        MC_AWAIT(base.receive(bv, msgs, prng, chl));
        setBaseOts(msgs, bv);

        MC_END();
    }


    task<> OtReceiver::receiveChosen(
        const BitVector& choices,
        span<block> recvMessages,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,&, recvMessages,
            temp = std::vector<std::array<block, 2>>(recvMessages.size())
        );
        MC_AWAIT(receive(choices, recvMessages, prng, chl));
        MC_AWAIT(chl.recv(temp));
        {

            auto iter = choices.begin();
            for (u64 i = 0; i < temp.size(); ++i)
            {
                recvMessages[i] = recvMessages[i] ^ temp[i][*iter];
                ++iter;
            }
        }

        MC_END();
    }

    task<> OtReceiver::receiveCorrelated(const BitVector& choices, span<block> recvMessages, PRNG& prng, Socket& chl)
    {
        MC_BEGIN(task<>,this, &choices, recvMessages, &prng, &chl,
            temp = std::vector<block>(recvMessages.size())
        );

        MC_AWAIT(receive(choices, recvMessages, prng, chl));
        MC_AWAIT(chl.recv(temp));
        {

            auto iter = choices.begin();
            for (u64 i = 0; i < temp.size(); ++i)
            {
                recvMessages[i] = recvMessages[i] ^ (zeroAndAllOne[*iter] & temp[i]);
                ++iter;
            }
        }
        MC_END();
    }

    task<> OtSender::sendChosen(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,
            this, messages, &prng, &chl,
            temp = std::vector<std::array<block, 2>>(messages.size())
        );
        MC_AWAIT(send(temp, prng, chl));

        for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
        {
            temp[i][0] = temp[i][0] ^ messages[i][0];
            temp[i][1] = temp[i][1] ^ messages[i][1];
        }

        MC_AWAIT(chl.send(std::move(temp)));
        MC_END();
    }
}
