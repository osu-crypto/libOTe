#include "OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/BitVector.h>
#include <vector>
#include <cryptoTools/Network/Channel.h>

void osuCrypto::OtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
{
#ifdef LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    genBaseOts(base, prng, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif
}

void osuCrypto::OtExtReceiver::genBaseOts(OtSender& base, PRNG& prng, Channel& chl)
{
    auto count = baseOtCount();
    auto msgsBacking = allocAlignedBlockArray<std::array<block, 2>>(count);
    span<std::array<block, 2>> msgs(msgsBacking.get(), count);
    base.send(msgs, prng, chl);
    setBaseOts(msgs, prng, chl);
}

void osuCrypto::OtExtSender::genBaseOts(PRNG & prng, Channel & chl)
{
#ifdef LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    genBaseOts(base, prng, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

}

void osuCrypto::OtExtSender::genBaseOts(OtReceiver& base, PRNG& prng, Channel& chl)
{
    auto count = baseOtCount();
    auto msgsBacking = allocAlignedBlockArray(count);
    span<block> msgs(msgsBacking.get(), count);
    BitVector bv(count);
    bv.randomize(prng);
    base.receive(bv, msgs, prng, chl);
    setBaseOts(msgs, bv, prng, chl);
}


void osuCrypto::OtReceiver::receiveChosen(
    const BitVector & choices,
    span<block> recvMessages,
    PRNG & prng,
    Channel & chl)
{
    receive(choices, recvMessages, prng, chl);
    std::vector<std::array<block,2>> temp(recvMessages.size());
    chl.recv(temp.data(), temp.size());
    auto iter = choices.begin();
    for (u64 i = 0; i < temp.size(); ++i)
    {
        recvMessages[i] = recvMessages[i] ^ temp[i][*iter];
        ++iter;
    }
}

void osuCrypto::OtReceiver::receiveCorrelated(const BitVector& choices, span<block> recvMessages, PRNG& prng, Channel& chl)
{
    receive(choices, recvMessages, prng, chl);
    std::vector<block> temp(recvMessages.size());
    chl.recv(temp.data(), temp.size());
    auto iter = choices.begin();

    for (u64 i = 0; i < temp.size(); ++i)
    {
        recvMessages[i] = recvMessages[i] ^ (zeroAndAllOne[*iter] & temp[i]);
        ++iter;
    }

}

void osuCrypto::OtSender::sendChosen(
    span<std::array<block, 2>> messages,
    PRNG & prng,
    Channel & chl)
{
    std::vector<std::array<block, 2>, AlignedBlockAllocator2> temp(messages.size());
    send(temp, prng, chl);

    for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
    {
        temp[i][0] = temp[i][0] ^ messages[i][0];
        temp[i][1] = temp[i][1] ^ messages[i][1];
    }

    chl.asyncSend(std::move(temp));
}
