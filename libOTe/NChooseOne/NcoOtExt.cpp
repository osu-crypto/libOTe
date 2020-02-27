#include "NcoOtExt.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Network/Channel.h>

void osuCrypto::NcoOtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
{
    auto count = getBaseOTCount();
    std::vector<std::array<block, 2>> msgs(count);

#ifdef ENABLE_IKNP
    if (!isMalicious())
    {
        IknpOtExtSender sender;
        sender.genBaseOts(prng, chl);
        sender.send(msgs, prng, chl);
        setBaseOts(msgs, prng, chl);
        return;
}
#endif

#ifdef ENABLE_KOS
    KosOtExtSender sender;
    sender.genBaseOts(prng, chl);
    sender.send(msgs, prng, chl);
#elif defined LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    base.send(msgs, prng, chl);
    setBaseOts(msgs, prng, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

    setBaseOts(msgs, prng, chl);
}


void osuCrypto::NcoOtExtSender::genBaseOts(PRNG & prng, Channel & chl)
{
    auto count = getBaseOTCount();
    std::vector<block> msgs(count);
    BitVector bv(count);
    bv.randomize(prng);

#ifdef ENABLE_IKNP
    if (!isMalicious())
    {
        IknpOtExtReceiver recver;
        recver.genBaseOts(prng, chl);
        recver.receive(bv, msgs, prng,  chl);
        setBaseOts(msgs, bv, chl);
        return;
    }
#endif
    
#ifdef ENABLE_KOS
    KosOtExtReceiver recver;
    recver.genBaseOts(prng, chl);
    recver.receive(bv, msgs, prng, chl);
#elif defined LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    base.receive(bv, msgs, prng, chl);
    setBaseOts(msgs, bv, chl);
#else 
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

    setBaseOts(msgs, bv, chl);
}

void osuCrypto::NcoOtExtSender::sendChosen(MatrixView<block> messages, PRNG & prng, Channel & chl)
{
    auto numMsgsPerOT = messages.cols();

    if (hasBaseOts() == false)
        throw std::runtime_error("call configure(...) and genBaseOts(...) first.");
    
    init(messages.rows(), prng, chl);
    recvCorrection(chl);

    if (isMalicious())
        check(chl, prng.get<block>());

    std::array<u64, 2> choice{0,0};
    u64& j = choice[0];

    Matrix<block> temp(messages.rows(), numMsgsPerOT);
    for (u64 i = 0; i < messages.rows(); ++i)
    {
        for (j = 0; j < messages.cols(); ++j)
        {
            encode(i, choice.data(), &temp(i, j));
            temp(i, j) = temp(i, j) ^ messages(i, j);
        }
    }


    chl.asyncSend(std::move(temp));
}

void osuCrypto::NcoOtExtReceiver::receiveChosen(
    u64 numMsgsPerOT, 
    span<block> messages, 
    span<u64> choices, PRNG & prng, Channel & chl)
{
    if (hasBaseOts() == false)
        throw std::runtime_error("call configure(...) and genBaseOts(...) first.");
    
    // must be at least 128 bits.
    std::array<u64, 2> choice{ 0,0 };
    auto& j = choice[0];

    init(messages.size(), prng, chl);

    for (i64 i = 0; i < messages.size(); ++i)
    {
        j = choices[i];
        encode(i, &j, &messages[i]);
    }
    sendCorrection(chl, messages.size());
    Matrix<block> temp(messages.size(), numMsgsPerOT);

    if (isMalicious())
        check(chl, prng.get<block>());

    chl.recv(temp.data(), temp.size());

    for (i64 i = 0; i < messages.size(); ++i)
    {
        messages[i] = messages[i] ^ temp(i, choices[i]);
    }
}
