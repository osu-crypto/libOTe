#include "NcoOtExt.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"

void osuCrypto::NcoOtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
{
    auto count = getBaseOTCount();
    std::vector<std::array<block, 2>> msgs(count);

    if (isMalicious())
    {
        KosOtExtSender sender;
        sender.genBaseOts(prng, chl);
        sender.send(msgs, prng, chl);
    }
    else
    {
        IknpOtExtSender sender;
        sender.genBaseOts(prng, chl);
        sender.send(msgs, prng, chl);
    }

    setBaseOts(msgs, prng, chl);

}

void osuCrypto::NcoOtExtSender::genBaseOts(PRNG & prng, Channel & chl)
{
    auto count = getBaseOTCount();
    std::vector<block> msgs(count);
    BitVector bv(count);
    bv.randomize(prng);

    if (isMalicious())
    {
        KosOtExtReceiver recver;
        recver.genBaseOts(prng, chl);
        recver.receive(bv, msgs, prng, chl);
    }
    else
    {
        IknpOtExtReceiver recver;
        recver.genBaseOts(prng, chl);
        recver.receive(bv, msgs, prng,  chl);
    }

    setBaseOts(msgs, bv, chl);
}
