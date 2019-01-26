#include "OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/BitVector.h>

void osuCrypto::OtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
{

#ifdef LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    auto count = baseOtCount();
    std::vector<std::array<block, 2>> msgs(count);
    base.send(msgs, prng, chl);

    setBaseOts(msgs, prng, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif
}

void osuCrypto::OtExtSender::genBaseOts(PRNG & prng, Channel & chl)
{
#ifdef LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    auto count = baseOtCount();
    std::vector<block> msgs(count);
    BitVector bv(count);
    bv.randomize(prng);

    base.receive(bv, msgs, prng, chl);
    setBaseOts(msgs, bv, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

}
