#include "OTOracleReceiver.h"
#include "Common/Exceptions.h"
#include "Common/Log.h"
#include "Common/BitVector.h"

using namespace osuCrypto;


OTOracleReceiver::OTOracleReceiver(const block& seed)
    :mPrng(seed)
{
}

OTOracleReceiver::~OTOracleReceiver()
{
}




void OTOracleReceiver::receive(
    const BitVector& choices,
    ArrayView<block> messages,
    PRNG& prng,
    Channel& chl)
{
    block test = mPrng.get<block>(); 

    std::array<block, 2> ss;

    for (u64 doneIdx = 0; doneIdx < messages.size(); ++doneIdx)
    {
        ss[0] = mPrng.get<block>();
        ss[1] = mPrng.get<block>();

        messages[doneIdx] =  ss[choices[doneIdx]]; 

        //std::cout << " idx  " << doneIdx << "   " << messages[doneIdx] << "   " << (u32)choices[doneIdx] << std::endl;
    }
    block test2;
    chl.recv((u8*)&test2, sizeof(block));
    if (neq(test, test2))
        throw std::runtime_error("");

}
