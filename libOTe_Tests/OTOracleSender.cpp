#include <unordered_map>
#include "Common/Defines.h"
#include "OTOracleSender.h"
#include "Common/Log.h"
#include <mutex>
#include "Network/Channel.h"


using namespace osuCrypto;

OTOracleSender::OTOracleSender(const block& seed)
    :mPrng(seed)
{
}

OTOracleSender::~OTOracleSender()
{
}




void OTOracleSender::send(
    ArrayView<std::array<block,2>> messages,
    PRNG& prng,
    Channel& chl)
{
    block test = mPrng.get<block>();
    chl.asyncSendCopy((u8*)&test, sizeof(block));

    u64 doneIdx = 0;

    for (doneIdx = 0; doneIdx < messages.size(); ++doneIdx)
    {
        messages[doneIdx][0] = mPrng.get<block>();
        messages[doneIdx][1] = mPrng.get<block>(); 

        //std::cout << " idx  " << doneIdx << "   " << messages[doneIdx][0] << "   " << messages[doneIdx][1] << std::endl;

    }
}

