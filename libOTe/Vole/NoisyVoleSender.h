#pragma once

#include <libOTe/config.h>
#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"

namespace osuCrypto
{


    class NoisyVoleSender : public TimerAdapter
    {
    public:


        void send(block x, span<block> z, PRNG& prng, OtReceiver& ot, Channel& chl);
        void send(block x, span<block> z, PRNG& prng, span<block> otMsg, Channel& chl);



    };


}

#endif