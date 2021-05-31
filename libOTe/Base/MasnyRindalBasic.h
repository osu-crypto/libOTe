#pragma once
#include "libOTe/config.h"
#include <cryptoTools/Common/Defines.h>
#if defined(ENABLE_MR) && defined(ENABLE_SODIUM)

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{

    class MasnyRindalBasic : public OtReceiver, public OtSender
    {
    public:

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            receive(choices, messages, prng, chl);
        }

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            send(messages, prng, chl);
        }

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) override;

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;
    };

}
#endif
