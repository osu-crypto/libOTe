#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/config.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

#ifdef ENABLE_NP

#if !defined ENABLE_RELIC  && !defined ENABLE_MIRACL
    #error "NaorPinkas requires with Relic or Miracl to be enabled.";
#endif

namespace osuCrypto
{

    class NaorPinkas : public OtReceiver, public OtSender
    {
    public:

        NaorPinkas();
        ~NaorPinkas(); 


        void receive(
            const BitVector& choices, 
            span<block> messages,
            PRNG& prng, 
            Channel& chl, 
            u64 numThreads);

        void send(
            span<std::array<block, 2>> messages, 
            PRNG& prng, 
            Channel& sock, 
            u64 numThreads);

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) override
        {
            receive(choices, messages, prng, chl, 1);
        }

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& sock) override
        {
            send(messages, prng, sock, 1);
        }
    };

}
#endif