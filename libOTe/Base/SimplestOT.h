#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

//#if defined(__linux__) && not defined(NO_SIMPLEST_OT)
//#define ENABLE_SIMPLESTOT
//#endif 

#include "libOTe/config.h"


#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

#if defined(ENABLE_SIMPLESTOT) || defined(ENABLE_RELIC) || defined(ENABLE_MIRACL)

#ifdef ENABLE_SIMPLESTOT
    // define that its was already enabled meaning we should use the ASM library
    #define ENABLE_SIMPLEST_ASM_LIB
#else
    #define ENABLE_SIMPLESTOT
#endif

namespace osuCrypto
{


    class SimplestOT : public OtReceiver, public OtSender
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