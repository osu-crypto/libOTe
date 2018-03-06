#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#if defined(__linux__) && not defined(NO_SIMPLEST_OT)
#define ENABLE_SIMPLEST_OT
#endif 


#ifdef ENABLE_SIMPLEST_OT
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>



namespace osuCrypto
{


    class SimplestOT : public OtReceiver, public OtSender
    {
    public:


        //void receive(
        //    const BitVector& choices,
        //    span<block> messages,
        //    PRNG& prng,
        //    Channel& chl,
        //    u64 numThreads);

        //void send(
        //    span<std::array<block, 2>> messages,
        //    PRNG& prng,
        //    Channel& sock,
        //    u64 numThreads);

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) override;

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& sock) override;
    };
}

#endif