#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <array>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Tools/LinearCode.h"

namespace osuCrypto
{

    class KosDotExtReceiver :
        public OtExtReceiver
    {
    public:
        KosDotExtReceiver()
            :mHasBase(false)
        {}

        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        //LinearCode mCode;
        bool mHasBase;
        std::vector<std::array<PRNG, 2>> mGens;

        void setBaseOts(
            span<std::array<block, 2>> baseSendOts)override;


        std::unique_ptr<OtExtReceiver> split() override;

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl/*,
            std::atomic<u64>& doneIdx*/)override;


    };

}
