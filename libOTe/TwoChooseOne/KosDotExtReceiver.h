#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "TwoChooseOne/OTExtInterface.h"
#include <array>
#include "Crypto/PRNG.h"
#include "Tools/LinearCode.h"

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

        LinearCode mCode;
        bool mHasBase;
        std::vector<std::array<PRNG, 2>> mGens;

        void setBaseOts(
            ArrayView<std::array<block, 2>> baseSendOts)override;


        std::unique_ptr<OtExtReceiver> split() override;

        void receive(
            const BitVector& choices,
            ArrayView<block> messages,
            PRNG& prng,
            Channel& chl/*,
            std::atomic<u64>& doneIdx*/)override;


    };

}
