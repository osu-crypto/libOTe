#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "TwoChooseOne/OTExtInterface.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include "Tools/LinearCode.h"
#include <array>
namespace osuCrypto {

    class KosDotExtSender :
        public OtExtSender
    {
    public: 



        std::vector<PRNG> mGens;
        BitVector mBaseChoiceBits;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }
        LinearCode mCode;
        //BitVector mmChoices;

        std::unique_ptr<OtExtSender> split() override;

        void setBaseOts(
            ArrayView<block> baseRecvOts,
            const BitVector& choices) override;


        void send(
            ArrayView<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;
    };
}

