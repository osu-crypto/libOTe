#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "TwoChooseOne/OTExtInterface.h"


#include <array>
#include "Crypto/PRNG.h"
#include "Common/BitVector.h"

#ifdef GetMessage
#undef GetMessage
#endif
namespace osuCrypto {

    class Channel;

    class LzKosOtExtSender :
        public OtExtSender
    {
    public: 
        std::array<PRNG, gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

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

