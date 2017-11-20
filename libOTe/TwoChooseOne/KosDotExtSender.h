#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Tools/LinearCode.h"
#include <array>
namespace osuCrypto {

    class KosDotExtSender :
        public OtExtSender
    {
    public: 


		block mDelta = ZeroBlock;
        std::vector<PRNG> mGens;
        BitVector mBaseChoiceBits;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }
        //LinearCode mCode;
        //BitVector mmChoices;

        std::unique_ptr<OtExtSender> split() override;

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;

		void setDelta(const block& delta);

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;
    };
}

