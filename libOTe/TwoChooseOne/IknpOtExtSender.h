#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <array>

namespace osuCrypto {

    class IknpOtExtSender :
        public OtExtSender
    {
    public: 


        std::array<PRNG, gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;
        std::unique_ptr<OtExtSender> split() override;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;


        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl/*,
            std::atomic<u64>& doneIdx*/) override;

    };
}

