#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libOTe/NChooseOne/NcoOtExt.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include "libOTe/Base/naor-pinkas.h"

#include <cryptoTools/Network/Channel.h>

#include <array>
#include <vector>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto {

    class KkrtNcoOtSender : public NcoOtExtSender
    {
    public: 
        std::vector<AES> mGens;
        std::vector<u64> mGensBlkIdx;
        BitVector mBaseChoiceBits;
        std::vector<block> mChoiceBlks;
        Matrix<block> mT, mCorrectionVals;
        u64 mCorrectionIdx, mInputByteCount;
        MultiKeyAES<4> mMultiKeyAES;

        void configure(bool maliciousSecure, u64 statSecParam, u64 inputBitCount) override;

        u64 getBaseOTCount() const override;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        void setBaseOts(
            gsl::span<block> baseRecvOts,
            const BitVector& choices) override;
        
        std::unique_ptr<NcoOtExtSender> split() override;


        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;


        using NcoOtExtSender::encode;
        void encode(
            u64 otIdx,
            const void* choice,
            void* dest,
            u64 destSize) override;


        void recvCorrection(Channel& chl, u64 recvCount) override;

        void check(Channel& chl, block seed) override {}
    };
}

