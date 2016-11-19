#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "NChooseOne/NcoOtExt.h"
#include "Common/BitVector.h"
#include "Common/MatrixView.h"
#include "Base/naor-pinkas.h"

#include "Network/Channel.h"

#include <array>
#include <vector>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto {

    class KkrtNcoOtSender : public NcoOtExtSender
    {
    public: 
        std::vector<PRNG> mGens;
        BitVector mBaseChoiceBits;
        std::vector<block> mChoiceBlks;
        MatrixView<block> mT;
        
        MatrixView<block> mCorrectionVals;
        u64 mCorrectionIdx;


        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        void setBaseOts(
            ArrayView<block> baseRecvOts,
            const BitVector& choices) override;
        
        std::unique_ptr<NcoOtExtSender> split() override;


        void init(u64 numOtExt) override;


        void encode(
            u64 otIdx,
            const ArrayView<block> codeWord, 
            block& val) override;

        void getParams(
            bool maliciousSecure,
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount,
            u64& inputBlkSize, u64& baseOtCount) override;

        void recvCorrection(Channel& chl, u64 recvCount) override;

        void check(Channel& chl) override {}
    };
}

