#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libOTe/NChooseOne/KkrtNcoOtSender.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include "libOTe/Base/naor-pinkas.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>

#include <array>
#include <vector>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto {

    class OosNcoOtSender 
        : public NcoOtExtSender
        //: public KkrtNcoOtSender
    {
    public: 

        OosNcoOtSender(LinearCode& code, u64 statSecParam)
            : mCode(code),
            mStatSecParm(statSecParam)
        {}
        ~OosNcoOtSender();

        LinearCode mCode;
        u64 mStatSecParm;

        std::vector<PRNG> mGens;
        BitVector mBaseChoiceBits;
        std::vector<block> mChoiceBlks;
        Matrix<block> mT, mCorrectionVals;
        u64 mCorrectionIdx;




        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;

        std::unique_ptr<NcoOtExtSender> split() override;


        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;


        using NcoOtExtSender::encode;

        void encode(
            u64 otIdx,
            const block* codeWord,
            u8* dest,
            u64 destSize) override;


        void getParams(
            bool maliciousSecure,
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount,
            u64& inputBlkSize, u64& baseOtCount) override;

        void recvCorrection(Channel& chl, u64 recvCount) override;

        void check(Channel& chl, block seed) override;
    };
}

