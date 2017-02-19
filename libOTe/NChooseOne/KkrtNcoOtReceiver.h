#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/NChooseOne/NcoOtExt.h"
#include <cryptoTools/Network/Channel.h>
#include <vector>
#include <cryptoTools/Crypto/AES.h>

#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{

    class KkrtNcoOtReceiver : public NcoOtExtReceiver
    {
    public:


        KkrtNcoOtReceiver()
            :mHasBase(false)
        {}

        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        bool mHasBase;
        std::vector<std::array<AES, 2>> mGens;
        std::vector<u64> mGensBlkIdx;
        MatrixView<block> mT0;
        MatrixView<block> mT1;
        u64 mCorrectionIdx;

        void setBaseOts(
            ArrayView<std::array<block, 2>> baseRecvOts) override;
        

        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;


        std::unique_ptr<NcoOtExtReceiver> split() override;

        void encode(
            u64 otIdx,
            const ArrayView<block> inputword,
            block& val) override;

        void zeroEncode(u64 otIdx) override;

        void getParams(
            bool maliciousSecure,
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount,
            u64& inputBlkSize, u64& baseOtCount) override;


        void sendCorrection(Channel& chl, u64 sendCount) override;

        void check(Channel& chl, block seed) override {}
    };

}
