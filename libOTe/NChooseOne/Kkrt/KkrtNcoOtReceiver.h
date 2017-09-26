#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/NChooseOne/NcoOtExt.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Matrix.h>
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

        bool mHasBase;
        std::vector<std::array<AES, 2>> mGens;
        std::vector<u64> mGensBlkIdx;
        Matrix<block> mT0;
        Matrix<block> mT1;
        u64 mCorrectionIdx;

        u64 mInputByteCount;

        MultiKeyAES<4> mMultiKeyAES;

        KkrtNcoOtReceiver()
            :mHasBase(false)
        {}
        
        
        void configure(bool maliciousSecure, u64 statSecParam, u64 inputBitCount) override;

        u64 getBaseOTCount() const override;

        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        void setBaseOts(
            gsl::span<std::array<block, 2>> baseRecvOts) override;
        

        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;




        using NcoOtExtReceiver::encode;

        void encode(
            u64 otIdx,
            const void* inputword,
            void* dest,
            u64 destSize ) override;



        void zeroEncode(u64 otIdx) override;


        void sendCorrection(Channel& chl, u64 sendCount) override;

        void check(Channel& chl, block seed) override {}



        std::unique_ptr<NcoOtExtReceiver> split() override;

    };

}
