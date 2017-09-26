#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/NChooseOne/NcoOtExt.h"
#include <cryptoTools/Network/Channel.h>
#include <vector>
#include "libOTe/Tools/LinearCode.h"
//#include "libOTe/NChooseOne/KkrtNcoOtReceiver.h"
#ifdef GetMessage
#undef GetMessage
#endif

#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{

    class OosNcoOtReceiver 
        : public NcoOtExtReceiver
    {
    public:


        OosNcoOtReceiver();

        bool hasBaseOts()const override
        {
            return mHasBase;
        }

        bool mHasBase, mMalicious;
        u64 mStatSecParam;
        LinearCode mCode;
        u64 mCorrectionIdx, mInputByteCount;

        std::vector<std::array<PRNG, 2>> mGens;
        Matrix<block> mT0;
        Matrix<block> mT1;
        Matrix<block> mW;

#ifndef NDEBUG
        std::vector<u8> mEncodeFlags;
#endif



        u64 getBaseOTCount() const override;

        void configure(bool maliciousSecure, u64 statSecParam, u64 inputBitCount) override;



        void setBaseOts(
            span<std::array<block, 2>> baseRecvOts) override;

        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;

        using NcoOtExtReceiver::encode;
        void encode(
            u64 otIdx,
            const void* inputword,
            void* dest,
            u64 destSize) override;

        void zeroEncode(u64 otIdx) override;

        void sendCorrection(Channel& chl, u64 sendCount) override;

        void check(Channel& chl, block wordSeed) override;

        std::unique_ptr<NcoOtExtReceiver> split() override;

    };

}
