#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/ArrayView.h>
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include <cryptoTools/Common/BitVector.h>
namespace osuCrypto
{

    class Rr17NcoOtReceiver : public NcoOtExtReceiver
    {

    public:
        KosOtExtReceiver mKos;
        std::vector<block> mMessages;
        u64 mEncodeSize, mSendIdx;
        BitVector mChoices;


#ifndef NDEBUG
        BitVector mDebugEncodeFlags;
#endif // !NDEBUG


        Rr17NcoOtReceiver();
        ~Rr17NcoOtReceiver();


        bool hasBaseOts() const override;

        void setBaseOts(
            ArrayView<std::array<block, 2>> baseRecvOts) override;

        std::unique_ptr<NcoOtExtReceiver> split() override;

        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;

        using NcoOtExtReceiver::encode;
        void encode(
            u64 otIdx,
            const block* choiceWord,
            u8* dest, 
            u64 destSize) override;

        void zeroEncode(u64 otIdx) override;


        void getParams(
            bool maliciousSecure,
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount,
            u64& inputBlkSize, u64& baseOtCount) override;

        void sendCorrection(Channel& chl, u64 sendCount) override;

        void check(Channel& chl, block seed) override;

    };

}
