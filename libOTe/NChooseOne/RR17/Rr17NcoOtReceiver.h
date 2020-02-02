#pragma once

#include "libOTe/config.h"
#ifdef ENABLE_RR

#include <cryptoTools/Common/Defines.h>
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

        bool isMalicious() const override { return true; }

        u64 getBaseOTCount() const override { return 128; }
        bool hasBaseOts() const override;

        void setBaseOts(
            span<std::array<block, 2>> baseRecvOts, PRNG& prng, Channel& chl) override;

        std::unique_ptr<NcoOtExtReceiver> split() override;

        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;

        using NcoOtExtReceiver::encode;
        void encode(
            u64 otIdx,
            const void* choiceWord,
            void* dest ,
            u64 destSize) override;

        void zeroEncode(u64 otIdx) override;


        void configure(
            bool maliciousSecure,
            u64 statSecParam, u64 inputBitCount) override;

        void sendCorrection(Channel& chl, u64 sendCount) override;

        void check(Channel& chl, block seed) override;

    };

}
#endif