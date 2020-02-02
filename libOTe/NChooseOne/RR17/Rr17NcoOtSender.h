#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_RR

#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

namespace osuCrypto
{


    class Rr17NcoOtSender : public NcoOtExtSender
    {
    public:
        KosOtExtSender mKos;
        std::vector<std::array<block, 2>> mMessages;

        std::vector<u8> mCorrection;
        u64 mCorrectionIdx, mInputByteCount;

        bool isMalicious() const override { return true; }


        u64 getBaseOTCount() const override { return 128; }

        // returns whether this OT extension has base OTs
        bool hasBaseOts() const override;

        // sets the base OTs and choices that they prepresent. This will determine
        // how wide the OT extension is. Currently, things have to be a multiple of
        // 128. If not this will throw.
        // @ baseRecvOts: The base 1 out of 2 OTs. 
        // @ choices: The select bits that were used in the base OT
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            Channel& chl) override;

        // Creates a new OT extesion of the same type that can be used
        // in parallel to the original. Each will be independent and can
        // securely be used in parallel. 
        std::unique_ptr<NcoOtExtSender> split() override;

        // Performs the PRNG expantion and transope operations. 
        // @ numOtExt: denotes the number of OTs that can be used before init
        //      should be called again.
        void init(u64 numOtExt, PRNG& prng, Channel& chl) override;


        using NcoOtExtSender::encode;
        void encode(
            u64 otIdx,
            const void* choiceWord,
            void* dest,
            u64 destSize) override;


        void configure(bool maliciousSecure,u64 statSecParam, u64 inputBitCount) override;

        void recvCorrection(Channel& chl, u64 recvCount) override;
        u64 recvCorrection(Channel& chl) override { throw std::runtime_error("not implemented" LOCATION); }

        void check(Channel& chl, block seed) override;
    };


}
#endif