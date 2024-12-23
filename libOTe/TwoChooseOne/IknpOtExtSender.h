#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libOTe/config.h"
#ifdef ENABLE_IKNP

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/MultiKeyAES.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/Timer.h>
#include <array>

namespace osuCrypto {

    class IknpOtExtSender :
        public OtExtSender, public TimerAdapter
    {
    public: 
        //std::vector<PRNG> mGens;
        MultiKeyAES<gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;
        bool mHash = true;
        u64 mPrngIdx = 0;

        IknpOtExtSender() = default;
        IknpOtExtSender(const IknpOtExtSender&) = delete;
        IknpOtExtSender(IknpOtExtSender&&) = default;

        IknpOtExtSender(
            span<block> baseRecvOts,
            const BitVector& choices)
        {
            setBaseOts(baseRecvOts, choices);
        }
        virtual ~IknpOtExtSender() = default;

        void operator=(IknpOtExtSender&&v) 
        {
            mPrngIdx = std::exchange(v.mPrngIdx, 0);
            mGens = std::move(v.mGens);
            mBaseChoiceBits = std::move(v.mBaseChoiceBits);
            mHash = v.mHash;
        }


        // return true if this instance has valid base OTs. 
        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        // Returns a independent instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        IknpOtExtSender splitBase();

        // Returns a independent (type eased) instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        std::unique_ptr<OtExtSender> split() override;

        // Sets the base OTs which must be peformed before calling split or send.
        // See frontend/main.cpp for an example. 
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        // Sets the base OTs which must be peformed before calling split or send.
        // See frontend/main.cpp for an example. 
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            PRNG& prng,
            Channel& chl) override {setBaseOts(baseRecvOts, choices);}

        // Takes a destination span of two blocks and performs OT extension
        // where the destination span is populated (written to) with the random
        // OT mMessages that then extension generates. User data is not transmitted. 
        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;

    };
}

#endif
