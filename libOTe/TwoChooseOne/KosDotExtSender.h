#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libOTe/config.h"
#ifdef ENABLE_DELTA_KOS
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Tools/LinearCode.h"
#include <array>
namespace osuCrypto {

    class KosDotExtSender :
        public OtExtSender , public TimerAdapter
    {
    public: 
		block mDelta = ZeroBlock;
        std::vector<PRNG> mGens;
        BitVector mBaseChoiceBits;


        KosDotExtSender() = default;
        KosDotExtSender(const KosDotExtSender&) = delete;
        KosDotExtSender(KosDotExtSender&&) = default;

        KosDotExtSender(
            span<block> baseRecvOts,
            const BitVector& choices)
        {
            setBaseOts(baseRecvOts, choices);
        }

        void operator=(KosDotExtSender&& v)
        {
            mGens = std::move(v.mGens);
            mBaseChoiceBits = std::move(v.mBaseChoiceBits);
            mDelta = v.mDelta;
            v.mDelta = ZeroBlock;
        }

        // defaults to requiring 40 more base OTs. This gives 40 bits 
        // of statistical secuirty.
        u64 baseOtCount() const override { return gOtExtBaseOtCount + 40; }


        // return true if this instance has valid base OTs. 
        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        // Returns a independent instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        KosDotExtSender splitBase();

        // Returns a independent (type eased) instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        std::unique_ptr<OtExtSender> split() override;

        // Sets the base OTs which must be peformed before calling split or send.
        // See frontend/main.cpp for an example. 
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            Channel& chl) override {
            setBaseOts(baseRecvOts, choices);
        }

        // Takes a destination span of two blocks and performs OT extension
        // where the destination span is populated (written to) with the random
        // OT messages that then extension generates. User data is not transmitted. 
        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;

        void setDelta(const block& delta);

    };
}

#endif