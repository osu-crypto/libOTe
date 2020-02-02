#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/config.h"
#ifdef ENABLE_DELTA_IKNP

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <array>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Tools/LinearCode.h"

namespace osuCrypto
{

    class IknpDotExtReceiver :
        public OtExtReceiver, public TimerAdapter
    {
    public:
        bool mHasBase = false;
        std::vector<std::array<PRNG, 2>> mGens;

        IknpDotExtReceiver() = default;
        IknpDotExtReceiver(const IknpDotExtReceiver&) = delete;
        IknpDotExtReceiver(IknpDotExtReceiver&&) = default;

        IknpDotExtReceiver(span<std::array<block, 2>> baseSendOts)
        {
            setBaseOts(baseSendOts);
        }

        void operator=(IknpDotExtReceiver&& v)
        {
            mHasBase = std::move(v.mHasBase);
            mGens = std::move(v.mGens);
            v.mHasBase = false;
        }


        // defaults to requiring 40 more base OTs. This gives 40 bits 
        // of statistical secuirty.
        u64 baseOtCount() const override { return gOtExtBaseOtCount + 40; }

        // returns whether the base OTs have been set. They must be set before
        // split or receive is called.
        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        // sets the base OTs.
        void setBaseOts(span<std::array<block, 2>> baseSendOts);

        // sets the base OTs.
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts,
            PRNG& prng,
            Channel& chl)override {
            setBaseOts(baseSendOts);
        };

        // returns an independent instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the orginial base OTs.
        IknpDotExtReceiver splitBase();

        // returns an independent (type eased) instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the orginial base OTs.
        std::unique_ptr<OtExtReceiver> split() override;

        // Performed the specicifed number of random OT extensions where the messages
        // receivers are indexed by the choices vector that is passed in. The received
        // values written to the messages parameter. 
        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl)override;


    };

}
#endif