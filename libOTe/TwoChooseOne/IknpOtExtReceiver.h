#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/config.h"
#ifdef ENABLE_IKNP
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include <array>

namespace osuCrypto
{

    class IknpOtExtReceiver :
        public OtExtReceiver, public TimerAdapter
    {
    public:
        bool mHasBase = false;
        std::array<std::array<PRNG, 2>, gOtExtBaseOtCount> mGens;


        IknpOtExtReceiver() = default;
        IknpOtExtReceiver(const IknpOtExtReceiver&) = delete;
        IknpOtExtReceiver(IknpOtExtReceiver&&) = default;

        IknpOtExtReceiver(span<std::array<block, 2>> baseSendOts)
        {
            setBaseOts(baseSendOts);
        }

        void operator=(IknpOtExtReceiver&& v)
        {
            mHasBase = std::move(v.mHasBase);
            mGens = std::move(v.mGens);
            v.mHasBase = false;
        }

        // returns whether the base OTs have been set. They must be set before
        // split or receive is called.
        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        // sets the base OTs.
        void setBaseOts(span<std::array<block, 2>> baseSendOts);

        // sets the base OTs.
        void setBaseOts(span<std::array<block, 2>> baseSendOts,
            PRNG& prng,
            Channel& chl)override {
            setBaseOts(baseSendOts);
        }

        // returns an independent instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the orginial base OTs.
        IknpOtExtReceiver splitBase();

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