#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
        bool mHasBase = false, mHash = true;
        //std::vector<std::array<PRNG, 2>> mGens;
        AlignedArray<MultiKeyAES<gOtExtBaseOtCount>,2> mGens;
        u64 mPrngIdx = 0;

        IknpOtExtReceiver() = default;
        IknpOtExtReceiver(const IknpOtExtReceiver&) = delete;
        IknpOtExtReceiver(IknpOtExtReceiver&&) = default;

        IknpOtExtReceiver(span<std::array<block, 2>> baseSendOts)
        {
            setBaseOts(baseSendOts);
        }

        virtual ~IknpOtExtReceiver() = default;

        void operator=(IknpOtExtReceiver&& v)
        {
            mHasBase = std::exchange(v.mHasBase, false);
            mPrngIdx = std::exchange(v.mPrngIdx, 0);
            mHash = v.mHash;
            mGens = std::move(v.mGens);
        }

        // returns whether the base OTs have been set. They must be set before
        // split or receive is called.
        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        // sets the base OTs.
        void setBaseOts(span<std::array<block, 2>> baseSendOts) override;


        // returns an independent instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the orginial base OTs.
        IknpOtExtReceiver splitBase();

        // returns an independent (type eased) instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the orginial base OTs.
        std::unique_ptr<OtExtReceiver> split() override;

        // Performed the specicifed number of random OT extensions where the mMessages
        // receivers are indexed by the choices vector that is passed in. The received
        // values written to the messages parameter. 
        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl)override;

    };

}
#endif