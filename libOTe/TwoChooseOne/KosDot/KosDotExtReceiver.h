#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_DELTA_KOS
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <array>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Tools/LinearCode.h"

namespace osuCrypto
{

    class KosDotExtReceiver :
        public OtExtReceiver, public TimerAdapter
    {
    public:
        bool mHasBase = false;
        std::vector<std::array<PRNG, 2>> mGens;


        KosDotExtReceiver() = default;
        KosDotExtReceiver(const KosDotExtReceiver&) = delete;
        KosDotExtReceiver(KosDotExtReceiver&&) = default;

        KosDotExtReceiver(span<std::array<block, 2>> baseSendOts)
        {
            setBaseOts(baseSendOts);
        }

        virtual ~KosDotExtReceiver() = default;

        void operator=(KosDotExtReceiver&& v)
        {
            mHasBase = std::move(v.mHasBase);
            mGens = std::move(v.mGens);
            v.mHasBase = false;
        }

        // defaults to requiring 40 more base OTs. This gives 40 bits 
        // of statistical security.
        u64 baseOtCount() const override { return gOtExtBaseOtCount + 40; }

        // returns whether the base OTs have been set. They must be set before
        // split or receive is called.
        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        // sets the base OTs.
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts) override;


        // returns an independent instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the original base OTs.
        KosDotExtReceiver splitBase();

        // returns an independent (type eased) instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the original base OTs.
        std::unique_ptr<OtExtReceiver> split() override;

        // Performed the specified number of random OT extensions where the messages
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