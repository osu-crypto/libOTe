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
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/Coproto.h"
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
        virtual ~KosDotExtSender() = default;

        void operator=(KosDotExtSender&& v)
        {
            mGens = std::move(v.mGens);
            mBaseChoiceBits = std::move(v.mBaseChoiceBits);
            mDelta = v.mDelta;
            v.mDelta = ZeroBlock;
        }

        // defaults to requiring 40 more base OTs. This gives 40 bits 
        // of statistical security.
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

        // Sets the base OTs which must be performed before calling split or send.
        // See frontend/main.cpp for an example. 
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;


        // Takes a destination span of two blocks and performs OT extension
        // where the destination span is populated (written to) with the random
        // OT messages that then extension generates. User data is not transmitted. 
        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override;

        void setDelta(const block& delta);

    };
}

#endif
