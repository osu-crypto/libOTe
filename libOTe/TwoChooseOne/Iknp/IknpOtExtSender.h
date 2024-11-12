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
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <cryptoTools/Common/Timer.h>
#include <array>

namespace osuCrypto {

    class IknpOtExtSender :
        public KosOtExtSender
    {
    public: 
        IknpOtExtSender()
        {
            mIsMalicious = false;
        }
        IknpOtExtSender(const IknpOtExtSender&) = delete;
        IknpOtExtSender(IknpOtExtSender&&) = default;
        IknpOtExtSender& operator=(IknpOtExtSender&& v) = default;

        IknpOtExtSender(
            span<block> baseRecvOts,
            const BitVector& choices)
        {
            mIsMalicious = false;
            setBaseOts(baseRecvOts, choices);
        }
        virtual ~IknpOtExtSender() = default;

        // Returns a independent instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        IknpOtExtSender splitBase()
        {
            IknpOtExtSender r;
            static_cast<KosOtExtSender&>(r) = static_cast<KosOtExtSender&>(*this).splitBase();
            return r;
        }


    };
}

#endif
