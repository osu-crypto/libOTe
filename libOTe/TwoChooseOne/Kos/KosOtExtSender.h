#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_KOS
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <array>
namespace osuCrypto {

    extern bool gKosWarning;
    class KosOtExtSender :
        public OtExtSender, public TimerAdapter
    {
    public:
        struct SetUniformOts {};


        std::vector<PRNG> mGens;
        BitVector mBaseChoiceBits;

        enum class HashType
        {
            RandomOracle,
            AesHash
        };
        HashType mHashType = HashType::AesHash;
        bool mFiatShamir = false;
        bool mUniformBase = false;

        KosOtExtSender() = default;
        KosOtExtSender(const KosOtExtSender&) = delete;
        KosOtExtSender(KosOtExtSender&&) = default;

        KosOtExtSender(
            SetUniformOts,
            span<block> baseRecvOts,
            const BitVector& choices);

        virtual ~KosOtExtSender() = default;

        void operator=(KosOtExtSender&& v)
        {
            mGens = std::move(v.mGens);
            mBaseChoiceBits = std::move(v.mBaseChoiceBits);
        }

        // return true if this instance has valid base OTs. 
        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        // Returns a independent instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        KosOtExtSender splitBase();

        // Returns a independent (type eased) instance of this extender which can 
        // be executed concurrently. The base OTs are derived from the
        // original base OTs.
        std::unique_ptr<OtExtSender> split() override;

        // Sets the base OTs which must be peformed before calling split or send.
        // See frontend/main.cpp for an example. 
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;

        void setUniformBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        // Takes a destination span of two blocks and performs OT extension
        // where the destination span is populated (written to) with the random
        // OT messages that then extension generates. User data is not transmitted. 
        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override;



        block hash(span<std::array<block, 2>> messages, block seed, std::array<block, 128>& extraBlocks);
    };
}

#endif
