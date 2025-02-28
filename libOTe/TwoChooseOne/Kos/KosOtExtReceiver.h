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
#include <array>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Tools/Coproto.h"
#include <cryptoTools/Crypto/MultiKeyAES.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"

namespace osuCrypto
{

    class KosOtExtReceiver :
        public OtExtReceiver, public TimerAdapter
    {
    public:
        struct SetUniformOts {};

        // have the base ots been set
        bool mHasBase = false;

        // the base OTs messages as the AES keys.
        std::vector<MultiKeyAES<gOtExtBaseOtCount>> mGens;

        // the index of the AES in counter mode used by mGen
        u64 mPrngIdx = 0;

        // If true, the malicious check is performed.
        bool mIsMalicious = true;

        // the type of hashing that is perform.
        HashType mHashType = HashType::AesHash;

        // if malicious, and this is true then Fiat Shamir is used
        // to generate the malicious security challenge.
        bool mFiatShamir = false;


        KosOtExtReceiver() = default;
        KosOtExtReceiver(const KosOtExtReceiver&) = delete;
        KosOtExtReceiver(KosOtExtReceiver&&) = default;
        KosOtExtReceiver(SetUniformOts, span<std::array<block, 2>> baseSendOts);

        void operator=(KosOtExtReceiver&& v)
        {
            mHasBase = std::exchange(v.mHasBase, 0);
            mGens = std::move(v.mGens);
            mPrngIdx = std::exchange(v.mPrngIdx, 0);
            mIsMalicious = v.mIsMalicious;
            mHashType = v.mHashType;
            mFiatShamir = v.mFiatShamir;
        }

        virtual ~KosOtExtReceiver() = default;

        // returns whether the base OTs have been set. They must be set before
        // split or receive is called.
        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        // sets the base OTs.
        void setBaseOts(span<std::array<block, 2>> baseSendOts) override;

        // sets the base OTs and the uniform base flag (base OTs will not be randomized)
        void setUniformBaseOts(span<std::array<block, 2>> baseSendOts);

        // returns an independent instance of this extender which can securely be
        // used concurrently to this current one. The base OTs for the new instance 
        // are derived from the orginial base OTs.
        KosOtExtReceiver splitBase();

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
            Socket& chl) override;

        // internal, hashes and returns the malicious check message.
        task<> check(
            span<block> messages,
            BitVector const& choices,
            BitVector const& extraChoices,
            block seed,
            coproto::Socket& sock);

    };

}
#endif