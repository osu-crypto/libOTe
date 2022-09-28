#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_KKRT

#include "libOTe/NChooseOne/NcoOtExt.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include "libOTe/Base/BaseOT.h"

#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>

#include <array>
#include <vector>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto {


    // The KKRT protocol for a 1-out-of-N OT extension.
    // Typically N is exponentially in the security parameter. For example, N=2^128.
    // To set the parameters for this specific OT ext. call the configure(...) method.
    // After configure(...), this class should have the setBaseOts() function called. Subsequentlly, the
    // split() function can optinally be called in which case the return instance does not need the
    // fucntion setBaseOts() called. To initialize m OTs, call init(n,...). Afterwards
    // recvCorrection(...) should be called one or more times. This takes two parameter, the
    // channel and the number of correction values that should be received. After k correction
    // values have been received by NcoOtExtSender, encode(i\in [0,...,k-1], ...) can be called. This will
    // give you the corresponding encoding. Finally, after all correction values have been
    // received, check should be called if this is a malicious secure protocol.
    class KkrtNcoOtSender : public NcoOtExtSender, public TimerAdapter
    {
    public:
        std::vector<AES> mGens;
        std::vector<u64> mGensBlkIdx;
        BitVector mBaseChoiceBits;
        std::vector<block> mChoiceBlks;
        Matrix<block> mT, mCorrectionVals;
        u64 mCorrectionIdx, mInputByteCount;
        MultiKeyAES<4> mMultiKeyAES;

        KkrtNcoOtSender() = default;
        KkrtNcoOtSender(const KkrtNcoOtSender&) = delete;
        KkrtNcoOtSender(KkrtNcoOtSender&&v) = default;

        void operator=(KkrtNcoOtSender&&v)
        {
            mGens = std::move(v.mGens);
            mGensBlkIdx = std::move(v.mGensBlkIdx);
            mBaseChoiceBits = std::move(v.mBaseChoiceBits);
            mChoiceBlks = std::move(v.mChoiceBlks);
            mT = std::move(v.mT);
            mCorrectionVals = std::move(v.mCorrectionVals);
            mCorrectionIdx = std::move(v.mCorrectionIdx);
            mInputByteCount = std::move(v.mInputByteCount);
            mMultiKeyAES = std::move(v.mMultiKeyAES);
        }

        bool isMalicious() const override { return false; }

        // This function should be called first. It sets a variety of internal parameters such as
        // the number of base OTs that are required.
        // @ maliciousSecure: Should this extension be malicious secure
        // @ statSecParam: the statistical security parameters, e.g. 40.
        // @ inputByteCount: the number of input bits that should be supported.
        //      i.e. input should be in {0,1}^inputBitsCount.
        void configure(bool maliciousSecure, u64 statSecParam, u64 inputBitCount) override;

        // Returns the number of base OTs that should be provided to setBaseOts(...).
        // congifure(...) should be called first.
        u64 getBaseOTCount() const override;

        // Returns whether the base OTs have already been set
        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        // Sets the base OTs. Note that  getBaseOTCount() number of OTs should be provided
        // @ baseRecvOts: a std vector like container that which holds a series of both
        //      2-choose-1 OT mMessages. The sender should hold one of them.
        // @ choices: The select bits that were used in the base OT
        // @ chl: not used.
        task<> setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices, Socket& chl) override {
            MC_BEGIN(task<>,this, baseRecvOts, &choices);
            setBaseOts(baseRecvOts, choices);
            MC_END();
        }


        // See other setBaseOts(...).
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        // Performs the PRNG expantion and transpose operations. This sets the
        // internal data structures that are needed for the subsequent encode(..)
        // calls. This call can be made several times, each time resetting the
        // internal state and creating new OTs.
        // @ numOtExt: denotes the number of OTs that can be used before init
        //      should be called again.
        task<> init(u64 numOtExt, PRNG& prng, Socket& chl) override;

        using NcoOtExtSender::encode;

        // This function allows the user to obtain the random OT mMessages of their choice
        // at a given index.
        // @ otIdx: denotes the OT index that should be encoded. Each OT index allows
        //       the receiver to learn a single message.
        // @ choiceWord: a pointer to the location that contains the choice c\in{0,1}^inputBitsCount
        //       that should be encoded. The sender can call this function many times for a given
        //       otIdx. Note that recvCorrection(...) must have been called one or more times
        //       where the sum of the "recvCount" must be greater than otIdx.
        // @ encoding: the location that the random OT message should be written to.
        // @ encodingSize: the number of bytes that should be writen to the encoding pointer.
        //       This should be a value between 1 and SHA::HashSize.
        void encode(
            u64 otIdx,
            const void* choice,
            void* dest,
            u64 destSize) override;

        // The way that this class works is that for each encode(otIdx,...), some internal
        // data for each otIdx is generated by the receiver. This data (corrections) has to be sent to
        // the sender before they can call encode(otIdx, ...). This method allows this and can be called multiple
        // times so that "streaming" encodes can be performed. The first time it is called, the internal
        // data for otIdx \in {0, 1, ..., recvCount - 1} is received. The next time this function is  called
        // with recvCount' the data for otIdx \in {recvCount, recvCount + 1, ..., recvCount' + recvCount - 1}
        // is sent. The receiver should call sendCorrection(recvCount) with the same recvCount.
        // @ chl: the channel that the data will be sent over
        // @ recvCount: the number of correction values that should be received.
        task<> recvCorrection(Socket& chl, u64 recvCount) override;
        
        // An alternative version of the recvCorrection(...) function which dynamically receivers the number of 
        // corrections based on how many were sent. The return value is the number received. See overload for details.
        //cp::task<>V<u64> recvCorrection(Socket& chl) override;

        task<> check(Socket& chl, block seed) override { MC_BEGIN(task<>); MC_END(); }


        // Creates a new OT extesion of the same type that can be used
        // in parallel to the original. Each will be independent and can
        // securely be used in parallel.
        std::unique_ptr<NcoOtExtSender> split() override;

        KkrtNcoOtSender splitBase();

    };
}

#endif
