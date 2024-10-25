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
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Matrix.h>
#include <vector>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/MultiKeyAES.h>

#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{

    // The KKRT protocol for a 1-out-of-N OT extension.
    // Typically N is exponentially in the security parameter. For example, N=2**128. 
    // To get the parameters for this specific OT ext. call the getParams() method.
    // This class should first have the setBaseOts() function called. Subsequentlly, the split
    // function can optinally be called in which case the return instance does not need the
    // fucntion setBaseOts() called. To initialize m OTs, call init(m). Then encode(i, ...) can 
    // be called. sendCorrectio(k) will send the next k correction values. Make sure to call
    // encode or zeroEncode for all i less than the sum of the k values. Finally, after
    // all correction values have been sent, check should be called.
    class KkrtNcoOtReceiver : public NcoOtExtReceiver, public TimerAdapter
    {
    public:

        std::vector<std::array<AES, 2>> mGens;
        std::vector<u64> mGensBlkIdx;
        Matrix<block> mT0;
        std::shared_ptr<Matrix<block>> mT1;
        
        u64 mCorrectionIdx;

        u64 mInputByteCount;

        MultiKeyAES<4> mMultiKeyAES;



        KkrtNcoOtReceiver() = default;
        KkrtNcoOtReceiver(const KkrtNcoOtReceiver&) = delete;
        KkrtNcoOtReceiver(KkrtNcoOtReceiver&&v)
        {
            *this = std::forward<KkrtNcoOtReceiver>(v);
        }

        ~KkrtNcoOtReceiver()
        {
        }


        void operator=(KkrtNcoOtReceiver&&v)
        {
            mGens = std::move(v.mGens);
            mGensBlkIdx = std::move(v.mGensBlkIdx);
            mT0 = std::move(v.mT0);
            mT1 = std::move(v.mT1);
            mCorrectionIdx = v.mCorrectionIdx;
            mInputByteCount = v.mInputByteCount;
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
            return mGensBlkIdx.size();
        }

        // Sets the base OTs. Note that getBaseOTCount() of OTs should be provided.
        // @ baseSendOts: a std vector like container that which holds a series of both 
        //      2-choose-1 OT mMessages. The sender should hold one of them.
        // @ prng: not used.
        // @ chl: not used.
        task<> setBaseOts(span<std::array<block, 2>> baseRecvOts, PRNG& prng, Socket& chl) override
        {
            setBaseOts(baseRecvOts);
            co_return;
        }
        
        // See other setBaseOts(...);
        void setBaseOts(span<std::array<block, 2>> baseRecvOts);

        // Perform some computation before encode(...) can be called. Note that this
        // can be called several times, with each call creating new OTs to be encoded.
        // @ numOtExt: the number of OTs that should be initialized. for encode(i,...) calls,
        //       i should be less then numOtExt.
        // @ prng: A random number generator for initializing the OTs
        // @ Channel: the channel that should be used to communicate with the sender.
        task<> init(u64 numOtExt, PRNG& prng, Socket& chl) override;

        using NcoOtExtReceiver::encode;

        // For the OT at index otIdx, this call compute the OT with 
        // choice value inputWord. 
        // @ otIdx: denotes the OT index that should be encoded. Each OT index allows
        //       the receiver to learn a single message.
        // @ inputWord: the choice value that should be encoded. inputWord should
        //      point to a value in the range  {0,1}^inputBitsCount. 
        // @ dest: The output buffer which will hold the OT message encoding the inputWord.
        // @ destSize: The number of bytes that should be written to the dest pointer.
        //      destSize must be no larger than RandomOracle::HashSize.
        void encode(
            u64 otIdx,
            const void* inputword,
            void* dest,
            u64 destSize ) override;

        // An optimization if the receiver does not want to use this otIdx. 
        // Note that simply note calling encode(otIdx,...) or zeroEncode(otIdx)
        // for some otIdx is insecure.
        // @ otIdx: the index of that OT that should be skipped.
        void zeroEncode(u64 otIdx) override;

        // The way that this class works is that for each encode(otIdx,...), some internal 
        // data for each otIdx is generated and stored. This data (corrections) has to be sent to the sender
        // before they can call encode(otIdx, ...). This method allows this and can be called multiple
        // times so that "streaming" encodes can be performed. The first time it is called, the internal
        // data for otIdx \in {0, 1, ..., sendCount - 1} is sent. The next time this function is  called
        // with sendCount' the data for otIdx \in {sendCount, sendCount + 1, ..., sendCount' + sendCount - 1}
        // is sent. The sender should call recvCorrection(sendCount) with the same sendCount.
        // @ chl: the channel that the data will be sent over
        // @ sendCount: the number of correction values that should be sent.
        task<> sendCorrection(Socket& chl, u64 sendCount) override;

        // Some malicious secure OT extensions require an additional step after all corrections have 
        // been sent. In this case, this method should be called.
        // @ chl: the channel that will be used to communicate
        // @ seed: a random seed that will be used in the function
        task<> check(Socket& chl, block seed) override { co_return; }

        // Allows a single NcoOtExtReceiver to be split into two, with each being 
        // independent of each other.
        std::unique_ptr<NcoOtExtReceiver> split() override;


        // Allows a single NcoOtExtReceiver to be split into two, with each being 
        // independent of each other.
        KkrtNcoOtReceiver splitBase();
    };

}
#endif