#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>
#include "libOTe/Tools/Coproto.h"
#include <array>
#ifdef GetMessage
#undef GetMessage
#endif

#if defined(ENABLE_OOS) || defined(ENABLE_KKRT) || defined(ENABLE_RR)
#define LIBOTE_HAS_NCO

namespace osuCrypto
{
    class PRNG;
    class BitVector;
    //static const u64 NcoOtExtDefaultDestSize(sizeof(block));

    // An pure abstract class that defines the required API for a 1-out-of-N OT extension.
    // Typically N is exponentially in the security parameter. For example, N=2^128.
    // To set the parameters for this specific OT ext. call the configure(...) method.
    // After configure(...), this class should have the setBaseOts() function called. Subsequentlly, the
    // split() function can optinally be called in which case the return instance does not need the
    // fucntion setBaseOts() called. To initialize m OTs, call init(n,...). Afterwards 
    // recvCorrection(...) should be called one or more times. This takes two parameter, the 
    // socket and the number of correction values that should be received. After k correction
    // values have been received by NcoOtExtSender, encode(i\in [0,...,k-1], ...) can be called. This will
    // give you the corresponding encoding. Finally, after all correction values have been
    // received, check should be called if this is a malicious secure protocol.
    class NcoOtExtSender
    {
    public:
        virtual ~NcoOtExtSender() = default;

        // This function should be called first. It sets a variety of internal parameters such as
        // the number of base OTs that are required.
        // @ maliciousSecure: Should this extension be malicious secure
        // @ statSecParam: the statistical security parameters, e.g. 40.
        // @ inputByteCount: the number of input bits that should be supported.
        //      i.e. input should be in {0,1}^inputBitsCount.
        virtual void configure(bool maliciousSecure, u64 statSecParam, u64 inputBitsCount) = 0;

        // Returns whether the base OTs have already been set
        virtual bool hasBaseOts() const = 0;

        // Returns the number of base OTs that should be provided to setBaseOts(...).
        // congifure(...) should be called first.
        virtual u64 getBaseOTCount() const = 0;

        // Returns whether the extension is configured to be malicious.
        // congifure(...) should be called first.
        virtual bool isMalicious() const = 0;


        task<> genBaseOts(PRNG& prng, Socket& chl);

        // Sets the base OTs. Note that  getBaseOTCount() number of OTs should be provided
        // @ baseRecvOts: a std vector like container that which holds a series of both
        //      2-choose-1 OT mMessages. The sender should hold one of them.
        // @ choices: The select bits that were used in the base OT
        // @ chl: the socket that the data will be received over.
        virtual task<> setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            Socket& chl) = 0;


        // Performs the PRNG expantion and transpose operations. This sets the
        // internal data structures that are needed for the subsequent encode(..)
        // calls. This call can be made several times, each time resetting the
        // internal state and creating new OTs.
        // @ numOtExt: denotes the number of OTs that can be used before init
        //      should be called again.
        virtual task<> init(u64 numOtExt, PRNG& prng, Socket& chl) = 0;

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
        virtual void encode(
            u64 otIdx,
            const void* choiceWord,
            void* encoding,
            u64 encodingSize) = 0;

        // This function allows the user to obtain the random OT mMessages of their choice
        // at a given index.
        // @ otIdx: denotes the OT index that should be encoded. Each OT index allows
        //       the receiver to learn a single message.
        // @ choiceWord: a pointer to the location that contains the choice c\in{0,1}^inputBitsCount
        //       that should be encoded. The sender can call this function many times for a given
        //       otIdx. Note that recvCorrection(...) must have been called one or more times
        //       where the sum of the "recvCount" must be greater than otIdx.
        // @ encoding: the location that the random OT message should be written to (16 bytes).
        void encode(u64 otIdx,const void* choiceWord,void* encoding)
        { encode(otIdx, choiceWord, encoding, sizeof(block)); }

        // The way that this class works is that for each encode(otIdx,...), some internal
        // data for each otIdx is generated by the receiver. This data (corrections) has to be sent to
        // the sender before they can call encode(otIdx, ...). This method allows this and can be called multiple
        // times so that "streaming" encodes can be performed. The first time it is called, the internal
        // data for otIdx \in {0, 1, ..., recvCount - 1} is received. The next time this function is  called
        // with recvCount' the data for otIdx \in {recvCount, recvCount + 1, ..., recvCount' + recvCount - 1}
        // is sent. The receiver should call sendCorrection(recvCount) with the same recvCount.
        // @ chl: the socket that the data will be sent over
        // @ recvCount: the number of correction values that should be received.
        virtual task<> recvCorrection(Socket& chl, u64 recvCount) = 0;

        // An alternative version of the recvCorrection(...) function which dynamically receivers the number of
        // corrections based on how many were sent. The return value is the number received. See overload for details.
        // virtual cp::task<>V<u64> recvCorrection(Socket& chl) = 0;

        // Some malicious secure OT extensions require an additional step after all corrections have 
        // been received. In this case, this method should be called.
        // @ chl: the socket that will be used to communicate
        // @ seed: a random seed that will be used in the function
        virtual task<> check(Socket& chl, block seed) = 0;


        // Creates a new OT extesion of the same type that can be used
        // in parallel to the original. Each will be independent and can
        // securely be used in parallel.
        virtual std::unique_ptr<NcoOtExtSender> split() = 0;


        // Send the chosen mMessages. The receiver will learn one message per row.
        // @ mMessages: the mMessages that should sent.
        // @ prng: randomness source
        // @ chl: the socket that should be communicated over.
        task<> sendChosen(MatrixView<block> messages, PRNG& prng, Socket& chl);
    };


    // An pure abstract class that defines the required API for a 1-out-of-N OT extension.
    // Typically N is exponentially in the security parameter. For example, N=2**128.
    // To get the parameters for this specific OT ext. call the getParams() method.
    // This class should first have the setBaseOts() function called. Subsequentlly, the split
    // function can optinally be called in which case the return instance does not need the
    // fucntion setBaseOts() called. To initialize m OTs, call init(m). Then encode(i, ...) can
    // be called. sendCorrectio(k) will send the next k correction values. Make sure to call
    // encode or zeroEncode for all i less than the sum of the k values. Finally, after
    // all correction values have been sent, check should be called.
    class NcoOtExtReceiver
    {
    public:
        virtual ~NcoOtExtReceiver() = default;

        // This function should be called first. It sets a variety of internal parameters such as
        // the number of base OTs that are required.
        // @ maliciousSecure: Should this extension be malicious secure
        // @ statSecParam: the statistical security parameters, e.g. 40.
        // @ inputByteCount: the number of input bits that should be supported.
        //      i.e. input should be in {0,1}^inputBitsCount.
        virtual void configure(bool maliciousSecure, u64 statSecParam, u64 inputBitsCount) = 0;

        // Returns whether the base OTs have already been set
        virtual bool hasBaseOts() const = 0;

        // Returns the number of base OTs that should be provided to setBaseOts(...).
        // congifure(...) should be called first.
        virtual u64 getBaseOTCount() const = 0;

        // Returns whether the extension is configured to be malicious.
        // congifure(...) should be called first.
        virtual bool isMalicious() const = 0;

        task<> genBaseOts(PRNG& prng, Socket& chl);

        // Sets the base OTs. Note that getBaseOTCount() of OTs should be provided.
        // @ baseSendOts: a std vector like container that which holds a series of both
        //      2-choose-1 OT mMessages. The sender should hold one of them.
        // @ prng: A random number generator used to randomize the base OTs.
        // @ chl:  A socket that is used to send data over.
        virtual task<> setBaseOts(span<std::array<block, 2>> baseSendOts, PRNG& prng, Socket& chl) = 0;


        // Perform some computation before encode(...) can be called. Note that this
        // can be called several times, with each call creating new OTs to be encoded.
        // @ numOtExt: the number of OTs that should be initialized. for encode(i,...) calls,
        //       i should be less then numOtExt.
        // @ prng: A random number generator for initializing the OTs
        // @ chl: the socket that should be used to communicate with the sender.
        virtual task<> init(u64 numOtExt, PRNG& prng, Socket& chl) = 0;

        // For the OT at index otIdx, this call compute the OT with
        // choice value inputWord.
        // @ otIdx: denotes the OT index that should be encoded. Each OT index allows
        //       the receiver to learn a single message.
        // @ inputWord: the choice value that should be encoded. inputWord should
        //      point to a value in the range  {0,1}^inputBitsCount.
        // @ dest: The output buffer which will hold the OT message encoding the inputWord.
        // @ destSize: The number of bytes that should be written to the dest pointer.
        //      destSize must be no larger than RandomOracle::HashSize.
        virtual void encode(
            u64 otIdx,
            const void* inputWord,
            void* dest,
            u64 destSize) = 0;

        void encode(u64 otIdx,const void* choiceWord,void* encoding)
        { encode(otIdx, choiceWord, encoding, sizeof(block)); }

        // An optimization if the receiver does not want to use this otIdx.
        // Note that simply note calling encode(otIdx,...) or zeroEncode(otIdx)
        // for some otIdx is insecure.
        // @ otIdx: the index of that OT that should be skipped.
        virtual void zeroEncode(u64 otIdx) = 0;

        // The way that this class works is that for each encode(otIdx,...), some internal
        // data for each otIdx is generated and stored. This data (corrections) has to be sent to the sender
        // before they can call encode(otIdx, ...). This method allows this and can be called multiple
        // times so that "streaming" encodes can be performed. The first time it is called, the internal
        // data for otIdx \in {0, 1, ..., sendCount - 1} is sent. The next time this function is  called
        // with sendCount' the data for otIdx \in {sendCount, sendCount + 1, ..., sendCount' + sendCount - 1}
        // is sent. The sender should call recvCorrection(sendCount) with the same sendCount.
        // @ chl: the socket that the data will be sent over
        // @ sendCount: the number of correction values that should be sent.
        virtual task<> sendCorrection(Socket& chl, u64 sendCount) = 0;

        // Some malicious secure OT extensions require an additional step after all corrections have
        // been sent. In this case, this method should be called.
        // @ chl: the socket that will be used to communicate
        // @ seed: a random seed that will be used in the function
        virtual task<> check(Socket& chl, block seed) = 0;

        // Allows a single NcoOtExtReceiver to be split into two, with each being
        // independent of each other.
        virtual std::unique_ptr<NcoOtExtReceiver> split() = 0;

        // Receive the chosen mMessages specified by the choices.
        // @ numMsgsPerOT: The number of choices each OT has. That is, choices[i] < numMsgsPerOT.
        // @ mMessages: the location that the received mMessages should be written to.
        // @ choices: the choices for which mMessages should be received.
        // @ prng: randomness source
        // @ chl: the socket that should be communicated over.
        task<> receiveChosen(u64 numMsgsPerOT, span<block> messages, span<u64> choices, PRNG& prng, Socket& chl);
    };

}

#endif

