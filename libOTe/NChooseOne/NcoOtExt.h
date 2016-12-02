#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/MatrixView.h"
#include <array>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto
{
    class PRNG;
    class Channel;
    class BitVector;

    // An pure abstract class that defines the required API for a 1-out-of-N OT extension.
    // Typically N is exponentially in the security parameter. For example, N=2**128. 
    // To get the parameters for this specific OT ext. call the getParams() method.
    // This class should first have the setBaseOts() function called. Subsequentlly, the split
    // function can optinally be called in which case the return instance does not need the
    // fucntion setBaseOts() called. To initialize m OTs, call init(m). Afterwards 
    // recvCorrection() should be called one or more times. This takes two parameter, the 
    // channel and the number of correction values that should be received. After k correction
    // values have been received, encode(i\in [0,...,k-1], ...) can be called. This will
    // give you the corresponding encoding. Finally, after all correction values have been
    // received, check should be called.
    class NcoOtExtSender
    {
    public:

        // returns whether this OT extension has base OTs
        virtual bool hasBaseOts() const = 0;

        // sets the base OTs and choices that they prepresent. This will determine
        // how wide the OT extension is. Currently, things have to be a multiple of
        // 128. If not this will throw.
        // @ baseRecvOts: The base 1 out of 2 OTs. 
        // @ choices: The select bits that were used in the base OT
        virtual void setBaseOts(
            ArrayView<block> baseRecvOts,
            const BitVector& choices) = 0;
        
        // Creates a new OT extesion of the same type that can be used
        // in parallel to the original. Each will be independent and can
        // securely be used in parallel. 
        virtual std::unique_ptr<NcoOtExtSender> split() = 0;

        // Performs the PRNG expantion and transope operations. 
        // @ numOtExt: denotes the number of OTs that can be used before init
        //      should be called again.
        virtual void init(u64 numOtExt) = 0;

        
        virtual void encode(
            u64 otIdx,
            const ArrayView<block> choiceWord,
            block& encoding) = 0;

        //virtual void encode(
        //    u64 otIdx,
        //    const MatrixView<block> choiceWord,
        //    ArrayView<block> encoding) = 0;


        virtual void getParams(
            bool maliciousSecure,
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount, 
            u64& inputBlkSize, u64& baseOtCount) = 0;

        virtual void recvCorrection(Channel& chl, u64 recvCount) = 0;

        virtual void check(Channel& chl) = 0;
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

        virtual bool hasBaseOts() const = 0;

        virtual void setBaseOts(
            ArrayView<std::array<block, 2>> baseRecvOts) = 0;

        virtual std::unique_ptr<NcoOtExtReceiver> split() = 0;

        virtual void init(u64 numOtExt) = 0;

        virtual void encode(
            u64 otIdx,
            const ArrayView<block> choiceWord,
            block& encoding) = 0;

        virtual void zeroEncode(u64 otIdx) = 0;


        virtual void getParams(
            bool maliciousSecure,
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount,
            u64& inputBlkSize, u64& baseOtCount) = 0;

        virtual void sendCorrection(Channel& chl, u64 sendCount) = 0;

        virtual void check(Channel& chl) = 0;

    };

}
