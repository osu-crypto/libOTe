#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <array>
#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{
    class PRNG;
    class Channel;
    class BitVector;

    // The hard coded number of base OT that is expected by the OT Extension implementations.
    // This can be changed if the code is adequately adapted. 
    const u64 gOtExtBaseOtCount(128);
    
    class OtReceiver
    {
    public:
        OtReceiver() {}


        // Receive random strings indexed by choices. The random strings will be written to 
        // messages.
        virtual void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) = 0;

        // Receive chosen strings indexed by choices. The chosen strings will be written to 
        // messages.
        void receiveChosen(
            const BitVector& choices,
            span<block> recvMessages,
            PRNG& prng,
            Channel& chl);

    };

    class OtSender
    {
    public:
        OtSender() {}

        // send random strings. The random strings will be written to 
        // messages.
        virtual void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) = 0;

        // send chosen strings. Thosen strings are read from messages.
        void sendChosen(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl);

    };


    class OtExtReceiver : public OtReceiver
    {
    public:
        OtExtReceiver() {}

        // sets the base OTs that are then used to extend
        virtual void setBaseOts(
            span<std::array<block,2>> baseSendOts,
            PRNG& prng,
            Channel& chl) = 0;
        
        // the number of base OTs that should be set.
        virtual u64 baseOtCount() const { return gOtExtBaseOtCount; }

        // returns true if the base OTs are currently set.
        virtual bool hasBaseOts() const = 0; 
        
        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtReceiver> split() = 0;

        // use the default base OT class to generate the
        // base OTs that are required.
        virtual void genBaseOts(PRNG& prng, Channel& chl);
    };

    class OtExtSender : public OtSender
    {
    public:
        OtExtSender() {}

        // the number of base OTs that should be set.
        virtual u64 baseOtCount() const { return gOtExtBaseOtCount; }

        // returns true if the base OTs are currently set.
        virtual bool hasBaseOts() const = 0;

        // sets the base OTs that are then used to extend
        virtual void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            Channel& chl)  = 0;

        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtSender> split() = 0;

        // use the default base OT class to generate the
        // base OTs that are required.
        virtual void genBaseOts(PRNG& prng, Channel& chl);
    };


}
