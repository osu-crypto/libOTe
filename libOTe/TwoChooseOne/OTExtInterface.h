#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
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
        OtReceiver() = default;
        virtual ~OtReceiver() = default;

        // Receive random strings indexed by choices. The random strings will be written to
        // messages. messages must have the same alignment as an AlignedBlockPtr, i.e. 32
        // bytes with avx or 16 bytes without avx.
        virtual void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) = 0;

        // Receive chosen strings indexed by choices. The chosen strings will be written to
        // messages. The same alignment restriction applies.
        void receiveChosen(
            const BitVector& choices,
            span<block> recvMessages,
            PRNG& prng,
            Channel& chl);

        // The same alignment restriction applies.
        void receiveCorrelated(
            const BitVector& choices,
            span<block> recvMessages,
            PRNG& prng,
            Channel& chl);

    };

    class OtSender
    {
    public:
        OtSender() {}
        virtual ~OtSender() = default;

        // send random strings. The random strings will be written to
        // messages, which must be aligned like an AlignedBlockPtr.
        virtual void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) = 0;

        // send chosen strings. Thosen strings are read from messages. No extra
        // alignment is required.
        void sendChosen(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl);

        // No extra alignment is required.
        template<typename CorrelationFunc>
        void sendCorrelated(span<block> messages, const CorrelationFunc& corFunc, PRNG& prng, Channel& chl)
        {

            auto temp = allocAlignedBlockArray<std::array<block, 2>>(messages.size());
            std::vector<block> temp2(messages.size());
            send(span<std::array<block, 2>>(temp.get(), messages.size()), prng, chl);

            for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
            {
                messages[i] = temp[i][0];
                temp2[i] = temp[i][1] ^ corFunc(temp[i][0], i);
            }

            chl.asyncSend(std::move(temp2));
        }

    };

    class OtExtSender;
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

        virtual void genBaseOts(OtSender& sender, PRNG& prng, Channel& chl);
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
            PRNG& prng,
            Channel& chl) = 0;

        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtSender> split() = 0;

        // use the default base OT class to generate the
        // base OTs that are required.
        virtual void genBaseOts(PRNG& prng, Channel& chl);
        virtual void genBaseOts(OtReceiver& recver, PRNG& prng, Channel& chl);
    };


}
