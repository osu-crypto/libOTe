#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Network/Channel.h>
#include <array>
#include "libOTe/Tools/Coproto.h"
#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{
    class PRNG;
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
        virtual task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl) = 0;

        // Receive chosen strings indexed by choices. The chosen strings will be written to 
        // messages. messages must have the same alignment as an AlignedBlockPtr, i.e. 32
        // bytes with avx or 16 bytes without avx.
        task<> receiveChosen(
            const BitVector& choices,
            span<block> recvMessages,
            PRNG& prng,
            Socket& chl);


        task<> receiveCorrelated(
            const BitVector& choices,
            span<block> recvMessages,
            PRNG& prng,
            Socket& chl);

    };

    class OtSender
    {
    public:
        OtSender() {}
        virtual ~OtSender() = default;

        // send random strings. The random strings will be written to 
        // messages.
        virtual task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) = 0;

        // send chosen strings. Thosen strings are read from messages.
        task<> sendChosen(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl);

        // No extra alignment is required.
        template<typename CorrelationFunc>
        task<> sendCorrelated(span<block> messages, const CorrelationFunc& corFunc, PRNG& prng, Socket& chl)
        {
            MC_BEGIN(task<>,this, messages, &corFunc, &prng, &chl,
                temp = AlignedUnVector<std::array<block, 2>>(messages.size()),
                temp2 = AlignedUnVector<block>(messages.size())
            );
            MC_AWAIT(send(temp, prng, chl));

            for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
            {
                messages[i] = temp[i][0];
                temp2[i] = temp[i][1] ^ corFunc(temp[i][0], i);
            }

            MC_AWAIT(chl.send(std::move(temp2)));
            MC_END();
        }

    };

    class OtExtSender;
    class OtExtReceiver : public OtReceiver
    {
    public:
        OtExtReceiver() {}
        
        // sets the base OTs that are then used to extend
        virtual void setBaseOts(
            span<std::array<block,2>> baseSendOts) = 0;
        
        // the number of base OTs that should be set.
        virtual u64 baseOtCount() const { return gOtExtBaseOtCount; }

        // returns true if the base OTs are currently set.
        virtual bool hasBaseOts() const = 0;

        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtReceiver> split() = 0;

        // use the default base OT class to generate the
        // base OTs that are required.
        virtual task<> genBaseOts(PRNG& prng, Socket& chl);
        virtual task<> genBaseOts(OtSender& sender, PRNG& prng, Socket& chl);

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
            const BitVector& choices)  = 0;

        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtSender> split() = 0;

        // use the default base OT class to generate the
        // base OTs that are required.
        virtual task<> genBaseOts(PRNG& prng, Socket& chl);
        virtual task<> genBaseOts(OtReceiver& recver, PRNG& prng, Socket& chl);

    };


}
