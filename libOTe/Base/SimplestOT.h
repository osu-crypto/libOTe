#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"


#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{

#if defined(ENABLE_SIMPLESTOT)
//#if defined(_MSC_VER)
//#    error "asm base simplest OT and windows is incompatible."
#if !(defined(ENABLE_SODIUM) || defined(ENABLE_RELIC))
#    error "Non-asm base Simplest OT requires libsodium or Relic"
#endif

    class SimplestOT : public OtReceiver, public OtSender
    {
    public:

        // set this to false if your use of the base OTs can tolerate
        // the receiver being able to choose the message that they receive.
        // If unsure leave as true as the strings will be uniform (safest but slower).
        bool mUniformOTs = true;


        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl,
            u64 numThreads)
        {
            return receive(choices, messages, prng, chl);
        }

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl,
            u64 numThreads)
        {
            return send(messages, prng, chl);
        }

        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl) override;

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override;
    };

#endif

#if defined(ENABLE_SIMPLESTOT_ASM) 
#if defined(_MSC_VER)
#    error "asm base simplest OT and windows is incompatible."
#endif

    void AsmSimplestOTTest();

    class AsmSimplestOT : public OtReceiver, public OtSender
    {
    public:
        // set this to false if your use of the base OTs can tolerate
        // the receiver being able to choose the message that they receive.
        // If unsure leave as true as the strings will be uniform (safest but slower).
        bool mUniformOTs = true;

        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl,
            u64 numThreads)
        {
            return receive(choices, messages, prng, chl);
        }

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl,
            u64 numThreads)
        {
            return send(messages, prng, chl);
        }

        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl) override;

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override;


        //void receive(
        //    const BitVector& choices,
        //    span<block> messages,
        //    PRNG& prng,
        //    Channel& chl);

        //void send(
        //    span<std::array<block, 2>> messages,
        //    PRNG& prng,
        //    Channel& chl);

    };

#endif
}
