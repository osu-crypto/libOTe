#pragma once
// © 2024 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_MOCK_OT

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
namespace osuCrypto
{

    class INSECURE_MOCK_OT : public OtReceiver, public OtSender
    {
    public:

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
            Socket& chl) override
        {
            struct Warning
            {

                ~Warning()
                {
                    std::cout << "warning, INSECURE_MOCK_OT was used. The program is insecure." << LOCATION << std::endl;
                }
            };
            static Warning w;

            block seed = prng.get();
            co_await chl.send(seed);

            std::vector<std::array<block, 2>> all(messages.size());

            PRNG sPrng(seed);
            sPrng.get(all.data(), all.size());

            for (u64 i = 0; i < all.size(); ++i)
            {
                messages[i] = all[i][choices[i]];
            }
        }

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override
        {
            block seed;
            co_await chl.recv(seed);
            PRNG sPrng(seed);
            sPrng.get(messages.data(), messages.size());
        }
    };

}
#endif