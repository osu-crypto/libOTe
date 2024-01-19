#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <libOTe/config.h>
#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "libOTe/Tools/Subfield/Subfield.h"

namespace osuCrypto {

    template <
        typename F,
        typename G = F,
        typename CoeffCtx = DefaultCoeffCtx<F, G>
    >
    class NoisySubfieldVoleReceiver : public TimerAdapter
    {
    public:

        // for chosen c, compute a such htat
        //
        //  a = b + c * delta
        //
        template<typename VecG, typename VecF>
        task<> receive(VecG& c, VecF& a, PRNG& prng,
            OtSender& ot, Socket& chl)
        {
            MC_BEGIN(task<>, this, &c, &a, &prng, &ot, &chl,
                otMsg = AlignedUnVector<std::array<block, 2>>{});

            setTimePoint("NoisyVoleReceiver.ot.begin");
            otMsg.resize(CoeffCtx::bitSize<F>());
            MC_AWAIT(ot.send(otMsg, prng, chl));

            setTimePoint("NoisyVoleReceiver.ot.end");

            MC_AWAIT(receive(c, a, prng, otMsg, chl));

            MC_END();
        }

        // for chosen c, compute a such htat
        //
        //  a = b + c * delta
        //
        template<typename VecG, typename VecF>
        task<> receive(VecG& c, VecF& a, PRNG& _,
            span<std::array<block, 2>> otMsg,
            Socket& chl)
        {
            MC_BEGIN(task<>, this, &c, &a, otMsg, &chl,
                buff = std::vector<u8>{},
                msg = typename CoeffCtx::Vec<F>{},
                temp = typename CoeffCtx::Vec<F>{},
                prng = std::move(PRNG{})
            );

            if (c.size() != a.size())
                throw RTE_LOC;
            if (a.size() == 0)
                throw RTE_LOC;

            setTimePoint("NoisyVoleReceiver.begin");

            CoeffCtx::zero(a.begin(), a.end());
            CoeffCtx::resize(msg, otMsg.size() * a.size());
            CoeffCtx::resize(temp, 2);

            for (size_t i = 0, k = 0; i < otMsg.size(); ++i)
            {
                prng.SetSeed(otMsg[i][0], a.size());

                // t1 = 2^i
                CoeffCtx::powerOfTwo(temp[1], i);
                //std::cout << "2^i " << CoeffCtx::str(temp[1]) << "\n";

                for (size_t j = 0; j < c.size(); ++j, ++k)
                {
                    // msg[i,j] = otMsg[i,j,0]
                    CoeffCtx::fromBlock<F>(msg[k], prng.get<block>());
                    //CoeffCtx::zero(msg.begin() + k, msg.begin() + k + 1);
                    //std::cout << "m" << i << ",0 = " << CoeffCtx::str(msg[k]) << std::endl;

                    // a[j] += otMsg[i,j,0]
                    CoeffCtx::plus(a[j], a[j], msg[k]);
                    //std::cout << "z = " << CoeffCtx::str(a[j]) << std::endl;

                    // temp = 2^i * c[j]
                    CoeffCtx::mul(temp[0], temp[1], c[j]);
                    //std::cout << "2^i y = " << CoeffCtx::str(temp[0]) << std::endl;

                    // msg[i,j] = otMsg[i,j,0] + 2^i * c[j]
                    CoeffCtx::minus(msg[k], msg[k], temp[0]);
                    //std::cout << "m" << i << ",0 + 2^i y = " << CoeffCtx::str(msg[k]) << std::endl;
                }

                k -= c.size();
                prng.SetSeed(otMsg[i][1], a.size());

                for (size_t j = 0; j < c.size(); ++j, ++k)
                {
                    // temp = otMsg[i,j,1]
                    CoeffCtx::fromBlock(temp[0], prng.get<block>());
                    //CoeffCtx::zero(temp.begin(), temp.begin() + 1);
                    //std::cout << "m" << i << ",1 = " << CoeffCtx::str(temp[0]) << std::endl;

                    // enc one message under the OT msg.
                    // msg[i,j] = (otMsg[i,j,0] + 2^i * c[j]) - otMsg[i,j,1]
                    CoeffCtx::minus(msg[k], msg[k], temp[0]);
                    //std::cout << "m" << i << ",0 + 2^i y - m" << i << ",1 = " << CoeffCtx::str(msg[k]) << std::endl << std::endl;
                }
            }

            buff.resize(msg.size() * CoeffCtx::byteSize<F>());
            CoeffCtx::serialize(msg.begin(), msg.end(), buff.begin());

            MC_AWAIT(chl.send(std::move(buff)));
            setTimePoint("NoisyVoleReceiver.done");

            MC_END();
        }

    };

}  // namespace osuCrypto
#endif
