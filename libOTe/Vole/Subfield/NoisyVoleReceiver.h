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

        template<typename VecG, typename VecF>
        task<> receive(VecG&& y, VecF&& z, PRNG& prng,
            OtSender& ot, Socket& chl)
        {
            MC_BEGIN(task<>, this, y, z, &prng, &ot, &chl,
                otMsg = AlignedUnVector<std::array<block, 2>>{});

            setTimePoint("NoisyVoleReceiver.ot.begin");

            MC_AWAIT(ot.send(otMsg, prng, chl));

            setTimePoint("NoisyVoleReceiver.ot.end");

            MC_AWAIT(receive(y, z, prng, otMsg, chl));

            MC_END();
        }

        template<typename VecG, typename VecF>
        task<> receive(VecG&& y, VecF&& z, PRNG& _,
            span<std::array<block, 2>> otMsg,
            Socket& chl)
        {
            MC_BEGIN(task<>, this, y, z, otMsg, &chl,
                buff = std::vector<u8>{},
                msg = typename CoeffCtx::Vec<F>{},
                temp = typename CoeffCtx::Vec<F>{},
                prng = std::move(PRNG{})
            );

            if (y.size() != z.size())
                throw RTE_LOC;
            if (z.size() == 0)
                throw RTE_LOC;

            setTimePoint("NoisyVoleReceiver.begin");

            CoeffCtx::zero(z.begin(), z.end());
            CoeffCtx::resize(msg, otMsg.size() * z.size());
            CoeffCtx::resize(temp, 2);

            for (size_t i = 0, k = 0; i < otMsg.size(); ++i)
            {
                prng.SetSeed(otMsg[i][0], z.size());

                // t1 = 2^i
                CoeffCtx::pow(temp[1], i);

                for (size_t j = 0; j < y.size(); ++j, ++k)
                {
                    // msg[i,j] = otMsg[i,j,0]
                    CoeffCtx::fromBlock<F>(msg[k], prng.get<block>());

                    // z[j] -= otMsg[i,j,0]
                    CoeffCtx::minus(z[j], z[j], msg[k]);

                    // temp = 2^i * y[j]
                    CoeffCtx::mul(temp[0], temp[1], y[j]);

                    // msg[i,j] = otMsg[i,j,0] + 2^i * y[j]
                    CoeffCtx::plus(msg[k], msg[k], temp[0]);
                }

                k -= y.size();
                prng.SetSeed(otMsg[i][1], z.size());

                for (size_t j = 0; j < y.size(); ++j, ++k)
                {
                    // temp = otMsg[i,j,1]
                    CoeffCtx::fromBlock(temp[0], prng.get<block>());

                    // enc one message under the OT msg.
                    // msg[i,j] = (otMsg[i,j,0] + 2^i * y[j]) - otMsg[i,j,1]
                    CoeffCtx::minus(msg[k], msg[k], temp[0]);
                }
            }

            buff.resize(msg.size() * CoeffCtx::byteSize<F>());
            CoeffCtx::serialize(buff, msg);

            MC_AWAIT(chl.send(std::move(buff)));
            setTimePoint("NoisyVoleReceiver.done");

            MC_END();
        }

    };

}  // namespace osuCrypto
#endif
