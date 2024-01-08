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

// This code implements features described in [Silver: Silent VOLE and Oblivious
// Transfer from Hardness of Decoding Structured LDPC Codes,
// https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative
// Commons Attribution 4.0 International Public License
// (https://creativecommons.org/licenses/by/4.0/legalcode).

#include <libOTe/config.h>
#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"

namespace osuCrypto::Subfield {

    template <typename TypeTrait>
    class NoisySubfieldVoleReceiver : public TimerAdapter {
    public:
        using F = typename TypeTrait::F;
        using G = typename TypeTrait::G;
        task<> receive(span<G> y, span<F> z, PRNG& prng,
            OtSender& ot, Socket& chl) {
            MC_BEGIN(task<>, this, y, z, &prng, &ot, &chl,
                otMsg = AlignedUnVector<std::array<block, 2>>{ TypeTrait::bitsF });

            setTimePoint("NoisyVoleReceiver.ot.begin");

            MC_AWAIT(ot.send(otMsg, prng, chl));

            setTimePoint("NoisyVoleReceiver.ot.end");

            MC_AWAIT(receive(y, z, prng, otMsg, chl));

            MC_END();
        }

        task<> receive(span<G> y, span<F> z, PRNG& _,
            span<std::array<block, 2>> otMsg,
            Socket& chl) {
            MC_BEGIN(task<>, this, y, z, otMsg, &chl, 
                msg = Matrix<F>{},
                prng = std::move(PRNG{})
            );

            if (otMsg.size() != TypeTrait::bitsF) throw RTE_LOC;
            if (y.size() != z.size()) throw RTE_LOC;
            if (z.size() == 0) throw RTE_LOC;

            setTimePoint("NoisyVoleReceiver.begin");

            memset(z.data(), 0, TypeTrait::bytesF * z.size());
            msg.resize(otMsg.size(), z.size(), AllocType::Uninitialized);

            for (size_t ii = 0; ii < TypeTrait::bitsF; ++ii) {
                prng.SetSeed(otMsg[ii][0], z.size());
                auto& buffer = prng.mBuffer;
                auto pow = TypeTrait::pow(ii);
                for (size_t j = 0; j < y.size(); ++j) {
                    auto bufj = TypeTrait::fromBlock(buffer[j]);
                    z[j] = TypeTrait::plus(z[j], bufj);
                    F yy = TypeTrait::mul(pow, y[j]);

                    msg(ii, j) = TypeTrait::plus(yy, bufj);
                }

                prng.SetSeed(otMsg[ii][1], z.size());

                for (size_t j = 0; j < y.size(); ++j) {
                    // enc one message under the OT msg.
                    msg(ii, j) = TypeTrait::plus(msg(ii, j), TypeTrait::fromBlock(prng.mBuffer[j]));
                }
            }

            MC_AWAIT(chl.send(std::move(msg)));
            setTimePoint("NoisyVoleReceiver.done");

            MC_END();
        }

    };

}  // namespace osuCrypto
#endif
