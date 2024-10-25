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

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto {
	template <
		typename F,
		typename G,
		typename CoeffCtx
	>
	class NoisyVoleSender : public TimerAdapter
	{

	public:
		using VecF = typename CoeffCtx::template Vec<F>;

		// for chosen delta, compute b such htat
		//
		//  a = b + c * delta
		//
		template<typename FVec>
		task<> send(F delta, FVec& b, PRNG& prng,
			OtReceiver& ot, Socket& chl, CoeffCtx ctx)
		{
			MACORO_TRY{

			auto bv = ctx.binaryDecomposition(delta);
			auto otMsg = AlignedUnVector<block>{ };
			otMsg.resize(bv.size());

			setTimePoint("NoisyVoleSender.ot.begin");

			co_await ot.receive(bv, otMsg, prng, chl);
			setTimePoint("NoisyVoleSender.ot.end");

			co_await send(delta, b, prng, otMsg, chl, ctx);

			} MACORO_CATCH(eptr) {
				co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		// for chosen delta, compute b such htat
		//
		//  a = b + c * delta
		//
		template<typename FVec>
		task<> send(F delta, FVec& b, PRNG& _,
			span<block> otMsg, Socket& chl, CoeffCtx ctx)
		{
			MACORO_TRY{
			auto prng = PRNG{};
			auto buffer = std::vector<u8>{};
			auto msg = VecF{};
			auto temp = VecF{};
			auto xb = BitVector{};

			xb = ctx.binaryDecomposition(delta);

			if (otMsg.size() != xb.size())
				throw RTE_LOC;
			setTimePoint("NoisyVoleSender.main");

			// b = 0;
			ctx.zero(b.begin(), b.end());

			// receive the the excrypted one shares.
			buffer.resize(xb.size() * b.size() * ctx.template byteSize<F>());
			co_await chl.recv(buffer);
			ctx.resize(msg, xb.size() * b.size());
			ctx.deserialize(buffer.begin(), buffer.end(), msg.begin());

			setTimePoint("NoisyVoleSender.recvMsg");

			temp.resize(1);
			for (size_t i = 0, k = 0; i < xb.size(); ++i)
			{
				// expand the zero shares or one share masks
				prng.SetSeed(otMsg[i], b.size());

				// otMsg[i,j, bc[i]] 
				//auto otMsgi = prng.getBufferSpan(b.size());

				for (u64 j = 0; j < (u64)b.size(); ++j, ++k)
				{
					// temp = otMsg[i,j, xb[i]]
					ctx.fromBlock(temp[0], prng.get<block>());

					// temp = otMsg[i,j,xb[i]] + xb[i] * msg[i,j] 
					//      = otMsg[i,j,xb[i]] + xb[i] * (otMsg[i,j,0] + 2^i * y[j] - otMsg[i,j,1])
					//      = otMsg[i,j,xb[i]]           // if 0
					//      = otMsg[i,j,0] + 2^i * y[j]  // if 1
					//      = -b + 2^i * y[j]            // if 1
					if (xb[i])
						ctx.plus(temp[0], msg[k], temp[0]);

					// zj += msg - xb[i] * otMsg[i,j]
					ctx.plus(b[j], b[j], temp[0]);
				}
			}
			setTimePoint("NoisyVoleSender.done");


			} MACORO_CATCH(eptr) {
				co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

	};
}  // namespace osuCrypto

#endif