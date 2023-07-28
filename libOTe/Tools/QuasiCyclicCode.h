#pragma once
// © 2022 Visaß.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_BITPOLYMUL

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/ThreadBarrier.h"
#include "bitpolymul.h"
#include "Tools.h"
#include "LDPC/Mtx.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include <cmath>

namespace osuCrypto
{

	// https://eprint.iacr.org/2019/1159.pdf
	struct QuasiCyclicCode : public TimerAdapter
	{
	private:
		u64 mScaler = 0;
		u64 mNumThreads = 1;

		// the length of the encoding
		u64 mP = 0;

		// the length of the input. mM = mP * mScaler;
		u64 mM = 0;

	public:

		//size of the input
		u64 size() { return mM; }

		// initialize the compressing matrix that maps a
		// vector of size n * scaler to a vector of size n.
		void init(u64 n, u64 scaler = 2)
		{
			if (scaler <= 1)
				throw RTE_LOC;

			if (isPrime(n) == false)
				throw RTE_LOC;

			mP = n;// nextPrime(n);
			//mN = n;
			mM = mP * scaler;
			mScaler = scaler;
		}

		static void bitShiftXor(span<block> dest, span<block> in, u8 bitShift)
		{
			if (bitShift > 127)
				throw RTE_LOC;
			if (u64(in.data()) % 16)
				throw RTE_LOC;

			if (bitShift >= 64)
			{
				bitShift -= 64;
				const int bitShift2 = 64 - bitShift;
				u8* inPtr = ((u8*)in.data()) + sizeof(u64);

				auto end = std::min<u64>(dest.size(), in.size() - 1);
				for (u64 i = 0; i < end; ++i, inPtr += sizeof(block))
				{
					block
						b0 = toBlock(inPtr),
						b1 = toBlock(inPtr + sizeof(u64));

					b0 = (b0 >> bitShift);
					b1 = (b1 << bitShift2);

					dest[i] = dest[i] ^ b0 ^ b1;
				}

				if (end != static_cast<u64>(dest.size()))
				{
					u64 b0 = *(u64*)inPtr;
					b0 = (b0 >> bitShift);

					*(u64*)(&dest[end]) ^= b0;
				}
			}
			else if (bitShift)
			{
				const int bitShift2 = 64 - bitShift;
				u8* inPtr = (u8*)in.data();

				auto end = std::min<u64>(dest.size(), in.size() - 1);
				for (u64 i = 0; i < end; ++i, inPtr += sizeof(block))
				{
					block
						b0 = toBlock(inPtr),
						b1 = toBlock(inPtr + sizeof(u64));

					b0 = (b0 >> bitShift);
					b1 = (b1 << bitShift2);

					//bv0.append((u8*)&b0, 128);
					//bv1.append((u8*)&b1, 128);

					dest[i] = dest[i] ^ b0 ^ b1;
				}

				if (end != static_cast<u64>(dest.size()))
				{
					block b0 = toBlock(inPtr);
					b0 = (b0 >> bitShift);

					//bv0.append((u8*)&b0, 128);

					dest[end] = dest[end] ^ b0;

					u64 b1 = *(u64*)(inPtr + sizeof(u64));
					b1 = (b1 << bitShift2);

					//bv1.append((u8*)&b1, 64);

					*(u64*)&dest[end] ^= b1;
				}



				//std::cout << " b0     " << bv0 << std::endl;
				//std::cout << " b1     " << bv1 << std::endl;
			}
			else
			{
				auto end = std::min<u64>(dest.size(), in.size());
				for (u64 i = 0; i < end; ++i)
				{
					dest[i] = dest[i] ^ in[i];
				}
			}
		}

		static void modp(span<block> dest, span<block> in, u64 p)
		{
			auto pBlocks = (p + 127) / 128;
			auto pBytes = (p + 7) / 8;

			if (static_cast<u64>(dest.size()) < pBlocks)
				throw RTE_LOC;

			if (static_cast<u64>(in.size()) < pBlocks)
				throw RTE_LOC;

			auto count = (in.size() * 128 + p - 1) / p;

			memcpy(dest.data(), in.data(), pBytes);

			for (u64 i = 1; i < count; ++i)
			{
				auto begin = i * p;
				auto end = std::min<u64>(i * p + p, in.size() * 128);

				auto shift = begin & 127;
				auto beginBlock = in.data() + (begin / 128);
				auto endBlock = in.data() + ((end + 127) / 128);

				if (endBlock > in.data() + in.size())
					throw RTE_LOC;


				auto in_i = span<block>(beginBlock, endBlock);

				bitShiftXor(dest, in_i, static_cast<u8>(shift));
			}


			auto offset = (p & 7);
			if (offset)
			{
				u8 mask = (1 << offset) - 1;
				auto idx = p / 8;
				((u8*)dest.data())[idx] &= mask;
			}

			auto rem = dest.size() * 16 - pBytes;
			if (rem)
				memset(((u8*)dest.data()) + pBytes, 0, rem);
		}

		void dualEncode(span<u8> X)
		{
			std::vector<block> XX(X.size());
			for (auto i : rng(X.size()))
			{
				if (X[i] > 1)
					throw RTE_LOC;

				XX[i] = block(X[i], X[i]);
			}
			dualEncode(XX);
			for (auto i : rng(X.size()))
			{
				X[i] = XX[i] == ZeroBlock ? 0 : 1;
			}
		}

		inline void transpose(span<block> s, MatrixView<block> r)
		{
			MatrixView<u8> ss((u8*)s.data(), s.size(), sizeof(block));
			MatrixView<u8> rr((u8*)r.data(), r.rows(), r.cols() * sizeof(block));
			::oc::transpose(ss, rr);
		}


		void dualEncode(span<block> X)
		{
			if(X.size() != mM)
				throw RTE_LOC;
			const u64 rows(128);

			auto nBlocks = (mP + rows-1) / rows;
			auto n2Blocks = ((mM-mP) + rows -1) / rows;

			Matrix<block> XT(rows, n2Blocks);
			transpose(X.subspan(mP), XT);

			auto n64 = i64(nBlocks * 2);
			
			std::vector<FFTPoly> a(mScaler - 1);

			Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);

			//std::unique_ptr<ThreadBarrier[]> brs(new ThreadBarrier[mScaler + 1]);
			//for (u64 i = 0; i <= mScaler; ++i)
				//brs[i].reset(mNumThreads);

			//auto routine = [&](u64 index)
			{
				//u64 j = 0;

				//{
				//	std::array<block, 128> tpBuffer;
				//	auto numBlocks = mM / 128;
				//	auto begin = index * numBlocks / mNumThreads;
				//	auto end = (index + 1) * numBlocks / mNumThreads;

				//	for (u64 i = begin; i < end; ++i)
				//	{
				//		u64 j = i * tpBuffer.size();

				//		for (u64 k = 0; k < tpBuffer.size(); ++k)
				//			tpBuffer[k] = X[j + k];

				//		transpose128(tpBuffer);

				//		auto end = i * tpBuffer.size() + 128;
				//		for (u64 k = 0; j < end; ++j, ++k)
				//			X[j] = tpBuffer[k];
				//	}

				//	if (index == 0)
				//		setTimePoint("sender.expand.qc.transposeXor");
				//}

				//brs[j++].decrementWait();

				FFTPoly bPoly;
				FFTPoly cPoly;

				AlignedUnVector<block> temp128(2 * nBlocks);

				FFTPoly::DecodeCache cache;
				for (u64 s = 1; s < mScaler; s += 1)
				{
					auto a64 = spanCast<u64>(temp128).subspan(n64);
					PRNG pubPrng(toBlock(s));
					pubPrng.get(a64.data(), a64.size());
					//memset(a64.data(), 0, a64.size() * sizeof(u64));
					//a64[0] = 1;

					a[s - 1].encode(a64);
				}


				//auto multAddReduce = [this, nBlocks, n64, &a, &bPoly, &cPoly, &temp128, &cache](span<block> b128, span<block> dest)
				//{

				//};

				for (u64 i = 0; i < rows; i += 1)
				{

					for (u64 s = 0; s < mScaler-1; ++s)
					{
						auto& aPoly = a[s];
						auto b64 = spanCast<u64>(XT[i]).subspan(s * n64, n64);

						bPoly.encode(b64);

						if (s == 0)
						{
							cPoly.mult(aPoly, bPoly);
						}
						else
						{
							bPoly.multEq(aPoly);
							cPoly.addEq(bPoly);
						}
					}

					// decode c[i] and store it at t64Ptr
					cPoly.decode(spanCast<u64>(temp128), cache, true);

					//for (u64 j = 0; j < nBlocks; ++j)
					//	temp128[j] = temp128[j] ^ XT[i][j];

					// reduce s[i] mod (x^p - 1) and store it at cModP1[i]
					modp(cModP1[i], temp128, mP);
				}
					//multAddReduce(rT[i], cModP1[i]);

				//if (index == 0)
				//	setTimePoint("sender.expand.qc.mulAddReduce");

				//brs[j++].decrementWait();

				{

					AlignedArray<block, 128> tpBuffer;
					auto numBlocks = (mP + 127) / 128;
					auto begin = 0 * numBlocks / mNumThreads;
					auto end = (1) * numBlocks / mNumThreads;
					for (u64 i = begin; i < end; ++i)
					{
						u64 j = i * tpBuffer.size();
						auto min = std::min<u64>(tpBuffer.size(), mP - j);

						for (u64 k = 0; k < tpBuffer.size(); ++k)
							tpBuffer[k] = cModP1(k, i);

						transpose128(tpBuffer.data());

						auto end = i * tpBuffer.size() + min;
						for (u64 k = 0; j < end; ++j, ++k)
							X[j] = X[j] ^ tpBuffer[k];
					}

					//if (index == 0)
					//	setTimePoint("sender.expand.qc.transposeXor");
				}
			};

			//std::vector<std::thread> thrds(mNumThreads - 1);
			//for (u64 i = 0; i < thrds.size(); ++i)
			//	thrds[i] = std::thread(routine, i);

			//routine(thrds.size());

			//for (u64 i = 0; i < thrds.size(); ++i)
			//	thrds[i].join();
		}


		DenseMtx getMatrix()
		{

			DenseMtx mtx(mM, mP);



			for (u64 i = 0; i < mM; ++i)
			{
				std::vector<block> in(mM);
				in[i] = oc::AllOneBlock;

				dualEncode(in);

				u64 w = 0;
				for (u64 j = 0; j < mP; ++j)
				{
					if (in[j] == oc::AllOneBlock)
					{
						++w;
						mtx(i, j) = 1;
					}
					else if (in[j] == oc::ZeroBlock)
					{
					}
					else
						throw RTE_LOC;
				}

				if (std::abs((long long)(mP - w)) < mP / 2 - std::sqrt(mP))
					throw RTE_LOC;
			}

			return mtx;
		}
	};

}

#endif
