#pragma once
// © 2025 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Code partially authored by:
// Maxime Bombar, Dung Bui, Geoffroy Couteau, Alain Couvreur, Clément Ducros, and Sacha Servan - Schreiber


#include "libOTe/config.h"
#if defined(ENABLE_FOLEAGE)

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Aligned.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Dpf/TernaryDpf.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"

namespace osuCrypto
{

	// The two party Foleage PCG protocol for generating F4 OLEs
	// and Binary Beaver triples. The caller should call
	//
	// FoleageTriple::init(...)
	// FoleageTriple::expand(...)
	// 
	// There are two expand function, one for OLEs and one for Triples.
	class FoleageTriple : public TimerAdapter
	{
	public:
		u64 mPartyIdx = 0;

		// the number of noisy positions per polynomial
		u64 mT = 27;

		// will be set to the log3 of mT.
		u64 mLog3T = 0;

		// the number of polynomials.
		u64 mC = 4;

		// the size of a polynomial, 3^mLog3N. 
		// We will produce this many OLEs.
		u64 mN = 0;

		// log3 polynomial size
		u64 mLog3N = 0;

		// The A poly in FFT format. We pack mC FFTs into a single u8. The 
		// first is hard coded to the identity polynomial.
		AlignedUnVector<u8> mFftA;

		// The A^2 poly in FFT format. We pack mC^2 FFTs into a single u32.
		AlignedVector<u32> mFftASquared;

		// the number of F4 values per block. Each block will have 1 non-zero.
		// A polynomial will have mT blocks. i.e. mN = mT * mBlockSize.
		u64 mBlockSize = 0;

		// The log3 of mBlockSize. 
		u64 mBlockDepth = 0;

		// The number of F4 elements that are packed into a leaf
		// of the main DPF. This will at most be 243.
		u64 mDpfLeafSize = 0;

		// The log3 of mDpfLeafSize. This will at most be 5.
		u64 mDpfLeafDepth = 0;

		// the number of F4x243 elements that the main DPF will output.
		// This will be approximately be mBlockSize / mDpfLeafSize.
		u64 mDpfTreeSize = 0;

		// The log3 of mDpfTreeSize.
		u64 mDpfTreeDepth = 0;

		// the locations of the non-zeros in the j'th block of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		Matrix<u64> mSparsePositions;

		// a dpf used to construct the F4x243 leaf value of the larger DPF.
		TernaryDpf<u8, CoeffCtxGF2> mDpfLeaf;

#ifdef ENABLE_SOFTSPOKEN_OT
		std::optional<SoftSpokenShOtReceiver<>> mOtExtRecver;
		std::optional<SoftSpokenShOtSender<>> mOtExtSender;
#endif

		struct FoleageCoeffCtx : CoeffCtxGF2
		{
			OC_FORCEINLINE void fromBlock(FoleageF4x243& ret, const block& b) {
				ret.mVal[0] = b;
				ret.mVal[1] = b ^ block(2314523225322345310, 3520873105824273452);
				ret.mVal[2] = b ^ block(3456459829022368567, 2452343456563201231);
				ret.mVal[3] = b ^ block(2430734095872024920, 8425914932983749298);
				mAesFixedKey.hashBlocks<4>(ret.mVal.data(), ret.mVal.data());
			}
		};

		// the main DPF which outputs 243 F4 elements for each leaf.
		TernaryDpf<FoleageF4x243, FoleageCoeffCtx> mDpf;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		std::vector<block> mRecvOts;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		std::vector<std::array<block, 2>> mSendOts;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		BitVector mChoiceOts;


		// Intializes the protocol to generate n F4 OLEs. Most efficient when n
		// is a power of 3. Once called, baseOtCount() can be called to 
		// determine the required number of base OTs.
		void init(u64 partyIdx, u64 n);

		bool isInitialized() const { return mN > 0; }

		struct BaseOtCount
		{
			// the number of base OTs as sender.
			u64 mSendCount = 0;

			// the number of base OTs as receiver.
			u64 mRecvCount = 0;
		};

		// returns the number of base OTs required. 
		BaseOtCount baseOtCount() const;

		// sets the base OTs that will be used.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices);

		// returns true of the base OTs have been set.
		bool hasBaseOts() const;

		macoro::task<> genBaseOts(PRNG& prng, Socket& sock, SilentBaseType baseType = SilentBaseType::BaseExtend);

		// The F4 OLE protocol. This will generate n OLEs.
		// the resulting OLEs are in bit decomposition form.
		// A = (AMsb || ALsb), C = (CMsb || CLsb). This party will
		// output (A,C) while the other outputs (A',C') such that
		// A * A' = C + C'.
		macoro::task<> expand(
			span<block> ALsb,
			span<block> AMsb,
			span<block> CLsb,
			span<block> CMsb,
			PRNG& prng,
			coproto::Socket& sock);


		// The F2 beaver triple protocol. This will generate n beaver triples.
		macoro::task<> expand(
			span<block> A,
			span<block> B,
			span<block> C,
			PRNG& prng,
			coproto::Socket& sock)
		{
			if (mPartyIdx)
			{
				co_await expand(B, A, C, {}, prng, sock);

				for (u64 i = 0; i < A.size(); ++i)
				{
					// b(0)b(1)
					auto bb = B[i] & A[i];
					// b(0)b(1) + [ab]1(0)
					C[i] ^= bb;
				}
			}
			else
			{
				//auto bLsb = temp[0];
				//auto bMsb = temp[1];
				co_await expand(A, B, C, {}, prng, sock);

				for (u64 i = 0; i < A.size(); ++i)
				{
					// a(0)a(1)
					auto aa = A[i] & B[i];

					// a(0)a(1) + [ab]0(0)
					C[i] ^= aa;
				}
			}
		}

		// sample random coefficients for the sparse polynomial and tensor
		// them with the other parties coefficients. The result is shared
		// as tensoredCoefficients. We allow the coeff to be zero.
		macoro::task<> tensor(span<u8> coeffs, span<u8> prod, coproto::Socket& sock);

		// sample the A polynomial. This is the polynomial that will be
		// multiplied the sparse polynomials by.
		void sampleA(block seed);


	};


}
#endif