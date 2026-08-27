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
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include <utility>

namespace osuCrypto
{
	enum class FoleageMode
	{
		F4Ole,
		F2TraceOle
	};

	enum class FoleageDpfMode
	{
		TernaryDpf,
		RevCuckoo
	};

	// The two party Foleage PCG protocol for generating F4 OLEs,
	// trace-derived binary OLEs, and binary Beaver triples. The caller should call
	//
	// FoleageTriple::init(...)
	// FoleageTriple::expand(...)
	// 
	// There are two expand function, one for OLEs and one for Triples.
	class FoleageTriple : public TimerAdapter
	{
	public:
		FoleageTriple() = default;
		FoleageTriple(const FoleageTriple&) = delete;
		FoleageTriple& operator=(const FoleageTriple&) = delete;

		FoleageTriple(FoleageTriple&& src)
		{
			*this = std::move(src);
		}

		FoleageTriple& operator=(FoleageTriple&& src)
		{
			if (this == &src)
				return *this;

			mTimer = std::exchange(src.mTimer, nullptr);
			mPartyIdx = std::exchange(src.mPartyIdx, 0);
			mMode = std::exchange(src.mMode, FoleageMode::F4Ole);
			mDpfMode = std::exchange(src.mDpfMode, FoleageDpfMode::TernaryDpf);
			mT = std::exchange(src.mT, 9);
			mLog3T = std::exchange(src.mLog3T, 0);
			mC = std::exchange(src.mC, 8);
			mN = std::exchange(src.mN, 0);
			mLog3N = std::exchange(src.mLog3N, 0);
			mFftA = std::move(src.mFftA);
			mFftASquared = std::move(src.mFftASquared);
			mFftAFrobenius = std::move(src.mFftAFrobenius);
			mBlockSize = std::exchange(src.mBlockSize, 0);
			mBlockDepth = std::exchange(src.mBlockDepth, 0);
			mDpfLeafSize = std::exchange(src.mDpfLeafSize, 0);
			mDpfLeafDepth = std::exchange(src.mDpfLeafDepth, 0);
			mDpfTreeSize = std::exchange(src.mDpfTreeSize, 0);
			mDpfTreeDepth = std::exchange(src.mDpfTreeDepth, 0);
			mSparsePositions = std::move(src.mSparsePositions);
			mDpfLeaf = std::move(src.mDpfLeaf);
#ifdef ENABLE_SOFTSPOKEN_OT
			mOtExtRecver = std::move(src.mOtExtRecver);
			mOtExtSender = std::move(src.mOtExtSender);
#endif
			mDpf = std::move(src.mDpf);
			mRecvOts = std::move(src.mRecvOts);
			mSendOts = std::move(src.mSendOts);
			mChoiceOts = std::move(src.mChoiceOts);
			mBaseOtsAvailable = std::exchange(src.mBaseOtsAvailable, false);

			src.mFftA.clear();
			src.mFftASquared.clear();
			src.mFftAFrobenius.clear();
			src.mSparsePositions = {};
#ifdef ENABLE_SOFTSPOKEN_OT
			src.mOtExtRecver.reset();
			src.mOtExtSender.reset();
#endif
			src.mRecvOts.clear();
			src.mSendOts.clear();
			src.mChoiceOts = {};
			return *this;
		}

		u64 mPartyIdx = 0;
		FoleageMode mMode = FoleageMode::F4Ole;
		FoleageDpfMode mDpfMode = FoleageDpfMode::TernaryDpf;

		// the number of noisy positions per polynomial
		u64 mT = 9;

		// will be set to the log3 of mT.
		u64 mLog3T = 0;

		// the number of polynomials.
		u64 mC = 8;

		// the size of a polynomial, 3^mLog3N. 
		// We will produce this many OLEs.
		u64 mN = 0;

		// log3 polynomial size
		u64 mLog3N = 0;

		// The A poly in FFT format. We pack mC FFTs into a single u8. The 
		// first is hard coded to the identity polynomial.
		AlignedUnVector<u16> mFftA;

		// The A^2 poly in FFT format. We pack mC^2 FFTs into a single block.
		AlignedVector<block> mFftASquared;

		// The packed A_r A_s^2 public coefficients used by trace OLE mode.
		AlignedVector<block> mFftAFrobenius;

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
		// the i'th row contains the coefficients for the i'th polynomial.
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

		// True exactly when a complete, unused base-OT set is installed.
		bool mBaseOtsAvailable = false;


		// Initializes the selected correlation mode. The protocol is most efficient
		// when n is a power of 3. Once called, baseOtCount() returns the required
		// number of base OTs.
		void init(
			u64 partyIdx,
			u64 n,
			FoleageMode mode = FoleageMode::F4Ole,
			FoleageDpfMode dpfMode = FoleageDpfMode::TernaryDpf);

		bool isInitialized() const { return mN > 0; }

		struct BaseCount
		{
			// the number of base OTs as sender.
			u64 mSendCount = 0;

			// the number of base OTs as receiver.
			u64 mRecvCount = 0;
		};

		// returns the number of base OTs required. 
		BaseCount baseOtCount() const;

		// sets the base OTs that will be used.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices);

		// returns true of the base OTs have been set.
		bool hasBaseOts() const;

		// Clears all base OTs and marks the current set as unavailable.
		void clearBaseOts();

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
		macoro::task<> tensor(span<u16> coeffs, span<u16> prod, coproto::Socket& sock);

		// As tensor(), and additionally shares a_i * b_j^2 without consuming
		// additional OTs or sending additional messages.
		macoro::task<> tensorTrace(
			span<u16> coeffs,
			span<u16> prod,
			span<u16> prodFrobenius,
			coproto::Socket& sock);

		// Generates two binary OLEs from the F4 correlation using the trace
		// maps Tr(x) and Tr(xi*x). The outputs satisfy
		//   ZTrace_0 + ZTrace_1 = XTrace_0 * XTrace_1, and
		//   ZXiTrace_0 + ZXiTrace_1 = XXiTrace_0 * XXiTrace_1.
		macoro::task<> expandF2Ole(
			span<block> XTrace,
			span<block> XXiTrace,
			span<block> ZTrace,
			span<block> ZXiTrace,
			PRNG& prng,
			coproto::Socket& sock);

		// sample the A polynomial. This is the polynomial that will be
		// multiplied the sparse polynomials by.
		void sampleA(block seed);

	private:
		template<bool Trace>
		macoro::task<> tensorImpl(
			span<u16> coeffs,
			span<u16> prod,
			span<u16> prodFrobenius,
			coproto::Socket& sock);


	};


}
#endif
