#pragma once
// © 2025 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#include "libOTe/config.h"
#if defined(ENABLE_RINGLPN)

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Aligned.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Dpf/RegularDpf.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/Tools/Ntt/NttNegWrap.h"
namespace osuCrypto
{

	// The two party RingLpn PCG protocol for generating F OLEs
	// and Binary Beaver triples. The caller should call
	//
	// RingLpnTriple::init(...)
	// RingLpnTriple::expand(...)
	// 
	// There are two expand function, one for OLEs and one for Triples.
	template<typename F>
	class RingLpnTriple : public TimerAdapter
	{
	public:
		u64 mPartyIdx = 0;

		// the number of noisy positions per polynomial
		u64 mT = 8;

		// the number of polynomials.
		u64 mC = 4;

		// the size of a polynomial, 2^mLogN. 
		// We will produce this many OLEs.
		u64 mN = 0;

		// log2 polynomial size
		u64 mLogN = 0;

		// The A poly in FFT format. There will be mC rows. 
		Matrix<F> mFftA;

		// The A^2 poly in FFT format. There will be mC^2 rows. 
		Matrix<F> mFftASquared;

		// the number of F values per block. Each block will have 1 non-zero.
		// A polynomial will have mT blocks. i.e. mN = mT * mBlockSize.
		u64 mBlockSize = 0;

		// The log2 of mBlockSize. 
		u64 mBlockDepth = 0;

		//// The number of F elements that are packed into a leaf
		//// of the main DPF.
		//u64 mDpfLeafSize = 0;

		//// The log2 of mDpfLeafSize.
		//u64 mDpfLeafDepth = 0;

		// the number of F^mDpfLeafSize elements that the main DPF will output.
		// This will be approximately be mBlockSize / log2|F| * mDpfLeafSize.
		u64 mDpfTreeSize = 0;

		// The log2 of mDpfTreeSize.
		u64 mDpfTreeDepth = 0;

		// the locations of the non-zeros in the j'th block of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		Matrix<u64> mSparsePositions;

		// a dpf used to construct the F^mDpfLeafSize leaf value of the larger DPF.
		//RegularDpf<F, CoeffCtxInteger> mDpfLeaf;

#ifdef ENABLE_SOFTSPOKEN_OT
		std::optional<SoftSpokenShOtReceiver<>> mOtExtRecver;
		std::optional<SoftSpokenShOtSender<>> mOtExtSender;
#endif

		//struct RingLpnCoeffCtx : CoeffCtxGF2
		//{
		//	OC_FORCEINLINE void fromBlock(RingLpnF4x243& ret, const block& b) {
		//		ret.mVal[0] = b;
		//		ret.mVal[1] = b ^ block(2314523225322345310, 3520873105824273452);
		//		ret.mVal[2] = b ^ block(3456459829022368567, 2452343456563201231);
		//		ret.mVal[3] = b ^ block(2430734095872024920, 8425914932983749298);
		//		mAesFixedKey.hashBlocks<4>(ret.mVal.data(), ret.mVal.data());
		//	}
		//};

		// the main DPF which outputs 243 F4 elements for each leaf.
		RegularDpf/*<F, CoeffCtxInteger>*/ mDpf;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		std::vector<block> mRecvOts;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		std::vector<std::array<block, 2>> mSendOts;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		BitVector mChoiceOts;


		// Intializes the protocol to generate n F OLEs. Most efficient when n
		// is a power of 2. Once called, baseOtCount() can be called to 
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

		// The F OLE protocol. This will generate n OLEs.
		// the resulting OLEs are in bit decomposition form.
		// A = (AMsb || ALsb), C = (CMsb || CLsb). This party will
		// output (A,C) while the other outputs (A',C') such that
		// A * A' = C + C'.
		macoro::task<> expand(
			span<F> A,
			span<F> C,
			PRNG& prng,
			coproto::Socket& sock);


		// The F beaver triple protocol. This will generate n beaver triples.
		macoro::task<> expand(
			span<F> A,
			span<F> B,
			span<F> C,
			PRNG& prng,
			coproto::Socket& sock)
		{
			throw RTE_LOC;
			//if (mPartyIdx)
			//{
			//	co_await expand(B, A, C, {}, prng, sock);

			//	for (u64 i = 0; i < A.size(); ++i)
			//	{
			//		// b(0)b(1)
			//		auto bb = B[i] & A[i];
			//		// b(0)b(1) + [ab]1(0)
			//		C[i] ^= bb;
			//	}
			//}
			//else
			//{
			//	//auto bLsb = temp[0];
			//	//auto bMsb = temp[1];
			//	co_await expand(A, B, C, {}, prng, sock);

			//	for (u64 i = 0; i < A.size(); ++i)
			//	{
			//		// a(0)a(1)
			//		auto aa = A[i] & B[i];

			//		// a(0)a(1) + [ab]0(0)
			//		C[i] ^= aa;
			//	}
			//}
		}

		// sample random coefficients for the sparse polynomial and tensor
		// them with the other parties coefficients. The result is shared
		// as tensoredCoefficients. We allow the coeff to be zero.
		macoro::task<> tensor(span<F> coeffs, span<F> prod, coproto::Socket& sock);

		// sample the A polynomial. This is the polynomial that will be
		// multiplied the sparse polynomials by.
		void sampleA(block seed);


	};
















	template<typename F>
	void RingLpnTriple<F>::init(u64 partyIdx, u64 n)
	{
		mPartyIdx = partyIdx;
		mLogN = log2ceil(n);
		auto logT = log2ceil(mT);
		mN = 1ull << mLogN;

		if (mT != 1ull<< logT)
			throw RTE_LOC;

		mBlockSize = mN / mT;
		mBlockDepth = mLogN - logT;
		//mDpfLeafDepth = std::min<u64>(5, mBlockDepth);
		mDpfTreeDepth = mBlockDepth;// -mDpfLeafDepth;

		//mDpfLeafSize = ipow(2, mDpfLeafDepth);
		mDpfTreeSize = 1ull << mDpfTreeDepth;

		//mDpfLeaf.init(mPartyIdx, mDpfLeafSize, mC * mC * mT * mT);
		mDpf.init(mPartyIdx, mDpfTreeSize, mC * mC * mT * mT);

		if (mBlockSize < 2)
			throw RTE_LOC;

		sampleA(block(3127894527893612049, 240925987420932408));
	}


	template<typename F>
	RingLpnTriple<F>::BaseOtCount RingLpnTriple<F>::baseOtCount() const
	{
		BaseOtCount counts;

		counts.mSendCount = mDpf.baseOtCount(); // mDpfLeaf.baseOtCount() + 
		counts.mRecvCount = mDpf.baseOtCount(); // mDpfLeaf.baseOtCount() + 
		if (mPartyIdx)
			counts.mSendCount += 2 * mC * mT;
		else
			counts.mRecvCount += 2 * mC * mT;
		return counts;
	}


	template<typename F>
	void RingLpnTriple<F>::setBaseOts(
		span<const std::array<block, 2>> baseSendOts,
		span<const block> recvBaseOts,
		const oc::BitVector& baseChoices)
	{
		auto baseCounts = baseOtCount();
		if (baseSendOts.size() != baseCounts.mSendCount)
			throw RTE_LOC;
		if (recvBaseOts.size() != baseCounts.mRecvCount)
			throw RTE_LOC;
		if (baseChoices.size() != baseCounts.mRecvCount)
			throw RTE_LOC;
		auto recvIter = recvBaseOts;
		auto sendIter = baseSendOts;
		auto choiceIter = baseChoices;

		u64 offset = 0;
		//auto dpfLeafCount = mDpfLeaf.baseOtCount();
		//mDpfLeaf.setBaseOts(
		//	sendIter.subspan(offset, dpfLeafCount),
		//	recvIter.subspan(offset, dpfLeafCount),
		//	BitVector(baseChoices.data(), dpfLeafCount, offset)
		//);
		//offset += dpfLeafCount;

		auto dpfCount = mDpf.baseOtCount();
		mDpf.setBaseOts(
			sendIter.subspan(offset, dpfCount),
			recvIter.subspan(offset, dpfCount),
			BitVector(baseChoices.data(), dpfCount, offset)
		);
		offset += dpfCount;

		auto sendOts = sendIter.subspan(offset);
		auto recvOts = recvIter.subspan(offset);
		mSendOts.insert(mSendOts.end(), sendOts.begin(), sendOts.end());
		mRecvOts.insert(mRecvOts.end(), recvOts.begin(), recvOts.end());
		mChoiceOts = BitVector(baseChoices.data(), baseChoices.size() - offset, offset);
	}

	template<typename F>
	bool RingLpnTriple<F>::hasBaseOts() const
	{
		return mSendOts.size() + mRecvOts.size() > 0;
	}

	template<typename F>
	macoro::task<> RingLpnTriple<F>::genBaseOts(
		PRNG& prng,
		Socket& sock,
		SilentBaseType baseType)
	{
		if (isInitialized() == false)
		{
			throw std::runtime_error("init must be called first. " LOCATION);
		}
		auto baseCount = baseOtCount();

		setTimePoint("genBase.start");
		if (mPartyIdx)
		{
			if (baseType == SilentBaseType::BaseExtend)
			{
#ifdef ENABLE_SOFTSPOKEN_OT
				if (!mOtExtRecver)
					mOtExtRecver.emplace();
				if (!mOtExtSender)
					mOtExtSender.emplace();

				if (mOtExtRecver->hasBaseOts() == false)
					co_await mOtExtRecver->genBaseOts(prng, sock);

				u64 extSenderCount = 0;
				if (mOtExtSender->hasBaseOts() == false)
				{
					extSenderCount = mOtExtSender->baseOtCount();
					baseCount.mRecvCount += extSenderCount;
				}


				BitVector choice(baseCount.mRecvCount);
				choice.randomize(prng);
				AlignedUnVector<block> recvMsg(choice.size());
				co_await mOtExtRecver->receive(choice, recvMsg, prng, sock);

				if (extSenderCount)
				{
					BitVector senderChoice(choice.data(), extSenderCount);
					span<block> senderMsg(recvMsg.data(), extSenderCount);
					mOtExtSender->setBaseOts(senderMsg, senderChoice);
				}

				AlignedUnVector<std::array<block, 2>> sendMsg(baseCount.mSendCount);
				co_await mOtExtSender->send(sendMsg, prng, sock);

				choice = BitVector(choice.data(), choice.size() - extSenderCount, extSenderCount);
				setBaseOts(sendMsg, span<block>(recvMsg).subspan(extSenderCount), choice);
#else
				throw std::runtime_error("ENABLE_SOFTSPOKEN_OT = false, must enable soft spoken. " LOCATION);
#endif
			}
			else
			{
#ifdef LIBOTE_HAS_BASE_OT
				auto sock2 = sock.fork();
				auto prng2 = prng.fork();
				auto baseOt1 = DefaultBaseOT{};
				auto baseOt2 = DefaultBaseOT{};
				std::vector<block> recvMsg(baseCount.mRecvCount);
				std::vector<std::array<block, 2>> sendMsg(baseCount.mSendCount);
				BitVector choice(baseCount.mRecvCount);
				choice.randomize(prng);

				co_await(
					macoro::when_all_ready(
						baseOt1.send(sendMsg, prng, sock),
						baseOt2.receive(choice, recvMsg, prng2, sock2)));

				setBaseOts(sendMsg, recvMsg, choice);
#else
				throw std::runtime_error("A base OT must be enabled. " LOCATION);
#endif
			}
		}
		else
		{

			if (baseType == SilentBaseType::BaseExtend)
			{
#ifdef ENABLE_SOFTSPOKEN_OT
				if (!mOtExtRecver)
					mOtExtRecver.emplace();
				if (!mOtExtSender)
					mOtExtSender.emplace();

				if (mOtExtSender->hasBaseOts() == false)
					co_await mOtExtSender->genBaseOts(prng, sock);

				u64 extRecverCount = 0;
				if (mOtExtRecver->hasBaseOts() == false)
				{
					extRecverCount = mOtExtRecver->baseOtCount();
					baseCount.mSendCount += extRecverCount;
				}

				AlignedUnVector<std::array<block, 2>> sendMsg(baseCount.mSendCount);
				co_await mOtExtSender->send(sendMsg, prng, sock);

				if (extRecverCount)
				{
					span<std::array<block, 2>> recverMsg(sendMsg.data(), extRecverCount);
					mOtExtRecver->setBaseOts(recverMsg);
				}

				BitVector choice(baseCount.mRecvCount);
				choice.randomize(prng);
				AlignedUnVector<block> recvMsg(choice.size());
				co_await mOtExtRecver->receive(choice, recvMsg, prng, sock);

				setBaseOts(span<std::array<block, 2>>(sendMsg).subspan(extRecverCount), recvMsg, choice);
#else
				throw std::runtime_error("ENABLE_SOFTSPOKEN_OT = false, must enable soft spoken. " LOCATION);
#endif
			}
			else
			{
#ifdef LIBOTE_HAS_BASE_OT
				auto sock2 = sock.fork();
				auto prng2 = prng.fork();
				auto baseOt1 = DefaultBaseOT{};
				auto baseOt2 = DefaultBaseOT{};
				std::vector<block> recvMsg(baseCount.mRecvCount);
				std::vector<std::array<block, 2>> sendMsg(baseCount.mSendCount);
				BitVector choice(baseCount.mRecvCount);
				choice.randomize(prng);

				co_await(
					macoro::when_all_ready(
						baseOt1.receive(choice, recvMsg, prng, sock),
						baseOt2.send(sendMsg, prng2, sock2)
					));

				setBaseOts(sendMsg, recvMsg, choice);
#else
				throw std::runtime_error("A base OT must be enabled. " LOCATION);
#endif
			}

		}
		setTimePoint("genBase.done");
	}


	template<typename F>
	void RingLpnTriple<F>::sampleA(block seed)
	{

		if (mC > 8)
			throw RTE_LOC;

		PRNG prng(seed);
		mFftA.resize(mC, mN);
		mFftASquared.resize(0, 0);
		mFftASquared.resize(mC * mC, mN);
		//prng.get(mFftA.data() + mN, mFftA.size() - mN);

		// make a_0 the identity polynomial (in FFT space) i.e., all 1s
		for (size_t i = 0; i < mN; i++) {
			mFftA(0, i) = 1;
			for(u64 j = 1; j < mC; ++j)
				mFftA(j, i) = prng.get();
		}

		for (size_t i = 0; i < mN; i++)
		{
			for (size_t j = 0; j < mC; j++)
			{
				for (size_t k = 0; k < mC; k++)
				{
					auto a = mFftA(j, i);
					auto b = mFftA(k, i);
					mFftASquared(j * mC + k, i) = a * b;
				}
			}
		}
	}




	template<typename F>
	macoro::task<> RingLpnTriple<F>::expand(
		span<F> A,
		span<F> B,
		PRNG& prng,
		coproto::Socket& sock)
	{
		setTimePoint("expand start");

		if (hasBaseOts() == false)
		{
			co_await genBaseOts(prng, sock);
		}

		if (mN < A.size())
			throw RTE_LOC;
		if (A.size() != B.size())
			throw RTE_LOC;

		// the coefficient of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		mSparsePositions.resize(mC, mT);

		// The mT coefficients of the mC sparse polynomials.
		Matrix<F> sparseCoefficients(mC, mT);
		std::vector<F> tensoredCoefficients(mC * mC * mT * mT);

		// generate random sparseCoefficients and tensor them with 
		// the other parties sparse coefficients. The result is shared
		// as tensoredCoefficients. Each set of (mC*mT) values in 
		// tensoredCoefficients are the multiplication of a single coeff 
		// from party 0 and all of the coefficients from party 1.
		co_await tensor(sparseCoefficients, tensoredCoefficients, sock);

		//co_await checkTensor(sparseCoefficients, tensoredCoefficients, sock);

		// select random positions for the sparse polynomial.
		// The i'th is the noise position in the i'th block.
		for (u64 i = 0; i < mSparsePositions.size(); ++i)
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;

		// we pack 8 FFTs into a single u16. 
		Matrix<F> fftSparsePoly(mC, mN);
		for (u64 i = 0; i < mT; ++i)
		{
			for (u64 j = 0; j < mC; ++j)
			{
				auto pos = i * mBlockSize + mSparsePositions(j, i);
				fftSparsePoly(j, pos) = sparseCoefficients(j, i);
			}
		}

		setTimePoint("sparsePolySample");

		// switch from polynomial to FFT form
		//foleageFft<u16>(fftSparsePoly, mLog3N, mN / 3);
		std::vector<F> w(mN * 2);
		{
			auto psi = primRootOfUnity<F>(mN * 2);
			for (u64 i = 0; i < mN * 2; ++i)
				w[i] = psi.pow(i);

			for (u64 j = 0; j < mC; ++j)
			{
				nttNegWrapCt(fftSparsePoly[j], w);
				hadamarProd<F>(mFftA[j], fftSparsePoly[j], fftSparsePoly[j]);
				// compress the resume and set the output.
				auto outSize = std::min<u64>(mN, A.size());
				for (u64 i = 0; i < outSize; ++i)
					A[i] = A[i] + fftSparsePoly[j][i];
			}
		}

		setTimePoint("input fft");
		// multiply by the packed A polynomial

		// sharing of the F coefficients of the product polynomails.
		// these will just be the tensored coefficients but in permuted
		// order to match how they are expended in the DPF and then added 
		// together.
		std::vector<F> prodPolyFCoeffs(mC * mC * mT * mT);

		// We are doing to use "early termination" on the main DPF. To do
		// this we are going to construct new F4^243 coefficients where
		// each prodPolyF4Coeffs is positioned at prodPolyLeafPos. This
		// will allow the main DPF to be more efficient as we are outputting
		// 243 F4 elements for each leaf.
		//std::vector<u32> prodPolyLeafPos(mC * mC * mT * mT);

		// once we construct large F4^243 coefficients, we will expand them
		// the main DPF to get the full shared polynomail. prodPolyTreePos
		// is the location that the F4^243 coefficient should be mapped to.
		std::vector<u32> prodPolyTreePos(mC * mC * mT * mT);



		for (u64 iA = 0, pointIdx = 0, polyOffset = 0; iA < mC; ++iA)
		{
			for (u64 iB = 0; iB < mC; ++iB, polyOffset += mT * mT)
			{
				std::vector<uint8_t> nextIdx(mT);

				for (u64 jA = 0; jA < mT; ++jA)
				{
					for (u64 jB = 0; jB < mT; ++jB, ++pointIdx)
					{
						u64 i = mPartyIdx ? iB : iA;
						u64 j = mPartyIdx ? jB : jA;


						// the block of the product coefficient is known
						// purely using the block index of the input coefficients.
						auto blockIdx = (jA + jB) ^ mN;
						//auto blockIdx = blockPos.toInt();

						// We want to put all DPF that will be added together
						// next to each other. We do this by using nextIdx to
						// keep track of the next index for each output block.
						size_t idx = polyOffset + blockIdx * mT + nextIdx[blockIdx]++;

						// split the position into the portion that will position
						// the F4 coefficient within the F4^243 coefficient and the
						// portion that will position the F4^243 coefficient within
						// the main DPF.
						//auto pos = F3x32(mSparsePositions(i, j)); // (F_3)^n + (F_3)^n
						//prodPolyLeafPos[idx] = pos.lower(mDpfLeafDepth);
						//prodPolyTreePos[idx] = pos.upper(mDpfLeafDepth);
						prodPolyTreePos[idx] = mSparsePositions(i, j);

						// get the corresponding tensored F4 coefficient.
						auto coeffIdx = (iA * mT + jA) * mC * mT + iB * mT + jB;
						prodPolyFCoeffs[idx] = tensoredCoefficients[coeffIdx];
					}
				}

				if (nextIdx != std::vector<uint8_t>(mT, mT))
					throw RTE_LOC;
			}
		}

		setTimePoint("dpfParams");


		//// sharing of the F4^243 coefficients of the product polynomails.
		//// These are obtained by expanding the F4 coefficients into 243
		//// elements using a "small DPF".
		//std::vector<FoleageF4x243> prodPolyF4x243Coeffs(mC * mC * mT * mT);

		//// current coefficients are single F4 elements. Expand them into
		//// 3^5=243 elements. These will be used as the new coefficients
		//// in the large tree.
		//co_await mDpfLeaf.expand(prodPolyLeafPos, prodPolyFCoeffs,
		//	[&, byteIdx = 0ull, bitIdx = 0ull](u64 treeIdx, u64 leafIdx, u8 v) mutable {
		//		if (treeIdx == 0)
		//		{
		//			byteIdx = leafIdx / 4;
		//			bitIdx = leafIdx % 4;
		//		}
		//		assert(byteIdx == leafIdx / 4);
		//		assert(bitIdx == leafIdx % 4);

		//		auto ptr = (u8*)&prodPolyF4x243Coeffs.data()[treeIdx];
		//		ptr[byteIdx] |= u8((v & 3) << (2 * bitIdx));
		//	}, prng, sock);

		//setTimePoint("leafDpf");


		Matrix<F> fft(mC * mC * mT, mDpfTreeSize);
		// expand the main tree and add the mT point functions correspond 
		// to a block together. This will give us the coefficients of the
		// the product polynomial.
		co_await mDpf.expand(prodPolyTreePos, prodPolyFCoeffs,
			[&, count = 0ull, out = fft.data(), end = fft.data() + fft.size()]
			(u64 treeIdx, u64 leafIdx, F v) mutable {
				// the callback is called in column major order but blocks
				// is row major (leafIdx will be the same). So we need to compute 
				// the correct index. Moreover, we are adding together mT trees 
				// so we also need divide the treeIdx by mT. To make this more 
				// efficient, we use the out pointer and manually increment it.

				assert(out == &fft(treeIdx / mT, leafIdx));
				*out ^= v;

				if (++count == mT)
				{
					count = 0;
					out += fft.cols();
					if (out >= end)
					{
						out -= fft.size() - 1;
					}
				}
			}, prng, sock);


		setTimePoint("mainDpf");


		fft.reshape(mC * mC, mT * mDpfTreeSize);

		for (u64 j = 0; j < mC * mC; ++j)
		{
			nttNegWrapCt(fft[j], w);
			hadamarProd<F>(mFftASquared[j], fft[j], fft[j]);
			// compress the resume and set the output.
			auto outSize = std::min<u64>(mN, B.size());
			for (u64 i = 0; i < outSize; ++i)
				B[i] = B[i] + fftSparsePoly[j][i];
		}

		setTimePoint("addCopyY");

	}


	template<typename F>
	macoro::task<> RingLpnTriple<F>::tensor(span<F> coeffs, span<F> prod, coproto::Socket& sock)
	{
		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;
		throw RTE_LOC;
		//auto expand = [](block k, span<block> diff) {
		//	AES aes(k);
		//	for (u64 i = 0; i < diff.size(); ++i)
		//		diff[i] = aes.ecbEncBlock(block(i));
		//	};

		//if (divCeil(coeffs.size(), 128) != 1)
		//	throw RTE_LOC; // not impl
		//auto size = 2 * divCeil(coeffs.size(), 128);


		//if (mPartyIdx)
		//{
		//	if (mSendOts.size() < 2 * coeffs.size() - 1)
		//		throw RTE_LOC; //base ots not set.
		//	// b * a = (b0 * a +  b1 * (2 * a))
		//	//auto getDiff = [](block k0, block k1, span<block> diff) {
		//	//		AES aes0(k0);
		//	//		AES aes1(k1);
		//	//		for (u64 i = 0; i < diff.size(); ++i)
		//	//			diff[i] = aes0.ecbEncBlock(block(i)) ^ aes1.ecbEncBlock(block(i) * 2);
		//	//	};
		//	std::array<std::vector<block>, 2> a; a[0].resize(size), a[1].resize(size);
		//	std::vector<block> t0(size), t1(size);
		//	expand(mSendOts[0][0], t0);
		//	expand(mSendOts[0][1], t1);
		//	for (u64 i = 0; i < size; ++i)
		//		a[0][i] = t0[i] ^ t1[i];

		//	// a[1] = 2 * a[0]
		//	F4Multiply(a[0][0], a[0][1], ZeroBlock, AllOneBlock, a[1][0], a[1][1]);

		//	{
		//		auto lsbIter = BitIterator(&a[0][0]);
		//		auto msbIter = BitIterator(&a[0][1]);
		//		for (u64 i = 0; i < coeffs.size(); ++i)
		//			coeffs[i] = (*lsbIter++ & 1) | ((*msbIter++ & 1) << 1);
		//	}

		//	{
		//		setBytes(prod, 0);
		//		auto prodIter = prod.begin();
		//		auto lsbIter = BitIterator(&t0[0]);
		//		auto msbIter = BitIterator(&t0[1]);
		//		for (u64 i = 0; i < coeffs.size(); ++i)
		//			*prodIter++ = (*lsbIter++) | (u8(*msbIter++) << 1);
		//	}


		//	std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
		//	auto buffIter = buffer.begin();
		//	for (u64 i = 1; i < 2 * coeffs.size(); ++i)
		//	{
		//		auto b = i & 1;
		//		auto idx = i / 2;
		//		auto prodIter = prod.begin() + idx * coeffs.size();

		//		expand(mSendOts[i][0], t0);
		//		expand(mSendOts[i][1], t1);

		//		// prod  = mask
		//		auto lsbIter = BitIterator(&t0[0]);
		//		auto msbIter = BitIterator(&t0[1]);
		//		for (u64 i = 0; i < coeffs.size(); ++i)
		//			*prodIter++ ^= (*lsbIter++) | (u8(*msbIter++) << 1);

		//		for (u64 i = 0; i < a.size(); ++i)
		//		{   //        mask    key     value
		//			*buffIter++ = t0[i] ^ t1[i] ^ a[b][i];
		//			//*buffIter++ = diff[i];
		//		}

		//	}

		//	co_await sock.send(std::move(buffer));
		//}
		//else
		//{

		//	if (mChoiceOts.size() < 2 * coeffs.size() - 1)
		//		throw RTE_LOC; //base ots not set.
		//	if (mRecvOts.size() < 2 * coeffs.size() - 1)
		//		throw RTE_LOC; //base ots not set.

		//	for (u64 i = 0; i < coeffs.size(); ++i)
		//		coeffs[i] = mChoiceOts[2 * i] | (u8(mChoiceOts[2 * i + 1] << 1));
		//	std::vector<block> t(size);
		//	expand(mRecvOts[0], t);

		//	{
		//		setBytes(prod, 0);
		//		auto prodIter = prod.begin();
		//		auto lsbIter = BitIterator(&t[0]);
		//		auto msbIter = BitIterator(&t[1]);
		//		for (u64 i = 0; i < coeffs.size(); ++i)
		//			*prodIter++ = (*lsbIter++) | (u8(*msbIter++) << 1);
		//	}

		//	std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
		//	co_await sock.recv(buffer);

		//	auto buffIter = buffer.begin();
		//	for (u64 i = 1; i < 2 * coeffs.size(); ++i)
		//	{
		//		auto idx = i / 2;
		//		auto prodIter = prod.begin() + idx * coeffs.size();

		//		expand(mRecvOts[i], t);
		//		if (mChoiceOts[i])
		//		{
		//			for (u64 i = 0; i < size; ++i)
		//			{
		//				t[i] = t[i] ^ *buffIter++;
		//			}
		//		}
		//		else
		//			buffIter += size;

		//		// prod  = mask
		//		auto lsbIter = BitIterator(&t[0]);
		//		auto msbIter = BitIterator(&t[1]);
		//		for (u64 i = 0; i < coeffs.size(); ++i)
		//			*prodIter++ ^= (*lsbIter++) | (u8(*msbIter++) << 1);
		//	}
		//}
	}


}
#endif