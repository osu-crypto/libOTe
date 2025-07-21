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
#include "libOTe/Dpf/SumDmpf.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/Tools/Ntt/NttNegWrap.h"
#include "libOTe/Tools/Ntt/Poly.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{


	// The two party RingLpn PCG protocol for generating F OLEs
	// and Binary Beaver triples. The caller should call
	//
	// RingLpnTriple::init(...)
	// RingLpnTriple::expand(...)
	// 
	// There are two expand function, one for OLEs and one for Triples.
	template<typename F, typename CoeffCtx = DefaultCoeffCtx<F>>
	class RingLpnTriple : public TimerAdapter
	{
	public:
		u64 mPartyIdx = 0;

		// the number of noisy positions per polynomial
		u64 mT = 8;

		// the number of polynomials.
		u64 mC = 1;

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
		// A polynomial will have mT blocks. polyIdx.e. mN = mT * mBlockSize.
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

		// the locations of the non-zeros in the bPolyIdx'th block of the sparse polynomial.
		// the polyIdx'th row containts the coeffs for the polyIdx'th poly.
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

		//RegularDpf<F, CoeffCtx> mDpf;
		SumDmpf<F, CoeffCtx> mDpf;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		std::vector<block> mRecvOts;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		std::vector<std::array<block, 2>> mSendOts;

		// The base OTs used to tensor the coefficients of the sparse polynomial.
		BitVector mChoiceOts;

		CoeffCtx mCtx;

		// Intializes the protocol to generate n F OLEs. Most efficient when n
		// is a power of 2. Once called, baseOtCount() can be called to 
		// determine the required number of base OTs.
		void init(u64 partyIdx, u64 n, CoeffCtx ctx = {});

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

			//	for (u64 polyIdx = 0; polyIdx < A.size(); ++polyIdx)
			//	{
			//		// b(0)b(1)
			//		auto bb = B[polyIdx] & A[polyIdx];
			//		// b(0)b(1) + [ab]1(0)
			//		C[polyIdx] ^= bb;
			//	}
			//}
			//else
			//{
			//	//auto bLsb = temp[0];
			//	//auto bMsb = temp[1];
			//	co_await expand(A, B, C, {}, prng, sock);

			//	for (u64 polyIdx = 0; polyIdx < A.size(); ++polyIdx)
			//	{
			//		// a(0)a(1)
			//		auto aa = A[polyIdx] & B[polyIdx];

			//		// a(0)a(1) + [ab]0(0)
			//		C[polyIdx] ^= aa;
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


		macoro::task<> arithmeticToBinary(
			span<u64> out,
			span<const u64> in,
			u64 mod,
			Socket& sock);

	};
















	template<typename F, typename CoeffCtx>
	void RingLpnTriple<F, CoeffCtx>::init(u64 partyIdx, u64 n, CoeffCtx ctx)
	{
		mPartyIdx = partyIdx;
		mLogN = log2ceil(n);
		auto logT = log2ceil(mT);
		mN = 1ull << mLogN;
		mCtx = ctx;

		if (mT != 1ull << logT)
			throw RTE_LOC;

		mBlockSize = mN / mT;
		mBlockDepth = mLogN - logT;
		//mDpfLeafDepth = std::min<u64>(5, mBlockDepth);
		mDpfTreeDepth = mBlockDepth + 1;// -mDpfLeafDepth;

		//mDpfLeafSize = ipow(2, mDpfLeafDepth);
		mDpfTreeSize = 1ull << mDpfTreeDepth;

		//mDpfLeaf.init(mPartyIdx, mDpfLeafSize, mC * mC * mT * mT);
		//mDpf.init(mPartyIdx, mDpfTreeSize, mT * mC * mC * mT);
		mDpf.init(mPartyIdx, mDpfTreeSize, mT, mC * mC * mT);

		if (mBlockSize < 2)
			throw RTE_LOC;

		sampleA(block(3127894527893612049, 240925987420932408));
	}


	template<typename F, typename CoeffCtx>
	RingLpnTriple<F, CoeffCtx>::BaseOtCount RingLpnTriple<F, CoeffCtx>::baseOtCount() const
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


	template<typename F, typename CoeffCtx>
	void RingLpnTriple<F, CoeffCtx>::setBaseOts(
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

	template<typename F, typename CoeffCtx>
	bool RingLpnTriple<F, CoeffCtx>::hasBaseOts() const
	{
		return mSendOts.size() + mRecvOts.size() > 0;
	}

	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::genBaseOts(
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


	template<typename F, typename CoeffCtx>
	void RingLpnTriple<F, CoeffCtx>::sampleA(block seed)
	{

		if (mC > 8)
			throw RTE_LOC;

		PRNG prng(seed);
		mFftA.resize(mC, mN);
		mFftASquared.resize(0, 0);
		mFftASquared.resize(mC * mC, mN);
		//prng.get(mFftA.data() + mN, mFftA.size() - mN);

		// make a_0 the identity polynomial (in FFT space) polyIdx.e., all 1s
		for (size_t i = 0; i < mN; i++) {
			mFftA(0, i) = 1;
			for (u64 j = 1; j < mC; ++j)
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
	struct CoeffCtxMod : DefaultCoeffCtx_t<F>::type
	{
		CoeffCtxMod(F mod) : mMod(mod)
		{
			if (mod == 0)
				throw RTE_LOC;
		}
		F mMod;

		template<typename T>
		u64 byteSize() { return sizeof(T); }

		void plus(F& ret, const F& x, const F& y)
		{
			ret = (x + y) % mMod;
		}
		//using DefaultCoeffCtx_t<F>::serialize;
		//using DefaultCoeffCtx_t<F>::deserialize;
	};

	template <typename F, typename CoeffCtx>
	macoro::task<> reveal(span<F> x, Socket& sock, CoeffCtx ctx = {})
	{
		std::vector<u8> buff(x.size() * ctx.template byteSize<F>());
		ctx.serialize(x.begin(), x.end(), buff.begin());

		co_await sock.send(std::move(buff));
		buff.resize(x.size() * ctx.template byteSize<F>());
		co_await sock.recv(buff);
		std::vector<F> xx(x.size());
		ctx.deserialize(buff.begin(), buff.end(), xx.begin());

		for (u64 i = 0; i < x.size(); ++i)
			ctx.plus(x[i], x[i], xx[i]);
	}


	//std::vector<u8> buffer(mC * mT * mCtx.template byteSize<F>());
	//mCtx.serialize(sparseCoefficients.begin(), sparseCoefficients.end(), buffer.begin());
	//co_await sock.send(coproto::copy(buffer));
	//co_await send<F>(sparseCoefficients, sock);
	template<typename F, typename CoeffCtx>
	macoro::task<> send(span<F> Val, coproto::Socket& sock, CoeffCtx ctx = {})
	{
		std::vector<u8> buffer(Val.size() * ctx.template byteSize<F>());
		ctx.serialize(Val.begin(), Val.end(), buffer.begin());
		co_await sock.send(std::move(buffer));
	}

	//co_await sock.recv(buffer);
	//mCtx.deserialize(buffer.begin(), buffer.end(), Val[mPartyIdx ^ 1].begin());
	//co_await recv<F>(sock, Val[mPartyIdx ^ 1]);
	template<typename F, typename CoeffCtx>
	macoro::task<> recv(span<F> Val, coproto::Socket& sock, CoeffCtx ctx = {})
	{
		std::vector<u8> buffer(Val.size() * ctx.template byteSize<F>());
		co_await sock.recv(buffer);
		ctx.deserialize(buffer.begin(), buffer.end(), Val.begin());
	}

	template<typename T>
	std::string print(span<T> x)
	{
		std::stringstream ss;
		ss << "[";
		for (u64 i = 0; i < x.size(); ++i)
		{
			if (i != 0)
				ss << ", ";
			ss << x[i];
		}
		ss << "]";
		return ss.str();
	}

	template<typename F, typename CoeffCtx>
	inline macoro::task<> RingLpnTriple<F, CoeffCtx>::arithmeticToBinary(
		span<u64> out,
		span<const u64> in,
		u64 mod,
		Socket& sock)
	{
		if (out.size() != in.size())
			throw RTE_LOC;

		// check if power of 2
		if (mod == 0 || (mod & (mod - 1)) != 0)
			throw RTE_LOC;

		// For now, we do this insecurely by revealing the inputs
		// and constructing XOR shares of the addition

		// Generate random values for XOR sharing
		PRNG prng(CCBlock);
		for (u64 i = 0; i < in.size(); ++i)
			out[i] = prng.get<u64>() % mod;

		// Now create XOR shares of these values
		// Party 0 gets a random value r, party 1 gets actualValue ^ r
		if (mPartyIdx == 0)
		{
			// Receive the other party's shares
			std::vector<u64> otherShares(in.size());
			co_await sock.recv(otherShares);

			for (u64 i = 0; i < in.size(); ++i)
			{
				out[i] ^= (in[i] + otherShares[i]) % mod;
			}
		}
		else
		{
			// Send my shares to the other party
			co_await sock.send(std::vector<u64>(in.begin(), in.end()));
		}

	}




	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::expand(
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
		// the polyIdx'th row contains the coeffs for the polyIdx'th poly.
		// the position is within the corresponding block, not the
		// overall polynomial.
		mSparsePositions.resize(mC, mT);

		// The mT coefficients of the mC sparse polynomials.
		Matrix<F> sparseCoefficients(mC, mT);
		std::vector<F> tensoredCoefficients(mC * mC * mT * mT);

		// generate random sparseCoefficients and tensor them with 
		// the other parties sparse coefficients. The result is shared
		// as tensoredCoefficients. Each set of (mC*mT) values in 
		// tensoredCoefficients are the multiplication of a single coeff 
		// from party 0 and all of the coefficients from party 1.
		// so that looks like
		//   a[0] * (b[0], ..., b[t-1])
		//   ...
		//   a[t-1] * (b[0],...,b[t-1])
		// but all flattened.
		co_await tensor(sparseCoefficients, tensoredCoefficients, sock);

		//co_await checkTensor(sparseCoefficients, tensoredCoefficients, sock);

		// select random positions for the sparse polynomial.
		// The polyIdx'th is the noise position in the polyIdx'th block.
		for (u64 i = 0; i < mSparsePositions.size(); ++i)
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;

		// we pack 8 FFTs into a single u16. 
		Matrix<F> fftSparsePoly(mC, mN);
		for (u64 i = 0; i < mT; ++i)
		{
			for (u64 j = 0; j < mC; ++j)
			{
				// actual position
				auto pos = i * mBlockSize + mSparsePositions(j, i);
				fftSparsePoly(j, pos) = sparseCoefficients(j, i);
			}
		}

		setTimePoint("sparsePolySample");

		// switch from polynomial to FFT form
		std::vector<F> w(mN * 2);
		{
			auto psi = primRootOfUnity<F>(mN * 2);
			for (u64 i = 0; i < mN * 2; ++i)
				w[i] = psi.pow(i);

			for (u64 j = 0; j < mC; ++j)
			{
				nttNegWrapCt<F>(fftSparsePoly[j], w);
				hadamarProd<F>(fftSparsePoly[j], mFftA[j], fftSparsePoly[j]);

				// compress the result and set the output. TODO, fuze the multiply add.
				auto outSize = std::min<u64>(mN, A.size());
				for (u64 i = 0; i < outSize; ++i)
					A[i] = A[i] + fftSparsePoly[j][i];
			}
		}

		setTimePoint("input fft");
		// multiply by the packed A polynomial

		// sharing of the F coefficients of the product polynomials.
		// these will just be the tensored coefficients but in permuted
		// order to match how they are expended in the DPF and then added 
		// together.
		std::vector<F> prodPolyFCoeffs(mC * mC * mT * mT);

		// we will expand them the main DPF to get the full shared polynomial. 
		// prodPolyTreePosArth is the location that the F coefficient should 
		// be mapped to as an arithmetic sharing. prodPolyTreePosXor will hold the same
		// as a binary sharing.
		std::vector<u64> prodPolyTreePosArth(mC * mC * mT * mT);
		std::vector<u64> prodPolyTreePosXor(mC * mC * mT * mT);


		// APolyIdx indexes the first polynomial held by party 0.
		// polyOffset is the offset into the tensored coefficients
		for (u64 APolyIdx = 0, polyOffset = 0; APolyIdx < mC; ++APolyIdx)
		{
			// BPolyIdx indexes the second polynomial held by party 1.
			for (u64 BPolyIdx = 0; BPolyIdx < mC; ++BPolyIdx, polyOffset += mT * mT)
			{
				// we are working with polynomials A[APolyIdx] and B[BPolyIdx].
				// these are "regular polynomials" where each has 
				// mT non-zeros, each of which is in a different block.

				// in the product polynomial C = A[APolyIdx] * B[BPolyIdx], 
				// there will be exactly mT^2 non-zeros. Each block 
				// will have exactly mT non-zeros. To simplify, we will
				// use nextIdx to keep track how many coefficients have 
				// been added to each block. 
				std::vector<uint8_t> nextIdx(mT);

				// ABlkIdx indexes the first block of the product polynomial.
				for (u64 ABlkIdx = 0; ABlkIdx < mT; ++ABlkIdx)
				{
					// BBlkIdx indexes the second block of the product polynomial.
					for (u64 BBlkIdx = 0; BBlkIdx < mT; ++BBlkIdx)
					{
						// get the polynomial index and the block index for my polynomial.
						u64 myPolyIdx = mPartyIdx ? BPolyIdx : APolyIdx;
						u64 myBlkIdx = mPartyIdx ? BBlkIdx : ABlkIdx;

						// the block of the product coefficient is known
						// purely using the block index of the input coefficients.
						auto prodBlkIdx = (ABlkIdx + BBlkIdx) % mT;

						// We want to put all DPF that will be added together
						// next to each other. We do this by using nextIdx to
						// keep track of the next index for each output block.
						size_t idx = polyOffset + prodBlkIdx * mT + nextIdx[prodBlkIdx]++;

						prodPolyTreePosArth[idx] = mSparsePositions(myPolyIdx, myBlkIdx);

						// get the corresponding tensored F4 coefficient.
						auto coeffIdx = (APolyIdx * mT + ABlkIdx) * mC * mT + BPolyIdx * mT + BBlkIdx;
						prodPolyFCoeffs[idx] = tensoredCoefficients[coeffIdx];

						// pre negate the coefficients  will need to wrap X^n+1.
						if (prodBlkIdx != ABlkIdx + BBlkIdx)
							prodPolyFCoeffs[idx] = -prodPolyFCoeffs[idx];
					}
				}

				if (nextIdx != std::vector<uint8_t>(mT, mT))
					throw RTE_LOC;
			}
		}

		// convert an arithmetic sharing into a binary sharing.
		// each party has prodPolyTreePosArth which are the arithmetic
		// modulo mBlockSize. The output will be the same values but
		// as a binary sharing. Each party will have prodPolyTreePos
		// such that 
		//   prodPolyTreePosXor[0] ^ prodPolyTreePosXor[1] = 
		//   prodPolyTreePosArth[0] + prodPolyTreePosArth[1] (mod mBlockSize)
		co_await arithmeticToBinary(prodPolyTreePosXor, prodPolyTreePosArth, mBlockSize * 2, sock);

		setTimePoint("dpfParams");

		// every set of mT rows is a single product polynomial.
		// once expanded, we will resize so each row is a single
		// product polynomial. The rows will be ordered as follows:
		//   A[0] * B[0], A[0] * B[1], ..., A[0] * B[C-1]
		//   ...
		//   A[C-1] * B[0], A[C-1] * B[1], ..., A[C-1] * B[C-1]
		//Matrix<F> prodPolys(mC * mC * mT, mDpfTreeSize);

		// the full set of monomial blocks.
		//Matrix<F> monomials(mC * mC * mT * mT, mDpfTreeSize);
		Matrix<F> prodPolys(mC* mC, mN + mBlockSize);
		// expand the main tree and add the mT point functions correspond 
		// to a block together. This will give us the coefficients of the
		// the product polynomial.
		co_await mDpf.expand(prodPolyTreePosXor, prodPolyFCoeffs, prng, sock,
			[&/*, count = 0ull, out = prodPolys.data(), end = prodPolys.data() + prodPolys.size()*/]
			(u64 treeIdx, u64 leafIdx, F v, auto t) mutable {
				// the callback is called in column major order but blocks
				// is row major (leafIdx will be the same). So we need to compute 
				// the correct index. Moreover, we are adding together mT trees 
				// so we also need divide the treeIdx by mT. To make this more 
				// efficient, we use the out pointer and manually increment it.

				//assert(out == &prodPolys(treeIdx / mT, leafIdx));
				//*out = *out + v;
				//monomials(treeIdx, leafIdx) = v;

				auto polyIdx = treeIdx / mT;
				auto blockIdx = treeIdx % mT;
				//auto blockIdx = monomialIdx / mT;
				prodPolys(polyIdx, leafIdx + blockIdx * mBlockSize) += v;
				//if (++count == mT)
				//{
				//	count = 0;
				//	out += prodPolys.cols();
				//	if (out >= end)
				//	{
				//		out -= prodPolys.size() - 1;
				//	}
				//}
			}, mCtx);


		for (u64 i = 0; i < mC * mC; ++i)
		{
			for(u64 j= 0; j <mBlockSize;++j)
				prodPolys(i, j) -= prodPolys(i, j + mN);
		}

		//std::vector<F> temp(mDpfTreeSize);
		// 
		// we have mC * mC product polynomials, each with mT blocks where
		// each block is made up of mBlockSize coefficients/monomials.
		//for (u64 i = 0, polyOffset = 0; i < mC * mC; ++i)
		//{
		//	// the i'th product polynomial is made up of mT blocks.
		//	auto poly = prodPolys[i];

		//	for (u64 k = 0; k < mT; ++k)
		//	{
		//		// the starting position of the k'th block in the polynomial.
		//		auto begin = k * mBlockSize;

		//		for (u64 j = 0; j < mT; ++j)
		//		{
		//			//for (u64 i = 0; i < mDpfTreeSize; ++i)
		//			//	temp[i] += monomial[i];

		//			// we are going to compress temp onto the polynomial
		//			// we need to manually perform the modulo operation.
		//			// Since we are working with X^n+1, coefficients with 
		//			// degree larger than n will wrap around and are negated.
		//			auto monomial = monomials[polyOffset++];

		//			// the begin position of monomail in the polynomial.
		//			auto base = (k + j) * mT;
		//			
		//			// add the first half of the monomial.
		//			//auto begin = base;
		//			for (u64 k = 0; k < mBlockSize; ++k)
		//				poly[begin + k] += monomial[k];
		//			// each monomial is mDpfTreeSize = 2*mBlockSize long.
		//			// since the second half might wrap while the first half
		//			// does not, we need to handle the two halves separately.
		//			if (base >= mN)
		//			{
		//				// subtract the first half of the monomial (wrapping).
		//				auto begin = base - mN;
		//				for (u64 k = 0; k < mBlockSize; ++k)
		//					poly[begin + k] -= monomial[k];
		//			}
		//			else
		//			{
		//			}

		//			if (base + mBlockSize >= mN)
		//			{
		//				// subtract the second half of the monomial (wrapping).
		//				auto begin = base + mBlockSize - mN;
		//				for (u64 k = 0; k < mBlockSize; ++k)
		//					poly[begin + k] -= monomial[k + mBlockSize];
		//			}
		//			else
		//			{
		//				// add the second half of the monomial.
		//				auto begin = base + mBlockSize;
		//				for (u64 k = 0; k < mBlockSize; ++k)
		//					poly[begin + mBlockSize + k] += monomial[k + mBlockSize];
		//			}
		//		}

		//	}
		//}


		if(1)
		{
			// the input polynomials positions and values.
			std::array<Matrix<u64>, 2> Pos;
			Pos[0].resize(mC, mT);
			Pos[1].resize(mC, mT);
			std::array <Matrix<F>, 2> Val;
			Val[0].resize(mC, mT);
			Val[1].resize(mC, mT);

			// the XOR shares of the product polynomials positions.
			Matrix<u64> ProdPosXor(mC * mC * mT, mT);
			// the arithmetic shares of the product polynomials positions.
			Matrix<u64> ProdPosArth(mC * mC * mT, mT);

			//Matrix<F> ProdVals = prodPolyFCoeffs;

			for (u64 i = 0; i < mC * mT; ++i)
			{
				Pos[mPartyIdx](i) = mSparsePositions(i);
				Val[mPartyIdx](i) = sparseCoefficients(i);
			}

			auto arthPos = prodPolyTreePosArth;
			co_await reveal<u64>(arthPos, sock, CoeffCtxMod<u64>{mDpfTreeSize});
			auto xorPos = prodPolyTreePosXor;
			co_await reveal<u64>(xorPos, sock, CoeffCtxGF2{});

			if (xorPos != arthPos)
			{
				std::cout << "Product polynomial position check failed." << std::endl;
				std::cout << "Expected: " << print<u64>(arthPos) << std::endl;
				std::cout << "Actual:   " << print<u64>(xorPos) << std::endl;
				throw RTE_LOC;
			}

			co_await sock.send(coproto::copy(mSparsePositions));
			co_await sock.recv(Pos[mPartyIdx ^ 1]);
			co_await send<F>(sparseCoefficients, sock, mCtx);
			co_await recv<F>(Val[mPartyIdx ^ 1], sock, mCtx);

			//auto monos = monomials;
			//co_await reveal<F>(monos, sock, mCtx);

			auto full = prodPolys;
			co_await reveal<F>(full, sock, mCtx);


			for (u64 aPolyIdx = 0, polyOffset = 0; aPolyIdx < mC; ++aPolyIdx)
			{
				Poly<F> aPoly;
				for (u64 i = 0; i < mT; ++i)
					aPoly[Pos[0][aPolyIdx][i] + i * mBlockSize] = Val[0][aPolyIdx][i];

				for (u64 bPolyIdx = 0; bPolyIdx < mC; ++bPolyIdx, polyOffset += mT * mT)
				{
					Poly<F> bPoly;
					for (u64 i = 0; i < mT; ++i)
						bPoly[Pos[1][bPolyIdx][i] + i * mBlockSize] = Val[1][bPolyIdx][i];


					std::vector<uint8_t> nextIdx(mT);
					Matrix<u64> expPos(mT, mT);
					Matrix<F> expVal(mT, mT);
					// ABlkIdx indexes the first block of the product polynomial.
					for (u64 ABlkIdx = 0; ABlkIdx < mT; ++ABlkIdx)
					{
						// BBlkIdx indexes the second block of the product polynomial.
						for (u64 BBlkIdx = 0; BBlkIdx < mT; ++BBlkIdx)
						{
							// the block of the product coefficient is known
							// purely using the block index of the input coefficients.
							auto prodBlkIdx = (ABlkIdx + BBlkIdx) % mT;
							auto offset = nextIdx[prodBlkIdx]++;

							expPos(prodBlkIdx, offset) =
								Pos[0][aPolyIdx][ABlkIdx] + Pos[1][bPolyIdx][BBlkIdx];
							expVal(prodBlkIdx, offset) =
								Val[0][aPolyIdx][ABlkIdx] * Val[1][bPolyIdx][BBlkIdx];
						}
					}
					//for (u64 ABlkIdx = 0; ABlkIdx < mT; ++ABlkIdx)
					//{
					//	// BBlkIdx indexes the second block of the product polynomial.
					//	for (u64 BBlkIdx = 0; BBlkIdx < mT; ++BBlkIdx)
					//	{
					//		Poly<F> act(monos[polyOffset + (ABlkIdx * mT) + BBlkIdx]);
					//		Poly<F> exp(expPos(ABlkIdx, BBlkIdx), expVal(ABlkIdx, BBlkIdx));

					//		if (act != exp)
					//		{
					//			std::cout << "Product polynomial mismatch at A[" << aPolyIdx << "], B[" << bPolyIdx << "]" << std::endl;
					//			std::cout << "block " << ABlkIdx << ", " << BBlkIdx << std::endl;

					//			std::cout << "act " << act << std::endl;
					//			std::cout << "exp " << exp << std::endl;
					//			throw RTE_LOC;
					//		}
					//	}
					//}

					Poly<F> xnPlus1;
					xnPlus1[mN] = 1;
					xnPlus1[0] = 1;

					auto pp = (aPoly * bPoly);
					auto exp = pp % xnPlus1;
					auto act = Poly<F>(full[aPolyIdx * mC + bPolyIdx].subspan(0,mN));
					if (act != exp)
					{
						std::cout << "Product polynomial mismatch at A[" << aPolyIdx << "], B[" << bPolyIdx << "]" << std::endl;
						std::cout << "act " << act << std::endl;
						std::cout << "exp " << exp << std::endl;
						std::cout << "= a " << aPoly << std::endl;
						std::cout << "* b " << bPoly << std::endl;
						std::cout << "= " << pp << std::endl;
						throw RTE_LOC;
					}
				}
			}
		}

		setTimePoint("mainDpf");


		for (u64 i = 0, polyOffset = 0; i < mC * mC; ++i) //polyOffset += mT * mT)
		{
			auto prod = prodPolys[i].subspan(0, mN);
			nttNegWrapCt<F>(prod, w);
			hadamarProd<F>(prod, mFftASquared[i], prod);
			// compress the resume and set the output.
			auto outSize = std::min<u64>(mN, B.size());
			for (u64 k = 0; k < outSize; ++k)
				B[k] = B[k] + prod[k];
		}

		setTimePoint("addCopyY");

	}

	// take input vectors private a,b from the two parties. 
	// 
	// compute shares of all products 
	// 
	//   ai * bj
	// 
	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::tensor(span<F> coeffs, span<F> prod, coproto::Socket& sock)
	{
		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;

		PRNG prng(CCBlock ^ block(mPartyIdx));
		for (auto& c : coeffs)
			c = prng.get();

		auto n = coeffs.size();
		auto byteSize = mCtx.template byteSize<F>();
		std::vector<u8> buffer(n * byteSize);
		mCtx.serialize(coeffs.begin(), coeffs.end(), buffer.begin());
		co_await sock.send(coproto::copy(buffer));

		buffer.resize(n * byteSize);
		co_await sock.recv(buffer);
		std::vector<F> oCoeffs(coeffs.size());
		mCtx.deserialize(buffer.begin(), buffer.end(), oCoeffs.begin());

		std::array<span<F>, 2> Coeffs;
		Coeffs[mPartyIdx] = coeffs;
		Coeffs[mPartyIdx ^ 1] = oCoeffs;

		for (size_t i = 0; i < n; i++)
		{
			for (size_t j = 0; j < n; j++)
			{
				auto p = i * n + j;

				auto ai = Coeffs[0][i];
				auto bj = Coeffs[1][j];

				if (mPartyIdx)
					prod[p] = ai * bj;
				else
					prod[p] = F(0);
			}
		}

		//auto expand = [](block k, span<block> diff) {
		//	AES aes(k);
		//	for (u64 polyIdx = 0; polyIdx < diff.size(); ++polyIdx)
		//		diff[polyIdx] = aes.ecbEncBlock(block(polyIdx));
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
		//	//		for (u64 polyIdx = 0; polyIdx < diff.size(); ++polyIdx)
		//	//			diff[polyIdx] = aes0.ecbEncBlock(block(polyIdx)) ^ aes1.ecbEncBlock(block(polyIdx) * 2);
		//	//	};
		//	std::array<std::vector<block>, 2> a; a[0].resize(size), a[1].resize(size);
		//	std::vector<block> t0(size), t1(size);
		//	expand(mSendOts[0][0], t0);
		//	expand(mSendOts[0][1], t1);
		//	for (u64 polyIdx = 0; polyIdx < size; ++polyIdx)
		//		a[0][polyIdx] = t0[polyIdx] ^ t1[polyIdx];

		//	// a[1] = 2 * a[0]
		//	F4Multiply(a[0][0], a[0][1], ZeroBlock, AllOneBlock, a[1][0], a[1][1]);

		//	{
		//		auto lsbIter = BitIterator(&a[0][0]);
		//		auto msbIter = BitIterator(&a[0][1]);
		//		for (u64 polyIdx = 0; polyIdx < coeffs.size(); ++polyIdx)
		//			coeffs[polyIdx] = (*lsbIter++ & 1) | ((*msbIter++ & 1) << 1);
		//	}

		//	{
		//		setBytes(prod, 0);
		//		auto prodIter = prod.begin();
		//		auto lsbIter = BitIterator(&t0[0]);
		//		auto msbIter = BitIterator(&t0[1]);
		//		for (u64 polyIdx = 0; polyIdx < coeffs.size(); ++polyIdx)
		//			*prodIter++ = (*lsbIter++) | (u8(*msbIter++) << 1);
		//	}


		//	std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
		//	auto buffIter = buffer.begin();
		//	for (u64 polyIdx = 1; polyIdx < 2 * coeffs.size(); ++polyIdx)
		//	{
		//		auto b = polyIdx & 1;
		//		auto idx = polyIdx / 2;
		//		auto prodIter = prod.begin() + idx * coeffs.size();

		//		expand(mSendOts[polyIdx][0], t0);
		//		expand(mSendOts[polyIdx][1], t1);

		//		// prod  = mask
		//		auto lsbIter = BitIterator(&t0[0]);
		//		auto msbIter = BitIterator(&t0[1]);
		//		for (u64 polyIdx = 0; polyIdx < coeffs.size(); ++polyIdx)
		//			*prodIter++ ^= (*lsbIter++) | (u8(*msbIter++) << 1);

		//		for (u64 polyIdx = 0; polyIdx < a.size(); ++polyIdx)
		//		{   //        mask    key     value
		//			*buffIter++ = t0[polyIdx] ^ t1[polyIdx] ^ a[b][polyIdx];
		//			//*buffIter++ = diff[polyIdx];
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

		//	for (u64 polyIdx = 0; polyIdx < coeffs.size(); ++polyIdx)
		//		coeffs[polyIdx] = mChoiceOts[2 * polyIdx] | (u8(mChoiceOts[2 * polyIdx + 1] << 1));
		//	std::vector<block> t(size);
		//	expand(mRecvOts[0], t);

		//	{
		//		setBytes(prod, 0);
		//		auto prodIter = prod.begin();
		//		auto lsbIter = BitIterator(&t[0]);
		//		auto msbIter = BitIterator(&t[1]);
		//		for (u64 polyIdx = 0; polyIdx < coeffs.size(); ++polyIdx)
		//			*prodIter++ = (*lsbIter++) | (u8(*msbIter++) << 1);
		//	}

		//	std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
		//	co_await sock.recv(buffer);

		//	auto buffIter = buffer.begin();
		//	for (u64 polyIdx = 1; polyIdx < 2 * coeffs.size(); ++polyIdx)
		//	{
		//		auto idx = polyIdx / 2;
		//		auto prodIter = prod.begin() + idx * coeffs.size();

		//		expand(mRecvOts[polyIdx], t);
		//		if (mChoiceOts[polyIdx])
		//		{
		//			for (u64 polyIdx = 0; polyIdx < size; ++polyIdx)
		//			{
		//				t[polyIdx] = t[polyIdx] ^ *buffIter++;
		//			}
		//		}
		//		else
		//			buffIter += size;

		//		// prod  = mask
		//		auto lsbIter = BitIterator(&t[0]);
		//		auto msbIter = BitIterator(&t[1]);
		//		for (u64 polyIdx = 0; polyIdx < coeffs.size(); ++polyIdx)
		//			*prodIter++ ^= (*lsbIter++) | (u8(*msbIter++) << 1);
		//	}
		//}
	}


}
#endif