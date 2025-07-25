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
#include "libOTe/Tools/Gmw/Gmw.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include "libOTe/Base/BaseOT.h"
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

		// t, the number of noisy positions per polynomial
		u64 mPolyWeight = 8;

		// c, the number of polynomials.
		u64 mNumPolys = 1;

		// the size of a polynomial, 2^mLogN. 
		// We will produce this many OLEs.
		u64 mN = 0;

		// log2 polynomial size
		u64 mLogN = 0;

		// The A poly in FFT format. There will be mNumPolys rows. 
		Matrix<F> mFftA;

		// The A^2 poly in FFT format. There will be mNumPolys^2 rows. 
		Matrix<F> mFftASquared;

		// the number of F values per block. Each block will have 1 non-zero.
		// A polynomial will have mPolyWeight blocks. polyIdx.e. mN = mPolyWeight * mBlockSize.
		u64 mBlockSize = 0;

		// The log2 of mBlockSize. 
		u64 mBlockDepth = 0;

		// the number of F^mDpfLeafSize elements that the main DPF will output.
		// This will be approximately be mBlockSize / log2|F| * mDpfLeafSize.
		u64 mDpfTreeSize = 0;

		// The log2 of mDpfTreeSize.
		u64 mDpfTreeDepth = 0;

		// the locations of the non-zeros in the bPolyIdx'th block of the sparse polynomial.
		// the polyIdx'th row containts the coeffs for the polyIdx'th poly.
		Matrix<u64> mSparsePositions;


		// The mPolyWeight coefficients of the mNumPolys sparse polynomials.
		std::vector<F> mSparseCoefficients;// (mNumPolys* mPolyWeight);
		std::vector<F> mTensoredCoefficients;// (mNumPolys* mNumPolys* mPolyWeight* mPolyWeight);


		// 
		std::vector<block> mTensorRecvOts;
		BitVector mTensorChoice;
		std::vector<std::array<block, 2>> mTensorSendOts;

#ifdef ENABLE_SOFTSPOKEN_OT
		std::optional<SoftSpokenShOtReceiver<>> mOtExtRecver;
		std::optional<SoftSpokenShOtSender<>> mOtExtSender;
#endif

		// run the insecure debug checks.
		bool mDebug = false;

		//RegularDpf<F, CoeffCtx> mDpf;
		SumDmpf<F, CoeffCtx> mDpf;


		using VecF = CoeffCtx::template Vec<F>;
		//struct Tensor
		//{
		//	VecF mSparseCoeffs; // the sparse coefficients
		//	VecF mTensoredCoeffs; // the tensored coefficients
		//};

		CoeffCtx mCtx;

		enum class BaseCorType
		{
			// generate the tensor using a OT based protocol (noisy vole).
			OtBased,

			// the user will provide the tensor coefficients
			Precomputed
		};

		BaseCorType mBaseCorType;

		BetaCircuit mAdder;

		Gmw mGmw;

		// Intializes the protocol to generate n F OLEs. Most efficient when n
		// is a power of 2. Once called, baseOtCount() can be called to 
		// determine the required number of base OTs.
		void init(u64 partyIdx, u64 n, BaseCorType tensorPre = BaseCorType::OtBased, CoeffCtx ctx = {});

		bool isInitialized() const { return mN > 0; }

		struct BaseCorCount
		{
			// the number of base OTs as sender.
			u64 mSendOtCount = 0;

			// the number of base OTs as receiver.
			u64 mRecvOtCount = 0;

			// the required number of binary oles.
			u64 mOleCount = 0;

			u64 mCoeffCount = 0;

		};

		// returns the number of base OTs required. 
		BaseCorCount baseCorCount() const;

		// sets the base OTs that will be used.
		void setBaseCors(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const BitVector& baseChoices,
			span<block> oleMult,
			span<block> oleAdd,
			span<F> coeffs,
			span<F> tensoredCoeffs);

		// returns true of the base OTs have been set.
		bool hasBaseCors() const;

		macoro::task<> genBaseCors(PRNG& prng, Socket& sock);

		// The F OLE protocol. This will generate n OLEs. This party will
		// output (A,C) while the other outputs (A',C') such that
		// A * A' = C + C'.
		macoro::task<> expand(
			span<F> A,
			span<F> C,
			PRNG& prng,
			coproto::Socket& sock);

		task<> checkExpanded(
			std::vector<osuCrypto::u64>& prodPolyTreePosArth, 
			coproto::Socket& sock, 
			std::vector<osuCrypto::u64>& prodPolyTreePosXor, 
			osuCrypto::Matrix<F>& prodPolys);


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
		// as `prod`. We allow the coeff to be zero.
		//
		// samples random coeffs and their product
		//
		//  coeffs[0]   * (other.coeffs[0], ..., other.coeffs[n-1])
		//  coeffs[1]   * (other.coeffs[0], ..., other.coeffs[n-1])
		//   ...						    
		//  coeffs[n-1] * (other.coeffs[0], ..., other.coeffs[n-1])
		// 
		macoro::task<> tensorSend(span<F> coeffs, span<F> prod, coproto::Socket& sock,
			PRNG& prng,
			span<std::array<block, 2>> sendOts);

		// samples random coeffs and their product
		//
		//  other.coeffs[0]   * (coeffs[0], ..., coeffs[n-1])
		//  other.coeffs[1]   * (coeffs[0], ..., coeffs[n-1])
		//   ...						    
		//  other.coeffs[n-1] * (coeffs[0], ..., coeffs[n-1])
		// 
		// 
		macoro::task<> tensorRecv(span<F> coeffs, span<F> prod, coproto::Socket& sock,
			PRNG& prng,
			span<block> recvOts,
			BitVector& choice);


		task<> checkTensor(Socket& sock);

		// sample the A polynomial. This is the polynomial that will be
		// multiplied the sparse polynomials by.
		void sampleA(block seed);


		macoro::task<> arithmeticToBinary(
			span<u64> out,
			span<const u64> in,
			Socket& sock);

	};












	// converts n OTs into n binary OLEs in packed format.
	void convertToOle(
		span<block> A,
		BitVector& choice,
		span<block> add,
		span<block> mult);


	// converts n OTs into n binary OLEs in packed format.
	void convertToOle(
		span<std::array<block, 2>> A,
		span<block> add,
		span<block> mult);





	template<typename F, typename CoeffCtx>
	void RingLpnTriple<F, CoeffCtx>::init(u64 partyIdx, u64 n, BaseCorType base, CoeffCtx ctx)
	{
		mPartyIdx = partyIdx;
		mLogN = log2ceil(n);
		auto logT = log2ceil(mPolyWeight);
		mN = 1ull << mLogN;
		mBaseCorType = base;
		mCtx = ctx;

		if (mPolyWeight != 1ull << logT)
			throw RTE_LOC;

		mBlockSize = mN / mPolyWeight;
		mBlockDepth = mLogN - logT;
		//mDpfLeafDepth = std::min<u64>(5, mBlockDepth);
		mDpfTreeDepth = mBlockDepth + 1;// -mDpfLeafDepth;

		//mDpfLeafSize = ipow(2, mDpfLeafDepth);
		mDpfTreeSize = 1ull << mDpfTreeDepth;

		//mDpfLeaf.init(mPartyIdx, mDpfLeafSize, mNumPolys * mNumPolys * mPolyWeight * mPolyWeight);
		//mDpf.init(mPartyIdx, mDpfTreeSize, mPolyWeight * mNumPolys * mNumPolys * mPolyWeight);
		mDpf.init(mPartyIdx, mDpfTreeSize, mPolyWeight, mNumPolys * mNumPolys * mPolyWeight);

		BetaLibrary lib;
		mAdder = *lib.int_int_add(mDpfTreeDepth, mDpfTreeDepth, mDpfTreeDepth, BetaLibrary::Optimized::Depth);

		auto weight = mNumPolys * mPolyWeight;
		mGmw.init(mPartyIdx, weight * weight, mAdder);

		if (mBlockSize < 2)
			throw RTE_LOC;

		sampleA(block(3127894527893612049, 240925987420932408));
	}


	template<typename F, typename CoeffCtx>
	RingLpnTriple<F, CoeffCtx>::BaseCorCount RingLpnTriple<F, CoeffCtx>::baseCorCount() const
	{
		BaseCorCount counts;

		counts.mSendOtCount = mDpf.baseOtCount();
		counts.mRecvOtCount = mDpf.baseOtCount();
		counts.mOleCount = mGmw.oleCount();

		if (mBaseCorType == BaseCorType::OtBased)
		{
			auto count = mNumPolys * mPolyWeight * mCtx.bitSize<F>();
			if (mPartyIdx)
				counts.mRecvOtCount += count;
			else
				counts.mSendOtCount += count;
		}
		else
		{
			counts.mCoeffCount = mNumPolys * mPolyWeight;
		}

		return counts;
	}


	template<typename F, typename CoeffCtx>
	void RingLpnTriple<F, CoeffCtx>::setBaseCors(
		span<const std::array<block, 2>> baseSendOts,
		span<const block> recvBaseOts,
		const BitVector& baseChoices,
		span<block> oleMult,
		span<block> oleAdd,
		span<F> coeffs,
		span<F> tensoredCoeffs)
	{
		auto baseCounts = baseCorCount();
		if (baseSendOts.size() != baseCounts.mSendOtCount)
			throw RTE_LOC;
		if (recvBaseOts.size() != baseCounts.mRecvOtCount)
			throw RTE_LOC;
		if (baseChoices.size() != baseCounts.mRecvOtCount)
			throw RTE_LOC;

		if (oleMult.size() != divCeil(baseCounts.mOleCount, 128))
			throw RTE_LOC;
		if (oleAdd.size() != divCeil(baseCounts.mOleCount, 128))
			throw RTE_LOC;

		if (coeffs.size() != baseCounts.mCoeffCount)
			throw RTE_LOC;
		if (tensoredCoeffs.size() != baseCounts.mCoeffCount * baseCounts.mCoeffCount)
			throw RTE_LOC;

		auto recvIter = recvBaseOts;
		auto sendIter = baseSendOts;
		auto& choiceIter = baseChoices;

		auto dpfCount = mDpf.baseOtCount();
		if (dpfCount)
		{
			mDpf.setBaseOts(
				sendIter.subspan(0, dpfCount),
				recvIter.subspan(0, dpfCount),
				baseChoices.subvec(0, dpfCount)
			);
		}

		mTensorRecvOts.assign(
			recvIter.subspan(dpfCount).begin(),
			recvIter.subspan(dpfCount).end());
		mTensorSendOts.assign(
			sendIter.subspan(dpfCount).begin(),
			sendIter.subspan(dpfCount).end());
		mTensorChoice = baseChoices.subvec(dpfCount);

		mGmw.setOle(oleMult, oleAdd);
		mSparseCoefficients.assign(coeffs.begin(), coeffs.end());
		mTensoredCoefficients.assign(tensoredCoeffs.begin(), tensoredCoeffs.end());

	}

	template<typename F, typename CoeffCtx>
	bool RingLpnTriple<F, CoeffCtx>::hasBaseCors() const
	{
		return mDpf.hasBaseOts();
	}

	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::genBaseCors(
		PRNG& prng,
		Socket& sock)
	{
		if (isInitialized() == false)
		{
			throw std::runtime_error("init must be called first. " LOCATION);
		}
		auto baseCount = baseCorCount();

		auto recvCount = baseCount.mRecvOtCount;
		auto sendCount = baseCount.mSendOtCount;

		if (mPartyIdx)
		{
			recvCount += baseCount.mOleCount;
		}
		else
		{
			sendCount += baseCount.mOleCount;
		}


		BitVector choice(recvCount);
		choice.randomize(prng);
		std::vector<block> recvMsg(choice.size());
		std::vector<std::array<block, 2>> sendMsg(sendCount);
		std::vector<block> oleMult(baseCount.mOleCount);
		std::vector<block> oleAdd(baseCount.mOleCount);

		setTimePoint("genBase.start");
		if (mPartyIdx)
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
				BitVector cc(extSenderCount);
				choice.append(cc);
				recvMsg.resize(choice.size());
			}

			co_await mOtExtRecver->receive(choice, recvMsg, prng, sock);

			if (extSenderCount)
			{
				BitVector senderChoice(choice.data(), extSenderCount, recvCount);
				span<block> senderMsg(recvMsg.data() + recvCount, extSenderCount);
				mOtExtSender->setBaseOts(senderMsg, senderChoice);
				choice.resize(recvCount);
				recvMsg.resize(recvCount);
			}

			co_await mOtExtSender->send(sendMsg, prng, sock);

#elif defined(LIBOTE_HAS_BASE_OT)
			auto sock2 = sock.fork();
			auto prng2 = prng.fork();
			auto baseOt1 = DefaultBaseOT{};
			auto baseOt2 = DefaultBaseOT{};

			co_await(
				macoro::when_all_ready(
					baseOt1.send(sendMsg, prng, sock),
					baseOt2.receive(choice, recvMsg, prng2, sock2)));
#else
			throw std::runtime_error("A base OT must be enabled. " LOCATION);
#endif
		}
		else
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
				sendMsg.resize(sendCount + extRecverCount);
			}

			co_await mOtExtSender->send(sendMsg, prng, sock);

			if (extRecverCount)
			{
				span<std::array<block, 2>> recverMsg(sendMsg.data() + sendCount, extRecverCount);
				mOtExtRecver->setBaseOts(recverMsg);
				sendMsg.resize(sendCount);
			}

			co_await mOtExtRecver->receive(choice, recvMsg, prng, sock);

#elif defined(LIBOTE_HAS_BASE_OT)
			auto sock2 = sock.fork();
			auto prng2 = prng.fork();
			auto baseOt1 = DefaultBaseOT{};
			auto baseOt2 = DefaultBaseOT{};

			co_await(
				macoro::when_all_ready(
					baseOt1.receive(choice, recvMsg, prng, sock),
					baseOt2.send(sendMsg, prng2, sock2)
				));
#else
			throw std::runtime_error("A base OT must be enabled. " LOCATION);
#endif
		}


		std::vector<F> coeffs(baseCount.mCoeffCount);
		std::vector<F> tensoredCoeffs(baseCount.mCoeffCount * baseCount.mCoeffCount);

		if (mPartyIdx)
		{
			{
				auto offset = recvMsg.size() - baseCount.mOleCount;
				span<block> recv(recvMsg.data() + offset, baseCount.mOleCount);
				BitVector bits(choice.data(), baseCount.mOleCount, offset);
				convertToOle(recv, bits, oleMult, oleAdd);
				choice.resize(offset);
				recvMsg.resize(offset);
			}

			{

				auto tensorOtCount = mNumPolys * mPolyWeight * mCtx.bitSize<F>();
				auto offset = recvMsg.size() - tensorOtCount;
				span<block> recv(recvMsg.data() + offset, tensorOtCount);
				BitVector bits(choice.data(), tensorOtCount, offset);
				co_await tensorRecv(
					coeffs,
					tensoredCoeffs,
					sock,
					prng,
					recv,
					bits);
			}
		}
		else
		{
			{
				auto offset = sendMsg.size() - baseCount.mOleCount;
				span<std::array<block, 2>> send(sendMsg.data() + offset, baseCount.mOleCount);
				convertToOle(send, oleMult, oleAdd);
			}


			{
				auto tensorOtCount = mNumPolys * mPolyWeight * mCtx.bitSize<F>();
				auto offset = recvMsg.size() - tensorOtCount;
				span<std::array<block, 2>> send(sendMsg.data() + offset, tensorOtCount);

				co_await tensorSend(
					coeffs,
					tensoredCoeffs,
					sock,
					prng,
					send);
			}
		}

		setBaseCors(sendMsg, recvMsg, choice, oleMult, oleAdd, coeffs, tensoredCoeffs);


		setTimePoint("genBase.done");
	}


	template<typename F, typename CoeffCtx>
	void RingLpnTriple<F, CoeffCtx>::sampleA(block seed)
	{

		if (mNumPolys > 8)
			throw RTE_LOC;

		PRNG prng(seed);
		mFftA.resize(mNumPolys, mN);
		mFftASquared.resize(0, 0);
		mFftASquared.resize(mNumPolys * mNumPolys, mN);
		//prng.get(mFftA.data() + mN, mFftA.size() - mN);

		// make a_0 the identity polynomial (in FFT space) polyIdx.e., all 1s
		for (size_t i = 0; i < mN; i++) {
			mFftA(0, i) = 1;
			for (u64 j = 1; j < mNumPolys; ++j)
				mFftA(j, i) = prng.get();
		}

		for (size_t i = 0; i < mN; i++)
		{
			for (size_t j = 0; j < mNumPolys; j++)
			{
				for (size_t k = 0; k < mNumPolys; k++)
				{
					auto a = mFftA(j, i);
					auto b = mFftA(k, i);
					mFftASquared(j * mNumPolys + k, i) = a * b;
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


	//std::vector<u8> buffer(mNumPolys * mPolyWeight * mCtx.template byteSize<F>());
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
		Socket& sock)
	{
		if (out.size() != in.size())
			throw RTE_LOC;

		if (0)
		{

			// For now, we do this insecurely by revealing the inputs
			// and constructing XOR shares of the addition

			// Generate random values for XOR sharing
			PRNG prng(CCBlock);
			for (u64 i = 0; i < in.size(); ++i)
				out[i] = prng.get<u64>() % mDpfTreeDepth;

			// Now create XOR shares of these values
			// Party 0 gets a random value r, party 1 gets actualValue ^ r
			if (mPartyIdx == 0)
			{
				// Receive the other party's shares
				std::vector<u64> otherShares(in.size());
				co_await sock.recv(otherShares);

				for (u64 i = 0; i < in.size(); ++i)
				{
					out[i] ^= (in[i] + otherShares[i]) % mDpfTreeDepth;
				}
			}
			else
			{
				// Send my shares to the other party
				co_await sock.send(std::vector<u64>(in.begin(), in.end()));
			}
		}
		else
		{
			if (mGmw.mN != in.size())
				throw RTE_LOC;
			MatrixView<const u64> inView(in.data(), in.size(), 1);
			mGmw.setInput<const u64>(mPartyIdx, inView);
			mGmw.setZeroInput(1 ^ mPartyIdx);

			co_await mGmw.run(sock);

			MatrixView<u64> outView(out.data(), out.size(), 1);
			mGmw.getOutput<u64>(0, outView);
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

		if (hasBaseCors() == false)
		{
			co_await genBaseCors(prng, sock);
		}

		if (mN < A.size())
			throw RTE_LOC;
		if (A.size() != B.size())
			throw RTE_LOC;

		// the coefficient of the sparse polynomial.
		// the polyIdx'th row contains the coeffs for the polyIdx'th poly.
		// the position is within the corresponding block, not the
		// overall polynomial.
		mSparsePositions.resize(mNumPolys, mPolyWeight);

		// select random positions for the sparse polynomial.
		// The polyIdx'th is the noise position in the polyIdx'th block.
		for (u64 i = 0; i < mSparsePositions.size(); ++i)
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;


		// we will expand them the main DPF to get the full shared polynomial. 
		// prodPolyTreePosArth is the location that the F coefficient should 
		// be mapped to as an arithmetic sharing. prodPolyTreePosXor will hold the same
		// as a binary sharing.
		std::vector<u64> prodPolyTreePosArth(mNumPolys * mNumPolys * mPolyWeight * mPolyWeight);
		std::vector<u64> prodPolyTreePosXor(mNumPolys * mNumPolys * mPolyWeight * mPolyWeight);


		// APolyIdx indexes the first polynomial held by party 0.
		// polyOffset is the offset into the tensored coefficients
		for (u64 APolyIdx = 0, polyOffset = 0; APolyIdx < mNumPolys; ++APolyIdx)
		{
			// BPolyIdx indexes the second polynomial held by party 1.
			for (u64 BPolyIdx = 0; BPolyIdx < mNumPolys; ++BPolyIdx, polyOffset += mPolyWeight * mPolyWeight)
			{
				// we are working with polynomials A[APolyIdx] and B[BPolyIdx].
				// these are "regular polynomials" where each has 
				// mPolyWeight non-zeros, each of which is in a different block.

				// in the product polynomial C = A[APolyIdx] * B[BPolyIdx], 
				// there will be exactly mPolyWeight^2 non-zeros. Each block 
				// will have exactly mPolyWeight non-zeros. To simplify, we will
				// use nextIdx to keep track how many coefficients have 
				// been added to each block. 
				std::vector<uint8_t> nextIdx(mPolyWeight);

				// ABlkIdx indexes the first block of the product polynomial.
				for (u64 ABlkIdx = 0; ABlkIdx < mPolyWeight; ++ABlkIdx)
				{
					// BBlkIdx indexes the second block of the product polynomial.
					for (u64 BBlkIdx = 0; BBlkIdx < mPolyWeight; ++BBlkIdx)
					{
						// get the polynomial index and the block index for my polynomial.
						u64 myPolyIdx = mPartyIdx ? BPolyIdx : APolyIdx;
						u64 myBlkIdx = mPartyIdx ? BBlkIdx : ABlkIdx;

						// the block of the product coefficient is known
						// purely using the block index of the input coefficients.
						auto prodBlkIdx = (ABlkIdx + BBlkIdx) % mPolyWeight;

						// We want to put all DPF that will be added together
						// next to each other. We do this by using nextIdx to
						// keep track of the next index for each output block.
						size_t idx = polyOffset + prodBlkIdx * mPolyWeight + nextIdx[prodBlkIdx]++;
						prodPolyTreePosArth[idx] = mSparsePositions(myPolyIdx, myBlkIdx);
					}
				}

				if (nextIdx != std::vector<uint8_t>(mPolyWeight, mPolyWeight))
					throw RTE_LOC;
			}
		}

		// convert an arithmetic sharing into a binary sharing.
		// each party has prodPolyTreePosArth which are the arithmetic
		// modulo mBlockSize. The output will be the same values but
		// as a binary sharing. Each party will have prodPolyTreePos
		// such that l
		//   prodPolyTreePosXor[0] ^ prodPolyTreePosXor[1] = 
		//   prodPolyTreePosArth[0] + prodPolyTreePosArth[1] (mod mDpfTreeSize)
		auto converter = arithmeticToBinary(prodPolyTreePosXor, prodPolyTreePosArth, sock);

		// check if we need to generate the tensored coefficients.
		if (mBaseCorType == BaseCorType::OtBased)
		{
			mSparseCoefficients.resize(mNumPolys * mPolyWeight);
			mTensoredCoefficients.resize(mNumPolys * mNumPolys * mPolyWeight * mPolyWeight);

			task<> tensorTask = mPartyIdx ?
				tensorRecv(
					mSparseCoefficients,
					mTensoredCoefficients,
					sock, prng,
					mTensorRecvOts, mTensorChoice) :
				tensorSend(
					mSparseCoefficients,
					mTensoredCoefficients,
					sock, prng,
					mTensorSendOts);

			co_await macoro::when_all_ready(
				std::move(tensorTask),
				std::move(converter));

		}
		else
		{
			co_await converter;
		}

		if (mDebug)
			co_await checkTensor(sock);

		setTimePoint("tesnor");

		// we pack 8 FFTs into a single u16. 
		Matrix<F> fftSparsePoly(mNumPolys, mN);
		for (u64 i = 0; i < mPolyWeight; ++i)
		{
			for (u64 j = 0; j < mNumPolys; ++j)
			{
				// actual position
				auto pos = i * mBlockSize + mSparsePositions(j, i);
				fftSparsePoly(j, pos) = mSparseCoefficients[j * mPolyWeight + i];
			}
		}

		setTimePoint("sparsePolySample");

		// switch from polynomial to FFT form
		std::vector<F> w(mN * 2);
		{
			auto psi = primRootOfUnity<F>(mN * 2);
			for (u64 i = 0; i < mN * 2; ++i)
				w[i] = psi.pow(i);

			for (u64 j = 0; j < mNumPolys; ++j)
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
		std::vector<F> prodPolyFCoeffs(mNumPolys * mNumPolys * mPolyWeight * mPolyWeight);

		// APolyIdx indexes the first polynomial held by party 0.
		// polyOffset is the offset into the tensored coefficients
		for (u64 APolyIdx = 0, polyOffset = 0; APolyIdx < mNumPolys; ++APolyIdx)
		{
			// BPolyIdx indexes the second polynomial held by party 1.
			for (u64 BPolyIdx = 0; BPolyIdx < mNumPolys; ++BPolyIdx, polyOffset += mPolyWeight * mPolyWeight)
			{
				// we are working with polynomials A[APolyIdx] and B[BPolyIdx].
				// these are "regular polynomials" where each has 
				// mPolyWeight non-zeros, each of which is in a different block.

				// in the product polynomial C = A[APolyIdx] * B[BPolyIdx], 
				// there will be exactly mPolyWeight^2 non-zeros. Each block 
				// will have exactly mPolyWeight non-zeros. To simplify, we will
				// use nextIdx to keep track how many coefficients have 
				// been added to each block. 
				std::vector<uint8_t> nextIdx(mPolyWeight);

				// ABlkIdx indexes the first block of the product polynomial.
				for (u64 ABlkIdx = 0; ABlkIdx < mPolyWeight; ++ABlkIdx)
				{
					// BBlkIdx indexes the second block of the product polynomial.
					for (u64 BBlkIdx = 0; BBlkIdx < mPolyWeight; ++BBlkIdx)
					{
						// the block of the product coefficient is known
						// purely using the block index of the input coefficients.
						auto prodBlkIdx = (ABlkIdx + BBlkIdx) % mPolyWeight;

						// We want to put all DPF that will be added together
						// next to each other. We do this by using nextIdx to
						// keep track of the next index for each output block.
						size_t idx = polyOffset + prodBlkIdx * mPolyWeight + nextIdx[prodBlkIdx]++;

						// get the corresponding tensored F4 coefficient.
						auto coeffIdx = (APolyIdx * mPolyWeight + ABlkIdx) * mNumPolys * mPolyWeight + BPolyIdx * mPolyWeight + BBlkIdx;
						prodPolyFCoeffs[idx] = mTensoredCoefficients[coeffIdx];

						// pre negate the coefficients  will need to wrap X^n+1.
						if (prodBlkIdx != ABlkIdx + BBlkIdx)
							prodPolyFCoeffs[idx] = -prodPolyFCoeffs[idx];
					}
				}
			}
		}

		setTimePoint("dpfParams");


		// the full set of monomial blocks.
		//Matrix<F> monomials(mNumPolys * mNumPolys * mPolyWeight * mPolyWeight, mDpfTreeSize);
		Matrix<F> prodPolys(mNumPolys * mNumPolys, mN + mBlockSize);
		// expand the main tree and add the mPolyWeight point functions correspond 
		// to a block together. This will give us the coefficients of the
		// the product polynomial.

		if (1ull << log2ceil(mPolyWeight) != mPolyWeight)
			throw RTE_LOC;
		auto shift = log2ceil(mPolyWeight);
		auto mask = mPolyWeight - 1;

		co_await mDpf.expand(prodPolyTreePosXor, prodPolyFCoeffs, prng, sock,
			[&/*, count = 0ull, out = prodPolys.data(), end = prodPolys.data() + prodPolys.size()*/]
			(u64 treeIdx, u64 leafIdx, F v, auto t) mutable {
				auto polyIdx = treeIdx >> shift;// / mPolyWeight;
				auto blockIdx = treeIdx & mask;//% mPolyWeight;
				prodPolys.data(polyIdx)[leafIdx + blockIdx * mBlockSize] += v;
			}, mCtx);

		// perform mod x^n+1 on the last block which overflows.
		for (u64 i = 0; i < mNumPolys * mNumPolys; ++i)
		{
			// negate and wrap the last block.
			for (u64 j = 0; j < mBlockSize; ++j)
				prodPolys(i, j) -= prodPolys(i, j + mN);
		}

		if (mDebug)
			co_await checkExpanded(prodPolyTreePosArth, sock, prodPolyTreePosXor, prodPolys);

		setTimePoint("mainDpf");


		for (u64 i = 0, polyOffset = 0; i < mNumPolys * mNumPolys; ++i)
		{
			auto prod = prodPolys[i].subspan(0, mN);
			nttNegWrapCt<F>(prod, w);
			hadamarProd<F>(prod, mFftASquared[i], prod);
			// compress the resume and set the output.
			auto outSize = std::min<u64>(mN, B.size());
			for (u64 k = 0; k < outSize; ++k)
				B[k] = B[k] + prod[k];
		}

		mSparseCoefficients.clear();
		mTensoredCoefficients.clear();

		setTimePoint("addCopyY");

	}

	template<typename F, typename CoeffCtx>
	task<> RingLpnTriple<F, CoeffCtx>::checkExpanded(
		std::vector<osuCrypto::u64>& prodPolyTreePosArth,
		coproto::Socket& sock,
		std::vector<osuCrypto::u64>& prodPolyTreePosXor,
		osuCrypto::Matrix<F>& prodPolys)
	{
		// the input polynomials positions and values.
		std::array<Matrix<u64>, 2> Pos;
		Pos[0].resize(mNumPolys, mPolyWeight);
		Pos[1].resize(mNumPolys, mPolyWeight);
		std::array <Matrix<F>, 2> Val;
		Val[0].resize(mNumPolys, mPolyWeight);
		Val[1].resize(mNumPolys, mPolyWeight);

		// the XOR shares of the product polynomials positions.
		Matrix<u64> ProdPosXor(mNumPolys * mNumPolys * mPolyWeight, mPolyWeight);
		// the arithmetic shares of the product polynomials positions.
		Matrix<u64> ProdPosArth(mNumPolys * mNumPolys * mPolyWeight, mPolyWeight);

		//Matrix<F> ProdVals = prodPolyFCoeffs;

		for (u64 i = 0; i < mNumPolys * mPolyWeight; ++i)
		{
			Pos[mPartyIdx](i) = mSparsePositions(i);
			Val[mPartyIdx](i) = mSparseCoefficients[i];
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
		co_await send<F>(mSparseCoefficients, sock, mCtx);
		co_await recv<F>(Val[mPartyIdx ^ 1], sock, mCtx);

		//auto monos = monomials;
		//co_await reveal<F>(monos, sock, mCtx);

		auto full = prodPolys;
		co_await reveal<F>(full, sock, mCtx);


		for (u64 aPolyIdx = 0, polyOffset = 0; aPolyIdx < mNumPolys; ++aPolyIdx)
		{
			Poly<F> aPoly;
			for (u64 i = 0; i < mPolyWeight; ++i)
				aPoly[Pos[0][aPolyIdx][i] + i * mBlockSize] = Val[0][aPolyIdx][i];

			for (u64 bPolyIdx = 0; bPolyIdx < mNumPolys; ++bPolyIdx, polyOffset += mPolyWeight * mPolyWeight)
			{
				Poly<F> bPoly;
				for (u64 i = 0; i < mPolyWeight; ++i)
					bPoly[Pos[1][bPolyIdx][i] + i * mBlockSize] = Val[1][bPolyIdx][i];


				std::vector<uint8_t> nextIdx(mPolyWeight);
				Matrix<u64> expPos(mPolyWeight, mPolyWeight);
				Matrix<F> expVal(mPolyWeight, mPolyWeight);
				// ABlkIdx indexes the first block of the product polynomial.
				for (u64 ABlkIdx = 0; ABlkIdx < mPolyWeight; ++ABlkIdx)
				{
					// BBlkIdx indexes the second block of the product polynomial.
					for (u64 BBlkIdx = 0; BBlkIdx < mPolyWeight; ++BBlkIdx)
					{
						// the block of the product coefficient is known
						// purely using the block index of the input coefficients.
						auto prodBlkIdx = (ABlkIdx + BBlkIdx) % mPolyWeight;
						auto offset = nextIdx[prodBlkIdx]++;

						expPos(prodBlkIdx, offset) =
							Pos[0][aPolyIdx][ABlkIdx] + Pos[1][bPolyIdx][BBlkIdx];
						expVal(prodBlkIdx, offset) =
							Val[0][aPolyIdx][ABlkIdx] * Val[1][bPolyIdx][BBlkIdx];
					}
				}
				//for (u64 ABlkIdx = 0; ABlkIdx < mPolyWeight; ++ABlkIdx)
				//{
				//	// BBlkIdx indexes the second block of the product polynomial.
				//	for (u64 BBlkIdx = 0; BBlkIdx < mPolyWeight; ++BBlkIdx)
				//	{
				//		Poly<F> act(monos[polyOffset + (ABlkIdx * mPolyWeight) + BBlkIdx]);
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
				auto act = Poly<F>(full[aPolyIdx * mNumPolys + bPolyIdx].subspan(0, mN));
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


	// samples random coeffs and their product
	//
	//  coeffs[0]   * (other.coeffs[0], ..., other.coeffs[n-1])
	//  coeffs[1]   * (other.coeffs[0], ..., other.coeffs[n-1])
	//   ...						    
	//  coeffs[n-1] * (other.coeffs[0], ..., other.coeffs[n-1])
	// 
	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::tensorRecv(
		span<F> coeffs, span<F> prod,
		coproto::Socket& sock,
		PRNG& prng,
		span<block> recvOts,
		BitVector& choice)
	{
		u64 n = coeffs.size();

		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;
		if (recvOts.size() != n * mCtx.bitSize<F>())
			throw RTE_LOC;


		// Storage for intermediate results - each VOLE needs its own storage
		std::vector<std::vector<F>> voleResults(n);
		for (u64 i = 0; i < n; ++i)
			voleResults[i].resize(n);

		// Create separate sockets for each parallel VOLE
		std::vector<coproto::Socket> sockets(n);
		std::vector<PRNG> prngs(n);
		std::vector<macoro::task<>> tasks(n);
		BitVector diff = std::move(choice);
		DefaultBaseOT base;
		for (u64 i = 0; i < n; ++i)
		{
			sockets[i] = sock.fork();
			prngs[i] = prng.fork();
			mCtx.fromBlock(coeffs[i], prng.get());
			auto bv = mCtx.binaryDecomposition(coeffs[i]);
			for (u64 j = 0; j < bv.size(); ++j)
				diff[i * bv.size() + j] ^= bv[j];
			auto ots = recvOts.subspan(i * mCtx.bitSize<F>(), mCtx.bitSize<F>());
			tasks[i] = NoisyVoleSender<F, F, CoeffCtx>::send(coeffs[i], voleResults[i], prngs[i], ots, sockets[i], mCtx);
		}

		co_await sock.send(std::move(diff));

		// Execute all VOLE instances in parallel
		co_await macoro::when_all_ready(std::move(tasks));

		// Copy results to the output array
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < n; ++j)
			{
				prod[j * n + i] = -voleResults[i][j];
			}
		}

		setTimePoint("tensor.done");

	}

	// samples random coeffs and their product
	//
	//  other.coeffs[0]   * (coeffs[0], ..., coeffs[n-1])
	//  other.coeffs[1]   * (coeffs[0], ..., coeffs[n-1])
	//   ...						    
	//  other.coeffs[n-1] * (coeffs[0], ..., coeffs[n-1])
	// 
	// 
	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::tensorSend(
		span<F> coeffs, span<F> prod, coproto::Socket& sock,
		PRNG& prng,
		span<std::array<block, 2>> sendOts)
	{
		u64 n = coeffs.size();

		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;
		if (sendOts.size() != n * mCtx.bitSize<F>())
			throw RTE_LOC;

		// Storage for intermediate results - each VOLE needs its own storage
		std::vector<std::vector<F>> voleResults(n);
		for (u64 i = 0; i < n; ++i)
			voleResults[i].resize(n);

		// Create separate sockets for each parallel VOLE
		std::vector<coproto::Socket> sockets(n);
		std::vector<PRNG> prngs(n);
		std::vector<macoro::task<>> tasks(n);
		for (u64 i = 0; i < n; ++i)
		{
			sockets[i] = sock.fork();
			prngs[i] = prng.fork();
			mCtx.fromBlock(coeffs[i], prng.get());
			auto ots = sendOts.subspan(i * mCtx.bitSize<F>(), mCtx.bitSize<F>());
			tasks[i] = NoisyVoleReceiver<F, F, CoeffCtx>::receive(coeffs, voleResults[i], prngs[i], ots, sockets[i], mCtx);
		}

		BitVector diff(n * mCtx.bitSize<F>());
		co_await sock.recv(diff);
		for (u64 i = 0; i < diff.size(); ++i)
		{
			if (diff[i])
				std::swap(sendOts[i][0], sendOts[i][1]);
		}

		// Execute all VOLE instances in parallel
		co_await macoro::when_all_ready(std::move(tasks));

		// Copy results to the output array
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < n; ++j)
			{
				prod[j * n + i] = voleResults[i][j];
			}
		}

		setTimePoint("tensor.done");
	}

	template<typename F, typename CoeffCtx>
	macoro::task<> RingLpnTriple<F, CoeffCtx>::checkTensor(Socket& sock)
	{


		// Create copies of our local coefficients and tensored coefficients for revealing
		std::array<std::vector<F>, 2> coeffs;
		std::vector<F> localTensored = mTensoredCoefficients;

		auto n = mSparseCoefficients.size();
		coeffs[mPartyIdx] = mSparseCoefficients;
		coeffs[mPartyIdx ^ 1].resize(mSparseCoefficients.size());

		// Reveal both parties' coefficients
		co_await send<F>(mSparseCoefficients, sock, mCtx);
		co_await recv<F>(coeffs[1 ^ mPartyIdx], sock, mCtx);
		co_await reveal<F>(localTensored, sock, mCtx);

		// Verify the tensor product correctness
		// The tensor should contain shares of party0Coeffs[i] * party1Coeffs[j] for all i,j
		bool tensorCorrect = true;
		std::stringstream errorMsg;

		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < n; ++j)
			{
				auto idx = i * n + j;

				// Expected value: party0Coeffs[i] * party1Coeffs[j]
				F expected;
				mCtx.mul(expected, coeffs[0][i], coeffs[1][j]);

				// Actual revealed value
				F actual = localTensored[idx];

				if (!mCtx.eq(expected, actual))
				{
					tensorCorrect = false;
					errorMsg << "Tensor mismatch at [" << i << "," << j << "]: "
						<< "expected " << expected << ", got " << actual << "\n";
				}
			}
		}

		if (!tensorCorrect)
		{
			std::cout << "Tensor verification failed!" << std::endl;
			std::cout << errorMsg.str() << std::endl;

			std::cout << "Party 0 coefficients: " << print<F>(coeffs[0]) << std::endl;
			std::cout << "Party 1 coefficients: " << print<F>(coeffs[1]) << std::endl;
			std::cout << "Revealed tensor: " << print<F>(localTensored) << std::endl;

			throw RTE_LOC;
		}

	}


}
#endif