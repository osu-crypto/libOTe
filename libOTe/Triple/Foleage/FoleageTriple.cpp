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

#include "FoleageTriple.h"
#include "libOTe/Triple/Foleage/FoleageUtils.h"
#include "libOTe/Triple/Foleage/fft/FoleageFft.h"
#include "cryptoTools/Common/BitIterator.h"
#include "libOTe/Dpf/TernaryDpf.h"
#include "libOTe/Base/BaseOT.h"
namespace osuCrypto
{
	namespace
	{
		OC_FORCEINLINE u8 tensorFrobenius(u8 v, bool xiLane)
		{
			const auto l = v & 1;
			const auto h = (v >> 1) & 1;
			return xiLane ? u8(l | ((l ^ h) << 1)) : u8((l ^ h) | (h << 1));
		}
	}


	void FoleageTriple::init(
		u64 partyIdx,
		u64 n,
		FoleageMode mode,
		FoleageDpfMode dpfMode)
	{
		if (partyIdx > 1)
			throw std::invalid_argument("FoleageTriple party index must be zero or one");
		if (!n)
			throw std::invalid_argument("FoleageTriple size must be positive");
		if (!mC || mC > 8)
			throw std::invalid_argument("FoleageTriple mC must be in [1, 8]");
		if (mode != FoleageMode::F4Ole && mode != FoleageMode::F2TraceOle)
			throw std::invalid_argument("Foleage mode is invalid");
		if (dpfMode != FoleageDpfMode::TernaryDpf)
			throw std::invalid_argument("Foleage RevCuckoo mode is not implemented");

		const auto log3N = log3ceil(n);
		auto noiseWeight = mT;
		if (!noiseWeight)
		{
			const auto selected = lpnParameters::select(
				mC, 4.0, LpnCoefficientDistribution::Uniform);
			noiseWeight = lpnParameters::roundUpPower(
				selected.mNoiseWeight, 3);
			if (!lpnParameters::qaSdHasNoExpectedEvaluationPoint(
				mC, 4.0, 3, log3N))
				throw std::invalid_argument(
					"FOLEAGE compression factor is too small for the requested dimension under the QA-SD interpolation check. " LOCATION);
		}
		if (!noiseWeight)
			throw std::invalid_argument("FoleageTriple mT must be positive");
		if (noiseWeight > 128 / mC)
			throw std::invalid_argument("FoleageTriple supports at most 128 sparse coefficients");
		const auto log3T = log3ceil(noiseWeight);

		if (noiseWeight != ipow(3, log3T))
			throw std::invalid_argument("FoleageTriple mT must be a power of three");
		if (log3N <= log3T)
			throw std::invalid_argument("FoleageTriple requires at least two positions per sparse block");

		const auto N = ipow(3, log3N);
		const auto blockSize = N / noiseWeight;
		const auto blockDepth = log3N - log3T;
		if (blockDepth > 32)
			throw std::invalid_argument("FoleageTriple block depth exceeds F3x32 capacity");

		clearBaseOts();
		mPartyIdx = partyIdx;
		mMode = mode;
		mDpfMode = dpfMode;
		mT = noiseWeight;
		mLog3N = log3N;
		mLog3T = log3T;
		mN = N;
		mBlockSize = blockSize;
		mBlockDepth = blockDepth;
		mDpfLeafDepth = std::min<u64>(5, mBlockDepth);
		mDpfTreeDepth = mBlockDepth - mDpfLeafDepth;

		mDpfLeafSize = ipow(3, mDpfLeafDepth);
		mDpfTreeSize = ipow(3, mDpfTreeDepth);

		const auto pointCount = mC * mC * mT * mT *
			(mode == FoleageMode::F2TraceOle ? 2 : 1);
		mDpfLeaf.init(mPartyIdx, mDpfLeafSize, pointCount);
		mDpf.init(mPartyIdx, mDpfTreeSize, pointCount);

		sampleA(block(3127894527893612049, 240925987420932408));
	}


	FoleageTriple::BaseCount FoleageTriple::baseOtCount() const
	{
		if (!isInitialized())
			throw std::runtime_error("FoleageTriple::init must be called first. " LOCATION);
		BaseCount counts;

		counts.mSendCount = mDpfLeaf.baseOtCount() + mDpf.baseOtCount();
		counts.mRecvCount = mDpfLeaf.baseOtCount() + mDpf.baseOtCount();
		if (mPartyIdx)
			counts.mSendCount += 2 * mC * mT;
		else
			counts.mRecvCount += 2 * mC * mT;
		return counts;
	}


	void FoleageTriple::setBaseOts(
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

		clearBaseOts();
		auto recvIter = recvBaseOts;
		auto sendIter = baseSendOts;
		auto choiceIter = baseChoices;

		auto dpfLeafCount = mDpfLeaf.baseOtCount();
		u64 offset = 0;
		mDpfLeaf.setBaseOts(
			sendIter.subspan(offset, dpfLeafCount),
			recvIter.subspan(offset, dpfLeafCount),
			BitVector(baseChoices.data(), dpfLeafCount, offset)
		);
		offset += dpfLeafCount;

		auto dpfCount = mDpf.baseOtCount();
		mDpf.setBaseOts(
			sendIter.subspan(offset, dpfCount),
			recvIter.subspan(offset, dpfCount),
			BitVector(baseChoices.data(), dpfCount, offset)
		);
		offset += dpfCount;

		auto sendOts = sendIter.subspan(offset);
		auto recvOts = recvIter.subspan(offset);
		mSendOts.assign(sendOts.begin(), sendOts.end());
		mRecvOts.assign(recvOts.begin(), recvOts.end());
		mChoiceOts = BitVector(baseChoices.data(), baseChoices.size() - offset, offset);
		mBaseOtsAvailable = true;
	}

	bool FoleageTriple::hasBaseOts() const
	{
		return mBaseOtsAvailable;
	}

	void FoleageTriple::clearBaseOts()
	{
		mBaseOtsAvailable = false;
		mSendOts.clear();
		mRecvOts.clear();
		mChoiceOts.resize(0);

		mDpfLeaf.mBaseSendOts.resize(0);
		mDpfLeaf.mBaseRecvOts.resize(0);
		mDpfLeaf.mBaseChoice.resize(0);
		mDpf.mBaseSendOts.resize(0);
		mDpf.mBaseRecvOts.resize(0);
		mDpf.mBaseChoice.resize(0);
	}

	macoro::task<> FoleageTriple::genBaseOts(
		PRNG& prng,
		Socket& sock,
		SilentBaseType baseType)
	{
		if (baseType != SilentBaseType::Base &&
			baseType != SilentBaseType::BaseExtend)
			throw std::invalid_argument("Silent base type not supported. " LOCATION);
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

				auto results = co_await(
					macoro::when_all_ready(
						baseOt1.send(sendMsg, prng, sock),
						baseOt2.receive(choice, recvMsg, prng2, sock2)));
				std::get<0>(results).result();
				std::get<1>(results).result();

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

				auto results = co_await(
					macoro::when_all_ready(
						baseOt1.receive(choice, recvMsg, prng, sock),
						baseOt2.send(sendMsg, prng2, sock2)
					));
				std::get<0>(results).result();
				std::get<1>(results).result();

				setBaseOts(sendMsg, recvMsg, choice);
#else
				throw std::runtime_error("A base OT must be enabled. " LOCATION);
#endif
			}

		}
		setTimePoint("genBase.done");
	}


	void FoleageTriple::sampleA(block seed)
	{

		if (mC > 8)
			throw RTE_LOC;

		PRNG prng(seed);
		mFftA.resize(mN);
		mFftASquared.resize(0);
		mFftASquared.resize(mN);
		mFftAFrobenius.clear();
		if (mMode == FoleageMode::F2TraceOle)
			mFftAFrobenius.resize(mN);
		prng.get(mFftA.data(), mFftA.size());

		// make a_0 the identity polynomial (in FFT space) i.e., all 1s
		for (size_t i = 0; i < mN; i++)
		{
			mFftA[i] = (mFftA[i] & ~3) | 1;
		}

		for (size_t i = 0; i < mN; i++)
		{
			std::array<u16, 8> arr{ };
			u64 pos = 0, off = 0;
			for (size_t j = 0; j < mC; j++)
			{
				//u16 temp = 0;
				for (size_t k = 0; k < mC; k++)
				{
					auto a = (mFftA[i] >> (2 * j)) & 0b11;
					auto b = (mFftA[i] >> (2 * k)) & 0b11;
					auto a1 = a & 1;
					auto a2 = a & 2;
					auto b1 = b & 1;
					auto b2 = b & 2;

					u8 prod;
					{
						u8 tmp = (a2 & b2);
						prod = tmp ^ ((a2 & (b1 << 1)) ^ ((a1 << 1) & b2));
						prod |= (a1 & b1) ^ (tmp >> 1);
					}
					arr[pos] |= u16(prod) << (2 * k);
					++off;
					if (off == 8)
					{
						off = 0;
						++pos;
					}
					// Use bit operations to set the appropriate 2 bits in the block
					//size_t slot = j * mC + k;
					//mFftASquared[i] |= prod << (2 * slot);
				}
			}
			mFftASquared[i] = arr;

		}

		if (mMode == FoleageMode::F2TraceOle)
		{
			for (size_t i = 0; i < mN; ++i)
			{
				std::array<u16, 8> frobeniusArr{ };
				u64 pos = 0, off = 0;
				for (size_t j = 0; j < mC; ++j)
				{
					for (size_t k = 0; k < mC; ++k)
					{
						auto a = (mFftA[i] >> (2 * j)) & 3;
						auto b = (mFftA[i] >> (2 * k)) & 3;
						auto bSquared = F4Multiply(u8(b), u8(b));
						auto prod = F4Multiply(u8(a), bSquared);
						frobeniusArr[pos] |= u16(prod) << (2 * k);
						if (++off == 8)
						{
							off = 0;
							++pos;
						}
					}
				}
				mFftAFrobenius[i] = frobeniusArr;
			}
		}
	}




	macoro::task<> FoleageTriple::expand(
		span<block> ALsb,
		span<block> AMsb,
		span<block> CLsb,
		span<block> CMsb,
		PRNG& prng,
		coproto::Socket& sock)
	{
		if (!isInitialized())
			throw std::runtime_error("FoleageTriple::init must be called first. " LOCATION);
		if (mMode != FoleageMode::F4Ole)
			throw std::runtime_error("Foleage F4 expansion requires F4Ole mode");

		setTimePoint("expand start");

		if (divCeil(mN, 128) < ALsb.size())
			throw RTE_LOC;
		if (ALsb.size() != AMsb.size() ||
			ALsb.size() != CLsb.size())
			throw RTE_LOC;
		if (ALsb.size() != CMsb.size() && CMsb.size())
			throw RTE_LOC;

		if (hasBaseOts() == false)
		{
			co_await genBaseOts(prng, sock);
		}
		if (!mBaseOtsAvailable)
			throw std::runtime_error("FoleageTriple requires a fresh base-OT set");

		// One expansion consumes every DPF and tensor base OT. Mark the set
		// unavailable before protocol I/O, and clear it on every exit path.
		mBaseOtsAvailable = false;
		struct ClearBaseOtsOnExit
		{
			FoleageTriple* mThis;
			~ClearBaseOtsOnExit() { mThis->clearBaseOts(); }
		} clearBaseOtsOnExit{ this };

		// the coefficient of the sparse polynomial.
		// the i'th row contains the coefficients for the i'th polynomial.
		mSparsePositions.resize(mC, mT);

		// The mT coefficients of the mC sparse polynomials.
		Matrix<u16> sparseCoefficients(mC, mT);
		std::vector<u16> tensoredCoefficients(mC * mC * mT * mT);

		// generate random sparseCoefficients and tensor them with 
		// the other parties sparse coefficients. The result is shared
		// as tensoredCoefficients. Each set of (mC*mT) values in 
		// tensoredCoefficients are the multiplication of a single coeff 
		// from party 0 and all of the coefficients from party 1.
		co_await tensor(sparseCoefficients, tensoredCoefficients, sock);

		//co_await checkTensor(sparseCoefficients, tensoredCoefficients, sock);

		// select random positions for the sparse polynomial.
		// The i'th is the noise position in the i'th block.
		// The LPN construction is robust to the small bias introduced by
		// reducing a 64-bit sample modulo this power of three; exact uniformity
		// is not required, and the intended parameters retain 30--40 bits of
		// statistical security from this sampling step.
		for (u64 i = 0; i < mSparsePositions.size(); ++i)
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;

		if (mC > 8)
			throw RTE_LOC;

		// we pack 8 FFTs into a single u16. 
		std::vector<u16> fftSparsePoly(mN);
		for (u64 i = 0; i < mT; ++i)
		{
			for (u64 j = 0; j < mC; ++j)
			{
				auto pos = i * mBlockSize + mSparsePositions(j, i);// .toInt();
				fftSparsePoly[pos] |= sparseCoefficients(j, i) << (2 * j);
			}
		}

		setTimePoint("sparsePolySample");

		// switch from polynomial to FFT form
		foleageFft<u16>(fftSparsePoly, mLog3N, mN / 3);

		setTimePoint("input fft");

		// multiply by the packed A polynomial
		F4Multiply(mFftA, fftSparsePoly, fftSparsePoly, mN);

		setTimePoint("input Mult");

		// Compress the result and set the output.
		auto outSize = std::min<u64>(mN, ALsb.size() * 128);
		//std::vector<u8> A(mN);

		u16 msbMask = 0b1010101010101010,
			lsbMask = 0b0101010101010101;
		for (u64 i = 0; i < outSize; ++i)
		{
			auto a =
				(popcount<u16>(fftSparsePoly[i] & lsbMask) & 1) ^
				((popcount<u16>(fftSparsePoly[i] & msbMask) & 1) << 1);

			if (a !=
				(((fftSparsePoly[i] >> 0) ^
					(fftSparsePoly[i] >> 2) ^
					(fftSparsePoly[i] >> 4) ^
					(fftSparsePoly[i] >> 6) ^
					(fftSparsePoly[i] >> 8) ^
					(fftSparsePoly[i] >> 10) ^
					(fftSparsePoly[i] >> 12) ^
					(fftSparsePoly[i] >> 14)) & 3))
				throw RTE_LOC;

			*BitIterator(ALsb.data(), i) = a & 1;
			*BitIterator(AMsb.data(), i) = (a >> 1) & 1;

			//A[i] = a;
		}
		setTimePoint("copyOutX");

		// Sharing of the F4 coefficients of the product polynomials.
		// these will just be the tensored coefficients but in permuted
		// order to match how they are expanded in the DPF and then added
		// together.
		std::vector<uint8_t> prodPolyF4Coeffs(mC * mC * mT * mT);

		// We are doing to use "early termination" on the main DPF. To do
		// this we are going to construct new F4^243 coefficients where
		// each prodPolyF4Coeffs is positioned at prodPolyLeafPos. This
		// will allow the main DPF to be more efficient as we are outputting
		// 243 F4 elements for each leaf.
		std::vector<F3x32> prodPolyLeafPos(mC * mC * mT * mT);

		// once we construct large F4^243 coefficients, we will expand them
		// the main DPF to get the full shared polynomial. prodPolyTreePos
		// is the location that the F4^243 coefficient should be mapped to.
		std::vector<F3x32> prodPolyTreePos(mC * mC * mT * mT);



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
						auto blockPos = F3x32(jA) + F3x32(jB);
						auto blockIdx = blockPos.toInt();

						// We want to put all DPF that will be added together
						// next to each other. We do this by using nextIdx to
						// keep track of the next index for each output block.
						size_t idx = polyOffset + blockIdx * mT + nextIdx[blockIdx]++;

						// split the position into the portion that will position
						// the F4 coefficient within the F4^243 coefficient and the
						// portion that will position the F4^243 coefficient within
						// the main DPF.
						auto pos = F3x32(mSparsePositions(i, j)); // (F_3)^n + (F_3)^n
						prodPolyLeafPos[idx] = pos.lower(mDpfLeafDepth);
						prodPolyTreePos[idx] = pos.upper(mDpfLeafDepth);

						// get the corresponding tensored F4 coefficient.
						auto coeffIdx = (iA * mT + jA) * mC * mT + iB * mT + jB;
						prodPolyF4Coeffs[idx] = tensoredCoefficients[coeffIdx];
					}
				}

				if (nextIdx != std::vector<uint8_t>(mT, mT))
					throw RTE_LOC;
			}
		}

		setTimePoint("dpfParams");

		// Sharing of the F4^243 coefficients of the product polynomials.
		// These are obtained by expanding the F4 coefficients into 243
		// elements using a "small DPF".
		std::vector<FoleageF4x243> prodPolyF4x243Coeffs(mC * mC * mT * mT);

		// current coefficients are single F4 elements. Expand them into
		// 3^5=243 elements. These will be used as the new coefficients
		// in the large tree.
		co_await mDpfLeaf.expand(prodPolyLeafPos, prodPolyF4Coeffs,
			[&, byteIdx = 0ull, bitIdx = 0ull](u64 treeIdx, u64 leafIdx, u8 v) mutable {
				if (treeIdx == 0)
				{
					byteIdx = leafIdx / 4;
					bitIdx = leafIdx % 4;
				}
				assert(byteIdx == leafIdx / 4);
				assert(bitIdx == leafIdx % 4);

				auto ptr = (u8*)&prodPolyF4x243Coeffs.data()[treeIdx];
				ptr[byteIdx] |= u8((v & 3) << (2 * bitIdx));
			}, prng, sock);

		setTimePoint("leafDpf");


		Matrix<FoleageF4x243> blocks(mC * mC * mT, mDpfTreeSize);
		// expand the main tree and add the mT point functions correspond 
		// to a block together. This will give us the coefficients of the
		// the product polynomial.
		co_await mDpf.expand(prodPolyTreePos, prodPolyF4x243Coeffs,
			[&, count = 0ull, out = blocks.data(), end = blocks.data() + blocks.size()]
			(u64 treeIdx, u64 leafIdx, FoleageF4x243 v) mutable {
				// the callback is called in column major order but blocks
				// is row major (leafIdx will be the same). So we need to compute 
				// the correct index. Moreover, we are adding together mT trees 
				// so we also need divide the treeIdx by mT. To make this more 
				// efficient, we use the out pointer and manually increment it.

				assert(out == &blocks(treeIdx / mT, leafIdx));
				*out ^= v;

				if (++count == mT)
				{
					count = 0;
					out += blocks.cols();
					if (out >= end)
					{
						out -= blocks.size() - 1;
					}
				}
			}, prng, sock);


		setTimePoint("mainDpf");


		std::vector<block> fft(mN), fftRes(mN);

		// We have mC*mC = 64 polynomials. We need to apply
		// the FFT to each. We do this by packing the 64 polynomials
		// into a single block. We then apply the FFT to this block.
		// This is done for each of the mT blocks of each polynomial.
		//
		// The DPFs used 512 bits to represent mDpfLeafSize=243 F4 elements. 
		// We need to skip the last 26 bits of each FoleageF4x243.
		for (size_t j = 0; j < mC; j++)
		{
			for (size_t k = 0; k < mC; k++)
			{
				size_t poly_index = (j * mC + k);

				oc::MatrixView<FoleageF4x243> poly(blocks.data(poly_index * mT), mT, mDpfTreeSize);

				for (u64 block_idx = 0, i = 0; block_idx < mT; ++block_idx)
				{
					for (u64 packed_idx = 0; packed_idx < mDpfTreeSize; ++packed_idx)
					{
						auto coeff = extractF4(poly(block_idx, packed_idx));
						auto e = std::min<u64>(mBlockSize - packed_idx * mDpfLeafSize, mDpfLeafSize);

						//for (u64 element_idx = 0; element_idx < e; ++element_idx, ++i)
						//{
						//	*BitIterator(&fft[i], 2 * poly_index) = coeff[element_idx] & 1;
						//	*BitIterator(&fft[i], 2 * poly_index + 1) = (coeff[element_idx] >> 1) & 1;
						//}
						if (poly_index < 32)
						{
							for (u64 element_idx = 0; element_idx < e; ++element_idx, ++i)
							{
								fft[i] |= block{ coeff[element_idx] }.slli_epi64(2 * poly_index);
							}
						}
						else
						{
							for (u64 element_idx = 0; element_idx < e; ++element_idx, ++i)
							{
								fft[i] |= block{ coeff[element_idx], 0 }.slli_epi64(2 * poly_index - 64);
							}
						}
					}
				}
			}
		}
		setTimePoint("transpose");

		foleageFft<block>(fft, mLog3N, mN / 3);
		setTimePoint("product fft");
		F4Multiply(mFftASquared, fft, fftRes, mN);
		setTimePoint("product mult");


		if (CMsb.size())
		{

			// XOR the (packed) columns into the accumulator.
			// Specifically, we perform column-wise XORs to get the result.
			block lsbMask, msbMask;
			setBytes(lsbMask, 0b01010101);
			setBytes(msbMask, 0b10101010);
			for (size_t i = 0; i < outSize; i++)
			{
				*BitIterator(CLsb.data(), i) = popcount(fftRes[i] & lsbMask) & 1;
				*BitIterator(CMsb.data(), i) = popcount(fftRes[i] & msbMask) & 1;
			}
		}
		else
		{
			// XOR the (packed) columns into the accumulator.
			// Specifically, we perform column-wise XORs to get the result.
			block lsbMask;
			setBytes(lsbMask, 0b01010101);
			for (size_t i = 0; i < outSize; i++)
			{
				*BitIterator(CLsb.data(), i) = popcount(fftRes[i] & lsbMask) & 1;
			}
		}


		setTimePoint("addCopyY");

	}


	macoro::task<> FoleageTriple::expand(
		span<block> X,
		span<block> Z,
		PRNG& prng,
		coproto::Socket& sock)
	{
		if (!isInitialized())
			throw std::runtime_error("FoleageTriple::init must be called first. " LOCATION);
		if (mMode != FoleageMode::F2TraceOle)
			throw std::runtime_error("Foleage trace expansion requires F2TraceOle mode");

		setTimePoint("trace expand start");

		if (divCeil(2 * mN, 128) < X.size())
			throw RTE_LOC;
		if (X.size() != Z.size())
			throw RTE_LOC;

		if (!hasBaseOts())
			co_await genBaseOts(prng, sock);
		if (!mBaseOtsAvailable)
			throw std::runtime_error("FoleageTriple requires a fresh base-OT set");

		mBaseOtsAvailable = false;
		struct ClearBaseOtsOnExit
		{
			FoleageTriple* mThis;
			~ClearBaseOtsOnExit() { mThis->clearBaseOts(); }
		} clearBaseOtsOnExit{ this };

		mSparsePositions.resize(mC, mT);
		Matrix<u16> sparseCoefficients(mC, mT);
		const auto productCount = mC * mC * mT * mT;
		std::vector<u16> tensoredCoefficients(productCount);
		std::vector<u16> tensoredFrobenius(productCount);

		co_await tensorTrace(
			sparseCoefficients,
			tensoredCoefficients,
			tensoredFrobenius,
			sock);

		// The LPN construction tolerates the small modulo-reduction bias. Exact
		// uniformity is unnecessary, and these parameters retain 30--40 bits of
		// statistical security from the position sampling step.
		for (u64 i = 0; i < mSparsePositions.size(); ++i)
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;

		std::vector<u16> fftSparsePoly(mN);
		for (u64 i = 0; i < mT; ++i)
		{
			for (u64 j = 0; j < mC; ++j)
			{
				auto pos = i * mBlockSize + mSparsePositions(j, i);
				fftSparsePoly[pos] |= sparseCoefficients(j, i) << (2 * j);
			}
		}

		setTimePoint("trace sparsePolySample");
		foleageFft<u16>(fftSparsePoly, mLog3N, mN / 3);
		setTimePoint("trace input fft");
		F4Multiply(mFftA, fftSparsePoly, fftSparsePoly, mN);
		setTimePoint("trace input mult");

		const auto outSize = std::min<u64>(mN, X.size() * 64);
		constexpr u16 msbMask = 0b1010101010101010;
		constexpr u16 lsbMask = 0b0101010101010101;
		auto xIter = BitIterator(X.data());
		for (u64 i = 0; i < outSize; ++i)
		{
			const auto l = popcount<u16>(fftSparsePoly[i] & lsbMask) & 1;
			const auto h = popcount<u16>(fftSparsePoly[i] & msbMask) & 1;
			*xIter++ = h;
			*xIter++ = l ^ h;
		}
		setTimePoint("trace copyOutX");

		const auto tracePointCount = 2 * productCount;
		std::vector<u8> prodPolyF4Coeffs(tracePointCount);
		std::vector<F3x32> prodPolyLeafPos(tracePointCount);
		std::vector<F3x32> prodPolyTreePos(tracePointCount);

		for (u64 lane = 0; lane < 2; ++lane)
		{
			// Lane 0 expands X_0 X_1 at p_0+p_1. Lane 1 expands
			// X_0 X_1^2 at p_0+2p_1; multiplication by 2 in Z_3 is negation.
			const auto laneOffset = lane * productCount;
			const auto& coefficients = lane ? tensoredFrobenius : tensoredCoefficients;
			for (u64 iA = 0, polyOffset = 0; iA < mC; ++iA)
			{
				std::array<u8, 128> nextIdx;
				for (u64 iB = 0; iB < mC; ++iB, polyOffset += mT * mT)
				{
					std::fill_n(nextIdx.data(), mT, 0);
					for (u64 jA = 0; jA < mT; ++jA)
					{
						for (u64 jB = 0; jB < mT; ++jB)
						{
							const u64 i = mPartyIdx ? iB : iA;
							const u64 j = mPartyIdx ? jB : jA;
							const auto blockPos = lane ?
								F3x32(jA) + (-F3x32(jB)) :
								F3x32(jA) + F3x32(jB);
							const auto blockIdx = blockPos.toInt();
							const auto idx = laneOffset + polyOffset +
								blockIdx * mT + nextIdx[blockIdx]++;

							auto pos = F3x32(mSparsePositions(i, j));
							if (lane && mPartyIdx)
								pos = -pos;
							prodPolyLeafPos[idx] = pos.lower(mDpfLeafDepth);
							prodPolyTreePos[idx] = pos.upper(mDpfLeafDepth);

							const auto coeffIdx = (iA * mT + jA) * mC * mT +
								iB * mT + jB;
							prodPolyF4Coeffs[idx] = coefficients[coeffIdx];
						}
					}

					for (u64 i = 0; i < mT; ++i)
					{
						if (nextIdx[i] != mT)
							throw RTE_LOC;
					}
				}
			}
		}

		setTimePoint("trace dpfParams");

		std::vector<FoleageF4x243> prodPolyF4x243Coeffs(tracePointCount);
		co_await mDpfLeaf.expand(prodPolyLeafPos, prodPolyF4Coeffs,
			[&, byteIdx = 0ull, bitIdx = 0ull]
			(u64 treeIdx, u64 leafIdx, u8 v) mutable {
				if (treeIdx == 0)
				{
					byteIdx = leafIdx / 4;
					bitIdx = leafIdx % 4;
				}
				assert(byteIdx == leafIdx / 4);
				assert(bitIdx == leafIdx % 4);
				auto ptr = reinterpret_cast<u8*>(
					&prodPolyF4x243Coeffs[treeIdx]);
				ptr[byteIdx] |= u8((v & 3) << (2 * bitIdx));
			}, prng, sock);

		setTimePoint("trace leafDpf");

		Matrix<FoleageF4x243> blocks(2 * mC * mC * mT, mDpfTreeSize);
		co_await mDpf.expand(prodPolyTreePos, prodPolyF4x243Coeffs,
			[&, count = 0ull, out = blocks.data(), end = blocks.data() + blocks.size()]
			(u64 treeIdx, u64 leafIdx, FoleageF4x243 v) mutable {
				assert(out == &blocks(treeIdx / mT, leafIdx));
				*out ^= v;
				if (++count == mT)
				{
					count = 0;
					out += blocks.cols();
					if (out >= end)
						out -= blocks.size() - 1;
				}
			}, prng, sock);

		setTimePoint("trace mainDpf");

		std::vector<block> fft(mN), fftRes(mN);
		block packedLsbMask, packedMsbMask;
		setBytes(packedLsbMask, 0b01010101);
		setBytes(packedMsbMask, 0b10101010);

		for (u64 lane = 0; lane < 2; ++lane)
		{
			if (lane)
				setBytes(fft, 0);

			const auto rowOffset = lane * mC * mC * mT;
			for (size_t j = 0; j < mC; ++j)
			{
				for (size_t k = 0; k < mC; ++k)
				{
					const size_t polyIndex = j * mC + k;
					MatrixView<FoleageF4x243> poly(
						blocks.data(rowOffset + polyIndex * mT),
						mT,
						mDpfTreeSize);

					for (u64 blockIdx = 0, i = 0; blockIdx < mT; ++blockIdx)
					{
						for (u64 packedIdx = 0; packedIdx < mDpfTreeSize; ++packedIdx)
						{
							auto coeff = extractF4(poly(blockIdx, packedIdx));
							const auto e = std::min<u64>(
								mBlockSize - packedIdx * mDpfLeafSize,
								mDpfLeafSize);

							if (polyIndex < 32)
							{
								for (u64 elementIdx = 0; elementIdx < e; ++elementIdx, ++i)
									fft[i] |= block{ coeff[elementIdx] }.slli_epi64(2 * polyIndex);
							}
							else
							{
								for (u64 elementIdx = 0; elementIdx < e; ++elementIdx, ++i)
									fft[i] |= block{ coeff[elementIdx], 0 }.slli_epi64(2 * polyIndex - 64);
							}
						}
					}
				}
			}

			setTimePoint(lane ? "trace transpose frobenius" : "trace transpose product");
			foleageFft<block>(fft, mLog3N, mN / 3);
			setTimePoint(lane ? "trace fft frobenius" : "trace fft product");
			F4Multiply(
				lane ? span<block>(mFftAFrobenius) : span<block>(mFftASquared),
				fft,
				fftRes,
				mN);
			setTimePoint(lane ? "trace mult frobenius" : "trace mult product");

			auto zIter = BitIterator(Z.data());
			for (u64 i = 0; i < outSize; ++i)
			{
				const auto h = popcount(fftRes[i] & packedMsbMask) & 1;
				if (!lane)
				{
					// For R0=X0*X1 and R1=X0*X1^2:
					// Tr(X0)Tr(X1) = msb(R0) + msb(R1), and
					// Tr(xi*X0)Tr(xi*X1) = lsb(R0) + msb(R1).
					*zIter++ = h;
					*zIter++ = popcount(fftRes[i] & packedLsbMask) & 1;
				}
				else
				{
					*zIter++ ^= h;
					*zIter++ ^= h;
				}
			}
		}

		setTimePoint("trace addCopyY");
	}


	macoro::task<> FoleageTriple::tensor(
		span<u16> coeffs,
		span<u16> prod,
		coproto::Socket& sock)
	{
		return tensorImpl<false>(coeffs, prod, {}, sock);
	}

	macoro::task<> FoleageTriple::tensorTrace(
		span<u16> coeffs,
		span<u16> prod,
		span<u16> prodFrobenius,
		coproto::Socket& sock)
	{
		return tensorImpl<true>(coeffs, prod, prodFrobenius, sock);
	}

	template<bool Trace>
	macoro::task<> FoleageTriple::tensorImpl(
		span<u16> coeffs,
		span<u16> prod,
		span<u16> prodFrobenius,
		coproto::Socket& sock)
	{
		if (!coeffs.size() || coeffs.size() > 128)
			throw std::invalid_argument("FoleageTriple tensor supports 1 to 128 coefficients");
		if (prod.size() != coeffs.size() * coeffs.size())
			throw std::invalid_argument("FoleageTriple tensor product has the wrong size");
		if constexpr (Trace)
		{
			if (prodFrobenius.size() != prod.size())
				throw std::invalid_argument("FoleageTriple Frobenius tensor product has the wrong size");
		}

		auto expand = [](block k, span<block> diff) {
			AES aes(k);
			for (u64 i = 0; i < diff.size(); ++i)
				diff[i] = aes.ecbEncBlock(block(i));
			};

		if (divCeil(coeffs.size(), 128) != 1)
			throw RTE_LOC; // not impl
		auto size = 2 * divCeil(coeffs.size(), 128);


		if (mPartyIdx)
		{
			if (mSendOts.size() < 2 * coeffs.size())
				throw RTE_LOC; //base ots not set.
			// b * a = (b0 * a +  b1 * (2 * a))
			//auto getDiff = [](block k0, block k1, span<block> diff) {
			//		AES aes0(k0);
			//		AES aes1(k1);
			//		for (u64 i = 0; i < diff.size(); ++i)
			//			diff[i] = aes0.ecbEncBlock(block(i)) ^ aes1.ecbEncBlock(block(i) * 2);
			//	};
			std::array<std::vector<block>, 2> a; a[0].resize(size), a[1].resize(size);
			std::vector<block> t0(size), t1(size);
			expand(mSendOts[0][0], t0);
			expand(mSendOts[0][1], t1);
			for (u64 i = 0; i < size; ++i)
				a[0][i] = t0[i] ^ t1[i];

			// a[1] = 2 * a[0]
			F4Multiply(a[0][0], a[0][1], ZeroBlock, AllOneBlock, a[1][0], a[1][1]);

			{
				auto lsbIter = BitIterator(&a[0][0]);
				auto msbIter = BitIterator(&a[0][1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
					coeffs[i] = (*lsbIter++ & 1) | ((*msbIter++ & 1) << 1);
			}

			{
				setBytes(prod, 0);
				if constexpr (Trace)
					setBytes(prodFrobenius, 0);
				auto prodIter = prod.begin();
				u16* frobeniusIter = nullptr;
				if constexpr (Trace)
					frobeniusIter = prodFrobenius.data();
				auto lsbIter = BitIterator(&t0[0]);
				auto msbIter = BitIterator(&t0[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
				{
					auto v = (*lsbIter++) | (u8(*msbIter++) << 1);
					*prodIter++ = v;
					if constexpr (Trace)
						*frobeniusIter++ = tensorFrobenius(v, false);
				}
			}


			std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
			auto buffIter = buffer.begin();
			for (u64 i = 1; i < 2 * coeffs.size(); ++i)
			{
				auto b = i & 1;
				auto idx = i / 2;
				auto prodIter = prod.begin() + idx * coeffs.size();
				u16* frobeniusIter = nullptr;
				if constexpr (Trace)
					frobeniusIter = prodFrobenius.data() + idx * coeffs.size();

				expand(mSendOts[i][0], t0);
				expand(mSendOts[i][1], t1);

				// prod  = mask
				auto lsbIter = BitIterator(&t0[0]);
				auto msbIter = BitIterator(&t0[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
				{
					auto v = (*lsbIter++) | (u8(*msbIter++) << 1);
					*prodIter++ ^= v;
					if constexpr (Trace)
						*frobeniusIter++ ^= tensorFrobenius(v, b != 0);
				}

				for (u64 i = 0; i < a.size(); ++i)
				{   //        mask    key     value
					*buffIter++ = t0[i] ^ t1[i] ^ a[b][i];
					//*buffIter++ = diff[i];
				}

			}

			co_await sock.send(std::move(buffer));
		}
		else
		{

			if (mChoiceOts.size() < 2 * coeffs.size())
				throw RTE_LOC; //base ots not set.
			if (mRecvOts.size() < 2 * coeffs.size())
				throw RTE_LOC; //base ots not set.

			for (u64 i = 0; i < coeffs.size(); ++i)
				coeffs[i] = mChoiceOts[2 * i] | (u8(mChoiceOts[2 * i + 1] << 1));
			std::vector<block> t(size);
			expand(mRecvOts[0], t);

			{
				setBytes(prod, 0);
				if constexpr (Trace)
					setBytes(prodFrobenius, 0);
				auto prodIter = prod.begin();
				u16* frobeniusIter = nullptr;
				if constexpr (Trace)
					frobeniusIter = prodFrobenius.data();
				auto lsbIter = BitIterator(&t[0]);
				auto msbIter = BitIterator(&t[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
				{
					auto v = (*lsbIter++) | (u8(*msbIter++) << 1);
					*prodIter++ = v;
					if constexpr (Trace)
						*frobeniusIter++ = tensorFrobenius(v, false);
				}
			}

			std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
			co_await sock.recv(buffer);

			auto buffIter = buffer.begin();
			for (u64 i = 1; i < 2 * coeffs.size(); ++i)
			{
				auto idx = i / 2;
				auto xiLane = (i & 1) != 0;
				auto prodIter = prod.begin() + idx * coeffs.size();
				u16* frobeniusIter = nullptr;
				if constexpr (Trace)
					frobeniusIter = prodFrobenius.data() + idx * coeffs.size();

				expand(mRecvOts[i], t);
				if (mChoiceOts[i])
				{
					for (u64 i = 0; i < size; ++i)
					{
						t[i] = t[i] ^ *buffIter++;
					}
				}
				else
					buffIter += size;

				// prod  = mask
				auto lsbIter = BitIterator(&t[0]);
				auto msbIter = BitIterator(&t[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
				{
					auto v = (*lsbIter++) | (u8(*msbIter++) << 1);
					*prodIter++ ^= v;
					if constexpr (Trace)
						*frobeniusIter++ ^= tensorFrobenius(v, xiLane);
				}
			}
		}
	}

	//macoro::task<> FoleageTriple::checkTensor(span<u8> coeffs, span<u8> tensoredCoefficients, coproto::Socket& sock)
	//{
	//	std::array<std::vector<u8>, 2> pCoeffs;// (coeffs.size());
	//	pCoeffs[mPartyIdx] = std::vector<u8>(coeffs.begin(), coeffs.end());
	//	pCoeffs[1 - mPartyIdx].resize(coeffs.size());

	//	Matrix<u8> pProd(coeffs.size(), coeffs.size());

	//	co_await sock.send(coproto::copy(pCoeffs[mPartyIdx]));
	//	co_await sock.send(coproto::copy(tensoredCoefficients));
	//	co_await sock.recv(pCoeffs[1 - mPartyIdx]);
	//	co_await sock.recv(pProd);

	//	for (u64 i = 0; i < pProd.size(); ++i)
	//	{
	//		pProd(i) ^= tensoredCoefficients[i];
	//	}

	//	for (u64 i = 0; i < coeffs.size(); ++i)
	//	{
	//		auto scaler = pCoeffs[0][i];
	//		for (u64 j = 0; j < coeffs.size(); ++j)
	//		{
	//			u8 exp = F4Multiply(scaler, pCoeffs[1][j]);
	//			auto prod = pProd(i, j);
	//			if (prod != exp)
	//			{
	//				std::cout << "tensor check failed " << i << " " << j << " exp " << int(exp) << " act " << int(prod) << std::endl;
	//				throw RTE_LOC;
	//			}
	//		}
	//	}

	//}

}
#endif
