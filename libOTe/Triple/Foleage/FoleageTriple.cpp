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


	void FoleageTriple::init(u64 partyIdx, u64 n)
	{
		mPartyIdx = partyIdx;
		mLog3N = log3ceil(n);
		mLog3T = log3ceil(mT);
		mN = ipow(3, mLog3N);

		if (mT != ipow(3, mLog3T))
			throw RTE_LOC;

		mBlockSize = mN / mT;
		mBlockDepth = mLog3N - mLog3T;
		mDpfLeafDepth = std::min<u64>(5, mBlockDepth);
		mDpfTreeDepth = mBlockDepth - mDpfLeafDepth;

		mDpfLeafSize = ipow(3, mDpfLeafDepth);
		mDpfTreeSize = ipow(3, mDpfTreeDepth);

		mDpfLeaf.init(mPartyIdx, mDpfLeafSize, mC * mC * mT * mT);
		mDpf.init(mPartyIdx, mDpfTreeSize, mC * mC * mT * mT);

		if (mBlockSize < 2)
			throw RTE_LOC;

		sampleA(block(3127894527893612049, 240925987420932408));
	}


	FoleageTriple::BaseCount FoleageTriple::baseOtCount() const
	{
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
		mSendOts.insert(mSendOts.end(), sendOts.begin(), sendOts.end());
		mRecvOts.insert(mRecvOts.end(), recvOts.begin(), recvOts.end());
		mChoiceOts = BitVector(baseChoices.data(), baseChoices.size() - offset, offset);
	}

	bool FoleageTriple::hasBaseOts() const
	{
		return mSendOts.size() + mRecvOts.size() > 0;
	}

	macoro::task<> FoleageTriple::genBaseOts(
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


	void FoleageTriple::sampleA(block seed)
	{

		if (mC > 8)
			throw RTE_LOC;

		PRNG prng(seed);
		mFftA.resize(mN);
		mFftASquared.resize(0);
		mFftASquared.resize(mN);
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
	}




	macoro::task<> FoleageTriple::expand(
		span<block> ALsb,
		span<block> AMsb,
		span<block> CLsb,
		span<block> CMsb,
		PRNG& prng,
		coproto::Socket& sock)
	{
		setTimePoint("expand start");

		if (hasBaseOts() == false)
		{
			co_await genBaseOts(prng, sock);
		}

		if (divCeil(mN, 128) < ALsb.size())
			throw RTE_LOC;
		if (ALsb.size() != AMsb.size() ||
			ALsb.size() != CLsb.size())
			throw RTE_LOC;
		if (ALsb.size() != CMsb.size() && CMsb.size())
			throw RTE_LOC;

		// the coefficient of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
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

		// compress the resume and set the output.
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

		// sharing of the F4 coefficients of the product polynomails.
		// these will just be the tensored coefficients but in permuted
		// order to match how they are expended in the DPF and then added 
		// together.
		std::vector<uint8_t> prodPolyF4Coeffs(mC * mC * mT * mT);

		// We are doing to use "early termination" on the main DPF. To do
		// this we are going to construct new F4^243 coefficients where
		// each prodPolyF4Coeffs is positioned at prodPolyLeafPos. This
		// will allow the main DPF to be more efficient as we are outputting
		// 243 F4 elements for each leaf.
		std::vector<F3x32> prodPolyLeafPos(mC * mC * mT * mT);

		// once we construct large F4^243 coefficients, we will expand them
		// the main DPF to get the full shared polynomail. prodPolyTreePos
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

		// sharing of the F4^243 coefficients of the product polynomails.
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
								fft[i] |= 
									block{ coeff[element_idx], 0 }.slli_epi64(2 * poly_index - 64);
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


	macoro::task<> FoleageTriple::tensor(span<u16> coeffs, span<u16> prod, coproto::Socket& sock)
	{
		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;

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
			if (mSendOts.size() < 2 * coeffs.size() - 1)
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
				auto prodIter = prod.begin();
				auto lsbIter = BitIterator(&t0[0]);
				auto msbIter = BitIterator(&t0[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
					*prodIter++ = (*lsbIter++) | (u8(*msbIter++) << 1);
			}


			std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
			auto buffIter = buffer.begin();
			for (u64 i = 1; i < 2 * coeffs.size(); ++i)
			{
				auto b = i & 1;
				auto idx = i / 2;
				auto prodIter = prod.begin() + idx * coeffs.size();

				expand(mSendOts[i][0], t0);
				expand(mSendOts[i][1], t1);

				// prod  = mask
				auto lsbIter = BitIterator(&t0[0]);
				auto msbIter = BitIterator(&t0[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
					*prodIter++ ^= (*lsbIter++) | (u8(*msbIter++) << 1);

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

			if (mChoiceOts.size() < 2 * coeffs.size() - 1)
				throw RTE_LOC; //base ots not set.
			if (mRecvOts.size() < 2 * coeffs.size() - 1)
				throw RTE_LOC; //base ots not set.

			for (u64 i = 0; i < coeffs.size(); ++i)
				coeffs[i] = mChoiceOts[2 * i] | (u8(mChoiceOts[2 * i + 1] << 1));
			std::vector<block> t(size);
			expand(mRecvOts[0], t);

			{
				setBytes(prod, 0);
				auto prodIter = prod.begin();
				auto lsbIter = BitIterator(&t[0]);
				auto msbIter = BitIterator(&t[1]);
				for (u64 i = 0; i < coeffs.size(); ++i)
					*prodIter++ = (*lsbIter++) | (u8(*msbIter++) << 1);
			}

			std::vector<block>  buffer((2 * coeffs.size() - 1) * size);
			co_await sock.recv(buffer);

			auto buffIter = buffer.begin();
			for (u64 i = 1; i < 2 * coeffs.size(); ++i)
			{
				auto idx = i / 2;
				auto prodIter = prod.begin() + idx * coeffs.size();

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
					*prodIter++ ^= (*lsbIter++) | (u8(*msbIter++) << 1);
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
