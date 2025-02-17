#include "FoleagePcg.h"
#include "libOTe/Tools/Foleage/FoleageUtils.h"
#include "libOTe/Tools/Foleage/F4Ops.h"
#include "libOTe/Tools/Foleage/fft/FoleageFft.h"
#include "cryptoTools/Common/BitIterator.h"
#include "libOTe/Tools/Foleage/tri-dpf/FoleageDpf.h"
#include "libOTe/Tools/Foleage/tri-dpf/FoleagePrf.h"
#include "libOTe/Tools/Dpf/TriDpf.h"
namespace osuCrypto
{


	void FoleageF4Ole::init(u64 partyIdx, u64 n, PRNG& prng)
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

		_mDpfDomainDepth = std::max<u64>(1, log3ceil(divCeil(mBlockSize, 256)));
		_mDpfBlockSize = 4 * ipow(3, _mDpfDomainDepth);


		mDpfLeaf.init(mPartyIdx, mDpfLeafSize, mC * mC * mT * mT);
		mDpf.init(mPartyIdx, mDpfTreeSize, mC * mC * mT * mT);

		if (mBlockSize < 2)
			throw RTE_LOC;

		sampleA(block(431234234, 213434234123));
	}


	void FoleageF4Ole::sampleA(block seed)
	{

		if (mC > 4)
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


		// FOR DEBUGGING: set fft_a to the identity
		// for (size_t i = 0; i < mN; i++)
		// {
		//     mFftA[i] = (0xaaaa >> 1);
		// }
		uint32_t prod;
		for (size_t i = 0; i < mN; i++)
		{
			mFftASquared[i] = 0;
			for (size_t j = 0; j < mC; j++)
			{
				for (size_t k = 0; k < mC; k++)
				{
					auto a = (mFftA[i] >> (2 * j)) & 0b11;
					auto b = (mFftA[i] >> (2 * k)) & 0b11;
					auto a1 = a & 1;
					auto a2 = a & 2;
					auto b1 = b & 1;
					auto b2 = b & 2;

					{
						u8 tmp = (a2 & b2);
						prod = tmp ^ ((a2 & (b1 << 1)) ^ ((a1 << 1) & b2));
						prod |= (a1 & b1) ^ (tmp >> 1);
						//return res;
					}
					//prod = mult_f4(, );
					size_t slot = j * mC + k;
					mFftASquared[i] |= prod << (2 * slot);
				}
			}
		}

		//{
		//	std::vector<uint8_t> fft_a(mN);
		//	std::vector<uint32_t> fft_a2(mN);
		//	PRNG APrng(block(431234234, 213434234123));
		//	sample_a_and_a2(fft_a, fft_a2, mN, mC, APrng);

		//	for (u64 i = 0; i < mN; ++i)
		//	{
		//		if (fft_a[i] != mFftA[i])
		//			throw RTE_LOC;
		//		if (fft_a2[i] != mFftASquared[i])
		//			throw RTE_LOC;
		//	}

		//}
	}


	macoro::task<> FoleageF4Ole::expand(
		span<block> ALsb,
		span<block> AMsb,
		span<block> CLsb,
		span<block> CMsb,
		PRNG& prng,
		coproto::Socket& sock)
	{
		bool oldDpf = false;

		setTimePoint("expand start");

		if (divCeil(mN, 128) < ALsb.size())
			throw RTE_LOC;
		if (ALsb.size() != AMsb.size() || ALsb.size() != CLsb.size() || ALsb.size() != CMsb.size())
			throw RTE_LOC;

		mSparseCoefficients.resize(mC, mT);
		mSparsePositions.resize(mC, mT);

		std::vector<u8> tensoredCoefficients(mC * mC * mT * mT);
		co_await tensor(mSparseCoefficients, tensoredCoefficients, sock);

		for (u64 i = 0; i < mC * mT; ++i)
		{
			//while (mSparseCoefficients(i) == 0)
			//	mSparseCoefficients(i) = prng.get<u8>() & 3;
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;
		}

		if (mC != 4)
			throw RTE_LOC;

		// we pack 4 FFTs into a single u8. 
		std::vector<u8> fftSparsePoly(mN);
		for (u64 i = 0; i < mT; ++i)
		{
			for (u64 j = 0; j < mC; ++j)
			{
				auto pos = i * mBlockSize + mSparsePositions(j, i);
				fftSparsePoly[pos] |= mSparseCoefficients(j, i) << (2 * j);
			}
		}

		setTimePoint("sparsePolySample");

		// switch from polynomial to FFT form
		fft_recursive_uint8(fftSparsePoly, mLog3N, mN / 3);

		// multiply by the packed A polynomial
		multiply_fft_8(mFftA, fftSparsePoly, fftSparsePoly, mN);

		setTimePoint("sparsePolyMul");


		// compress the resume and set the output.
		auto outSize = std::min(mN, ALsb.size() * 128);
		std::vector<u8> A(mN);
		for (u64 i = 0; i < outSize; ++i)
		{
			auto a =
				((fftSparsePoly[i] >> 0) ^
					(fftSparsePoly[i] >> 2) ^
					(fftSparsePoly[i] >> 4) ^
					(fftSparsePoly[i] >> 6)) & 3;

			*BitIterator(ALsb.data(), i) = a & 1;
			*BitIterator(AMsb.data(), i) = (a >> 1) & 1;

			A[i] = a;
		}
		setTimePoint("copyOutX");

		std::vector<uint8_t> prodPolyCoefficientShare(mC * mC * mT * mT);
		std::vector<block512> prodPolyCoefficient3(mC * mC * mT * mT);
		std::vector<Trit32> prodPolyLeafPos(mC * mC * mT * mT);
		std::vector<Trit32> prodPolyTreePos(mC * mC * mT * mT);

		setTimePoint("sendRecv");


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

						auto pos = Trit32(mSparsePositions(i, j));
						auto blockPos = Trit32(jA) + Trit32(jB);
						auto blockIdx = blockPos.toInt();
						size_t idx = polyOffset + blockIdx * mT + nextIdx[blockIdx]++;
						prodPolyLeafPos[idx] = pos.lower(mDpfLeafDepth);
						prodPolyTreePos[idx] = pos.upper(mDpfLeafDepth);


						auto coeffIdx = (iA * mT + jA) * mC * mT + iB * mT + jB;

						prodPolyCoefficientShare[idx] = tensoredCoefficients[coeffIdx];
					}
				}

				if (nextIdx != std::vector<uint8_t>(mT, mT))
					throw RTE_LOC;
			}
		}

		setTimePoint("sparseProductCompute");


		std::vector<u32> fft(mN), fftRes(mN);
		Matrix<block512> blocks512(mC * mC * mT, mDpfTreeSize);

		//{
		//	auto numOTs = mDpfLeaf.baseOtCount();
		//	std::vector<block> baseRecvOts(numOTs);
		//	std::vector<std::array<block, 2>> baseSendOts(numOTs);
		//	BitVector baseChoices(numOTs);
		//	PRNG basePrng(block(324234, 234234));
		//	basePrng.get(baseSendOts.data(), baseSendOts.size());
		//	baseChoices.randomize(basePrng);
		//	for (u64 i = 0; i < numOTs; ++i)
		//		baseRecvOts[i] = baseSendOts[i][baseChoices[i]];
		//	mDpfLeaf.setBaseOts(baseSendOts, baseRecvOts, baseChoices);
		//}

		co_await mDpfLeaf.expand(prodPolyLeafPos, prodPolyCoefficientShare, [&](u64 treeIdx, u64 leafIdx, u8 v) {
			*BitIterator(&prodPolyCoefficient3[treeIdx], leafIdx * 2 + 0) = (v >> 0) & 1;
			*BitIterator(&prodPolyCoefficient3[treeIdx], leafIdx * 2 + 1) = (v >> 1) & 1;
			}, prng, sock);


		//{
		//	auto numOTs = mDpf.baseOtCount();
		//	std::vector<block> baseRecvOts(numOTs);
		//	std::vector<std::array<block, 2>> baseSendOts(numOTs);
		//	BitVector baseChoices(numOTs);
		//	PRNG basePrng(block(324234, 234234));
		//	basePrng.get(baseSendOts.data(), baseSendOts.size());
		//	baseChoices.randomize(basePrng);
		//	for (u64 i = 0; i < numOTs; ++i)
		//		baseRecvOts[i] = baseSendOts[i][baseChoices[i]];
		//	mDpf.setBaseOts(baseSendOts, baseRecvOts, baseChoices);
		//}

		co_await mDpf.expand(prodPolyTreePos, prodPolyCoefficient3, [&](u64 treeIdx, u64 leafIdx, block512 v) {
			auto row = treeIdx / mT;
			blocks512(row, leafIdx) ^= v;
			}, prng, sock);

		for (size_t j = 0; j < mC; j++)
		{
			for (size_t k = 0; k < mC; k++)
			{
				size_t poly_index = (j * mC + k);

				oc::MatrixView<block512> poly(blocks512.data(poly_index * mT), mT, mDpfTreeSize);

				u64 i = 0;
				for (u64 block_idx = 0; block_idx < mT; ++block_idx)
				{
					for (u64 packed_idx = 0; packed_idx < mDpfTreeSize; ++packed_idx)
					{
						auto coeff = extractF4(poly(block_idx, packed_idx));
						auto e = std::min<u64>(mBlockSize - packed_idx * mDpfLeafSize, mDpfLeafSize);

						for (u64 element_idx = 0; element_idx < e; ++element_idx)
						{
							fft[i] |= u32{ coeff[element_idx] } << (2 * poly_index);
							++i;
						}
					}
				}
			}
		}

		setTimePoint("dpfKeyEval");

		fft_recursive_uint32(fft, mLog3N, mN / 3);
		//std::cout << "Cfft " << hash(fft.data(), fft.size()) << std::endl;
		multiply_fft_32(mFftASquared, fft, fftRes, mN);

		//std::cout << "C " << hash(fftRes.data(), fftRes.size()) << std::endl;

		setTimePoint("fft");

		// XOR the (packed) columns into the accumulator.
		// Specifically, we perform column-wise XORs to get the result.
		uint128_t lsbMask, msbMask;
		setBytes(lsbMask, 0b01010101);
		setBytes(msbMask, 0b10101010);
		for (size_t i = 0; i < outSize; i++)
		{
			//auto resA = extractF4(res_poly_mat_A[i]);
			//auto resB = extractF4(res_poly_mat_B[i]);

			*BitIterator(CLsb.data(), i) = popcount(fftRes[i] & lsbMask) & 1;
			*BitIterator(CMsb.data(), i) = popcount(fftRes[i] & msbMask) & 1;
		}


		setTimePoint("addCopyY");

	}


	macoro::task<> FoleageF4Ole::tensor(span<u8> coeffs, span<u8> prod, coproto::Socket& sock)
	{
		//if (coeffs.size() != mC * mT)
		//	throw RTE_LOC;

		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;

		if (0)
		{
			PRNG prng(CCBlock);
			std::array<std::vector<u8>, 2> s;
			s[0].resize(coeffs.size());
			s[1].resize(coeffs.size());
			//prng.get(s0.data(), s0.size());
			for (u64 i = 0; i < s[0].size(); ++i)
			{
				s[0][i] = prng.get<u8>() % 4;
				s[1][i] = prng.get<u8>() % 4;
			}
			std::copy(s[mPartyIdx].begin(), s[mPartyIdx].end(), coeffs.begin());

			for (u64 iA = 0, pointIdx = 0; iA < s[0].size(); ++iA)
			{
				for (u64 iB = 0; iB < s[1].size(); ++iB, ++pointIdx)
				{
					prod[pointIdx] =
						(mult_f4(s[0][iA], s[1][iB]) * mPartyIdx);// ^
						//(prng.get<u8>() % 4);
				}
			}
		}
		else
		{

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
				f4Mult(a[0][0], a[0][1], ZeroBlock, AllOneBlock, a[1][0], a[1][1]);

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

	}
}