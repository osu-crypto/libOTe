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


	void FoleageF4Ole::init2(u64 partyIdx, u64 n, PRNG& prng)
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
		for (u64 i = 0; i < mC * mT; ++i)
		{
			while (mSparseCoefficients(i) == 0)
				mSparseCoefficients(i) = prng.get<u8>() & 3;
			mSparsePositions(i) = prng.get<u64>() % mBlockSize;
		}


		//std::cout << "pos " << hash(mSparsePositions.data(), mSparsePositions.size()) << std::endl;
		//std::cout << "coeff " << hash(mSparseCoefficients.data(), mSparseCoefficients.size()) << std::endl;


		if (mC != 4)
			throw RTE_LOC;

		// we pack 4 FFTs into a single u8. 
		std::vector<u8> fftSparsePoly(mN);
		//std::vector<u8> fftSparsePolyLsb(mN), fftSparsePolyMsb(mN);
		for (u64 i = 0; i < mT; ++i)
		{
			for (u64 j = 0; j < mC; ++j)
			{
				auto pos = i * mBlockSize + mSparsePositions(j, i);
				fftSparsePoly[pos] |= mSparseCoefficients(j, i) << (2 * j);

				//fftSparsePolyLsb[pos] |= (mSparseCoefficients(j, i) & 1) << j;
				//fftSparsePolyMsb[pos] |= ((mSparseCoefficients(j, i) >> 1) & 1) << j;
			}
		}

		setTimePoint("sparsePolySample");

		//std::cout << "sparse " << hash(fftSparsePoly.data(), fftSparsePoly.size()) << std::endl;

		// switch from polynomial to FFT form
		fft_recursive_uint8(fftSparsePoly, mLog3N, mN / 3);

		//foleageFFT2<1>(fftSparsePolyLsb, fftSparsePolyMsb);

		// multiply by the packed A polynomial
		multiply_fft_8(mFftA, fftSparsePoly, fftSparsePoly, mN);

		//std::cout << "mult " << hash(fftSparsePoly.data(), fftSparsePoly.size()) << std::endl;
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

		std::vector<u8> tensoredCoefficients(mC * mC * mT * mT);
		co_await tensor(mSparseCoefficients, tensoredCoefficients, sock);

		u64 polyOffset = 0;
		for (u64 iA = 0, pointIdx = 0; iA < mC; ++iA)
		{
			for (u64 iB = 0; iB < mC; ++iB)
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
						prodPolyCoefficientShare[idx] = tensoredCoefficients[pointIdx];
					}
				}

				if (nextIdx != std::vector<uint8_t>(mT, mT))
					throw RTE_LOC;

				polyOffset += mT * mT;
			}
		}

		setTimePoint("sparseProductCompute");


		std::vector<u32> fft(mN), fftRes(mN);
		Matrix<block512> blocks512(mC * mC * mT, mDpfTreeSize);

		{
			mDpfLeaf.init(mPartyIdx, mDpfLeafSize, prodPolyLeafPos.size());
			auto numOTs = mDpfLeaf.baseOtCount();
			std::vector<block> baseRecvOts(numOTs);
			std::vector<std::array<block, 2>> baseSendOts(numOTs);
			BitVector baseChoices(numOTs);
			PRNG basePrng(block(324234, 234234));
			basePrng.get(baseSendOts.data(), baseSendOts.size());
			baseChoices.randomize(basePrng);
			for (u64 i = 0; i < numOTs; ++i)
				baseRecvOts[i] = baseSendOts[i][baseChoices[i]];
			mDpfLeaf.setBaseOts(baseSendOts, baseRecvOts, baseChoices);
		}

		co_await mDpfLeaf.expand(prodPolyLeafPos, prodPolyCoefficientShare, [&](u64 treeIdx, u64 leafIdx, u8 v) {
			*BitIterator(&prodPolyCoefficient3[treeIdx], leafIdx * 2 + 0) = (v >> 0) & 1;
			*BitIterator(&prodPolyCoefficient3[treeIdx], leafIdx * 2 + 1) = (v >> 1) & 1;
			}, prng, sock);


		{
			mDpf.init(mPartyIdx, mDpfTreeSize, prodPolyLeafPos.size());
			auto numOTs = mDpf.baseOtCount();
			std::vector<block> baseRecvOts(numOTs);
			std::vector<std::array<block, 2>> baseSendOts(numOTs);
			BitVector baseChoices(numOTs);
			PRNG basePrng(block(324234, 234234));
			basePrng.get(baseSendOts.data(), baseSendOts.size());
			baseChoices.randomize(basePrng);
			for (u64 i = 0; i < numOTs; ++i)
				baseRecvOts[i] = baseSendOts[i][baseChoices[i]];
			mDpf.setBaseOts(baseSendOts, baseRecvOts, baseChoices);
		}

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
							//fft[i] |= u32{ coeff[63 - element_idx] } << (2 * poly_index);
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

	//macoro::task<> FoleageF4Ole::dpfEval(
	//	u64 domain,
	//	span<Trit32> points, 
	//	span<u8> coeffs, 
	//	MatrixView<uint128_t> output, 
	//	PRNG& prng, 
	//	coproto::Socket& sock)
	//{


	//	co_return;
	//}


	macoro::task<> FoleageF4Ole::tensor(span<u8> coeffs, span<u8> prod, coproto::Socket& sock)
	{
		if (coeffs.size() * coeffs.size() != prod.size())
			throw RTE_LOC;
		std::vector<u8> other(coeffs.size());
		co_await sock.send(coproto::copy(coeffs));
		co_await sock.recv(other);

		span<u8> A = coeffs, B = other;
		if (mPartyIdx)
			std::swap(A, B);

		for (u64 iA = 0, pointIdx = 0; iA < mC; ++iA)
		{
			for (u64 iB = 0; iB < mC; ++iB)
			{
				for (u64 jA = 0; jA < mT; ++jA)
				{
					for (u64 jB = 0; jB < mT; ++jB, ++pointIdx)
					{
						auto pos = iA * mT + jA;
						auto pos2 = iB * mT + jB;
						prod[pointIdx] =
							(mult_f4(A[pos], B[pos2]) * mPartyIdx) ^
							(pointIdx % 4);
					}
				}
			}
		}
	}

}