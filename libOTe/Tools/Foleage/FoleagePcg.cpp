#include "FoleagePcg.h"
#include "libOTe/Tools/Foleage/FoleageUtils.h"
#include "libOTe/Tools/Foleage/F4Ops.h"
#include "libOTe/Tools/Foleage/fft/FoleageFft.h"
#include "cryptoTools/Common/BitIterator.h"
#include "libOTe/Tools/Foleage/tri-dpf/FoleageDpf.h"
#include "libOTe/Tools/Foleage/tri-dpf/FoleagePrf.h"
namespace osuCrypto
{


	void FoleageF4Ole::init(u64 partyIdx, u64 n, PRNG& prng)
	{
		mPartyIdx = partyIdx;
		mLog3N = log3ceil(n);
		mN = ipow(3, mLog3N);

		if (mT != ipow(3, mLog3T))
			throw RTE_LOC;

		mDpfDomainDepth = std::max<u64>(1, log3ceil(divCeil(mN, mT * 256)));
		mDpfBlockSize = 4 * ipow(3, mDpfDomainDepth);

		mBlockSize = mN / mT;
		if (mBlockSize < 8)
			throw RTE_LOC;

		sampleA(block(431234234, 213434234123));


		//std::cout << "a " << hash(mFftA.data(), mFftA.size()) << std::endl;
		//std::cout << "a2 " << hash(mFftASquared.data(), mFftASquared.size()) << std::endl;


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
		//std::cout << "compress " << hash(fftSparsePoly.data(), fftSparsePoly.size()) << std::endl;


		std::vector<uint8_t> prodPolyCoefficient(mC * mC * mT * mT);
		std::vector<size_t> prodPolyPosition(mC * mC * mT * mT);

		std::vector<u8> tritABlk(mLog3T), tritBBlk(mLog3T), tritsBlk(mLog3T);
		std::vector<u8> tritAPos(mLog3N - mLog3T), tritBPos(mLog3N - mLog3T), tritsPos(mLog3N - mLog3T);

		Matrix<u8> otherSparseCoefficients(mC, mT);
		Matrix<u64> otherSparsePositions(mC, mT);
		co_await sock.send(coproto::copy(mSparseCoefficients));
		co_await sock.send(coproto::copy(mSparsePositions));
		co_await sock.recv(otherSparseCoefficients);
		co_await sock.recv(otherSparsePositions);
		setTimePoint("sendRecv");

		u64 polyOffset = 0;
		u8 vA, vB;
		for (u64 iA = 0; iA < mC; ++iA)
		{
			for (u64 iB = 0; iB < mC; ++iB)
			{
				std::vector<uint8_t> nextIdx(mT);

				for (u64 jA = 0; jA < mT; ++jA)
				{
					for (u64 jB = 0; jB < mT; ++jB)
					{
						int_to_trits(jA, tritABlk);
						int_to_trits(jB, tritBBlk);

						for (size_t k = 0; k < mLog3T; k++)
						{
							tritsBlk[k] = (tritABlk[k] + tritBBlk[k]) % 3;
						}
						u64 blockIdx = trits_to_int(tritsBlk);

						u64 posA_;
						u64 posB_;

						if (mPartyIdx == 0)
						{
							vA = mSparseCoefficients(iA, jA);
							vB = otherSparseCoefficients(iB, jB);
							posA_ = mSparsePositions(iA, jA);
							posB_ = otherSparsePositions(iB, jB);

						}
						else
						{
							vA = otherSparseCoefficients(iA, jA);
							vB = mSparseCoefficients(iB, jB);
							posA_ = otherSparsePositions(iA, jA);
							posB_ = mSparsePositions(iB, jB);
						}
						int_to_trits(posA_, tritAPos);
						int_to_trits(posB_, tritBPos);

						for(u64 k = 0; k < tritBPos.size(); ++k)
						{
							tritsPos[k] = (tritAPos[k] + tritBPos[k]) % 3;
						}

						auto subblock_pos = trits_to_int(tritsPos);
						
						size_t idx = polyOffset + blockIdx * mT + nextIdx[blockIdx]++;
						prodPolyCoefficient[idx] = mult_f4(vA, vB);
						prodPolyPosition[idx] = subblock_pos;
					}
				}

				if (nextIdx != std::vector<uint8_t>(mT, mT))
					throw RTE_LOC;

				polyOffset += mT * mT;
			}
		}

		setTimePoint("sparseProductCompute");

		std::vector<DPFKey> Dpfs(mC * mC * mT * mT);

		// Sample PRF keys for the DPFs
		PRFKeys prf_keys;
		PRNG prfSeedPrng(block(3412342134, 56453452362346));
		prf_keys.gen(prfSeedPrng);

		// Sample DPF keys for each of the t errors in the t blocks
		u64 index = 0;
		PRNG genPrng;

		//oc::RandomOracle dpfHash(16);

		for (u64 i = 0; i < mC; i++)
		{
			for (u64 j = 0; j < mC; j++)
			{
				for (u64 k = 0; k < mT; k++)
				{
					for (u64 l = 0; l < mT; l++, ++index)
					{
						//size_t index = i * c * t * t + j * t * t + k * t + l;

						// Parse the index into the right format
						size_t alpha = prodPolyPosition[index];

						// Output message index in the DPF output space
						// which consists of 256 F4 elements
						size_t alpha_0 = alpha / 256;

						// Coeff index in the block of 256 coefficients
						size_t alpha_1 = alpha % 256;

						// Coeff index in the uint128_t output (64 elements of F4)
						size_t packed_idx = alpha_1 / 64;

						// Bit index in the uint128_t ouput
						size_t bit_idx = alpha_1 % 64;

						// Set the DPF message to the coefficient
						uint128_t coeff = uint128_t(prodPolyCoefficient[index]);

						// Position coefficient into the block
						std::array<uint128_t, 4> beta; // init to zero
						setBytes(beta, 0);
						beta[packed_idx] = coeff << (2 * (63 - bit_idx));

						// Message (beta) is of size 4 blocks of 128 bits
						genPrng.SetSeed(block(index, 542345234));
						DPFKey _;
						if (mPartyIdx)
						{
							DPFGen(prf_keys, mDpfDomainDepth, alpha_0, beta, 4, _, Dpfs[index], genPrng);
						}
						else
						{
							DPFGen(prf_keys, mDpfDomainDepth, alpha_0, beta, 4, Dpfs[index], _, genPrng);
						}

						//dpfHash.Update(Dpfs[index].k.data(), Dpfs[index].k.size());
						//dpfHash.Update(Dpfs[index].msg_len);
						//dpfHash.Update(Dpfs[index].size);

					}
				}
			}
		}
		setTimePoint("dpfKeyGen");

		//block dpfHashVal;
		//dpfHash.Final(dpfHashVal);
		//std::cout << "dpf " << dpfHashVal << std::endl;

		std::vector<uint128_t> shares(mDpfBlockSize);
		std::vector<uint128_t> cache(mDpfBlockSize);

		size_t packedBlockSize = divCeil(mBlockSize, 64);
		Matrix<uint128_t> blocks(mC * mC * mT, packedBlockSize);

		std::vector<u32> fft(mN), fftRes(mN);

		auto dpfIter = Dpfs.begin();
		//auto dpf_keys_B_iter = dpf_keys_B.begin();

		for (size_t i = 0; i < mC; i++)
		{
			for (size_t j = 0; j < mC; j++)
			{
				const size_t poly_index = i * mC + j;

				oc::MatrixView<uint128_t> packed_polyA_(blocks.data(poly_index * mT), mT, blocks.cols());

				for (size_t k = 0; k < mT; k++)
				{
					span<uint128_t> poly_blockA = packed_polyA_[k];

					for (size_t l = 0; l < mT; l++)
					{

						DPFKey& dpf = *dpfIter++;

						DPFFullDomainEval(dpf, cache, shares);

						// Sum all the DPFs for the current block together
						// note that there is some extra "garbage" in the last
						// block of uint128_t since 64 does not divide block_size.
						// We deal with this slack later when packing the outputs
						// into the parallel FFT matrix.
						for (size_t w = 0; w < packedBlockSize; w++)
						{
							poly_blockA[w] ^= shares[w];
						}
					}
				}
			}
		}
		setTimePoint("dpfKeyEval");

		//std::cout << "block " << hash(blocks.data(), blocks.size()) << std::endl;


		for (size_t j = 0; j < mC; j++)
		{
			for (size_t k = 0; k < mC; k++)
			{
				size_t poly_index = (j * mC + k);

				oc::MatrixView<uint128_t> poly(blocks.data(poly_index * mT), mT, packedBlockSize);

				u64 i = 0;
				for (u64 block_idx = 0; block_idx < mT; ++block_idx)
				{
					for (u64 packed_idx = 0; packed_idx < packedBlockSize; ++packed_idx)
					{
						auto coeff = extractF4(poly(block_idx, packed_idx));
						auto e = std::min<u64>(mBlockSize - packed_idx * 64, 64);

						for (u64 element_idx = 0; element_idx < e; ++element_idx)
						{
							fft[i] |= u32{ coeff[63 - element_idx] } << (2 * poly_index);
							++i;
						}
					}
				}
			}
		}

		setTimePoint("transpose");

		//std::cout << "CIn " << hash(fft.data(), fft.size()) << std::endl;


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


}