#pragma once
#include "BaseCode.h"
#include "Randomness.h" // For xorshifthash
#include <cryptoTools/Common/Defines.h>

namespace osuCrypto
{
	template <typename T>
	void vectorBlockMultiply(
		const std::vector<T>& x,
		std::vector<T>& result,
		oc::u64 sigma,
		oc::u64 e,
		oc::u64 t,
		unsigned int seed);

	template <typename T>
	class BlockDiagonal : public BaseCode<T> {
		oc::u64 sigma, e, t;
		unsigned int seed; // TODO: Replace this with oc::PRNG

	public:
		BlockDiagonal(oc::u64 sigma, oc::u64 e, oc::u64 t) : sigma(sigma), e(e), t(t) {

			if (sigma <= 0 || e <= 0 || t <= 0) {
				throw std::invalid_argument("inputs must be positive");
			}

			// TODO: Use the oc::PRNG here
			// Set up pseudorandom generator for xorshift seeds
			//std::mt19937 rngcpu32(std::random_device{}());
			//std::uniform_int_distribution<uint32_t> dist32(0, std::numeric_limits<uint32_t>::max());
			//seed = dist32(rngcpu32);
			seed = 1;

			//initialize_matrix_meta(matrix_meta, sigma, e, t);
		}

		/*
		int outSize() const override {
			return matrix_meta.block_num_cols;
		}
		*/

		void invoke(const std::vector<T>& x, std::vector<T>& out) override {
			oc::vectorBlockMultiply<T>(x, out, sigma, e, t, seed);
		}
	};



	template <typename T>
	void vectorBlockMultiply(
		const std::vector<T>& x,
		std::vector<T>& result,
		oc::u64 sigma,
		oc::u64 e,
		oc::u64 t,
		unsigned int seed) {


		//int t = matrix_meta.t;
		int block_num_rows = sigma * e;
		int block_num_cols = sigma;

		result.resize(t * block_num_cols, T{});

		for (int output_idx = 0; output_idx < result.size(); ++output_idx)
		{
			//int row_start = matrix_meta.row_indices[output_idx];
			//int col_start = matrix_meta.col_indices[output_idx];

			int row_start = output_idx / (sigma * e);
			T temp = {};
			memset(&temp, 0, sizeof(T));

			// Initialize the result for this block
			for (int row = 0; row < block_num_rows; row += 32)
			{
				unsigned int mask = xorshifthash(seed ^ (output_idx * block_num_rows + row)); // 32-bit output
				// Process 4 rows at a time
				for (int bit_pos = 0; bit_pos < 8; bit_pos++)
				{  // 8-bit chunks
					unsigned int mask_4 = (mask >> bit_pos) & 0x01010101;  // Extract bit for 4 rows (1 per byte)

					// Expand the 4 bits into full 64-bit masks efficiently
					long long mask0 = -(long long)((mask_4) & 1);
					long long mask1 = -(long long)((mask_4 >> 8) & 1);
					long long mask2 = -(long long)((mask_4 >> 16) & 1);
					long long mask3 = -(long long)((mask_4 >> 24) & 1);


					auto x0 = x[row_start + row + bit_pos * 4];
					auto x1 = x[row_start + row + bit_pos * 4 + 1];
					auto x2 = x[row_start + row + bit_pos * 4 + 2];
					auto x3 = x[row_start + row + bit_pos * 4 + 3];

					temp ^= (x0 & static_cast<T>(mask0));
					temp ^= (x1 & static_cast<T>(mask1));
					temp ^= (x2 & static_cast<T>(mask2));
					temp ^= (x3 & static_cast<T>(mask3));


				}
			}

			// Store the result in the output vector
			result[output_idx] = temp;

		}
	}




	struct BlockDiagXorShift
	{
		block mState;// = 54234523452345763;
		std::array<u8, 128> mBuffer;
		//u64 mIndex = 0;

		BlockDiagXorShift() = default;
		BlockDiagXorShift(i32 seed) : mState(seed) {}

		std::span<u8, 128> operator()()
		{
			//if (mIndex == mBuffer.size())
			//{
			mState = xorshifthash(mState);
			for (u64 i = 0; i < 8; ++i)
			{
				auto bits = (mState >> i) & block::allSame<u8>(1);
				memcpy(mBuffer.data() + i * 4, &bits, sizeof(mState));
			}
			return std::span<u8, 128>(mBuffer.data(), mBuffer.size());
			//mIndex = 0;
		//}
		//auto ret = std::span<u8, 8>(mBuffer.data() + mIndex, 8);
		//mIndex += 8;
		//return ret;
		}

	};


	template <typename T, typename Rand = BlockDiagXorShift>
	class BlockDiagonal2 : public BaseCode2<T>
	{
		using BaseCode2<T>::mK;
		using BaseCode2<T>::mN;
		oc::u64 mSigma;
		Rand mRand;
	public:
		BlockDiagonal2(u64 k, u64 n, oc::u64 sigma, Rand rand = {})
			: BaseCode2<T>(k, n), mSigma(sigma), mRand(std::move(rand))
		{

			if (k % sigma)
				throw RTE_LOC;

			if (sigma % 8)
				throw RTE_LOC;

			if (inplace())
			{
				if ((mN - mK) % sigma)
					throw RTE_LOC;
			}
		}

		// we are inplace if we are compressing. G = (I || G')
		bool inplace() const override
		{
			return mK != mN;
		}

		void invoke(span<const T> x, span<T> y) override {
			if (inplace())
			{
				if (x.size())
					throw RTE_LOC;
				vectorBlockMultiplyInplace(y);

			}
			else
			{
				throw RTE_LOC;
				//oc::vectorBlockMultiply2<T>(x, y, sigma, e, t, seed);
			}
		}

		void vectorBlockMultiplyInplace(span<T> inOut) {

			if (inOut.size() != mN)
				throw RTE_LOC;

			auto x = inOut.subspan(0, mK);
			auto y = inOut.subspan(mK);

			auto sigmaK = mSigma;
			auto sigmaN = mSigma * (y.size() / x.size());
			auto numBlock = y.size() / sigmaN;

			//if (sigmaK != 8)
			//	throw RTE_LOC;

			std::array<T, 2> zeroOne;
			setBytes(zeroOne[0], 0);
			setBytes(zeroOne[1], -1);

			std::span<u8, 128> masks = mRand();
			u64 idx = 0;
			for (u64 blkIdx = 0; blkIdx < numBlock; ++blkIdx)
			{
				auto xBeing = x.data() + blkIdx * sigmaK;
				auto xEnd = xBeing + sigmaK;
				auto yBeing = y.data() + blkIdx * sigmaN;
				auto yEnd = yBeing + sigmaN;

				for (T* __restrict yy = yBeing; yy < yEnd; ++yy)
				{
					if (idx == 128)
					{
						idx = 0;
						masks = mRand();
					}

					for (T* __restrict xx = xBeing; xx < xEnd; xx += 8)
					{

						auto v0 = zeroOne.data()[masks.data()[0]] & xx[0];
						auto v1 = zeroOne.data()[masks.data()[1]] & xx[1];
						auto v2 = zeroOne.data()[masks.data()[2]] & xx[2];
						auto v3 = zeroOne.data()[masks.data()[3]] & xx[3];
						auto v4 = zeroOne.data()[masks.data()[4]] & xx[4];
						auto v5 = zeroOne.data()[masks.data()[5]] & xx[5];
						auto v6 = zeroOne.data()[masks.data()[6]] & xx[6];
						auto v7 = zeroOne.data()[masks.data()[7]] & xx[7];

						idx += 8;
						*yy ^= (v0 ^ v1 ^ v2 ^ v3 ^ v4 ^ v5 ^ v6 ^ v7);
					}
				}
			}
		}

	};

}