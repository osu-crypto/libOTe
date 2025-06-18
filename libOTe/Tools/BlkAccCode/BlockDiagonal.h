#pragma once
#include "BaseCode.h"
#include "Randomness.h" // For xorshifthash
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>

namespace osuCrypto
{

	/**
	 * @brief A pseudorandom number generator using XOR-shift for the block diagonal code
	 *
	 * This class provides a deterministic sequence of bytes used to determine
	 * which bits from the input blocks contribute to each output bit.
	 * It maintains internal state and a buffer of random bytes that are generated
	 * as needed.
	 */
	struct BlockDiagXorShift
	{
		block mState;
		std::array<u8, 128> mBuffer;

		BlockDiagXorShift() = default;
		BlockDiagXorShift(block seed) : mState(seed) {}

		/**
		 * @brief Generate 128 random bytes and return them. Each bit is zero one.
		 *
		 * Uses the XOR-shift algorithm to evolve the internal state and
		 * extracts bits from the state to fill the buffer with random bytes.
		 *
		 * @return A span containing 128 random bytes
		 */
		auto operator()()
		{
			mState = xorshifthash(mState);
			for (u64 i = 0; i < 8; ++i)
			{
				auto bits = mState.srli_epi64(i) & block::allSame<u8>(1);
				memcpy(mBuffer.data() + i * 16, &bits, sizeof(mState));
			}
			return mBuffer.data();
		}

	};

	/**
	 * @brief Block diagonal code implementation for encoding/decoding data
	 * see "Block-Diagonal Codes: Accelerated Linear Codes for Pseudorandom Correlation Generators"
	 *
	 * This class implements a block diagonal matrix multiplication that maps
	 * from a larger space to a smaller space. The matrix is not stored explicitly
	 * but is generated on-the-fly using pseudorandom bits.
	 *
	 * For each output position, a local subset of input bits are XORed together.
	 *
	 * @tparam T The type of elements being processed (typically block or u8)
	 * @tparam Rand The randomness source type (defaults to BlockDiagXorShift)
	 */
	template <typename Rand = BlockDiagXorShift>
	class BlockDiagonal// : public BaseCode<T>
	{
		u64 mK = 0;  // Size of output (message size)
		u64 mN = 0;  // Size of input (code size)
		oc::u64 mSigma = 0;         // Block size parameter
		block mSeed = ZeroBlock;            // Seed for randomness

	public:


		/**
		 * @brief Construct a new Block Diagonal code
		 *
		 * @param k Output size (message size)
		 * @param n Input size (code size)
		 * @param sigma Block size parameter (must be divisible by 8)
		 * @param seed Seed for randomness
		 */
		BlockDiagonal(u64 k, u64 n, oc::u64 sigma, block seed = block(2325612597802098727, 245619238745623702))
			: mK(k), mN(n), mSigma(sigma), mSeed(seed)
		{
			if (sigma % 8)
				throw RTE_LOC;
		}

		/**
		 * @brief Apply the block diagonal code to the input data
		 *
		 * @param x Input data (ignored in inplace mode)
		 * @param y Output data (or in-place input/output in inplace mode)
		 */
		template<typename F, typename CoeffCtx>
		void dualEncode(auto iter, CoeffCtx ctx) {


			auto xIter = iter;
			auto yIter = iter + mK;
			auto xSize = mK;
			auto ySize = mN - mK;

			auto sigmaK = mSigma;
			auto sigmaN = roundUpTo(mSigma * (ySize / xSize), 8);
			auto numBlock = xSize / sigmaK;

			std::array<block, 2> zeroOne_;
			setBytes(zeroOne_[0], 0);
			setBytes(zeroOne_[1], -1);
			auto zeroOne = zeroOne_.data();
			typename CoeffCtx::template Vec<F> v;
			ctx.resize(v, 8);
			auto seed = mSeed;
			Rand rand(seed);
			auto bitIter = rand();

			u64 idx = 0, count = 0;

			for (u64 blkIdx = 0; blkIdx < numBlock - 1; ++blkIdx)
			{
				auto xBeing = xIter + blkIdx * sigmaK;
				auto xEnd = xBeing + sigmaK;
				auto yBeing = yIter + blkIdx * sigmaN;
				auto yEnd = yBeing + sigmaN;

				for (auto yy = yBeing; yy < yEnd; ++yy)
				{
					for (auto xx = xBeing; xx < xEnd; xx += 8)
					{
						if (idx == 128)
						{
							if (count++ == 128)
							{
								// rerandomize the seed as XorShift is not perfect.
								seed = mAesFixedKey.hashBlock(seed);
								rand = Rand(seed);
								count = 0;
							}

							idx = 0;
							bitIter = rand();
						}
						if ((bitIter[0] |
							bitIter[1] |
							bitIter[2] |
							bitIter[3] |
							bitIter[4] |
							bitIter[5] |
							bitIter[6] |
							bitIter[7]) > 1)
							throw RTE_LOC;

						// vi = xi * randBits[i]
						ctx.template mask<F>(v[0], xx[0], zeroOne[bitIter[0]]);
						ctx.template mask<F>(v[1], xx[1], zeroOne[bitIter[1]]);
						ctx.template mask<F>(v[2], xx[2], zeroOne[bitIter[2]]);
						ctx.template mask<F>(v[3], xx[3], zeroOne[bitIter[3]]);
						ctx.template mask<F>(v[4], xx[4], zeroOne[bitIter[4]]);
						ctx.template mask<F>(v[5], xx[5], zeroOne[bitIter[5]]);
						ctx.template mask<F>(v[6], xx[6], zeroOne[bitIter[6]]);
						ctx.template mask<F>(v[7], xx[7], zeroOne[bitIter[7]]);

						bitIter += 8;
						idx += 8;

						//*yy ^= (v0 ^ v1 ^ v2 ^ v3 ^ v4 ^ v5 ^ v6 ^ v7);
						ctx.plus(v[0], v[0], v[1]);
						ctx.plus(v[2], v[2], v[3]);
						ctx.plus(v[4], v[4], v[5]);
						ctx.plus(v[6], v[6], v[7]);

						ctx.plus(v[0], v[0], v[2]);
						ctx.plus(v[4], v[4], v[6]);

						ctx.plus(v[0], v[0], v[4]);
						ctx.plus(*yy, *yy, v[0]);
					}
				}
			}

			// the last block might be over sized so we handle it specially
			{
				auto blkIdx = numBlock - 1;
				auto xBeing = xIter + blkIdx * sigmaK;
				auto xEnd = xIter + xSize;
				auto yBeing = yIter + blkIdx * sigmaN;
				auto yEnd = yIter + ySize;

				for (auto yy = yBeing; yy < yEnd; ++yy)
				{

					for (auto xx = xBeing; xx < xEnd; ++xx)
					{
						if (idx == 128)
						{
							if (count++ == 128)
							{
								// rerandomize the seed as XorShift is not perfect.
								seed = mAesFixedKey.hashBlock(seed);
								rand = Rand(seed);
								count = 0;
							}

							idx = 0;
							bitIter = rand();
						}

						// vi = xi * randBits[i]
						ctx.template mask<F>(v[0], xx[0], zeroOne[*bitIter]);

						++bitIter;
						++idx;
						ctx.plus(*yy, *yy, v[0]);
					}
				}
			}

		}


	};

}