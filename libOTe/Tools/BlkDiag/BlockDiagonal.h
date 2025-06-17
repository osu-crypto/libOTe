#pragma once
#include "BaseCode.h"
#include "Randomness.h" // For xorshifthash
#include <cryptoTools/Common/Defines.h>

namespace osuCrypto
{

	template <typename T, typename Rand = BlockDiagXorShift>
	class BlockDiagonal2 : public BaseCode<T>
	{
		using BaseCode<T>::mK;
		using BaseCode<T>::mN;
		oc::u64 mSigma;
		block mSeed;
	public:
		BlockDiagonal2(u64 k, u64 n, oc::u64 sigma, block seed = block(2325612597802098727,245619238745623702))
			: BaseCode<T>(k, n), mSigma(sigma), mSeed(seed)
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

			auto seed = mSeed;
			Rand rand(seed);
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