#pragma once

#include "Enumerator.h"
#include "EnumeratorTools.h"

#include <limits>
#include <vector>

namespace osuCrypto
{
	template<typename I, typename R>
	struct WrapConvDPEnumerator : Enumerator<R>
	{
		WrapConvDPEnumerator(
			u64 k,
			u64 n,
			u64 sigma,
			const Choose<I>& choose)
			: Enumerator<R>(k, n)
			, mSigma(sigma)
			, mChoose(choose)
		{
			if (k > n)
				throw RTE_LOC;
			if (sigma == 0 || sigma >= 63)
				throw RTE_LOC;
		}

		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		u64 mSigma = 0;
		const Choose<I>& mChoose;

		u64 numTicks() const override
		{
			return mN;
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerateImpl(inDist, outDist);
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> full) override
		{
			enumerateImpl(inDist, outDist, full);
		}

		static u64 stateCount(u64 sigma)
		{
			if (sigma >= 63)
				throw RTE_LOC;
			return u64(1) << sigma;
		}

		static u64 lowMask(u64 sigma)
		{
			if (sigma == 0)
				return 0;
			return (u64(1) << sigma) - 1;
		}

		// 0 => parity always 0, 1 => parity always 1, 2 => parity is uniform.
		static u8 parityMode(u64 step, u64 state, u64 sigma)
		{
			if (step == 0)
				return 0;

			if (step < sigma)
			{
				auto mask = lowMask(step);
				return (state & mask) ? 2 : 0;
			}

			auto youngerMask = lowMask(sigma - 1);
			if (state & youngerMask)
				return 2;
			return u8((state >> (sigma - 1)) & 1);
		}

		template<typename Full = int>
		void enumerateImpl(
			span<const R> inDist,
			span<R> outDist,
			Full&& full = {})
		{
			if (inDist.size() != mK + 1)
				throw RTE_LOC;
			if (outDist.size() != mN + 1)
				throw RTE_LOC;

			constexpr bool haveFull = std::is_same_v<std::remove_cvref_t<Full>, int> == false;
			if constexpr (haveFull)
			{
				if (full.rows() != mK + 1 || full.cols() != mN + 1)
					throw RTE_LOC;
			}

			Matrix<R> localFull;
			MatrixView<R> fullEnum = [&]() -> MatrixView<R>
			{
				if constexpr (haveFull)
					return full;
				else
				{
					localFull.resize(mK + 1, mN + 1);
					return localFull;
				}
			}();

			for (auto& v : outDist)
				v = R(0);
			for (auto& v : fullEnum)
				v = R(0);

			auto states = stateCount(mSigma);
			auto rowStride = mN + 1;
			auto stateStride = (mK + 1) * rowStride;
			auto total = states * stateStride;

			std::vector<R> cur(total, R(0));
			std::vector<R> nxt(total, R(0));

			auto idx = [&](u64 state, u64 w, u64 h)
			{
				return state * stateStride + w * rowStride + h;
			};

			cur[idx(0, 0, 0)] = R(1);
			auto stateMask = lowMask(mSigma);
			auto half = R(1) / R(2);

			for (u64 step = 0; step < mN; ++step)
			{
				std::fill(nxt.begin(), nxt.end(), R(0));

				auto wMax = std::min<u64>(step, mK);
				auto nextWMax = std::min<u64>(step + 1, mK);
				for (u64 state = 0; state < states; ++state)
				{
					auto mode = parityMode(step, state, mSigma);
					for (u64 w = 0; w <= wMax; ++w)
					{
						for (u64 h = 0; h <= step; ++h)
						{
							auto base = cur[idx(state, w, h)];
							if (base == R(0))
								continue;

							auto push = [&](u64 xBit, const R& mass)
							{
								if (mass == R(0))
									return;
								if (w + xBit > nextWMax)
									return;

								if (mode == 2)
								{
									auto massHalf = mass * half;
									auto y0 = xBit;
									auto s0 = ((state << 1) | y0) & stateMask;
									nxt[idx(s0, w + xBit, h + y0)] += massHalf;

									auto y1 = xBit ^ 1;
									auto s1 = ((state << 1) | y1) & stateMask;
									nxt[idx(s1, w + xBit, h + y1)] += massHalf;
								}
								else
								{
									auto y = xBit ^ mode;
									auto s = ((state << 1) | y) & stateMask;
									nxt[idx(s, w + xBit, h + y)] += mass;
								}
							};

							push(0, base);
							if (step < mK)
								push(1, base);
						}
					}
				}

				std::swap(cur, nxt);
				if (mLoadBar)
					mLoadBar->tick();
			}

			for (u64 state = 0; state < states; ++state)
			{
				for (u64 w = 0; w <= mK; ++w)
				{
					for (u64 h = 0; h <= mN; ++h)
					{
						fullEnum(w, h) += cur[idx(state, w, h)];
					}
				}
			}

			std::vector<R> inputFrac(inDist.size(), R(0));
			for (u64 w = 0; w <= mK; ++w)
			{
				inputFrac[w] = inDist[w] / mChoose(mK, w);
			}

			for (u64 h = 0; h <= mN; ++h)
			{
				R dh = 0;
				for (u64 w = 0; w <= mK; ++w)
					dh += inputFrac[w] * fullEnum(w, h);
				outDist[h] = dh;
			}
		}
	};

	void WrapConvDP_compare_Test(const CLP& cmd);
	void WrapConvDP_exhaustive_Test(const CLP& cmd);
}
