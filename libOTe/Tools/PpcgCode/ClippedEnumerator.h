#pragma once

#include "Enumerator.h"
#include "EnumeratorTools.h"

#include <memory>

namespace osuCrypto
{
	template<typename I, typename R>
	struct ClippedEnumerator : Enumerator<R>
	{
		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		std::unique_ptr<Enumerator<R>> mInner;
		const Choose<I>& mChoose;
		u64 mClipMinWeight = 0;

		ClippedEnumerator(
			std::unique_ptr<Enumerator<R>> inner,
			const Choose<I>& choose,
			u64 clipMinWeight)
			: Enumerator<R>(inner ? inner->mK : 0, inner ? inner->mN : 0)
			, mInner(std::move(inner))
			, mChoose(choose)
			, mClipMinWeight(clipMinWeight)
		{
			if (mInner == nullptr)
				throw RTE_LOC;
		}

		u64 numTicks() const override
		{
			return mInner->numTicks() + mK;
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

			Matrix<R> innerEnum(mK + 1, mN + 1);
			std::vector<R> innerDist(mN + 1);
			mInner->mLoadBar = mLoadBar;
			mInner->enumerate(inDist, innerDist, innerEnum);

			for (u64 w = 1; w <= mK; ++w)
			{
				for (u64 h = 0; h < std::min<u64>(mClipMinWeight, mN + 1); ++h)
					innerEnum(w, h) = R(0);
			}

			osuCrypto::enumerate<R>(innerEnum, inDist, outDist, mChoose, nullptr);

			if constexpr (std::is_same_v<std::remove_cvref_t<Full>, int> == false)
			{
				if (full.rows() != innerEnum.rows() || full.cols() != innerEnum.cols())
					throw RTE_LOC;
				std::copy(innerEnum.begin(), innerEnum.end(), full.begin());
			}
		}
	};
}
