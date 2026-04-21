#pragma once

#include "Enumerator.h"
#include "EnumeratorTools.h"

#include <memory>

namespace osuCrypto
{
	template<typename I, typename R>
	struct SystematicEnumerator : Enumerator<R>
	{
		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		std::unique_ptr<Enumerator<R>> mParity;
		const Choose<I>& mChoose;

		SystematicEnumerator(
			std::unique_ptr<Enumerator<R>> parity,
			const Choose<I>& choose)
			: Enumerator<R>(parity ? parity->mK : 0, parity ? parity->mK + parity->mN : 0)
			, mParity(std::move(parity))
			, mChoose(choose)
		{
			if (mParity == nullptr)
				throw RTE_LOC;
		}

		u64 numTicks() const override
		{
			return mParity->numTicks() + mK;
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

			Matrix<R> parityEnum(mK + 1, mParity->mN + 1);
			std::vector<R> parityDist(mParity->mN + 1);
			mParity->mLoadBar = mLoadBar;
			mParity->enumerate(inDist, parityDist, parityEnum);

			auto sysEnum = makeSystematic<R>(parityEnum);
			osuCrypto::enumerate<R>(sysEnum, inDist, outDist, mChoose, nullptr);

			if constexpr (std::is_same_v<std::remove_cvref_t<Full>, int> == false)
			{
				if (full.rows() != sysEnum.rows() || full.cols() != sysEnum.cols())
					throw RTE_LOC;
				std::copy(sysEnum.begin(), sysEnum.end(), full.begin());
			}
		}
	};
}
