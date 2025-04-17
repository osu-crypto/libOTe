#pragma once

#include "EnumeratorTools.h"
#include "Enumerator.h"
#include <iostream>
#include "libOTe/Tools/LDPC/Mtx.h"

namespace osuCrypto {


	template<typename I>
	I repeaterEnumerator(u64 w, u64 h, u64 k, u64 e, const ChooseCache<I>& pascal_triangle) {
		assert(w <= k);
		assert(h <= e * k);

		// for E_w,h to be nonzero, h must equal to w*e
		if (h != w * e) {
			return 0;
		}
		return choose_pascal<I>(k, w, pascal_triangle);
	}


	template<typename I, typename R, typename Enum = int>
	void repeaterEnumerator(
		span<const R> inDist,
		span<R> outDist,
		u64 k,
		u64 n,
		const ChooseCache<I>& choose,
		Enum&& full = {}) {
		if (n % k)
			throw RTE_LOC;

		auto e = n / k;
		if (inDist.size() != k + 1)
			throw RTE_LOC;
		if (outDist.size() != n + 1)
			throw RTE_LOC;

		std::fill(outDist.begin(), outDist.end(), R(0));
		outDist[0] = inDist[0];
		if constexpr (std::is_same_v<Enum, int> == false)
			full(0, 0) = 1;

		for (u64 w = 1; w <= k; ++w)
		{
			auto h = w * e;
			outDist[h] = inDist[w];

			if constexpr (std::is_same_v<Enum, int> == false)
				full(w, h) = choose(k,w);
		}
	}

	template<typename I, typename R>
	struct RepeaterEnumerator : Enumerator<R>
	{
		using Enumerator<R>::mK;
		using Enumerator<R>::mN;

		const ChooseCache<I>& mChoose;

		RepeaterEnumerator(u64 k,
			u64 n,
			const ChooseCache<I>& choose)
			: Enumerator<R>{ k, n }
			, mChoose(choose)
		{
			if (n % k)
				throw RTE_LOC;
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			repeaterEnumerator(inDist, outDist, mK, mN, mChoose);
		}
		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> fullEnum) override
		{
			repeaterEnumerator(inDist, outDist, mK, mN, mChoose, fullEnum);
		}

		SparseMtx getMtx() const
		{
			PointList list(mK, mN);
			for (u64 w = 0; w < mK; ++w)
			{
				for (u64 e = 0; e < mN / mK; ++e)
				{
					auto h = w + mK * e;
					list.push_back(w, h);
				}
			}
			return list;
		}

	};

	void RepeaterEnum_exhaustive_Test(const CLP& cmd);

}

