#pragma once
#include "cryptoTools/Common/Defines.h"
#include "EnumeratorTools.h"
#include <vector>
#include "BlockEnumerator.h"
#include "AccumulateEnumerator.h"
#include "RepeaterEnumerator.h"
#include "SubcodeType.h"
namespace osuCrypto
{

	struct Subcode
	{
		SubcodeType mType;
		u64 mK = 0;
		u64 mN = 0;
		u64 mSigma = 0;

		bool mSystematic = 0;

		template<typename I, typename R>
		void enumerate(
			std::vector<R>& inDist,
			std::vector<R>& outDist,
			u64 numThreads,
			ChooseCache<I>& pascal_triangle,
			ChooseCache<Int>& pascal_triangle2)
		{
			throw RTE_LOC;

			//if (inDist.size() && inDist.size() != mK + 1)
			//	throw RTE_LOC;

			//if (outDist.size() == 0)
			//{
			//	outDist.resize(mN + 1);
			//}
			//else
			//{
			//	outDist.resize(mN + 1);
			//	std::fill(outDist.begin(), outDist.end(), R(0));
			//}

			//switch (mType)
			//{
			//case SubcodeType::Repeater:
			//	if (inDist.size())
			//		throw std::runtime_error("repeater does not support an input distirbution. " LOCATION);

			//	repeaterEnumerator<I, R>(outDist, mK, mN, pascal_triangle);

			//	break;
			//case SubcodeType::Block:

			//	BlockEnumerator<I, R>::enumerate(
			//		inDist,
			//		outDist,
			//		mSystematic,
			//		mK,
			//		mN,
			//		mSigma,
			//		numThreads,
			//		pascal_triangle,
			//		pascal_triangle2);

			//	break;
			//case SubcodeType::Accumulate:


			//	AccumulatorEnumerator<I, R>::enumerate(inDist, outDist, mSystematic,
			//		mK, mN, numThreads,
			//		pascal_triangle);
			//	break;
			//default:
			//	throw RTE_LOC;
			//}
		}

	};


}