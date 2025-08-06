#pragma once

#include "cryptoTools/Common/Defines.h"
#include "RegularDpf.h"
namespace osuCrypto
{

	template<typename T, typename CoeffCtx = DefaultCoeffCtx<T>>
	struct SumDmpf
	{

		u64 mPartyIdx = 0;

		// t
		u64 mNumPointsPerSet = 0;

		u64 mNumSets = 0;

		// N
		u64 mDomain = 0;

		bool mPrint = false;

		RegularDpf<T,CoeffCtx> mDpf;


		void init(
			u64 partyIdx,
			u64 domain,
			u64 pointsPerSet,
			u64 numSets)
		{
			mPartyIdx = partyIdx;
			mNumPointsPerSet = pointsPerSet;
			mDomain = domain;
			mNumSets = numSets;
			mDpf.init(partyIdx, domain, pointsPerSet * numSets);
		}

		struct BaseCorCount
		{
			u64 mSendCount = 0;
			u64 mRecvCount = 0;
		};

		BaseCorCount baseOtCount() const
		{
			auto c = mDpf.baseOtCount();
			return { c, c };
		}

		bool hasBaseOts() const
		{
			return mDpf.hasBaseOts();
		}

		void setBaseOts(
			span<const std::array<block, 2>>baseSend,
			span<const block>  baseRecv,
			const BitVector& recvChoice)
		{
			mDpf.setBaseOts(baseSend, baseRecv, recvChoice);
		}

		template<typename Output>
		macoro::task<> expand(
			span<u64> points,
			span<T> values,
			PRNG& prng,
			coproto::Socket& sock,
			Output&& output,
			CoeffCtx ctx = {})
		{
			if (points.size() != mNumSets * mNumPointsPerSet)
				throw RTE_LOC;
			if (values.size() != mNumSets * mNumPointsPerSet)
				throw RTE_LOC;

			T sum;
			block t;
			ctx.zero(sum);
			u64 count = 0;
			co_await mDpf.expand(
				points, values, prng, sock, 
				[&](u64 treeIdx, u64 pointIdx, auto value, block tag) {
					ctx.plus(sum, sum, value);
					if (++count == mNumPointsPerSet)
					{
						output(treeIdx / mNumPointsPerSet, pointIdx, sum);
						ctx.zero(sum);
						count = 0;
					}
				}, ctx);
			co_return;
		}


	};

}