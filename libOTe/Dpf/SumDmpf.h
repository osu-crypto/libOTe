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
		u64 mNumPoints = 0;

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
			mNumPoints = pointsPerSet;
			mDomain = domain;
			mNumSets = numSets;
			mDpf.init(partyIdx, domain, pointsPerSet * numSets);
		}

		u64 baseOtCount() const
		{
			return mDpf.baseOtCount();
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
			if (points.size() != mNumSets * mNumPoints)
				throw RTE_LOC;
			if (values.size() != mNumSets * mNumPoints)
				throw RTE_LOC;

			T sum;
			block t;
			ctx.zero(sum);
			t = ZeroBlock;
			u64 count = 0;
			co_await mDpf.expand(
				points, values, prng, sock, 
				[&](u64 treeIdx, u64 pointIdx, auto value, block tag) {
					ctx.plus(sum, sum, value);
					t ^= tag;
					if (++count == mNumPoints)
					{
						output(treeIdx / mNumPoints, pointIdx, sum, t);
						ctx.zero(sum);
						count = 0;
						t = ZeroBlock;
					}
				}, ctx);
			co_return;
		}


	};

}