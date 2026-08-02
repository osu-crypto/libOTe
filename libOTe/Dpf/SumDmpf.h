#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "RegularDpf.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{

	template<typename T, typename CoeffCtx = DefaultCoeffCtx<T>>
	struct SumDmpf : public TimerAdapter
	{

		u64 mPartyIdx = 0;

		// t
		u64 mNumPointsPerSet = 0;

		u64 mNumSets = 0;

		// N
		u64 mDomain = 0;

		bool mPrint = false;

		RegularDpf<T,CoeffCtx> mDpf;

		std::vector<u64> mPoints;

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



		macoro::task<> setPoints(
			MatrixView<const u64> points,
			PRNG& prng,
			coproto::Socket& sock)
		{
			if (points.size() != mNumSets * mNumPointsPerSet)
				throw RTE_LOC;
			if (points.stride() != mNumPointsPerSet)
				throw RTE_LOC;

			mPoints.assign(points.data(), points.data() + points.size());
			co_return;
		}

		template<typename Output, typename = std::enable_if_t<
			std::is_lvalue_reference<Output>::value || std::is_object<Output>::value>>
		macoro::task<> expand(
			span<T> values,
			PRNG& prng,
			coproto::Socket& sock,
			Output output,
			CoeffCtx ctx = {})
		{
			if (mPoints.size() != mNumSets * mNumPointsPerSet)
				throw RTE_LOC;
			if (values.size() != mNumSets * mNumPointsPerSet)
				throw RTE_LOC;

			T sum;
			ctx.zero(sum);
			u64 count = 0;
			co_await mDpf.expand(
				mPoints, values, prng, sock, 
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

		void clear() {
			mPoints.clear();
		}

	};


}