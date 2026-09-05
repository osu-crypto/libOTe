#pragma once

#include "libOTe/Dpf/RevCuckoo/WaksmanPermute.h"

#include <array>

namespace osuCrypto
{
	/// An exactly uniform hidden permutation implemented as two serial passes.
	/// Party p samples and privately controls pass p. The composed permutation
	/// is uniform even conditioned on either party's complete local state.
	class SerialWaksmanPermute
	{
		u64 mPartyIdx = 0;
		std::array<WaksmanPermute, 2> mPass;

	public:
		using BaseOtCount = WaksmanPermute::BaseOtCount;

		void init(u64 partyIdx, u64 n, u64 batches = 1)
		{
			if (partyIdx > 1)
				throw std::invalid_argument("Serial Waksman party index must be zero or one. " LOCATION);
			mPartyIdx = partyIdx;
			mPass[0].initPrivate(partyIdx, 0, n, batches);
			mPass[1].initPrivate(partyIdx, 1, n, batches);
		}

		BaseOtCount baseOtCount() const
		{
			const auto first = mPass[0].baseOtCount();
			const auto second = mPass[1].baseOtCount();
			return {
				first.mRecvCount + second.mRecvCount,
				first.mSendCount + second.mSendCount
			};
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const BitVector& baseChoices)
		{
			const auto total = baseOtCount();
			if (baseSendOts.size() != total.mSendCount ||
				recvBaseOts.size() != total.mRecvCount ||
				baseChoices.size() != total.mRecvCount)
				throw std::invalid_argument("Serial Waksman base OT count mismatch. " LOCATION);

			u64 sendOffset = 0;
			u64 recvOffset = 0;
			for (auto& pass : mPass)
			{
				const auto count = pass.baseOtCount();
				BitVector choices;
				choices.append(baseChoices, count.mRecvCount, recvOffset);
				pass.setBaseOts(
					baseSendOts.subspan(sendOffset, count.mSendCount),
					recvBaseOts.subspan(recvOffset, count.mRecvCount),
					choices);
				sendOffset += count.mSendCount;
				recvOffset += count.mRecvCount;
			}
		}

		bool hasBaseOts() const
		{
			return mPass[0].hasBaseOts() && mPass[1].hasBaseOts();
		}

		void sample(PRNG& prng)
		{
			mPass[0].samplePrivatePermutations(prng);
			mPass[1].samplePrivatePermutations(prng);
		}

		template<typename F, typename VecF, typename CoeffCtx>
		task<> applyMany(span<VecF> data, Socket& socket, CoeffCtx context)
		{
			co_await mPass[0].applyMany<F, VecF>(data, socket, context);
			co_await mPass[1].applyMany<F, VecF>(data, socket, context);
		}

		template<typename F, typename VecF, typename CoeffCtx>
		task<> applyManyInverse(span<VecF> data, Socket& socket, CoeffCtx context)
		{
			co_await mPass[1].applyManyInverse<F, VecF>(data, socket, context);
			co_await mPass[0].applyManyInverse<F, VecF>(data, socket, context);
		}

		const std::vector<u32>& privatePermutation(u64 batch) const
		{
			return mPass[mPartyIdx].privatePermutation(batch);
		}

		void clear()
		{
			mPass[0].clear();
			mPass[1].clear();
			mPartyIdx = 0;
		}
	};
}
