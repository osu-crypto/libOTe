#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include <vector>
#include <algorithm>
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Dpf/DpfMult.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{

	struct WaksmanPermute
	{

		u64 mPartyIdx = 0;

		u64 mN = 0;

		u64 mBatches = 1;

		DpfMult mMult;
		std::vector<DpfMult::MultSession> mMultSessions;

		u64 mOtIdx = 0;

		bool print = false;

		void init(u64 partyIdx, u64 n, u64 batches = 1)
		{
			if (partyIdx > 1)
				throw std::runtime_error("GoldreichHash: partyIdx must be 0 or 1. " LOCATION);
			if (n == 0)
				throw std::runtime_error("GoldreichHash: n must be > 0. " LOCATION);

			mPartyIdx = partyIdx;
			mN = n;
			mBatches = batches;

			std::unordered_map<u64, u64> map;
			mMult.init(mPartyIdx, switchCount(mN, map) * batches);
		}

		static u64 switchCount(u64 n, std::unordered_map<u64, u64>& map)
		{
			if (n <= 1) return 0;
			if (n == 2) return 1;                       // single switch, one stage

			auto iter = map.find(n);
			if (iter != map.end())
				return iter->second;

			u64 k = n >> 1;                   // ⌊n/2⌋  (input stage)
			u64 up = (n + 1) >> 1;             // ⌈n/2⌉
			u64 low = n >> 1;                   // ⌊n/2⌋

			u64 out = k;// -((n & 1) == 0);       // output stage:
			//   even n : k-1
			//   odd  n : k
			auto count = k + switchCount(up, map) + switchCount(low, map) + out;
			map[n] = count;
			return count;
		}

		struct BaseOtCount {
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		BaseOtCount baseOtCount() const
		{
			auto c = mMult.baseOtCount();
			return { c, c };
		}


		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			mMult.setBaseOts(baseSendOts, recvBaseOts, baseChoices);

			//if (baseSendOts.size() != baseOtCount().mSendCount ||
			//	recvBaseOts.size() != baseOtCount().mRecvCount ||
			//	baseChoices.size() != baseOtCount().mRecvCount)
			//	throw RTE_LOC;

			//mSendOts.clear();
			//mRecvOts.clear();
			//mSendOts.insert(mSendOts.end(), baseSendOts.begin(), baseSendOts.end());
			//mRecvOts.insert(mRecvOts.end(), recvBaseOts.begin(), recvBaseOts.end());
			//mChoiceBits = baseChoices;
			//mOtIdx = 0;
		}

		bool hasBaseOts() const
		{
			return mMult.hasBaseOts();
			//return !mRecvOts.empty() && !mSendOts.empty() && mChoiceBits.size();
		}


		template<typename F, typename CoeffCtx>
		task<> left(auto&& src, auto&& dst, auto&& diff, CoeffCtx ctx,
			std::vector<u64>& subnetSizes,
			u64& numSubnets,
			std::vector<u64>& nextSubnetSizes,
			u64& nextNumSubnets2,
			Socket& sock)
		{
			nextNumSubnets2 = 0;
			auto diffIter = diff.begin();
			auto srcIter = src.begin();

			for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
			{
				auto size = subnetSizes.data()[subnetIdx];

				auto inputBegin = srcIter;
				srcIter += size;
				
				nextSubnetSizes.data()[nextNumSubnets2++] = size / 2;
				nextSubnetSizes.data()[nextNumSubnets2++] = size - size / 2;

				// Collect differences for this subnet
				for (u64 i = 0; i + 1 < size; i += 2)
				{
					// diff = input[1] - input[0]
					ctx.minus(*diffIter++, inputBegin[i + 1], inputBegin[i]);
				}
			}

			co_await randMultiply<F>(diff.begin(), diffIter, sock, ctx);

			// Apply the multiplied differences
			
			diffIter = diff.begin();
			srcIter = src.begin();
			auto dstIter = dst.begin();
			auto temp_val = ctx.template makeVec<F>(1);

			for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
			{
				auto size = subnetSizes.data()[subnetIdx];
				auto inputBegin = srcIter;
				auto output0Begin = dstIter;
				auto output1Begin = output0Begin + size / 2;

				srcIter += size;
				dstIter += size;

				for (u64 i = 0; i + 1 < size; i += 2)
				{
					auto input0 = *inputBegin++;
					auto input1 = *inputBegin++;

					// output0 = ctrl * (input[1]-input[0]) + input[0]
					//         = input[ctrl]
					ctx.plus(*output0Begin, input0, *diffIter++);

					// output1 = (input[0]+input[1]) - output0
					//         = input[!ctrl]
					ctx.plus(temp_val[0], input0, input1);
					ctx.minus(*output1Begin++, temp_val[0], *output0Begin++);

				}

				if (size & 1)
				{
					ctx.copy(*output1Begin, *inputBegin);
				}
			}
		}


		template<typename F, typename CoeffCtx>
		task<> right(auto&& src, auto&& dst, auto&& diff, CoeffCtx ctx,
			std::vector<u64>& subnetSizes,
			u64 numSubnets,
			std::vector<u64>& nextSubnetSizes,
			u64& nextNumSubnets,
			Socket& sock)
		{

			nextNumSubnets = 0;
			auto diffIter = diff.begin();
			auto srcIter = src.begin();

			//auto numSubnets = subnetSizes.size();
			for (u64 subnetIdx = 0; subnetIdx < numSubnets; subnetIdx += 2)
			{
				auto size0 = subnetSizes.data()[subnetIdx];
				auto size1 = subnetSizes.data()[subnetIdx + 1];

				auto input0Begin = srcIter;
				auto input1Begin = input0Begin + size0;
				srcIter = input1Begin + size1;

				//idx += size0 + size1;
				nextSubnetSizes.data()[nextNumSubnets++] = size0 + size1;

				// Collect differences
				for (u64 i = 0; i + 1 < size0 + size1; i += 2)
				{
					ctx.minus(*diffIter++, *input1Begin++, *input0Begin++);
				}
			}

			co_await randMultiply<F>(diff.begin(), diffIter, sock, ctx);

			auto temp_val = ctx.template makeVec<F>(1);
			diffIter = diff.begin();
			srcIter = src.begin();
			auto dstIter = dst.begin();
			for (u64 subnetIdx = 0; subnetIdx < numSubnets; subnetIdx += 2)
			{
				auto size0 = subnetSizes.data()[subnetIdx];
				auto size1 = subnetSizes.data()[subnetIdx + 1];

				auto input0Begin = srcIter;
				auto input1Begin = input0Begin + size0;
				auto outputBegin = dstIter;

				auto size = size0 + size1;
				srcIter += size;
				dstIter += size;

				for (u64 i = 0; i + 1 < size; i += 2)
				{
					auto out0 = outputBegin++;
					auto out1 = outputBegin++;

					// output[i] = ctrl * (input1[i/2] - input0[i/2]) + input0[i/2]
					//           = input[ctrl][i/2]
					ctx.plus(*out0, *input0Begin, *diffIter++);

					// output[i+1] = (input0[i/2] + input1[i/2]) - output[i]
					//             = input[!ctrl][i/2]
					ctx.plus(temp_val[0], *input0Begin++, *input1Begin++);
					ctx.minus(*out1, temp_val[0], *out0);
				}

				if (size0 != size1)
				{
					ctx.copy(*outputBegin, *input1Begin);
				}
			}
		}


		// data is a vector of F, which is the type of the coefficients.
		template<typename F, typename CoeffCtx>
		task<> apply(
			auto&& data,
			Socket& sock,
			CoeffCtx ctx)
		{
			if(mBatches != 1)
				throw std::runtime_error("WaksmanPermute::apply: Batches != 1. " LOCATION);

			mOtIdx = 0;
			//auto print = false;
			auto n = mN;
			if (data.size() != mN)
				throw RTE_LOC;

			u64 numStages = log2ceil(n);
			std::vector<u64> subnetSizes{ n };
			std::vector<u64> nextSubnetSizes;
			subnetSizes.resize(1ull<< log2ceil(n));
			nextSubnetSizes.resize(1ull << log2ceil(n));
			u64 numSubnets = 1;
			u64 nextNumSubnets = 0;

			//subnetSizes.reserve(n);
			//nextSubnetSizes.reserve(n);

			auto temp = ctx.template makeVec<F>(data.size());

			// diff = input[1] - input[0]
			auto diff = ctx.template makeVec<F>(data.size());
			u64 stageBit = 0;
			//auto* src = data;
			//auto* dst = temp;

			// process all left columns/stages
			for (u64 stage = 0; stage < numStages; ++stage)
			{
				if (stageBit == 0)
					co_await left<F>(data, temp, diff, ctx, 
						subnetSizes, numSubnets, 
						nextSubnetSizes, nextNumSubnets, sock);
				else
					co_await left<F>(temp, data, diff, ctx, 
						subnetSizes, numSubnets,
						nextSubnetSizes, nextNumSubnets, sock);

				stageBit ^= 1;
				std::swap(subnetSizes, nextSubnetSizes);
				numSubnets = nextNumSubnets;
				nextNumSubnets = 0;
			}

			//subnetSizes.resize(numSubnets);
			//nextSubnetSizes.clear();
			// Right stages (reverse)
			for (u64 stage = numStages - 2; stage < numStages; --stage)
			{

				if (stageBit == 0)
					co_await right<F>(data, temp, diff, ctx, 
						subnetSizes, numSubnets, 
						nextSubnetSizes, nextNumSubnets, sock);
				else													  
					co_await right<F>(temp, data, diff, ctx, 
						subnetSizes, numSubnets, 
						nextSubnetSizes, nextNumSubnets, sock);

				stageBit ^= 1;
				std::swap(subnetSizes, nextSubnetSizes);
				numSubnets = nextNumSubnets;
				nextNumSubnets = 0;
				//nextSubnetSizes.clear();
			}

			if (stageBit)
			{
				// Copy final result back to data
				for (u64 i = 0; i < data.size(); ++i)
				{

					ctx.copy(data[i], temp[i]);
				}
			}
		}


		template<typename F, typename CoeffCtx>
		task<> leftMany(auto&& src, auto&& dst, auto&& diff, CoeffCtx ctx,
			std::vector<u64>& subnetSizes,
			u64& numSubnets,
			std::vector<u64>& nextSubnetSizes,
			u64& nextNumSubnets2,
			Socket& sock)
		{

			if (src.size() != mBatches)
				throw std::runtime_error("WaksmanPermute::rightMany: src.size() != mBatches. " LOCATION);
			if (dst.size() != mBatches)
				throw std::runtime_error("WaksmanPermute::rightMany: dst.size() != mBatches. " LOCATION);
			if (diff.size() != mBatches * mN)
				throw std::runtime_error("WaksmanPermute::rightMany: diff.size() != mBatches. " LOCATION);

			nextNumSubnets2 = 0;

			for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
			{
				auto size = subnetSizes.data()[subnetIdx];
				nextSubnetSizes.data()[nextNumSubnets2++] = size / 2;
				nextSubnetSizes.data()[nextNumSubnets2++] = size - size / 2;
			}

			auto diffIter = diff.begin();
			for (u64 batch = 0; batch < mBatches; ++batch)
			{

				if( src[batch].size() != dst[batch].size())
					throw std::runtime_error("WaksmanPermute::leftMany: src[batch].size() != dst[batch].size() " LOCATION);
				if (src[batch].size() != mN)
					throw std::runtime_error("WaksmanPermute::leftMany: src[batch].size() != mN. " LOCATION);

				auto srcIter = src[batch].begin();

				for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
				{
					auto size = subnetSizes.data()[subnetIdx];

					auto inputBegin = srcIter;
					srcIter += size;

					// Collect differences for this subnet
					for (u64 i = 0; i + 1 < size; i += 2)
					{
						// diff = input[1] - input[0]
						ctx.minus(*diffIter++, inputBegin[i + 1], inputBegin[i]);
					}
				}
			}

			co_await randMultiply<F>(diff.begin(), diffIter, sock, ctx);

			// Apply the multiplied differences

			auto temp_val = ctx.template makeVec<F>(1);
			diffIter = diff.begin();

			for (u64 batch = 0; batch < mBatches; ++batch)
			{
				auto srcIter = src[batch].begin();
				auto dstIter = dst[batch].begin();

				for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
				{
					auto size = subnetSizes.data()[subnetIdx];
					auto inputBegin = srcIter;
					auto output0Begin = dstIter;
					auto output1Begin = output0Begin + size / 2;

					srcIter += size;
					dstIter += size;

					for (u64 i = 0; i + 1 < size; i += 2)
					{
						auto input0 = *inputBegin++;
						auto input1 = *inputBegin++;

						// output0 = ctrl * (input[1]-input[0]) + input[0]
						//         = input[ctrl]
						ctx.plus(*output0Begin, input0, *diffIter++);

						// output1 = (input[0]+input[1]) - output0
						//         = input[!ctrl]
						ctx.plus(temp_val[0], input0, input1);
						ctx.minus(*output1Begin++, temp_val[0], *output0Begin++);

					}

					if (size & 1)
					{
						ctx.copy(*output1Begin, *inputBegin);
					}
				}
			}
		}


		template<typename F, typename CoeffCtx>
		task<> rightMany(auto&& src, auto&& dst, auto&& diff, CoeffCtx ctx,
			std::vector<u64>& subnetSizes,
			u64 numSubnets,
			std::vector<u64>& nextSubnetSizes,
			u64& nextNumSubnets,
			Socket& sock)
		{

			if(src.size() != mBatches)
				throw std::runtime_error("WaksmanPermute::rightMany: src.size() != mBatches. " LOCATION);
			if (dst.size() != mBatches)
				throw std::runtime_error("WaksmanPermute::rightMany: dst.size() != mBatches. " LOCATION);
			if (diff.size() != mBatches * mN)
				throw std::runtime_error("WaksmanPermute::rightMany: diff.size() != mBatches. " LOCATION);

			nextNumSubnets = 0;

			for (u64 subnetIdx = 0; subnetIdx < numSubnets; subnetIdx += 2)
			{
				auto size0 = subnetSizes.data()[subnetIdx];
				auto size1 = subnetSizes.data()[subnetIdx + 1];
				nextSubnetSizes.data()[nextNumSubnets++] = size0 + size1;
			}

			auto diffIter = diff.begin();
			for (u64 batch = 0; batch < mBatches; ++batch)
			{
				if (src[batch].size() != dst[batch].size())
					throw std::runtime_error("WaksmanPermute::rightMany: src[batch].size() != dst[batch].size() " LOCATION);

				auto srcIter = src[batch].begin();

				for (u64 subnetIdx = 0; subnetIdx < numSubnets; subnetIdx += 2)
				{
					auto size0 = subnetSizes.data()[subnetIdx];
					auto size1 = subnetSizes.data()[subnetIdx + 1];

					auto input0Begin = srcIter;
					auto input1Begin = input0Begin + size0;
					srcIter = input1Begin + size1;

					// Collect differences
					for (u64 i = 0; i + 1 < size0 + size1; i += 2)
					{
						ctx.minus(*diffIter++, *input1Begin++, *input0Begin++);
					}
				}
			}
			co_await randMultiply<F>(diff.begin(), diffIter, sock, ctx);

			auto temp_val = ctx.template makeVec<F>(1);
			diffIter = diff.begin();

			for (u64 batch = 0; batch < mBatches; ++batch)
			{
				auto srcIter = src[batch].begin();
				auto dstIter = dst[batch].begin();
				for (u64 subnetIdx = 0; subnetIdx < numSubnets; subnetIdx += 2)
				{
					auto size0 = subnetSizes.data()[subnetIdx];
					auto size1 = subnetSizes.data()[subnetIdx + 1];

					auto input0Begin = srcIter;
					auto input1Begin = input0Begin + size0;
					auto outputBegin = dstIter;

					auto size = size0 + size1;
					srcIter += size;
					dstIter += size;

					for (u64 i = 0; i + 1 < size; i += 2)
					{
						auto out0 = outputBegin++;
						auto out1 = outputBegin++;

						// output[i] = ctrl * (input1[i/2] - input0[i/2]) + input0[i/2]
						//           = input[ctrl][i/2]
						ctx.plus(*out0, *input0Begin, *diffIter++);

						// output[i+1] = (input0[i/2] + input1[i/2]) - output[i]
						//             = input[!ctrl][i/2]
						ctx.plus(temp_val[0], *input0Begin++, *input1Begin++);
						ctx.minus(*out1, temp_val[0], *out0);
					}

					if (size0 != size1)
					{
						ctx.copy(*outputBegin, *input1Begin);
					}
				}
			}
		}




		// data is a vector of F, which is the type of the coefficients.
		template<typename F, typename VecF, typename CoeffCtx>
		task<> applyMany(
			span<VecF> data,
			Socket& sock,
			CoeffCtx ctx)
		{
			if (mBatches != data.size())
				throw std::runtime_error("WaksmanPermute::applyMany: Batches != data.size(). " LOCATION);
			mOtIdx = 0;

			auto n = mN;
			for (auto& d : data)
			{
				if (d.size() != mN)
					throw RTE_LOC;
			}

			u64 numStages = log2ceil(n);
			std::vector<u64> subnetSizes{ n };
			std::vector<u64> nextSubnetSizes;
			subnetSizes.resize(1ull << log2ceil(n));
			nextSubnetSizes.resize(1ull << log2ceil(n));
			u64 numSubnets = 1;
			u64 nextNumSubnets = 0;

			using Vec = typename CoeffCtx::template Vec<F>;
			std::vector<Vec> temp(data.size());
			Vec diff = ctx.template makeVec<F>(mN * mBatches);
			for (u64 i = 0; i < data.size(); ++i)
				temp[i] = ctx.template makeVec<F>(data[i].size());

			u64 stageBit = 0;
			
			// process all left columns/stages
			for (u64 stage = 0; stage < numStages; ++stage)
			{
				if (stageBit == 0)
					co_await leftMany<F>(data, temp, diff, ctx,
						subnetSizes, numSubnets,
						nextSubnetSizes, nextNumSubnets, sock);
				else
					co_await leftMany<F>(temp, data, diff, ctx,
						subnetSizes, numSubnets,
						nextSubnetSizes, nextNumSubnets, sock);

				stageBit ^= 1;
				std::swap(subnetSizes, nextSubnetSizes);
				numSubnets = nextNumSubnets;
				nextNumSubnets = 0;
			}

			//subnetSizes.resize(numSubnets);
			//nextSubnetSizes.clear();
			// Right stages (reverse)
			for (u64 stage = numStages - 2; stage < numStages; --stage)
			{

				if (stageBit == 0)
					co_await rightMany<F>(data, temp, diff, ctx,
						subnetSizes, numSubnets,
						nextSubnetSizes, nextNumSubnets, sock);
				else
					co_await rightMany<F>(temp, data, diff, ctx,
						subnetSizes, numSubnets,
						nextSubnetSizes, nextNumSubnets, sock);

				stageBit ^= 1;
				std::swap(subnetSizes, nextSubnetSizes);
				numSubnets = nextNumSubnets;
				nextNumSubnets = 0;
				//nextSubnetSizes.clear();
			}

			if (stageBit)
			{
				// Copy final result back to data
				for (u64 i = 0; i < data.size(); ++i)
				{
					auto& temp_i = temp[i];
					auto& data_i = data[i];
					for (u64 j = 0; j < data_i.size(); ++j)
					{
						ctx.copy(data_i[j], temp_i[j]);
					}
				}
			}
		}




		// Multiply each input vector with a random bit using existing choice bits.
		// Does not take control bits as input - uses internal mMult choice bits directly.
		template<typename F>
		task<> randMultiply(
			auto&& begin,
			auto&& end,
			coproto::Socket& sock,
			auto&& ctx)
		{
			if (mMultSessions.size() == mOtIdx)
			{
				auto size = std::distance(begin, end);
				mMultSessions.push_back(mMult.randMultiply(size));
			}

			if (mMultSessions.size() <= mOtIdx)
				throw RTE_LOC;

			co_await mMultSessions[mOtIdx++].multiply<F>(begin, end, begin, sock, ctx);

		}

		void clear()
		{
			mMult.clear();
			mMultSessions.clear();
			mOtIdx = 0;
			mBatches = 0;
			mN = 0;
		}
	};

}