#pragma once

#include <algorithm>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Dpf/DpfMult.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/Coproto.h"

#include <iterator>
#include <numeric>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace osuCrypto
{

	/// Oblivious Waksman permutation over one or more coefficient vectors.
	///
	/// init() retains the original shared-control protocol used by Reverse
	/// Cuckoo. initPrivate() lets one party choose all switch controls without
	/// revealing them and is used by SerialWaksmanPermute.
	struct WaksmanPermute
	{
		struct PrivateMultSession
		{
			u64 mPartyIdx = 0;
			u64 mOwner = 0;
			u64 mExpandIdx = 0;
			span<block> mRecvOts;
			span<std::array<block, 2>> mSendOts;
			BitVector mControls;

			template<typename F, typename CoeffCtx>
			task<> multiply(
				auto&& yBegin,
				auto&& yEnd,
				auto&& xyBegin,
				Socket& socket,
				CoeffCtx ctx)
			{
				const auto n = static_cast<u64>(std::distance(yBegin, yEnd));
				if (n == 0)
					co_return;
				std::ignore = *(xyBegin + (n - 1));
				const auto bytes = ctx.template byteSize<F>();
				AES hash(block(0x4f1bbcdc6765a9d3ull, 0x94d049bb133111ebull ^ mExpandIdx++));

				if (mPartyIdx != mOwner)
				{
					if (mSendOts.size() != n)
						throw RTE_LOC;
					AlignedUnVector<u8> message(n * bytes);
					auto messageIter = message.data();
					auto zero = ctx.template makeVec<F>(1);
					auto h0 = ctx.template makeVec<F>(8);
					auto h1 = ctx.template makeVec<F>(8);
					auto correction = ctx.template makeVec<F>(8);
					ctx.zero(zero[0]);
					block hashes0[8];
					block hashes1[8];
					const auto n8 = n / 8 * 8;
					for (u64 i = 0; i < n8; i += 8)
					{
						for (u64 j = 0; j < 8; ++j)
						{
							hashes0[j] = mSendOts[i + j][0];
							hashes1[j] = mSendOts[i + j][1];
						}
						hash.hashBlocks<8>(hashes0, hashes0);
						hash.hashBlocks<8>(hashes1, hashes1);
						for (u64 j = 0; j < 8; ++j)
						{
							ctx.fromBlock(h0[j], hashes0[j]);
							ctx.fromBlock(h1[j], hashes1[j]);
							ctx.plus(correction[j], h0[j], yBegin[i + j]);
							ctx.minus(correction[j], correction[j], h1[j]);
							ctx.minus(xyBegin[i + j], zero[0], h0[j]);
						}
						ctx.serialize(correction.begin(), correction.end(), messageIter);
						messageIter += 8 * bytes;
					}
					for (u64 i = n8; i < n; ++i)
					{
						ctx.fromBlock(h0[0], hash.hashBlock(mSendOts[i][0]));
						ctx.fromBlock(h1[0], hash.hashBlock(mSendOts[i][1]));
						ctx.plus(correction[0], h0[0], yBegin[i]);
						ctx.minus(correction[0], correction[0], h1[0]);
						ctx.minus(xyBegin[i], zero[0], h0[0]);
						ctx.serialize(correction.begin(), correction.begin() + 1, messageIter);
						messageIter += bytes;
					}
					co_await socket.send(std::move(message));
					co_return;
				}

				if (mRecvOts.size() != n || mControls.size() != n)
					throw RTE_LOC;
				AlignedUnVector<u8> message(n * bytes);
				co_await socket.recv(message);
				auto messageIter = message.data();
				auto received = ctx.template makeVec<F>(8);
				auto correction = ctx.template makeVec<F>(8);
				auto localProduct = ctx.template makeVec<F>(8);
				block hashes[8];
				const auto n8 = n / 8 * 8;
				for (u64 i = 0; i < n8; i += 8)
				{
					for (u64 j = 0; j < 8; ++j)
						hashes[j] = mRecvOts[i + j];
					hash.hashBlocks<8>(hashes, hashes);
					ctx.deserialize(messageIter + 0, messageIter + 8 * bytes, correction.begin());
					messageIter += 8 * bytes;
					for (u64 j = 0; j < 8; ++j)
					{
						ctx.fromBlock(received[j], hashes[j]);
						const auto control = mControls[i + j];
						ctx.mask(localProduct[j], yBegin[i + j],
							control ? block::allSame<u32>(-1) : block::allSame<u32>(0));
						if (control)
							ctx.plus(received[j], received[j], correction[j]);
						ctx.plus(xyBegin[i + j], localProduct[j], received[j]);
					}
				}
				for (u64 i = n8; i < n; ++i)
				{
					ctx.deserialize(messageIter + 0, messageIter + bytes, correction.begin());
					messageIter += bytes;
					ctx.fromBlock(received[0], hash.hashBlock(mRecvOts[i]));
					const auto control = mControls[i];
					ctx.mask(localProduct[0], yBegin[i],
						control ? block::allSame<u32>(-1) : block::allSame<u32>(0));
					if (control)
						ctx.plus(received[0], received[0], correction[0]);
					ctx.plus(xyBegin[i], localProduct[0], received[0]);
				}
			}
		};

		u64 mPartyIdx = 0;

		u64 mN = 0;

		u64 mBatches = 1;

		DpfMult mMult;
		std::vector<DpfMult::MultSession> mMultSessions;

		bool mPrivateControls = false;
		bool mPrivatePrepared = false;
		bool mPrivateSampled = false;
		u64 mControlOwner = 0;
		u64 mPrivateOtOffset = 0;
		AlignedUnVector<block> mPrivateRecvOts;
		AlignedUnVector<std::array<block, 2>> mPrivateSendOts;
		BitVector mPrivateBaseChoices;
		BitVector mPrivateControlsBits;
		std::vector<std::vector<u32>> mPrivatePermutations;
		std::vector<PrivateMultSession> mPrivateSessions;

		u64 mOtIdx = 0;
		bool mUseInverseSessions = false;

		void init(u64 partyIdx, u64 n, u64 batches = 1)
		{
			if (partyIdx > 1)
				throw std::invalid_argument("Waksman party index must be zero or one. " LOCATION);
			if (n == 0 || batches == 0)
				throw std::invalid_argument("Waksman dimensions must be nonzero. " LOCATION);

			clear();
			mPartyIdx = partyIdx;
			mN = n;
			mBatches = batches;
			mPrivateControls = false;

			std::unordered_map<u64, u64> map;
			mMult.init(mPartyIdx, switchCount(mN, map) * batches);
		}

		void initPrivate(u64 partyIdx, u64 controlOwner, u64 n, u64 batches = 1)
		{
			if (partyIdx > 1 || controlOwner > 1)
				throw std::invalid_argument("Waksman party indices must be zero or one. " LOCATION);
			if (n == 0 || batches == 0)
				throw std::invalid_argument("Waksman dimensions must be nonzero. " LOCATION);

			clear();
			mPartyIdx = partyIdx;
			mControlOwner = controlOwner;
			mN = n;
			mBatches = batches;
			mPrivateControls = true;
			mPrivatePrepared = false;
			mPrivateSampled = false;
			mPrivateOtOffset = 0;
			mOtIdx = 0;
			mUseInverseSessions = false;
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
			if (mPrivateControls)
			{
				std::unordered_map<u64, u64> map;
				const auto count = switchCount(mN, map) * mBatches;
				return mPartyIdx == mControlOwner ?
					BaseOtCount{ count, 0 } : BaseOtCount{ 0, count };
			}
			auto c = mMult.baseOtCount();
			return { c, c };
		}


		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			if (mPrivateControls)
			{
				const auto count = baseOtCount();
				if (baseSendOts.size() != count.mSendCount ||
					recvBaseOts.size() != count.mRecvCount ||
					baseChoices.size() != count.mRecvCount)
					throw std::invalid_argument("Private Waksman base OT count mismatch. " LOCATION);
				mPrivateSendOts.resize(baseSendOts.size());
				std::copy(baseSendOts.begin(), baseSendOts.end(), mPrivateSendOts.begin());
				mPrivateRecvOts.resize(recvBaseOts.size());
				std::copy(recvBaseOts.begin(), recvBaseOts.end(), mPrivateRecvOts.begin());
				mPrivateBaseChoices = baseChoices;
				return;
			}
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
			if (mPrivateControls)
			{
				const auto count = baseOtCount();
				return mPrivateSendOts.size() == count.mSendCount &&
					mPrivateRecvOts.size() == count.mRecvCount &&
					mPrivateBaseChoices.size() == count.mRecvCount;
			}
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

			if (mPrivateControls)
			{
				using VecF = std::remove_reference_t<decltype(data)>;
				span<VecF> batch(std::addressof(data), 1);
				co_await applyManyPrivateForward<F, VecF>(batch, sock, ctx);
				co_return;
			}
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
			if (mPrivateControls)
			{
				co_await applyManyPrivateForward<F, VecF>(data, sock, ctx);
				co_return;
			}
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

		struct PrivateNode
		{
			u64 mOffset = 0;
			u64 mSize = 0;
		};

		std::vector<std::vector<PrivateNode>> privateNodeLayers() const
		{
			std::vector<std::vector<PrivateNode>> layers;
			std::vector<PrivateNode> current{ { 0, mN } };
			while (!current.empty())
			{
				layers.push_back(current);
				std::vector<PrivateNode> next;
				for (const auto& node : current)
				{
					if (node.mSize <= 2)
						continue;
					const auto lower = node.mSize / 2;
					const auto upper = node.mSize - lower;
					if (lower > 1)
						next.push_back({ node.mOffset, lower });
					if (upper > 1)
						next.push_back({ node.mOffset + lower, upper });
				}
				current = std::move(next);
			}
			return layers;
		}

		static u64 privateLayerSwitchCount(
			span<const PrivateNode> nodes,
			bool includeCenters)
		{
			u64 count = 0;
			for (const auto& node : nodes)
				if (node.mSize > 2 || (includeCenters && node.mSize == 2))
					count += node.mSize / 2;
			return count;
		}

		template<typename F, typename CoeffCtx>
		task<> privateSplitMany(
			auto&& src,
			auto&& dst,
			auto&& diff,
			CoeffCtx context,
			span<const PrivateNode> nodes,
			bool includeCenters,
			Socket& socket)
		{
			for (u64 batch = 0; batch < mBatches; ++batch)
				for (u64 i = 0; i < mN; ++i)
					context.copy(dst[batch][i], src[batch][i]);

			auto diffIter = diff.begin();
			for (u64 batch = 0; batch < mBatches; ++batch)
				for (const auto& node : nodes)
				{
					if (node.mSize <= 1 || (!includeCenters && node.mSize == 2))
						continue;
					for (u64 pair = 0; pair < node.mSize / 2; ++pair)
					{
						const auto input = node.mOffset + 2 * pair;
						context.minus(*diffIter++, src[batch][input + 1], src[batch][input]);
					}
				}
			co_await randMultiply<F>(diff.begin(), diffIter, socket, context);

			diffIter = diff.begin();
			auto sum = context.template makeVec<F>(1);
			for (u64 batch = 0; batch < mBatches; ++batch)
				for (const auto& node : nodes)
				{
					if (node.mSize <= 1 || (!includeCenters && node.mSize == 2))
						continue;
					const auto lower = node.mSize / 2;
					for (u64 pair = 0; pair < lower; ++pair)
					{
						const auto input = node.mOffset + 2 * pair;
						const auto output0 = node.mSize == 2 ? node.mOffset : node.mOffset + pair;
						const auto output1 = node.mSize == 2 ? node.mOffset + 1 : node.mOffset + lower + pair;
						context.plus(dst[batch][output0], src[batch][input], *diffIter++);
						context.plus(sum[0], src[batch][input], src[batch][input + 1]);
						context.minus(dst[batch][output1], sum[0], dst[batch][output0]);
					}
					if (node.mSize & 1)
						context.copy(
							dst[batch][node.mOffset + node.mSize - 1],
							src[batch][node.mOffset + node.mSize - 1]);
				}
		}

		template<typename F, typename CoeffCtx>
		task<> privateMergeMany(
			auto&& src,
			auto&& dst,
			auto&& diff,
			CoeffCtx context,
			span<const PrivateNode> nodes,
			bool includeCenters,
			Socket& socket)
		{
			for (u64 batch = 0; batch < mBatches; ++batch)
				for (u64 i = 0; i < mN; ++i)
					context.copy(dst[batch][i], src[batch][i]);

			auto diffIter = diff.begin();
			for (u64 batch = 0; batch < mBatches; ++batch)
				for (const auto& node : nodes)
				{
					if (node.mSize <= 1 || (!includeCenters && node.mSize == 2))
						continue;
					const auto lower = node.mSize / 2;
					for (u64 pair = 0; pair < lower; ++pair)
					{
						const auto input0 = node.mSize == 2 ? node.mOffset : node.mOffset + pair;
						const auto input1 = node.mSize == 2 ? node.mOffset + 1 : node.mOffset + lower + pair;
						context.minus(*diffIter++, src[batch][input1], src[batch][input0]);
					}
				}
			co_await randMultiply<F>(diff.begin(), diffIter, socket, context);

			diffIter = diff.begin();
			auto sum = context.template makeVec<F>(1);
			for (u64 batch = 0; batch < mBatches; ++batch)
				for (const auto& node : nodes)
				{
					if (node.mSize <= 1 || (!includeCenters && node.mSize == 2))
						continue;
					const auto lower = node.mSize / 2;
					for (u64 pair = 0; pair < lower; ++pair)
					{
						const auto input0 = node.mSize == 2 ? node.mOffset : node.mOffset + pair;
						const auto input1 = node.mSize == 2 ? node.mOffset + 1 : node.mOffset + lower + pair;
						const auto output = node.mOffset + 2 * pair;
						context.plus(dst[batch][output], src[batch][input0], *diffIter++);
						context.plus(sum[0], src[batch][input0], src[batch][input1]);
						context.minus(dst[batch][output + 1], sum[0], dst[batch][output]);
					}
					if (node.mSize & 1)
						context.copy(
							dst[batch][node.mOffset + node.mSize - 1],
							src[batch][node.mOffset + node.mSize - 1]);
				}
		}

		template<typename F, typename VecF, typename CoeffCtx>
		task<> applyManyPrivateForward(
			span<VecF> data,
			Socket& socket,
			CoeffCtx context)
		{
			if (mBatches != data.size())
				throw RTE_LOC;
			for (auto& batch : data)
				if (batch.size() != mN)
					throw RTE_LOC;
			co_await preparePrivate(socket);
			mOtIdx = 0;
			mPrivateOtOffset = 0;
			if (mN == 1)
				co_return;

			using Vec = typename CoeffCtx::template Vec<F>;
			std::vector<Vec> temp(mBatches);
			for (auto& batch : temp)
				batch = context.template makeVec<F>(mN);
			auto diff = context.template makeVec<F>(mN * mBatches);
			const auto layers = privateNodeLayers();
			bool inTemp = false;

			for (const auto& layer : layers)
			{
				if (!inTemp)
					co_await privateSplitMany<F>(data, temp, diff, context, layer, true, socket);
				else
					co_await privateSplitMany<F>(temp, data, diff, context, layer, true, socket);
				inTemp = !inTemp;
			}
			for (u64 depth = layers.size(); depth-- > 0;)
			{
				const auto& layer = layers[depth];
				if (privateLayerSwitchCount(layer, false) == 0)
					continue;
				if (!inTemp)
					co_await privateMergeMany<F>(data, temp, diff, context, layer, false, socket);
				else
					co_await privateMergeMany<F>(temp, data, diff, context, layer, false, socket);
				inTemp = !inTemp;
			}
			if (inTemp)
				for (u64 batch = 0; batch < mBatches; ++batch)
					for (u64 i = 0; i < mN; ++i)
						context.copy(data[batch][i], temp[batch][i]);
		}

		template<typename F, typename VecF, typename CoeffCtx>
		task<> applyManyPrivateInverse(
			span<VecF> data,
			Socket& socket,
			CoeffCtx context)
		{
			if (mPrivateSessions.empty())
				throw std::runtime_error("Private Waksman inverse requires a prior forward application. " LOCATION);
			struct DirectionGuard
			{
				bool& mFlag;
				~DirectionGuard() { mFlag = false; }
			} guard{ mUseInverseSessions };
			mUseInverseSessions = true;
			mOtIdx = mPrivateSessions.size();

			using Vec = typename CoeffCtx::template Vec<F>;
			std::vector<Vec> temp(mBatches);
			for (auto& batch : temp)
				batch = context.template makeVec<F>(mN);
			auto diff = context.template makeVec<F>(mN * mBatches);
			const auto layers = privateNodeLayers();
			bool inTemp = false;

			for (const auto& layer : layers)
			{
				if (privateLayerSwitchCount(layer, false) == 0)
					continue;
				if (!inTemp)
					co_await privateSplitMany<F>(data, temp, diff, context, layer, false, socket);
				else
					co_await privateSplitMany<F>(temp, data, diff, context, layer, false, socket);
				inTemp = !inTemp;
			}
			for (u64 depth = layers.size(); depth-- > 0;)
			{
				const auto& layer = layers[depth];
				if (!inTemp)
					co_await privateMergeMany<F>(data, temp, diff, context, layer, true, socket);
				else
					co_await privateMergeMany<F>(temp, data, diff, context, layer, true, socket);
				inTemp = !inTemp;
			}
			if (inTemp)
				for (u64 batch = 0; batch < mBatches; ++batch)
					for (u64 i = 0; i < mN; ++i)
						context.copy(data[batch][i], temp[batch][i]);
			if (mOtIdx != 0)
				throw RTE_LOC;
		}

		struct PrivateProgramState
		{
			BitVector* mControls = nullptr;
			u64 mBatch = 0;
			std::vector<u64> mLeftCount;
			std::vector<u64> mRightCount;
			std::vector<u64> mLeftBase;
			std::vector<u64> mRightBase;
			std::vector<u64> mLeftCursor;
			std::vector<u64> mRightCursor;
			std::vector<u32> mInverse;
			std::vector<u32> mQueue;
			std::vector<i8> mColor;
		};

		static void writePrivateControl(
			PrivateProgramState& state,
			u64 depth,
			bool right,
			u8 control)
		{
			auto& cursor = right ? state.mRightCursor : state.mLeftCursor;
			const auto& count = right ? state.mRightCount : state.mLeftCount;
			const auto& base = right ? state.mRightBase : state.mLeftBase;
			if (depth >= count.size() || cursor[depth] >= count[depth])
				throw RTE_LOC;
			(*state.mControls)[
				base[depth] + state.mBatch * count[depth] + cursor[depth]++] = control;
		}

		static void programPrivateRecursiveFlat(
			u32* permutation,
			u32* childPermutation,
			u64 offset,
			u64 n,
			u64 depth,
			PrivateProgramState& state)
		{
			if (n <= 1)
				return;
			if (n == 2)
			{
				const auto first = permutation[offset];
				const auto second = permutation[offset + 1];
				if (first > 1 || second > 1 || first == second)
					throw RTE_LOC;
				writePrivateControl(state, depth, false, static_cast<u8>(first));
				return;
			}

			auto* inverse = state.mInverse.data();
			auto* color = state.mColor.data();
			auto* queue = state.mQueue.data();
			std::fill_n(inverse, n, static_cast<u32>(n));
			std::fill_n(color, n, static_cast<i8>(-1));
			for (u32 input = 0; input < n; ++input)
			{
				const auto output = permutation[offset + input];
				if (output >= n || inverse[output] != n)
					throw std::invalid_argument("Waksman programming requires a permutation. " LOCATION);
				inverse[output] = input;
			}

			auto assignComponent = [&](u32 start, i8 initial)
			{
				if (color[start] != -1)
				{
					if (color[start] != initial)
						throw RTE_LOC;
					return;
				}
				u64 head = 0;
				u64 tail = 0;
				color[start] = initial;
				queue[tail++] = start;
				while (head != tail)
				{
					const auto current = queue[head++];
					const auto required = static_cast<i8>(color[current] ^ 1);
					auto visit = [&](u32 next)
					{
						if (color[next] == -1)
						{
							color[next] = required;
							queue[tail++] = next;
						}
						else if (color[next] != required)
							throw RTE_LOC;
					};

					const auto inputMate = current ^ 1;
					if (inputMate < n)
						visit(inputMate);
					const auto output = permutation[offset + current];
					const auto outputMate = output ^ 1;
					if (outputMate < n)
						visit(inverse[outputMate]);
				}
			};

			if (n & 1)
			{
				assignComponent(static_cast<u32>(n - 1), 1);
				assignComponent(inverse[n - 1], 1);
			}
			for (u32 token = 0; token < n; ++token)
				if (color[token] == -1)
					assignComponent(token, 0);

			const auto lower = n / 2;
			const auto upper = n - lower;
			for (u64 pair = 0; pair < lower; ++pair)
			{
				writePrivateControl(state, depth, false, static_cast<u8>(color[2 * pair]));
				writePrivateControl(state, depth, true, static_cast<u8>(color[inverse[2 * pair]]));
			}
			for (u32 token = 0; token < n; ++token)
			{
				const auto child = static_cast<u64>(color[token]);
				const auto childSize = child ? upper : lower;
				const auto childInput = static_cast<u64>(token / 2);
				const auto childOutput = static_cast<u64>(permutation[offset + token] / 2);
				if (childInput >= childSize || childOutput >= childSize)
					throw RTE_LOC;
				childPermutation[offset + (child ? lower : 0) + childInput] =
					static_cast<u32>(childOutput);
			}

			programPrivateRecursiveFlat(
				childPermutation, permutation, offset, lower, depth + 1, state);
			programPrivateRecursiveFlat(
				childPermutation, permutation, offset + lower, upper, depth + 1, state);
		}

		void samplePrivatePermutations(PRNG& prng)
		{
			if (!mPrivateControls)
				throw RTE_LOC;
			if (mPrivateSampled)
				return;
			if (mPartyIdx != mControlOwner)
			{
				mPrivateSampled = true;
				return;
			}

			const auto layers = privateNodeLayers();
			const auto stages = layers.size();
			PrivateProgramState state;
			state.mControls = &mPrivateControlsBits;
			state.mLeftCount.resize(stages);
			state.mRightCount.resize(stages);
			state.mLeftBase.resize(stages);
			state.mRightBase.resize(stages);
			state.mLeftCursor.resize(stages);
			state.mRightCursor.resize(stages);
			state.mInverse.resize(mN);
			state.mQueue.resize(mN);
			state.mColor.resize(mN);
			for (u64 depth = 0; depth < stages; ++depth)
			{
				state.mLeftCount[depth] = privateLayerSwitchCount(layers[depth], true);
				state.mRightCount[depth] = privateLayerSwitchCount(layers[depth], false);
			}

			u64 offset = 0;
			for (u64 depth = 0; depth < stages; ++depth)
			{
				state.mLeftBase[depth] = offset;
				offset += state.mLeftCount[depth] * mBatches;
			}
			for (u64 depth = stages; depth-- > 0;)
			{
				state.mRightBase[depth] = offset;
				offset += state.mRightCount[depth] * mBatches;
			}
			std::unordered_map<u64, u64> map;
			const auto expected = switchCount(mN, map) * mBatches;
			if (offset != expected)
				throw RTE_LOC;
			mPrivateControlsBits.resize(expected);

			mPrivatePermutations.resize(mBatches);
			std::vector<u32> work0(mN);
			std::vector<u32> work1(mN);
			for (u64 batch = 0; batch < mBatches; ++batch)
			{
				auto& permutation = mPrivatePermutations[batch];
				permutation.resize(mN);
				std::iota(permutation.begin(), permutation.end(), 0);
				std::shuffle(permutation.begin(), permutation.end(), prng);
				std::copy(permutation.begin(), permutation.end(), work0.begin());
				std::fill(state.mLeftCursor.begin(), state.mLeftCursor.end(), 0);
				std::fill(state.mRightCursor.begin(), state.mRightCursor.end(), 0);
				state.mBatch = batch;
				programPrivateRecursiveFlat(
					work0.data(), work1.data(), 0, mN, 0, state);
				if (state.mLeftCursor != state.mLeftCount ||
					state.mRightCursor != state.mRightCount)
					throw RTE_LOC;
			}
			mPrivateSampled = true;
		}

		task<> preparePrivate(Socket& socket)
		{
			if (!mPrivateControls || mPrivatePrepared)
				co_return;
			if (!hasBaseOts())
				throw RTE_LOC;
			std::unordered_map<u64, u64> map;
			const auto count = switchCount(mN, map) * mBatches;
			if (count == 0)
			{
				mPrivatePrepared = true;
				co_return;
			}
			const auto bytes = divCeil(count, 8);
			AlignedUnVector<u8> phi(bytes);
			std::fill(phi.begin(), phi.end(), 0);
			if (mPartyIdx == mControlOwner)
			{
				if (!mPrivateSampled || mPrivateControlsBits.size() != count ||
					mPrivateBaseChoices.size() != count)
					throw RTE_LOC;
				for (u64 i = 0; i < count; ++i)
					phi[i / 8] |= static_cast<u8>(
						(mPrivateControlsBits[i] ^ mPrivateBaseChoices[i]) << (i % 8));
				co_await socket.send(std::move(phi));
			}
			else
			{
				co_await socket.recv(phi);
				if (phi.size() != bytes || mPrivateSendOts.size() != count)
					throw RTE_LOC;
				for (u64 i = 0; i < count; ++i)
					if ((phi[i / 8] >> (i % 8)) & 1)
						std::swap(mPrivateSendOts[i][0], mPrivateSendOts[i][1]);
			}
			mPrivatePrepared = true;
		}

		const std::vector<u32>& privatePermutation(u64 batch) const
		{
			if (mPartyIdx != mControlOwner || batch >= mPrivatePermutations.size())
				throw RTE_LOC;
			return mPrivatePermutations[batch];
		}

		// Apply the inverse of the previously sampled hidden permutation.
		//
		// A forward Waksman pass stores one multiplication session for each
		// switch layer. Every switch is an involution. The inverse network is
		// therefore obtained by traversing those sessions in reverse order and
		// exchanging split layers with merge layers.
		template<typename F, typename VecF, typename CoeffCtx>
		task<> applyManyInverse(
			span<VecF> data,
			Socket& sock,
			CoeffCtx ctx)
		{
			if (mBatches != data.size())
				throw std::runtime_error("WaksmanPermute::applyManyInverse: Batches != data.size(). " LOCATION);

			const auto n = mN;
			for (auto& d : data)
				if (d.size() != n)
					throw RTE_LOC;
			if (n == 1)
				co_return;
			if (mPrivateControls)
			{
				co_await applyManyPrivateInverse<F, VecF>(data, sock, ctx);
				co_return;
			}
			if (mMultSessions.empty())
				throw std::runtime_error("WaksmanPermute::applyManyInverse requires a prior forward application. " LOCATION);

			struct DirectionGuard
			{
				bool& mFlag;
				~DirectionGuard() { mFlag = false; }
			} guard{ mUseInverseSessions };
			mUseInverseSessions = true;
			mOtIdx = mMultSessions.size();

			const auto numStages = log2ceil(n);
			std::vector<u64> subnetSizes(1ull << numStages);
			std::vector<u64> nextSubnetSizes(1ull << numStages);
			u64 numSubnets = 2;
			u64 nextNumSubnets = 0;
			subnetSizes[0] = n / 2;
			subnetSizes[1] = n - n / 2;

			using Vec = typename CoeffCtx::template Vec<F>;
			std::vector<Vec> temp(data.size());
			Vec diff = ctx.template makeVec<F>(mN * mBatches);
			for (u64 i = 0; i < data.size(); ++i)
				temp[i] = ctx.template makeVec<F>(data[i].size());

			u64 stageBit = 0;
			// Undo the forward merge layers, from the output inward.
			for (u64 stage = 0; stage + 1 < numStages; ++stage)
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

			// Undo the forward split layers and merge back to the input order.
			for (u64 stage = 0; stage < numStages; ++stage)
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
			}

			if (mOtIdx != 0)
				throw RTE_LOC;
			if (stageBit)
			{
				for (u64 batch = 0; batch < data.size(); ++batch)
					for (u64 i = 0; i < data[batch].size(); ++i)
						ctx.copy(data[batch][i], temp[batch][i]);
			}
		}

		template<typename F, typename CoeffCtx>
		task<> applyInverse(
			auto&& data,
			Socket& sock,
			CoeffCtx ctx)
		{
			if (mBatches != 1)
				throw std::runtime_error("WaksmanPermute::applyInverse: Batches != 1. " LOCATION);
			using VecF = std::remove_reference_t<decltype(data)>;
			span<VecF> batch(std::addressof(data), 1);
			co_await applyManyInverse<F, VecF>(batch, sock, ctx);
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
			if (mPrivateControls)
			{
				if (!mPrivatePrepared)
					throw RTE_LOC;
				if (mUseInverseSessions)
				{
					if (mOtIdx == 0)
						throw RTE_LOC;
					const auto idx = --mOtIdx;
					co_await mPrivateSessions[idx].multiply<F>(begin, end, begin, sock, ctx);
					co_return;
				}

				if (mPrivateSessions.size() == mOtIdx)
				{
					const auto size = static_cast<u64>(std::distance(begin, end));
					PrivateMultSession session;
					session.mPartyIdx = mPartyIdx;
					session.mOwner = mControlOwner;
					if (mPartyIdx == mControlOwner)
					{
						if (mPrivateOtOffset + size > mPrivateRecvOts.size() ||
							mPrivateOtOffset + size > mPrivateControlsBits.size())
							throw RTE_LOC;
						session.mRecvOts = span<block>(mPrivateRecvOts.data() + mPrivateOtOffset, size);
						session.mControls.append(mPrivateControlsBits, size, mPrivateOtOffset);
					}
					else
					{
						if (mPrivateOtOffset + size > mPrivateSendOts.size())
							throw RTE_LOC;
						session.mSendOts = span<std::array<block, 2>>(
							mPrivateSendOts.data() + mPrivateOtOffset, size);
					}
					mPrivateOtOffset += size;
					mPrivateSessions.push_back(std::move(session));
				}

				if (mPrivateSessions.size() <= mOtIdx)
					throw RTE_LOC;
				const auto idx = mOtIdx++;
				co_await mPrivateSessions[idx].multiply<F>(begin, end, begin, sock, ctx);
				co_return;
			}

			if (mUseInverseSessions)
			{
				if (mOtIdx == 0)
					throw RTE_LOC;
				auto idx = --mOtIdx;
				co_await mMultSessions[idx].multiply<F>(begin, end, begin, sock, ctx);
				co_return;
			}

			if (mMultSessions.size() == mOtIdx)
			{
				auto size = std::distance(begin, end);
				mMultSessions.push_back(mMult.randMultiply(size));
			}

			if (mMultSessions.size() <= mOtIdx)
				throw RTE_LOC;

			auto idx = mOtIdx++;
			co_await mMultSessions[idx].multiply<F>(begin, end, begin, sock, ctx);

		}

		void clear()
		{
			mMult.clear();
			mMultSessions.clear();
			mPrivateRecvOts.clear();
			mPrivateSendOts.clear();
			mPrivateBaseChoices.reset(0);
			mPrivateControlsBits.reset(0);
			mPrivatePermutations.clear();
			mPrivateSessions.clear();
			mPrivateControls = false;
			mPrivatePrepared = false;
			mPrivateSampled = false;
			mPrivateOtOffset = 0;
			mOtIdx = 0;
			mUseInverseSessions = false;
			mPartyIdx = 0;
			mControlOwner = 0;
			mBatches = 0;
			mN = 0;
		}
	};

}
