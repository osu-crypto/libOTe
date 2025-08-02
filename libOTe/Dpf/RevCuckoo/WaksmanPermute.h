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

		DpfMult mMult;
		std::vector<DpfMult::MultSession> mMultSessions;

		u64 mOtIdx = 0;

		bool print = false;

		void init(u64 partyIdx, u64 n)
		{
			if (partyIdx > 1)
				throw std::runtime_error("GoldreichHash: partyIdx must be 0 or 1. " LOCATION);
			if (n == 0)
				throw std::runtime_error("GoldreichHash: n must be > 0. " LOCATION);

			mPartyIdx = partyIdx;
			mN = n;

			std::unordered_map<u64, u64> map;
			mMult.init(mPartyIdx, switchCount(mN, map));
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


		template<typename R>
		void applyPlain(MatrixView<u8> data, R&& ctrl)
		{

			u64 n = data.rows();
			u64 numStages = log2ceil(n);
			std::vector<u64> subnetSizes{ n };
			std::vector<u64> nextSubnetSizes;
			subnetSizes.reserve(n);
			nextSubnetSizes.reserve(n);
			Matrix<u8> temp(data.rows(), data.cols());
			MatrixView<u8> src = data;
			MatrixView<u8> dst = temp;

			// process all left columns/stages
			for (u64 stage = 0; stage < numStages; ++stage)
			{
				auto numSubnets = subnetSizes.size();
				for (u64 subnetIdx = 0, idx = 0;
					subnetIdx < numSubnets;
					++subnetIdx)
				{
					auto size = subnetSizes[subnetIdx];
					MatrixView<u8> input(src.data(idx),
						size,
						src.cols());

					MatrixView<u8> output0(
						dst.data(idx),
						size / 2,
						src.cols()
					);

					MatrixView<u8> output1(
						dst.data(idx + size / 2),
						size - size / 2,
						src.cols()
					);

					idx += input.rows();
					nextSubnetSizes.push_back(output0.rows());
					nextSubnetSizes.push_back(output1.rows());

					for (u64 i = 0; i + 1 < subnetSizes[subnetIdx]; i += 2)
					{
						auto s = ctrl();
						auto v0 = input[i];
						auto v1 = input[i + 1];
						if (s)
						{
							std::swap_ranges(v0.begin(), v0.end(), v1.begin());
						}

						copyBytes(output0[i / 2], v0);
						copyBytes(output1[i / 2], v1);
					}

					if (size & 1)
					{
						copyBytes(output1[size / 2], input[size - 1]);
					}
				}


				std::swap(src, dst);
				std::swap(subnetSizes, nextSubnetSizes);
				nextSubnetSizes.clear();
			}

			for (u64 stage = numStages - 2; stage < numStages; --stage)
			{
				auto numSubnets = subnetSizes.size();
				for (u64 subnetIdx = 0, idx = 0;
					subnetIdx < numSubnets;
					subnetIdx += 2)
				{
					auto size0 = subnetSizes[subnetIdx];
					auto size1 = subnetSizes[subnetIdx + 1];
					MatrixView<u8> input0(
						src.data(idx),
						size0,
						src.cols()
					);

					MatrixView<u8> input1(
						src.data(idx + size0),
						size1,
						src.cols()
					);

					MatrixView<u8> output(dst.data(idx),
						size0 + size1,
						src.cols());

					idx += size0 + size1;
					nextSubnetSizes.push_back(size0 + size1);

					for (u64 i = 0; i + 1 < size0 + size1; i += 2)
					{
						auto s = ctrl();
						auto v0 = input0[i / 2];
						auto v1 = input1[i / 2];
						if (s)
						{
							std::swap_ranges(v0.begin(), v0.end(), v1.begin());
						}

						copyBytes(output[i + 0], v0);
						copyBytes(output[i + 1], v1);
					}

					if (size0 != size1)
					{
						copyBytes(output[size1 + size0 - 1], input1[size1 - 1]);
					}
				}

				std::swap(src, dst);
				std::swap(subnetSizes, nextSubnetSizes);
				nextSubnetSizes.clear();
			}

			if (src.data() != data.data())
			{
				copyBytes(data, src);
			}
		}

		template<typename F, typename CoeffCtx>
		task<> left(auto&& src, auto&& dst, auto&& diff, CoeffCtx ctx,
			std::vector<u64>& subnetSizes,
			std::vector<u64>& nextSubnetSizes,
			Socket& sock)
		{
			auto numSubnets = subnetSizes.size();
			u64 idx = 0;
			u64 dIdx = 0;

			for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
			{
				auto size = subnetSizes[subnetIdx];

				auto inputBegin = src.begin() + idx;
				auto output0Begin = dst.begin() + idx;
				auto output1Begin = output0Begin + size / 2;

				idx += size;
				nextSubnetSizes.push_back(size / 2);
				nextSubnetSizes.push_back(size - size / 2);

				// Collect differences for this subnet
				for (u64 i = 0; i + 1 < size; i += 2)
				{
					// Expand diff if needed
					if (dIdx >= diff.size())
					{
						ctx.resize(diff, dIdx + 1);
					}

					// diff = input[1] - input[0]
					ctx.minus(diff[dIdx++], inputBegin[i + 1], inputBegin[i]);
				}
			}

			// Multiply differences with random bits
			ctx.resize(diff, dIdx);
			co_await randMultiply<F>(diff, diff, sock, ctx);

			// Apply the multiplied differences
			idx = 0;
			dIdx = 0;
			for (u64 subnetIdx = 0; subnetIdx < numSubnets; ++subnetIdx)
			{
				auto size = subnetSizes[subnetIdx];
				auto inputBegin = src.begin() + idx;
				auto output0Begin = dst.begin() + idx;
				auto output1Begin = output0Begin + size / 2;

				idx += size;

				for (u64 i = 0; i + 1 < size; i += 2)
				{
					// output0 = ctrl * (input[1]-input[0]) + input[0]
					//         = input[ctrl]
					ctx.plus(output0Begin[i / 2], inputBegin[i], diff[dIdx]);

					// output1 = (input[0]+input[1]) - output0
					//         = input[!ctrl]
					auto temp_val = ctx.template make<F>();
					ctx.plus(temp_val, inputBegin[i], inputBegin[i + 1]);
					ctx.minus(output1Begin[i / 2], temp_val, output0Begin[i / 2]);

					dIdx++;
				}

				if (size & 1)
				{
					ctx.copy(output1Begin[size / 2], inputBegin[size - 1]);
				}
			}

			if (print)
			{
				// Debug output - would need to be adapted for generic types
				// Skipping for now as it requires type-specific serialization
			}

		}


		template<typename F, typename CoeffCtx>
		task<> right(auto&& src, auto&& dst, auto&& diff, CoeffCtx ctx,
			std::vector<u64>& subnetSizes,
			std::vector<u64>& nextSubnetSizes,
			Socket& sock)
		{

			u64 dIdx = 0;
			ctx.resize(diff, 0);

			auto numSubnets = subnetSizes.size();
			for (u64 subnetIdx = 0, idx = 0; subnetIdx < numSubnets; subnetIdx += 2)
			{
				auto size0 = subnetSizes[subnetIdx];
				auto size1 = subnetSizes[subnetIdx + 1];

				auto input0Begin = src.begin() + idx;
				auto input1Begin = input0Begin + size0;

				idx += size0 + size1;
				nextSubnetSizes.push_back(size0 + size1);

				// Collect differences
				for (u64 i = 0; i + 1 < size0 + size1; i += 2)
				{
					if (dIdx >= diff.size())
					{
						ctx.resize(diff, dIdx + 1);
					}

					ctx.minus(diff[dIdx++], input1Begin[i / 2], input0Begin[i / 2]);
				}
			}

			ctx.resize(diff, dIdx);
			co_await randMultiply<F>(diff, diff, sock, ctx);

			dIdx = 0;
			for (u64 subnetIdx = 0, idx = 0; subnetIdx < numSubnets; subnetIdx += 2)
			{
				auto size0 = subnetSizes[subnetIdx];
				auto size1 = subnetSizes[subnetIdx + 1];

				auto input0Begin = src.begin() + idx;
				auto input1Begin = input0Begin + size0;
				auto outputBegin = dst.begin() + idx;

				idx += size0 + size1;

				for (u64 i = 0; i + 1 < size0 + size1; i += 2)
				{
					// output[i] = ctrl * (input1[i/2] - input0[i/2]) + input0[i/2]
					//           = input[ctrl][i/2]
					ctx.plus(outputBegin[i], input0Begin[i / 2], diff[dIdx]);

					// output[i+1] = (input0[i/2] + input1[i/2]) - output[i]
					//             = input[!ctrl][i/2]
					auto temp_val = ctx.template make<F>();
					ctx.plus(temp_val, input0Begin[i / 2], input1Begin[i / 2]);
					ctx.minus(outputBegin[i + 1], temp_val, outputBegin[i]);

					dIdx++;
				}

				if (size0 != size1)
				{
					ctx.copy(outputBegin[size0 + size1 - 1], input1Begin[size1 - 1]);
				}
			}

		}

		template<typename F, typename CoeffCtx = DefaultCoeffCtx<F>>
		task<> apply(
			auto&& data,
			Socket& sock,
			CoeffCtx ctx = {})
		{
			mOtIdx = 0;
			auto print = false;
			auto n = mN;
			if (data.size() != mN)
				throw RTE_LOC;

			u64 numStages = log2ceil(n);
			std::vector<u64> subnetSizes{ n };
			std::vector<u64> nextSubnetSizes;
			subnetSizes.reserve(n);
			nextSubnetSizes.reserve(n);

			auto temp = ctx.template makeVec<F>(data.size());
			ctx.resize(temp, data.size());

			// diff = input[1] - input[0]
			auto diff = ctx.template makeVec<F>(data.size());
			u64 stageBit = 0;
			//auto* src = data;
			//auto* dst = temp;

			// process all left columns/stages
			for (u64 stage = 0; stage < numStages; ++stage)
			{
				if (stageBit == 0)
					co_await left<F>(data, temp, diff, ctx, subnetSizes, nextSubnetSizes, sock);
				else
					co_await left<F>(temp, data, diff, ctx, subnetSizes, nextSubnetSizes, sock);

				stageBit ^= 1;
				std::swap(subnetSizes, nextSubnetSizes);
				nextSubnetSizes.clear();
			}

			// Right stages (reverse)
			for (u64 stage = numStages - 2; stage < numStages; --stage)
			{

				if (stageBit == 0)
					co_await right<F>(data, temp, diff, ctx, subnetSizes, nextSubnetSizes, sock);
				else
					co_await right<F>(temp, data, diff, ctx, subnetSizes, nextSubnetSizes, sock);

				stageBit ^= 1;
				std::swap(subnetSizes, nextSubnetSizes);
				nextSubnetSizes.clear();
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



		// Multiply each input vector with a random bit using existing choice bits.
		// Does not take control bits as input - uses internal mMult choice bits directly.
		template<typename F>
		task<> randMultiply(
			auto&& y,
			auto&& xy,
			coproto::Socket& sock,
			auto&& ctx)
		{
			if (mMultSessions.size() == mOtIdx)
			{
				mMultSessions.push_back(mMult.randMultiply(y.size()));
			}

			if (mMultSessions.size() <= mOtIdx)
				throw RTE_LOC;

			co_await mMultSessions[mOtIdx++].multiply<F>(y, xy, sock, ctx);

		}
	};

}