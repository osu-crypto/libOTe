#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include <vector>
#include <algorithm>
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Dpf/DpfMult.h"

namespace osuCrypto
{

	struct WaksmanPermute
	{

		u64 mPartyIdx = 0;

		u64 mN = 0;

		DpfMult mMult;

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
		}



		template<typename R>
		void apply(MatrixView<u8> data, R&& ctrl)
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





		task<> apply(MatrixView<u8> data, block seed, Socket& sock)
		{
			auto print = false;
			auto n = mN;
			if (data.rows() != mN)
				throw RTE_LOC;

			u64 numStages = log2ceil(n);
			std::vector<u64> subnetSizes{ n };
			std::vector<u64> nextSubnetSizes;
			subnetSizes.reserve(n);
			nextSubnetSizes.reserve(n);
			Matrix<u8> temp(data.rows(), data.cols());
			Matrix<u8> diff(data.rows() / 2, data.cols());
			std::vector<u8> ctrlBits(divCeil(diff.rows(), 8));
			MatrixView<u8> src = data;
			MatrixView<u8> dst = temp;

			PRNG prng(seed);

			// process all left columns/stages
			for (u64 stage = 0; stage < numStages; ++stage)
			{
				diff.resize(data.rows(), data.cols());
				//setBytes(dst, 0xcc * mPartyIdx);
				auto numSubnets = subnetSizes.size();
				u64 idx = 0;
				u64 dIdx = 0;
				for (u64 subnetIdx = 0;
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

					for (u64 i = 0; i + 1 < size; i += 2)
					{
						auto v0 = input[i];
						auto v1 = input[i + 1];
						auto d = diff[dIdx++];
						for (u64 j = 0; j < v0.size(); ++j)
							d[j] = v0[j] ^ v1[j];
					}
				}


				diff.resize(dIdx, diff.cols());
				ctrlBits.resize(divCeil(diff.rows(), 8));
				prng.get(ctrlBits.data(), ctrlBits.size());

				// diff = ctrl * (input[2i] ^ input[2i+1]);
				co_await mMult.multiply(diff.cols() * 8, ctrlBits, diff, diff, sock);

				idx = 0;
				dIdx = 0;
				for (u64 subnetIdx = 0;
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

					for (u64 i = 0; i + 1 < size; i += 2)
					{
						auto v0 = input[i];
						auto v1 = input[i + 1];
						auto d = diff[dIdx++];
						auto d0 = output0[i / 2];
						auto d1 = output1[i / 2];
						for (u64 j = 0; j < v0.size(); ++j)
						{
							// d0 = ctrl * (input[2i] ^ input[2i+1]) ^ input[2i]
							//    = ctrl ? input[2i+1] : input[2i]
							d0[j] = d[j] ^ v0[j];

							// d1 = d0 ^ input[2i] ^ input[2i+1]
							//    = ctrl ? input[2i] : input[2i+1]
							d1[j] = v0[j] ^ v1[j] ^ d0[j];
						}
					}

					if (size & 1)
					{
						copyBytes(output1[size / 2], input[size - 1]);
					}
				}

				if(print)
				{
					Matrix<u8> D = dst;
					co_await sock.send(coproto::copy(D));
					co_await sock.recv(D);
					for (u64 i = 0; i < data.size(); ++i)
						D(i) ^= dst(i);
					if (mPartyIdx == 0)
					{
						std::cout << "stage " << stage << " " << D.rows() << std::endl;
						for (u64 i = 0; i < D.rows(); ++i)
						{
							std::cout << "D[" << i << "]: " << toHex(D[i]) << std::endl;
						}
					}
				}

				std::swap(src, dst);
				std::swap(subnetSizes, nextSubnetSizes);
				nextSubnetSizes.clear();
			}

			for (u64 stage = numStages - 2; stage < numStages; --stage)
			{
				diff.resize(data.rows(), data.cols());
				u64 dIdx = 0;
				//setBytes(dst, 0xcc * mPartyIdx);

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
						auto v0 = input0[i / 2];
						auto v1 = input1[i / 2];
						auto d = diff[dIdx++];
						for (u64 j = 0; j < v0.size(); ++j)
						{
							d[j] = v0[j] ^ v1[j];
						}
					}
				}
				diff.resize(dIdx, diff.cols());
				ctrlBits.resize(divCeil(diff.rows(), 8));
				prng.get(ctrlBits.data(), ctrlBits.size());

				//if (mPartyIdx == 0)
				//	std::cout << "stage " << stage << " " << diff.rows() << std::endl;

				if (diff.rows() + mMult.mOtIdx > mMult.mTotalMults)
					throw RTE_LOC;

				co_await mMult.multiply(diff.cols() * 8, ctrlBits, diff, diff, sock);
				dIdx = 0;

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

					for (u64 i = 0; i + 1 < size0 + size1; i += 2)
					{

						auto v0 = input0[i / 2];
						auto v1 = input1[i / 2];
						auto d = diff[dIdx++];
						auto d0 = output[i + 0];
						auto d1 = output[i + 1];
						for (u64 j = 0; j < v0.size(); ++j)
						{
							// d0 = ctrl * (input[2i] ^ input[2i+1]) ^ input[2i]
							//    = ctrl ? input[2i+1] : input[2i]
							d0[j] = d[j] ^ v0[j];

							// d1 = d0 ^ input[2i] ^ input[2i+1]
							//    = ctrl ? input[2i] : input[2i+1]
							d1[j] = v0[j] ^ v1[j] ^ d0[j];
						}
					}

					if (size0 != size1)
					{
						copyBytes(output[size1 + size0 - 1], input1[size1 - 1]);
					}
				}

				if (print)
				{
					Matrix<u8> D = dst;
					co_await sock.send(coproto::copy(D));
					co_await sock.recv(D);
					for (u64 i = 0; i < data.size(); ++i)
						D(i) ^= dst(i);
					if (mPartyIdx == 0)
					{
						std::cout << "stage " << stage << " " << D.rows() << std::endl;
						for (u64 i = 0; i < D.rows(); ++i)
						{
							std::cout << "D[" << i << "]: " << toHex(D[i]) << std::endl;
						}
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

	};

}