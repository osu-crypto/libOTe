#pragma once


#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{

	struct SparseDpf
	{
		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		struct Point
		{
			// the point's true address
			u32 mAddress;

			// the number of points before this point.
			u32 mFinalRank;
		};

		BitVector reverse(BitVector b)
		{
			BitVector r(b.size());
			for (u64 i = 0; i < b.size(); ++i)
				r[r.size() - 1 - i] = b[i];
			return r;
		}
		std::string print(u32 p, u32 bitCount)
		{
			auto low = reverse(BitVector((u8*)&p, bitCount));
			auto hgh = reverse(BitVector((u8*)&p, 32 - bitCount, bitCount));
			std::stringstream ss;
			ss << hgh << "." << low;
			return ss.str();
		}

		// For the given Expand node, mDepth[0] is how far down the 
		// expanded left child should be copied. mDepth[1] is how far down the
		// expanded right child should be copied.
		//
		// 0 indicates that it is a final node and should be copied to the
		// final output.
		struct Expand
		{
			std::array<u8, 2> mDepth;
		};

		enum class Initial
		{
			None,
			Final,
			Expand
		};

		bool mDebug = true;
		std::vector<std::vector<Initial>> mInitals;
		std::vector<std::vector<std::vector<u32>>> mFinals;
		std::vector<std::vector<std::vector<Expand>>> mExpands;


		// A partition represents a path of mDepth degree 1 nodes
		// followed a degree 2 node. e.g.
		//  *		 <| 0
		//   *		 <| 1
		//    *		 <| 2
		//   * *
		// This would have depth 2.  A partition also
		// contains two sets of points that are under 
		// the left and right subtree.
		struct Partition
		{
			// The sets of points that are contained in the left and right subtree.
			std::array<span<u32>, 2> mSets;

			// The number of degree 1 nodes that lead to the degree 2 node.
			u32 mDepth;

			//u32 mPrefix;

			u32 mLowBitCount;
		};

		Partition partition(span<u32> points, u32 lowBitCount)
		{
#ifndef NDEBUG
			u32 prefix = points[0] >> (lowBitCount + 1);
			for (auto pp : points)
				if (pp >> (lowBitCount + 1) != prefix)
					throw RTE_LOC;
#endif

			assert(points.size() > 1);
			auto iter = std::find_if(points.begin(), points.end(), [lowBitCount](auto v) {return (v >> lowBitCount) & 1; });
			if (iter == points.begin() || iter == points.end())
			{
				assert(lowBitCount);
				auto p = partition(points, lowBitCount - 1);
				++p.mDepth;
				return p;
			}

			return Partition{
				.mSets{ span<u32>(points.begin(), iter), span<u32>(iter, points.end()) },
				.mDepth{0},
				.mLowBitCount = lowBitCount };
		}

		void getLevels(Partition& par, u64 treeIdx, span<u32> points)
		{
			std::cout << "-> {";
			for (auto j = 0; j < 2; ++j)
			{
				if (j)
					std::cout << ',' << std::endl;
				else
					std::cout << std::endl;

				for (auto p : par.mSets[j])
				{
					std::cout << print(p, par.mLowBitCount) << std::endl;
				}
			}
			std::cout << "}" << std::endl;

			Expand expand;
			for (u64 i = 0; i < 2; ++i)
			{
				if (par.mSets[i].size() == 1)
				{
					auto idx = std::distance(points.data(), &par.mSets[i][0]);
					mFinals[treeIdx][par.mLowBitCount].push_back(idx);
					expand.mDepth[i] = 0;
					//expand = (Expand)((u8)i | (u8)expand);
				}
				else
				{

					//  *	 <| par	
					//   *	 <|	
					//    *	 <|	
					//   * *     <| p2
					//      *    <|
					//       *   <|
					//      * *

					assert(par.mSets[i].size());
					auto bIdx2 = par.mLowBitCount - 1 - par.mDepth;
					auto p2 = partition(par.mSets[i], bIdx2);
					getLevels(p2, treeIdx, points);
					expand.mDepth[i] = p2.mDepth + 1;
					//expand.mOutputs[i] = Address{ .mLevel{bIdx2}, .mIndex{mSizes[treeIdx][bIdx2]++} };
				}
			}
			mExpands[treeIdx][par.mLowBitCount].push_back(expand);
		}


		void init(
			u64 partyIdx,
			u64 domain,
			MatrixView<u32> sparsePoints)
		{
			mPartyIdx = partyIdx;
			mDomain = domain;

			auto depth = log2ceil(domain);
			auto preDepth = log2ceil(sparsePoints.cols());
			auto preDomain = 1ull << preDepth;
			auto bitCount = depth - preDepth;
			auto shift = bitCount - 1;
			u32 mask = (1ull << bitCount) - 1;

			mExpands.resize(sparsePoints.rows());
			mFinals.resize(sparsePoints.rows());
			mInitals.resize(sparsePoints.rows());

			for (u64 r = 0; r < sparsePoints.rows(); ++r)
			{
				assert(std::is_sorted(sparsePoints[r].begin(), sparsePoints[r].end()));

				mInitals[r].resize(preDomain);
				mExpands[r].resize(bitCount);
				mFinals[r].resize(bitCount + 1);
				std::vector<span<u32>> points(preDomain);
				auto iter = sparsePoints[r].begin();
				while (iter != sparsePoints[r].end())
				{
					auto p = *iter;
					auto idx = p >> bitCount;
					auto end = std::find_if(iter, sparsePoints[r].end(), [idx, bitCount](auto v) {return (v >> bitCount) != idx; });
					points[idx] = span<u32>(iter, end);
					iter = end;
				}
				for (u64 c = 0; c < sparsePoints.cols(); ++c)
				{
					std::cout << "(" << sparsePoints(r, c) << ", " << c << ") ";
				}
				std::cout << std::endl;

				for (u32 c = 0; c < points.size(); ++c)
				{
					std::cout << " group " << c << std::endl;
					//std::sort(points[c].begin(), points[c].end(), [](auto& a, auto& b) {return a.mAddress < b.mAddress; });
					for (auto p : points[c])
					{
						std::cout << print(p, bitCount) << std::endl;
					}

					if (points[c].size() == 1)
					{
						mInitals[r][c] = Initial::Final;
						auto idx = std::distance(sparsePoints.data(), &points[c][0]);
						mFinals[r].back().push_back(points[c][0]);
					}
					else if (points[c].size() > 1)
					{
						mInitals[r][c] = Initial::Expand;
						auto par = partition(points[c], bitCount - 1);
						getLevels(par, r, sparsePoints);
					}
					else
					{
						mInitals[r][c] = Initial::None;
					}
				}

				std::vector<u8> set(sparsePoints.cols());
				std::vector<std::vector<std::vector<u32>>> states(bitCount + 1);
				states.back().resize(preDomain);
				for (auto point : sparsePoints[r])
					states.back()[point >> bitCount].push_back(point);
				auto copyIter = mFinals[r].back().begin();
				for (u64 i = 0; i < mInitals[r].size(); ++i)
				{
					switch (mInitals[r][i])
					{
					case Initial::None:
						break;
					case Initial::Final:
					{

						if (states.back()[i].size() != 1)
							throw RTE_LOC;
						auto idx = *copyIter++;
						if (sparsePoints[r][idx] != states.back()[i][0])
							throw RTE_LOC;
						set[idx] = 1;
						break;
					}
					case Initial::Expand:
						states[bitCount - 1].push_back(states.back()[i]);
						break;
					}
				}


				if (mDebug)
				{

					for (u64 i = bitCount; i != 0; --i)
					{
						auto& ex = mExpands[r][i - 1];
						auto& state = states[i - 1];
						auto copyIter = mFinals[r][i - 1].begin();

						for (u64 j = 0; j < ex.size(); ++j)
						{
							std::cout << "expand " << i << " " << j << std::endl;
							auto mid = std::partition(state[j].begin(), state[j].end(), [&](auto& a) {return !(a >> (i - 1) & 1); });
							for (auto p : state[j])
							{

								std::cout << print(p, i);
								if (p == *mid)
									std::cout << " <- mid";
								std::cout << std::endl;
							}
							std::cout << std::endl;
							std::array<span<u32>, 2> sets{ span<u32>(state[j].begin(), mid), span<u32>(mid, state[j].end()) };
							for (u64 k = 0; k < 2; ++k)
							{
								if (ex[j].mDepth[k] == 0)
								{
									if (state[j].size() != 2)
										throw RTE_LOC;
									auto c0 = *copyIter++;
									//auto c1 = *copyIter++;

									auto p0 = sparsePoints[r][c0];
									if (p0 != state[j][k])
										throw RTE_LOC;

									set[c0] = 1;
								}
								else
								{
									if (sets[k].size() <= 1)
										throw RTE_LOC;
									auto next = i - 1 - ex[j].mDepth[k];
									std::cout << "pushing set " << k << " to lvl " << next << std::endl;
									states[next].push_back(std::vector<u32>(sets[k].begin(), sets[k].end()));
								}
							}
						}

					}
					if (std::find(set.begin(), set.end(), 0) != set.end())
						throw RTE_LOC;;
				}
			}

		}


		template<typename Output>
		macoro::task<> expand(
			Output&& output,
			PRNG& prng,
			coproto::Socket& sock)
		{
		}


	};

}

#undef SIMD8