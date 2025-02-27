#pragma once


#include "libOTe/config.h"
#if defined(ENABLE_SPARSE_DPF) 

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

		u64 mNumPoints = 0;

		u64 mDomain = 0;

		u64 mDenseDepth = 0;


		RegularDpf mRegDpf;

		DpfMult mMultiplier;

		void init(
			u64 partyIdx,
			u64 numPoints,
			u64 domain,
			u64 denseDepth
		)
		{
			mNumPoints = numPoints;
			mPartyIdx = partyIdx;
			mDomain = domain;
			mDenseDepth = std::min(denseDepth, log2ceil(mDomain));
			auto depth = log2ceil(mDomain) - mDenseDepth;
			mMultiplier.init(mPartyIdx, depth * mNumPoints);
			if (mDenseDepth)
				mRegDpf.init(mPartyIdx, 1ull << mDenseDepth, numPoints);
		}

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}


		u64 baseOtCount() const
		{
			return log2ceil(mDomain) * mNumPoints;
		}


		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			auto count = baseOtCount();
			if (baseSendOts.size() != count)
				throw RTE_LOC;
			if (recvBaseOts.size() != count)
				throw RTE_LOC;
			if (baseChoices.size() != count)
				throw RTE_LOC;

			auto denseCount = mRegDpf.baseOtCount();
			auto
				sDense = baseSendOts.subspan(0, denseCount),
				sRest = baseSendOts.subspan(denseCount);

			auto
				rDense = recvBaseOts.subspan(0, denseCount),
				rRest = recvBaseOts.subspan(denseCount);

			BitVector cDense, cRest;
			cDense.append(baseChoices, denseCount);
			cRest.append(baseChoices, count - denseCount, denseCount);

			if (denseCount)
				mRegDpf.setBaseOts(sDense, rDense, cDense);

			mMultiplier.setBaseOts(sRest, rRest, cRest);
		}


		struct Partition
		{
			// the index of the bit that partitions the left and right
			// sets.
			span<u32> mRange;
			span<u32>::iterator mMid;

			Partition() = default;
			Partition(span<u32> range, span<u32>::iterator mid)
				: mRange(range), mMid(mid)
			{
			}



			std::array<span<u32>, 2>  children()
			{
				return
				{ span<u32>(mRange.begin(), mMid), span<u32>(mMid, mRange.end()) };
			}

			std::string print(u64 bitIdx)
			{
				std::stringstream ss;
				ss << "bit " << bitIdx << " val " << (1 << bitIdx) << " {";
				--bitIdx;
				for (auto iter = mRange.begin(); iter != mRange.end(); ++iter)
				{
					if (iter == mMid)
						ss << ",";

					auto upper = *iter >> bitIdx;
					auto lower = *iter & ((1 << bitIdx) - 1);

					ss << " " << upper << "." << lower;
				}
				ss << "}";
				return ss.str();
			}
		};


		// the upper bits of points[i] are all the same and points is sorted.
		// "upper bits" are defined as bits indexed by {upperBitsBegin,...,31}
		// This function will look at the bits at index upperBitsBegin and paritions
		// the points into two sets.
		std::pair<u32, Partition> partition(span<u32> points, u32 upperBitsBegin)
		{
			if (points.size() == 1)
				return { 0, Partition{points, points.end()} };
#ifndef NDEBUG
			if (std::adjacent_find(points.begin(), points.end(), std::greater<u32>{}) != points.end())
				throw RTE_LOC;
			if (std::any_of(points.begin(), points.end(),
				[upperBitsBegin, prefix = points[0] >> (upperBitsBegin)](auto v) {return v >> (upperBitsBegin) != prefix; }))
				throw RTE_LOC;
			if (points.size() <= 1)
				throw RTE_LOC;
#endif

			Partition par;
			do {
				assert(upperBitsBegin != 0);
				--upperBitsBegin;
				par.mMid = std::upper_bound(
					points.begin(), points.end(), 0,
					[upperBitsBegin](auto, auto b) {return (b >> upperBitsBegin) & 1; });
			} while (par.mMid == points.begin() || par.mMid == points.end());

			par.mRange = points;
			return { upperBitsBegin + 1, par };
		}

		struct Tree
		{
			std::vector<std::vector<Partition>> mPartitions;
			std::vector<std::vector<block>> mSeeds;
			std::vector<std::vector<u8>> mTags;
			std::vector<std::vector<u8>> mChild;
			std::vector<std::vector<u8>> mParent;


			std::vector<std::array<block, 2>> mZ;
			std::vector<u8> mC;
			std::vector<std::array<u8, 2>> mTau;
			std::vector<block> mSigma;

			void resize(u64 depth)
			{
				mPartitions.resize(depth);
				mSeeds.resize(depth);
				mTags.resize(depth);
				mChild.resize(depth);
				mParent.resize(depth);
				mZ.resize(depth);
				mC.resize(depth);
				mTau.resize(depth);
				mSigma.resize(depth);
			}

			struct Level
			{
				Tree* mTree;
				u64 mIdx;

				void push_back(u8 child, u8 parentLevel, Partition& b, block seed, u8 tag)
				{
					mTree->mPartitions[mIdx].push_back(b);
					mTree->mSeeds[mIdx].push_back(seed);
					mTree->mTags[mIdx].push_back(tag);
					mTree->mChild[mIdx].push_back(child);
					mTree->mParent[mIdx].push_back(parentLevel);
				}

				u64 size() const
				{
					return mTree->mPartitions[mIdx].size();
				}
			};
			Level operator[](u64 i)
			{
				return { this, i };
			}



		};

		template<typename Output>
		macoro::task<> expand(
			span<u64> points,
			span<block> values,
			Output&& output,
			PRNG& prng,
			MatrixView<u32> sparsePoints,
			coproto::Socket& sock)
		{
			if (points.size() != sparsePoints.rows())
				throw RTE_LOC;
			u64 depth = log2ceil(mDomain) - mDenseDepth;

			std::vector<Tree> trees(mNumPoints);
			for (u64 i = 0; i < mNumPoints; ++i)
			{
				trees[i].resize(depth + 1);
			}
			using T = block;
			std::unique_ptr<u8[]> mem;
			std::vector<std::span<T>> leafValues(mNumPoints);
			std::vector<std::span<u8>> leafTags(mNumPoints);
			u64 totalSize = 0;
			for (u64 i = 0; i < mNumPoints; ++i)
				totalSize += sparsePoints[i].size();

			mem.reset(new u8[totalSize * (sizeof(T) + 1)]());
			auto iter = mem.get();
			for (u64 i = 0; i < mNumPoints; ++i)
			{
				leafValues[i] = span<T>((T*)iter, sparsePoints[i].size());
				iter += leafValues[i].size_bytes();
			}
			for (u64 i = 0; i < mNumPoints; ++i)
			{
				leafTags[i] = span<u8>(iter, sparsePoints[i].size());
				iter += leafTags[i].size_bytes();
			}

			//for (u64 i = 0; i < mNumPoints; ++i)
			//{
			//	for (auto p : sparsePoints[i])
			//		std::cout << p << " ";
			//	std::cout << std::endl;
			//}


			if (mDenseDepth)
			{

				if (mDenseDepth > log2ceil(mDomain))
					throw RTE_LOC;

				std::vector<u64> densePoints(points.size());
				for (u64 i = 0; i < points.size(); ++i)
					densePoints[i] = points[i] >> depth;
				Matrix<block> seeds(points.size(), 1ull << mDenseDepth);
				Matrix<u8> tags(points.size(), 1ull << mDenseDepth);
				co_await mRegDpf.expand(densePoints, {}, prng.get(), [&](auto treeIdx, auto leafIdx, auto seed, block tag) {
					seeds(treeIdx, leafIdx) = seed;
					tags(treeIdx, leafIdx) = tag.get<u8>(0)&1;
					}, sock);

				for (u64 r = 0; r < sparsePoints.rows(); ++r)
				{
					//auto seed = seeds[i]
					auto& tree = trees[r];
					auto iter = sparsePoints[r].begin();
					auto end = sparsePoints[r].end();
					while (iter != end)
					{
						auto p = *iter;
						auto bin = p >> depth;
						auto seed = seeds(r, bin);
						auto tag = tags(r, bin);

						auto e = std::find_if(iter, end, [bin, depth](auto v) {return (v >> depth) != bin; });
						auto points = span<u32>(iter, e);
						if (points.size() == 1)
						{
							auto idx = std::distance(sparsePoints.data(r), &points[0]);
							leafValues[r][idx] = seed;
							leafTags[r][idx] = tag;
							//std::cout << "p " << mPartyIdx << " leaf " << idx << " seed " << seed << " " << int(tag) << std::endl;
						}
						else if (points.size())
						{
							auto [delta, root] = partition(points, depth);

							block cSeeds[2];
							cSeeds[0] = mAesFixedKey.hashBlock(seed ^ ZeroBlock);
							cSeeds[1] = mAesFixedKey.hashBlock(seed ^ OneBlock);

							auto children = root.children();
							for (u64 j = 0; j < 2; ++j)
							{
								auto [delta2, b2] = partition(children[j], delta);
								//if (!mPartyIdx)
								//	std::cout << b2.print(delta2) << std::endl;
								//std::cout << "p " << mPartyIdx << " d " << delta << " j " << j <<" bin " << bin << " seed " << cSeeds[j] << " " << int(tag) << std::endl;
								tree[delta2].push_back(j, delta, b2, cSeeds[j], tag);
								tree.mZ[delta][j] ^= cSeeds[j];
								tree.mC[delta] = 1;
							}
						}
						iter = e;
					}
				}
			}
			else
			{

				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto points = sparsePoints[r];
					auto& tree = trees[r];
					// range must be sorted and unique
					//if (std::adjacent_find(points.begin(), points.end(), std::greater<u32>{}) != points.end())
					//	throw RTE_LOC;

					auto [delta, b] = partition(points, depth);
					//if (!mPartyIdx)
					//	std::cout << b.print(delta) << std::endl;

					auto children = b.children();
					for (u64 j = 0; j < 2; ++j)
					{
						auto [delta2, b2] = partition(children[j], delta);
						//if (!mPartyIdx)
						//	std::cout << b2.print(delta2) << std::endl;
						block seed = prng.get();
						//std::cout << "p " << mPartyIdx << " d " << delta << " j " << j << " seed " << seed << std::endl;
						tree[delta2].push_back(j, delta, b2, seed, mPartyIdx);
						tree.mZ[delta][j] = seed;
						tree.mC[delta] = 1;
					}
				}
			}


			for (u64 d = depth; d; --d)
			{
				//std::cout << "-----" << d << "-----" << std::endl;

				std::vector<block> z0(mNumPoints);
				std::vector<block> z1(mNumPoints);

				BitVector negAlpha(mNumPoints);
				std::vector<std::array<u8, 2>> taus(mNumPoints);
				std::vector<block>  sigmas(mNumPoints);
				bool used = false;
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto& tree = trees[r];
					if (tree.mC[d] == 0)
						tree.mZ[d] = prng.get();
					else
						used = true;

					auto alphaD = (points[r] >> (d - 1)) & 1;
					taus[r][0] = lsb(tree.mZ[d][0]) ^ alphaD ^ mPartyIdx;
					taus[r][1] = lsb(tree.mZ[d][1]) ^ alphaD;

					//std::cout << "p " << mPartyIdx << " d " << d << " z " << tree.mZ[d][0] << " " <<tree.mZ[d][1] << std::endl;


					negAlpha[r] = alphaD ^ mPartyIdx;
					sigmas[r] = tree.mZ[d][0] ^ tree.mZ[d][1];

					z0[r] = tree.mZ[d][0];
					z1[r] = tree.mZ[d][1];

				}

				if (used)
				{

					co_await reveal(z0, sock);
					co_await reveal(z1, sock);


					co_await mMultiplier.multiply(negAlpha, sigmas, sigmas, sock);
					for (u64 r = 0; r < mNumPoints; ++r)
						sigmas[r] = sigmas[r] ^ trees[r].mZ[d][0];
					co_await reveal(sigmas, taus, sock);

					//std::cout << "p " << mPartyIdx << " d " << d << " ~a " << negAlpha[0] << " s " << sigmas[0] << std::endl;
					//std::cout << "        z  " << z0[0] << "   " << z1[0] << std::endl;

					for (u64 r = 0; r < mNumPoints; ++r)
					{
						//std::cout << "setting >" << d << "<" << std::endl;
						trees[r].mSigma[d] = sigmas[r];
						trees[r].mTau[d] = taus[r];
					}
				}

				auto dNext = d - 1;
				if (dNext == 0)
					break;

				//std::cout << "vvvvv" << dNext << "vvvvv" << std::endl;

				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto& tree = trees[r];
					auto size = tree.mSeeds[dNext].size();

					for (u64 i = 0; i < size; ++i)
					{
						auto& seed = tree.mSeeds[dNext][i];
						auto par = tree.mPartitions[dNext][i];
						auto tag = tree.mTags[dNext][i];
						auto child = tree.mChild[dNext][i];
						auto parent = tree.mParent[dNext][i];
						auto pTau = tree.mTau[parent][child];
						auto pSigma = tree.mSigma[parent];

						auto cTag = lsb(seed) ^ tag * pTau;
						//auto old = seed;
						seed = seed ^ (pSigma & block::allSame<u8>(-tag));

						//std::cout <<"p " << mPartyIdx << " d " << dNext << " i " << i << " "
						//	<<old << " -> " << seed << " via >"<<  int(parent)<< "< " << pSigma << " t " << int(tag) << std::endl;

						std::array<block, 2> cSeed;
						cSeed[0] = mAesFixedKey.hashBlock(seed ^ ZeroBlock);
						cSeed[1] = mAesFixedKey.hashBlock(seed ^ OneBlock);

						tree.mZ[dNext][0] = tree.mZ[dNext][0] ^ cSeed[0];
						tree.mZ[dNext][1] = tree.mZ[dNext][1] ^ cSeed[1];
						tree.mC[dNext] = 1;

						auto children = par.children();
						for (u64 j = 0; j < 2; ++j)
						{
							auto [cd, cPar] = partition(children[j], dNext);

							//if(!mPartyIdx)
							//	std::cout << cPar.print(cd) << std::endl;
							tree.mPartitions[cd].push_back(cPar);
							tree.mChild[cd].push_back(j);
							tree.mParent[cd].push_back(dNext);
							tree.mSeeds[cd].push_back(cSeed[j]);
							tree.mTags[cd].push_back(cTag);
						}
					}
				}
			}

			std::vector<block> gamma(values.begin(), values.end());
			for (u64 r = 0; r < mNumPoints; ++r)
			{
				auto& tree = trees[r];
				auto size = tree.mSeeds[0].size();

				for (u64 i = 0; i < size; ++i)
				{
					auto& seed = tree.mSeeds[0][i];
					auto& tag = tree.mTags[0][i];
					auto j = tree.mChild[0][i];
					auto parent = tree.mParent[0][i];
					auto par = tree.mPartitions[0][i];
					auto pTau = tree.mTau[parent][j];
					auto pSigma = tree.mSigma[parent];

					auto b = std::distance(sparsePoints.data(r), par.mRange.data());
					leafTags[r][b] = lsb(seed) ^ tag * pTau;
					leafValues[r][b] = seed ^ (pSigma & block::allSame<u8>(-tag));
					gamma[r] = gamma[r] ^ leafValues[r][b];
					//std::cout << "p " << mPartyIdx << " d " << 0 << " i " << i << " "
					//	<< seed << " -> " << leafValues[r][b] << " via >" << int(parent) << "< " << pSigma << " t " << int(tag) << std::endl;

				}
			}

			co_await reveal(gamma, sock);
			//std::cout << "-----------final-------------" << std::endl;
			for (u64 r = 0; r < mNumPoints; ++r)
			{
				auto size = sparsePoints[r].size();
				for (u64 i = 0; i < size; ++i)
				{
					assert(leafValues[r][i] != oc::ZeroBlock);
					auto val = leafValues[r][i] ^ (gamma[r] & block::allSame<u8>(-leafTags[r][i]));

					//std::cout << "p " << mPartyIdx << " d " << 0 << " i " << i << " "
					//	<< leafValues[r][i] << " -> " << val << " via " << gamma[r] << " t " << int(leafTags[r][i]) << std::endl;

					output(r, i, val, leafTags[r][i]);
				}
			}

			co_return;
		}



		//std::vector<block> gamma(values.begin(), values.end());
		//for (u64 r = 0; r < mNumPoints; ++r)
		//{
		//	auto& tree = trees[r];
		//	auto size = sparsePoints[r].size();
		//	if (tree.mSeeds[0].size() != size)
		//		throw RTE_LOC;
		//	for (u64 i = 0; i < size; ++i)
		//	{
		//		auto& seed = tree.mSeeds[0][i];
		//		auto& tag = tree.mTags[0][i];
		//		auto j = tree.mChild[0][i];
		//		auto parent = tree.mParent[0][i];
		//		auto par = tree.mPartitions[0][i];
		//		auto pTau = tree.mTau[parent][j];
		//		auto pSigma = tree.mSigma[parent];

		//		//auto old = seed;

		//		auto b = std::distance(sparsePoints.data(r), par.mRange.data());
		//		leafTags[r][b] = lsb(seed) ^ tag * pTau;
		//		leafValues[r][b] = seed ^ (pSigma & block::allSame<u8>(-tag));

		//		//std::cout << "p " << mPartyIdx << " d " << 0 << " i " << i << " "
		//		//	<< old << " -> " << seed << " via >" << int(parent) << "< " << pSigma << " t " << int(tag) << std::endl;


		//		gamma[r] = gamma[r] ^ seed;
		//	}
		//}

		//co_await reveal(gamma, sock);
		////std::cout << "-----------final-------------" << std::endl;
		//for (u64 r = 0; r < mNumPoints; ++r)
		//{
		//	//auto& tree = trees[r];
		//	auto size = sparsePoints[r].size();
		//	for (u64 i = 0; i < size; ++i)
		//	{
		//		//auto seed = tree.mSeeds[0][i];
		//		//auto tag = tree.mTags[0][i];


		//		//auto old = seed;
		//		auto val = leafValues[r][i] ^ (gamma[r] & block::allSame<u8>(-leafTags[r][i]));

		//		//std::cout << "p " << mPartyIdx << " d " << 0 << " i " << i << " "
		//		//	<< old << " -> " << seed << " via " << gamma[r] << " t " << int(tag) << std::endl;

		//		output(r, i, val, leafTags[r][i]);
		//	}
		//}



		macoro::task<> reveal(span<block> sigma, span<std::array<u8, 2>> tau, coproto::Socket& sock)
		{
			if (sigma.size() != tau.size())
				throw RTE_LOC;
			std::vector<block> sBuff(sigma.begin(), sigma.end());
			std::vector<std::array<u8, 2>> tBuff(tau.begin(), tau.end());
			co_await macoro::when_all_ready(
				sock.send(std::move(sBuff)),
				sock.send(std::move(tBuff))
			);
			sBuff.resize(sigma.size());
			tBuff.resize(tau.size());
			co_await macoro::when_all_ready(
				sock.recv(sBuff),
				sock.recv(tBuff)
			);
			for (u64 i = 0; i < sigma.size(); ++i)
			{
				sigma[i] = sigma[i] ^ sBuff[i];
				tau[i][0] = tau[i][0] ^ tBuff[i][0];
				tau[i][1] = tau[i][1] ^ tBuff[i][1];
			}
		}


		macoro::task<> reveal(span<block> sigma, coproto::Socket& sock)
		{
			std::vector<block> sBuff(sigma.begin(), sigma.end());
			co_await sock.send(std::move(sBuff));
			sBuff.resize(sigma.size());
			co_await  sock.recv(sBuff);
			for (u64 i = 0; i < sigma.size(); ++i)
			{
				sigma[i] = sigma[i] ^ sBuff[i];
			}
		}

	};

}

#undef SIMD8

#endif