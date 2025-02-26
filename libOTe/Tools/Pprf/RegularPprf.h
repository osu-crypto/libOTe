#pragma once
#include "libOTe/config.h"

#ifdef ENABLE_PPRF
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Coproto.h"
#include <array>
#include "libOTe/Tools/CoeffCtx.h"
#include "PprfUtil.h"

namespace osuCrypto
{

	extern const std::array<AES, 2> gGgmAes;


	template<
		typename F,
		typename G = F,
		typename CoeffCtx = DefaultCoeffCtx<F, G>
	>
	class RegularPprfSender : public TimerAdapter {
	public:

		// the number of leaves in a single tree.
		u64 mDomain = 0;

		// the depth of each tree.
		u64 mDepth = 0;

		// the number of trees, must be a multiple of 8.
		u64 mPntCount = 0;

		// the values that should be programmed at the punctured points.
		std::vector<F> mValue;

		// the base OTs that should be set.
		Matrix<std::array<block, 2>> mBaseOTs;

		// if true, tree OT messages are eagerly sent in batches of 8.
		// otherwise, the OT messages are sent in a single batch.
		bool mEagerSend = true;

		using VecF = typename CoeffCtx::template Vec<F>;
		using VecG = typename CoeffCtx::template Vec<G>;

		// a function that can be used to output the result of the PPRF.
		std::function<void(u64 treeIdx, VecF& leaf)> mOutputFn;

		// an internal buffer that is used to expand the tree.
		AlignedUnVector<block> mTempBuffer;

		RegularPprfSender() = default;

		RegularPprfSender(const RegularPprfSender&) = delete;

		RegularPprfSender(RegularPprfSender&&) = delete;

		RegularPprfSender(u64 domainSize, u64 pointCount) {
			configure(domainSize, pointCount);
		}

		void configure(u64 domainSize, u64 pointCount)
		{
			if (domainSize & 1)
				throw std::runtime_error("Pprf domain must be even. " LOCATION);
			if (domainSize < 2)
				throw std::runtime_error("Pprf domain must must be at least 2. " LOCATION);

			mDomain = domainSize;
			mDepth = log2ceil(mDomain);
			mPntCount = pointCount;

			mBaseOTs.resize(0, 0);
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const {
			return mDepth * mPntCount;
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const {
			return mBaseOTs.size();
		}


		void setBase(span<const std::array<block, 2>> baseMessages) {
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;

			mBaseOTs.resize(mPntCount, mDepth);
			for (u64 i = 0; i < static_cast<u64>(mBaseOTs.size()); ++i)
				mBaseOTs(i) = baseMessages[i];
		}

		task<> expand(
			Socket& chl,
			const VecF& value,
			block seed,
			VecF& output,
			PprfOutputFormat oFormat,
			bool programPuncturedPoint,
			u64 numThreads,
			CoeffCtx ctx = {})
		{
			MACORO_TRY{
			if (programPuncturedPoint)
				setValue(value);

			setTimePoint("SilentMultiPprfSender.start");

			pprf::validateExpandFormat(oFormat, output, mDomain, mPntCount);

			//auto tree = span<AlignedArray<block, 8>>{};
			auto levels = std::vector<span<AlignedArray<block, 8>> >{};
			auto leafIndex = u64{};
			auto leafLevelPtr = (VecF*)nullptr;
			auto leafLevel = VecF{};
			auto buff = std::vector<u8>{};
			auto encSums = span<std::array<block, 2>>{};
			auto leafMsgs = span<u8>{};
			auto encStepSize = u64{};
			auto leafStepSize = u64{};
			auto encOffset = u64{};
			auto leafOffset = u64{};

			auto dd = mDomain > 2 ? roundUpTo((mDomain + 1) / 2, 2) : 1;
			pprf::allocateExpandTree(dd, mTempBuffer, levels);
			assert(levels.size() == mDepth);

			if (!mEagerSend)
			{
				// we need to allocate one large buffer that will store all OT messages.
				pprf::allocateExpandBuffer<F>(
					mDepth - 1, mPntCount, programPuncturedPoint, buff, encSums, leafMsgs, ctx);
				encStepSize = encSums.size() / mPntCount;
				leafStepSize = leafMsgs.size() / mPntCount;
				encOffset = 0;
				leafOffset = 0;
			}

			for (auto treeIndex = 0ull; treeIndex < mPntCount; treeIndex += 8)
			{
				// for interleaved format, the leaf level of the tree
				// is simply the output.
				if (oFormat == PprfOutputFormat::Interleaved)
				{
					leafIndex = treeIndex * mDomain;
					leafLevelPtr = &output;
				}
				else
				{
					// we will use leaf level as a buffer before
					// copying the result to the output.
					leafIndex = 0;
					ctx.resize(leafLevel, mDomain * 8);
					leafLevelPtr = &leafLevel;
				}

				auto min = std::min<u64>(8, mPntCount - treeIndex);
				if (mEagerSend)
				{
					// allocate a send buffer for the next 8 trees.
					pprf::allocateExpandBuffer<F>(
						mDepth - 1, min, programPuncturedPoint, buff, encSums, leafMsgs, ctx);
					encStepSize = encSums.size() / min;
					leafStepSize = leafMsgs.size() / min;
					encOffset = 0;
					leafOffset = 0;
				}

				// exapnd the tree
				expandOne(
					seed,
					treeIndex,
					programPuncturedPoint,
					levels,
					*leafLevelPtr,
					leafIndex,
					encSums.subspan(encOffset, encStepSize * min),
					leafMsgs.subspan(leafOffset, leafStepSize * min),
					ctx);

				encOffset += encStepSize * min;
				leafOffset += leafStepSize * min;

				if (mEagerSend)
				{
					// send the buffer for the current set of trees.
					co_await(chl.send(std::move(buff)));
				}

				// if we aren't interleaved, we need to copy the
				// leaf layer to the output.
				if (oFormat != PprfOutputFormat::Interleaved)
					pprf::copyOut<VecF, CoeffCtx>(leafLevel, output, mPntCount, treeIndex, oFormat, mOutputFn);

			}


			if (!mEagerSend)
			{
				// send the buffer for all of the trees.
				co_await(chl.send(std::move(buff)));
			}

			mBaseOTs = {};

			setTimePoint("SilentMultiPprfSender.de-alloc");

			} MACORO_CATCH(eptr) {
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		void setValue(span<const F> value) {

			mValue.resize(mPntCount);

			if (value.size() == 1) {
				std::fill(mValue.begin(), mValue.end(), value[0]);
			}
			else {
				if ((u64)value.size() != mPntCount)
					throw RTE_LOC;

				std::copy(value.begin(), value.end(), mValue.begin());
			}
		}

		void clear() {
			mBaseOTs.resize(0, 0);
			mDomain = 0;
			mDepth = 0;
			mPntCount = 0;
		}

		void expandOne(
			block aesSeed,
			u64 treeIdx,
			bool programPuncturedPoint,
			span<span<AlignedArray<block, 8>>> levels,
			VecF& leafLevel,
			const u64 leafOffset,
			span<std::array<block, 2>>  encSums,
			span<u8> leafMsgs,
			CoeffCtx ctx)
		{
			auto remTrees = std::min<u64>(8, mPntCount - treeIdx);

			// the first level should be size 1, the root of the tree.
			// we will populate it with random seeds using aesSeed in counter mode
			// based on the tree index.
			assert(levels[0].size() == 1);
			mAesFixedKey.ecbEncCounterMode(aesSeed ^ block(treeIdx), levels[0][0]);

			assert(encSums.size() == (mDepth - 1) * remTrees);
			auto encSumIter = encSums.begin();

			// space for our sums of each level. Should always be less then
			// 24 levels... If not increase the limit or make it a vector.
			std::array<std::array<block, 8>, 2> sums;

			// use the optimized approach for intern nodes of the tree
			// For each level perform the following.
			for (u64 d = 0; d < mDepth - 1; ++d)
			{
				// clear the sums
				memset(&sums, 0, sizeof(sums));

				// The total number of parents in this level.
				auto width = divCeil(mDomain, 1ull << (mDepth - d));

				// The previous level of the GGM tree.
				auto parents = levels[d];

				// The next level of theGGM tree that we are populating.
				auto children = levels[d + 1]; 
				assert((u64)parents.data() % sizeof(block) == 0 && "levels requires aligment");
				assert((u64)children.data() % sizeof(block) == 0 && "levels requires aligment");


				// For each child, populate the child by expanding the parent.
				for (u64 parentIdx = 0, childIdx = 0; parentIdx < width; ++parentIdx, childIdx += 2)
				{
					// The value of the parent.
					auto& parent = parents.data()[parentIdx];

					auto& child0 = children.data()[childIdx];
					auto& child1 = children.data()[childIdx + 1];
					mAesFixedKey.ecbEncBlocks<8>(parent.data(), child1.data());

					// inspired by the Expand Accumualte idea to
					// use 
					// 
					// child0 = AES(parent) ^ parent
					// child1 = AES(parent) + parent
					//
					// but instead we are a bit more conservative and
					// compute 
					//
					// child0 = AES:Round(AES(parent),      parent)
					//        = AES:Round(AES(parent), 0) ^ parent
					// child1 =           AES(parent)     + parent
					//
					// That is, we applies an additional AES round function
					// to the first child before XORing it with parent.
					child0[0] = AES::roundEnc(child1[0], parent[0]);
					child0[1] = AES::roundEnc(child1[1], parent[1]);
					child0[2] = AES::roundEnc(child1[2], parent[2]);
					child0[3] = AES::roundEnc(child1[3], parent[3]);
					child0[4] = AES::roundEnc(child1[4], parent[4]);
					child0[5] = AES::roundEnc(child1[5], parent[5]);
					child0[6] = AES::roundEnc(child1[6], parent[6]);
					child0[7] = AES::roundEnc(child1[7], parent[7]);

					// Update the running sums for this level. We keep
					// a left and right totals for each level.
					sums[0][0] = sums[0][0] ^ child0[0];
					sums[0][1] = sums[0][1] ^ child0[1];
					sums[0][2] = sums[0][2] ^ child0[2];
					sums[0][3] = sums[0][3] ^ child0[3];
					sums[0][4] = sums[0][4] ^ child0[4];
					sums[0][5] = sums[0][5] ^ child0[5];
					sums[0][6] = sums[0][6] ^ child0[6];
					sums[0][7] = sums[0][7] ^ child0[7];

					// child1 = AES(parent) + parent
					child1[0] = child1[0].add_epi64(parent[0]);
					child1[1] = child1[1].add_epi64(parent[1]);
					child1[2] = child1[2].add_epi64(parent[2]);
					child1[3] = child1[3].add_epi64(parent[3]);
					child1[4] = child1[4].add_epi64(parent[4]);
					child1[5] = child1[5].add_epi64(parent[5]);
					child1[6] = child1[6].add_epi64(parent[6]);
					child1[7] = child1[7].add_epi64(parent[7]);

					sums[1][0] = sums[1][0] ^ child1[0];
					sums[1][1] = sums[1][1] ^ child1[1];
					sums[1][2] = sums[1][2] ^ child1[2];
					sums[1][3] = sums[1][3] ^ child1[3];
					sums[1][4] = sums[1][4] ^ child1[4];
					sums[1][5] = sums[1][5] ^ child1[5];
					sums[1][6] = sums[1][6] ^ child1[6];
					sums[1][7] = sums[1][7] ^ child1[7];

				}

				// encrypt the sums and write them to the output.
				for (u64 j = 0; j < remTrees; ++j)
				{
					(*encSumIter)[0] = sums[0][j] ^ mBaseOTs(treeIdx + j, mDepth - 1 - d)[1];
					(*encSumIter)[1] = sums[1][j] ^ mBaseOTs(treeIdx + j, mDepth - 1 - d)[0];
					++encSumIter;
				}
			}
			assert(encSumIter == encSums.end());

			auto d = mDepth - 1;

			// The previous level of the GGM tree.
			auto level0 = levels[d];

			// The total number of parents in this level.
			auto width = divCeil(mDomain, 1ull << (mDepth - d));

			// The next level of theGGM tree that we are populating.
			std::array<block, 8> child;

			// clear the sums
			std::array<VecF, 2> leafSums;
			ctx.resize(leafSums[0], 8);
			ctx.resize(leafSums[1], 8);
			ctx.zero(leafSums[0].begin(), leafSums[0].end());
			ctx.zero(leafSums[1].begin(), leafSums[1].end());

			auto outIter = leafLevel.data() + leafOffset;

			// for the leaf nodes we need to hash both children.
			for (u64 parentIdx = 0, childIdx = 0; parentIdx < width; ++parentIdx)
			{
				// The value of the parent.
				auto& parent = level0.data()[parentIdx];

				// The bit that indicates if we are on the left child (0)
				// or on the right child (1).
				for (u64 keep = 0; keep < 2; ++keep, ++childIdx)
				{
					// The child that we will write in this iteration.

					if constexpr (std::is_same_v<F, block> && (
						std::is_same_v<CoeffCtx, CoeffCtxGF2> ||
						std::is_same_v<CoeffCtx, CoeffCtxGF128>)
						)
					{
						gGgmAes.data()[keep].hashBlocks<8>(parent.data(), outIter);
					}
					else
					{
						// Each parent is expanded into the left and right children
						// using a different AES fixed-key. Therefore our OWF is:
						//
						//    H(x) = (AES(k0, x) + x) || (AES(k1, x) + x);
						//
						// where each half defines one of the children.
						gGgmAes.data()[keep].hashBlocks<8>(parent.data(), child.data());

						ctx.fromBlock(*(outIter + 0), child.data()[0]);
						ctx.fromBlock(*(outIter + 1), child.data()[1]);
						ctx.fromBlock(*(outIter + 2), child.data()[2]);
						ctx.fromBlock(*(outIter + 3), child.data()[3]);
						ctx.fromBlock(*(outIter + 4), child.data()[4]);
						ctx.fromBlock(*(outIter + 5), child.data()[5]);
						ctx.fromBlock(*(outIter + 6), child.data()[6]);
						ctx.fromBlock(*(outIter + 7), child.data()[7]);
					}

					// leafSum += child
					auto& leafSum = leafSums[keep];
					ctx.plus(leafSum.data()[0], leafSum.data()[0], *(outIter + 0));
					ctx.plus(leafSum.data()[1], leafSum.data()[1], *(outIter + 1));
					ctx.plus(leafSum.data()[2], leafSum.data()[2], *(outIter + 2));
					ctx.plus(leafSum.data()[3], leafSum.data()[3], *(outIter + 3));
					ctx.plus(leafSum.data()[4], leafSum.data()[4], *(outIter + 4));
					ctx.plus(leafSum.data()[5], leafSum.data()[5], *(outIter + 5));
					ctx.plus(leafSum.data()[6], leafSum.data()[6], *(outIter + 6));
					ctx.plus(leafSum.data()[7], leafSum.data()[7], *(outIter + 7));

					outIter += 8;
					assert(outIter <= leafLevel.data() + leafLevel.size());
				}

			}

			if (programPuncturedPoint)
			{
				// For the leaf level, we are going to do something special.
				// The other party is currently missing both leaf children of
				// the active parent. Since this is the leaf level, we want
				// the inactive child to just be the normal value but the
				// active child should be the correct value XOR the delta.
				// This will be done by sending the sums and the sums plus
				// delta and ensure that they can only decrypt the correct ones.
				VecF leafOts;
				ctx.resize(leafOts, 2);
				PRNG otMasker;

				for (u64 j = 0; j < remTrees; ++j)
				{
					// we will construct two OT strings. Let
					// s0, s1 be the left and right child sums.
					// 
					// m0 = (s0      , s1 + val)
					// m1 = (s0 + val, s1      )
					//
					// these will be encrypted by the OT keys 
					for (u64 k = 0; k < 2; ++k)
					{
						if (k == 0)
						{
							// m0 = (s0, s1 + val)
							ctx.copy(leafOts[0], leafSums[0][j]);
							ctx.plus(leafOts[1], leafSums[1][j], mValue[treeIdx + j]);
						}
						else
						{
							// m1 = (s0+val, s1)
							ctx.plus(leafOts[0], leafSums[0][j], mValue[treeIdx + j]);
							ctx.copy(leafOts[1], leafSums[1][j]);
						}

						// copy m0 into the output buffer.
						span<u8> buff = leafMsgs.subspan(0, 2 * ctx.template byteSize<F>());
						leafMsgs = leafMsgs.subspan(buff.size());
						ctx.serialize(leafOts.begin(), leafOts.end(), buff.begin());

						// encrypt the output buffer.
						otMasker.SetSeed(mBaseOTs[treeIdx + j][0][1 ^ k], divCeil(buff.size(), sizeof(block)));
						for (u64 i = 0; i < buff.size(); ++i)
							buff[i] ^= otMasker.get<u8>();

					}
				}
			}
			else
			{
				VecF leafOts;
				ctx.resize(leafOts, 1);
				PRNG otMasker;

				for (u64 j = 0; j < remTrees; ++j)
				{
					for (u64 k = 0; k < 2; ++k)
					{
						// copy the sum k into the output buffer.
						ctx.copy(leafOts[0], leafSums[k][j]);
						span<u8> buff = leafMsgs.subspan(0, ctx.template byteSize<F>());
						leafMsgs = leafMsgs.subspan(buff.size());
						ctx.serialize(leafOts.begin(), leafOts.end(), buff.begin());

						// encrypt the output buffer.
						otMasker.SetSeed(mBaseOTs[treeIdx + j][0][1 ^ k], divCeil(buff.size(), sizeof(block)));
						for (u64 i = 0; i < buff.size(); ++i)
							buff[i] ^= otMasker.get<u8>();

					}
				}
			}

			assert(leafMsgs.size() == 0);
		}


	};


	template<
		typename F,
		typename G = F,
		typename CoeffCtx = DefaultCoeffCtx<F, G>
	>
	class RegularPprfReceiver : public TimerAdapter
	{
	public:

		// the number of leaves in a single tree.
		u64 mDomain = 0;

		// the depth of each tree.
		u64 mDepth = 0;

		// the number of trees, must be a multiple of 8.
		u64 mPntCount = 0;

		using VecF = typename CoeffCtx::template Vec<F>;
		using VecG = typename CoeffCtx::template Vec<G>;

		// base ots that will be used to expand the tree.
		Matrix<block> mBaseOTs;

		// the choice bits, each row should be the bit decomposition of the active path.
		Matrix<u8> mBaseChoices;

		// if true, tree OT messages are eagerly sent in batches of 8.
		// otherwise, the OT messages are sent in a single batch.
		bool mEagerSend = true;

		// a function that can be used to output the result of the PPRF.
		std::function<void(u64 treeIdx, VecF& leafs)> mOutputFn;

		// an internal buffer that is used to expand the tree.
		AlignedUnVector<block> mTempBuffer;

		RegularPprfReceiver() = default;
		RegularPprfReceiver(const RegularPprfReceiver&) = delete;
		RegularPprfReceiver(RegularPprfReceiver&&) = delete;

		void configure(u64 domainSize, u64 pointCount)
		{
			if (domainSize & 1)
				throw std::runtime_error("Pprf domain must be even. " LOCATION);
			if (domainSize < 2)
				throw std::runtime_error("Pprf domain must must be at least 2. " LOCATION);

			mDomain = domainSize;
			mDepth = log2ceil(mDomain);
			mPntCount = pointCount;

			mBaseOTs.resize(0, 0);
		}


		// this function sample mPntCount integers in the range
		// [0,domain) and returns these as the choice bits.
		BitVector sampleChoiceBits(PRNG& prng)
		{
			BitVector choices(mPntCount * mDepth);

			// The points are read in blocks of 8, so make sure that there is a
			// whole number of blocks.
			mBaseChoices.resize(mPntCount, mDepth);
			for (u64 i = 0; i < mPntCount; ++i)
			{
				u64 idx = prng.get<u64>() % mDomain;
				for (u64 j = 0; j < mDepth; ++j)
					mBaseChoices(i, j) = *BitIterator((u8*)&idx, j);
			}

			for (u64 i = 0; i < mBaseChoices.size(); ++i)
			{
				choices[i] = mBaseChoices(i);
			}

			return choices;
		}

		// choices is in the same format as the output from sampleChoiceBits.
		void setChoiceBits(const BitVector& choices)
		{
			// Make sure we're given the right number of OTs.
			if (choices.size() != baseOtCount())
				throw RTE_LOC;

			mBaseChoices.resize(mPntCount, mDepth);
			for (u64 i = 0; i < mPntCount; ++i)
			{
				u64 idx = 0;
				for (u64 j = 0; j < mDepth; ++j)
				{
					mBaseChoices(i, j) = choices[mDepth * i + j];
					idx |= u64(choices[mDepth * i + j]) << j;
				}

				if (idx >= mDomain)
					throw std::runtime_error("provided choice bits index outside of the domain." LOCATION);
			}
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const
		{
			return mDepth * mPntCount;
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const
		{
			return mBaseOTs.size();
		}


		void setBase(span<const block> baseMessages)
		{
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;

			// The OTs are used in blocks of 8, so make sure that there is a whole
			// number of blocks.
			mBaseOTs.resize(roundUpTo(mPntCount, 8), mDepth);
			if (mBaseOTs.size() < baseMessages.size())
				throw RTE_LOC;
			memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));
		}

		std::vector<u64> getPoints(PprfOutputFormat format)
		{
			std::vector<u64> pnts(mPntCount);
			getPoints(pnts, format);
			return pnts;
		}
		void getPoints(span<u64> points, PprfOutputFormat format)
		{
			if ((u64)points.size() != mPntCount)
				throw RTE_LOC;

			switch (format)
			{
			case PprfOutputFormat::ByLeafIndex:
			case PprfOutputFormat::ByTreeIndex:

				memset(points.data(), 0, points.size() * sizeof(u64));
				for (u64 j = 0; j < mPntCount; ++j)
				{
					for (u64 k = 0; k < mDepth; ++k)
						points[j] |= u64(mBaseChoices(j, k)) << k;

					assert(points[j] < mDomain);
				}


				break;
			case PprfOutputFormat::Interleaved:
			case PprfOutputFormat::Callback:

				getPoints(points, PprfOutputFormat::ByLeafIndex);

				// in interleaved mode we generate 8 trees in a batch.
				// the i'th leaf of these 8 trees are next to eachother.
				for (u64 j = 0; j < points.size(); ++j)
				{
					auto subTree = j % 8;
					auto batch = j / 8;
					points[j] = (batch * mDomain + points[j]) * 8 + subTree;
				}

				//interleavedPoints(points, mDomain, format);

				break;
			default:
				throw RTE_LOC;
				break;
			}
		}

		// programPuncturedPoint says whether the sender is trying to program the
		// active child to be its correct value XOR delta. If it is not, the
		// active child will just take a random value.
		task<> expand(
			Socket& chl,
			VecF& output,
			PprfOutputFormat oFormat,
			bool programPuncturedPoint,
			u64 numThreads,
			CoeffCtx ctx = {})
		{
			MACORO_TRY{
				pprf::validateExpandFormat(oFormat, output, mDomain, mPntCount);

				auto treeIndex = u64{};
				auto levels = std::vector<span<AlignedArray<block, 8>>>{};
				auto leafIndex = u64{};
				auto leafLevelPtr = (VecF*)nullptr;
				auto leafLevel = VecF{};
				auto buff = std::vector<u8>{};
				auto encSums = span<std::array<block, 2>>{};
				auto leafMsgs = span<u8>{};
				auto points = std::vector<u64>{};
				auto encStepSize = u64{};
				auto leafStepSize = u64{};
				auto encOffset = u64{};
				auto leafOffset = u64{};

				setTimePoint("SilentMultiPprfReceiver.start");
				points.resize(mPntCount);
				getPoints(points, PprfOutputFormat::ByLeafIndex);

				//setTimePoint("SilentMultiPprfSender.reserve");

				auto dd = mDomain > 2 ? roundUpTo((mDomain + 1) / 2, 2) : 1;
				pprf::allocateExpandTree(dd, mTempBuffer, levels);
				assert(levels.size() == mDepth);


				if (!mEagerSend)
				{
					// we need to allocate one large buffer that will store all OT messages.
					pprf::allocateExpandBuffer<F>(
						mDepth - 1, mPntCount, programPuncturedPoint, buff, encSums, leafMsgs, ctx);
					encStepSize = encSums.size() / mPntCount;
					leafStepSize = leafMsgs.size() / mPntCount;
					encOffset = 0;
					leafOffset = 0;

					co_await(chl.recv(buff));
				}

				for (treeIndex = 0ull; treeIndex < mPntCount; treeIndex += 8)
				{
					// for interleaved format, the leaf level of the tree
					// is simply the output.
					if (oFormat == PprfOutputFormat::Interleaved)
					{
						leafIndex = treeIndex * mDomain;
						leafLevelPtr = &output;
					}
					else
					{
						// we will use leaf level as a buffer before
						// copying the result to the output.
						leafIndex = 0;
						ctx.resize(leafLevel, mDomain * 8);
						leafLevelPtr = &leafLevel;
					}

					auto min = std::min<u64>(8, mPntCount - treeIndex);
					if (mEagerSend)
					{

						// allocate the send buffer and partition it.
						pprf::allocateExpandBuffer<F>(mDepth - 1, min,
							programPuncturedPoint, buff, encSums, leafMsgs, ctx);
						encStepSize = encSums.size() / min;
						leafStepSize = leafMsgs.size() / min;
						encOffset = 0;
						leafOffset = 0;
						co_await(chl.recv(buff));
					}

					// exapnd the tree
					expandOne(
						treeIndex,
						programPuncturedPoint,
						levels,
						*leafLevelPtr,
						leafIndex,
						encSums.subspan(encOffset, encStepSize * min),
						leafMsgs.subspan(leafOffset, leafStepSize * min),
						points,
						ctx);

					encOffset += encStepSize * min;
					leafOffset += leafStepSize * min;

					// if we aren't interleaved, we need to copy the
					// leaf layer to the output.
					if (oFormat != PprfOutputFormat::Interleaved)
						pprf::copyOut<VecF, CoeffCtx>(leafLevel, output, mPntCount, treeIndex, oFormat, mOutputFn);
				}

				setTimePoint("SilentMultiPprfReceiver.join");

				mBaseOTs = {};

				setTimePoint("SilentMultiPprfReceiver.de-alloc");

			} MACORO_CATCH(eptr) {
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		void clear()
		{
			mBaseOTs.resize(0, 0);
			mBaseChoices.resize(0, 0);
			mDomain = 0;
			mDepth = 0;
			mPntCount = 0;
		}

		void expandOne(
			u64 treeIdx,
			bool programPuncturedPoint,
			span<span<AlignedArray<block, 8>>> levels,
			VecF& leafLevel,
			const u64 outputOffset,
			span<std::array<block, 2>> theirSums,
			span<u8> leafMsg,
			span<u64> points,
			CoeffCtx& ctx)
		{
			auto remTrees = std::min<u64>(8, mPntCount - treeIdx);
			assert(theirSums.size() == remTrees * (mDepth - 1));

			// We change the hash function for the leaf so lets update  
			// inactiveChildValues to use the new hash and subtract
			// these from the leafSums
			std::array<VecF, 2> leafSums;
			if (mDepth > 1)
			{
				auto theirSumsIter = theirSums.begin();

				// special case for the first level.
				auto l1 = levels[1];
				for (u64 i = 0; i < remTrees; ++i)
				{
					// For the non-active path, set the child of the root node
					// as the OT message XOR'ed with the correction sum.

					int active = mBaseChoices[i + treeIdx].back();
					l1[active ^ 1][i] = mBaseOTs[i + treeIdx].back() ^ (*theirSumsIter)[active ^ 1];
					l1[active][i] = ZeroBlock;
					++theirSumsIter;
					//if (!i)
					//    std::cout << " unmask " 
					//    << mBaseOTs[i + treeIdx].back() << " ^ "
					//    << theirSums[0][active ^ 1][i] << " = "
					//    << l1[active ^ 1][i] << std::endl;

				}

				// space for our sums of each level.
				std::array<std::array<block, 8>, 2> mySums;

				// this will be the value of both children of active an parent
				// before the active child is updated. We will need to subtract 
				// this value as the main loop does not distinguish active parents.
				std::array<block, 2> inactiveChildValues;
				inactiveChildValues[0] = AES::roundEnc(mAesFixedKey.ecbEncBlock(ZeroBlock), ZeroBlock);
				inactiveChildValues[1] = mAesFixedKey.ecbEncBlock(ZeroBlock);

				// For all other levels, expand the GGM tree and add in
				// the correction along the active path.
				for (u64 d = 1; d < mDepth - 1; ++d)
				{
					// initialized the sums with inactiveChildValue so that
					// it will cancel when we expand the actual inactive child.
					std::fill(mySums[0].begin(), mySums[0].end(), inactiveChildValues[0]);
					std::fill(mySums[1].begin(), mySums[1].end(), inactiveChildValues[1]);

					// We will iterate over each node on this level and
					// expand it into it's two children. Note that the
					// active node will also be expanded. Later we will just
					// overwrite whatever the value was. This is an optimization.
					auto width = divCeil(mDomain, 1ull << (mDepth - d));

					// The already constructed level. Only missing the
					// GGM tree node value along the active path.
					auto level0 = levels[d];
					assert(level0.size() == width || level0.size() == width + 1);

					// The next level that we want to construct.
					auto level1 = levels[d + 1];
					assert(level1.size() == width * 2);
					assert((u64)level0.data() % sizeof(block) == 0 && "levels requires aligment");
					assert((u64)level1.data() % sizeof(block) == 0 && "levels requires aligment");

					for (u64 parentIdx = 0, childIdx = 0; parentIdx < width; ++parentIdx, childIdx += 2)
					{
						// The value of the parent.
						auto parent = level0[parentIdx];

						auto& child0 = level1.data()[childIdx];
						auto& child1 = level1.data()[childIdx + 1];
						mAesFixedKey.ecbEncBlocks<8>(parent.data(), child1.data());

						// inspired by the Expand Accumualte idea to
						// use 
						// 
						// child0 = AES(parent) ^ parent
						// child1 = AES(parent) + parent
						//
						// but instead we are a bit more conservative and
						// compute 
						//
						// child0 = AES:Round(AES(parent),      parent)
						//        = AES:Round(AES(parent), 0) ^ parent
						// child1 =           AES(parent)     + parent
						//
						// That is, we applies an additional AES round function
						// to the first child before XORing it with parent.
						child0[0] = AES::roundEnc(child1[0], parent[0]);
						child0[1] = AES::roundEnc(child1[1], parent[1]);
						child0[2] = AES::roundEnc(child1[2], parent[2]);
						child0[3] = AES::roundEnc(child1[3], parent[3]);
						child0[4] = AES::roundEnc(child1[4], parent[4]);
						child0[5] = AES::roundEnc(child1[5], parent[5]);
						child0[6] = AES::roundEnc(child1[6], parent[6]);
						child0[7] = AES::roundEnc(child1[7], parent[7]);

						// Update the running sums for this level. We keep
						// a left and right totals for each level. Note that
						// we are actually XOR in the incorrect value of the
						// children of the active parent but this will cancel 
						// with inactiveChildValue thats already there.
						mySums[0][0] = mySums[0][0] ^ child0[0];
						mySums[0][1] = mySums[0][1] ^ child0[1];
						mySums[0][2] = mySums[0][2] ^ child0[2];
						mySums[0][3] = mySums[0][3] ^ child0[3];
						mySums[0][4] = mySums[0][4] ^ child0[4];
						mySums[0][5] = mySums[0][5] ^ child0[5];
						mySums[0][6] = mySums[0][6] ^ child0[6];
						mySums[0][7] = mySums[0][7] ^ child0[7];

						// child1 = AES(parent) + parent
						child1[0] = child1[0].add_epi64(parent[0]);
						child1[1] = child1[1].add_epi64(parent[1]);
						child1[2] = child1[2].add_epi64(parent[2]);
						child1[3] = child1[3].add_epi64(parent[3]);
						child1[4] = child1[4].add_epi64(parent[4]);
						child1[5] = child1[5].add_epi64(parent[5]);
						child1[6] = child1[6].add_epi64(parent[6]);
						child1[7] = child1[7].add_epi64(parent[7]);

						mySums[1][0] = mySums[1][0] ^ child1[0];
						mySums[1][1] = mySums[1][1] ^ child1[1];
						mySums[1][2] = mySums[1][2] ^ child1[2];
						mySums[1][3] = mySums[1][3] ^ child1[3];
						mySums[1][4] = mySums[1][4] ^ child1[4];
						mySums[1][5] = mySums[1][5] ^ child1[5];
						mySums[1][6] = mySums[1][6] ^ child1[6];
						mySums[1][7] = mySums[1][7] ^ child1[7];

					}


					// we have to update the non-active child of the active parent.
					for (u64 i = 0; i < remTrees; ++i)
					{
						// the index of the leaf node that is active.
						auto leafIdx = points[i + treeIdx];

						// The index of the active (missing) child node.
						auto missingChildIdx = leafIdx >> (mDepth - 1 - d);

						// The index of the active child node sibling.
						auto siblingIdx = missingChildIdx ^ 1;

						// The indicator as to the left or right child is inactive
						auto notAi = siblingIdx & 1;

						// our sums & OTs cancel and we are leaf with the 
						// correct value for the inactive child.
						level1[siblingIdx][i] =
							(*theirSumsIter)[notAi] ^
							mySums[notAi][i] ^
							mBaseOTs(i + treeIdx, mDepth - 1 - d);

						++theirSumsIter;

						// we have to set the active child to zero so 
						// the next children are predictable.
						level1[missingChildIdx][i] = ZeroBlock;
					}
				}

				auto d = mDepth - 1;
				// The already constructed level. Only missing the
				// GGM tree node value along the active path.
				auto level0 = levels[d];

				// The next level of theGGM tree that we are populating.
				std::array<block, 8> child;

				// We will iterate over each node on this level and
				// expand it into it's two children. Note that the
				// active node will also be expanded. Later we will just
				// overwrite whatever the value was. This is an optimization.
				auto width = divCeil(mDomain, 1ull << (mDepth - d));

				VecF temp;
				ctx.resize(temp, 2);
				for (u64 k = 0; k < 2; ++k)
				{
					ctx.resize(leafSums[k], 8);
					ctx.zero(leafSums[k].begin(), leafSums[k].end());
					ctx.fromBlock(temp[k], gGgmAes[k].hashBlock(ZeroBlock));
					ctx.minus(leafSums[k][0], leafSums[k][0], temp[k]);
					for (u64 i = 1; i < 8; ++i)
						ctx.copy(leafSums[k][i], leafSums[k][0]);
				}

				auto outIter = leafLevel.data() + outputOffset;
				// for leaf nodes both children should be hashed.
				for (u64 parentIdx = 0, childIdx = 0; parentIdx < width; ++parentIdx)
				{
					// The value of the parent.
					auto parent = level0.data()[parentIdx];

					for (u64 keep = 0; keep < 2; ++keep, ++childIdx)
					{
						if constexpr (std::is_same_v<F, block> && (
							std::is_same_v<CoeffCtx, CoeffCtxGF2> ||
							std::is_same_v<CoeffCtx, CoeffCtxGF128>
							))
							{
								gGgmAes.data()[keep].hashBlocks<8>(parent.data(), outIter);
						}
						else
						{
							// Each parent is expanded into the left and right children
							// using a different AES fixed-key. Therefore our OWF is:
							//
							//    H(x) = (AES(k0, x) + x) || (AES(k1, x) + x);
							//
							// where each half defines one of the children.
							gGgmAes.data()[keep].hashBlocks<8>(parent.data(), child.data());

							ctx.fromBlock(*(outIter + 0), child.data()[0]);
							ctx.fromBlock(*(outIter + 1), child.data()[1]);
							ctx.fromBlock(*(outIter + 2), child.data()[2]);
							ctx.fromBlock(*(outIter + 3), child.data()[3]);
							ctx.fromBlock(*(outIter + 4), child.data()[4]);
							ctx.fromBlock(*(outIter + 5), child.data()[5]);
							ctx.fromBlock(*(outIter + 6), child.data()[6]);
							ctx.fromBlock(*(outIter + 7), child.data()[7]);
						}
						auto& leafSum = leafSums[keep];
						ctx.plus(leafSum.data()[0], leafSum.data()[0], *(outIter + 0));
						ctx.plus(leafSum.data()[1], leafSum.data()[1], *(outIter + 1));
						ctx.plus(leafSum.data()[2], leafSum.data()[2], *(outIter + 2));
						ctx.plus(leafSum.data()[3], leafSum.data()[3], *(outIter + 3));
						ctx.plus(leafSum.data()[4], leafSum.data()[4], *(outIter + 4));
						ctx.plus(leafSum.data()[5], leafSum.data()[5], *(outIter + 5));
						ctx.plus(leafSum.data()[6], leafSum.data()[6], *(outIter + 6));
						ctx.plus(leafSum.data()[7], leafSum.data()[7], *(outIter + 7));

						outIter += 8;
						assert(outIter <= leafLevel.data() + leafLevel.size());
					}
				}
			}
			else
			{
				for (u64 k = 0; k < 2; ++k)
				{
					ctx.resize(leafSums[k], 8);
					ctx.zero(leafSums[k].begin(), leafSums[k].end());
				}
			}

			// leaf level.
			if (programPuncturedPoint)
			{
				// Now processes the leaf level. This one is special
				// because we must XOR in the correction value as
				// before but we must also fixed the child value for
				// the active child. To do this, we will receive 4
				// values. Two for each case (left active or right active).
				//timer.setTimePoint("recv.recvleaf");
				VecF leafOts;
				ctx.resize(leafOts, 2);
				PRNG otMasker;

				for (u64 j = 0; j < remTrees; ++j)
				{

					// The index of the child on the active path.
					auto activeChildIdx = points[j + treeIdx];

					// The index of the other (inactive) child.
					auto inactiveChildIdx = activeChildIdx ^ 1;

					// The indicator as to the left or right child is inactive
					auto notAi = inactiveChildIdx & 1;

					// offset to the first or second ot message, based on the one we want
					auto offset = ctx.template byteSize<F>() * 2 * notAi;


					// decrypt the ot string
					span<u8> buff = leafMsg.subspan(offset, ctx.template byteSize<F>() * 2);
					leafMsg = leafMsg.subspan(buff.size() * 2);
					otMasker.SetSeed(mBaseOTs[j + treeIdx][0], divCeil(buff.size(), sizeof(block)));
					for (u64 i = 0; i < buff.size(); ++i)
						buff[i] ^= otMasker.get<u8>();

					ctx.deserialize(buff.begin(), buff.end(), leafOts.begin());

					auto out0 = (activeChildIdx & ~1ull) * 8 + j + outputOffset;
					auto out1 = (activeChildIdx | 1ull) * 8 + j + outputOffset;

					ctx.minus(leafLevel[out0], leafOts[0], leafSums[0][j]);
					ctx.minus(leafLevel[out1], leafOts[1], leafSums[1][j]);
				}
			}
			else
			{
				VecF leafOts;
				ctx.resize(leafOts, 1);
				PRNG otMasker;

				for (u64 j = 0; j < remTrees; ++j)
				{
					// The index of the child on the active path.
					auto activeChildIdx = points[j + treeIdx];

					// The index of the other (inactive) child.
					auto inactiveChildIdx = activeChildIdx ^ 1;

					// The indicator as to the left or right child is inactive
					auto notAi = inactiveChildIdx & 1;

					// offset to the first or second ot message, based on the one we want
					auto offset = ctx.template byteSize<F>() * notAi;

					// decrypt the ot string
					span<u8> buff = leafMsg.subspan(offset, ctx.template byteSize<F>());
					leafMsg = leafMsg.subspan(buff.size() * 2);
					otMasker.SetSeed(mBaseOTs[j + treeIdx][0], divCeil(buff.size(), sizeof(block)));
					for (u64 i = 0; i < buff.size(); ++i)
						buff[i] ^= otMasker.get<u8>();

					ctx.deserialize(buff.begin(), buff.end(), leafOts.begin());

					std::array<u64, 2> out{
						(activeChildIdx & ~1ull) * 8 + j + outputOffset,
						(activeChildIdx | 1ull) * 8 + j + outputOffset
					};

					auto keep = leafLevel.begin() + out[notAi];
					auto zero = leafLevel.begin() + out[notAi ^ 1];

					ctx.minus(*keep, leafOts[0], leafSums[notAi][j]);
					ctx.zero(zero, zero + 1);
				}
			}
		}
	};
}

#endif