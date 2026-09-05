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

#define HALF_TREE_PPRF_SIMD8(VAR, STATEMENT) do { \
	{ constexpr u64 VAR = 0; STATEMENT; } \
	{ constexpr u64 VAR = 1; STATEMENT; } \
	{ constexpr u64 VAR = 2; STATEMENT; } \
	{ constexpr u64 VAR = 3; STATEMENT; } \
	{ constexpr u64 VAR = 4; STATEMENT; } \
	{ constexpr u64 VAR = 5; STATEMENT; } \
	{ constexpr u64 VAR = 6; STATEMENT; } \
	{ constexpr u64 VAR = 7; STATEMENT; } \
} while (0)

#if defined(_MSC_VER) && defined(_M_X64)
// MSVC otherwise serializes the eight independent AES-NI chains. This is a
// compiler barrier only; it emits no machine instruction.
#define HALF_TREE_PPRF_ROUND_BARRIER() _ReadWriteBarrier()
#else
#define HALF_TREE_PPRF_ROUND_BARRIER() do {} while (0)
#endif

	extern const std::array<AES, 2> gGgmAes;

	namespace pprf
	{
		// Expand eight half-tree parents while keeping the AES outputs in
		// registers. The left child is H(x) = AES(x) XOR x and the right child
		// is x XOR H(x) = AES(x).
		OC_FORCEINLINE void expandHalfTree8(
			const AES& aes,
			const block* parents,
			block* left,
			block* right,
			block& leftAccumulator,
			block& rightAccumulator)
		{
			const auto& k = aes.mRoundKey;
			block x0 = AES::firstFn(parents[0], k[0]);
			block x1 = AES::firstFn(parents[1], k[0]);
			block x2 = AES::firstFn(parents[2], k[0]);
			block x3 = AES::firstFn(parents[3], k[0]);
			block x4 = AES::firstFn(parents[4], k[0]);
			block x5 = AES::firstFn(parents[5], k[0]);
			block x6 = AES::firstFn(parents[6], k[0]);
			block x7 = AES::firstFn(parents[7], k[0]);
			HALF_TREE_PPRF_ROUND_BARRIER();

#define HALF_TREE_PPRF_AES_ROUND(R, FN) do { \
			x0 = AES::FN(x0, k[R]); \
			x1 = AES::FN(x1, k[R]); \
			x2 = AES::FN(x2, k[R]); \
			x3 = AES::FN(x3, k[R]); \
			x4 = AES::FN(x4, k[R]); \
			x5 = AES::FN(x5, k[R]); \
			x6 = AES::FN(x6, k[R]); \
			x7 = AES::FN(x7, k[R]); \
		} while (0)

			HALF_TREE_PPRF_AES_ROUND(1, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(2, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(3, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(4, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(5, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(6, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(7, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(8, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_AES_ROUND(9, penultimateFn);
			HALF_TREE_PPRF_ROUND_BARRIER();

#undef HALF_TREE_PPRF_AES_ROUND

#define HALF_TREE_PPRF_STORE_CHILD(I) do { \
			const auto encrypted = AES::finalFn(x##I, k[10]); \
			const auto leftChild = encrypted ^ parents[I]; \
			const auto rightChild = encrypted; \
			left[I] = leftChild; \
			right[I] = rightChild; \
			leftAccumulator = leftAccumulator ^ leftChild; \
			rightAccumulator = rightAccumulator ^ rightChild; \
		} while (0)

			HALF_TREE_PPRF_STORE_CHILD(0);
			HALF_TREE_PPRF_STORE_CHILD(1);
			HALF_TREE_PPRF_STORE_CHILD(2);
			HALF_TREE_PPRF_STORE_CHILD(3);
			HALF_TREE_PPRF_STORE_CHILD(4);
			HALF_TREE_PPRF_STORE_CHILD(5);
			HALF_TREE_PPRF_STORE_CHILD(6);
			HALF_TREE_PPRF_STORE_CHILD(7);

#undef HALF_TREE_PPRF_STORE_CHILD
		}

		OC_FORCEINLINE void hashHalfTreeLeaves8(
			const AES& aes,
			const block* parents,
			block* output,
			block& accumulator)
		{
			const auto& k = aes.mRoundKey;
			block x0 = AES::firstFn(parents[0], k[0]);
			block x1 = AES::firstFn(parents[1], k[0]);
			block x2 = AES::firstFn(parents[2], k[0]);
			block x3 = AES::firstFn(parents[3], k[0]);
			block x4 = AES::firstFn(parents[4], k[0]);
			block x5 = AES::firstFn(parents[5], k[0]);
			block x6 = AES::firstFn(parents[6], k[0]);
			block x7 = AES::firstFn(parents[7], k[0]);
			HALF_TREE_PPRF_ROUND_BARRIER();

#define HALF_TREE_PPRF_HASH_ROUND(R, FN) do { \
			x0 = AES::FN(x0, k[R]); \
			x1 = AES::FN(x1, k[R]); \
			x2 = AES::FN(x2, k[R]); \
			x3 = AES::FN(x3, k[R]); \
			x4 = AES::FN(x4, k[R]); \
			x5 = AES::FN(x5, k[R]); \
			x6 = AES::FN(x6, k[R]); \
			x7 = AES::FN(x7, k[R]); \
		} while (0)

			HALF_TREE_PPRF_HASH_ROUND(1, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(2, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(3, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(4, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(5, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(6, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(7, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(8, roundFn);
			HALF_TREE_PPRF_ROUND_BARRIER();
			HALF_TREE_PPRF_HASH_ROUND(9, penultimateFn);
			HALF_TREE_PPRF_ROUND_BARRIER();

#undef HALF_TREE_PPRF_HASH_ROUND

#define HALF_TREE_PPRF_STORE_HASH(I) do { \
			const auto hash = AES::finalFn(x##I, k[10]) ^ parents[I]; \
			output[I] = hash; \
			accumulator = accumulator ^ hash; \
		} while (0)

			HALF_TREE_PPRF_STORE_HASH(0);
			HALF_TREE_PPRF_STORE_HASH(1);
			HALF_TREE_PPRF_STORE_HASH(2);
			HALF_TREE_PPRF_STORE_HASH(3);
			HALF_TREE_PPRF_STORE_HASH(4);
			HALF_TREE_PPRF_STORE_HASH(5);
			HALF_TREE_PPRF_STORE_HASH(6);
			HALF_TREE_PPRF_STORE_HASH(7);

#undef HALF_TREE_PPRF_STORE_HASH
		}
	}


	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	class HalfTreePprfSender : public PprfSender<F, CoeffCtx> {
	public:

		// the number of leaves in a single tree.
		u64 mDomain = 0;

		// the depth of each tree.
		u64 mDepth = 0;

		// the number of trees.
		u64 mPntCount = 0;

		// the values that should be programmed at the punctured points.
		std::vector<F> mValue;

		// the base OTs that should be set.
		Matrix<std::array<block, 2>> mBaseOTs;

		// if true, tree OT messages are eagerly sent in batches of 8.
		// otherwise, the OT messages are sent in a single batch.
		bool mEagerSend = true;

		using VecF = typename CoeffCtx::template Vec<F>;

		// a function that can be used to output the result of the PPRF.
		std::function<void(u64 treeIdx, VecF& leaf)> mOutputFn;

		// Compact two-level scratch reused one tree at a time.
		pprf::ExpandTreeBuffer mTempBuffer;

		HalfTreePprfSender() = default;

		HalfTreePprfSender(const HalfTreePprfSender&) = delete;

		HalfTreePprfSender(HalfTreePprfSender&&) = delete;

		HalfTreePprfSender(u64 domainSize, u64 pointCount) {
			configure(domainSize, pointCount);
		}

		void configure(u64 domainSize, u64 pointCount) override
		{
			auto depth = pprf::validateConfigure(domainSize, pointCount);
			mDomain = domainSize;
			mDepth = depth;
			mPntCount = pointCount;

			mBaseOTs.resize(0, 0);
			mValue.clear();
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const override {
			return mDepth * mPntCount;
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const override {
			return mBaseOTs.rows() == mPntCount &&
				mBaseOTs.cols() == mDepth && mBaseOTs.size();
		}


		void setBase(span<const std::array<block, 2>> baseMessages) override {
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before setting base OTs. " LOCATION);
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
			CoeffCtx ctx = {}) override
		{
			(void)numThreads;
			auto consumeBaseOts = false;
			MACORO_TRY {
				pprf::validateExpandFormat(oFormat, output, mDomain, mPntCount);
				if (!hasBaseOts())
					throw std::runtime_error("PPRF sender base OTs are not set. " LOCATION);
				if (oFormat == PprfOutputFormat::Callback && !mOutputFn)
					throw std::runtime_error("PPRF callback output requires a callback. " LOCATION);
				if (programPuncturedPoint)
					setValue(value);

				this->setTimePoint("SilentMultiPprfSender.start");
				consumeBaseOts = true;

				std::vector<span<AlignedArray<block, 8>>> levels;
				if (mDepth > 3)
				{
					const auto parentDomain = pprf::paddedDomain(mDomain) / 16;
					pprf::allocateExpandTree(parentDomain, mTempBuffer, levels);
				}

				VecF callbackLeaves;
				if (oFormat == PprfOutputFormat::Callback)
					ctx.resize(callbackLeaves, mDomain);

				auto buff = std::vector<u8>{};
				auto encSums = span<std::array<block, 2>>{};
				auto leafMsgs = span<u8>{};
				const auto encPerTree = mDepth - 1;
				const auto leafPerTree =
					ctx.template byteSize<F>() * (2 + 2 * u64(programPuncturedPoint));

				for (u64 batch = 0; batch < mPntCount;)
				{
					const auto count = mEagerSend ?
						std::min<u64>(8, mPntCount - batch) :
						mPntCount;
					pprf::allocateExpandBuffer<F>(
						encPerTree, count, programPuncturedPoint,
						buff, encSums, leafMsgs, ctx);

					for (u64 j = 0; j < count; ++j)
					{
						const auto tree = batch + j;
						const auto root = mAesFixedKey.ecbEncBlock(seed ^ block(tree));
						auto treeSums = encSums.subspan(j * encPerTree, encPerTree);
						auto treeLeaves = leafMsgs.subspan(j * leafPerTree, leafPerTree);
						auto levelSpan = span<span<AlignedArray<block, 8>>>(levels);

						switch (oFormat)
						{
						case PprfOutputFormat::ByLeafIndex:
							expandOne<PprfOutputFormat::ByLeafIndex>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							break;
						case PprfOutputFormat::ByTreeIndex:
							expandOne<PprfOutputFormat::ByTreeIndex>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							break;
						case PprfOutputFormat::ByPhysicalIndex:
							expandOne<PprfOutputFormat::ByPhysicalIndex>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							break;
						case PprfOutputFormat::Callback:
							expandOne<PprfOutputFormat::Callback>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							mOutputFn(tree, callbackLeaves);
							break;
						default:
							throw RTE_LOC;
						}
					}

					co_await chl.send(std::move(buff));
					batch += count;
					if (!mEagerSend)
						break;
				}

				mBaseOTs = {};
				consumeBaseOts = false;
				this->setTimePoint("SilentMultiPprfSender.de-alloc");
			}
			MACORO_CATCH(eptr) {
				if (consumeBaseOts)
					mBaseOTs = {};
				if (!chl.closed())
					co_await chl.close();
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

		void clear() override {
			mBaseOTs.resize(0, 0);
			mValue.clear();
			mTempBuffer.clear();
			mDomain = 0;
			mDepth = 0;
			mPntCount = 0;
		}

		template<PprfOutputFormat Format>
		void expandOne(
			block root,
			u64 treeIdx,
			bool programPuncturedPoint,
			span<span<AlignedArray<block, 8>>> levels,
			VecF& output,
			VecF& callbackLeaves,
			span<std::array<block, 2>> encSums,
			span<u8> leafMsgs,
			CoeffCtx& ctx)
		{
			assert(encSums.size() == mDepth - 1);
			auto encSumIter = encSums.begin();
			std::array<block, 8> current{};
			std::array<block, 8> next{};
			current[0] = root;

			const auto topInternalDepth = std::min<u64>(3, mDepth - 1);
			for (u64 d = 0; d < topInternalDepth; ++d)
			{
				block leftAccumulator = ZeroBlock;
				block rightAccumulator = ZeroBlock;
				const auto width = u64{ 1 } << d;
				for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					const auto aes = mAesFixedKey.ecbEncBlock(parent);
					// The half-tree variant uses H(x) = AES(x) XOR x and
					// derives the other child as x XOR H(x) = AES(x).
					const auto left = aes ^ parent;
					const auto right = aes;
					next[2 * parentIdx] = left;
					next[2 * parentIdx + 1] = right;
					leftAccumulator = leftAccumulator ^ left;
					rightAccumulator = rightAccumulator ^ right;
				}
				(*encSumIter)[0] = leftAccumulator ^
					mBaseOTs(treeIdx, mDepth - 1 - d)[1];
				(*encSumIter)[1] = rightAccumulator ^
					mBaseOTs(treeIdx, mDepth - 1 - d)[0];
				++encSumIter;
				current = next;
			}

			if (mDepth > 3)
			{
				assert(levels.size() == mDepth - 3);
				HALF_TREE_PPRF_SIMD8(lane, {
					levels[0][0][lane] = current[lane];
				});

				for (u64 localDepth = 0; localDepth + 1 < levels.size(); ++localDepth)
				{
					block leftAccumulator = ZeroBlock;
					block rightAccumulator = ZeroBlock;
					auto parents = levels[localDepth];
					auto children = levels[localDepth + 1];
					const auto width = u64{ 1 } << localDepth;
					for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
					{
						auto& parent = parents[parentIdx];
						auto& left = children[2 * parentIdx];
						auto& right = children[2 * parentIdx + 1];
						pprf::expandHalfTree8(
							mAesFixedKey, parent.data(), left.data(), right.data(),
							leftAccumulator, rightAccumulator);
					}

					const auto globalDepth = 3 + localDepth;
					(*encSumIter)[0] = leftAccumulator ^
						mBaseOTs(treeIdx, mDepth - 1 - globalDepth)[1];
					(*encSumIter)[1] = rightAccumulator ^
						mBaseOTs(treeIdx, mDepth - 1 - globalDepth)[0];
					++encSumIter;
				}
			}
			assert(encSumIter == encSums.end());

			auto leafSums = ctx.template makeVec<F>(2);
			ctx.zero(leafSums.begin(), leafSums.end());
			const auto padded = pprf::paddedDomain(mDomain);
			const auto subtreeDomain = mDepth > 3 ? padded / 8 : padded;
			u64 nativeLeaf = 0;

			auto storeLeaf = [&](u64 logicalLeaf, u64 physicalLeaf, const F& value) {
				if constexpr (Format == PprfOutputFormat::ByLeafIndex)
					ctx.copy(output[logicalLeaf * mPntCount + treeIdx], value);
				else if constexpr (Format == PprfOutputFormat::ByTreeIndex)
					ctx.copy(output[treeIdx * mDomain + logicalLeaf], value);
				else if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
					ctx.copy(output[treeIdx * mDomain + physicalLeaf], value);
				else
					ctx.copy(callbackLeaves[physicalLeaf], value);
			};

			auto addLeaf = [&](u64 side, const block& hashed, u64 logicalLeaf) {
				F value;
				if constexpr (std::is_same_v<F, block>)
					value = hashed;
				else
					ctx.fromBlock(value, hashed);
				ctx.plus(leafSums[side], leafSums[side], value);
				if (logicalLeaf < mDomain)
					storeLeaf(logicalLeaf, nativeLeaf++, value);
			};

			if (mDepth <= 3)
			{
				const auto parentWidth = padded / 2;
				for (u64 parentIdx = 0; parentIdx < parentWidth; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					addLeaf(0, gGgmAes[0].hashBlock(parent), 2 * parentIdx);
					addLeaf(1, gGgmAes[1].hashBlock(parent), 2 * parentIdx + 1);
				}
			}
			else
			{
				auto parents = levels.back();
				auto generateGeneric = [&] {
					std::array<block, 8> hashed;
					for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
					{
						for (u64 side = 0; side < 2; ++side)
						{
							gGgmAes[side].hashBlocks<8>(
								parents[parentIdx].data(), hashed.data());
							const auto localLeaf = 2 * parentIdx + side;
							HALF_TREE_PPRF_SIMD8(lane, {
								addLeaf(
									side, hashed[lane],
									lane * subtreeDomain + localLeaf);
							});
						}
					}
				};

				if constexpr (
					std::is_same_v<F, block> &&
					std::is_base_of_v<CoeffCtxGF2, CoeffCtx> &&
					(Format == PprfOutputFormat::ByPhysicalIndex ||
						Format == PprfOutputFormat::Callback))
				{
					if (mDomain == padded)
					{
						block* dest;
						if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
							dest = output.data() + treeIdx * mDomain;
						else
							dest = callbackLeaves.data();

						block leftAccumulator = ZeroBlock;
						block rightAccumulator = ZeroBlock;
						for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
						{
							pprf::hashHalfTreeLeaves8(gGgmAes[0],
								parents[parentIdx].data(), dest + nativeLeaf,
								leftAccumulator);
							nativeLeaf += 8;
							pprf::hashHalfTreeLeaves8(gGgmAes[1],
								parents[parentIdx].data(), dest + nativeLeaf,
								rightAccumulator);
							nativeLeaf += 8;
						}
						leafSums[0] = leftAccumulator;
						leafSums[1] = rightAccumulator;
					}
					else
					{
						generateGeneric();
					}
				}
				else
				{
					generateGeneric();
				}
			}
			assert(nativeLeaf == mDomain);

			auto leafOts = ctx.template makeVec<F>(2);
			PRNG otMasker;
			for (u64 choice = 0; choice < 2; ++choice)
			{
				if (programPuncturedPoint)
				{
					if (choice == 0)
					{
						ctx.copy(leafOts[0], leafSums[0]);
						ctx.plus(leafOts[1], leafSums[1], mValue[treeIdx]);
					}
					else
					{
						ctx.plus(leafOts[0], leafSums[0], mValue[treeIdx]);
						ctx.copy(leafOts[1], leafSums[1]);
					}
				}
				else
				{
					ctx.copy(leafOts[0], leafSums[choice]);
				}

				const auto count = 1 + u64(programPuncturedPoint);
				auto msg = leafMsgs.subspan(
					0, count * ctx.template byteSize<F>());
				leafMsgs = leafMsgs.subspan(msg.size());
				ctx.serialize(leafOts.begin(), leafOts.begin() + count, msg.begin());
				otMasker.SetSeed(
					mBaseOTs(treeIdx, 0)[1 ^ choice],
					divCeil(msg.size(), sizeof(block)));
				for (u64 i = 0; i < msg.size(); ++i)
					msg[i] ^= otMasker.get<u8>();
			}
			assert(leafMsgs.empty());
		}


	};


	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	class HalfTreePprfReceiver : public PprfReceiver<F, CoeffCtx>
	{
	public:

		// the number of leaves in a single tree.
		u64 mDomain = 0;

		// the depth of each tree.
		u64 mDepth = 0;

		// the number of trees.
		u64 mPntCount = 0;

		using VecF = typename CoeffCtx::template Vec<F>;

		// base ots that will be used to expand the tree.
		Matrix<block> mBaseOTs;

		// the choice bits, each row should be the bit decomposition of the active path.
		Matrix<u8> mBaseChoices;

		// if true, tree OT messages are eagerly sent in batches of 8.
		// otherwise, the OT messages are sent in a single batch.
		bool mEagerSend = true;

		// a function that can be used to output the result of the PPRF.
		std::function<void(u64 treeIdx, VecF& leafs)> mOutputFn;

		// Compact two-level scratch reused one tree at a time.
		pprf::ExpandTreeBuffer mTempBuffer;

		HalfTreePprfReceiver() = default;
		HalfTreePprfReceiver(const HalfTreePprfReceiver&) = delete;
		HalfTreePprfReceiver(HalfTreePprfReceiver&&) = delete;

		void configure(u64 domainSize, u64 pointCount) override
		{
			auto depth = pprf::validateConfigure(domainSize, pointCount);
			mDomain = domainSize;
			mDepth = depth;
			mPntCount = pointCount;

			mBaseOTs.resize(0, 0);
			mBaseChoices.resize(0, 0);
		}


		// this function sample mPntCount integers in the range
		// [0,domain) and returns these as the choice bits.
		BitVector sampleChoiceBits(PRNG& prng)override
		{
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before sampling choices. " LOCATION);
			BitVector choices(mPntCount * mDepth);

			mBaseChoices.resize(mPntCount, mDepth);
			for (u64 i = 0; i < mPntCount; ++i)
			{
				u64 idx = pprf::sampleMod(prng, mDomain);
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
		void setChoiceBits(const BitVector& choices)override
		{
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before setting choices. " LOCATION);
			// Make sure we're given the right number of OTs.
			if (choices.size() != baseOtCount())
				throw RTE_LOC;

			// Validate every encoded point before changing the active paths.
			for (u64 i = 0; i < mPntCount; ++i)
			{
				u64 idx = 0;
				for (u64 j = 0; j < mDepth; ++j)
					idx |= u64(choices[mDepth * i + j]) << j;

				if (idx >= mDomain)
					throw std::runtime_error("provided choice bits index outside of the domain." LOCATION);
			}

			mBaseChoices.resize(mPntCount, mDepth);
			for (u64 i = 0; i < mBaseChoices.size(); ++i)
				mBaseChoices(i) = choices[i];
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const override
		{
			return mDepth * mPntCount;
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const override
		{
			return mBaseOTs.rows() == mPntCount &&
				mBaseOTs.cols() == mDepth && mBaseOTs.size();
		}

		bool hasChoiceBits() const
		{
			return mBaseChoices.rows() == mPntCount &&
				mBaseChoices.cols() == mDepth && mBaseChoices.size();
		}


		void setBase(span<const block> baseMessages) override
		{
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before setting base OTs. " LOCATION);
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;

			mBaseOTs.resize(mPntCount, mDepth);
			memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));
		}


		std::vector<u64> getPoints(PprfOutputFormat format) const override
		{
			std::vector<u64> pnts(mPntCount);
			getPoints(pnts, format);
			return pnts;
		}

		void getPoints(span<u64> points, PprfOutputFormat format) const  override
		{
			if ((u64)points.size() != mPntCount)
				throw RTE_LOC;
			if (!hasChoiceBits())
				throw std::runtime_error("PPRF receiver choices are not set. " LOCATION);

			switch (format)
			{
			case PprfOutputFormat::ByLeafIndex:
			case PprfOutputFormat::ByTreeIndex:

				memset(points.data(), 0, points.size() * sizeof(u64));
				for (u64 j = 0; j < mPntCount; ++j)
				{
					for (u64 k = 0; k < mDepth; ++k)
						points[j] |= u64(mBaseChoices(j, k)) << k;

					if (points[j] >= mDomain)
						throw std::runtime_error("PPRF receiver choice is outside the domain. " LOCATION);
				}


				break;
			case PprfOutputFormat::ByPhysicalIndex:
			case PprfOutputFormat::Callback:

				getPoints(points, PprfOutputFormat::ByLeafIndex);
				for (u64 j = 0; j < points.size(); ++j)
					points[j] = j * mDomain +
						pprf::physicalLeafIndex(mDomain, points[j]);

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
			CoeffCtx ctx = {}) override
		{
			(void)numThreads;
			auto consumeBaseOts = false;
			MACORO_TRY {
				pprf::validateExpandFormat(oFormat, output, mDomain, mPntCount);
				if (!hasBaseOts())
					throw std::runtime_error("PPRF receiver base OTs are not set. " LOCATION);
				if (!hasChoiceBits())
					throw std::runtime_error("PPRF receiver choices are not set. " LOCATION);
				if (oFormat == PprfOutputFormat::Callback && !mOutputFn)
					throw std::runtime_error("PPRF callback output requires a callback. " LOCATION);

				this->setTimePoint("SilentMultiPprfReceiver.start");
				consumeBaseOts = true;

				auto points = getPoints(PprfOutputFormat::ByTreeIndex);
				std::vector<span<AlignedArray<block, 8>>> levels;
				if (mDepth > 3)
				{
					const auto parentDomain = pprf::paddedDomain(mDomain) / 16;
					pprf::allocateExpandTree(parentDomain, mTempBuffer, levels);
				}

				VecF callbackLeaves;
				if (oFormat == PprfOutputFormat::Callback)
					ctx.resize(callbackLeaves, mDomain);

				auto buff = std::vector<u8>{};
				auto theirSums = span<std::array<block, 2>>{};
				auto leafMsgs = span<u8>{};
				const auto sumsPerTree = mDepth - 1;
				const auto leafPerTree =
					ctx.template byteSize<F>() * (2 + 2 * u64(programPuncturedPoint));

				for (u64 batch = 0; batch < mPntCount;)
				{
					const auto count = mEagerSend ?
						std::min<u64>(8, mPntCount - batch) :
						mPntCount;
					pprf::allocateExpandBuffer<F>(
						sumsPerTree, count, programPuncturedPoint,
						buff, theirSums, leafMsgs, ctx);
					co_await chl.recv(buff);

					for (u64 j = 0; j < count; ++j)
					{
						const auto tree = batch + j;
						auto treeSums = theirSums.subspan(j * sumsPerTree, sumsPerTree);
						auto treeLeaves = leafMsgs.subspan(j * leafPerTree, leafPerTree);
						auto levelSpan = span<span<AlignedArray<block, 8>>>(levels);

						switch (oFormat)
						{
						case PprfOutputFormat::ByLeafIndex:
							expandOne<PprfOutputFormat::ByLeafIndex>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							break;
						case PprfOutputFormat::ByTreeIndex:
							expandOne<PprfOutputFormat::ByTreeIndex>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							break;
						case PprfOutputFormat::ByPhysicalIndex:
							expandOne<PprfOutputFormat::ByPhysicalIndex>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							break;
						case PprfOutputFormat::Callback:
							expandOne<PprfOutputFormat::Callback>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							mOutputFn(tree, callbackLeaves);
							break;
						default:
							throw RTE_LOC;
						}
					}

					batch += count;
					if (!mEagerSend)
						break;
				}

				this->setTimePoint("SilentMultiPprfReceiver.join");
				mBaseOTs = {};
				consumeBaseOts = false;
				this->setTimePoint("SilentMultiPprfReceiver.de-alloc");
			}
			MACORO_CATCH(eptr) {
				if (consumeBaseOts)
					mBaseOTs = {};
				if (!chl.closed())
					co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		void clear() override
		{
			mBaseOTs.resize(0, 0);
			mBaseChoices.resize(0, 0);
			mTempBuffer.clear();
			mDomain = 0;
			mDepth = 0;
			mPntCount = 0;
		}

		template<PprfOutputFormat Format>
		void expandOne(
			u64 treeIdx,
			bool programPuncturedPoint,
			span<span<AlignedArray<block, 8>>> levels,
			VecF& output,
			VecF& callbackLeaves,
			span<std::array<block, 2>> theirSums,
			span<u8> leafMsgs,
			u64 point,
			CoeffCtx& ctx)
		{
			assert(theirSums.size() == mDepth - 1);
			auto theirSumsIter = theirSums.begin();
			std::array<block, 8> current{};
			std::array<block, 8> next{};

			const auto zeroAes = mAesFixedKey.ecbEncBlock(ZeroBlock);
			const std::array<block, 2> inactiveInternal{ zeroAes, zeroAes };

			const auto topInternalDepth = std::min<u64>(3, mDepth - 1);
			for (u64 d = 0; d < topInternalDepth; ++d)
			{
				block leftAccumulator = inactiveInternal[0];
				block rightAccumulator = inactiveInternal[1];
				const auto width = u64{ 1 } << d;
				for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					const auto aes = mAesFixedKey.ecbEncBlock(parent);
					const auto left = aes ^ parent;
					const auto right = aes;
					next[2 * parentIdx] = left;
					next[2 * parentIdx + 1] = right;
					leftAccumulator = leftAccumulator ^ left;
					rightAccumulator = rightAccumulator ^ right;
				}

				const auto missing = point >> (mDepth - 1 - d);
				const auto sibling = missing ^ 1;
				const auto branch = sibling & 1;
				const std::array<block, 2> sums{
					leftAccumulator, rightAccumulator
				};
				next[sibling] = (*theirSumsIter)[branch] ^ sums[branch] ^
					mBaseOTs(treeIdx, mDepth - 1 - d);
				next[missing] = ZeroBlock;
				++theirSumsIter;
				current = next;
			}

			if (mDepth > 3)
			{
				assert(levels.size() == mDepth - 3);
				HALF_TREE_PPRF_SIMD8(lane, {
					levels[0][0][lane] = current[lane];
				});

				for (u64 localDepth = 0; localDepth + 1 < levels.size(); ++localDepth)
				{
					block leftAccumulator = inactiveInternal[0];
					block rightAccumulator = inactiveInternal[1];
					auto parents = levels[localDepth];
					auto children = levels[localDepth + 1];
					const auto width = u64{ 1 } << localDepth;
					for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
					{
						auto& parent = parents[parentIdx];
						auto& left = children[2 * parentIdx];
						auto& right = children[2 * parentIdx + 1];
						pprf::expandHalfTree8(
							mAesFixedKey, parent.data(), left.data(), right.data(),
							leftAccumulator, rightAccumulator);
					}

					const auto globalDepth = 3 + localDepth;
					const auto childDepth = globalDepth + 1;
					const auto missingPrefix = point >> (mDepth - childDepth);
					const auto localChildDepth = childDepth - 3;
					const auto lane = missingPrefix >> localChildDepth;
					const auto localMask = (u64{ 1 } << localChildDepth) - 1;
					const auto missing = missingPrefix & localMask;
					const auto sibling = missing ^ 1;
					const auto branch = sibling & 1;
					const std::array<block, 2> sums{
						leftAccumulator, rightAccumulator
					};
					children[sibling][lane] = (*theirSumsIter)[branch] ^
						sums[branch] ^ mBaseOTs(treeIdx, mDepth - 1 - globalDepth);
					children[missing][lane] = ZeroBlock;
					++theirSumsIter;
				}
			}
			assert(theirSumsIter == theirSums.end());

			auto leafSums = ctx.template makeVec<F>(2);
			auto zero = ctx.template makeVec<F>(1);
			ctx.zero(zero.begin(), zero.end());
			for (u64 side = 0; side < 2; ++side)
			{
				F inactive;
				if constexpr (std::is_same_v<F, block>)
					inactive = gGgmAes[side].hashBlock(ZeroBlock);
				else
					ctx.fromBlock(inactive, gGgmAes[side].hashBlock(ZeroBlock));
				ctx.minus(leafSums[side], zero[0], inactive);
			}

			const auto padded = pprf::paddedDomain(mDomain);
			const auto subtreeDomain = mDepth > 3 ? padded / 8 : padded;
			u64 nativeLeaf = 0;

			auto storeLeaf = [&](u64 logicalLeaf, u64 physicalLeaf, const F& value) {
				if constexpr (Format == PprfOutputFormat::ByLeafIndex)
					ctx.copy(output[logicalLeaf * mPntCount + treeIdx], value);
				else if constexpr (Format == PprfOutputFormat::ByTreeIndex)
					ctx.copy(output[treeIdx * mDomain + logicalLeaf], value);
				else if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
					ctx.copy(output[treeIdx * mDomain + physicalLeaf], value);
				else
					ctx.copy(callbackLeaves[physicalLeaf], value);
			};

			auto addLeaf = [&](u64 side, const block& hashed, u64 logicalLeaf) {
				F value;
				if constexpr (std::is_same_v<F, block>)
					value = hashed;
				else
					ctx.fromBlock(value, hashed);
				ctx.plus(leafSums[side], leafSums[side], value);
				if (logicalLeaf < mDomain)
					storeLeaf(logicalLeaf, nativeLeaf++, value);
			};

			if (mDepth <= 3)
			{
				const auto parentWidth = padded / 2;
				for (u64 parentIdx = 0; parentIdx < parentWidth; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					addLeaf(0, gGgmAes[0].hashBlock(parent), 2 * parentIdx);
					addLeaf(1, gGgmAes[1].hashBlock(parent), 2 * parentIdx + 1);
				}
			}
			else
			{
				auto parents = levels.back();
				auto generateGeneric = [&] {
					std::array<block, 8> hashed;
					for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
					{
						for (u64 side = 0; side < 2; ++side)
						{
							gGgmAes[side].hashBlocks<8>(
								parents[parentIdx].data(), hashed.data());
							const auto localLeaf = 2 * parentIdx + side;
							HALF_TREE_PPRF_SIMD8(lane, {
								addLeaf(
									side, hashed[lane],
									lane * subtreeDomain + localLeaf);
							});
						}
					}
				};

				if constexpr (
					std::is_same_v<F, block> &&
					std::is_base_of_v<CoeffCtxGF2, CoeffCtx> &&
					(Format == PprfOutputFormat::ByPhysicalIndex ||
						Format == PprfOutputFormat::Callback))
				{
					if (mDomain == padded)
					{
						block* dest;
						if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
							dest = output.data() + treeIdx * mDomain;
						else
							dest = callbackLeaves.data();

						block leftAccumulator = gGgmAes[0].hashBlock(ZeroBlock);
						block rightAccumulator = gGgmAes[1].hashBlock(ZeroBlock);
						for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
						{
							pprf::hashHalfTreeLeaves8(gGgmAes[0],
								parents[parentIdx].data(), dest + nativeLeaf,
								leftAccumulator);
							nativeLeaf += 8;
							pprf::hashHalfTreeLeaves8(gGgmAes[1],
								parents[parentIdx].data(), dest + nativeLeaf,
								rightAccumulator);
							nativeLeaf += 8;
						}
						leafSums[0] = leftAccumulator;
						leafSums[1] = rightAccumulator;
					}
					else
					{
						generateGeneric();
					}
				}
				else
				{
					generateGeneric();
				}
			}
			assert(nativeLeaf == mDomain);

			const auto active = point;
			const auto inactive = active ^ 1;
			const auto inactiveSide = inactive & 1;
			const auto valueCount = 1 + u64(programPuncturedPoint);
			const auto valueBytes = valueCount * ctx.template byteSize<F>();
			auto selected = leafMsgs.subspan(inactiveSide * valueBytes, valueBytes);
			PRNG otMasker(
				mBaseOTs(treeIdx, 0),
				divCeil(selected.size(), sizeof(block)));
			for (u64 i = 0; i < selected.size(); ++i)
				selected[i] ^= otMasker.get<u8>();

			auto leafOts = ctx.template makeVec<F>(valueCount);
			ctx.deserialize(selected.begin(), selected.end(), leafOts.begin());
			if (programPuncturedPoint)
			{
				F left;
				F right;
				ctx.minus(left, leafOts[0], leafSums[0]);
				ctx.minus(right, leafOts[1], leafSums[1]);
				storeLeaf(active & ~u64{ 1 },
					pprf::physicalLeafIndex(mDomain, active & ~u64{ 1 }), left);
				storeLeaf(active | 1,
					pprf::physicalLeafIndex(mDomain, active | 1), right);
			}
			else
			{
				F keep;
				ctx.minus(keep, leafOts[0], leafSums[inactiveSide]);
				storeLeaf(inactive,
					pprf::physicalLeafIndex(mDomain, inactive), keep);
				storeLeaf(active,
					pprf::physicalLeafIndex(mDomain, active), zero[0]);
			}
		}

	};

}

#undef HALF_TREE_PPRF_SIMD8
#undef HALF_TREE_PPRF_ROUND_BARRIER

#endif
