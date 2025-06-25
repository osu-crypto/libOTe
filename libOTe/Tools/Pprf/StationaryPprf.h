#pragma once
#include "libOTe/config.h"

#ifdef ENABLE_PPRF
#include "RegularPprf.h"
#include "PprfUtil.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{

	extern const std::array<AES, 2> gGgmAes;


	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	class StationaryPprfSender : public PprfSender<F, CoeffCtx> {
	public:

		using VecF = typename CoeffCtx::template Vec<F>;

		RegularPprfSender<block> mSender;

		AlignedUnVector<block> mShare;

		u64 mExpandCounter = 0;

		bool mExpanded = false;


		void configure(u64 domainSize, u64 pointCount) override
		{
			mExpanded = false;
			mExpandCounter = 0;
			mSender.configure(domainSize, pointCount);
		}

		// the number of base OTs that should be set.
		u64 baseOtCount() const override{
			if (mExpanded)
				return 0;
			else
				return mSender.baseOtCount();
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const  override {
			return mExpanded || mSender.hasBaseOts();
		}


		void setBase(span<const std::array<block, 2>> baseMessages) override {
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;
			mSender.setBase(baseMessages);
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
			if (oFormat != PprfOutputFormat::ByTreeIndex)
				throw RTE_LOC;//not impl
			if (!programPuncturedPoint)
				throw RTE_LOC;//not impl

			u64 numTrees = mSender.mPntCount;
			u64 treeSize = mSender.mDomain;
			if (mExpanded == false)
			{
				mShare.resize(numTrees * treeSize);
				co_await mSender.expand(chl, {}, seed, mShare, PprfOutputFormat::ByTreeIndex, false, numThreads);
				mExpanded = true;
				mExpandCounter = 0;
			}


			MatrixView<block> share(mShare.data(), numTrees, treeSize);
			VecF sum, val;
			ctx.resize(sum, 8);
			ctx.resize(val, 8);
			ctx.zero(sum.begin(), sum.end());
			PRNG otMasker;
			std::array<block, 8> seeds;

			AES aes(mAesFixedKey.hashBlock(
				block(24152452152341234, 213423421546325324) ^
				block(mExpandCounter++)));

			std::vector<u8> buffer(ctx.template byteSize<F>() * numTrees);
			span<u8> leafMsgs = buffer;
			auto shareIter = share.data();
			auto outIter = output.begin();
			auto treeSize8 = treeSize / 8 * 8;


#define SIMD8(VAR, STATEMENT) \
	{ constexpr u64 VAR = 0; STATEMENT; }\
	{ constexpr u64 VAR = 1; STATEMENT; }\
	{ constexpr u64 VAR = 2; STATEMENT; }\
	{ constexpr u64 VAR = 3; STATEMENT; }\
	{ constexpr u64 VAR = 4; STATEMENT; }\
	{ constexpr u64 VAR = 5; STATEMENT; }\
	{ constexpr u64 VAR = 6; STATEMENT; }\
	{ constexpr u64 VAR = 7; STATEMENT; }\
	do{}while(0)

			for (u64 j = 0; j < numTrees; ++j)
			{
				ctx.zero(sum.begin(), sum.end());
				ctx.copy(sum[0], value[j]);
				u64 k = 0; 
				for (; k < treeSize8; k += 8)
				{
					aes.hashBlocks<8>(shareIter, seeds.data());

					SIMD8(q, ctx.template fromBlock<F>(val[q], seeds[q]));
					SIMD8(q, ctx.plus(sum[q], sum[q], val[q]));
					SIMD8(q, ctx.copy(outIter[q], val[q]));

					outIter += 8;
					shareIter += 8;
				}

				for (; k < treeSize; ++k)
				{
					auto seed = aes.hashBlock(*shareIter++);
					ctx.template fromBlock<F>(val[0], seed);
					ctx.plus(sum[0], sum[0], val[0]);
					ctx.copy(*outIter++, val[0]);
				}
				for (u64 i = 1; i < 8; ++i)
					ctx.plus(sum[0], sum[0], sum[i]);

				// copy m0 into the output buffer.
				span<u8> buff = leafMsgs.subspan(0, ctx.template byteSize<F>());
				leafMsgs = leafMsgs.subspan(buff.size());
				ctx.serialize(sum.begin(), sum.begin()+1, buff.begin());
			}

			co_await chl.send(std::move(buffer));
		}

		void clear() override {
			mSender.clear();
			mShare.clear();
			mExpanded = false;
		}

	};


	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	class StationaryPprfReceiver : public PprfReceiver<F, CoeffCtx>
	{
	public:

		RegularPprfReceiver<block> mRecver;
		AlignedUnVector<block> mShare;
		bool mExpanded = false;
		u64 mExpandCounter = 0;
		using VecF = typename CoeffCtx::template Vec<F>;

		void configure(u64 domainSize, u64 pointCount) override
		{
			mRecver.configure(domainSize, pointCount);
			mExpanded = false;
			mExpandCounter = 0;
		}


		// this function sample mPntCount integers in the range
		// [0,domain) and returns these as the choice bits.
		BitVector sampleChoiceBits(PRNG& prng) override
		{
			if (mExpanded)
				return {};

			return mRecver.sampleChoiceBits(prng);
		}

		// choices is in the same format as the output from sampleChoiceBits.
		void setChoiceBits(const BitVector& choices) override
		{
			mRecver.setChoiceBits(choices);
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const override
		{
			if (mExpanded)
				return 0;
			else
				return mRecver.baseOtCount();
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const override
		{
			if (mExpanded)
				return true;
			else
				return mRecver.hasBaseOts();
		}

		void setBase(span<const block> baseMessages) override
		{
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;
			mRecver.setBase(baseMessages);
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

			if (oFormat != PprfOutputFormat::ByTreeIndex)
				throw RTE_LOC;//not impl
			if (!programPuncturedPoint)
				throw RTE_LOC;//not impl

			u64 numTrees = mRecver.mPntCount;
			u64 treeSize = mRecver.mDomain;
			if (mExpanded == false)
			{
				mShare.resize(numTrees * treeSize);
				co_await mRecver.expand(
					chl, mShare,
					PprfOutputFormat::ByTreeIndex,
					false, numThreads);
				mExpanded = true;
				mExpandCounter = 0;
			}

			MatrixView<block> share(mShare.data(), numTrees, treeSize);

			VecF sum, val;
			ctx.resize(sum, 8);
			ctx.resize(val, 8);
			PRNG otMasker;
			std::array<block, 8> seeds;

			AES aes(mAesFixedKey.hashBlock(
				block(24152452152341234, 213423421546325324) ^
				block(mExpandCounter++)));

			std::vector<u8> buffer(ctx.template byteSize<F>() * numTrees);
			span<u8> leafMsgs = buffer;
			auto shareIter = share.data();
			auto outIter = output.begin();
			auto treeSize8 = treeSize / 8 * 8;

			co_await chl.recv(buffer);
			
			auto points = getPoints(PprfOutputFormat::ByTreeIndex);
			for (u64 j = 0; j < numTrees; ++j)
			{
				span<u8> buff = leafMsgs.subspan(0, ctx.template byteSize<F>());
				leafMsgs = leafMsgs.subspan(buff.size());
				ctx.zero(sum.begin(), sum.end());
				ctx.deserialize(buff.begin(), buff.end(), sum.begin());

				u64 k = 0;

				for (; k < treeSize8; k+=8)
				{
					aes.hashBlocks<8>(shareIter, seeds.data());
					SIMD8(q, ctx.template fromBlock<F>(val[q], seeds[q]));
					SIMD8(q, ctx.minus(sum[q], sum[q], val[q]));
					SIMD8(q, ctx.copy(outIter[q], val[q]));

					shareIter += 8;
					outIter += 8;
				}

				for (; k < treeSize; ++k)
				{
					auto seed = aes.hashBlock(*shareIter++);
					ctx.template fromBlock<F>(val[0], seed);
					ctx.minus(sum[0], sum[0], val[0]);
					ctx.copy(*outIter++, val[0]);

				}

				for (u64 i = 1; i < 8; ++i)
					ctx.plus(sum[0], sum[0], sum[i]);

				// out = s1,s2,s3,...,rp,...,sn
				// sum = v+s1+s2+s3+...+sp+...+sn 
				//        -s1-s2-s3-...-rp-...-sn
				//     = v+sp-rp
				// out[p] = sum + rp
				//        = v+sp
				ctx.plus(
					output[j * treeSize + points[j]],
					sum[0],
					output[j * treeSize + points[j]]);
			}

		}


		std::vector<u64> getPoints(PprfOutputFormat format) const override
		{
			return mRecver.getPoints(format);
		}

		void getPoints(span<u64> points, PprfOutputFormat format) const override
		{
			mRecver.getPoints(points, format);
		}

		void clear() override
		{
			mExpanded = false;
			mRecver.clear();
		}

	};
}

#undef SIMD8

#endif