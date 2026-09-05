#pragma once

#include "libOTe/config.h"
#if defined(ENABLE_REGULAR_DPF)


#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#include "DpfMult.h"
#include "libOTe/Tools/CoeffCtx.h" 
#include <limits>

namespace osuCrypto
{
#define REGULAR_DPF_SIMD8(VAR, STATEMENT) do { \
	{ constexpr u64 VAR = 0; STATEMENT; } \
	{ constexpr u64 VAR = 1; STATEMENT; } \
	{ constexpr u64 VAR = 2; STATEMENT; } \
	{ constexpr u64 VAR = 3; STATEMENT; } \
	{ constexpr u64 VAR = 4; STATEMENT; } \
	{ constexpr u64 VAR = 5; STATEMENT; } \
	{ constexpr u64 VAR = 6; STATEMENT; } \
	{ constexpr u64 VAR = 7; STATEMENT; } \
} while (0)

	struct RegularDpfKey
	{
		template<typename F, typename CoeffCtx = DefaultCoeffCtx<F>>
		void resize(u64 domain, u64 numTrees, CoeffCtx ctx = {}, bool programLeafVal = true)
		{
			auto depth = log2ceil(domain);
			if (depth == 0 || depth >= 64)
				throw RTE_LOC;

			mCorrectionWords.resize(depth, numTrees);
			mCorrectionBits.resize(depth, numTrees);
			auto byteSize = ctx.template byteSize<F>();
			if (numTrees && byteSize > std::numeric_limits<u64>::max() / numTrees)
				throw RTE_LOC;
			if (programLeafVal)
				mLeafVals.resize(numTrees * byteSize);
			else
				mLeafVals.clear();
		}
		block mSeed;
		Matrix<block> mCorrectionWords;
		Matrix<u8> mCorrectionBits;
		std::vector<u8> mLeafVals;

		bool operator==(const RegularDpfKey& o) const
		{
			return
				mSeed == o.mSeed &&
				mCorrectionWords == o.mCorrectionWords &&
				mCorrectionBits == o.mCorrectionBits &&
				mLeafVals == o.mLeafVals;
		}

		u64 sizeBytes() { return sizeof(block) * (1 + mCorrectionWords.size()) + mCorrectionBits.size() + mLeafVals.size(); }
		void toBytes(span<u8> dest)
		{
			if (dest.size() != sizeBytes())
				throw RTE_LOC;
			copyBytesMin(dest, mSeed);
			dest = dest.subspan(sizeof(block));
			copyBytesMin(dest, mCorrectionWords);
			dest = dest.subspan(mCorrectionWords.size() * sizeof(block));
			copyBytesMin(dest, mCorrectionBits);
			dest = dest.subspan(mCorrectionBits.size());
			copyBytes(dest, mLeafVals);
		}

		void fromBytes(span<u8> src)
		{
			if (src.size() != sizeBytes())
				throw RTE_LOC;

			auto correctionBits = src.subspan(
				sizeof(block) + mCorrectionWords.size() * sizeof(block),
				mCorrectionBits.size());
			for (auto bit : correctionBits)
				if (bit > 1)
					throw RTE_LOC;

			copyBytesMin(mSeed, src);
			src = src.subspan(sizeof(block));
			copyBytesMin(mCorrectionWords, src);
			src = src.subspan(mCorrectionWords.size() * sizeof(block));
			copyBytesMin(mCorrectionBits, src);
			src = src.subspan(mCorrectionBits.size());
			copyBytes(mLeafVals, src);
		}

	};

	inline std::ostream& operator<<(std::ostream& o, const RegularDpfKey& k)
	{
		o << k.mSeed << std::endl;
		for (u64 i = 0; i < k.mCorrectionWords.size(); ++i)
		{
			o << k.mCorrectionWords(i) << " " << int(k.mCorrectionBits(i)) << " ";
		}
		o << std::endl;
		for (u64 i = 0; i < k.mLeafVals.size(); ++i)
			o << k.mLeafVals[i] << " ";
		o << std::endl;

		return o;
	}

	template<typename T, typename CoeffCtx = DefaultCoeffCtx<T>>
	struct RegularDpf
	{
		struct CompactScratch;

		RegularDpf() = default;
		RegularDpf(const RegularDpf&) = delete;
		RegularDpf& operator=(const RegularDpf&) = delete;

		RegularDpf(RegularDpf&& src) noexcept
		{
			*this = std::move(src);
		}

		RegularDpf& operator=(RegularDpf&& src) noexcept
		{
			if (this != &src)
			{
				mPartyIdx = src.mPartyIdx;
				mDomain = src.mDomain;
				mDepth = src.mDepth;
				mNumPoints = src.mNumPoints;
				mMultiplier = std::move(src.mMultiplier);
				src.clear();
			}
			return *this;
		}

		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		u64 mDepth = 0;

		u64 mNumPoints = 0;

		DpfMult mMultiplier;

		// used to initialize the interactive protocols.
		void init(
			u64 partyIdx,
			u64 domain,
			u64 numPoints,
			CoeffCtx ctx = {});


		bool hasBaseOts() const
		{
			return mMultiplier.hasBaseOts();
		}


		// returns the number of OTs required for the protocol.
		// each party must have this many OTs as the sender and 
		// as the receiver.
		u64 baseOtCount() const;

		// set the base OTs.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices);

		// perform interactive full domain eval.
		// - points should be a secret sharing of the locations.
		// - values should be a secret sharing of the values.
		// - output should be a lambda of the form [](treeIdx, leadIdx, value, tag){...}
		// this will be called for each leaf value produced. tag is a zero/one secret sharing
		// indicating if this is the active leaf. Each tree completes before the next;
		// leaves use physical order. leadIdx is the logical domain index.
		// - prng randomness.
		// - sock is the network socket to the other party.
		// - ctx context for F operations.
		template<typename VecT, typename Output>
		macoro::task<> expand(
			span<u64> points,
			VecT&& values,
			PRNG& prng,
			coproto::Socket& sock,
			Output&& output,
			CoeffCtx ctx = {});


		// perform interactive key generation.
		// - points should be a secret sharing of the locations.
		// - values should be a secret sharing of the values.
		// - seed should be a random seed.
		// - outputKey is where the result is written to.
		// - sock is the network socket to the other party.
		macoro::task<> keyGen(
			span<u64> points,
			auto&& values,
			PRNG& seed,
			RegularDpfKey& outputKey,
			coproto::Socket& sock,
			CoeffCtx ctx = {});

		// As above, but reuse caller-owned compact tree storage. This is useful
		// when generating several keys with the same maximum domain.
		macoro::task<> keyGen(
			span<u64> points,
			auto&& values,
			PRNG& seed,
			RegularDpfKey& outputKey,
			CompactScratch& scratch,
			coproto::Socket& sock,
			CoeffCtx ctx = {});


		// A static function that can generate a pair of keys. 
		// - domain is the number of leaf values.
		// - points is the plaintext list of locations.
		// - values is the plaintext list of values.
		// - prng is the source of randomness.
		// - keys is a list of two keys where the result is written.
		static void keyGen(
			u64 domain,
			span<u64> points,
			auto&& values,
			PRNG& prng,
			span<RegularDpfKey> keys,
			CoeffCtx ctx = {});

		// A static function that performs non-interative
		// full domain evaluation. 
		// - partyIdx is this partie's index, 0 or 1.
		// - domain is the number of leaf values.
		// - key is the share of the FSS key.
		// - output should be a lambda of the form [](treeIdx, leadIdx, value, tag){...}
		// this will be called for each leaf value produced. tag is a zero/one secret sharing
		// indicating if this is the active leaf. Each tree completes before the next;
		// leaves use the physical order of the compact tree kernel. leadIdx is the
		// logical domain index and must be used if ordered output is required.
		template<typename Output>
		static void expand(
			u64 partyIdx,
			u64 domain,
			const RegularDpfKey& key,
			Output&& output,
			CoeffCtx ctx = {});

		// As above, but reuse caller-owned scratch independent of the number of
		// DPF trees. Eight physical lanes are eight public subtrees of one tree.
		template<typename Output>
		static void expand(
			u64 partyIdx,
			u64 domain,
			const RegularDpfKey& key,
			CompactScratch& scratch,
			Output&& output,
			CoeffCtx ctx = {});

		template<typename VecT>
		macoro::task<> implKeyGen(
			span<u64> points,
			VecT&& values,
			PRNG& prng,
			RegularDpfKey& outputKey,
			CompactScratch& scratch,
			coproto::Socket& sock,
			CoeffCtx ctx);

		struct CompactScratch
		{
			std::array<AlignedUnVector<block>, 2> mSeeds;
			std::array<std::vector<u8>, 2> mTags;

			void resize(u64 depth)
			{
				if (depth <= 3)
					return;
				const auto localDepth = depth - 3;
				const auto paddedDomain = u64{ 1 } << depth;
				const auto subtreeDomain = u64{ 1 } << localDepth;
				const auto finalSlab = localDepth & 1;
				mSeeds[finalSlab].resize(paddedDomain);
				mSeeds[finalSlab ^ 1].resize(paddedDomain / 2);
				mTags[finalSlab].resize(subtreeDomain);
				mTags[finalSlab ^ 1].resize(std::max<u64>(subtreeDomain / 2, 1));
			}
		};

		static void compactChildSums(
			u64 partyIdx,
			u64 targetDepth,
			u64 tree,
			const std::array<block, 2>& roots,
			const RegularDpfKey& key,
			CompactScratch& scratch,
			block& leftSum,
			block& rightSum);


		static u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		// extracts the lsb of b and returns a block saturated with that bit.
		static block tagBit(const block& b)
		{
			auto bit = b & block(0, 1);
			auto mask = block(0, 0).sub_epi64(bit);
			return mask.unpacklo_epi64(mask);
		}


		void clear()
		{

			mPartyIdx = 0;
			mDomain = 0;
			mDepth = 0;
			mNumPoints = 0;
			mMultiplier.clear();
		}
	};



	template<typename T, typename CoeffCtx>
	inline void RegularDpf<T, CoeffCtx>::init(
		u64 partyIdx,
		u64 domain,
		u64 numPoints,
		CoeffCtx ctx)
	{
		if (partyIdx > 1)
			throw RTE_LOC;
		if (domain < 2)
			throw RTE_LOC;
		if (!numPoints)
			throw RTE_LOC;

		auto depth = log2ceil(domain);
		if (depth >= 64)
			throw RTE_LOC;
		const auto roundedDomain = u64{ 1 } << depth;
		if (numPoints > std::numeric_limits<u64>::max() / roundedDomain)
			throw RTE_LOC;

		mDepth = depth;
		mPartyIdx = partyIdx;
		mDomain = domain;
		mNumPoints = numPoints;

		auto multsPerPoint = mDepth + !ctx.template characteristicTwo<T>();
		if (numPoints > std::numeric_limits<u64>::max() / multsPerPoint)
			throw RTE_LOC;

		mMultiplier.init(partyIdx, numPoints * multsPerPoint);
	}


	template<typename T, typename CoeffCtx>
	template<typename VecT, typename Output >
	macoro::task<> RegularDpf<T, CoeffCtx>::expand(
		span<u64> points,
		VecT&& values,
		PRNG& prng,
		coproto::Socket& sock,
		Output&& output,
		CoeffCtx ctx)
	{
		CompactScratch scratch;
		RegularDpfKey key;
		co_await implKeyGen(
			points, values, prng, key, scratch, sock, ctx);
		expand(
			mPartyIdx, mDomain, key, scratch,
			std::forward<Output>(output), ctx);
	}



	// distributed keygen, points, values should be shared and seed is some 
	// random see. inputKey == nullptr, output = anything, and outputKey
	// should point to valid object. Base OTs must be set.
	template<typename T, typename CoeffCtx>
	inline macoro::task<> RegularDpf<T, CoeffCtx>::keyGen(
		span<u64> points,
		auto&& values,
		PRNG& prng,
		RegularDpfKey& outputKey,
		coproto::Socket& sock,
		CoeffCtx ctx)
	{
		CompactScratch scratch;
		co_await implKeyGen(
			points, values, prng, outputKey, scratch, sock, ctx);
	}

	template<typename T, typename CoeffCtx>
	inline macoro::task<> RegularDpf<T, CoeffCtx>::keyGen(
		span<u64> points,
		auto&& values,
		PRNG& prng,
		RegularDpfKey& outputKey,
		CompactScratch& scratch,
		coproto::Socket& sock,
		CoeffCtx ctx)
	{
		return implKeyGen(
			points, values, prng, outputKey, scratch, sock, ctx);
	}

	template<typename T, typename CoeffCtx>
	void RegularDpf<T, CoeffCtx>::compactChildSums(
		u64 partyIdx,
		u64 targetDepth,
		u64 tree,
		const std::array<block, 2>& roots,
		const RegularDpfKey& key,
		CompactScratch& scratch,
		block& leftSum,
		block& rightSum)
	{
		if (targetDepth == 0 || targetDepth > key.mCorrectionWords.rows())
			throw RTE_LOC;

		std::array<block, 8> currentSeeds{};
		std::array<block, 8> nextSeeds{};
		std::array<block, 8> currentTags{};
		std::array<block, 8> nextTags{};
		currentSeeds[0] = roots[0];
		currentSeeds[1] = roots[1];
		currentTags[0] = block::allSame<u8>(-static_cast<i8>(partyIdx));
		currentTags[1] = currentTags[0];

		const auto topDepth = std::min<u64>(3, targetDepth);
		for (u64 d = 1; d < topDepth; ++d)
		{
			const auto width = u64{ 1 } << d;
			for (u64 node = 0; node < width; ++node)
			{
				const auto branch = node & 1;
				auto sigma = key.mCorrectionWords(d - 1, tree);
				if (branch)
					*BitIterator(&sigma) = key.mCorrectionBits(d - 1, tree);
				auto corrected = currentSeeds[node] ^ (currentTags[node] & sigma);
				auto aes = mAesFixedKey.ecbEncBlock(corrected);
				nextSeeds[2 * node] = AES::roundEnc(aes, corrected);
				nextSeeds[2 * node + 1] = aes.add_epi64(corrected);
				nextTags[2 * node] = tagBit(corrected);
				nextTags[2 * node + 1] = nextTags[2 * node];
			}
			currentSeeds = nextSeeds;
			currentTags = nextTags;
		}

		block leftAccumulator = ZeroBlock;
		block rightAccumulator = ZeroBlock;
		if (targetDepth <= 3)
		{
			const auto width = u64{ 1 } << targetDepth;
			for (u64 node = 0; node < width; ++node)
			{
				const auto branch = node & 1;
				auto sigma = key.mCorrectionWords(targetDepth - 1, tree);
				if (branch)
					*BitIterator(&sigma) = key.mCorrectionBits(targetDepth - 1, tree);
				auto corrected = currentSeeds[node] ^ (currentTags[node] & sigma);
				auto aes = mAesFixedKey.ecbEncBlock(corrected);
				leftAccumulator = leftAccumulator ^ AES::roundEnc(aes, corrected);
				rightAccumulator = rightAccumulator ^ aes.add_epi64(corrected);
			}
			leftSum = leftAccumulator;
			rightSum = rightAccumulator;
			return;
		}

		for (u64 lane = 0; lane < 8; ++lane)
			scratch.mSeeds[0][lane] = currentSeeds[lane];
		u8 topTagBits = 0;
		for (u64 lane = 0; lane < 8; ++lane)
			topTagBits |= lsb(currentTags[lane]) << lane;
		scratch.mTags[0][0] = topTagBits;

		std::array<block, 8> corrected;
		std::array<block, 8> aes;
		for (u64 d = 3; d < targetDepth; ++d)
		{
			const auto level = d - 3;
			const auto currentSlab = level & 1;
			const auto nextSlab = currentSlab ^ 1;
			const auto width = u64{ 1 } << level;
			const auto sigma0 = key.mCorrectionWords(d - 1, tree);
			auto sigma1 = sigma0;
			*BitIterator(&sigma1) = key.mCorrectionBits(d - 1, tree);

			for (u64 node = 0; node < width; ++node)
			{
				const auto* parent = scratch.mSeeds[currentSlab].data() + 8 * node;
				auto* left = scratch.mSeeds[nextSlab].data() + 16 * node;
				auto* right = left + 8;
				const auto parentTagBits = scratch.mTags[currentSlab][node];
				u8 childTagBits = 0;
				if (d == 3)
				{
					REGULAR_DPF_SIMD8(lane, {
						const auto tagMask = block::allSame<u8>(
							-static_cast<i8>((parentTagBits >> lane) & 1));
						corrected[lane] = parent[lane] ^
							(tagMask & (lane & 1 ? sigma1 : sigma0));
						childTagBits |= lsb(corrected[lane]) << lane;
					});
				}
				else
				{
					const auto& sigma = node & 1 ? sigma1 : sigma0;
					REGULAR_DPF_SIMD8(lane, {
						const auto tagMask = block::allSame<u8>(
							-static_cast<i8>((parentTagBits >> lane) & 1));
						corrected[lane] = parent[lane] ^ (tagMask & sigma);
						childTagBits |= lsb(corrected[lane]) << lane;
					});
				}
				mAesFixedKey.ecbEncBlocks<8>(corrected.data(), aes.data());
				REGULAR_DPF_SIMD8(lane, {
					left[lane] = AES::roundEnc(aes[lane], corrected[lane]);
					right[lane] = aes[lane].add_epi64(corrected[lane]);
				});
				scratch.mTags[nextSlab][2 * node] = childTagBits;
				scratch.mTags[nextSlab][2 * node + 1] = childTagBits;
			}
		}

		const auto level = targetDepth - 3;
		const auto currentSlab = level & 1;
		const auto width = u64{ 1 } << level;
		const auto sigma0 = key.mCorrectionWords(targetDepth - 1, tree);
		auto sigma1 = sigma0;
		*BitIterator(&sigma1) = key.mCorrectionBits(targetDepth - 1, tree);
		for (u64 node = 0; node < width; ++node)
		{
			const auto* parent = scratch.mSeeds[currentSlab].data() + 8 * node;
			const auto parentTagBits = scratch.mTags[currentSlab][node];
			const auto& sigma = node & 1 ? sigma1 : sigma0;
			REGULAR_DPF_SIMD8(lane, {
				const auto tagMask = block::allSame<u8>(
					-static_cast<i8>((parentTagBits >> lane) & 1));
				corrected[lane] = parent[lane] ^ (tagMask & sigma);
			});
			mAesFixedKey.ecbEncBlocks<8>(corrected.data(), aes.data());

			// One accumulator pair is shared by all eight subtrees. Keeping this
			// reduction independent of the physical lanes gives substantially
			// better register allocation than eight long-lived sums.
			leftAccumulator = leftAccumulator ^ AES::roundEnc(aes[0], corrected[0]) ^
				AES::roundEnc(aes[1], corrected[1]) ^
				AES::roundEnc(aes[2], corrected[2]) ^
				AES::roundEnc(aes[3], corrected[3]) ^
				AES::roundEnc(aes[4], corrected[4]) ^
				AES::roundEnc(aes[5], corrected[5]) ^
				AES::roundEnc(aes[6], corrected[6]) ^
				AES::roundEnc(aes[7], corrected[7]);
			rightAccumulator = rightAccumulator ^ aes[0].add_epi64(corrected[0]) ^
				aes[1].add_epi64(corrected[1]) ^
				aes[2].add_epi64(corrected[2]) ^
				aes[3].add_epi64(corrected[3]) ^
				aes[4].add_epi64(corrected[4]) ^
				aes[5].add_epi64(corrected[5]) ^
				aes[6].add_epi64(corrected[6]) ^
				aes[7].add_epi64(corrected[7]);
		}
		leftSum = leftAccumulator;
		rightSum = rightAccumulator;
	}

	template<typename T, typename CoeffCtx>
	template<typename VecT>
	macoro::task<> RegularDpf<T, CoeffCtx>::implKeyGen(
		span<u64> points,
		VecT&& values,
		PRNG& prng,
		RegularDpfKey& outputKey,
		CompactScratch& scratch,
		coproto::Socket& sock,
		CoeffCtx ctx)
	{
		if (points.size() != mNumPoints ||
			(values.size() && values.size() != mNumPoints))
			throw RTE_LOC;
		if (!mMultiplier.hasBaseOts())
			throw RTE_LOC;

		const auto numPoints = mNumPoints;
		outputKey.resize<T>(mDomain, numPoints, ctx, false);
		outputKey.mSeed = prng.get<block>();

		std::vector<std::array<block, 2>> roots(numPoints);
		std::array<AlignedUnVector<block>, 2> z;
		z[0].resize(numPoints);
		z[1].resize(numPoints);
		PRNG basePrng(outputKey.mSeed, 2 * numPoints);
		for (u64 point = 0; point < numPoints; ++point)
		{
			roots[point][0] = basePrng.get<block>();
			roots[point][1] = basePrng.get<block>();
			z[0][point] = roots[point][0];
			z[1][point] = roots[point][1];
		}

		std::array<AlignedUnVector<block>, 2> sigma;
		sigma[0].resize(numPoints);
		sigma[1].resize(numPoints);
		AlignedUnVector<block> sigmaMult(numPoints);
		AlignedUnVector<block> diff(numPoints);
		BitVector negAlphaj(numPoints);
		scratch.resize(mDepth);

		for (u64 iter = 1; iter <= mDepth; ++iter)
		{
			for (u64 point = 0; point < numPoints; ++point)
			{
				const auto alphaj = *BitIterator(&points[point], mDepth - iter);
				diff[point] = z[0][point] ^ z[1][point];
				*BitIterator(&diff[point]) = 0;
				negAlphaj[point] = alphaj ^ mPartyIdx;
			}

			co_await mMultiplier.multiply(negAlphaj, diff, diff, sock);

			std::vector<block> buffer(numPoints + divCeil(numPoints, 128));
			auto z1LsbIter = BitIterator(&buffer[numPoints]);
			for (u64 point = 0; point < numPoints; ++point)
			{
				const auto alphaj = *BitIterator(&points[point], mDepth - iter);
				sigmaMult[point] = diff[point] ^ z[0][point] ^
					block(0, mPartyIdx ^ alphaj);
				buffer[point] = sigmaMult[point];
				*z1LsbIter++ = lsb(z[1][point]) ^ alphaj;
			}

			co_await sock.send(coproto::copy(buffer));
			co_await sock.recv(buffer);
			z1LsbIter = BitIterator(&buffer[numPoints]);
			for (u64 point = 0; point < numPoints; ++point)
			{
				const auto alphaj = *BitIterator(&points[point], mDepth - iter);
				const auto sigma1Bit = *z1LsbIter++ ^ lsb(z[1][point]) ^ alphaj;
				sigma[0][point] = buffer[point] ^ sigmaMult[point];
				sigma[1][point] = sigma[0][point];
				*BitIterator(&sigma[1][point]) = sigma1Bit;
				outputKey.mCorrectionWords(iter - 1, point) = sigma[0][point];
				outputKey.mCorrectionBits(iter - 1, point) = sigma1Bit;
			}

			if (iter != mDepth)
			{
				for (u64 point = 0; point < numPoints; ++point)
				{
					compactChildSums(
						mPartyIdx, iter, point, roots[point], outputKey, scratch,
						z[0][point], z[1][point]);
				}
			}
		}

		if (!values.size())
			co_return;

		auto leafSums = ctx.template makeVec<T>(numPoints);
		ctx.zero(leafSums.begin(), leafSums.end());
		std::vector<u8> d(numPoints);
		const auto sumDomain = roundUpTo(mDomain, 2);
		expand(
			mPartyIdx,
			sumDomain,
			outputKey,
			scratch,
			[&](u64 tree, u64, const auto& leaf, block tag) {
				ctx.plus(leafSums[tree], leafSums[tree], leaf);
				d[tree] += lsb(tag);
			},
			ctx);

		for (u64 point = 0; point < numPoints; ++point)
			ctx.minus(leafSums[point], values[point], leafSums[point]);

		if (!ctx.template characteristicTwo<T>())
		{
			auto signDiff = ctx.template makeVec<T>(numPoints);
			BitVector dBits(numPoints);
			for (u64 point = 0; point < numPoints; ++point)
			{
				d[point] = ((d[point] / 2) % 2) ^ (mPartyIdx & d[point]);
				dBits[point] = d[point];
				ctx.plus(signDiff[point], leafSums[point], leafSums[point]);
			}

			co_await mMultiplier.multiply<T>(
				dBits.getSpan<u8>(), signDiff, signDiff, sock, ctx);
			for (u64 point = 0; point < numPoints; ++point)
				ctx.minus(leafSums[point], leafSums[point], signDiff[point]);
		}

		std::vector<u8> gammaBuffer(numPoints * ctx.template byteSize<T>());
		ctx.serialize(leafSums.begin(), leafSums.end(), gammaBuffer.begin());
		co_await sock.send(std::move(gammaBuffer));
		gammaBuffer.resize(numPoints * ctx.template byteSize<T>());
		co_await sock.recv(gammaBuffer);
		auto gamma = ctx.template makeVec<T>(numPoints);
		ctx.deserialize(gammaBuffer.begin(), gammaBuffer.end(), gamma.begin());
		for (u64 point = 0; point < numPoints; ++point)
			ctx.plus(gamma[point], gamma[point], leafSums[point]);

		outputKey.mLeafVals.resize(numPoints * ctx.template byteSize<T>());
		ctx.serialize(gamma.begin(), gamma.end(), outputKey.mLeafVals.begin());
	}

	template<typename T, typename CoeffCtx>
	inline u64 RegularDpf<T, CoeffCtx>::baseOtCount() const {
		return mMultiplier.baseOtCount();
	}

	template<typename T, typename CoeffCtx>
	inline void RegularDpf<T, CoeffCtx>::setBaseOts(
		span<const std::array<block, 2>> baseSendOts,
		span<const block> recvBaseOts,
		const oc::BitVector& baseChoices)
	{
		mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
	}


	template<typename T, typename CoeffCtx>
	inline void RegularDpf<T, CoeffCtx>::keyGen(
		u64 domain,
		span<u64> points,
		auto&& values,
		PRNG& prng,
		span<RegularDpfKey> keys,
		CoeffCtx ctx)
	{
		if (keys.size() != 2)
			throw RTE_LOC;
		if (domain < 2 || log2ceil(domain) >= 64 || points.empty())
			throw RTE_LOC;
		if (values.size() != points.size() && values.size() != 0)
			throw RTE_LOC;
		if (std::any_of(points.begin(), points.end(),
			[domain](u64 point) { return point >= domain; }))
			throw RTE_LOC;

		auto depth = log2ceil(domain);
		keys[0].resize<T>(domain, points.size(), ctx, false);
		keys[1].resize<T>(domain, points.size(), ctx, false);

		auto seed0 = prng.get<block>();
		auto seed1 = prng.get<block>();
		std::array<PRNG, 2> prngs{ seed0, seed1 };
		keys[0].mSeed = prngs[0].getSeed();
		keys[1].mSeed = prngs[1].getSeed();
		for (u64 i = 0; i < points.size(); ++i)
		{
			std::array<block, 2> parentTags;
			std::array<std::array<block, 2>, 2> seeds;

			for (u64 p = 0; p < 2; ++p)
			{
				prngs[p].get(seeds[p].data(), seeds[p].size());
				parentTags[p] = block::allSame(-p);
			}

			for (u64 iter = 1; iter <= depth; ++iter)
			{
				auto a = *BitIterator(&points[i], depth - iter);
				auto na = a ^ 1;

				auto diff = seeds[0][na] ^ seeds[1][na];
				u8 tau[2];
				tau[0] = lsb(seeds[0][0] ^ seeds[1][0]) ^ na;
				tau[1] = lsb(seeds[0][1] ^ seeds[1][1]) ^ a;

				// we want   diff || lsbs[0] ^ na || lsbs[1] ^ a
				*BitIterator(&diff) = tau[0];

				block sigma[2];
				sigma[0] = diff;
				sigma[1] = diff;
				*BitIterator(&sigma[1]) = tau[1];

				for (u64 p = 0; p < 2; ++p)
				{
					keys[p].mCorrectionWords(iter - 1, i) = diff;
					keys[p].mCorrectionBits(iter - 1, i) = tau[1];

					seeds[p][0] ^= sigma[0] & parentTags[p];
					seeds[p][1] ^= sigma[1] & parentTags[p];
					parentTags[p] = tagBit(seeds[p][a]);
				}

				if (seeds[0][na] != seeds[1][na])
					throw RTE_LOC;
				if (lsb(seeds[0][a] ^ seeds[1][a]) != 1)
					throw RTE_LOC;
				if ((parentTags[0] ^ parentTags[1]) != AllOneBlock)
					throw RTE_LOC;

				for (u64 p = 0; p < 2; ++p)
				{
					if (iter != depth)
					{
						auto seed = seeds[p][a];
						auto temp = mAesFixedKey.ecbEncBlock(seed);
						seeds[p][0] = AES::roundEnc(temp, seed);
						seeds[p][1] = temp.add_epi64(seed);
					}
				}
			}

			if (values.size())
			{
				auto a = *BitIterator(&points[i], 0);
				auto na = a ^ 1;

				if (seeds[0][na] != seeds[1][na])
					throw RTE_LOC;

				std::array<u8, 2> tags;
				for (u64 p = 0; p < 2; ++p)
				{
					tags[p] = lsb(seeds[p][a]);
					seeds[p][a] = AES::roundEnc(seeds[p][a], seeds[p][a]);
				}

				if (tags[0] == tags[1])
					throw RTE_LOC;

				auto leaf0 = ctx.template make<T>();
				auto leaf1 = ctx.template make<T>();
				auto leafVal = ctx.template make<T>();
				auto gamma = ctx.template make<T>();

				ctx.fromBlock(leaf0, seeds[0][a]);
				ctx.fromBlock(leaf1, seeds[1][a]);
				ctx.minus(leafVal, leaf0, leaf1);
				ctx.minus(gamma, values[i], leafVal);

				// if party 1 is going to apply gamma, then we
				// need to negate the user provided value because
				// party 1 subtracts gamma while party 0 adds it.
				if (tags[1])
				{
					auto zero = ctx.template make<T>();
					ctx.zero(zero);
					ctx.minus(gamma, zero, gamma);
				}

				// Serialize the result using CoeffCtx
				std::vector<u8> serialized(ctx.template byteSize<T>());
				ctx.serialize(&gamma, &gamma + 1, serialized.begin());

				keys[0].mLeafVals.insert(keys[0].mLeafVals.end(),
					serialized.begin(),
					serialized.end());
				keys[1].mLeafVals.insert(keys[1].mLeafVals.end(),
					serialized.begin(),
					serialized.end());
			}
		}
	}

	template<typename T, typename CoeffCtx>
	template<typename Output>
	void RegularDpf<T, CoeffCtx>::expand(
		u64 partyIdx,
		u64 domain,
		const RegularDpfKey& key,
		Output&& output,
		CoeffCtx ctx)
	{
		CompactScratch scratch;
		expand(
			partyIdx, domain, key, scratch,
			std::forward<Output>(output), ctx);
	}

	template<typename T, typename CoeffCtx>
	template<typename Output>
	void RegularDpf<T, CoeffCtx>::expand(
		u64 partyIdx,
		u64 domain,
		const RegularDpfKey& key,
		CompactScratch& scratch,
		Output&& output,
		CoeffCtx ctx)
	{
		if (partyIdx > 1 || domain < 2)
			throw RTE_LOC;

		const auto depth = log2ceil(domain);
		const auto numTrees = key.mCorrectionBits.cols();
		if (!numTrees || depth == 0 || depth >= 64)
			throw RTE_LOC;

		const auto leafByteSize = ctx.template byteSize<T>();
		if (numTrees && leafByteSize > std::numeric_limits<u64>::max() / numTrees)
			throw RTE_LOC;
		if (key.mCorrectionWords.rows() != depth ||
			key.mCorrectionWords.cols() != numTrees ||
			key.mCorrectionBits.rows() != depth ||
			key.mCorrectionBits.cols() != numTrees ||
			(key.mLeafVals.size() != 0 &&
				key.mLeafVals.size() != numTrees * leafByteSize))
			throw RTE_LOC;

		constexpr u64 TopDepth = 3;
		const auto topDepth = std::min<u64>(TopDepth, depth);
		const auto laneCount = u64{ 1 } << topDepth;
		const auto localDepth = depth - topDepth;
		const auto subtreeDomain = u64{ 1 } << localDepth;

		// Two alternating slabs hold the largest two physical levels. A physical
		// node is eight adjacent subtrees of one DPF tree. Unlike the old matrix
		// layout, the workspace does not grow with numTrees.
		scratch.resize(depth);
		auto& seedSlabs = scratch.mSeeds;
		auto& tagSlabs = scratch.mTags;

		auto gamma = ctx.template makeVec<T>(numTrees);
		const auto hasGamma = !key.mLeafVals.empty();
		if (hasGamma)
			ctx.deserialize(key.mLeafVals.begin(), key.mLeafVals.end(), gamma.begin());

		auto zero = ctx.template make<T>();
		ctx.zero(zero);
		auto leaf = ctx.template make<T>();
		auto maskedGamma = ctx.template make<T>();

		PRNG basePrng(key.mSeed, 2 * numTrees);
		for (u64 tree = 0; tree < numTrees; ++tree)
		{
			std::array<block, 8> currentSeeds{};
			std::array<block, 8> nextSeeds{};
			std::array<block, 8> currentTags{};
			std::array<block, 8> nextTags{};
			currentSeeds[0] = basePrng.get<block>();
			currentSeeds[1] = basePrng.get<block>();
			currentTags[0] = block::allSame<u8>(-static_cast<i8>(partyIdx));
			currentTags[1] = currentTags[0];

			// Expand the small public top tree. Its leaves become the SIMD lanes
			// of the lower physical traversal.
			for (u64 d = 1; d < topDepth; ++d)
			{
				const auto width = u64{ 1 } << d;
				for (u64 node = 0; node < width; ++node)
				{
					const auto branch = node & 1;
					auto sigma = key.mCorrectionWords(d - 1, tree);
					if (branch)
						*BitIterator(&sigma) = key.mCorrectionBits(d - 1, tree);
					auto corrected = currentSeeds[node] ^ (currentTags[node] & sigma);
					auto aes = mAesFixedKey.ecbEncBlock(corrected);
					nextSeeds[2 * node] = AES::roundEnc(aes, corrected);
					nextSeeds[2 * node + 1] = aes.add_epi64(corrected);
					nextTags[2 * node] = tagBit(corrected);
					nextTags[2 * node + 1] = nextTags[2 * node];
				}
				currentSeeds = nextSeeds;
				currentTags = nextTags;
			}

			if (depth <= TopDepth)
			{
				for (u64 lane = 0; lane < laneCount; ++lane)
				{
					if (lane >= domain)
						continue;
					auto sigma = key.mCorrectionWords(depth - 1, tree);
					if (lane & 1)
						*BitIterator(&sigma) = key.mCorrectionBits(depth - 1, tree);
					auto corrected = currentSeeds[lane] ^ (currentTags[lane] & sigma);
					auto tag = tagBit(corrected);
					ctx.fromBlock(leaf, AES::roundEnc(corrected, corrected));
					if (partyIdx)
						ctx.minus(leaf, zero, leaf);
					if (hasGamma)
					{
						ctx.mask(maskedGamma, gamma[tree], tag);
						if (partyIdx)
							ctx.minus(leaf, leaf, maskedGamma);
						else
							ctx.plus(leaf, leaf, maskedGamma);
					}
					output(tree, lane, leaf, tag);
				}
				continue;
			}

			for (u64 lane = 0; lane < 8; ++lane)
				seedSlabs[0][lane] = currentSeeds[lane];
			u8 topTagBits = 0;
			for (u64 lane = 0; lane < 8; ++lane)
				topTagBits |= lsb(currentTags[lane]) << lane;
			tagSlabs[0][0] = topTagBits;

			std::array<block, 8> corrected;
			std::array<block, 8> aes;
			for (u64 d = TopDepth; d < depth; ++d)
			{
				const auto level = d - TopDepth;
				const auto currentSlab = level & 1;
				const auto nextSlab = currentSlab ^ 1;
				const auto width = u64{ 1 } << level;
				const auto sigma0 = key.mCorrectionWords(d - 1, tree);
				auto sigma1 = sigma0;
				*BitIterator(&sigma1) = key.mCorrectionBits(d - 1, tree);

				for (u64 node = 0; node < width; ++node)
				{
					const auto* parent = seedSlabs[currentSlab].data() + 8 * node;
					auto* left = seedSlabs[nextSlab].data() + 16 * node;
					auto* right = left + 8;
					const auto parentTagBits = tagSlabs[currentSlab][node];
					u8 childTagBits = 0;
					if (d == TopDepth)
					{
						REGULAR_DPF_SIMD8(lane, {
							const auto tagMask = block::allSame<u8>(
								-static_cast<i8>((parentTagBits >> lane) & 1));
							corrected[lane] = parent[lane] ^
								(tagMask & (lane & 1 ? sigma1 : sigma0));
							childTagBits |= lsb(corrected[lane]) << lane;
						});
					}
					else
					{
						const auto& sigma = node & 1 ? sigma1 : sigma0;
						REGULAR_DPF_SIMD8(lane, {
							const auto tagMask = block::allSame<u8>(
								-static_cast<i8>((parentTagBits >> lane) & 1));
							corrected[lane] = parent[lane] ^ (tagMask & sigma);
							childTagBits |= lsb(corrected[lane]) << lane;
						});
					}

					mAesFixedKey.ecbEncBlocks<8>(corrected.data(), aes.data());
					REGULAR_DPF_SIMD8(lane, {
						left[lane] = AES::roundEnc(aes[lane], corrected[lane]);
						right[lane] = aes[lane].add_epi64(corrected[lane]);
					});
					tagSlabs[nextSlab][2 * node] = childTagBits;
					tagSlabs[nextSlab][2 * node + 1] = childTagBits;
				}
			}

			const auto leafSlab = localDepth & 1;
			const auto sigma0 = key.mCorrectionWords(depth - 1, tree);
			auto sigma1 = sigma0;
			*BitIterator(&sigma1) = key.mCorrectionBits(depth - 1, tree);
			for (u64 local = 0; local < subtreeDomain; ++local)
			{
				const auto* seeds = seedSlabs[leafSlab].data() + 8 * local;
				const auto parentTagBits = tagSlabs[leafSlab][local];
				const auto& sigma = local & 1 ? sigma1 : sigma0;
				REGULAR_DPF_SIMD8(lane, {
					const auto logicalLeaf = lane * subtreeDomain + local;
					if (logicalLeaf < domain)
					{
						const auto tagMask = block::allSame<u8>(
							-static_cast<i8>((parentTagBits >> lane) & 1));
						auto correctedLeaf = seeds[lane] ^ (tagMask & sigma);
						auto tag = tagBit(correctedLeaf);
						ctx.fromBlock(leaf, AES::roundEnc(correctedLeaf, correctedLeaf));
						if (partyIdx)
							ctx.minus(leaf, zero, leaf);
						if (hasGamma)
						{
							ctx.mask(maskedGamma, gamma[tree], tag);
							if (partyIdx)
								ctx.minus(leaf, leaf, maskedGamma);
							else
								ctx.plus(leaf, leaf, maskedGamma);
						}
						output(tree, logicalLeaf, leaf, tag);
					}
				});
			}
		}
	}

}

#undef REGULAR_DPF_SIMD8

#endif
