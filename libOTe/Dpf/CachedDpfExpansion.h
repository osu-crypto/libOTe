#pragma once

#include "cryptoTools/Crypto/AES.h"

#include <stdexcept>

namespace osuCrypto::details
{
	/// Expand cached punctured-DPF leaves for one online payload.
	///
	/// sparseSets, leafShares, and expanded contain one row per DPF tree; the
	/// leaves within corresponding rows have identical order and cardinality.
	/// hashSeed is advanced once per call so repeated expansions use independent
	/// leaf masks. The explicit eight-lane body is intentional: this is a hot
	/// kernel and produces better code than the previously generic inner loop.
	template<typename T>
	inline void expandCachedDpfLeaves(
		u64 partyIdx,
		auto& sparseSets,
		auto& leafShares,
		auto& expanded,
		auto& leafSums,
		block& hashSeed,
		auto context)
	{
		if (leafShares.size() != sparseSets.size())
			throw std::invalid_argument("Cached DPF leaf-share dimensions do not match sparse sets. " LOCATION);
		for (u64 tree = 0; tree < sparseSets.size(); ++tree)
			if (leafShares[tree].size() != sparseSets[tree].size())
				throw std::invalid_argument("Cached DPF leaf-share row has the wrong size. " LOCATION);

		context.resize(expanded, sparseSets.size());
		for (u64 tree = 0; tree < expanded.size(); ++tree)
			if (expanded[tree].size() != sparseSets[tree].size())
				context.resize(expanded[tree], sparseSets[tree].size());
		if (leafSums.size() != sparseSets.size())
			context.resize(leafSums, sparseSets.size());
		context.zero(leafSums.begin(), leafSums.end());

		auto zero = context.template make<T>();
		context.zero(zero);
		::osuCrypto::AES aes(hashSeed);
		hashSeed = aes.hashBlock(block(35434523452345, 2345324523452345234));

#define CACHED_DPF_SIMD8(VAR, STATEMENT) do { \
	{ constexpr u64 VAR = 0; STATEMENT; } \
	{ constexpr u64 VAR = 1; STATEMENT; } \
	{ constexpr u64 VAR = 2; STATEMENT; } \
	{ constexpr u64 VAR = 3; STATEMENT; } \
	{ constexpr u64 VAR = 4; STATEMENT; } \
	{ constexpr u64 VAR = 5; STATEMENT; } \
	{ constexpr u64 VAR = 6; STATEMENT; } \
	{ constexpr u64 VAR = 7; STATEMENT; } \
} while (0)

		if (partyIdx)
		{
			for (u64 tree = 0; tree < expanded.size(); ++tree)
			{
				const auto leaves = sparseSets[tree].size();
				const auto leaves8 = leaves / 8 * 8;
				auto* values = expanded[tree].data();
				const auto* seeds = leafShares[tree].data();
				for (u64 leaf = 0; leaf < leaves8; leaf += 8)
				{
					CACHED_DPF_SIMD8(q, context.fromBlock(
						values[leaf + q], aes.hashBlock(seeds[leaf + q])));
					CACHED_DPF_SIMD8(q, context.minus(values[leaf + q], zero, values[leaf + q]));
					CACHED_DPF_SIMD8(q, context.plus(
						leafSums[tree], leafSums[tree], values[leaf + q]));
				}
				for (u64 leaf = leaves8; leaf < leaves; ++leaf)
				{
					context.fromBlock(values[leaf], aes.hashBlock(seeds[leaf]));
					context.minus(values[leaf], zero, values[leaf]);
					context.plus(leafSums[tree], leafSums[tree], values[leaf]);
				}
			}
		}
		else
		{
			for (u64 tree = 0; tree < expanded.size(); ++tree)
			{
				const auto leaves = sparseSets[tree].size();
				const auto leaves8 = leaves / 8 * 8;
				auto* values = expanded[tree].data();
				const auto* seeds = leafShares[tree].data();
				for (u64 leaf = 0; leaf < leaves8; leaf += 8)
				{
					CACHED_DPF_SIMD8(q, context.fromBlock(
						values[leaf + q], aes.hashBlock(seeds[leaf + q])));
					CACHED_DPF_SIMD8(q, context.plus(
						leafSums[tree], leafSums[tree], values[leaf + q]));
				}
				for (u64 leaf = leaves8; leaf < leaves; ++leaf)
				{
					context.fromBlock(values[leaf], aes.hashBlock(seeds[leaf]));
					context.plus(leafSums[tree], leafSums[tree], values[leaf]);
				}
			}
		}

#undef CACHED_DPF_SIMD8
	}

	template<typename T>
	inline void applyCachedDpfUpdates(
		u64 partyIdx,
		u64 numSets,
		u64 treesPerSet,
		u64 domain,
		auto& sparseSets,
		auto& leafTags,
		auto& expanded,
		auto& gamma,
		auto& tempOutput,
		auto&& output,
		auto context)
	{
		const auto trees = numSets * treesPerSet;
		if (sparseSets.size() != trees || leafTags.size() != trees ||
			expanded.size() != trees || gamma.size() != trees)
			throw std::invalid_argument("Cached DPF update dimensions do not match. " LOCATION);
		for (u64 tree = 0; tree < trees; ++tree)
			if (leafTags[tree].size() != sparseSets[tree].size() ||
				expanded[tree].size() != sparseSets[tree].size())
				throw std::invalid_argument("Cached DPF update row has the wrong size. " LOCATION);

		if (tempOutput.size() != domain)
			context.resize(tempOutput, domain);
		auto temporary = context.template makeVec<T>(8);

#define CACHED_DPF_SIMD8(VAR, STATEMENT) do { \
	{ constexpr u64 VAR = 0; STATEMENT; } \
	{ constexpr u64 VAR = 1; STATEMENT; } \
	{ constexpr u64 VAR = 2; STATEMENT; } \
	{ constexpr u64 VAR = 3; STATEMENT; } \
	{ constexpr u64 VAR = 4; STATEMENT; } \
	{ constexpr u64 VAR = 5; STATEMENT; } \
	{ constexpr u64 VAR = 6; STATEMENT; } \
	{ constexpr u64 VAR = 7; STATEMENT; } \
} while (0)

		for (u64 set = 0, tree = 0; set < numSets; ++set)
		{
			context.zero(tempOutput.begin(), tempOutput.end());
			for (u64 localTree = 0; localTree < treesPerSet; ++localTree, ++tree)
			{
				const auto leaves = sparseSets[tree].size();
				const auto leaves8 = leaves / 8 * 8;
				const auto* values = expanded[tree].data();
				const auto* tags = leafTags[tree].data();
				const auto* points = sparseSets[tree].data();
				if (partyIdx)
				{
					for (u64 leaf = 0; leaf < leaves8; leaf += 8)
					{
						CACHED_DPF_SIMD8(q, context.mask(
							temporary[q], gamma[tree], block::allSame<u8>(-tags[leaf + q])));
						CACHED_DPF_SIMD8(q, context.minus(
							temporary[q], values[leaf + q], temporary[q]));
						u32 indices[8];
						CACHED_DPF_SIMD8(q, indices[q] = points[leaf + q]);
						CACHED_DPF_SIMD8(q, context.plus(
							tempOutput[indices[q]], tempOutput[indices[q]], temporary[q]));
					}
					for (u64 leaf = leaves8; leaf < leaves; ++leaf)
					{
						context.mask(
							temporary[0], gamma[tree], block::allSame<u8>(-tags[leaf]));
						context.minus(temporary[0], values[leaf], temporary[0]);
						context.plus(
							tempOutput[points[leaf]], tempOutput[points[leaf]], temporary[0]);
					}
				}
				else
				{
					for (u64 leaf = 0; leaf < leaves8; leaf += 8)
					{
						CACHED_DPF_SIMD8(q, context.mask(
							temporary[q], gamma[tree], block::allSame<u8>(-tags[leaf + q])));
						CACHED_DPF_SIMD8(q, context.plus(
							temporary[q], values[leaf + q], temporary[q]));
						u32 indices[8];
						CACHED_DPF_SIMD8(q, indices[q] = points[leaf + q]);
						CACHED_DPF_SIMD8(q, context.plus(
							tempOutput[indices[q]], tempOutput[indices[q]], temporary[q]));
					}
					for (u64 leaf = leaves8; leaf < leaves; ++leaf)
					{
						context.mask(
							temporary[0], gamma[tree], block::allSame<u8>(-tags[leaf]));
						context.plus(temporary[0], values[leaf], temporary[0]);
						context.plus(
							tempOutput[points[leaf]], tempOutput[points[leaf]], temporary[0]);
					}
				}
			}
			for (u64 point = 0; point < domain; ++point)
				output(set, point, tempOutput[point]);
		}

#undef CACHED_DPF_SIMD8
	}
}
