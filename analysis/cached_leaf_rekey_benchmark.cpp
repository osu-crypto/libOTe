// Sequential microbenchmark of cached-leaf conversion, not full expansion.
// Baseline: CachedDpfExpansion.h at b2e9b7b5c5ab60adf800ba56b087c0d1b4330812,
// renamed and noinline to match
// the production kernel's call boundary.
#include "libOTe/Dpf/CachedDpfExpansion.h"
#include "libOTe/Tools/CoeffCtx.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>
using namespace osuCrypto;
namespace osuCrypto::details {
	template<typename T>
	__attribute__((noinline)) inline void baselineLeaves(
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


}
int main()
{
    using Clock = std::chrono::steady_clock;
    std::cout << "profile,party,leaves,old_ns_per_leaf,rekey_ns_per_leaf,change_pct\n";
    for (u64 profile = 0; profile < 4; ++profile)
    {
        const u64 trees = profile == 0 ? 64 : profile == 1 ? 320 : 16;
        const u64 leaves = profile == 0 ? 4 * (1ull << 20) :
            profile == 1 ? 3 * (1ull << 20) : profile == 2 ? 1024 : 5120;
        const u64 repetitions = profile < 2 ? 1 : 1024;
        std::vector<std::vector<u32>> sets(trees);
        std::vector<std::vector<block>> seeds(trees);
        std::vector<std::vector<u64>> values;
        std::vector<u64> sums;
        PRNG prng(block(317, 901));
        for (u64 tree = 0; tree < trees; ++tree)
        {
            const auto count = leaves / trees + (tree < leaves % trees);
            sets[tree].resize(count);
            seeds[tree].resize(count);
            for (auto& seed : seeds[tree]) seed = prng.get<block>() & ~OneBlock;
        }
        for (u64 party = 0; party < 2; ++party)
        {
            block root = details::cachedDpfLeafRoot(block(12, 34), profile);
            std::array<std::vector<double>, 2> times;
            u64 checksum = 0;
            for (u64 trial = 0; trial < 24; ++trial)
                for (u64 order = 0; order < 2; ++order)
                {
                    const auto implementation = (order + trial) % 2;
                    const auto begin = Clock::now();
                    for (u64 repeat = 0; repeat < repetitions; ++repeat)
                    {
                        if (implementation)
                            details::expandCachedDpfLeaves<u64>(
                                party, sets, seeds, values, sums, root, CoeffCtxInteger{});
                        else
                            details::baselineLeaves<u64>(
                                party, sets, seeds, values, sums, root, CoeffCtxInteger{});
                        checksum ^= sums[repeat % trees];
                    }
                    const auto elapsed = std::chrono::duration<double, std::nano>(Clock::now() - begin).count();
                    if (trial >= 4) times[implementation].push_back(elapsed / (leaves * repetitions));
                }
            for (auto& t : times) std::sort(t.begin(), t.end());
            const double oldTime = (times[0][9] + times[0][10]) / 2;
            const double newTime = (times[1][9] + times[1][10]) / 2;
            const char* names[] = { "4N", "3N", "scatter64", "scatter320" };
            std::cout << names[profile] << ',' << party << ',' << leaves << ','
                << std::fixed << std::setprecision(4) << oldTime << ',' << newTime << ','
                << (newTime / oldTime - 1) * 100 << std::endl;
            std::cerr << "checksum=" << checksum << '\n';
        }
    }
}
