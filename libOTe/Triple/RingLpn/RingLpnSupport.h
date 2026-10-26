#pragma once
#include "cryptoTools/Common/Defines.h"
#include <array>
#include <bit>
#include <stdexcept>

namespace osuCrypto
{
	// Count occupied residues separately for each sparse polynomial. This
	// helper does not certify a parameter set; only the analyzed profile below
	// is enabled by RingLpnTriple.
	template<u64 RingSize_, u64 NumPolys_, u64 PolyWeight_, u64 FactorDegree_, u64 MinWeight_>
	struct RingLpnFoldedSupportFilter
	{
		static constexpr u64 RingSize = RingSize_;
		static constexpr u64 NumPolys = NumPolys_;
		static constexpr u64 PolyWeight = PolyWeight_;
		static constexpr u64 BlockSize = RingSize / PolyWeight;
		static constexpr u64 FactorDegree = FactorDegree_;
		static constexpr u64 MinWeight = MinWeight_;
		static constexpr u64 NumPositions = NumPolys * PolyWeight;
		static_assert(NumPolys > 0 && PolyWeight > 0 && RingSize % PolyWeight == 0);
		static_assert(FactorDegree > 0);
		static_assert(RingSize % FactorDegree == 0);
		static_assert((BlockSize & (BlockSize - 1)) == 0);
		static_assert(MinWeight <= NumPositions);

		static constexpr bool matches(u64 ringSize, u64 numPolys, u64 polyWeight)
		{
			return ringSize == RingSize && numPolys == NumPolys && polyWeight == PolyWeight;
		}

		// Offsets are row-major, with one row per polynomial. Count occupied
		// residues before coefficient cancellation; never merge different rows.
		static u64 foldedWeight(span<const u64> offsets)
		{
			if (offsets.size() != NumPositions)
				throw std::invalid_argument("RingLPN support count does not match filter profile.");
			u64 weight = 0;
			for (u64 p = 0; p < NumPolys; ++p)
			{
				std::array<u64, (FactorDegree + 63) / 64> occupied{};
				for (u64 i = 0; i < PolyWeight; ++i)
				{
					const auto offset = offsets[p * PolyWeight + i];
					if (offset >= BlockSize)
						throw std::invalid_argument("RingLPN support offset is outside its block.");
					// FactorDegree is a compile-time constant; the analyzed 128-fold
					// profile reduces this remainder to a bit mask.
					const auto residue = ((i * BlockSize) + offset) % FactorDegree;
					occupied[residue >> 6] |= 1ull << (residue & 63);
				}
				for (const auto word : occupied)
					weight += std::popcount(word);
			}
			return weight;
		}

		static bool accepts(span<const u64> offsets)
		{
			return foldedWeight(offsets) >= MinWeight;
		}

		// Called only during setup, before any support-dependent messages.
		// Resample the entire tuple, not individual rejected polynomials. The
		// templated PRNG permits deterministic rejection tests without dispatch.
		template<typename Rng>
		static void sample(span<u64> offsets, Rng& prng)
		{
			if (offsets.size() != NumPositions)
				throw std::invalid_argument("RingLPN support count does not match filter profile.");
			do
			{
				for (auto& offset : offsets)
					offset = prng.template get<u64>() & (BlockSize - 1);
			} while (!accepts(offsets));
		}
	};

	// The 61-of-128 threshold rejects low folded weight for the analyzed
	// degree-128 factors. Other parameters need their own threshold analysis.
	struct GoldilocksRingLpnSupportFilter :
		RingLpnFoldedSupportFilter<1ull << 20, 4, 16, 128, 61>
	{
		static constexpr u64 FieldOrder = 0xffffffff00000001ull;
	};
}
