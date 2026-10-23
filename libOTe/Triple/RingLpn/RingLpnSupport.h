#pragma once
#include "cryptoTools/Common/Defines.h"
#include <array>
#include <bit>
#include <stdexcept>

namespace osuCrypto
{
	// The analyzed Goldilocks profile, not a parameter generator for other rings.
	struct RingLpnSupportFilter
	{
		static constexpr u64 RingSize = 1ull << 20;
		static constexpr u64 FieldOrder = 0xffffffff00000001ull;
		static constexpr u64 NumPolys = 4;
		static constexpr u64 PolyWeight = 16;
		static constexpr u64 BlockSize = RingSize / PolyWeight;
		static constexpr u64 FactorDegree = 128;
		static constexpr u64 MinWeight = 61;
		static constexpr u64 NumPositions = NumPolys * PolyWeight;
		static_assert(BlockSize % FactorDegree == 0);
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
				throw std::invalid_argument("RingLPN support filter requires four weight-16 supports.");
			u64 weight = 0;
			for (u64 p = 0; p < NumPolys; ++p)
			{
				std::array<u64, 2> occupied{};
				for (u64 i = 0; i < PolyWeight; ++i)
				{
					const auto offset = offsets[p * PolyWeight + i];
					if (offset >= BlockSize)
						throw std::invalid_argument("RingLPN support offset is outside its block.");
					// i * BlockSize is divisible by FactorDegree in this profile.
					const auto residue = offset & (FactorDegree - 1);
					occupied[residue >> 6] |= 1ull << (residue & 63);
				}
				weight += std::popcount(occupied[0]) + std::popcount(occupied[1]);
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
				throw std::invalid_argument("RingLPN support filter requires four weight-16 supports.");
			do
			{
				for (auto& offset : offsets)
					offset = prng.template get<u64>() & (BlockSize - 1);
			} while (!accepts(offsets));
		}
	};
}
