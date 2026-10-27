#pragma once
#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/CompilerHints.h"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <vector>

namespace osuCrypto
{
	namespace detail
	{
		// The filter policy is derived from public Ring-LPN parameters and the
		// conservative statistical-decoding cost estimate once at setup. The
		// estimate is not a proof of Ring-LPN security. Candidate sampling has
		// bounded stack storage and no allocations.
		struct RingLpnSupportFilter
		{
			static constexpr u64 MaxPolyWeight = 256;
			static constexpr u64 MaxConstraints = 64;
			static constexpr u64 MaxSamplingAttempts = 1ull << 20;
			// A runtime budget, not a security margin: do not use a rule that
			// takes more than 64 proposals on average by itself.
			static constexpr long double MinMarginalAcceptance = 1.0L / 64;

			struct Constraint
			{
				u64 mFactorDegree = 0;
				u64 mMinWeight = 0;
				long double mMarginalAcceptance = 0;
			};

			u64 mRingSize = 0;
			u64 mNumPolys = 0;
			u64 mPolyWeight = 0;
			u64 mBlockSize = 0;
			u64 mSecurityParameter = 0;
			std::array<Constraint, MaxConstraints> mConstraints{};
			u64 mConstraintCount = 0;

			RingLpnSupportFilter() = default;

			RingLpnSupportFilter(u64 ringSize, u64 numPolys, u64 polyWeight,
				u64 twoAdicity, u64 securityParameter)
				: mRingSize(ringSize)
				, mNumPolys(numPolys)
				, mPolyWeight(polyWeight)
				, mBlockSize(polyWeight ? ringSize / polyWeight : 0)
				, mSecurityParameter(securityParameter)
			{
				if (!std::has_single_bit(ringSize) || ringSize < 2 ||
					numPolys < 2 || !polyWeight || !securityParameter || !twoAdicity ||
					polyWeight > MaxPolyWeight || ringSize % polyWeight ||
					!std::has_single_bit(mBlockSize) ||
					numPolys > std::numeric_limits<u64>::max() / polyWeight)
					throw std::invalid_argument("Invalid Ring-LPN support filter parameters.");

				const u64 logN = std::countr_zero(ringSize);
				for (u64 logD = 1; logD <= logN; ++logD)
				{
					// A degree-d binomial factor of X^N+1 exists when q-1
					// contains more than log2(N/d) powers of two.
					if (twoAdicity <= logN - logD)
						continue;
					const u64 d = 1ull << logD;
					const long double bitsPerWeight = std::log2(
						(static_cast<long double>(numPolys) * d) / (d - 1));
					const long double required =
						(static_cast<long double>(securityParameter) - logD) / bitsPerWeight;
					u64 cutoff = required <= 0 ? 0 :
						required >= d ? d : static_cast<u64>(std::ceil(required));
					if (cutoff < d && logD + cutoff * bitsPerWeight < securityParameter)
						++cutoff;

					// For d>B, each row has d/B disjoint residue groups;
					// otherwise each row has one. Every group is occupied.
					const u64 groupsPerRow = d > mBlockSize ? d / mBlockSize : 1;
					if (cutoff <= numPolys * groupsPerRow)
						continue;
					if (cutoff > numPolys * std::min(polyWeight, d))
						throw std::invalid_argument(
							"Ring-LPN support filter cannot meet the requested security parameter.");

					// W_2d >= W_d >= ceil(W_2d/2). Drop rules implied by
					// those already retained, and replace weaker earlier rules.
					bool implied = false;
					for (u64 i = 0; i < mConstraintCount; ++i)
						implied |= mConstraints[i].mMinWeight >= cutoff;
					if (implied)
						continue;
					u64 retained = 0;
					for (u64 i = 0; i < mConstraintCount; ++i)
					{
						const auto& prior = mConstraints[i];
						const u64 ratio = d / prior.mFactorDegree;
						if (1 + (cutoff - 1) / ratio < prior.mMinWeight)
							mConstraints[retained++] = prior;
					}
					mConstraintCount = retained;
					if (mConstraintCount == MaxConstraints)
						throw std::invalid_argument("Too many Ring-LPN support constraints.");
					mConstraints[mConstraintCount++] = { d, cutoff, 0 };
				}

				for (u64 i = 0; i < mConstraintCount; ++i)
				{
					auto& rule = mConstraints[i];
					rule.mMarginalAcceptance = marginalAcceptance(
						ringSize, numPolys, polyWeight,
						rule.mFactorDegree, rule.mMinWeight);
					if (rule.mMarginalAcceptance < MinMarginalAcceptance)
						throw std::invalid_argument(
							"Ring-LPN support filter is too expensive for the requested security parameter.");
				}
				std::sort(mConstraints.begin(), mConstraints.begin() + mConstraintCount,
					[](const Constraint& a, const Constraint& b) {
						return a.mMarginalAcceptance < b.mMarginalAcceptance;
					});
			}

			bool isConfigured() const { return mBlockSize != 0; }

		private:
			// Exact occupancy law for a single factor, evaluated only during
			// setup. With d>B, each of the d/B disjoint groups in a row has
			// t/(d/B) draws into B bins; otherwise a row has t draws into d bins.
			static long double marginalAcceptance(u64 ringSize, u64 numPolys,
				u64 polyWeight, u64 factorDegree, u64 cutoff)
			{
				const u64 blockSize = ringSize / polyWeight;
				const u64 groupsPerRow = factorDegree > blockSize ? factorDegree / blockSize : 1;
				const u64 bins = std::min(factorDegree, blockSize);
				const u64 draws = polyWeight / groupsPerRow;
				const u64 maxOccupied = std::min(draws, bins);
				std::vector<long double> group(maxOccupied + 1), next(maxOccupied + 1);
				group[0] = 1;
				for (u64 draw = 0; draw < draws; ++draw)
				{
					std::fill(next.begin(), next.end(), 0);
					for (u64 occupied = 0; occupied <= std::min(draw, bins); ++occupied)
					{
						const auto probability = group[occupied];
						next[occupied] += probability * occupied / bins;
						if (occupied < bins)
							next[occupied + 1] += probability * (bins - occupied) / bins;
					}
					group.swap(next);
				}

				std::vector<long double> distribution(1, 1);
				for (u64 i = 0; i < numPolys * groupsPerRow; ++i)
				{
					std::vector<long double> convolved(
						distribution.size() + group.size() - 1, 0);
					for (u64 a = 0; a < distribution.size(); ++a)
						for (u64 b = 1; b < group.size(); ++b)
							convolved[a + b] += distribution[a] * group[b];
					distribution.swap(convolved);
				}

				long double acceptance = 0;
				for (u64 occupied = cutoff; occupied < distribution.size(); ++occupied)
					acceptance += distribution[occupied];
				return acceptance;
			}

			// Sorting at most 256 residues avoids a bitmap proportional to d.
			OC_NOINLINE u64 foldedWeightSorted(span<const u64> offsets,
				u64 factorMask) const
			{
				std::array<u64, MaxPolyWeight> residues;
				u64 weight = 0;
				for (u64 p = 0; p < mNumPolys; ++p)
				{
					const auto row = p * mPolyWeight;
					for (u64 i = 0; i < mPolyWeight; ++i)
						residues[i] = (i * mBlockSize + offsets[row + i]) & factorMask;
					std::sort(residues.begin(), residues.begin() + mPolyWeight);
					++weight;
					for (u64 i = 1; i < mPolyWeight; ++i)
						weight += residues[i] != residues[i - 1];
				}
				return weight;
			}

			// Count distinct exponent residues within each polynomial. Combining
			// rows would incorrectly cancel collisions between independent errors.
			// Small factors use one word per row; larger factors use fixed scratch.
			OC_NOINLINE u64 foldedWeightUnchecked(span<const u64> offsets,
				u64 factorMask) const
			{
				if (factorMask >= 64)
					return foldedWeightSorted(offsets, factorMask);

				u64 weight = 0;
				for (u64 p = 0; p < mNumPolys; ++p)
				{
					u64 residueMask = 0;
					const auto row = p * mPolyWeight;
					for (u64 i = 0; i < mPolyWeight; ++i)
						residueMask |= 1ull << ((i * mBlockSize + offsets[row + i]) & factorMask);
					weight += std::popcount(residueMask);
				}
				return weight;
			}

			bool acceptsUnchecked(span<const u64> offsets) const
			{
				for (u64 i = 0; i < mConstraintCount; ++i)
				{
					const auto& rule = mConstraints[i];
					if (foldedWeightUnchecked(offsets, rule.mFactorDegree - 1) < rule.mMinWeight)
						return false;
				}
				return true;
			}

		public:
			OC_NOINLINE u64 foldedWeight(span<const u64> offsets,
				u64 factorDegree) const
			{
				validate(offsets);
				if (!std::has_single_bit(factorDegree) || factorDegree > mRingSize)
					throw std::invalid_argument("Invalid Ring-LPN factor degree.");
				return foldedWeightUnchecked(offsets, factorDegree - 1);
			}

			bool accepts(span<const u64> offsets) const
			{
				validate(offsets);
				return acceptsUnchecked(offsets);
			}

			// The entire tuple is redrawn on rejection. The PRNG is a template
			// so production and scripted-test streams use the same code.
			template<typename Rng>
			OC_NOINLINE void sample(span<u64> offsets, Rng& prng) const
			{
				if (!isConfigured() || offsets.size() != mNumPolys * mPolyWeight)
					throw std::invalid_argument("Ring-LPN support count does not match filter parameters.");
				for (u64 attempt = 0; attempt < MaxSamplingAttempts; ++attempt)
				{
					for (auto& offset : offsets)
						offset = prng.template get<u64>() & (mBlockSize - 1);
					if (acceptsUnchecked(offsets))
						return;
				}
				throw std::runtime_error("Ring-LPN support filter exceeded its sampling attempt limit.");
			}

		private:
			void validate(span<const u64> offsets) const
			{
				if (!isConfigured() || offsets.size() != mNumPolys * mPolyWeight)
					throw std::invalid_argument("Ring-LPN support count does not match filter parameters.");
				for (const auto offset : offsets)
					if (offset >= mBlockSize)
						throw std::invalid_argument("Ring-LPN support offset is outside its block.");
			}
		};
	}

}
