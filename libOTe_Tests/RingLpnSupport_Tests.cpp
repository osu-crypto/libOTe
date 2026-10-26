#include "RingLpn_Tests.h"
#include "libOTe/Triple/RingLpn/RingLpnTriple.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include "cryptoTools/Common/TestCollection.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <set>

namespace osuCrypto
{
#ifdef ENABLE_RINGLPN
	namespace
	{
		using Filter = detail::RingLpnSupportFilter;
		constexpr u64 RingSize = 1ull << 20;
		constexpr u64 NumPolys = 4;
		constexpr u64 PolyWeight = 16;
		constexpr u64 NumPositions = NumPolys * PolyWeight;
		using Support = std::array<u64, NumPositions>;

		struct ScriptedSupportPrng
		{
			std::array<Support, 2> candidates;
			u64 consumed = 0;

			template<typename T> T get()
			{
				if (consumed >= 2 * NumPositions)
					throw UnitTestFail("Support sampler did not accept the second candidate");
				const auto i = consumed++;
				return T(candidates[i / NumPositions][i % NumPositions]);
			}
		};

		u64 referenceWeight(const Filter& filter, span<const u64> offsets,
			u64 factorDegree)
		{
			u64 total = 0;
			for (u64 p = 0; p < filter.mNumPolys; ++p)
			{
				std::set<u64> occupied;
				for (u64 i = 0; i < filter.mPolyWeight; ++i)
					occupied.insert((i * filter.mBlockSize +
						offsets[p * filter.mPolyWeight + i]) % factorDegree);
				total += occupied.size();
			}
			return total;
		}

		bool referenceAccepts(const Filter& filter, span<const u64> offsets)
		{
			for (u64 i = 0; i < filter.mConstraintCount; ++i)
			{
				const auto& rule = filter.mConstraints[i];
				if (referenceWeight(filter, offsets, rule.mFactorDegree) <
					rule.mMinWeight)
					return false;
			}
			return true;
		}

		void referenceSample(const Filter& filter, span<u64> offsets, PRNG& prng,
			u64& rejections)
		{
			for (;;)
			{
				for (auto& offset : offsets)
					offset = prng.get<u64>() % filter.mBlockSize;
				if (referenceAccepts(filter, offsets))
					return;
				++rejections;
			}
		}

		bool hasConstraint(const Filter& filter, u64 factorDegree, u64 minWeight)
		{
			for (u64 i = 0; i < filter.mConstraintCount; ++i)
				if (filter.mConstraints[i].mFactorDegree == factorDegree &&
					filter.mConstraints[i].mMinWeight == minWeight)
					return true;
			return false;
		}
	}
#endif

	void RingLpn_SupportFilter_test(const CLP&)
	{
#ifdef ENABLE_RINGLPN
		const Filter filter(RingSize, NumPolys, PolyWeight, 32, 128);
		if (!filter.isConfigured() || filter.mBlockSize != RingSize / PolyWeight ||
			filter.mConstraintCount != 2 ||
			!hasConstraint(filter, 64, 61) || !hasConstraint(filter, 32, 32))
			throw UnitTestFail("Goldilocks support policy derived incorrect constraints");

		// Only fields with sufficient two-adicity expose small binomial factors.
		const Filter lowTwoAdicity(64, 4, 4, 1, 20);
		const Filter highTwoAdicity(64, 4, 4, 6, 20);
		if (lowTwoAdicity.mConstraintCount != 0 ||
			!hasConstraint(highTwoAdicity, 8, 8))
			throw UnitTestFail("Field two-adicity did not control factor selection");

		// Here d=8 exceeds B=4. Each polynomial has two independent
		// two-draw groups of four residues. Enumerate all 4^8 supports to
		// check both the regular-block occupancy and the exact marginal law.
		const Filter small(16, 2, 4, 8, 12);
		if (!hasConstraint(small, 8, 8))
			throw UnitTestFail("Small profile omitted its degree-eight constraint");
		u64 acceptedSmall = 0;
		std::array<u64, 8> smallOffsets{};
		for (u64 encoded = 0; encoded < (1ull << 16); ++encoded)
		{
			auto bits = encoded;
			for (auto& offset : smallOffsets)
			{
				offset = bits & 3;
				bits >>= 2;
			}
			const auto weight = referenceWeight(small, smallOffsets, 8);
			if (small.foldedWeight(smallOffsets, 8) != weight)
				throw UnitTestFail("Degree-eight folded weight differs from enumeration");
			acceptedSmall += weight >= 8;
		}
		if (acceptedSmall != 20736)
			throw UnitTestFail("Degree-eight exact acceptance count is incorrect");
		for (u64 i = 0; i < small.mConstraintCount; ++i)
			if (small.mConstraints[i].mFactorDegree == 8 &&
				std::abs(small.mConstraints[i].mMarginalAcceptance -
					static_cast<long double>(acceptedSmall) / (1ull << 16)) > 1e-15L)
				throw UnitTestFail("Degree-eight marginal acceptance is incorrect");

		// Each polynomial contributes its own occupied residues. The offsets
		// include high bits, which must not change the degree-64 result.
		Support full{}, sixty{}, sixtyOne{};
		for (u64 p = 0; p < NumPolys; ++p)
			for (u64 i = 0; i < PolyWeight; ++i)
				full[p * PolyWeight + i] =
					128 * (p + 1) + (i < 8 ? i : 120 + i - 8);
		sixty = full;
		for (u64 p = 0; p < NumPolys; ++p)
			sixty[p * PolyWeight + 15] = sixty[p * PolyWeight];
		sixtyOne = sixty;
		sixtyOne[15] = full[15];
		if (filter.foldedWeight(full, 64) != 64 ||
			filter.foldedWeight(sixty, 64) != 60 ||
			filter.foldedWeight(sixtyOne, 64) != 61 ||
			filter.accepts(sixty) || !filter.accepts(sixtyOne))
			throw UnitTestFail("Degree-64 support boundary is incorrect");

		// Keep degree-64 weight above its cutoff while crossing the degree-32
		// cutoff, so this checks that both constraints are enforced.
		Support thirtyOne{}, thirtyTwo{};
		for (u64 p = 0; p < NumPolys; ++p)
			for (u64 i = 0; i < PolyWeight; ++i)
				thirtyOne[p * PolyWeight + i] = i < 8 ? i : 32 + i - 8;
		thirtyOne[3 * PolyWeight + 7] = 0;
		thirtyOne[3 * PolyWeight + 15] = 32;
		thirtyTwo = thirtyOne;
		thirtyTwo[3 * PolyWeight + 15] = 39;
		if (filter.foldedWeight(thirtyOne, 64) < 61 ||
			filter.foldedWeight(thirtyOne, 32) != 31 ||
			filter.foldedWeight(thirtyTwo, 32) != 32 ||
			filter.accepts(thirtyOne) || !filter.accepts(thirtyTwo))
			throw UnitTestFail("Degree-32 support constraint was not enforced");

		Support shifted{};
		if (filter.foldedWeight(shifted, 1ull << 17) != 8)
			throw UnitTestFail("Support filter ignored block positions");
		for (u64 p = 0; p < NumPolys; ++p)
			for (u64 i = 8; i < PolyWeight; ++i)
				shifted[p * PolyWeight + i] = 1;
		if (filter.foldedWeight(shifted, 1ull << 19) != 64)
			throw UnitTestFail("Support filter mishandled a large factor degree");
		Support collisions{};
		if (filter.foldedWeight(collisions, 64) != 4 || filter.accepts(collisions))
			throw UnitTestFail("Support filter accepted a collision-heavy candidate");

		const auto expectInvalid = [](auto action) {
			try { action(); }
			catch (const std::invalid_argument&) { return; }
			throw UnitTestFail("Support filter accepted an invalid input");
		};
		expectInvalid([&] { filter.foldedWeight(span<const u64>(full.data(), 63), 64); });
		Support invalid = full;
		invalid[0] = filter.mBlockSize;
		expectInvalid([&] { filter.foldedWeight(invalid, 64); });
		expectInvalid([&] { Filter(96, 1, 3, 8, 1); });
		expectInvalid([&] { Filter(64, 2, 2, 12, 0); });
		expectInvalid([&] { Filter(RingSize, NumPolys, PolyWeight, 32, 256); });
		expectInvalid([&] { Filter(64, 2, 2, 12, 128); });

		ScriptedSupportPrng script{ { sixty, sixtyOne } };
		Support sampled{};
		filter.sample(sampled, script);
		if (script.consumed != 2 * sampled.size() || sampled != sixtyOne)
			throw UnitTestFail("Support sampler did not resample the complete tuple");

		PRNG actual(block(11, 23)), reference(block(11, 23));
		u64 rejected = 0;
		for (u64 trial = 0; trial < 64; ++trial)
		{
			Support expected{};
			referenceSample(filter, expected, reference, rejected);
			filter.sample(sampled, actual);
			if (sampled != expected || !filter.accepts(sampled) ||
				!referenceAccepts(filter, sampled) ||
				filter.foldedWeight(sampled, 64) != referenceWeight(filter, sampled, 64) ||
				filter.foldedWeight(sampled, 32) != referenceWeight(filter, sampled, 32))
				throw UnitTestFail("Support sampler differs from independent rejection sampler");
		}
		if (!rejected || actual.get<block>() != reference.get<block>())
			throw UnitTestFail("Support sampler consumed incorrect randomness");

		using Ring = RingLpnTriple<Goldilocks>;
		Ring ring;
		PRNG lifecyclePrng(ZeroBlock);
		const auto expectLifecycleError = [&] {
			try { ring.sampleSparsePositions(lifecyclePrng); }
			catch (const std::logic_error&) { return; }
			throw UnitTestFail("Support sampling ignored the setup lifecycle");
		};
		expectLifecycleError();
		for (auto dpf : { Ring::DpfType::RevCuckooDmpf, Ring::DpfType::SumDmpf })
		{
			ring.init(0, RingSize, Ring::Ole, dpf,
				Ring::TensorBaseCorType::Precomputed,
				DefaultCoeffCtx<Goldilocks>{});
			if (ring.mN != RingSize)
				throw UnitTestFail("RingLPN initialized the wrong ring degree");
			PRNG prng(block(19, 7)), expectedPrng(block(19, 7));
			ring.sampleSparsePositions(prng);
			Support expected{};
			u64 unusedRejections = 0;
			referenceSample(filter, expected, expectedPrng, unusedRejections);
			if (!std::equal(expected.begin(), expected.end(),
				ring.mSparsePositions.begin()) ||
				prng.get<block>() != expectedPrng.get<block>())
				throw UnitTestFail("RingLPN setup did not use the derived sampler");
			ring.mHasDpf = true;
			expectLifecycleError();
		}

		ring.init(0, RingSize / 2, Ring::Triple);
		if (ring.mN != RingSize)
			throw UnitTestFail("Triple count was confused with ring degree");
		PRNG triplePrng(block(41, 13)), tripleReference(block(41, 13));
		ring.sampleSparsePositions(triplePrng);
		Support tripleExpected{};
		u64 tripleRejections = 0;
		referenceSample(filter, tripleExpected, tripleReference, tripleRejections);
		if (!std::equal(tripleExpected.begin(), tripleExpected.end(),
			ring.mSparsePositions.begin()) ||
			triplePrng.get<block>() != tripleReference.get<block>())
			throw UnitTestFail("Triple mode used a different support policy");

		RingLpnTriple<Fp31> otherField;
		otherField.init(0, RingSize, RingLpnTriple<Fp31>::Ole);
		PRNG otherPrng(block(43, 17)), otherReference(block(43, 17));
		otherField.sampleSparsePositions(otherPrng);
		Support otherExpected{};
		u64 otherRejections = 0;
		referenceSample(filter, otherExpected, otherReference, otherRejections);
		if (!std::equal(otherExpected.begin(), otherExpected.end(),
			otherField.mSparsePositions.begin()) ||
			otherPrng.get<block>() != otherReference.get<block>())
			throw UnitTestFail("Support filter was limited to Goldilocks");

		using ToyRing = RingLpnTriple<F12289>;
		const Filter toyFilter(64, 2, 2, 12, 6);
		if (!hasConstraint(toyFilter, 4, 3))
			throw UnitTestFail("Low-security toy policy omitted its constraint");
		ToyRing toy;
		toy.mNumPolys = 2;
		toy.mPolyWeight = 2;
		toy.init(0, 64, ToyRing::Ole, ToyRing::DpfType::RevCuckooDmpf,
			ToyRing::TensorBaseCorType::OtBased, 6);
		PRNG toyPrng(block(31, 5)), toyReference(block(31, 5));
		std::array<u64, 4> toyExpected{};
		u64 toyRejections = 0;
		toy.sampleSparsePositions(toyPrng);
		referenceSample(toyFilter, toyExpected, toyReference, toyRejections);
		if (!std::equal(toyExpected.begin(), toyExpected.end(),
			toy.mSparsePositions.begin()) ||
			toyPrng.get<block>() != toyReference.get<block>())
			throw UnitTestFail("Small profile bypassed the support sampler");
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif
	}
}
