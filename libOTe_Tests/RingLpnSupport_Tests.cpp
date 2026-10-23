#include "RingLpn_Tests.h"
#include "libOTe/Triple/RingLpn/RingLpnTriple.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include "cryptoTools/Common/TestCollection.h"
#include <set>

namespace osuCrypto
{
#ifdef ENABLE_RINGLPN
	namespace
	{
		using Filter = RingLpnSupportFilter;
		using Support = std::array<u64, Filter::NumPositions>;

		struct ScriptedSupportPrng
		{
			std::array<Support, 2> candidates;
			u64 consumed = 0;
			template<typename T> T get()
			{
				if (consumed >= 2 * Filter::NumPositions)
					throw UnitTestFail("Support sampler did not accept the second candidate");
				const auto i = consumed++;
				return T(candidates[i / Filter::NumPositions][i % Filter::NumPositions]);
			}
		};

		u64 referenceWeight(span<const u64> offsets)
		{
			u64 total = 0;
			for (u64 p = 0; p < Filter::NumPolys; ++p)
			{
				std::set<u64> occupied;
				for (u64 i = 0; i < Filter::PolyWeight; ++i)
					occupied.insert((i * Filter::BlockSize + offsets[p * Filter::PolyWeight + i]) % Filter::FactorDegree);
				total += occupied.size();
			}
			return total;
		}
	}
#endif

	void RingLpn_SupportFilter_test(const CLP&)
	{
#ifdef ENABLE_RINGLPN
		Support full{}, sixty{}, sixtyOne{};
		for (u64 p = 0; p < Filter::NumPolys; ++p)
			for (u64 i = 0; i < Filter::PolyWeight; ++i)
			{
				// Exercise both occupancy words and irrelevant high offset bits.
				full[p * Filter::PolyWeight + i] = 128 * (p + 1) + (i < 8 ? i : 120 + i - 8);
			}
		sixty = full;
		for (u64 p = 0; p < Filter::NumPolys; ++p)
			sixty[p * Filter::PolyWeight + 15] = sixty[p * Filter::PolyWeight];
		sixtyOne = sixty;
		sixtyOne[15] = full[15];
		if (Filter::foldedWeight(full) != 64 || Filter::foldedWeight(sixty) != 60 ||
			Filter::foldedWeight(sixtyOne) != 61 || Filter::accepts(sixty) || !Filter::accepts(sixtyOne))
			throw UnitTestFail("Support filter boundary or per-polynomial counting is incorrect");
		Support collisions{};
		if (Filter::foldedWeight(collisions) != 4 || Filter::accepts(collisions))
			throw UnitTestFail("Support filter accepted a collision-heavy candidate");
		const auto expectInvalid = [](auto action) {
			try { action(); }
			catch (const std::invalid_argument&) { return; }
			throw UnitTestFail("Support filter accepted an invalid input");
		};
		expectInvalid([&] { Filter::foldedWeight(span<const u64>(full.data(), 63)); });
		Support invalid = full;
		invalid[0] = Filter::BlockSize;
		expectInvalid([&] { Filter::foldedWeight(invalid); });

		ScriptedSupportPrng script{ { sixty, sixtyOne } };
		Support sampled{};
		Filter::sample(sampled, script);
		if (script.consumed != 128 || sampled != sixtyOne)
			throw UnitTestFail("Support sampler did not resample the complete four-polynomial tuple");

		PRNG actual(block(11, 23)), reference(block(11, 23));
		u64 rejected = 0;
		for (u64 trial = 0; trial < 256; ++trial)
		{
			Support expected;
			do
			{
				for (auto& offset : expected)
					offset = reference.get<u64>() % Filter::BlockSize;
				if (referenceWeight(expected) >= Filter::MinWeight) break;
				++rejected;
			} while (true);
			Filter::sample(sampled, actual);
			if (sampled != expected || !Filter::accepts(sampled))
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
			ring.init(0, Filter::RingSize, Ring::Ole, dpf, Ring::TensorBaseCorType::Precomputed);
			if (!ring.usesSupportFilter())
				throw UnitTestFail("Analyzed profile did not enable support filtering");
			PRNG prng(block(19, 7)), expectedPrng(block(19, 7));
			ring.sampleSparsePositions(prng);
			Filter::sample(sampled, expectedPrng);
			if (!std::equal(sampled.begin(), sampled.end(), ring.mSparsePositions.begin()))
				throw UnitTestFail("RingLPN setup did not use filtered sampling");
			ring.mHasDpf = true;
			expectLifecycleError();
		}
		ring.init(0, Filter::RingSize / 2, Ring::Triple);
		if (!ring.usesSupportFilter())
			throw UnitTestFail("Triple count was confused with ring degree");
		ring.init(0, Filter::RingSize / 2, Ring::Ole);
		if (ring.usesSupportFilter())
			throw UnitTestFail("Support filter silently covered a different ring degree");
		PRNG legacy(block(31, 5)), legacyRef(block(31, 5));
		ring.sampleSparsePositions(legacy);
		for (auto offset : ring.mSparsePositions)
			if (offset != legacyRef.get<u64>() % ring.mBlockSize)
				throw UnitTestFail("Unsupported profile's sampler changed");
		ring.mNumPolys = 2;
		ring.mPolyWeight = 16;
		ring.init(0, Filter::RingSize, Ring::Ole);
		if (ring.usesSupportFilter())
			throw UnitTestFail("Support filter silently covered a different polynomial count");
		ring.mNumPolys = 4;
		ring.mPolyWeight = 8;
		ring.init(0, Filter::RingSize, Ring::Ole);
		if (ring.usesSupportFilter())
			throw UnitTestFail("Support filter silently covered a different weight");
		RingLpnTriple<Fp31> otherField;
		otherField.init(0, Filter::RingSize, RingLpnTriple<Fp31>::Ole);
		if (otherField.usesSupportFilter())
			throw UnitTestFail("Goldilocks support filter silently covered a different field");
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif
	}
}
