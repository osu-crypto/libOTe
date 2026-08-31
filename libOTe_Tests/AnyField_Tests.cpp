#include "AnyField_Tests.h"
#include "libOTe/Triple/AnyField/AnyFieldCtx.h"
#include "libOTe/Triple/AnyField/AnyFieldOle.h"
#include "cryptoTools/Common/TestCollection.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include <array>
#include <bit>
#include <chrono>
#include <cstring>
#include <iostream>
#include <utility>
#include <vector>

namespace osuCrypto
{
	void AnyField_F9_Test(const CLP&)
	{
		AnyFieldF9Ctx ctx;
		CoeffCtxF9 coeffCtx;

		for (u8 i = 0; i < 9; ++i)
		{
			const auto a = F9::fromIndex(i);
			if (!a.isCanonical())
				throw UnitTestFail("F9 enumeration produced a non-canonical element");
			if (a + F9::zero() != a || a - a != F9::zero())
				throw UnitTestFail("F9 additive identity failed");
			if (a.frobenius() != a.pow(3) || a.frobenius().frobenius() != a)
				throw UnitTestFail("F9 Frobenius failed");
			if (F9(a.trace(), F3(0)) != a + a.frobenius())
				throw UnitTestFail("F9 trace failed");
			if (i && a * a.inverse() != F9::one())
				throw UnitTestFail("F9 inverse failed");

			auto mutableA = a;
			auto bits = coeffCtx.binaryDecomposition(mutableA);
			F9 reconstructed = F9::zero();
			for (u64 bit = 0; bit < bits.size(); ++bit)
			{
				F9 generator;
				coeffCtx.powerOfTwo(generator, bit);
				if (bits[bit])
					reconstructed += generator;
			}
			if (reconstructed != a)
				throw UnitTestFail("F9 additive decomposition failed");

			for (u8 j = 0; j < 9; ++j)
			{
				const auto b = F9::fromIndex(j);
				if ((a + b) - b != a)
					throw UnitTestFail("F9 addition/subtraction failed");
				if (a * (b + F9::one()) != a * b + a)
					throw UnitTestFail("F9 distributivity failed");
			}
		}

		const auto xi = ctx.traceBasis(0);
		if (xi.pow(8) != F9::one() || xi.pow(4) == F9::one())
			throw UnitTestFail("F9 context generator does not have order eight");
		if (ctx.traceBasis(1) != xi.frobenius())
			throw UnitTestFail("F9 context trace basis is inconsistent");
	}

	void AnyField_F9Transform_Test(const CLP&)
	{
		AnyFieldF9Ctx ctx;
		std::array<F9, 8> input;
		for (u8 i = 0; i < input.size(); ++i)
			input[i] = F9::fromIndex(i);

		auto actual = input;
		ctx.transform(actual, 1);

		std::array<F9, 8> expected;
		const auto omega = ctx.rootOfUnity();
		for (u64 frequency = 0; frequency < 8; ++frequency)
		{
			F9 sum = F9::zero();
			for (u64 coefficient = 0; coefficient < 8; ++coefficient)
				sum += input[coefficient] * omega.pow(coefficient * frequency);

			const auto reversed = static_cast<u64>(
				((frequency & 1) << 2) | (frequency & 2) | ((frequency & 4) >> 2));
			expected[reversed] = sum;
		}

		if (actual != expected)
			throw UnitTestFail("F9 fixed radix-eight transform disagrees with direct evaluation");

		std::vector<F9> twoDimensional(64, F9::zero());
		twoDimensional[0] = F9::one();
		ctx.transform(twoDimensional, 2);
		for (const auto value : twoDimensional)
			if (value != F9::one())
				throw UnitTestFail("F9 multidimensional transform has inconsistent strides");
	}

	void AnyField_F4_Test(const CLP&)
	{
		AnyFieldF4Ctx ctx;
		CoeffCtxF4 coeffCtx;

		for (u8 i = 0; i < 4; ++i)
		{
			const auto a = F4::fromIndex(i);
			if (!a.isCanonical())
				throw UnitTestFail("F4 enumeration produced a non-canonical element");
			if (a + F4::zero() != a || a - a != F4::zero())
				throw UnitTestFail("F4 additive identity failed");
			if (a.frobenius() != a.pow(2) || a.frobenius().frobenius() != a)
				throw UnitTestFail("F4 Frobenius failed");
			if (F4(a.trace(), F2(0)) != a + a.frobenius())
				throw UnitTestFail("F4 trace failed");
			if (i && a * a.inverse() != F4::one())
				throw UnitTestFail("F4 inverse failed");

			auto mutableA = a;
			auto bits = coeffCtx.binaryDecomposition(mutableA);
			F4 reconstructed = F4::zero();
			for (u64 bit = 0; bit < bits.size(); ++bit)
			{
				F4 generator;
				coeffCtx.powerOfTwo(generator, bit);
				if (bits[bit])
					reconstructed += generator;
			}
			if (reconstructed != a)
				throw UnitTestFail("F4 additive decomposition failed");

			for (u8 j = 0; j < 4; ++j)
			{
				const auto b = F4::fromIndex(j);
				if ((a + b) - b != a)
					throw UnitTestFail("F4 addition/subtraction failed");
				if (a * (b + F4::one()) != a * b + a)
					throw UnitTestFail("F4 distributivity failed");
			}
		}

		const auto xi = ctx.traceBasis(0);
		if (xi.pow(3) != F4::one() || xi == F4::one())
			throw UnitTestFail("F4 context generator does not have order three");
		if (ctx.traceBasis(1) != xi.frobenius())
			throw UnitTestFail("F4 context trace basis is inconsistent");
	}

	void AnyField_F4Transform_Test(const CLP&)
	{
		AnyFieldF4Ctx ctx;
		std::array<F4, 3> input{
			F4::fromIndex(1), F4::fromIndex(2), F4::fromIndex(3) };
		auto actual = input;
		ctx.transform(actual, 1);

		std::array<F4, 3> expected;
		const auto omega = ctx.rootOfUnity();
		for (u64 frequency = 0; frequency < 3; ++frequency)
		{
			F4 sum = F4::zero();
			for (u64 coefficient = 0; coefficient < 3; ++coefficient)
				sum += input[coefficient] * omega.pow(coefficient * frequency);
			expected[frequency] = sum;
		}
		if (actual != expected)
			throw UnitTestFail("F4 fixed radix-three transform disagrees with direct evaluation");

		std::vector<F4> twoDimensional(9, F4::zero());
		twoDimensional[0] = F4::one();
		ctx.transform(twoDimensional, 2);
		for (const auto value : twoDimensional)
			if (value != F4::one())
				throw UnitTestFail("F4 multidimensional transform has inconsistent strides");
	}

	void AnyField_GoldilocksTransform_Test(const CLP&)
	{
		AnyFieldGoldilocksCtx ctx;
		std::array<Goldilocks, 4> input{
			Goldilocks{ 1 }, Goldilocks{ 2 }, Goldilocks{ 3 }, Goldilocks{ 4 } };
		auto actual = input;
		ctx.transform(actual, 2);

		std::array<Goldilocks, 4> expected;
		for (u64 y = 0; y < expected.size(); ++y)
		{
			auto sum = Goldilocks::zero();
			for (u64 x = 0; x < input.size(); ++x)
				sum += ((std::popcount(x & y) & 1) ? -input[x] : input[x]);
			expected[y] = sum;
		}
		if (actual != expected)
			throw UnitTestFail("Goldilocks Walsh-Hadamard transform disagrees with direct evaluation");
	}

	void AnyField_PositionCircuit_Test(const CLP&)
	{
#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)
		auto runCase = [](u64 modulus, u64 coordinateBits, u64 dimensions) {
			u64 domain = 1;
			for (u64 i = 0; i < dimensions; ++i)
				domain *= modulus;
			auto circuit = anyField::detail::makePositionCircuit(
				modulus, coordinateBits, dimensions, domain);
			const auto inputBits = coordinateBits * dimensions;
			const auto outputBits = log2ceil(domain);

			auto pack = [&](u64 position) {
				u64 result = 0;
				for (u64 coordinate = 0; coordinate < dimensions; ++coordinate)
				{
					result |= (position % modulus) << (coordinateBits * coordinate);
					position /= modulus;
				}
				return result;
			};

			for (u64 lhs = 0; lhs < domain; ++lhs)
				for (u64 rhs = 0; rhs < domain; ++rhs)
				{
					auto lhsInput = pack(lhs);
					auto rhsInput = pack(rhs);
					std::vector<BitVector> inputs(2), outputs(1);
					inputs[0].append(reinterpret_cast<u8*>(&lhsInput), inputBits);
					inputs[1].append(reinterpret_cast<u8*>(&rhsInput), inputBits);
					outputs[0].resize(outputBits);
					circuit.evaluate(inputs, outputs, false);

					u64 actual = 0;
					std::memcpy(&actual, outputs[0].data(), outputs[0].sizeBytes());
					u64 expected = 0;
					u64 radix = 1;
					auto lhsDigits = lhs;
					auto rhsDigits = rhs;
					for (u64 coordinate = 0; coordinate < dimensions; ++coordinate)
					{
						expected += ((lhsDigits % modulus + rhsDigits % modulus) % modulus) * radix;
						lhsDigits /= modulus;
						rhsDigits /= modulus;
						radix *= modulus;
					}
					if (actual != expected)
						throw UnitTestFail("AnyField position circuit produced the wrong group sum");
				}
		};

		runCase(3, 2, 1);
		runCase(3, 2, 2);
		runCase(3, 2, 3);
		runCase(5, 3, 2);
		runCase(8, 3, 2);
#else
		throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_CIRCUITS are required.");
#endif
	}

#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)
	static_assert(sizeof(AnyFieldF2Ole::PackedPublic) == sizeof(u16));
	static_assert(sizeof(AnyFieldF3Ole::PackedPublic) == sizeof(u32));
	static_assert(sizeof(AnyFieldGoldilocksOle::PackedPublic) == sizeof(Goldilocks));

	struct AnyFieldOleTestParams
	{
		static constexpr u64 compressionFactor = 2;
		static constexpr u64 blockDimensions = 1;
		static constexpr u64 pointsPerBlock = 2;
		static constexpr u64 minimumDimension = 2;
		static constexpr u64 maximumDimension = 6;
	};

	struct AnyFieldF4BenchmarkParams
	{
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 2;
		static constexpr u64 pointsPerBlock = 2;
		static constexpr u64 minimumDimension = 4;
		static constexpr u64 maximumDimension = 8;
	};

	// Keep the RevCuckoo integration test bounded. Production AnyField parameter
	// sets are exercised separately from this state-machine/correctness test.
	struct AnyFieldF4RevCuckooTestParams
	{
		static constexpr u64 compressionFactor = 2;
		static constexpr u64 blockDimensions = 1;
		static constexpr u64 pointsPerBlock = 1;
		static constexpr u64 minimumDimension = 5;
		static constexpr u64 maximumDimension = 6;
	};

	// Exercise every c=8 convolution channel without approaching a production
	// output size. This catches channel/lane ordering errors while keeping the
	// RevCuckoo real-leaf count at 2(2c-1)N = 7290.
	struct AnyFieldF4RevCuckooChannelTestParams
	{
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 1;
		static constexpr u64 pointsPerBlock = 1;
		static constexpr u64 minimumDimension = 5;
		static constexpr u64 maximumDimension = 5;
	};

	// Test-only comparison policy for measuring the cost that generalized
	// regular blocks avoid. All 18 points occupy one full-domain block.
	struct AnyFieldF4FullDomainBenchmarkParams
	{
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 0;
		static constexpr u64 pointsPerBlock = 18;
		static constexpr u64 minimumDimension = 4;
		static constexpr u64 maximumDimension = 8;
	};

	struct AnyFieldF9BenchmarkParams
	{
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 1;
		static constexpr u64 pointsPerBlock = 3;
		static constexpr u64 minimumDimension = 2;
		static constexpr u64 maximumDimension = 4;
	};

	// Exercise the production Goldilocks layout at a bounded domain: eight
	// public polynomials, eight regular blocks, and three points per block. A
	// request for 16 OLEs rounds to N=32, which also checks the truncated public
	// coefficient storage without launching the full N=2^20 expansion.
	struct AnyFieldGoldilocksTestParams
	{
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 3;
		static constexpr u64 pointsPerBlock = 3;
		static constexpr u64 minimumDimension = 5;
		static constexpr u64 maximumDimension = 6;
	};

	template<typename Ole>
	void runAnyFieldOleCase(
		u64 numOles,
		bool printTiming,
		const char* fieldName,
		AnyFieldDpfMode dpfMode = AnyFieldDpfMode::RegularDpf,
		AnyFieldNoiseMode noiseMode = AnyFieldNoiseMode::SingleUse)
	{
		using Base = typename Ole::Base;
		using Ctx = typename Ole::Ctx;
		std::array<Ole, 2> ole;
		const block publicSeed(0x9132749812374981, 0x1239874192387491);
		for (u64 party = 0; party < 2; ++party)
			ole[party].init(party, numOles, publicSeed, dpfMode, noiseMode);
		if (ole[0].outputSize() != numOles || ole[1].outputSize() != numOles)
			throw UnitTestFail("AnyFieldOle did not preserve the requested output count");

		PRNG prng0(block(0x1111111111111111, 0x2222222222222222));
		PRNG prng1(block(0x3333333333333333, 0x4444444444444444));
		std::array<std::vector<Base>, 2> x, z;
		for (u64 party = 0; party < 2; ++party)
		{
			x[party].resize(ole[party].outputSize());
			z[party].resize(ole[party].outputSize());
		}

		double setupMs = 0;
		double expandMs = 0;
		const auto repetitions = printTiming ? 1 : 2;
		for (u64 repetition = 0; repetition < repetitions; ++repetition)
		{
			const auto count0 = ole[0].baseCorCount();
			const auto count1 = ole[1].baseCorCount();
			if (count0.mSendOtCount != count1.mRecvOtCount ||
				count0.mRecvOtCount != count1.mSendOtCount ||
				count0.mOleCount != count1.mOleCount)
				throw UnitTestFail("AnyFieldOle base-correlation counts disagree");
			if (repetition &&
				(ole[0].hasPositions() != (noiseMode == AnyFieldNoiseMode::Stationary) ||
					ole[1].hasPositions() != (noiseMode == AnyFieldNoiseMode::Stationary)))
				throw UnitTestFail("AnyFieldOle noise mode has the wrong position lifecycle");

			PRNG basePrng(block(
				0x1234567812345678ull + repetition,
				0x8765432187654321ull - repetition));
			std::array<std::vector<std::array<block, 2>>, 2> sendOts;
			std::array<std::vector<block>, 2> recvOts;
			std::array<BitVector, 2> choices;
			const std::array counts{ count0, count1 };
			for (u64 sender = 0; sender < 2; ++sender)
			{
				sendOts[sender].resize(counts[sender].mSendOtCount);
				basePrng.get(sendOts[sender].data(), sendOts[sender].size());
				const auto receiver = 1 ^ sender;
				recvOts[receiver].resize(sendOts[sender].size());
				choices[receiver].resize(sendOts[sender].size());
				choices[receiver].randomize(basePrng);
				for (u64 i = 0; i < sendOts[sender].size(); ++i)
					recvOts[receiver][i] =
						sendOts[sender][i][choices[receiver][i]];
			}

			const auto oleBlocks = divCeil(count0.mOleCount, 128);
			std::array<std::vector<block>, 2> oleMult{
				std::vector<block>(oleBlocks), std::vector<block>(oleBlocks) };
			std::array<std::vector<block>, 2> oleAdd{
				std::vector<block>(oleBlocks), std::vector<block>(oleBlocks) };
			for (u64 party = 0; party < 2; ++party)
			{
				basePrng.get(oleMult[party].data(), oleMult[party].size());
				basePrng.get(oleAdd[party].data(), oleAdd[party].size());
			}
			for (u64 i = 0; i < count0.mOleCount; ++i)
			{
				const auto product = *BitIterator(oleMult[0].data(), i) &
					*BitIterator(oleMult[1].data(), i);
				*BitIterator(oleAdd[1].data(), i) =
					product ^ *BitIterator(oleAdd[0].data(), i);
			}

			for (u64 party = 0; party < 2; ++party)
				ole[party].setBaseCors(
					sendOts[party], recvOts[party], choices[party],
					oleMult[party], oleAdd[party]);

			auto setupSockets = coproto::LocalAsyncSocket::makePair();
			const auto setupStart = std::chrono::steady_clock::now();
			auto setupResult = macoro::sync_wait(macoro::when_all_ready(
				ole[0].setup(prng0, setupSockets[0]),
				ole[1].setup(prng1, setupSockets[1])));
			std::get<0>(setupResult).result();
			std::get<1>(setupResult).result();
			const auto setupEnd = std::chrono::steady_clock::now();

			if (!ole[0].hasSetup() || !ole[1].hasSetup() ||
				!ole[0].hasPositions() || !ole[1].hasPositions() ||
				ole[0].hasBaseCors() || ole[1].hasBaseCors())
				throw UnitTestFail("AnyFieldOle setup retained or lost protocol state");

			auto expandSockets = coproto::LocalAsyncSocket::makePair();
			auto expandResult = macoro::sync_wait(macoro::when_all_ready(
				ole[0].expand(x[0], z[0], prng0, expandSockets[0]),
				ole[1].expand(x[1], z[1], prng1, expandSockets[1])));
			std::get<0>(expandResult).result();
			std::get<1>(expandResult).result();
			const auto expandEnd = std::chrono::steady_clock::now();

			for (u64 i = 0; i < x[0].size(); ++i)
				if (x[0][i] * x[1][i] != z[0][i] + z[1][i])
					throw UnitTestFail("AnyFieldOle correlation failed");
			if (ole[0].hasSetup() || ole[1].hasSetup() ||
				ole[0].hasPositions() != (noiseMode == AnyFieldNoiseMode::Stationary) ||
				ole[1].hasPositions() != (noiseMode == AnyFieldNoiseMode::Stationary))
				throw UnitTestFail("AnyFieldOle expansion consumed the wrong state");

			setupMs += std::chrono::duration<double, std::milli>(
				setupEnd - setupStart).count();
			expandMs += std::chrono::duration<double, std::milli>(
				expandEnd - setupEnd).count();
		}
		if (printTiming)
		{
			std::cout << "AnyField " << fieldName << " OLE: N="
				<< ole[0].expandedOutputSize() / Ctx::extensionDegree
				<< ", requested=" << ole[0].outputSize()
				<< ", c=" << Ole::CompressionFactor
				<< ", blocks=" << Ole::BlockCount
				<< ", points/block=" << Ole::PointsPerBlock
				<< ", setup=" << setupMs
				<< " ms, expand=" << expandMs << " ms\n";
		}
	}
#endif

	void AnyField_F3Ole_Test(const CLP& cmd)
	{
#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)
		using TestOle = AnyFieldOle<AnyFieldF9Ctx, AnyFieldOleTestParams>;
		runAnyFieldOleCase<TestOle>(1, false, "F3");
		runAnyFieldOleCase<TestOle>(128, false, "F3");
		if (cmd.isSet("v"))
		{
			using BenchmarkOle = AnyFieldOle<AnyFieldF9Ctx, AnyFieldF9BenchmarkParams>;
			runAnyFieldOleCase<BenchmarkOle>(cmd.getOr("n", 128ull), true, "F3");
		}
#else
		throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_CIRCUITS are required.");
#endif
	}

	void AnyField_F2Ole_Test(const CLP& cmd)
	{
#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)
		using TestOle = AnyFieldOle<AnyFieldF4Ctx, AnyFieldOleTestParams>;
		if (!cmd.isSet("revOnly"))
		{
			runAnyFieldOleCase<TestOle>(1, false, "F2");
			runAnyFieldOleCase<TestOle>(18, false, "F2");
			runAnyFieldOleCase<TestOle>(
				1, false, "F2 regular stationary",
				AnyFieldDpfMode::RegularDpf, AnyFieldNoiseMode::Stationary);
		}
#ifdef ENABLE_SPARSE_DPF
		if (!cmd.isSet("regularOnly"))
		{
			using RevTestOle = AnyFieldOle<
				AnyFieldF4Ctx, AnyFieldF4RevCuckooTestParams>;
			if (!cmd.isSet("stationaryOnly"))
				runAnyFieldOleCase<RevTestOle>(
					1, false, "F2 RevCuckoo single-use",
					AnyFieldDpfMode::RevCuckoo, AnyFieldNoiseMode::SingleUse);
			if (!cmd.isSet("singleOnly"))
				runAnyFieldOleCase<RevTestOle>(
					1, false, "F2 RevCuckoo stationary",
					AnyFieldDpfMode::RevCuckoo, AnyFieldNoiseMode::Stationary);
			if (!cmd.isSet("stationaryOnly"))
			{
				using ChannelTestOle = AnyFieldOle<
					AnyFieldF4Ctx, AnyFieldF4RevCuckooChannelTestParams>;
				runAnyFieldOleCase<ChannelTestOle>(
					1, false, "F2 RevCuckoo c=8 channels",
					AnyFieldDpfMode::RevCuckoo, AnyFieldNoiseMode::SingleUse);
			}
		}
#endif
		if (cmd.isSet("v"))
		{
			if (cmd.isSet("fullDomain"))
			{
				using BenchmarkOle = AnyFieldOle<
					AnyFieldF4Ctx, AnyFieldF4FullDomainBenchmarkParams>;
				runAnyFieldOleCase<BenchmarkOle>(cmd.getOr("n", 486ull), true, "F2 full-domain");
			}
			else
			{
				using BenchmarkOle = AnyFieldOle<AnyFieldF4Ctx, AnyFieldF4BenchmarkParams>;
				runAnyFieldOleCase<BenchmarkOle>(cmd.getOr("n", 486ull), true, "F2");
			}
		}
#else
		throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_CIRCUITS are required.");
#endif
	}

	void AnyField_GoldilocksOle_Test(const CLP& cmd)
	{
#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)
		using TestOle = AnyFieldOle<AnyFieldGoldilocksCtx, AnyFieldGoldilocksTestParams>;
		runAnyFieldOleCase<TestOle>(1, false, "Goldilocks");
		runAnyFieldOleCase<TestOle>(16, false, "Goldilocks");

		const block publicSeed(0x9132749812374981, 0x1239874192387491);
		TestOle source;
		source.init(0, 16, publicSeed);
		TestOle destination(std::move(source));
		if (source.isInitialized() || destination.outputSize() != 16)
			throw UnitTestFail("AnyFieldOle move construction retained or lost public state");
		destination.clear();
		if (destination.isInitialized() || destination.hasSetup() || destination.hasBaseCors())
			throw UnitTestFail("AnyFieldOle explicit clear retained protocol state");

		if (cmd.isSet("v"))
			runAnyFieldOleCase<AnyFieldGoldilocksOle>(
				cmd.getOr("n", 1ull << 20), true, "Goldilocks");
#else
		throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_CIRCUITS are required.");
#endif
	}
}
