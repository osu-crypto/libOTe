#include "Waterfall_Tests.h"

#include "libOTe/Dpf/WaterfallDmpf.h"
#include "libOTe/Dpf/Waterfall/WaterfallBasic.h"
#include "libOTe/Dpf/Waterfall/WaterfallCandidates.h"
#include "libOTe/Dpf/Waterfall/WaterfallConfig.h"
#include "libOTe/Dpf/Waterfall/WaterfallHash.h"
#include "libOTe/Dpf/Waterfall/WaterfallPlacement.h"
#include "libOTe/Dpf/Waterfall/WaterfallReachability.h"
#include "libOTe/Dpf/Waterfall/WaterfallScatter.h"
#include "coproto/Socket/LocalAsyncSock.h"

#include <array>
#include <numeric>
#include <unordered_map>

namespace osuCrypto
{
	template<typename Protocol>
	void setCorrelatedOts(std::array<Protocol, 2>& protocol, PRNG& prng)
	{
		const auto count = protocol[0].baseOtCount();
		if (protocol[1].baseOtCount() != count)
			throw RTE_LOC;

		std::array<std::vector<std::array<block, 2>>, 2> send;
		std::array<std::vector<block>, 2> receive;
		std::array<BitVector, 2> choices;
		for (u64 party = 0; party < 2; ++party)
		{
			send[party].resize(count);
			receive[party].resize(count);
			choices[party].resize(count);
			prng.get(send[party].data(), send[party].size());
			choices[party].randomize(prng);
		}
		for (u64 party = 0; party < 2; ++party)
			for (u64 i = 0; i < count; ++i)
				receive[party][i] = send[party ^ 1][i][choices[party][i]];
		for (u64 party = 0; party < 2; ++party)
			protocol[party].setBaseOts(send[party], receive[party], choices[party]);
	}

	template<typename Protocol>
	void setCorrelatedAsymmetricOts(std::array<Protocol, 2>& protocol, PRNG& prng)
	{
		const std::array counts{ protocol[0].baseOtCount(), protocol[1].baseOtCount() };
		if (counts[0].mRecvCount != counts[1].mSendCount ||
			counts[1].mRecvCount != counts[0].mSendCount)
			throw RTE_LOC;

		std::array<std::vector<std::array<block, 2>>, 2> send;
		std::array<std::vector<block>, 2> receive;
		std::array<BitVector, 2> choices;
		for (u64 party = 0; party < 2; ++party)
		{
			send[party].resize(counts[party].mSendCount);
			receive[party].resize(counts[party].mRecvCount);
			choices[party].resize(counts[party].mRecvCount);
			prng.get(send[party].data(), send[party].size());
			choices[party].randomize(prng);
		}
		for (u64 party = 0; party < 2; ++party)
			for (u64 i = 0; i < receive[party].size(); ++i)
				receive[party][i] = send[party ^ 1][i][choices[party][i]];
		for (u64 party = 0; party < 2; ++party)
			protocol[party].setBaseOts(send[party], receive[party], choices[party]);
	}

	void Waterfall_config_Test(const oc::CLP&)
	{
		auto four = WaterfallConfig::compact4N();
		four.validate();
		if (four.numPartitions() != 4 || four.numColumns() != 64 || four.mRepairLimit != 3)
			throw RTE_LOC;

		auto three = WaterfallConfig::compact3N();
		three.validate();
		if (three.numPartitions() != 3 || three.numColumns() != 320 || three.mRepairLimit != 2)
			throw RTE_LOC;

		WaterfallReachability fourRepair;
		WaterfallReachability threeRepair;
		fourRepair.init(0, 16, 1, four);
		threeRepair.init(0, 16, 1, three);
		if (fourRepair.baseOtCount() != 4213 || threeRepair.baseOtCount() != 2654)
			throw RTE_LOC;

		bool rejected = false;
		try
		{
			WaterfallConfig{ { 16, 12, 16 }, 2 }.validate();
		}
		catch (const std::invalid_argument&)
		{
			rejected = true;
		}
		if (!rejected)
			throw RTE_LOC;

#if defined(ENABLE_SPARSE_DPF)
		std::array<WaterfallDmpf<block>, 2> dmpf;
		for (u64 party = 0; party < 2; ++party)
			dmpf[party].init(party, 16, 2, 1ull << 20, four);
		if (dmpf[0].mConfig.numColumns() != 64 ||
			dmpf[0].mDedup.size() != 2 ||
			dmpf[0].mSparseDpf.mNumPoints != 128)
			throw RTE_LOC;
		PRNG basePrng(block(0x7251, 0x441));
		setCorrelatedAsymmetricOts(dmpf, basePrng);
#endif
	}

	void Waterfall_validation_Test(const oc::CLP&)
	{
		auto expectInvalid = [](auto&& operation)
		{
			bool rejected = false;
			try
			{
				operation();
			}
			catch (const std::invalid_argument&)
			{
				rejected = true;
			}
			if (!rejected)
				throw RTE_LOC;
		};

		expectInvalid([] { WaterfallConfig{ {}, 0 }.validate(); });
		expectInvalid([] { WaterfallConfig{ { 8, 0 }, 0 }.validate(); });
		expectInvalid([] { WaterfallConfig{ { 8, 12 }, 0 }.validate(); });

#if defined(ENABLE_SPARSE_DPF)
		const WaterfallConfig config{ { 8, 8 }, 1 };
		expectInvalid([&] { WaterfallDmpf<u64>{}.init(2, 4, 1, 256, config); });
		expectInvalid([&] { WaterfallDmpf<u64>{}.init(0, 3, 1, 256, config); });
		expectInvalid([&] { WaterfallDmpf<u64>{}.init(0, 4, 1, 255, config); });
		expectInvalid([&] { WaterfallDmpf<u64>{}.init(0, 4, 1, 1ull << 33, config); });

		WaterfallDmpf<u64> dmpf;
		dmpf.init(0, 4, 1, 256, config);
		const auto firstOtCount = dmpf.baseOtCount();
		dmpf.mProposal.mCandidates.resize(4, 2);
		dmpf.mOverflow.resize(4);
		dmpf.mSetupComplete = true;
		dmpf.init(1, 8, 2, 512, WaterfallConfig{ { 16, 16 }, 2 });
		if (dmpf.mPartyIdx != 1 || dmpf.mNumPointsPerSet != 8 ||
			dmpf.mNumSets != 2 || dmpf.mDomain != 512 ||
			dmpf.mSetupComplete || dmpf.mProposal.mCandidates.size() != 0 ||
			dmpf.mOverflow.size() != 0)
			throw RTE_LOC;
		const auto secondOtCount = dmpf.baseOtCount();
		if (firstOtCount.mRecvCount == secondOtCount.mRecvCount &&
			firstOtCount.mSendCount == secondOtCount.mSendCount)
			throw RTE_LOC;
#endif
	}

	void Waterfall_emptySparseColumn_Test(const oc::CLP&)
	{
#if defined(ENABLE_SPARSE_DPF)
		constexpr u64 rowsPerSet = 4;
		constexpr u64 domain = 16;
		const WaterfallConfig config{ { 4 }, 0 };
		WaterfallDmpf<u64> dmpf;
		dmpf.init(0, rowsPerSet, 1, domain, config);

		WaterfallCandidates::Proposal proposal;
		proposal.mCoefficients.resize(1, rowsPerSet);
		std::fill(proposal.mCoefficients.begin(), proposal.mCoefficients.end(), 0);
		const auto representatives = dmpf.buildSparseSets(proposal);

		if (dmpf.mSparseSets.size() != config.numColumns() ||
			dmpf.mSparseSets[0].size() != domain ||
			representatives(0, 0) != 0)
			throw RTE_LOC;
		for (u64 point = 0; point < domain; ++point)
			if (dmpf.mSparseSets[0][point] != point)
				throw RTE_LOC;
		for (u64 column = 1; column < config.numColumns(); ++column)
			if (!dmpf.mSparseSets[column].empty() || representatives(0, column) != 0)
				throw RTE_LOC;

		std::array<SparseDpf, 2> sparseDpf;
		for (u64 party = 0; party < 2; ++party)
			sparseDpf[party].init(party, config.numColumns(), domain, log2ceil(domain));
		PRNG prng(block(0x656d7074792d7365ull, 0x742d6470662d7465ull));
		setCorrelatedOts(sparseDpf, prng);
		std::array<std::vector<u64>, 2> pointShares{
			std::vector<u64>(config.numColumns()),
			std::vector<u64>(config.numColumns())
		};
		for (u64 tree = 0; tree < config.numColumns(); ++tree)
		{
			pointShares[0][tree] = prng.get<u64>();
			pointShares[1][tree] = pointShares[0][tree];
		}
		std::array<std::vector<u64>, 2> callbacks{
			std::vector<u64>(config.numColumns()),
			std::vector<u64>(config.numColumns())
		};
		std::array<PRNG, 2> partyPrng{
			PRNG(prng.get<block>()),
			PRNG(prng.get<block>())
		};
		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto expansion = macoro::sync_wait(macoro::when_all_ready(
			sparseDpf[0].expand(
				pointShares[0],
				{},
				[&](u64 tree, u64, block, u8) { ++callbacks[0][tree]; },
				partyPrng[0],
				dmpf.mSparseSets,
				sockets[0]),
			sparseDpf[1].expand(
				pointShares[1],
				{},
				[&](u64 tree, u64, block, u8) { ++callbacks[1][tree]; },
				partyPrng[1],
				dmpf.mSparseSets,
				sockets[1])
		));
		std::get<0>(expansion).result();
		std::get<1>(expansion).result();
		for (u64 party = 0; party < 2; ++party)
		{
			if (callbacks[party][0] != domain)
				throw RTE_LOC;
			for (u64 column = 1; column < config.numColumns(); ++column)
				if (callbacks[party][column] != 0)
					throw RTE_LOC;
		}
#endif
	}

	void Waterfall_placement_Test(const oc::CLP&)
	{
		{
			const WaterfallConfig config{ { 4, 4 }, 0 };
			const std::array<u32, 6> candidates{
				1, 2,
				1, 3,
				2, 3
			};
			auto result = WaterfallPlacement::generate(config, 3, candidates);
			if (!result.mSuccess || result.mRepairs != 0)
				throw RTE_LOC;
			if (result.mPartitionByRow != std::vector<u32>{ 0, 1, 0 })
				throw RTE_LOC;
		}

		// The final row initially overflows. Moving row 2 from partition 0
		// to its free partition-1 bin creates an augmenting path.
		const std::array<u32, 8> repairCandidates{
			0, 0,
			0, 1,
			1, 0,
			1, 1
		};
		{
			auto result = WaterfallPlacement::generate(
				WaterfallConfig{ { 2, 2 }, 0 }, 4, repairCandidates);
			if (result.mSuccess)
				throw RTE_LOC;
		}
		{
			auto result = WaterfallPlacement::generate(
				WaterfallConfig{ { 2, 2 }, 1 }, 4, repairCandidates);
			if (!result.mSuccess || result.mRepairs != 1)
				throw RTE_LOC;

			std::array<u8, 4> occupied{};
			for (auto column : result.mColumnByRow)
			{
				if (column >= occupied.size() || occupied[column])
					throw RTE_LOC;
				occupied[column] = 1;
			}
		}

		{
			const std::array<u32, 6> impossible{
				0, 0,
				0, 0,
				0, 0
			};
			auto result = WaterfallPlacement::generate(
				WaterfallConfig{ { 2, 2 }, 3 }, 3, impossible);
			if (result.mSuccess)
				throw RTE_LOC;
		}
	}

	void Waterfall_hash_Test(const oc::CLP&)
	{
		WaterfallHash countCheck;
		countCheck.init(0, 1, 16, 20);
		if (countCheck.karatsubaProductCount() != 81 || countCheck.baseOtCount() != 7 * 81)
			throw RTE_LOC;

		constexpr u64 numSets = 2;
		constexpr u64 rowsPerSet = 4;
		constexpr u64 numRows = numSets * rowsPerSet;
		constexpr u64 degree = rowsPerSet;
		constexpr u64 fieldBits = 5;
		const std::array<u64, 3> partitionSizes{ 8, 4, 8 };
		PRNG prng(block(0x57a7e2, 0x18c0));

		std::array<WaterfallHash, 2> hash;
		for (u64 party = 0; party < 2; ++party)
			hash[party].init(party, numRows, degree, fieldBits);
		setCorrelatedOts(hash, prng);

		const std::array<u32, numRows> input{ 1, 2, 3, 4, 5, 6, 7, 8 };
		std::array<Matrix<u8>, 2> inputShares{ Matrix<u8>(numRows, 1), Matrix<u8>(numRows, 1) };
		for (u64 row = 0; row < numRows; ++row)
		{
			inputShares[0](row, 0) = prng.get<u8>() & 31;
			inputShares[1](row, 0) = inputShares[0](row, 0) ^ static_cast<u8>(input[row]);
		}

		Matrix<u32> coefficients(numSets * partitionSizes.size(), degree);
		for (auto& coefficient : coefficients)
			coefficient = prng.get<u32>() & 31;

		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto prepared = macoro::sync_wait(macoro::when_all_ready(
			hash[0].prepare(inputShares[0], sockets[0]),
			hash[1].prepare(inputShares[1], sockets[1])));
		auto powers0 = std::get<0>(prepared).result();
		auto powers1 = std::get<1>(prepared).result();

		std::array<Matrix<u32>, 2> output{ Matrix<u32>(numRows, partitionSizes.size()), Matrix<u32>(numRows, partitionSizes.size()) };
		hash[0].evaluate(powers0, coefficients, numSets, partitionSizes, output[0]);
		hash[1].evaluate(powers1, coefficients, numSets, partitionSizes, output[1]);

		auto plainPowers = hash[0].preparePlain(input);
		Matrix<u32> expected(numRows, partitionSizes.size());
		hash[0].evaluate(plainPowers, coefficients, numSets, partitionSizes, expected);
		for (u64 i = 0; i < expected.size(); ++i)
			if ((output[0](i) ^ output[1](i)) != expected(i))
				throw RTE_LOC;

		{
			constexpr u64 towerRows = 2;
			constexpr u64 towerDegree = 4;
			constexpr std::array<u64, 2> towerPartitions{ 256, 1024 };
			const std::array<u32, towerRows> towerInput{ 0x12345, 0xabcde };
			std::array<WaterfallHash, 2> tower;
			for (u64 party = 0; party < 2; ++party)
				tower[party].init(party, towerRows, towerDegree, 20);
			setCorrelatedOts(tower, prng);

			std::array<Matrix<u8>, 2> towerShares{
				Matrix<u8>(towerRows, 3),
				Matrix<u8>(towerRows, 3)
			};
			for (u64 row = 0; row < towerRows; ++row)
			{
				u32 share = prng.get<u32>() & ((1u << 20) - 1);
				copyBytesMin(towerShares[0][row], share);
				share ^= towerInput[row];
				copyBytesMin(towerShares[1][row], share);
			}
			Matrix<u32> towerCoefficients(towerPartitions.size(), towerDegree);
			for (auto& coefficient : towerCoefficients)
				coefficient = prng.get<u32>() & ((1u << 20) - 1);
			auto towerSockets = coproto::LocalAsyncSocket::makePair();
			auto towerPrepared = macoro::sync_wait(macoro::when_all_ready(
				tower[0].prepare(towerShares[0], towerSockets[0]),
				tower[1].prepare(towerShares[1], towerSockets[1])));
			auto towerPowers0 = std::get<0>(towerPrepared).result();
			auto towerPowers1 = std::get<1>(towerPrepared).result();
			std::array<Matrix<u32>, 2> towerOutput{
				Matrix<u32>(towerRows, towerPartitions.size()),
				Matrix<u32>(towerRows, towerPartitions.size())
			};
			tower[0].evaluate(
				towerPowers0, towerCoefficients, 1, towerPartitions, towerOutput[0]);
			tower[1].evaluate(
				towerPowers1, towerCoefficients, 1, towerPartitions, towerOutput[1]);
			auto towerPlainPowers = tower[0].preparePlain(towerInput);
			Matrix<u32> towerExpected(towerRows, towerPartitions.size());
			tower[0].evaluate(
				towerPlainPowers, towerCoefficients, 1, towerPartitions, towerExpected);
			for (u64 i = 0; i < towerExpected.size(); ++i)
				if ((towerOutput[0](i) ^ towerOutput[1](i)) != towerExpected(i))
					throw std::runtime_error("GF(2^20) tower multiplication mismatch. " LOCATION);

			WaterfallHash batchHash;
			batchHash.init(0, 1, 16, 20);
			std::array<u32, 16> batchCoefficients0{};
			std::array<u32, 16> batchCoefficients1{};
			for (auto& coefficient : batchCoefficients0)
				coefficient = prng.get<u32>() & ((1u << 20) - 1);
			for (auto& coefficient : batchCoefficients1)
				coefficient = prng.get<u32>() & ((1u << 20) - 1);
			std::vector<u32> batchOutput0(1031);
			std::vector<u32> batchOutput1(1031);
			batchHash.evaluateConsecutivePair(
				batchCoefficients0,
				batchCoefficients1,
				16,
				128,
				batchOutput0,
				batchOutput1);
			for (u64 point = 0; point < batchOutput0.size(); ++point)
			{
				if (batchOutput0[point] != batchHash.evaluatePlain(
					batchCoefficients0, static_cast<u32>(point), 16))
					throw std::runtime_error("Batched first polynomial mismatch. " LOCATION);
				if (batchOutput1[point] != batchHash.evaluatePlain(
					batchCoefficients1, static_cast<u32>(point), 128))
					throw std::runtime_error("Batched second polynomial mismatch. " LOCATION);
			}

			std::vector<u32> batchInput(batchOutput0.size());
			for (u64 point = 0; point < batchInput.size(); ++point)
				batchInput[point] = static_cast<u32>(point * 7919 + 0x34567) & ((1u << 20) - 1);
			batchHash.evaluatePointPair(
				batchCoefficients0,
				batchCoefficients1,
				16,
				128,
				batchInput,
				batchOutput0,
				batchOutput1);
			for (u64 point = 0; point < batchInput.size(); ++point)
			{
				if (batchOutput0[point] != batchHash.evaluatePlain(
					batchCoefficients0, batchInput[point], 16))
					throw std::runtime_error("Batched arbitrary first polynomial mismatch. " LOCATION);
				if (batchOutput1[point] != batchHash.evaluatePlain(
					batchCoefficients1, batchInput[point], 128))
					throw std::runtime_error("Batched arbitrary second polynomial mismatch. " LOCATION);
			}
		}
	}

	void Waterfall_candidates_Test(const oc::CLP&)
	{
		constexpr u64 domain = 32;
		constexpr u64 indexBits = 6;
		constexpr u64 rowsPerSet = 4;
		constexpr u64 numSets = 2;
		constexpr u64 numRows = rowsPerSet * numSets;
		const WaterfallConfig config{ { 4, 8, 4 }, 0 };
		const std::array<u32, numRows> addresses{ 1, 2, 32, 4, 5, 32, 7, 8 };

		std::array<WaterfallCandidates, 2> generator;
		for (u64 party = 0; party < 2; ++party)
			generator[party].init(party, rowsPerSet, numSets, domain, indexBits, config);
		PRNG otPrng(block(0xc47a, 0x51d));
		setCorrelatedAsymmetricOts(generator, otPrng);

		std::array<Matrix<u8>, 2> shares{ Matrix<u8>(numRows, 1), Matrix<u8>(numRows, 1) };
		for (u64 row = 0; row < numRows; ++row)
		{
			shares[0](row, 0) = otPrng.get<u8>() & 63;
			shares[1](row, 0) = shares[0](row, 0) ^ static_cast<u8>(addresses[row]);
		}

		std::array<PRNG, 2> prng{ PRNG(block(0x111, 0x222)), PRNG(block(0x333, 0x444)) };
		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto prepared = macoro::sync_wait(macoro::when_all_ready(
			generator[0].prepare(shares[0], prng[0], sockets[0]),
			generator[1].prepare(shares[1], prng[1], sockets[1])));
		auto state0 = std::get<0>(prepared).result();
		auto state1 = std::get<1>(prepared).result();
		for (u64 row = 0; row < numRows; ++row)
		{
			const bool activity = state0.mActivity[row] ^ state1.mActivity[row];
			if (activity != (addresses[row] != domain))
				throw RTE_LOC;
		}

		auto verifyProposal = [&](auto& proposal0, auto& proposal1)
		{
			if (proposal0.mPublicSeed != proposal1.mPublicSeed ||
				proposal0.mCoefficients != proposal1.mCoefficients)
				throw RTE_LOC;
			auto plainPowers = generator[0].mHash.preparePlain(addresses);
			Matrix<u32> expected(numRows, config.numPartitions());
			generator[0].mHash.evaluate(
				plainPowers,
				proposal0.mCoefficients,
				numSets,
				config.mPartitionSizes,
				expected);
			for (u64 row = 0; row < numRows; ++row)
			{
				for (u64 partition = 0; partition < config.numPartitions(); ++partition)
				{
					const auto candidate = proposal0.mCandidates(row, partition) ^ proposal1.mCandidates(row, partition);
					if (candidate >= config.mPartitionSizes[partition])
						throw RTE_LOC;
					if (addresses[row] != domain && candidate != expected(row, partition))
						throw RTE_LOC;
				}
			}
		};

		auto sampled = macoro::sync_wait(macoro::when_all_ready(
			generator[0].sample(state0, prng[0], sockets[0]),
			generator[1].sample(state1, prng[1], sockets[1])));
		auto proposal0 = std::get<0>(sampled).result();
		auto proposal1 = std::get<1>(sampled).result();
		verifyProposal(proposal0, proposal1);
		auto masked = macoro::sync_wait(macoro::when_all_ready(
			generator[0].maskActive(state0, shares[0], sockets[0]),
			generator[1].maskActive(state1, shares[1], sockets[1])
		));
		auto masked0 = std::get<0>(masked).result();
		auto masked1 = std::get<1>(masked).result();
		for (u64 row = 0; row < numRows; ++row)
			if ((masked0(row, 0) ^ masked1(row, 0)) !=
				(addresses[row] == domain ? 0 : addresses[row]))
				throw RTE_LOC;

		auto resampled = macoro::sync_wait(macoro::when_all_ready(
			generator[0].sample(state0, prng[0], sockets[0]),
			generator[1].sample(state1, prng[1], sockets[1])));
		auto proposal2 = std::get<0>(resampled).result();
		auto proposal3 = std::get<1>(resampled).result();
		verifyProposal(proposal2, proposal3);
		if (proposal0.mPublicSeed == proposal2.mPublicSeed)
			throw RTE_LOC;
	}

	void Waterfall_basicMpc_Test(const oc::CLP&)
	{
		const WaterfallConfig config{ { 4, 8 }, 0 };
		constexpr u64 rowsPerSet = 4;
		constexpr u64 numSets = 2;
		constexpr u64 numRows = rowsPerSet * numSets;
		constexpr u64 w = 2;
		const std::array<u32, numRows * w> candidates{
			0, 0,
			0, 1,
			1, 0,
			1, 1,
			0, 0,
			1, 0,
			0, 1,
			1, 1
		};

		PRNG prng(block(0x57a7e2, 0xb451c));
		std::array<WaterfallBasic, 2> basic;
		for (u64 party = 0; party < 2; ++party)
			basic[party].init(party, rowsPerSet, numSets, config);
		if (basic[0].baseOtCount() != 96)
			throw RTE_LOC;
		setCorrelatedOts(basic, prng);

		std::array<Matrix<u32>, 2> shares{ Matrix<u32>(numRows, w), Matrix<u32>(numRows, w) };
		for (u64 i = 0; i < candidates.size(); ++i)
		{
			const auto partition = i % w;
			shares[0](i) = prng.get<u32>() & static_cast<u32>(config.mPartitionSizes[partition] - 1);
			shares[1](i) = shares[0](i) ^ candidates[i];
		}

		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto placed = macoro::sync_wait(macoro::when_all_ready(
			basic[0].place(shares[0], sockets[0]),
			basic[1].place(shares[1], sockets[1])));
		auto result0 = std::get<0>(placed).result();
		auto result1 = std::get<1>(placed).result();

		for (u64 set = 0; set < numSets; ++set)
		{
			auto expected = WaterfallPlacement::generate(
				config,
				rowsPerSet,
				span<const u32>(candidates).subspan(set * rowsPerSet * w, rowsPerSet * w));
			for (u64 row = 0; row < rowsPerSet; ++row)
			{
				const auto globalRow = set * rowsPerSet + row;
				for (u64 partition = 0; partition < w; ++partition)
				{
					const bool actual = result0.mMatching[globalRow * w + partition] ^ result1.mMatching[globalRow * w + partition];
					const bool wanted = expected.mPartitionByRow[row] == partition;
					if (actual != wanted)
						throw RTE_LOC;
					if (result0.mDecoder[partition][globalRow].size() !=
						config.mPartitionSizes[partition])
						throw RTE_LOC;
					for (u64 bin = 0; bin < config.mPartitionSizes[partition]; ++bin)
					{
						const bool decoded = result0.mDecoder[partition][globalRow][bin] ^
							result1.mDecoder[partition][globalRow][bin];
						if (decoded != (bin == candidates[globalRow * w + partition]))
							throw RTE_LOC;
					}
				}
				const auto overflow = result0.mOverflow[globalRow] ^ result1.mOverflow[globalRow];
				if (overflow != (expected.mPartitionByRow[row] == WaterfallPlacement::NoIndex))
					throw RTE_LOC;
			}
		}
	}

	namespace
	{
		u64 maximumMatchingSize(
			const WaterfallConfig& config,
			u64 rows,
			span<const u32> candidates)
		{
			const auto w = config.numPartitions();
			std::vector<u64> offset(w);
			u64 columns = 0;
			for (u64 partition = 0; partition < w; ++partition)
			{
				offset[partition] = columns;
				columns += config.mPartitionSizes[partition];
			}
			std::vector<u64> owner(columns, rows);
			u64 matched = 0;
			for (u64 root = 0; root < rows; ++root)
			{
				std::vector<u8> seen(columns);
				struct Search
				{
					const WaterfallConfig& config;
					span<const u32> candidates;
					span<const u64> offset;
					span<u64> owner;
					span<u8> seen;
					u64 rows;

					bool run(u64 row)
					{
						for (u64 partition = 0; partition < config.numPartitions(); ++partition)
						{
							const auto column = offset[partition] +
								candidates[row * config.numPartitions() + partition];
							if (seen[column])
								continue;
							seen[column] = 1;
							if (owner[column] == rows || run(owner[column]))
							{
								owner[column] = row;
								return true;
							}
						}
						return false;
					}
				} search{ config, candidates, offset, owner, seen, rows };
				matched += search.run(root);
			}
			return matched;
		}

		void runReachabilityCase(
			const WaterfallConfig& config,
			u64 rowsPerSet,
			u64 numSets,
			span<const u32> candidates,
			PRNG& prng)
		{
			const auto w = config.numPartitions();
			const auto numRows = rowsPerSet * numSets;
			std::array<WaterfallBasic, 2> basic;
			std::array<WaterfallReachability, 2> repair;
			for (u64 party = 0; party < 2; ++party)
			{
				basic[party].init(party, rowsPerSet, numSets, config);
				repair[party].init(party, rowsPerSet, numSets, config);
			}
			setCorrelatedOts(basic, prng);
			setCorrelatedOts(repair, prng);

			std::array<Matrix<u32>, 2> shares{
				Matrix<u32>(numRows, w),
				Matrix<u32>(numRows, w)
			};
			for (u64 row = 0; row < numRows; ++row)
				for (u64 partition = 0; partition < w; ++partition)
				{
					const auto i = row * w + partition;
					shares[0](i) = prng.get<u32>() &
						static_cast<u32>(config.mPartitionSizes[partition] - 1);
					shares[1](i) = shares[0](i) ^ candidates[i];
				}

			auto sockets = coproto::LocalAsyncSocket::makePair();
			auto basicResult = macoro::sync_wait(macoro::when_all_ready(
				basic[0].place(shares[0], sockets[0]),
				basic[1].place(shares[1], sockets[1])));
			auto basic0 = std::get<0>(basicResult).result();
			auto basic1 = std::get<1>(basicResult).result();
			auto repaired = macoro::sync_wait(macoro::when_all_ready(
				repair[0].repair(shares[0], basic0.mMatching, basic0.mDecoder, sockets[0]),
				repair[1].repair(shares[1], basic1.mMatching, basic1.mDecoder, sockets[1])));
			auto result0 = std::get<0>(repaired).result();
			auto result1 = std::get<1>(repaired).result();

			for (u64 set = 0; set < numSets; ++set)
			{
				std::vector<u8> occupied(config.numColumns());
				u64 basicSize = 0;
				u64 repairedSize = 0;
				u64 offset = 0;
				std::vector<u64> partitionOffset(w);
				for (u64 partition = 0; partition < w; ++partition)
				{
					partitionOffset[partition] = offset;
					offset += config.mPartitionSizes[partition];
				}
				for (u64 row = 0; row < rowsPerSet; ++row)
				{
					const auto globalRow = set * rowsPerSet + row;
					u64 rowWeight = 0;
					u64 placementWeight = 0;
					u64 expectedColumn = config.numColumns();
					for (u64 partition = 0; partition < w; ++partition)
					{
						basicSize += basic0.mMatching[globalRow * w + partition] ^
							basic1.mMatching[globalRow * w + partition];
						const bool selected = result0.mMatching[globalRow * w + partition] ^
							result1.mMatching[globalRow * w + partition];
						if (selected)
						{
							const auto column = partitionOffset[partition] +
								candidates[globalRow * w + partition];
							if (occupied[column])
								throw RTE_LOC;
							occupied[column] = 1;
							expectedColumn = column;
							++rowWeight;
							++repairedSize;
						}
					}
					for (u64 column = 0; column < config.numColumns(); ++column)
					{
						const bool placed = result0.mPlacement[globalRow * config.numColumns() + column] ^
							result1.mPlacement[globalRow * config.numColumns() + column];
						placementWeight += placed;
						if (placed != (column == expectedColumn))
							throw RTE_LOC;
					}
					if (rowWeight > 1)
						throw RTE_LOC;
					if (placementWeight != rowWeight)
						throw RTE_LOC;
					const bool overflow = result0.mOverflow[globalRow] ^ result1.mOverflow[globalRow];
					if (overflow != (rowWeight == 0))
						throw RTE_LOC;
				}

				const auto setCandidates = candidates.subspan(set * rowsPerSet * w, rowsPerSet * w);
				const auto maximum = maximumMatchingSize(config, rowsPerSet, setCandidates);
				const auto expected = std::min(maximum, basicSize + config.mRepairLimit);
				if (repairedSize != expected)
					throw RTE_LOC;
			}
		}
	}

	void Waterfall_reachabilityMpc_Test(const oc::CLP&)
	{
		PRNG prng(block(0x771ac, 0x5e4));
		const std::array<u32, 8> repairCandidates{
			0, 0,
			0, 1,
			1, 0,
			1, 1
		};
		runReachabilityCase(
			WaterfallConfig{ { 2, 2 }, 1 },
			4,
			1,
			repairCandidates,
			prng);

		{
			const WaterfallConfig config{ { 2, 2 }, 2 };
			constexpr u64 rowsPerSet = 4;
			constexpr u64 numSets = 16;
			std::vector<u32> candidates(rowsPerSet * numSets * config.numPartitions());
			for (auto& candidate : candidates)
				candidate = prng.get<u32>() & 1;
			runReachabilityCase(config, rowsPerSet, numSets, candidates, prng);
		}

		for (const auto& config : {
			WaterfallConfig::compact4N(),
			WaterfallConfig::compact3N() })
		{
			constexpr u64 rowsPerSet = 16;
			constexpr u64 numSets = 2;
			std::vector<u32> candidates(rowsPerSet * numSets * config.numPartitions());
			for (u64 row = rowsPerSet; row < rowsPerSet * numSets; ++row)
				for (u64 partition = 0; partition < config.numPartitions(); ++partition)
					candidates[row * config.numPartitions() + partition] = prng.get<u32>() &
						static_cast<u32>(config.mPartitionSizes[partition] - 1);

			// A layered collision chain leaves the final special row unmatched,
			// although moving row zero to its free second candidate repairs it.
			const auto w = config.numPartitions();
			for (u64 row = 0; row <= w; ++row)
				for (u64 partition = 0; partition < w; ++partition)
					candidates[row * w + partition] =
						partition < row ? 0 : static_cast<u32>(partition == row ? 0 : 10 + row);
			for (u64 row = w + 1; row < rowsPerSet; ++row)
			{
				candidates[row * w] = static_cast<u32>(row - w);
				for (u64 partition = 1; partition < w; ++partition)
					candidates[row * w + partition] = static_cast<u32>(10 + row);
			}
			runReachabilityCase(config, rowsPerSet, numSets, candidates, prng);
		}
	}

	void Waterfall_scatterMpc_Test(const oc::CLP&)
	{
		constexpr u64 rowsPerSet = 4;
		constexpr u64 numSets = 2;
		constexpr u64 columns = 9;
		constexpr u64 numRows = rowsPerSet * numSets;
		const std::array<u32, numRows> addresses{ 3, 11, 32, 7, 9, 32, 18, 2 };
		const std::array<u32, numRows> placementColumn{ 3, 0, 7, 4, 8, 2, 5, 1 };

		PRNG prng(block(0x5ca77e2, 0x194));
		std::vector<u64> permutationSizes(65);
		std::iota(permutationSizes.begin(), permutationSizes.end(), 1);
		permutationSizes.push_back(320);
		for (const u64 size : permutationSizes)
		{
			std::array<SerialWaksmanPermute, 2> permutation;
			for (u64 party = 0; party < 2; ++party)
				permutation[party].init(party, size, numSets);
			setCorrelatedAsymmetricOts(permutation, prng);
			std::array<PRNG, 2> permutationPrng{
				PRNG(prng.get<block>()),
				PRNG(prng.get<block>())
			};
			for (u64 party = 0; party < 2; ++party)
				permutation[party].sample(permutationPrng[party]);

			std::vector<Matrix<u8>> plain(numSets, Matrix<u8>(size, 2));
			std::array<std::vector<Matrix<u8>>, 2> shares;
			for (u64 party = 0; party < 2; ++party)
				shares[party].assign(numSets, Matrix<u8>(size, 2));
			for (u64 set = 0; set < numSets; ++set)
				for (u64 input = 0; input < size; ++input)
					for (u64 byte = 0; byte < 2; ++byte)
					{
						plain[set](input, byte) = static_cast<u8>((19 * set + input) >> (8 * byte));
						shares[0][set](input, byte) = prng.get<u8>();
						shares[1][set](input, byte) =
							shares[0][set](input, byte) ^ plain[set](input, byte);
					}

			auto context = DpfMult::BitMatrixCoeffCtx(16);
			using View = DpfMult::BitMatrixCoeffCtx::View<u8>;
			std::array<std::vector<View>, 2> views;
			for (u64 party = 0; party < 2; ++party)
				for (auto& set : shares[party])
					views[party].emplace_back(set);
			auto sockets = coproto::LocalAsyncSocket::makePair();
			auto forward = macoro::sync_wait(macoro::when_all_ready(
				permutation[0].applyMany<u8, View>(views[0], sockets[0], context),
				permutation[1].applyMany<u8, View>(views[1], sockets[1], context)
			));
			std::get<0>(forward).result();
			std::get<1>(forward).result();

			for (u64 set = 0; set < numSets; ++set)
			{
				const auto& first = permutation[0].privatePermutation(set);
				const auto& second = permutation[1].privatePermutation(set);
				for (u64 input = 0; input < size; ++input)
				{
					const auto output = second[first[input]];
					for (u64 byte = 0; byte < 2; ++byte)
						if ((shares[0][set](output, byte) ^ shares[1][set](output, byte)) !=
							plain[set](input, byte))
							throw std::runtime_error(
								"Serial Waksman mismatch at size " + std::to_string(size) +
								", batch " + std::to_string(set) +
								", input " + std::to_string(input) + ". " LOCATION);
				}
			}

			auto inverse = macoro::sync_wait(macoro::when_all_ready(
				permutation[0].applyManyInverse<u8, View>(views[0], sockets[0], context),
				permutation[1].applyManyInverse<u8, View>(views[1], sockets[1], context)
			));
			std::get<0>(inverse).result();
			std::get<1>(inverse).result();
			for (u64 set = 0; set < numSets; ++set)
				for (u64 input = 0; input < size; ++input)
					for (u64 byte = 0; byte < 2; ++byte)
						if ((shares[0][set](input, byte) ^ shares[1][set](input, byte)) !=
							plain[set](input, byte))
							throw RTE_LOC;
		}
		{
			std::array<WaksmanPermute, 2> permutation;
			for (u64 party = 0; party < 2; ++party)
				permutation[party].init(party, columns, numSets);
			setCorrelatedAsymmetricOts(permutation, prng);
			std::vector<Matrix<u8>> plain(numSets, Matrix<u8>(columns, 1));
			std::array<std::vector<Matrix<u8>>, 2> shares;
			for (u64 party = 0; party < 2; ++party)
				shares[party].assign(numSets, Matrix<u8>(columns, 1));
			for (u64 set = 0; set < numSets; ++set)
				for (u64 i = 0; i < plain[set].size(); ++i)
				{
					plain[set](i) = prng.get<u8>();
					shares[0][set](i) = prng.get<u8>();
					shares[1][set](i) = shares[0][set](i) ^ plain[set](i);
				}
			auto context = DpfMult::BitMatrixCoeffCtx(4);
			using View = DpfMult::BitMatrixCoeffCtx::View<u8>;
			std::array<std::vector<View>, 2> views;
			for (u64 party = 0; party < 2; ++party)
				for (auto& set : shares[party])
					views[party].emplace_back(set);
			auto sockets = coproto::LocalAsyncSocket::makePair();
			auto forward = macoro::sync_wait(macoro::when_all_ready(
				permutation[0].applyMany<u8, View>(views[0], sockets[0], context),
				permutation[1].applyMany<u8, View>(views[1], sockets[1], context)
			));
			std::get<0>(forward).result();
			std::get<1>(forward).result();
			std::array<std::vector<Matrix<u8>>, 2> wideShares;
			std::array<std::vector<View>, 2> wideViews;
			for (u64 party = 0; party < 2; ++party)
				wideShares[party].assign(numSets, Matrix<u8>(columns, 2));
			for (u64 set = 0; set < numSets; ++set)
				for (u64 row = 0; row < columns; ++row)
				{
					const auto value = shares[0][set](row, 0) ^ shares[1][set](row, 0);
					wideShares[0][set](row, 0) = prng.get<u8>();
					wideShares[1][set](row, 0) = wideShares[0][set](row, 0) ^ value;
					wideShares[0][set](row, 1) = prng.get<u8>();
					wideShares[1][set](row, 1) = wideShares[0][set](row, 1);
				}
			for (u64 party = 0; party < 2; ++party)
				for (auto& set : wideShares[party])
					wideViews[party].emplace_back(set);
			auto wideContext = DpfMult::BitMatrixCoeffCtx(16);
			auto inverse = macoro::sync_wait(macoro::when_all_ready(
				permutation[0].applyManyInverse<u8, View>(wideViews[0], sockets[0], wideContext),
				permutation[1].applyManyInverse<u8, View>(wideViews[1], sockets[1], wideContext)
			));
			std::get<0>(inverse).result();
			std::get<1>(inverse).result();
			for (u64 set = 0; set < numSets; ++set)
				for (u64 row = 0; row < columns; ++row)
					if ((wideShares[0][set](row, 0) ^ wideShares[1][set](row, 0)) != plain[set](row, 0))
						throw RTE_LOC;
		}
		std::array<WaterfallScatter, 2> scatter;
		for (u64 party = 0; party < 2; ++party)
			scatter[party].init(party, rowsPerSet, numSets, columns);
		setCorrelatedAsymmetricOts(scatter, prng);

		std::array<BitVector, 2> activity{ BitVector(numRows), BitVector(numRows) };
		std::array<BitVector, 2> placement{
			BitVector(numRows * columns),
			BitVector(numRows * columns)
		};
		std::array<Matrix<u8>, 2> masked{
			Matrix<u8>(numRows, 1),
			Matrix<u8>(numRows, 1)
		};
		for (u64 row = 0; row < numRows; ++row)
		{
			const bool active = addresses[row] != 32;
			activity[0][row] = prng.getBit();
			activity[1][row] = activity[0][row] ^ static_cast<u8>(active);
			masked[0](row, 0) = prng.get<u8>();
			masked[1](row, 0) = masked[0](row, 0) ^
				static_cast<u8>(active ? addresses[row] : 0);
			for (u64 column = 0; column < columns; ++column)
			{
				const auto index = row * columns + column;
				placement[0][index] = prng.getBit();
				placement[1][index] = placement[0][index] ^
					(column == placementColumn[row]);
			}
		}

		Matrix<u32> representatives(numSets, columns);
		for (u64 set = 0; set < numSets; ++set)
			for (u64 column = 0; column < columns; ++column)
				representatives(set, column) = static_cast<u32>((7 * set + 3 * column) % 32);

		std::array<PRNG, 2> permutationPrng{
			PRNG(prng.get<block>()),
			PRNG(prng.get<block>())
		};
		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto scattered = macoro::sync_wait(macoro::when_all_ready(
			scatter[0].scatterAddresses(masked[0], activity[0], placement[0], representatives, permutationPrng[0], sockets[0]),
			scatter[1].scatterAddresses(masked[1], activity[1], placement[1], representatives, permutationPrng[1], sockets[1])
		));
		auto result0 = std::get<0>(scattered).result();
		auto result1 = std::get<1>(scattered).result();
		for (u64 row = 0; row < numRows; ++row)
			if ((result0.mDestinations[row] ^ result1.mDestinations[row]) !=
				placementColumn[row])
				throw RTE_LOC;
		for (u64 set = 0; set < numSets; ++set)
			for (u64 column = 0; column < columns; ++column)
			{
				bool expectedActivity = false;
				u32 expectedAddress = representatives(set, column);
				for (u64 row = 0; row < rowsPerSet; ++row)
				{
					const auto globalRow = set * rowsPerSet + row;
					if (placementColumn[globalRow] == column && addresses[globalRow] != 32)
					{
						expectedActivity = true;
						expectedAddress = addresses[globalRow];
					}
				}
				const auto output = set * columns + column;
				if (static_cast<bool>(result0.mActivity[output] ^ result1.mActivity[output]) != expectedActivity)
					throw RTE_LOC;
				if ((result0.mAddresses(output, 0) ^ result1.mAddresses(output, 0)) != expectedAddress)
					throw RTE_LOC;
			}
	}

	template<typename F, typename Context>
	void Waterfall_dmpfEndToEnd_Impl(PRNG& prng)
	{
		constexpr u64 rowsPerSet = 4;
		constexpr u64 numSets = 2;
		constexpr u64 domain = 256;
		const WaterfallConfig config{ { 8, 8 }, 2 };
		const std::array<std::array<u64, rowsPerSet>, numSets> clearPoints{
			std::array<u64, rowsPerSet>{ 3, 7, 3, 19 },
			std::array<u64, rowsPerSet>{ 5, 5, 31, 12 }
		};

		Matrix<u64> pointShare[2]{
			Matrix<u64>(numSets, rowsPerSet),
			Matrix<u64>(numSets, rowsPerSet)
		};
		for (u64 set = 0; set < numSets; ++set)
			for (u64 row = 0; row < rowsPerSet; ++row)
			{
				pointShare[0](set, row) = prng.get<u64>() & 0x1ff;
				pointShare[1](set, row) = pointShare[0](set, row) ^ clearPoints[set][row];
			}

		Context context;
		std::array<WaterfallDmpf<F, Context>, 2> dmpf;
		for (u64 party = 0; party < 2; ++party)
			dmpf[party].init(
				party,
				rowsPerSet,
				numSets,
				domain,
				config,
				context.template characteristicTwo<F>());
		setCorrelatedAsymmetricOts(dmpf, prng);

		std::array<PRNG, 2> partyPrng{
			PRNG(prng.get<block>()),
			PRNG(prng.get<block>())
		};
		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto setup = macoro::sync_wait(macoro::when_all_ready(
			dmpf[0].setPoints(pointShare[0], partyPrng[0], sockets[0]),
			dmpf[1].setPoints(pointShare[1], partyPrng[1], sockets[1])
		));
		std::get<0>(setup).result();
		std::get<1>(setup).result();

		if (!dmpf[0].mSetupComplete || !dmpf[1].mSetupComplete ||
			dmpf[0].mProposal.mPublicSeed != dmpf[1].mProposal.mPublicSeed ||
			dmpf[0].mProposal.mCoefficients != dmpf[1].mProposal.mCoefficients)
			throw RTE_LOC;
		for (u64 row = 0; row < numSets * rowsPerSet; ++row)
			if (dmpf[0].mOverflow[row] ^ dmpf[1].mOverflow[row])
				throw std::runtime_error("Waterfall end-to-end fixture unexpectedly overflowed. " LOCATION);

		auto runExpansion = [&]
		{
			using ValueVector = typename Context::template Vec<F>;
			std::array<ValueVector, 2> valueShare{
				context.template makeVec<F>(numSets * rowsPerSet),
				context.template makeVec<F>(numSets * rowsPerSet)
			};
			for (u64 i = 0; i < valueShare[0].size(); ++i)
			{
				context.fromBlock(valueShare[0][i], prng.get<block>());
				context.fromBlock(valueShare[1][i], prng.get<block>());
			}

			std::array<Matrix<F>, 2> output{
				Matrix<F>(numSets, domain),
				Matrix<F>(numSets, domain)
			};
			auto expansion = macoro::sync_wait(macoro::when_all_ready(
				dmpf[0].expand(
					valueShare[0],
					partyPrng[0],
					sockets[0],
					[&](u64 set, u64 point, const F& value) { output[0](set, point) = value; },
					context),
				dmpf[1].expand(
					valueShare[1],
					partyPrng[1],
					sockets[1],
					[&](u64 set, u64 point, const F& value) { output[1](set, point) = value; },
					context)
			));
			std::get<0>(expansion).result();
			std::get<1>(expansion).result();

			for (u64 set = 0; set < numSets; ++set)
			{
				std::unordered_map<u64, F> expected;
				for (u64 row = 0; row < rowsPerSet; ++row)
				{
					F value;
					context.plus(
						value,
						valueShare[0][set * rowsPerSet + row],
						valueShare[1][set * rowsPerSet + row]);
					context.plus(
						expected[clearPoints[set][row]],
						expected[clearPoints[set][row]],
						value);
				}
				for (u64 point = 0; point < domain; ++point)
				{
					F actual;
					F zero;
					context.plus(actual, output[0](set, point), output[1](set, point));
					context.zero(zero);
					const auto found = expected.find(point);
					const auto& expectedValue = found == expected.end() ? zero : found->second;
					if (!context.eq(actual, expectedValue))
						throw std::runtime_error(
							"Waterfall end-to-end output mismatch at set " + std::to_string(set) +
							", point " + std::to_string(point) + ". " LOCATION);
				}
			}
		};
		runExpansion();
		runExpansion();
	}

	void Waterfall_dmpfEndToEnd_Test(const oc::CLP&)
	{
		PRNG prng(block(0x574654455354ull, 0x20260807ull));
		Waterfall_dmpfEndToEnd_Impl<block, CoeffCtxGF128>(prng);
		Waterfall_dmpfEndToEnd_Impl<u64, CoeffCtxInteger>(prng);
		Waterfall_dmpfEndToEnd_Impl<
			std::array<u64, 4>,
			CoeffCtxArray<u64, 4>>(prng);
	}
}
