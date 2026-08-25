#include "Gmw_Tests.h"

#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/TestCollection.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Tools/Gmw/Gmw.h"
#include <sstream>
#include <type_traits>

namespace osuCrypto
{
	void Gmw_Audit_Test(const CLP&)
	{
#ifdef ENABLE_CIRCUITS
		static_assert(!std::is_copy_constructible<Gmw>::value);
		static_assert(!std::is_copy_assignable<Gmw>::value);
		static_assert(std::is_nothrow_move_constructible<Gmw>::value);
		static_assert(std::is_nothrow_move_assignable<Gmw>::value);

		BetaLibrary library;
		auto* add2 = library.int_int_add(2, 2, 2);
		std::array<Gmw, 2> gmw;
		gmw[0].init(0, 128, *add2);
		gmw[1].init(1, 128, *add2);
		gmw[0].setZeroInput(0);
		gmw[0].setZeroInput(1);
		gmw[1].setZeroInput(0);
		gmw[1].setZeroInput(1);

		auto oleBlocks = gmw[0].oleCount() / 128;
		PRNG prng(block(0x12345678, 0x90abcdef));
		std::array<std::vector<block>, 2> mult, add;
		for (u64 i = 0; i < 2; ++i)
		{
			mult[i].resize(oleBlocks);
			add[i].resize(oleBlocks);
			prng.get(mult[i].data(), mult[i].size());
		}
		prng.get(add[0].data(), add[0].size());
		for (u64 i = 0; i < oleBlocks; ++i)
			add[1][i] = (mult[0][i] & mult[1][i]) ^ add[0][i];
		gmw[0].setOle(mult[0], add[0]);
		gmw[1].setOle(mult[1], add[1]);

		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto result = macoro::sync_wait(macoro::when_all_ready(
			gmw[0].run(sockets[0]), gmw[1].run(sockets[1])));
		std::get<0>(result).result();
		std::get<1>(result).result();
		if (!gmw[0].mOleMult.empty() || !gmw[0].mOleAdd.empty() ||
			!gmw[1].mOleMult.empty() || !gmw[1].mOleAdd.empty())
			throw UnitTestFail("GMW retained consumed OLE correlations");

		bool consumedOleRejected = false;
		try { gmw[0].setOle(mult[0], add[0]); }
		catch (const std::logic_error&) { consumedOleRejected = true; }
		if (!consumedOleRejected)
			throw UnitTestFail("GMW accepted fresh OLEs after consuming its gate schedule");

		bool missingOleRejected = false;
		try
		{
			macoro::sync_wait(gmw[0].run(sockets[0]));
		}
		catch (const std::invalid_argument&)
		{
			missingOleRejected = true;
		}
		if (!missingOleRejected)
			throw UnitTestFail("GMW accepted a nonlinear run without OLE correlations");

		auto* add16 = library.int_int_add(16, 16, 16);
		Gmw mapped;
		mapped.init(0, 129, *add16);
		Matrix<u8> shortRows(add16->mOutputs[0].size(), 17);
		bool shortOutputRejected = false;
		try
		{
			mapped.mapOutput(0, shortRows);
		}
		catch (const std::runtime_error&)
		{
			shortOutputRejected = true;
		}
		if (!shortOutputRejected)
			throw UnitTestFail("GMW accepted an output row shorter than its block stride");

		bool evaluationBoundRejected = false;
		try
		{
			mapped.init(0, Gmw::MaxOleDimension + 1, *add2);
		}
		catch (const std::invalid_argument&)
		{
			evaluationBoundRejected = true;
		}
		auto oversizedCircuit = *add2;
		oversizedCircuit.mNonlinearGateCount = Gmw::MaxOleDimension + 1;
		bool gateBoundRejected = false;
		try
		{
			mapped.init(0, 128, oversizedCircuit);
		}
		catch (const std::invalid_argument&)
		{
			gateBoundRejected = true;
		}
		if (!evaluationBoundRejected || !gateBoundRejected)
			throw UnitTestFail("GMW accepted an oversized OLE dimension");

		auto expectInitRejected = [&](const BetaCircuit& circuit, u64 party,
			u64 evaluations, const char* message) {
			bool rejected = false;
			try { mapped.init(party, evaluations, circuit); }
			catch (const std::invalid_argument&) { rejected = true; }
			if (!rejected)
				throw UnitTestFail(message);
		};
		expectInitRejected(*add2, 2, 128,
			"GMW accepted an invalid party index");
		expectInitRejected(*add2, 0, 0,
			"GMW accepted zero circuit evaluations");

		auto badWireCircuit = *add2;
		badWireCircuit.mGates[0].mInput[0] = badWireCircuit.mWireCount;
		expectInitRejected(badWireCircuit, 0, 128,
			"GMW accepted an out-of-range gate wire");

		auto badLevels = *add2;
		badLevels.mLevelCounts = { badLevels.mGates.size() + 1 };
		badLevels.mLevelAndCounts = { 0 };
		expectInitRejected(badLevels, 0, 128,
			"GMW accepted levels extending beyond the gate list");

		BetaCircuit dependentCircuit;
		BetaBundle dependentInput(3), dependentOutput(1);
		BetaWire dependentTemp;
		dependentCircuit.addInputBundle(dependentInput);
		dependentCircuit.addOutputBundle(dependentOutput);
		dependentCircuit.addTempWire(dependentTemp);
		dependentCircuit.addGate(
			dependentInput[0], dependentInput[1], GateType::And, dependentTemp);
		dependentCircuit.addGate(
			dependentTemp, dependentInput[2], GateType::And, dependentOutput[0]);
		dependentCircuit.mLevelCounts = { 2 };
		dependentCircuit.mLevelAndCounts = { 2 };
		expectInitRejected(dependentCircuit, 0, 128,
			"GMW accepted a same-round nonlinear dependency");

		BetaCircuit flaggedCircuit;
		BetaBundle flaggedInput(2), flaggedOutput(3);
		flaggedCircuit.addInputBundle(flaggedInput);
		flaggedCircuit.addOutputBundle(flaggedOutput);
		flaggedCircuit.addGate(
			flaggedInput[0], flaggedInput[1], GateType::Xor, flaggedOutput[0]);
		flaggedCircuit.addConst(flaggedOutput[1], 1);
		flaggedCircuit.addCopy(flaggedInput[0], flaggedOutput[2]);
		flaggedCircuit.addInvert(flaggedOutput[2]);

		std::array<Gmw, 2> flaggedGmw;
		flaggedGmw[0].init(0, 3, flaggedCircuit);
		flaggedGmw[1].init(1, 3, flaggedCircuit);
		Matrix<u8> flaggedInput0(3, 1), flaggedInput1(3, 1);
		flaggedInput0(0, 0) = 1;
		flaggedInput0(1, 0) = 2;
		flaggedInput0(2, 0) = 3;
		std::fill(flaggedInput1.begin(), flaggedInput1.end(), 0);
		flaggedGmw[0].setInput<u8>(0, flaggedInput0);
		flaggedGmw[1].setInput<u8>(0, flaggedInput1);
		Gmw movedFlagged0(std::move(flaggedGmw[0]));
		Gmw movedFlagged1;
		movedFlagged1 = std::move(flaggedGmw[1]);
		for (const auto& source : flaggedGmw)
		{
			if (source.mN || source.mRole != ~0ull || !source.mGates.empty() ||
				!source.mWords.empty() || !source.mMem.empty() ||
				!source.mOleMult.empty() || !source.mOleAdd.empty())
				throw UnitTestFail("GMW move retained active source state");
		}

		auto flaggedSockets = coproto::LocalAsyncSocket::makePair();
		auto flaggedResult = macoro::sync_wait(macoro::when_all_ready(
			movedFlagged0.run(flaggedSockets[0]),
			movedFlagged1.run(flaggedSockets[1])));
		std::get<0>(flaggedResult).result();
		std::get<1>(flaggedResult).result();

		Matrix<u8> flaggedOutput0(3, 1), flaggedOutput1(3, 1);
		movedFlagged0.getOutput<u8>(0, flaggedOutput0);
		movedFlagged1.getOutput<u8>(0, flaggedOutput1);
		const std::array<u8, 3> expectedFlaggedOutput{ 3, 7, 2 };
		for (u64 i = 0; i < expectedFlaggedOutput.size(); ++i)
		{
			if (((flaggedOutput0(i, 0) ^ flaggedOutput1(i, 0)) & 7) !=
				expectedFlaggedOutput[i])
				throw UnitTestFail("GMW did not materialize a flagged output");
		}

		bool linearRerunRejected = false;
		try { macoro::sync_wait(movedFlagged0.run(flaggedSockets[0])); }
		catch (const std::logic_error&) { linearRerunRejected = true; }
		if (!linearRerunRejected)
			throw UnitTestFail("GMW reran a consumed linear gate schedule");

		auto emptyBundleCircuit = *add2;
		emptyBundleCircuit.mInputs.emplace_back();
		Gmw emptyBundle;
		emptyBundle.init(0, 128, emptyBundleCircuit);
		bool emptyBundleRejected = false;
		try { emptyBundle.setZeroInput(emptyBundleCircuit.mInputs.size() - 1); }
		catch (const std::invalid_argument&) { emptyBundleRejected = true; }
		if (!emptyBundleRejected)
			throw UnitTestFail("GMW dereferenced an empty input bundle");

		std::stringstream malformedBinary(
			std::ios::in | std::ios::out | std::ios::binary);
		badWireCircuit.writeBin(malformedBinary);
		BetaCircuit parsed = *add2;
		const auto originalHash = parsed.hash();
		bool malformedBinaryRejected = false;
		try
		{
			malformedBinary.seekg(0);
			parsed.readBin(malformedBinary);
		}
		catch (const std::exception&)
		{
			malformedBinaryRejected = true;
		}
		if (!malformedBinaryRejected || neq(parsed.hash(), originalHash))
			throw UnitTestFail("BetaCircuit accepted malformed binary structure or changed state");

		std::stringstream validBinary(
			std::ios::in | std::ios::out | std::ios::binary);
		add2->writeBin(validBinary);
		auto truncatedBytes = validBinary.str();
		truncatedBytes.pop_back();
		std::stringstream truncatedBinary(truncatedBytes,
			std::ios::in | std::ios::binary);
		bool truncatedBinaryRejected = false;
		try { parsed.readBin(truncatedBinary); }
		catch (const std::exception&) { truncatedBinaryRejected = true; }
		if (!truncatedBinaryRejected || neq(parsed.hash(), originalHash))
			throw UnitTestFail("BetaCircuit accepted truncated binary input or changed state");

		std::istringstream malformedBristol("1 3 2 2 1\n");
		bool malformedBristolRejected = false;
		try { parsed.readBristol(malformedBristol); }
		catch (const std::exception&) { malformedBristolRejected = true; }
		if (!malformedBristolRejected || neq(parsed.hash(), originalHash))
			throw UnitTestFail("BetaCircuit accepted invalid Bristol dimensions or changed state");

		Gmw cleared;
		cleared.init(0, 128, *add2);
		std::vector<block> clearMult(cleared.oleCount() / 128, ZeroBlock);
		std::vector<block> clearAdd(clearMult.size(), ZeroBlock);
		cleared.setOle(clearMult, clearAdd);
		cleared.clear();
		if (!cleared.mOleMult.empty() || !cleared.mOleAdd.empty() ||
			cleared.mOleIndex)
			throw UnitTestFail("GMW clear retained OLE state");
#else
		throw UnitTestSkipped("ENABLE_CIRCUITS not defined.");
#endif
	}
}
