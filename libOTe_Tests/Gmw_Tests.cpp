#include "Gmw_Tests.h"

#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/TestCollection.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Tools/Gmw/Gmw.h"

namespace osuCrypto
{
	void Gmw_Audit_Test(const CLP&)
	{
#ifdef ENABLE_CIRCUITS
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
