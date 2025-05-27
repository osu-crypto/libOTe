
#include "Foleage_Tests.h"
#include "libOTe/Triple/Foleage/fft/FoleageFft.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Triple/Foleage/FoleageTriple.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/TestCollection.h"


namespace osuCrypto
{

	// This test evaluates the full PCG.Expand for both parties and
	// checks correctness of the resulting OLE correlation.
	void foleage_F4ole_test(const CLP& cmd)
	{
#ifdef ENABLE_FOLEAGE




		auto logn = 6;
		u64 n = ipow(3, logn) - 67;
		auto blocks = divCeil(n, 128);
		bool verbose = cmd.isSet("v");
		std::vector<u64> cs{ 8 };

		for (auto c : cs)
		{

			std::array<FoleageTriple, 2> oles;
			if (cmd.hasValue("t"))
				oles[0].mT = oles[1].mT = cmd.get<u64>("t");

			oles[0].mC = oles[1].mC = c;

			PRNG prng0(block(2424523452345, 111124521521455324));
			PRNG prng1(block(6474567454546, 567546754674345444));
			Timer timer;

			oles[0].init(0, n);
			oles[1].init(1, n);

			{
				auto otCount0 = oles[0].baseOtCount();
				auto otCount1 = oles[1].baseOtCount();
				if (otCount0.mRecvCount != otCount1.mSendCount ||
					otCount0.mSendCount != otCount1.mRecvCount)
					throw RTE_LOC;
				std::array<std::vector<std::array<block, 2>>, 2> baseSend;
				baseSend[0].resize(otCount0.mSendCount);
				baseSend[1].resize(otCount1.mSendCount);
				std::array<std::vector<block>, 2> baseRecv;
				std::array<BitVector, 2> baseChoice;

				for (u64 i = 0; i < 2; ++i)
				{
					prng0.get(baseSend[i].data(), baseSend[i].size());
					baseRecv[1 ^ i].resize(baseSend[i].size());
					baseChoice[1 ^ i].resize(baseSend[i].size());
					baseChoice[1 ^ i].randomize(prng0);
					for (u64 j = 0; j < baseSend[i].size(); ++j)
					{
						baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
					}
				}

				oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
				oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
			}

			auto sock = coproto::LocalAsyncSocket::makePair();
			std::vector<block>
				ALsb(blocks),
				AMsb(blocks),
				BLsb(blocks),
				BMsb(blocks),
				C0Lsb(blocks),
				C0Msb(blocks),
				C1Lsb(blocks),
				C1Msb(blocks);

			if (verbose)
				oles[0].setTimer(timer);

			auto r = macoro::sync_wait(macoro::when_all_ready(
				oles[0].expand(ALsb, AMsb, C0Lsb, C0Msb, prng0, sock[0]),
				oles[1].expand(BLsb, BMsb, C1Lsb, C1Msb, prng1, sock[1])));
			std::get<0>(r).result();
			std::get<1>(r).result();

			// Now we check that we got the correct OLE correlations and fail
			// the test otherwise.
			for (size_t i = 0; i < blocks; i++)
			{
				auto Lsb = C0Lsb[i] ^ C1Lsb[i];
				auto Msb = C0Msb[i] ^ C1Msb[i];
				block mLsb, mMsb;
				F4Multiply(
					ALsb[i], AMsb[i],
					BLsb[i], BMsb[i],
					mLsb, mMsb);

				if (Lsb != mLsb)
					throw RTE_LOC;
				if (Msb != mMsb)
					throw RTE_LOC;
			}

			if (verbose)
				std::cout << "Time taken: \n" << timer << std::endl;
		}

#else
		throw UnitTestSkipped("ENABLE_FOLEAGE not defined.");
#endif

	}

	void foleage_Triple_test(const CLP& cmd)
	{
#ifdef ENABLE_FOLEAGE

		std::array<FoleageTriple, 2> oles;

		auto logn = 5;
		u64 n = ipow(3, logn);
		auto blocks = divCeil(n, 128);
		bool verbose = cmd.isSet("v");

		if (cmd.hasValue("t"))
			oles[0].mT = oles[1].mT = cmd.get<u64>("t");

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		oles[0].init(0, n);
		oles[1].init(1, n);

		{
			auto otCount0 = oles[0].baseOtCount();
			auto otCount1 = oles[1].baseOtCount();
			if (otCount0.mRecvCount != otCount1.mSendCount ||
				otCount0.mSendCount != otCount1.mRecvCount)
				throw RTE_LOC;
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			baseSend[0].resize(otCount0.mSendCount);
			baseSend[1].resize(otCount1.mSendCount);
			std::array<std::vector<block>, 2> baseRecv;
			std::array<BitVector, 2> baseChoice;

			for (u64 i = 0; i < 2; ++i)
			{
				prng0.get(baseSend[i].data(), baseSend[i].size());
				baseRecv[1 ^ i].resize(baseSend[i].size());
				baseChoice[1 ^ i].resize(baseSend[i].size());
				baseChoice[1 ^ i].randomize(prng0);
				for (u64 j = 0; j < baseSend[i].size(); ++j)
				{
					baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
				}
			}

			oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
		}

		auto sock = coproto::LocalAsyncSocket::makePair();
		std::array<std::vector<block>, 2>
			A, B, C;
		for (u64 i = 0; i < 2; ++i)
		{
			A[i].resize(blocks);
			B[i].resize(blocks);
			C[i].resize(blocks);
		}

		if (verbose)
			oles[0].setTimer(timer);

		auto r = macoro::sync_wait(macoro::when_all_ready(
			oles[0].expand(A[0], B[0], C[0], prng0, sock[0]),
			oles[1].expand(A[1], B[1], C[1], prng1, sock[1])));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// Now we check that we got the correct OLE correlations and fail
		// the test otherwise.
		for (size_t i = 0; i < blocks; i++)
		{
			auto a = A[0][i] ^ A[1][i];
			auto b = B[0][i] ^ B[1][i];
			auto c = C[0][i] ^ C[1][i];
			if ((a & b) != c)
				throw RTE_LOC;
		}

		if (verbose)
			std::cout << "Time taken: \n" << timer << std::endl;
#else
		throw UnitTestSkipped("ENABLE_FOLEAGE not defined.");
#endif
	}

	void foleage_GenBase_test(const CLP& cmd)
	{
#ifdef ENABLE_FOLEAGE
		// This test checks the base OTs are generated correctly.

		for (auto type : { SilentBaseType::Base, SilentBaseType::BaseExtend })
		{

			std::array<FoleageTriple, 2> oles;
			PRNG prng0(block(2424523452345, 111124521521455324));
			PRNG prng1(block(6474567454546, 567546754674345444));

			// insecure but makes the but makes the test run faster.
			oles[0].mT = 3;
			oles[1].mT = 3;

			u64 n = 1000;
			oles[0].init(0, n);
			oles[1].init(1, n);

			auto blocks = divCeil(n, 128);

			auto sock = coproto::LocalAsyncSocket::makePair();
			std::vector<block>
				ALsb(blocks),
				AMsb(blocks),
				BLsb(blocks),
				BMsb(blocks),
				C0Lsb(blocks),
				C0Msb(blocks),
				C1Lsb(blocks),
				C1Msb(blocks);

			// baseExtend is the default and will be called by expand.
			if (type == SilentBaseType::Base)
			{
				auto r = macoro::sync_wait(macoro::when_all_ready(
					oles[0].genBaseOts(prng0, sock[0], type),
					oles[1].genBaseOts(prng1, sock[1], type)));
				std::get<0>(r).result();
				std::get<1>(r).result();
			}

			auto r = macoro::sync_wait(macoro::when_all_ready(
				oles[0].expand(ALsb, AMsb, C0Lsb, C0Msb, prng0, sock[0]),
				oles[1].expand(BLsb, BMsb, C1Lsb, C1Msb, prng1, sock[1])));
			std::exception_ptr ep;
			try{
				std::get<0>(r).result();
			}
			catch (std::exception& e)
			{
				std::cout << e.what() << std::endl;
				ep = std::current_exception();
			}

			std::get<1>(r).result();

			if (ep)
				std::rethrow_exception(ep);

			// Now we check that we got the correct OLE correlations and fail
			// the test otherwise.
			for (size_t i = 0; i < blocks; i++)
			{
				auto Lsb = C0Lsb[i] ^ C1Lsb[i];
				auto Msb = C0Msb[i] ^ C1Msb[i];
				block mLsb, mMsb;
				F4Multiply(
					ALsb[i], AMsb[i],
					BLsb[i], BMsb[i],
					mLsb, mMsb);

				if (Lsb != mLsb)
					throw RTE_LOC;
				if (Msb != mMsb)
					throw RTE_LOC;
			}
		}
#else
		throw UnitTestSkipped("ENABLE_FOLEAGE not defined.");
#endif
	}

	void foleage_tensor_test(const CLP& cmd)
	{
#ifdef ENABLE_FOLEAGE

		std::array<FoleageTriple, 2> oles;

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));

		oles[0].init(0, 1000);
		oles[1].init(1, 1000);

		u64 n = oles[0].mC * oles[0].mT;
		u64 n2 = n * n;
		auto sock = coproto::LocalAsyncSocket::makePair();
		std::array<std::vector<u16>, 2> coeff, prod;
		coeff[0].resize(n);
		coeff[1].resize(n);
		prod[0].resize(n2);
		prod[1].resize(n2);

		oles[1].mSendOts.resize(2 * n);
		oles[0].mRecvOts.resize(2 * n);
		oles[0].mChoiceOts.resize(2 * n);
		for (u64 i = 0; i < 2 * n; ++i)
		{
			oles[1].mSendOts[i] = prng0.get();;
			oles[0].mChoiceOts[i] = prng0.getBit();
			oles[0].mRecvOts[i] = oles[1].mSendOts[i][oles[0].mChoiceOts[i]];
		}
		auto r = macoro::sync_wait(macoro::when_all_ready(
			oles[0].tensor(coeff[0], prod[0], sock[0]),
			oles[1].tensor(coeff[1], prod[1], sock[1])));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// Now we check that we got the correct OLE correlations and fail
		// the test otherwise.
		for (size_t i = 0; i < n; i++)
		{
			for (size_t j = 0; j < n; j++)
			{
				auto p = i * n + j;

				u8 ci = coeff[0][i];
				u8 cj = coeff[1][j];
				auto exp = F4Multiply(ci, cj);
				auto act = prod[0][p] ^ prod[1][p];
				if (exp != act)
					throw RTE_LOC;
			}
		}
#else
		throw UnitTestSkipped("ENABLE_FOLEAGE not defined.");
#endif
	}
}