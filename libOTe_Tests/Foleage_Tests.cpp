
#include "Foleage_Tests.h"
#include "libOTe/Triple/Foleage/fft/FoleageFft.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Triple/Foleage/FoleageTriple.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/TestCollection.h"
#include <type_traits>


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

			for (const auto& ole : oles)
			{
				if (ole.hasBaseOts())
					throw UnitTestFail("Foleage retained consumed base OTs");
				if (ole.mSendOts.size() || ole.mRecvOts.size() || ole.mChoiceOts.size() ||
					ole.mDpfLeaf.mBaseSendOts.size() || ole.mDpfLeaf.mBaseRecvOts.size() ||
					ole.mDpf.mBaseSendOts.size() || ole.mDpf.mBaseRecvOts.size())
					throw UnitTestFail("Foleage did not clear consumed base-OT storage");
			}

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

	void foleage_F2ole_test(const CLP& cmd)
	{
#ifdef ENABLE_FOLEAGE
		const auto logn = 6;
		const u64 n = ipow(3, logn) - 67;
		const auto blockCount = divCeil(n, 128);
		const bool verbose = cmd.isSet("v");

		std::array<FoleageTriple, 2> oles;
		if (cmd.hasValue("t"))
			oles[0].mT = oles[1].mT = cmd.get<u64>("t");

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		oles[0].init(0, n, FoleageMode::F2TraceOle);
		oles[1].init(1, n, FoleageMode::F2TraceOle);

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
				baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
		}
		oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		std::array<std::vector<block>, 2> xTrace, xXiTrace, zTrace, zXiTrace;
		for (u64 i = 0; i < 2; ++i)
		{
			xTrace[i].resize(blockCount);
			xXiTrace[i].resize(blockCount);
			zTrace[i].resize(blockCount);
			zXiTrace[i].resize(blockCount);
		}

		auto sockets = coproto::LocalAsyncSocket::makePair();
		if (verbose)
			oles[0].setTimer(timer);
		auto result = macoro::sync_wait(macoro::when_all_ready(
			oles[0].expandF2Ole(
				xTrace[0], xXiTrace[0], zTrace[0], zXiTrace[0], prng0, sockets[0]),
			oles[1].expandF2Ole(
				xTrace[1], xXiTrace[1], zTrace[1], zXiTrace[1], prng1, sockets[1])));
		std::get<0>(result).result();
		std::get<1>(result).result();

		for (const auto& ole : oles)
		{
			if (ole.hasBaseOts() || ole.mSendOts.size() || ole.mRecvOts.size() ||
				ole.mChoiceOts.size() || ole.mDpfLeaf.mBaseSendOts.size() ||
				ole.mDpfLeaf.mBaseRecvOts.size() || ole.mDpf.mBaseSendOts.size() ||
				ole.mDpf.mBaseRecvOts.size())
				throw UnitTestFail("Foleage trace expansion retained consumed base OTs");
		}

		for (u64 i = 0; i < n; ++i)
		{
			const auto traceProduct =
				*BitIterator(xTrace[0].data(), i) & *BitIterator(xTrace[1].data(), i);
			const auto traceShare =
				*BitIterator(zTrace[0].data(), i) ^ *BitIterator(zTrace[1].data(), i);
			if (traceProduct != traceShare)
				throw UnitTestFail("Foleage Tr(x) OLE correlation failed");

			const auto xiTraceProduct =
				*BitIterator(xXiTrace[0].data(), i) & *BitIterator(xXiTrace[1].data(), i);
			const auto xiTraceShare =
				*BitIterator(zXiTrace[0].data(), i) ^ *BitIterator(zXiTrace[1].data(), i);
			if (xiTraceProduct != xiTraceShare)
				throw UnitTestFail("Foleage Tr(xi*x) OLE correlation failed");
		}

		if (verbose)
			std::cout << "Time taken: \n" << timer << std::endl;
#else
		throw UnitTestSkipped("ENABLE_FOLEAGE not defined.");
#endif
	}

	void foleage_Audit_test(const CLP&)
	{
#ifdef ENABLE_FOLEAGE
		static_assert(!std::is_copy_constructible_v<FoleageTriple>);
		static_assert(!std::is_copy_assignable_v<FoleageTriple>);
		static_assert(std::is_move_constructible_v<FoleageTriple>);
		static_assert(std::is_move_assignable_v<FoleageTriple>);

		auto expectRejected = [](auto&& fn, const char* message) {
			bool rejected = false;
			try { fn(); }
			catch (const std::exception&) { rejected = true; }
			if (!rejected)
				throw UnitTestFail(message);
		};

		expectRejected([] {
			FoleageTriple triple;
			triple.init(0, 0);
		}, "Foleage accepted a zero domain");
		expectRejected([] {
			FoleageTriple triple;
			triple.init(0, 1);
		}, "Foleage accepted fewer than two positions per sparse block");
		expectRejected([] {
			FoleageTriple triple;
			triple.init(2, 1000);
		}, "Foleage accepted an invalid party index");
		expectRejected([] {
			FoleageTriple triple;
			triple.init(0, 1000, FoleageMode::F2TraceOle, FoleageDpfMode::RevCuckoo);
		}, "Foleage accepted the unimplemented RevCuckoo mode");
		expectRejected([] {
			FoleageTriple triple;
			triple.init(0, 1000, static_cast<FoleageMode>(255));
		}, "Foleage accepted an invalid correlation mode");
		expectRejected([] {
			FoleageTriple triple;
			(void)triple.baseOtCount();
		}, "Foleage reported base-OT counts before initialization");
		expectRejected([] {
			FoleageTriple triple;
			triple.setBaseOts({}, {}, {});
		}, "Foleage installed base OTs before initialization");
		expectRejected([] {
			FoleageTriple triple;
			triple.init(0, 1000);
			PRNG prng(ZeroBlock);
			auto sockets = coproto::LocalAsyncSocket::makePair();
			macoro::sync_wait(triple.genBaseOts(
				prng, sockets[0], static_cast<SilentBaseType>(255)));
		}, "Foleage accepted an invalid base-OT mode");
		expectRejected([] {
			FoleageTriple triple;
			PRNG prng(ZeroBlock);
			auto sockets = coproto::LocalAsyncSocket::makePair();
			std::vector<block> empty;
			macoro::sync_wait(triple.expand(
				empty, empty, empty, empty, prng, sockets[0]));
		}, "Foleage expanded before initialization");
		expectRejected([] {
			(void)log3ceil(std::numeric_limits<u64>::max());
		}, "log3ceil accepted an unrepresentable power-of-three result");

		std::vector<u8> shortPoly(1);
		expectRejected([&] {
			F4Multiply(span<u8>(shortPoly), span<u8>(shortPoly),
				span<u8>(shortPoly), 2);
		}, "F4Multiply accepted spans shorter than poly_size");

		std::vector<u16> shortFft(2);
		expectRejected([&] {
			foleageFft<u16>(span<u16>(shortFft), 1, 1);
		}, "foleageFft accepted an undersized coefficient span");

		for (u64 i = 0; i < ipow(3, 6); ++i)
		{
			const F3x32 x(i);
			if ((x + (-x)).toInt() != 0)
				throw UnitTestFail("F3x32 packed negation failed");
		}
		F3x32 packedTrits;
		packedTrits.mVal = 0x6666666666666666ull;
		if ((packedTrits + (-packedTrits)).mVal != 0)
			throw UnitTestFail("F3x32 packed negation failed in upper trits");

		// Check the two characteristic-two trace product identities for every
		// pair in F4. For z = l + xi*h, Tr(z)=h and Tr(xi*z)=l+h.
		for (u8 x = 0; x < 4; ++x)
		{
			for (u8 y = 0; y < 4; ++y)
			{
				const auto r0 = F4Multiply(x, y);
				const auto r1 = F4Multiply(x, F4Multiply(y, y));
				const auto traceProduct = ((r0 >> 1) ^ (r1 >> 1)) & 1;
				const auto xiTraceProduct = ((r0 & 1) ^ (r1 >> 1)) & 1;
				if (traceProduct != (((x >> 1) & 1) & ((y >> 1) & 1)))
					throw UnitTestFail("Foleage Tr product identity failed");
				if (xiTraceProduct != (((x ^ (x >> 1)) & 1) & ((y ^ (y >> 1)) & 1)))
					throw UnitTestFail("Foleage Tr(xi*x) product identity failed");
			}
		}

		FoleageTriple triple;
		triple.init(1, 1000);
		auto counts = triple.baseOtCount();
		std::vector<std::array<block, 2>> sendOts(counts.mSendCount);
		std::vector<block> recvOts(counts.mRecvCount);
		BitVector choices(counts.mRecvCount);
		triple.setBaseOts(sendOts, recvOts, choices);
		triple.mDpfLeaf.mOtIdx = triple.mDpfLeaf.baseOtCount();
		triple.mDpf.mOtIdx = triple.mDpf.baseOtCount();

		triple.setBaseOts(sendOts, recvOts, choices);
		if (triple.mSendOts.size() != 2 * triple.mC * triple.mT ||
			triple.mRecvOts.size() != 0)
			throw UnitTestFail("Foleage appended replacement tensor base OTs");
		if (triple.mDpfLeaf.mOtIdx || triple.mDpf.mOtIdx)
			throw UnitTestFail("Foleage did not reset replacement DPF base OTs");

		triple.clearBaseOts();
		if (triple.hasBaseOts() || triple.mSendOts.size() ||
			triple.mDpf.mBaseSendOts.size())
			throw UnitTestFail("Foleage clearBaseOts retained active state");

		triple.setBaseOts(sendOts, recvOts, choices);
		auto moved(std::move(triple));
		if (!moved.isInitialized() || !moved.hasBaseOts() ||
			moved.mN == 0 || moved.mSendOts.size() != 2 * moved.mC * moved.mT)
			throw UnitTestFail("Foleage move construction lost active state");
		if (triple.isInitialized() || triple.hasBaseOts() || triple.mTimer ||
			triple.mT != 9 || triple.mC != 8 || triple.mN ||
			triple.mMode != FoleageMode::F4Ole ||
			triple.mDpfMode != FoleageDpfMode::TernaryDpf ||
			triple.mFftA.size() || triple.mFftASquared.size() ||
			triple.mFftAFrobenius.size() ||
			triple.mSparsePositions.size() || triple.mRecvOts.size() ||
			triple.mSendOts.size() || triple.mChoiceOts.size())
			throw UnitTestFail("Foleage move construction retained source state");

		FoleageTriple assigned;
		assigned = std::move(moved);
		if (!assigned.isInitialized() || !assigned.hasBaseOts() ||
			moved.isInitialized() || moved.hasBaseOts() || moved.mTimer ||
			moved.mT != 9 || moved.mC != 8 || moved.mN ||
			moved.mMode != FoleageMode::F4Ole ||
			moved.mDpfMode != FoleageDpfMode::TernaryDpf ||
			moved.mFftA.size() || moved.mFftASquared.size() ||
			moved.mFftAFrobenius.size() ||
			moved.mSparsePositions.size() || moved.mRecvOts.size() ||
			moved.mSendOts.size() || moved.mChoiceOts.size())
			throw UnitTestFail("Foleage move assignment retained source state");

		triple.init(0, 1000);
		(void)triple.baseOtCount();
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
		std::array<std::vector<u16>, 2> coeff, prod, prodFrobenius;
		coeff[0].resize(n);
		coeff[1].resize(n);
		prod[0].resize(n2);
		prod[1].resize(n2);
		prodFrobenius[0].resize(n2);
		prodFrobenius[1].resize(n2);

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
			oles[0].tensorTrace(coeff[0], prod[0], prodFrobenius[0], sock[0]),
			oles[1].tensorTrace(coeff[1], prod[1], prodFrobenius[1], sock[1])));
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

				auto expFrobenius = F4Multiply(ci, F4Multiply(cj, cj));
				auto actFrobenius = prodFrobenius[0][p] ^ prodFrobenius[1][p];
				if (expFrobenius != actFrobenius)
					throw RTE_LOC;
			}
		}
#else
		throw UnitTestSkipped("ENABLE_FOLEAGE not defined.");
#endif
	}
}
