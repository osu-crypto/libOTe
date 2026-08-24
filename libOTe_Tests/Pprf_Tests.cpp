#include "Pprf_Tests.h"

#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "libOTe/Tools/Pprf/StationaryPprf.h"
#include "cryptoTools/Common/TestCollection.h"

#ifdef ENABLE_PPRF
#include "cryptoTools/Common/Log.h"
#include "Common.h"
#include <numeric>
using namespace osuCrypto;
using namespace tests_libOTe;


template<typename F, typename G, typename Ctx>
void RegularPprf_expandOne_test_impl(u64 domain, bool program)
{

	u64 depth = log2ceil(domain);
	auto pntCount = 8ull;
	PRNG prng(CCBlock);

	RegularPprfSender<F, Ctx> sender;
	RegularPprfReceiver<F,  Ctx> recver;

	sender.configure(domain, pntCount);
	recver.configure(domain, pntCount);

	F value = prng.get();
	sender.setValue({ &value, 1 });

	auto numOTs = sender.baseOtCount();
	std::vector<std::array<block, 2>> sendOTs(numOTs);
	std::vector<block> recvOTs(numOTs);
	BitVector recvBits = recver.sampleChoiceBits(prng);


	prng.get(sendOTs.data(), sendOTs.size());
	for (u64 i = 0; i < numOTs; ++i)
	{
		recvOTs[i] = sendOTs[i][recvBits[i]];
	}
	sender.setBase(sendOTs);
	recver.setBase(recvOTs);


	block seed = CCBlock;

	auto sLevels = std::vector<span<AlignedArray<block, 8>>>{};
	auto rLevels = std::vector<span<AlignedArray<block, 8>>>{};
	auto sBuff = std::vector<u8>{};
	auto sSums = span<std::array<block, 2>>{};
	auto sLast = span<u8>{};

	//pprf::TreeAllocator mTreeAlloc;
	sLevels.resize(depth);
	rLevels.resize(depth);


	//mTreeAlloc.reserve(2, (1ull << depth) + 2);
	AlignedUnVector<block> sTree, rTree;

	pprf::allocateExpandTree(domain, sTree, sLevels, false);
	pprf::allocateExpandTree(domain, rTree, rLevels, false);
	using VecF = typename Ctx::template Vec<F>;
	VecF sLeafLevel(8ull * domain);
	VecF rLeafLevel(8ull * domain);
	u64 leafOffset = 0;

	Ctx ctx;
	pprf::allocateExpandBuffer<F, Ctx>(depth - 1, pntCount, program, sBuff, sSums, sLast, ctx);

	std::vector<u64> points(recver.mPntCount);
	recver.getPoints(points, PprfOutputFormat::ByLeafIndex);

	sender.expandOne(seed, 0, program, sLevels, sLeafLevel, leafOffset, sSums, sLast, ctx);
	recver.expandOne(0, program, rLevels, rLeafLevel, leafOffset, sSums, sLast, points, ctx);

	bool failed = false;
	for (u64 i = 0; i < pntCount; ++i)
	{
		// the index of the leaf node that is active.
		auto leafIdx = points[i];
		//std::cout << "active leaf idx = " << leafIdx << std::endl;
		for (u64 d = 1; d < depth; ++d)
		{
			//u64 width = std::min<u64>(domain, 1ull << d);
			auto width = divCeil(domain, 1ull << (depth - d));

			// The index of the active child node.
			auto activeChildIdx = leafIdx >> (depth - d);

			// The index of the active child node sibling.

			for (u64 j = 0; j < width; ++j)
			{
				//std::cout
				//    << " " << sLevels[d][j][i].get<u16>()[0]
				//    << " " << rLevels[d][j][i].get<u16>()[0]
				//    ;

				if (j == activeChildIdx)
				{
					//std::cout << "*";
					continue;
				}


				if (sLevels[d][j][i] != rLevels[d][j][i])
				{
					//std::cout << " < ";
					throw RTE_LOC;
					failed = true;
				}

				//std::cout << ", ";
			}
			//std::cout << std::endl;
		}

		MatrixView<F> sLeaves(sLeafLevel.data(), sLeafLevel.size() / 8, 8);
		MatrixView<F> rLeaves(rLeafLevel.data(), rLeafLevel.size() / 8, 8);

		for (u64 j = 0; j < sLeaves.rows(); ++j)
		{
			if (j == leafIdx)
			{
				F exp;
				ctx.plus(exp, sLeaves(j, i), value);
				if (program && exp != rLeaves(j, i))
				{
					std::cout << i << " exp " << ctx.str(exp) << " " << ctx.str(rLeaves(j, i)) << std::endl;
					throw RTE_LOC;
				}
			}
			else
			{
				if (sLeaves(j, i) != rLeaves(j, i))
				{
					std::cout << "j " << j << " i " << i << " sender " << ctx.str(sLeaves(j, i)) << " recver " << ctx.str(rLeaves(j, i)) << std::endl;
					throw RTE_LOC;
				}
			}
		}
	}

	if (failed)
		throw RTE_LOC;
}

void RegularPprf_expandOne_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)


	for (u64 domain : { 2, 128, 4522}) for (bool program : {true, false})
	{

		RegularPprf_expandOne_test_impl<u64, u64, CoeffCtxInteger>(domain, program);
		RegularPprf_expandOne_test_impl<block, block, CoeffCtxGF128>(domain, program);
		RegularPprf_expandOne_test_impl<std::array<u32, 11>, u32, CoeffCtxArray<u32, 11>>(domain, program);

	}

#else
	throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

void Pprf_Audit_Test(const oc::CLP&)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)
	auto expectThrow = [](auto&& fn, const char* message) {
		bool rejected = false;
		try { fn(); }
		catch (const std::exception&) { rejected = true; }
		if (!rejected)
			throw UnitTestFail(message);
	};

	// Configuration must reject dimensions that make later products or
	// shifts invalid.
	{
		RegularPprfSender<block> sender;
		RegularPprfReceiver<block> receiver;
		expectThrow([&] { sender.configure(4, 0); },
			"PPRF sender accepted zero points");
		expectThrow([&] { receiver.configure(4, 0); },
			"PPRF receiver accepted zero points");
		expectThrow([&] { sender.configure(std::numeric_limits<u64>::max() - 1, 1); },
			"PPRF sender accepted a depth-64 domain");
		expectThrow([&] { receiver.configure(2, std::numeric_limits<u64>::max()); },
			"PPRF receiver accepted wrapped dimensions");
	}

	// The high half of the oversized sample must affect modular reduction.
	if (pprf::reduce128Mod(0, 1, 3) != 1)
		throw UnitTestFail("PPRF 128-bit modular reduction ignored its high limb");

	PRNG prng(CCBlock);

	// Reconfiguration removes the prior active paths, and incomplete state is
	// rejected before raw matrix indexing.
	{
		RegularPprfReceiver<block> receiver;
		receiver.configure(8, 1);
		receiver.sampleChoiceBits(prng);
		receiver.configure(8, 1);
		expectThrow([&] { (void)receiver.getPoints(PprfOutputFormat::ByTreeIndex); },
			"PPRF receiver retained choices across configuration");

		auto sockets = cp::LocalAsyncSocket::makePair();
		AlignedUnVector<block> output(8);
		auto protocol = receiver.expand(
			sockets[1], output, PprfOutputFormat::ByTreeIndex, false, 1);
		expectThrow([&] { macoro::sync_wait(std::move(protocol)); },
			"PPRF receiver expanded without base OTs or choices");
	}

	// Local preflight failures do not consume unused OTs, while a failure
	// after expansion begins consumes the complete reserved set.
	{
		RegularPprfSender<block> sender;
		sender.configure(4, 1);
		std::vector<std::array<block, 2>> base(sender.baseOtCount());
		prng.get(base.data(), base.size());
		sender.setBase(base);

		auto sockets = cp::LocalAsyncSocket::makePair();
		AlignedUnVector<block> output;
		auto missingCallback = sender.expand(
			sockets[0], {}, prng.get(), output,
			PprfOutputFormat::Callback, false, 1);
		expectThrow([&] { macoro::sync_wait(std::move(missingCallback)); },
			"PPRF sender accepted callback output without a callback");
		if (!sender.hasBaseOts())
			throw UnitTestFail("PPRF preflight failure consumed unused base OTs");

		auto callbackSockets = cp::LocalAsyncSocket::makePair();
		sender.mOutputFn = [](u64, AlignedUnVector<block>&) {
			throw std::runtime_error("intentional callback failure");
		};
		auto failingCallback = sender.expand(
			callbackSockets[0], {}, prng.get(), output,
			PprfOutputFormat::Callback, false, 1);
		expectThrow([&] { macoro::sync_wait(std::move(failingCallback)); },
			"PPRF sender callback failure did not propagate");
		if (sender.hasBaseOts())
			throw UnitTestFail("PPRF sender retained used base OTs after failure");
	}

	// A malformed correction message consumes receiver OTs on the exception
	// path instead of leaving a retryable partially used set.
	{
		RegularPprfReceiver<block> receiver;
		receiver.configure(4, 1);
		receiver.sampleChoiceBits(prng);
		std::vector<block> base(receiver.baseOtCount());
		prng.get(base.data(), base.size());
		receiver.setBase(base);

		auto sockets = cp::LocalAsyncSocket::makePair();
		AlignedUnVector<block> output(4);
		auto honest = receiver.expand(
			sockets[1], output, PprfOutputFormat::ByTreeIndex, false, 1);
		auto malformedProtocol = [&]() -> task<> {
			std::vector<u8> malformed(1);
			co_await sockets[0].send(std::move(malformed));
		};
		auto malformed = malformedProtocol();
		expectThrow([&] { eval(honest, malformed); },
			"PPRF receiver accepted a malformed correction message");
		if (receiver.hasBaseOts())
			throw UnitTestFail("PPRF receiver retained used base OTs after failure");
	}

	// Stationary expansion validates both public vectors before it writes or
	// initializes retained protocol state.
	{
		StationaryPprfSender<block> sender;
		sender.configure(4, 1);
		auto sockets = cp::LocalAsyncSocket::makePair();
		AlignedUnVector<block> output(4);
		auto missingValue = sender.expand(
			sockets[0], {}, prng.get(), output,
			PprfOutputFormat::ByTreeIndex, true, 1);
		expectThrow([&] { macoro::sync_wait(std::move(missingValue)); },
			"Stationary PPRF sender accepted a missing value");

		AlignedUnVector<block> value(1);
		AlignedUnVector<block> shortOutput(3);
		auto shortExpansion = sender.expand(
			sockets[0], value, prng.get(), shortOutput,
			PprfOutputFormat::ByTreeIndex, true, 1);
		expectThrow([&] { macoro::sync_wait(std::move(shortExpansion)); },
			"Stationary PPRF sender accepted a short output");

		StationaryPprfReceiver<block> receiver;
		receiver.configure(4, 1);
		auto shortReceive = receiver.expand(
			sockets[1], shortOutput,
			PprfOutputFormat::ByTreeIndex, true, 1);
		expectThrow([&] { macoro::sync_wait(std::move(shortReceive)); },
			"Stationary PPRF receiver accepted a short output");
	}

	// Once stationary shares have been fixed, the receiver cannot replace
	// their punctures. Clear removes both retained shares and counters.
	{
		StationaryPprfSender<block> sender;
		StationaryPprfReceiver<block> receiver;
		sender.configure(4, 1);
		receiver.configure(4, 1);
		auto choices = receiver.sampleChoiceBits(prng);
		std::vector<std::array<block, 2>> sendBase(sender.baseOtCount());
		std::vector<block> recvBase(receiver.baseOtCount());
		prng.get(sendBase.data(), sendBase.size());
		for (u64 i = 0; i < recvBase.size(); ++i)
			recvBase[i] = sendBase[i][choices[i]];
		sender.setBase(sendBase);
		receiver.setBase(recvBase);

		auto sockets = cp::LocalAsyncSocket::makePair();
		AlignedUnVector<block> value(1), senderOutput(4), receiverOutput(4);
		auto send = sender.expand(
			sockets[0], value, prng.get(), senderOutput,
			PprfOutputFormat::ByTreeIndex, true, 1);
		auto recv = receiver.expand(
			sockets[1], receiverOutput,
			PprfOutputFormat::ByTreeIndex, true, 1);
		eval(send, recv);

		expectThrow([&] { receiver.setChoiceBits(choices); },
			"Stationary PPRF receiver changed fixed punctures");
		sender.clear();
		receiver.clear();
		if (sender.mShare.size() || receiver.mShare.size() ||
			sender.mExpandCounter || receiver.mExpandCounter)
			throw UnitTestFail("Stationary PPRF clear retained expansion state");
	}
#else
	throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}


template<
	typename S, typename R,
	typename F, typename G, typename Ctx>
void Pprf_test_impl(
	u64 domain,
	u64 numPoints,
	bool program,
	PprfOutputFormat  format,
	bool eagerSend,
	bool verbose)
{

	auto threads = 1;
	PRNG prng(CCBlock);
	using Vec = typename Ctx::template Vec<F>;

	auto sockets = cp::LocalAsyncSocket::makePair();

	S sender;
	R recver;
	Vec delta;
	Ctx ctx;
	auto seed = prng.get<block>();
	ctx.resize(delta, numPoints * program);
	for (u64 i = 0; i < delta.size(); ++i)
		ctx.fromBlock(delta[i], seed);

	sender.configure(domain, numPoints);
	recver.configure(domain, numPoints);

	auto numOTs = sender.baseOtCount();
	std::vector<std::array<block, 2>> sendOTs(numOTs);
	std::vector<block> recvOTs(numOTs);
	BitVector recvBits = recver.sampleChoiceBits(prng);

	prng.get(sendOTs.data(), sendOTs.size());
	for (u64 i = 0; i < numOTs; ++i)
		recvOTs[i] = sendOTs[i][recvBits[i]];

	sender.setBase(sendOTs);
	recver.setBase(recvOTs);

	Vec a(numPoints * domain), a2;
	Vec b(numPoints * domain), b2;
	if (format == PprfOutputFormat::Callback)
	{
		a2 = std::move(a);
		b2 = std::move(b);
		a = {};
		b = {};
		sender.mOutputFn = [&](u64 treeIdx, Vec& data) {
			auto offset = treeIdx * domain;
			std::copy(data.begin(), data.end(), b2.begin() + offset);
			};
		recver.mOutputFn = [&](u64 treeIdx, Vec& data) {
			auto offset = treeIdx * domain;
			std::copy(data.begin(), data.end(), a2.begin() + offset);
			};
	}

	std::vector<u64> points(numPoints);
	recver.getPoints(points, format);
	sender.mEagerSend = eagerSend;
	recver.mEagerSend = eagerSend;

	// a = b + points * delta
	auto p0 = sender.expand(sockets[0], delta, prng.get(), b, format, program, threads);
	auto p1 = recver.expand(sockets[1], a, format, program, threads);


	eval(p0, p1);


	if (format == PprfOutputFormat::Callback)
	{
		a = std::move(a2);
		b = std::move(b2);
	}

	switch (format)
	{
	case osuCrypto::PprfOutputFormat::ByLeafIndex:
	case osuCrypto::PprfOutputFormat::ByTreeIndex:
	{

		bool failed = false;
		for (u64 j = 0; j < numPoints; ++j)
		{
			for (u64 i = 0; i < domain; ++i)
			{
				u64 idx = format == osuCrypto::PprfOutputFormat::ByTreeIndex ?
					j * domain + i :
					i * numPoints + j;

				F exp;

				if (points[j] == i)
				{
					if (program)
						ctx.plus(exp, b[idx], delta[j]);
					else
						ctx.zero(&exp, &exp + 1);
				}
				else
					exp = b[idx];

				if (program && exp != a[idx])
				{
					failed = true;

					if (verbose)
						std::cout << Color::Red;
				}
				if (verbose)
				{
					std::cout << "r[" << j << "][" << i << "] " << exp << " " << ctx.str(a[idx]);
					if (points[j] == i)
						std::cout << " < ";

					std::cout << std::endl << Color::Default;
				}
			}
			if (verbose)
				std::cout << "\n";
		}

		if (failed)
			throw RTE_LOC;

		break;
	}
	case osuCrypto::PprfOutputFormat::Interleaved:
	case osuCrypto::PprfOutputFormat::Callback:
	{

		bool failed = false;
		std::vector<std::size_t> index(points.size());
		std::iota(index.begin(), index.end(), 0);
		std::sort(index.begin(), index.end(),
			[&](std::size_t i, std::size_t j) { return points[i] < points[j]; });

		auto iIter = index.begin();
		auto leafIdx = points[*iIter];
		F deltaVal;
		ctx.zero(&deltaVal, &deltaVal + 1);
		if (program)
			deltaVal = delta[*iIter];

		++iIter;
		for (u64 j = 0; j < a.size(); ++j)
		{
			F exp, act;

			// a = b + points * delta

			// act = a - b 
			//     = point * delta
			ctx.minus(act, a[j], b[j]);
			ctx.zero(&exp, &exp + 1);
			bool active = false;
			if (j == leafIdx)
			{
				active = true;
				if (program)
					ctx.copy(exp, deltaVal);
				else
					ctx.minus(exp, exp, b[j]);
			}

			if (exp != act)
			{
				failed = true;
				if (verbose)
					std::cout << Color::Red;
			}

			if (verbose)
			{
				std::cout << j << " exp " << ctx.str(exp) << " " << ctx.str(act)
					<< " a " << ctx.str(a[j]) << " b " << ctx.str(b[j]);

				if (active)
					std::cout << " < " << deltaVal;

				std::cout << std::endl << Color::Default;
			}

			if (j == leafIdx)
			{
				if (iIter != index.end())
				{
					leafIdx = points[*iIter];
					if (program)
						deltaVal = delta[*iIter];
					++iIter;
				}
			}
		}

		if (failed)
			throw RTE_LOC;
		break;
	}
	default:
		break;
	}


}

template<
	typename F, typename Ctx>
void RegularPprf_test_impl(
	u64 domain,
	u64 numPoints,
	bool program,
	PprfOutputFormat  format,
	bool eagerSend,
	bool verbose)
{
	Pprf_test_impl<
		RegularPprfSender<F, Ctx>,
		RegularPprfReceiver<F, Ctx>,
		F, F, Ctx>(
			domain,
			numPoints,
			program,
			format,
			eagerSend,
			verbose);
}

//template<
//    typename F, typename Ctx>
//void StationaryPprf_test_impl(
//    u64 domain,
//    u64 numPoints,
//    bool program,
//    PprfOutputFormat  format,
//    bool eagerSend,
//    bool verbose)
//{
//
//    Pprf_test_impl<
//        StationaryPprfSender<F, F, Ctx>,
//        StationaryPprfReceiver<F, F, Ctx>,
//        F, F, Ctx>(
//            domain,
//            numPoints,
//            program,
//            format,
//            eagerSend,
//            verbose);
//}

void RegularPprf_inter_test(const CLP& cmd)
{
	auto f = PprfOutputFormat::Interleaved;
	auto v = cmd.isSet("v");
	for (auto d : { 32,3242 }) for (auto n : { 8, 128 }) for (auto p : { true, false }) for (auto e : { true, false })
	{
		RegularPprf_test_impl<u64, CoeffCtxInteger>(d, n, p, f, e, v);
		RegularPprf_test_impl<block, CoeffCtxGF2>(d, n, p, f, e, v);
	}
}



void RegularPprf_ByLeafIndex_test(const CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

	auto f = PprfOutputFormat::ByLeafIndex;
	auto v = cmd.isSet("v");
	for (auto d : { 32,3242 }) for (auto n : { 8, 128 }) for (auto p : { true/*, false */ }) for (auto e : { true/*, false */ })
	{
		RegularPprf_test_impl<u64, CoeffCtxInteger>(d, n, p, f, e, v);
		RegularPprf_test_impl<block, CoeffCtxGF2>(d, n, p, f, e, v);
	}
#else
	throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}



void RegularPprf_ByTreeIndex_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)


	auto f = PprfOutputFormat::ByTreeIndex;
	auto v = cmd.isSet("v");
	for (auto d : { 32,3242 }) for (auto n : { 8, 19 }) for (auto p : { true/*, false*/ })
	{
		RegularPprf_test_impl<u64, CoeffCtxInteger>(d, n, p, f, false, v);
		RegularPprf_test_impl<block, CoeffCtxGF2>(d, n, p, f, false, v);
	}

#else
	throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}



void RegularPprf_callback_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

	auto f = PprfOutputFormat::Callback;
	auto v = cmd.isSet("v");
	for (auto d : { 32,3242 }) for (auto n : { 8, 128 }) for (auto p : { true/*, false */ })
	{
		RegularPprf_test_impl<u64, CoeffCtxInteger>(d, n, p, f, false, v);
		RegularPprf_test_impl<block, CoeffCtxGF2>(d, n, p, f, false, v);
	}
#else
	throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}





template<
	//typename S, typename R,
	typename F, typename Ctx>
void StationaryPprf_test_impl(
	u64 domain,
	u64 numPoints,
	bool program,
	PprfOutputFormat  format,
	bool eagerSend,
	bool verbose)
{

	auto threads = 1;
	PRNG prng(CCBlock);
	using Vec = typename Ctx::template Vec<F>;

	auto sockets = cp::LocalAsyncSocket::makePair();

	StationaryPprfSender<F, Ctx> sender;
	StationaryPprfReceiver<F, Ctx> recver;
	Vec delta;
	Ctx ctx;
	auto seed = prng.get<block>();
	ctx.resize(delta, numPoints * program);
	for (u64 i = 0; i < delta.size(); ++i)
	{
		//delta[i] = F(1);
		ctx.fromBlock(delta[i], seed);
	}

	sender.configure(domain, numPoints);
	recver.configure(domain, numPoints);

	auto numOTs = sender.baseOtCount();
	std::vector<std::array<block, 2>> sendOTs(numOTs);
	std::vector<block> recvOTs(numOTs);
	BitVector recvBits = recver.sampleChoiceBits(prng);

	prng.get(sendOTs.data(), sendOTs.size());
	for (u64 i = 0; i < numOTs; ++i)
		recvOTs[i] = sendOTs[i][recvBits[i]];

	sender.setBase(sendOTs);
	recver.setBase(recvOTs);

	Vec a(numPoints * domain), a2;
	Vec b(numPoints * domain), b2;
	//if (format == PprfOutputFormat::Callback)
	//{
	//    a2 = std::move(a);
	//    b2 = std::move(b);
	//    a = {};
	//    b = {};
	//    sender.mOutputFn = [&](u64 treeIdx, Vec& data) {
	//        auto offset = treeIdx * domain;
	//        std::copy(data.begin(), data.end(), b2.begin() + offset);
	//        };
	//    recver.mOutputFn = [&](u64 treeIdx, Vec& data) {
	//        auto offset = treeIdx * domain;
	//        std::copy(data.begin(), data.end(), a2.begin() + offset);
	//        };
	//}

	std::vector<u64> points(numPoints);
	recver.getPoints(points, format);


	for (u64 jj = 0; jj < 3; ++jj)
	{

		// a = b + points * delta
		auto p0 = sender.expand(sockets[0], delta, prng.get(), b, format, program, threads);
		auto p1 = recver.expand(sockets[1], a, format, program, threads);


		eval(p0, p1);


		//if (format == PprfOutputFormat::Callback)
		//{
		//    a = std::move(a2);
		//    b = std::move(b2);
		//}

		switch (format)
		{
		case osuCrypto::PprfOutputFormat::ByLeafIndex:
		case osuCrypto::PprfOutputFormat::ByTreeIndex:
		{

			bool failed = false;
			for (u64 j = 0; j < numPoints; ++j)
			{
				for (u64 i = 0; i < domain; ++i)
				{
					u64 idx = format == osuCrypto::PprfOutputFormat::ByTreeIndex ?
						j * domain + i :
						i * numPoints + j;

					F exp;

					if (points[j] == i)
					{
						if (program)
							ctx.plus(exp, b[idx], delta[j]);
						else
							ctx.zero(&exp, &exp + 1);
					}
					else
						exp = b[idx];

					if (program && exp != a[idx])
					{
						failed = true;

						if (verbose)
							std::cout << Color::Red;
					}
					if (verbose)
					{
						std::cout << "r[" << j << "][" << i << "] " << exp << " " << ctx.str(a[idx]);
						if (points[j] == i)
							std::cout << " < ";

						std::cout << std::endl << Color::Default;
					}
				}
				if (verbose)
					std::cout << "\n";
			}

			if (failed)
				throw RTE_LOC;

			break;
		}
		case osuCrypto::PprfOutputFormat::Interleaved:
			//case osuCrypto::PprfOutputFormat::Callback:
		{

			bool failed = false;
			std::vector<std::size_t> index(points.size());
			std::iota(index.begin(), index.end(), 0);
			std::sort(index.begin(), index.end(),
				[&](std::size_t i, std::size_t j) { return points[i] < points[j]; });

			auto iIter = index.begin();
			auto leafIdx = points[*iIter];
			F deltaVal;
			ctx.zero(&deltaVal, &deltaVal + 1);
			if (program)
				deltaVal = delta[*iIter];

			++iIter;
			for (u64 j = 0; j < a.size(); ++j)
			{
				F exp, act;

				// a = b + points * delta

				// act = a - b 
				//     = point * delta
				ctx.minus(act, a[j], b[j]);
				ctx.zero(&exp, &exp + 1);
				bool active = false;
				if (j == leafIdx)
				{
					active = true;
					if (program)
						ctx.copy(exp, deltaVal);
					else
						ctx.minus(exp, exp, b[j]);
				}

				if (exp != act)
				{
					failed = true;
					if (verbose)
						std::cout << Color::Red;
				}

				if (verbose)
				{
					std::cout << j << " exp " << ctx.str(exp) << " " << ctx.str(act)
						<< " a " << ctx.str(a[j]) << " b " << ctx.str(b[j]);

					if (active)
						std::cout << " < " << deltaVal;

					std::cout << std::endl << Color::Default;
				}

				if (j == leafIdx)
				{
					if (iIter != index.end())
					{
						leafIdx = points[*iIter];
						if (program)
							deltaVal = delta[*iIter];
						++iIter;
					}
				}
			}

			if (failed)
				throw RTE_LOC;
			break;
		}
		default:
			throw RTE_LOC;
			break;
		}
	}

}


void StationaryPprf_inter_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

	auto f = PprfOutputFormat::ByTreeIndex;
	auto v = cmd.isSet("v");
	for (auto d : { 32,342 }) for (auto n : { 8, 32 }) for (auto p : { true/*, false */ })
	{
		StationaryPprf_test_impl<u64, CoeffCtxInteger>(d, n, p, f, false, v);
		StationaryPprf_test_impl<block, CoeffCtxGF2>(d, n, p, f, false, v);
	}
#else
	throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

#else


namespace {
	void throwDisabled()
	{
		throw oc::UnitTestSkipped(
			"ENABLE_PPRF not defined. "
		);
	}
}

void RegularPprf_expandOne_test(const oc::CLP& cmd) { throwDisabled(); }
void RegularPprf_inter_test(const oc::CLP& cmd) { throwDisabled(); }
void RegularPprf_ByLeafIndex_test(const oc::CLP& cmd) { throwDisabled(); }
void RegularPprf_ByTreeIndex_test(const oc::CLP& cmd) { throwDisabled(); }
void RegularPprf_callback_test(const oc::CLP& cmd) { throwDisabled(); }
void Pprf_Audit_Test(const oc::CLP& cmd) { throwDisabled(); }
void StationaryPprf_inter_test(const oc::CLP& cmd) { throwDisabled(); }

#endif
