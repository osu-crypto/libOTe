#include "Dpf_Tests.h"
#include "libOTe/Dpf/RegularDpf.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Dpf/SparseDpf.h"
#include <algorithm>
#include <numeric>
#include "libOTe/Dpf/TernaryDpf.h"
#include "cryptoTools/Common/TestCollection.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Dpf/InvMtxDmpf.h"
#include "libOTe/Dpf/InvMtxDmpf/Equality.h"
#include "libOTe/Dpf/InvMtxDmpf/GoldreichHash.h"


using namespace oc;

void RegularDpf_Multiply_Test(const CLP& cmd)
{
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)
	u64 n = 13;
	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].init(0, n);
	dpf[1].init(1, n);

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(n);
		recvOts[i].resize(n);
		choices[i].resize(n);
		choices[i].randomize(prng);
		prng.get(sendOts[i].data(), sendOts[i].size());
		for (u64 j = 0; j < n; ++j)
			recvOts[i][j] = sendOts[i][j][choices[i][j]];
	}

	dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
	dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

	{
		u64 i = 0;
		u64 a0 = dpf[0].mChoiceBits[i];
		block A0 = block(-a0, -a0);
		auto c00 = dpf[0].mRecvOts[i];

		auto b1 = dpf[0].mSendOts[i][0] ^ dpf[0].mSendOts[i][1];
		auto c10 = dpf[0].mSendOts[i][0];

		// C0' = c00+c10+a0b1
		auto C0 = c00 ^ c10 ^ (b1 & A0);

		u64 a1 = dpf[1].mChoiceBits[i];
		block A1 = block(-a1, -a1);
		auto c01 = dpf[1].mRecvOts[i];

		auto b0 = dpf[1].mSendOts[i][1] ^ dpf[1].mSendOts[i][1];
		auto c11 = dpf[1].mSendOts[i][0];

		// C0' = c00+c10+a0b1
		auto C1 = c11 ^ c01 ^ (b0 & A1);

		auto a = a0 ^ a1;
		auto B = b0 ^ b1;
		auto C = C0 ^ C1;

		if (a == 0 && C != oc::ZeroBlock)
			throw RTE_LOC;
		if (a == 1 && C != B)
			throw RTE_LOC;
	}

	auto sock = coproto::LocalAsyncSocket::makePair();

	for (u64 i = 0; i < 10; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 i = 0; i < 2; ++i)
		{
			choices[i].randomize(prng);
			prng.get(sendOts[i].data(), sendOts[i].size());
			for (u64 j = 0; j < n; ++j)
				recvOts[i][j] = sendOts[i][j][choices[i][j]];
		}
		dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
		dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

		BitVector x0(n), x1(n);
		x0.randomize(prng);
		x1.randomize(prng);
		std::vector<block> xy0(n), xy1(n), y0(n), y1(n);

		prng.get(y0.data(), y0.size());
		prng.get(y1.data(), y1.size());

		macoro::sync_wait(macoro::when_all_ready(
			dpf[0].multiply(x0, y0, xy0, sock[0]),
			dpf[1].multiply(x1, y1, xy1, sock[1])
		));

		for (u64 j = 0; j < n; ++j)
		{

			u64 x = x0[j] ^ x1[j];
			auto y = y0[j] ^ y1[j];
			auto xy = xy0[j] ^ xy1[j];
			auto exp = block(-x, -x) & y;
			if (xy != exp)
			{
				std::cout << "i " << i << std::endl;
				std::cout << "act " << xy << " " << xy0[j] << " + " << xy1[j] << std::endl;
				std::cout << "exp " << exp << std::endl;
				throw RTE_LOC;
			}
		}
	}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_SPARSE_DPF not defined.");
#endif
}

void RegularDpf_MultByte_Test(const CLP& cmd)
{
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)

	{
		u64 n = 10;
		u64 bitCount = 3;
		Matrix<u8> m(n, divCeil(bitCount, 8));
		Matrix<u8> d(n, divCeil(bitCount, 8));
		std::vector<u8> b(divCeil(n * bitCount, 8));

		PRNG prng(block(231234, 321312));
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < bitCount; ++j)
			{
				*BitIterator(m[i].data(), j) = prng.getBit();
			}
		}

		DpfMult::packBits(b, m, bitCount);
		DpfMult::unpackBits(d, b, bitCount);
		if (m != d)
			throw RTE_LOC;
	}


for (auto m : { 16, 3,8, 13, 33, 233 })
{

	u64 n = 13;
	u64 m8 = divCeil(m, 8);

	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].init(0, n);
	dpf[1].init(1, n);

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(n);
		recvOts[i].resize(n);
		choices[i].resize(n);
	}

	auto sock = coproto::LocalAsyncSocket::makePair();

	for (u64 i = 0; i < 4; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 i = 0; i < 2; ++i)
		{
			choices[i].randomize(prng);
			prng.get(sendOts[i].data(), sendOts[i].size());
			for (u64 j = 0; j < n; ++j)
				recvOts[i][j] = sendOts[i][j][choices[i][j]];
		}
		dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
		dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

		BitVector x0(n), x1(n);
		x0.randomize(prng);
		x1.randomize(prng);
		Matrix<u8> xy0(n, m8), xy1(n, m8), y0(n, m8), y1(n, m8);

		//prng.get(y0.data(), y0.size());
		//prng.get(y1.data(), y1.size());
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < m; ++j)
			{
				*BitIterator(y0[i].data(), j) = prng.getBit();
				*BitIterator(y1[i].data(), j) = prng.getBit();
			}
		}

		macoro::sync_wait(macoro::when_all_ready(
			dpf[0].multiply(m, x0.getSpan<u8>(), y0, xy0, sock[0]),
			dpf[1].multiply(m, x1.getSpan<u8>(), y1, xy1, sock[1])
		));

		for (u64 j = 0; j < n; ++j)
		{
			for (u64 i = 0; i < m8; ++i)
			{

				u64 x = x0[j] ^ x1[j];
				auto y = y0[j][i] ^ y1[j][i];
				auto xy = xy0[j][i] ^ xy1[j][i];
				auto exp = x * y;
				if (xy != exp)
				{
					std::cout << " m " << m << std::endl;
					std::cout << "j " << j << " i " << i << std::endl;
					std::cout << "act " << int(xy) << "=" << int(xy0[j][i]) << " + " << int(xy1[j][i]) << std::endl;
					std::cout << "exp " << int(exp) << std::endl;
					throw RTE_LOC;
				}
			}
		}
	}
}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_SPARSE_DPF not defined.");
#endif
}


void RegularDpf_MultBit_Test(const CLP& cmd)
{
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)


	u64 n = 1311;

	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].init(0, n);
	dpf[1].init(1, n);

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(n);
		recvOts[i].resize(n);
		choices[i].resize(n);
	}

	auto sock = coproto::LocalAsyncSocket::makePair();

	for (u64 i = 0; i < 4; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 i = 0; i < 2; ++i)
		{
			choices[i].randomize(prng);
			prng.get(sendOts[i].data(), sendOts[i].size());
			for (u64 j = 0; j < n; ++j)
				recvOts[i][j] = sendOts[i][j][choices[i][j]];
		}
		dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
		dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

		BitVector x0(n), x1(n);
		BitVector xy0(n), xy1(n), y0(n), y1(n);
		x0.randomize(prng);
		x1.randomize(prng);
		y0.randomize(prng);
		y1.randomize(prng);

		macoro::sync_wait(macoro::when_all_ready(
			dpf[0].multiplyBits(x0, y0, xy0, sock[0]),
			dpf[1].multiplyBits(x1, y1, xy1, sock[1])
		));

		for (u64 j = 0; j < n; ++j)
		{

			u64 x = x0[j] ^ x1[j];
			auto y = y0[j] ^ y1[j];
			auto xy = xy0[j] ^ xy1[j];
			auto exp = x & y;
			if (xy != exp)
			{
				std::cout << "j " << j << " i " << i << std::endl;
				std::cout << "x   " << int(x) << "=" << int(x0[j]) << " + " << int(x1[j]) << std::endl;
				std::cout << "y   " << int(y) << "=" << int(y0[j]) << " + " << int(y1[j]) << std::endl;
				std::cout << "act " << int(xy) << "=" << int(xy0[j]) << " + " << int(xy1[j]) << std::endl;
				std::cout << "exp " << int(exp) << std::endl;
				throw RTE_LOC;
			}
		}
	}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_SPARSE_DPF not defined.");
#endif
}
void RegularDpf_Proto_Test(const CLP& cmd)
{
#ifdef ENABLE_REGULAR_DPF

	PRNG prng(block(231234, 321312));
	u64 domain = cmd.getOr("domain", 211);
	u64 numPoints = cmd.getOr("numPoints", 11);
	std::vector<u64> points0(numPoints);
	std::vector<u64> points1(numPoints);
	std::vector<block> values0(numPoints);
	std::vector<block> values1(numPoints);
	for (u64 i = 0; i < numPoints; ++i)
	{
		points1[i] = prng.get<u64>();
		points0[i] = (prng.get<u64>() % domain) ^ points1[i];
		values0[i] = prng.get();
		values1[i] = prng.get();
	}

	std::array<oc::RegularDpf, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<block>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numPoints, domain);
	output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	auto sock = coproto::LocalAsyncSocket::makePair();
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, values0, prng.get(), [&](auto k, auto i, auto v, block t) { output[0](k, i) = v; tags[0](k, i) = t.get<u8>(0) & 1; }, sock[0]),
		dpf[1].expand(points1, values1, prng.get(), [&](auto k, auto i, auto v, block t) { output[1](k, i) = v; tags[1](k, i) = t.get<u8>(0) & 1; }, sock[1])
	));


	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];
			auto act = output[0][k][i] ^ output[1][k][i];
			auto t = i == p ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			auto exp = t ? (values0[k] ^ values1[k]) : ZeroBlock;
			if (exp != act)
			{

				throw RTE_LOC;
			}
			if (t != tAct)
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

void RegularDpf_Puncture_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_REGULAR_DPF
	PRNG prng(block(231234, 321312));
	u64 domain = cmd.getOr("domain", 8);
	u64 numPoints = cmd.getOr("numPoints", 1);
	std::vector<u64> points0(numPoints);
	std::vector<u64> points1(numPoints);
	for (u64 i = 0; i < numPoints; ++i)
	{
		points1[i] = prng.get<u64>();
		points0[i] = (prng.get<u64>() % domain) ^ points1[i];
	}

	std::array<oc::RegularDpf, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<block>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numPoints, domain);
	output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);
	auto seed0 = prng.get<block>();
	auto seed1 = prng.get<block>();

	auto sock = coproto::LocalAsyncSocket::makePair();
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, {}, seed0, [&](auto k, auto i, auto v, block t) { output[0](k, i) = v; tags[0](k, i) = t.get<u8>(0) & 1; }, sock[0]),
		dpf[1].expand(points1, {}, seed1, [&](auto k, auto i, auto v, block t) { output[1](k, i) = v; tags[1](k, i) = t.get<u8>(0) & 1; }, sock[1])
	));


	bool failed = false;
	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];
			auto act = output[0][k][i] ^ output[1][k][i];
			auto t = i == p ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			if (t == 0 && act != ZeroBlock)
				throw RTE_LOC;

			if (t == 1 && act == ZeroBlock)
				failed = true;

			if (t != tAct)
				throw RTE_LOC;
		}
	}

	if (failed)
		throw RTE_LOC;

#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

void RegularDpf_keyGen_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_REGULAR_DPF

	PRNG prng(block(231234, 321312));
	u64 domain = cmd.getOr("domain", 211);
	u64 numPoints = cmd.getOr("numPoints", 11);
	std::vector<u64> points(numPoints);
	std::vector<u64> points0(numPoints);
	std::vector<u64> points1(numPoints);
	std::vector<block> values(numPoints);
	std::vector<block> values0(numPoints);
	std::vector<block> values1(numPoints);
	for (u64 i = 0; i < numPoints; ++i)
	{
		points[i] = prng.get<u64>() % domain;
		points1[i] = prng.get<u64>();
		points0[i] = points[i] ^ points1[i];
		values0[i] = prng.get();
		values1[i] = prng.get();
		values[i] = values0[i] ^ values1[i];
	}

	std::array<oc::RegularDpf, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<block>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numPoints, domain);
	output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	std::array<RegularDpfKey, 2> key, key2, key3;

	auto sock = coproto::LocalAsyncSocket::makePair();

	prng.SetSeed(block(214234, 2341234));
	block seed0 = prng.get();
	block seed1 = prng.get();

	// generate the keys using MPC
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].keyGen(points0, values0, seed0, key[0], sock[0]),
		dpf[1].keyGen(points1, values1, seed1, key[1], sock[1])
	));






	// real code should use:
	//     prng.SetSeed(sysRandomSeed());
	prng.SetSeed(block(214234, 2341234));

	// generate the seeds.
	RegularDpf::keyGen(domain, span<u64>(points), span<block>(values), prng, span<RegularDpfKey>(key2));

	if (key[0] != key2[0])
		throw RTE_LOC;
	if (key[1] != key2[1])
		throw RTE_LOC;

	// serialize the seeds.
	std::vector<u8> buff0(key2[0].sizeBytes());
	std::vector<u8> buff1(key2[1].sizeBytes());
	key2[0].toBytes(buff0);
	key2[1].toBytes(buff1);

	// send buffer...
	// deserialize
	key3[0].resize(domain, numPoints);
	key3[1].resize(domain, numPoints);
	key3[0].fromBytes(buff0);
	key3[1].fromBytes(buff1);

	if (key[0] != key3[0])
		throw RTE_LOC;
	if (key[1] != key3[1])
		throw RTE_LOC;

	// expand the dpf
	RegularDpf::expand(0, domain, key3[0], [&](auto k, auto i, auto v, block t) { output[0](k, i) = v; tags[0](k, i) = t.get<u8>(0) & 1; });
	RegularDpf::expand(1, domain, key3[1], [&](auto k, auto i, auto v, block t) { output[1](k, i) = v; tags[1](k, i) = t.get<u8>(0) & 1; });

	// check the results
	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];
			auto act = output[0][k][i] ^ output[1][k][i];
			auto t = i == p ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			auto exp = t ? (values0[k] ^ values1[k]) : ZeroBlock;
			if (exp != act)
			{

				throw RTE_LOC;
			}
			if (t != tAct)
				throw RTE_LOC;
		}
	}

#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

void SparseDpf_Proto_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SPARSE_DPF

	PRNG prng(block(32324, 2342));
	u64 numPoints = 1;
	u64 domain = 1773;
	u64 dense = 4;
	u64 fraction = 16;

	auto index{ std::vector<u64>(numPoints) };
	auto value{ std::vector<block>(numPoints) };
	std::array points{ std::vector<u64>(numPoints),std::vector<u64>(numPoints) };
	std::array values{ std::vector<block>(numPoints), std::vector<block>(numPoints) };
	oc::SparseDpf dpf[2];
	Matrix<u32> sparsePoints(numPoints, domain / fraction);

	for (u64 j = 0; j < numPoints; ++j)
	{
		std::vector<u32> set(domain);
		std::iota(set.begin(), set.end(), 0);
		for (u64 i = 0; i < sparsePoints.cols(); ++i)
		{
			auto k = prng.get<u32>() % set.size();
			std::swap(set[k], set.back());
			sparsePoints(j, i) = set.back();
			set.pop_back();
		}
	}

	for (u64 i = 0; i < sparsePoints.rows(); ++i)
	{
		std::sort(sparsePoints[i].begin(), sparsePoints[i].end());
		index[i] = prng.get<u64>() % sparsePoints.cols();
		value[i] = prng.get();
		//auto alpha = sparsePoints(i, index[i]);
		//std::cout << "alpha " << alpha << " " << oc::BitVector((u8*)&alpha, log2ceil(domain)) << std::endl;
		points[0][i] = prng.get();
		points[1][i] = points[0][i] ^ sparsePoints(i, index[i]);
		values[0][i] = prng.get();
		values[1][i] = values[0][i] ^ value[i];
	}


	dpf[0].init(0, numPoints, domain, dense);
	dpf[1].init(1, numPoints, domain, dense);
	auto sock = coproto::LocalAsyncSocket::makePair();

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(baseCount);
		recvOts[i].resize(baseCount);
		choices[i].resize(baseCount);
		choices[i].randomize(prng);
		prng.get(sendOts[i].data(), sendOts[i].size());
		for (u64 j = 0; j < baseCount; ++j)
			recvOts[i][j] = sendOts[i][j][choices[i][j]];
	}

	dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
	dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);


	std::array<Matrix<block>, 2> out;
	std::array<Matrix<u8>, 2> tags;
	out[0].resize(numPoints, sparsePoints.cols());
	out[1].resize(numPoints, sparsePoints.cols());
	tags[0].resize(numPoints, sparsePoints.cols());
	tags[1].resize(numPoints, sparsePoints.cols());
	auto r = macoro::sync_wait(
		macoro::when_all_ready(
			dpf[0].expand(points[0], values[0], [&](auto k, auto i, auto v, auto t) { out[0](k, i) = v; tags[0](k, i) = t; }, prng, sparsePoints, sock[0]),
			dpf[1].expand(points[1], values[1], [&](auto k, auto i, auto v, auto t) { out[1](k, i) = v; tags[1](k, i) = t; }, prng, sparsePoints, sock[1])
		));


	std::get<0>(r).result();
	std::get<1>(r).result();

	for (u64 i = 0; i < numPoints; ++i)
	{
		for (u64 j = 0; j < sparsePoints.cols(); ++j)
		{
			auto active = index[i] == j ? 1 : 0;

			auto tag = tags[0](i, j) ^ tags[1](i, j);
			if (tag != active)
				throw RTE_LOC;

			auto act = out[0](i, j) ^ out[1](i, j);
			auto exp = active ? value[i] : ZeroBlock;
			if (act != exp)
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_SPARSE_DPF not defined.");
#endif
}

template<typename F, typename Ctx>
void TernaryDpf_Proto_Test_(const oc::CLP& cmd)
{
#ifdef ENABLE_TERNARY_DPF

	PRNG prng(block(231234, 321312));
	u64 depth = cmd.getOr("depth", 3);
	u64 domain = ipow(3, depth) - 3;
	u64 numPoints = cmd.getOr("numPoints", 17);
	std::vector<F3x32> points0(numPoints);
	std::vector<F3x32> points1(numPoints);
	std::vector<F3x32> points(numPoints);
	std::vector<F> values0(numPoints);
	std::vector<F> values1(numPoints);
	Ctx ctx;
	for (u64 i = 0; i < numPoints; ++i)
	{
		points[i] = F3x32(prng.get<u64>() % domain);
		points1[i] = F3x32(prng.get<u64>() % domain);
		points0[i] = points[i] - points1[i];
		//std::cout << points[i] << " = " << points0[i] <<" + "<< points1[i] << std::endl;
		values0[i] = prng.get();
		values1[i] = prng.get();
		//ctx.minus(points0[i], points[i], points1[i];)
	}

	std::array<oc::TernaryDpf<F, Ctx>, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<F>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numPoints, domain);
	output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	auto sock = coproto::LocalAsyncSocket::makePair();
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, values0, [&](auto k, auto i, auto v, auto t) { output[0](k, i) = v; tags[0](k, i) = t; }, prng, sock[0]),
		dpf[1].expand(points1, values1, [&](auto k, auto i, auto v, auto t) { output[1](k, i) = v; tags[1](k, i) = t; }, prng, sock[1])
	));


	for (u64 i = 0; i < domain; ++i)
	{
		F3x32 I(i);
		for (u64 k = 0; k < numPoints; ++k)
		{
			F act;
			ctx.plus(act, output[0][k][i], output[1][k][i]);
			auto t = I == points[k] ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			F exp;
			if (t)
				ctx.plus(exp, values0[k], values1[k]);
			else
				ctx.zero(&exp, &exp + 1);

			if (exp != act)
			{
				std::cout << "i " << i << "=" << F3x32(i) << " " << t << std::endl;
				std::cout << "exp " << exp << std::endl;
				std::cout << "act " << act << std::endl;
				throw RTE_LOC;
			}
			if (t != tAct)
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_TERNARY_DPF not defined.");
#endif
}
void TritDpf_Proto_Test(const oc::CLP& cmd)
{
	TernaryDpf_Proto_Test_<block, CoeffCtxGF2>(cmd);
	TernaryDpf_Proto_Test_<u8, CoeffCtxGF2>(cmd);
}


void MtxDpf_Proto_Test(const oc::CLP& cmd)
{

}


void Goldreich_Proto_Test(const oc::CLP& cmd)
{

	std::array<GoldreichHash, 2> hash;
	u64 n = 100; // Increased sample size for better statistical analysis
	u64 in = 8;  // Increased input size
	u64 out = 16; // Increased output size for better testing
	bool v = cmd.isSet("v");
	auto inBits = in * 8;
	auto outBits = out * 8;

	hash[0].init(0, n, in, out);
	hash[1].init(1, n, in, out);

	auto count0 = hash[0].baseOtCount();
	auto count1 = hash[1].baseOtCount();
	if (count0.mRecvCount != count1.mSendCount)
		throw RTE_LOC;
	if (count0.mSendCount != count1.mRecvCount)
		throw RTE_LOC;

	PRNG prng(block(231234, 321312));
	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(count0.mRecvCount);
	baseRecv[1].resize(count1.mRecvCount);
	baseSend[0].resize(count0.mSendCount);
	baseSend[1].resize(count1.mSendCount);
	baseChoice[0].resize(count0.mRecvCount);
	baseChoice[1].resize(count1.mRecvCount);
	for (u64 i = 0; i < 2; ++i)
	{
		baseChoice[i].randomize(prng);
		prng.get(baseSend[i ^ 1].data(), baseSend[i ^ 1].size());
		for (u64 j = 0; j < baseChoice[i].size(); ++j)
			baseRecv[i][j] = baseSend[i ^ 1][j][baseChoice[i][j]];
	}

	hash[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	hash[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	auto seed = prng.get<block>();

	std::array<Matrix<u8>, 2> input, output;
	input[0].resize(n, in);
	input[1].resize(n, in);
	prng.get(input[0].data(), input[0].size());
	prng.get(input[1].data(), input[1].size());
	output[0].resize(n, out);
	output[1].resize(n, out);

	auto sock = coproto::LocalAsyncSocket::makePair();
	macoro::sync_wait(macoro::when_all_ready(
		hash[0].hash(input[0], output[0], sock[0], seed),
		hash[1].hash(input[1], output[1], sock[1], seed)
	));

	Matrix<u8> rIn(n, in), rOut(n, out);
	for (u64 j = 0; j < n; ++j)
	{
		for (u64 k = 0; k < in; ++k)
		{
			rIn(j, k) = input[0](j, k) ^ input[1](j, k);
		}
	}

	hash[0].hash(rIn, rOut, seed);
	for (u64 j = 0; j < n; ++j)
	{
		std::vector<u8> act(out);
		for (u64 k = 0; k < out; ++k)
			act[k] = output[0](j, k) ^ output[1](j, k);
		for (u64 k = 0; k < out; ++k)
		{
			if (act[k] != rOut[j][k])
			{
				std::cout << "j " << j << std::endl;
				std::cout << "act " << toHex(act) << std::endl;
				std::cout << "exp " << toHex(rOut[j]) << std::endl;
				throw RTE_LOC;
			}
		}
	}

}

void Goldreich_stat_Test(const oc::CLP& cmd)
{

	GoldreichHash hash;
	u64 n = 100000; // Increased sample size for better statistical analysis
	u64 in = 8;  // Increased input size
	u64 out = 16; // Increased output size for better testing
	bool v = cmd.isSet("v");
	auto inBits = in * 8;
	auto outBits = out * 8;

	hash.init(0, n, in, out);
	block seed = block(2342143213662143,4352452314532765);

	Matrix<u8> rIn(n, in), rOut(n, out);
	for (u64 j = 0; j < n; ++j)
	{
		copyBytesMin(rIn[j], j);
	}

	hash.hash(rIn, rOut, seed);
	if (v)
	{
		// Print a sample of the output for inspection
		std::cout << "\nSample of hash output (first 10 rows):" << std::endl;
		for (u64 j = 0; j < std::min(n, 10ull); ++j)
		{
			std::cout << "Row " << j << ": ";
			for (u64 k = 0; k < divCeil(outBits, 8); ++k)
			{
				auto act = rOut(j, k);
				std::cout << std::hex << std::setw(2) << std::setfill('0') << int(act);
			}
			std::cout << std::endl;
		}
		std::cout << std::dec; // Reset output to decimal
	}

	// Let's now test the uniformity of the output
	if (v)
	{
		std::cout << "\n==============================================" << std::endl;
		std::cout << "Testing uniformity of GoldreichHash output" << std::endl;
		std::cout << "==============================================" << std::endl;
	}

	// 1. Chi-Square Test for byte distribution
	// We'll count occurrences of each byte value in the output and check if they're uniform
	std::array<u64, 256> byteFrequencies{};
	u64 totalBytes = 0;

	// Count frequency of each byte value
	for (u64 i = 0; i < n; ++i)
	{
		for (u64 j = 0; j < divCeil(outBits, 8); ++j)
		{
			u8 xorByte = rOut(i,j);
			byteFrequencies[xorByte]++;
			totalBytes++;
		}
	}

	// Chi-square statistic for byte distribution
	double expectedFreq = static_cast<double>(totalBytes) / 256.0;
	double chiSquare = 0.0;

	for (u64 i = 0; i < 256; ++i)
	{
		double diff = byteFrequencies[i] - expectedFreq;
		chiSquare += (diff * diff) / expectedFreq;
	}

	// For 255 degrees of freedom at 0.05 significance level, critical value is around 293
	const double chiSquareCritical = 293.25;
	bool chiSquaredPassed = chiSquare < chiSquareCritical;

	if (v)
	{
		std::cout << "Chi-Square Test for Byte Distribution:" << std::endl;
		std::cout << "Chi-Square Value: " << chiSquare << std::endl;
		std::cout << "Critical Value (α=0.05): " << chiSquareCritical << std::endl;
		std::cout << "Result: " << (chiSquaredPassed ? "PASSED" : "FAILED") << std::endl;
		std::cout << "Interpretation: " << (chiSquaredPassed ?
			"Output bytes are uniformly distributed" :
			"Output bytes are NOT uniformly distributed") << std::endl;
		std::cout << std::endl;
	}

	// 2. Bit Distribution Test
	// We'll check if each bit position is roughly 50% 0's and 50% 1's
	std::vector<u64> bitOnes(outBits, 0);

	for (u64 i = 0; i < n; ++i)
	{
		for (u64 j = 0; j < outBits; ++j)
		{
			u64 bytePos = j / 8;
			u64 bitPos = j % 8;
			u8 xorByte = rOut(i, bytePos);
			bool bitValue = (xorByte >> bitPos) & 1;

			if (bitValue)
				bitOnes[j]++;
		}
	}

	if (v)
	{
		std::cout << "Bit Distribution Test:" << std::endl;
		std::cout << "Checking if each bit position is approximately 50% ones" << std::endl;
	}

	// Expected number of ones for a uniform distribution is n/2
	double expectedOnes = static_cast<double>(n) / 2.0;

	// Chi-square statistic for bit distribution (1 degree of freedom per bit)
	double bitChiSquare = 0.0;
	u64 failedBits = 0;

	for (u64 j = 0; j < outBits; ++j)
	{
		double diff = bitOnes[j] - expectedOnes;
		double bitChi = (diff * diff) / expectedOnes + (diff * diff) / (n - expectedOnes);

		// Critical value for 1 degree of freedom at 0.05 significance is 3.84
		bool bitPassed = bitChi < 3.84;

		if (!bitPassed)
			failedBits++;

		if (v)
		{
			// Detailed bit analysis if verbose mode is on
			std::cout << "Bit " << j << ": " << (bitOnes[j] * 100.0 / n) << "% ones, chi-square = "
				<< bitChi << " - " << (bitPassed ? "PASSED" : "FAILED") << std::endl;
		}
	}

	// We expect about 5% of bits to fail by random chance (at α=0.05)
	double expectedFailRate = 0.05;
	double actualFailRate = static_cast<double>(failedBits) / outBits;
	bool bitDistributionPassed = actualFailRate <= expectedFailRate * 2;

	if (v)
	{
		std::cout << "Failed Bits: " << failedBits << " out of " << outBits << " ("
			<< (actualFailRate * 100.0) << "%)" << std::endl;
		std::cout << "Expected Fail Rate: " << (expectedFailRate * 100.0) << "%" << std::endl;
		std::cout << "Result: " << (bitDistributionPassed ? "PASSED" : "FAILED") << std::endl;
		std::cout << "Interpretation: " << (bitDistributionPassed ?
			"Bit positions show expected randomness" :
			"Some bit positions show non-random distribution") << std::endl;

		std::cout << "==============================================" << std::endl;
	}

	// 4. Overall result summary
	if (v)
	{
		std::cout << "\nSummary of GoldreichHash Uniformity Tests:" << std::endl;
		std::cout << "1. Chi-Square Test: " << (chiSquaredPassed ? "PASSED" : "FAILED") << std::endl;
		std::cout << "2. Bit Distribution Test: " << (bitDistributionPassed ? "PASSED" : "FAILED") << std::endl;
		std::cout << "Overall: " << ((chiSquaredPassed && bitDistributionPassed) ?
			"PASSED - Output appears uniform" :
			"FAILED - Output may not be uniform") << std::endl;
	}

	// Throw exception if any test fails
	if (!chiSquaredPassed || !bitDistributionPassed)
		throw RTE_LOC;

}
