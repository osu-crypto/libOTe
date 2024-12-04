#include "RegularDpf_Tests.h"
#include "libOTe/Tools/Dpf/RegularDpf.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Tools/Dpf/SparseDpf.h"
#include <algorithm>
#include <numeric>
using namespace oc;

void RegularDpf_Multiply_Test(const CLP& cmd)
{
	u64 n = 13;
	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].mPartyIdx = 0;
	dpf[1].mPartyIdx = 1;
	dpf[0].mSendOts.push_back(prng.get());
	dpf[1].mSendOts.push_back(prng.get());
	dpf[0].mChoiceBits.pushBack(0);
	dpf[1].mChoiceBits.pushBack(1);
	dpf[0].mRecvOts.push_back(dpf[1].mSendOts[0][dpf[0].mChoiceBits[0]]);
	dpf[1].mRecvOts.push_back(dpf[0].mSendOts[0][dpf[1].mChoiceBits[0]]);


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

	for (u64 i = 0; i < 100; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 j = 0; j < n; ++j)
		{
			dpf[0].mSendOts.push_back(prng.get());
			dpf[1].mSendOts.push_back(prng.get());
			dpf[0].mChoiceBits.pushBack(prng.getBit());
			dpf[1].mChoiceBits.pushBack(prng.getBit());
			dpf[0].mRecvOts.push_back(dpf[1].mSendOts.back()[dpf[0].mChoiceBits.back()]);
			dpf[1].mRecvOts.push_back(dpf[0].mSendOts.back()[dpf[1].mChoiceBits.back()]);
		}


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
}

void RegularDpf_Proto_Test(const CLP& cmd)
{
	PRNG prng(block(231234, 321312));
	u64 domain = 131;
	u64 numPoints = 11;
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
		dpf[0].expand(points0, values0, [&](auto k, auto i, auto v, auto t) { output[0](k, i) = v; tags[0](k, i) = t; }, prng, sock[0]),
		dpf[1].expand(points1, values1, [&](auto k, auto i, auto v, auto t) { output[1](k, i) = v; tags[1](k, i) = t; }, prng, sock[1])
	));


	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];
			auto act = output[0][k][i] ^ output[1][k][i];
			auto t = i == p;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			auto exp = t ? (values0[k] ^ values1[k]) : ZeroBlock;
			if (exp != act)
				throw RTE_LOC;
			if (t != tAct)
				throw RTE_LOC;
		}
	}
}

void SparseDpf_Proto_Test(const oc::CLP& cmd)
{
	PRNG prng(block(32324, 2342));
	u64 numPoints = 1;
	u64 domain = 256;
	oc::SparseDpf dpf;
	Matrix<u32> sparsePoints(numPoints, domain / 10);
	std::vector<u32> set(domain);
	std::iota(set.begin(), set.end(), 0);
	for(u64 i = 0; i < sparsePoints.size(); ++i)
	{
		auto j = prng.get<u32>() % set.size();
		std::swap(set[j], set.back());
		sparsePoints(i) = set.back();
		set.pop_back();
	}

	for (u64 i = 0; i < sparsePoints.rows(); ++i)
	{
		std::sort(sparsePoints[i].begin(), sparsePoints[i].end());
	}
	dpf.init(0, domain, sparsePoints);
}
