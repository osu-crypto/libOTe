#include "Equality_Tests.h"
#include "libOTe/DPF/InvMtxDmpf/Equality.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "coproto/Socket/LocalAsyncSock.h"

namespace osuCrypto
{
	void BitInject_basic_test(const CLP& cmd)
	{

		u64 n = cmd.getOr("n", 11);
		u64 m = cmd.getOr("m", 13);
		u64 mod = cmd.getOr("mod", 16);

		std::array<BitInject, 2> otEq;
		otEq[0].init(0, n, m, mod);
		otEq[1].init(1, n, m, mod);

		auto count0 = otEq[0].baseOtCount();
		auto count1 = otEq[1].baseOtCount();
		if (count0.mRecvCount != count1.mSendCount ||
			count0.mSendCount != count1.mRecvCount)
		{
			throw RTE_LOC;
		}

		std::vector<block> baseRecv0(count0.mRecvCount);
		std::vector<block> baseRecv1(count1.mRecvCount);
		std::vector<std::array<block, 2>> baseSend0(count0.mSendCount);
		std::vector<std::array<block, 2>> baseSend1(count1.mSendCount);
		BitVector baseChoice0(count0.mRecvCount);
		BitVector baseChoice1(count1.mRecvCount);

		PRNG prng(CCBlock);
		baseChoice0.randomize(prng);
		baseChoice1.randomize(prng);
		for (u64 i = 0; i < count0.mSendCount; ++i)
		{
			baseSend0[i] = prng.get();
			baseRecv1[i] = baseChoice1[i] ? baseSend0[i][1] : baseSend0[i][0];
		}
		for (u64 i = 0; i < count1.mSendCount; ++i)
		{
			baseSend1[i] = prng.get();
			baseRecv0[i] = baseChoice0[i] ? baseSend1[i][1] : baseSend1[i][0];
		}

		otEq[0].setBaseOts(baseSend0, baseRecv0, baseChoice0);
		otEq[1].setBaseOts(baseSend1, baseRecv1, baseChoice1);

		BitVector exp(n);
		exp.randomize(prng);

		std::array<Matrix<u8>, 2> A, B;
		A[0].resize(n, divCeil(m,8));
		A[1].resize(n, divCeil(m,8));
		B[0].resize(n, m);
		B[1].resize(n, m);
		u64 mask = (1ull << (m % 8)) - 1;
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j + 1 < A[0].cols(); ++j)
			{
				A[0](i, j) = prng.get<u8>();
				A[1](i, j) = prng.get<u8>();
			}
			
			A[0][i].back() = prng.get<u8>() & mask;
			A[1][i].back() = prng.get<u8>() & mask;
		}

		auto sock = coproto::LocalAsyncSocket::makePair();
		auto res = macoro::sync_wait(
			macoro::when_all_ready(
				otEq[0].inject(A[0], B[0], sock[0], prng),
				otEq[1].inject(A[1], B[1], sock[1], prng)
			));

		std::get<0>(res).result();
		std::get<1>(res).result();

		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < m; ++j)
			{
				auto aij = bit(A[0][i], j) ^ bit(A[1][i], j);
				auto bij = (B[0](i, j) + B[1](i, j)) % mod;
				if (aij != bij)
					throw RTE_LOC;
			}
		}
	}

	template<typename EQ, typename T>
	void Equality_Test(const CLP& cmd)
	{

		u64 n = cmd.getOr("n", 128);
		u64 bc = cmd.getOr("bc", 8);

		std::array<EQ, 2> otEq;
		otEq[0].init(0, n, bc);
		otEq[1].init(1, n, bc);

		auto count0 = otEq[0].baseOtCount();
		auto count1 = otEq[1].baseOtCount();
		if (count0.mRecvCount != count1.mSendCount ||
			count0.mSendCount != count1.mRecvCount)
		{
			throw RTE_LOC;
		}

		std::vector<block> baseRecv0(count0.mRecvCount);
		std::vector<block> baseRecv1(count1.mRecvCount);
		std::vector<std::array<block, 2>> baseSend0(count0.mSendCount);
		std::vector<std::array<block, 2>> baseSend1(count1.mSendCount);
		BitVector baseChoice0(count0.mRecvCount);
		BitVector baseChoice1(count1.mRecvCount);

		PRNG prng(CCBlock);
		baseChoice0.randomize(prng);
		baseChoice1.randomize(prng);
		for (u64 i = 0; i < count0.mSendCount; ++i)
		{
			baseSend0[i] = prng.get();
			baseRecv1[i] = baseChoice1[i] ? baseSend0[i][1] : baseSend0[i][0];
		}
		for (u64 i = 0; i < count1.mSendCount; ++i)
		{
			baseSend1[i] = prng.get();
			baseRecv0[i] = baseChoice0[i] ? baseSend1[i][1] : baseSend1[i][0];
		}

		otEq[0].setBaseOts(baseSend0, baseRecv0, baseChoice0);
		otEq[1].setBaseOts(baseSend1, baseRecv1, baseChoice1);

		BitVector exp(n);
		exp.randomize(prng);

		std::array<std::vector<T>, 2> A, B;
		A[0].resize(n);
		A[1].resize(n);
		B[0].resize(n);
		B[1].resize(n);
		u64 mask = (1ull << bc) - 1;
		for (u64 i = 0; i < n; ++i)
		{
			auto a = prng.get<T>() & mask;
			auto b = prng.get<T>() & mask;

			if (exp[i])
				b = a;
			else if (b == a)
				b = (b + 1) & mask; // ensure b != a

			A[0][i] = prng.get<T>() & mask;
			A[1][i] = a ^ A[0][i];
			B[0][i] = prng.get<T>() & mask;
			B[1][i] = b ^ B[0][i];

		}

		std::array<BitVector, 2> y;
		auto sock = coproto::LocalAsyncSocket::makePair();

		auto res = macoro::sync_wait(
			macoro::when_all_ready(
				otEq[0].equal<T>(A[0], B[0], y[0], sock[0], prng),
				otEq[1].equal<T>(A[1], B[1], y[1], sock[1], prng)
			));

		std::get<0>(res).result();
		std::get<1>(res).result();

		auto act = y[0] ^ y[1];
		if (act != exp)
		{
			throw RTE_LOC;
		}
	}


	void OtEquality_basic_Test(const CLP& cmd)
	{
		Equality_Test<OtEquality, u8>(cmd);
	}

	void HybEquality_basic_Test(const CLP& cmd)
	{
		auto cmd2 = cmd;
		if (cmd2.isSet("bc") == false)
			cmd2.setDefault("bc", "55");

		Equality_Test<HybEquality, u64>(cmd2);
	}
}
