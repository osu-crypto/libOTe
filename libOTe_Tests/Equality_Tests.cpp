#include "Equality_Tests.h"
#include "libOTe/Dpf/InvMtxDmpf/Equality.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Dpf/InvMtxDmpf/Dedup.h"

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
		A[0].resize(n, divCeil(m, 8));
		A[1].resize(n, divCeil(m, 8));
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

	void Dedup_orTree_test(const CLP& cmd)
	{
		using namespace osuCrypto;
		u64 n = cmd.getOr("n", 8); // Small n for easy verification
		u64 keyBits = cmd.getOr("keyBits", 8);

		std::array<Dedup, 2> dedup;
		dedup[0].init(0, n, keyBits);
		dedup[1].init(1, n, keyBits);

		// Compute and set base OTs
		auto count0 = dedup[0].baseOtCount();
		auto count1 = dedup[1].baseOtCount();
		std::vector<block> baseRecv0(count0.mRecvCount);
		std::vector<block> baseRecv1(count1.mRecvCount);
		std::vector<std::array<block, 2>> baseSend0(count0.mSendCount);
		std::vector<std::array<block, 2>> baseSend1(count1.mSendCount);
		BitVector baseChoice0(count0.mRecvCount);
		BitVector baseChoice1(count1.mRecvCount);

		PRNG prng(CCBlock);
		baseChoice0.randomize(prng);
		baseChoice1.randomize(prng);

		for (u64 i = 0; i < count0.mSendCount; ++i) {
			baseSend0[i] = prng.get();
			baseRecv1[i] = baseChoice1[i] ? baseSend0[i][1] : baseSend0[i][0];
		}
		for (u64 i = 0; i < count1.mSendCount; ++i) {
			baseSend1[i] = prng.get();
			baseRecv0[i] = baseChoice0[i] ? baseSend1[i][1] : baseSend1[i][0];
		}

		dedup[0].setBaseOts(baseSend0, baseRecv0, baseChoice0);
		dedup[1].setBaseOts(baseSend1, baseRecv1, baseChoice1);

		// Create test c_{i,j} values (equality bits)
		// Size is n*(n-1)/2 - triangular matrix without diagonal
		u64 cSize = n * (n - 1) / 2;
		std::array<BitVector, 2> c, d;
		c[0].resize(cSize);
		c[1].resize(cSize);
		d[0].resize(n-1);
		d[1].resize(n-1);

		std::vector<u8>A(n);
		for (u64 i = 0; i < n; i++)
			A[i] = prng.get<u8>() % 4;

		// Set known pattern for testing
		// For this test, we'll say keys with the same index mod 2 are equal
		Matrix<u8> C(n, n);
		for (u64 i = 0, idx = 0; i < n; ++i) {
			for (u64 j = i + 1; j < n; ++j, ++idx) {
				C(i,j) = A[i] == A[j];
				c[0][idx] = prng.getBit(); // Random share for party 0
				c[1][idx] = c[0][idx] ^ C(i, j); // Share for party 1
			}
		}

		//std::cout << "C " << std::endl;
		//for (u64 i = 0; i < n; ++i) {
		//	for (u64 j = 0; j < n; ++j) {
		//		std::cout << int(C(i, j)) << " ";
		//	}
		//	std::cout << std::endl;
		//}
		// Run orTree protocol
		auto sock = coproto::LocalAsyncSocket::makePair();
		auto res = macoro::sync_wait(
			macoro::when_all_ready(
				dedup[0].orTree(c[0], d[0], prng, sock[0]),
				dedup[1].orTree(c[1], d[1], prng, sock[1])
			)
		);

		std::get<0>(res).result();
		std::get<1>(res).result();

		// Reconstruct the final d values by XORing both parties' shares
		BitVector actualD(n-1), expectedD(n-1);
		auto dIter0 = d[0].begin();
		auto dIter1 = d[1].begin();
		auto cIter0 = c[0].begin();
		auto cIter1 = c[1].begin();
		for (u64 i = 0; i < n; ++i) {
			if(i)
				actualD[i-1] = (*dIter0++) ^ (*dIter1++);
			//for (u64 j = i + 1; j < n; ++j) {
			//	C(i, j) = (*cIter0++) ^ (*cIter1++); // Reconstruct c[i,j] values
			//}
		}

		for (u64 i = 1; i < n; ++i) {
			u8 orValue = 0;
			for (u64 j = 0; j < i; ++j) {
				orValue |= C(j, i); // Calculate OR of all c[j,i] for j < i
			}
			expectedD[i-1] = orValue;
		}

		// Verify results
		if (actualD != expectedD) 
		{
			std::cout << "act : " << actualD << std::endl;
			std::cout << "exp : " << expectedD << std::endl;


				throw RTE_LOC;
		}

	}

	void Dedup_protocol_test(const CLP& cmd)
	{
		using namespace osuCrypto;
		u64 n = cmd.getOr("n", 16);
		u64 keyBits = cmd.getOr("keyBits", 8);
		u64 valueBits = cmd.getOr("valueBits", 16);

		std::array<Dedup, 2> dedup;
		dedup[0].init(0, n, keyBits);
		dedup[1].init(1, n, keyBits);
		// Compute and set the required base OTs for the Dedup protocol.
		auto count0 = dedup[0].baseOtCount();
		auto count1 = dedup[1].baseOtCount();

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

		PRNG prng(block(215342345234,324523452345));
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

		dedup[0].setBaseOts(baseSend0, baseRecv0, baseChoice0);
		dedup[1].setBaseOts(baseSend1, baseRecv1, baseChoice1);

		// Generate random keys, values, and alternate keys
		std::array<std::vector<u32>, 2> keys, altKeys;
		std::array<Matrix<u8>, 2> values;
		for (int p = 0; p < 2; ++p) {
			keys[p].resize(n);
			values[p].resize(n, divCeil(valueBits, 8));
		 	prng.get(values[p].data(), values[p].size());
			altKeys[p].resize(n);
		}

		// Make the keys[0] and keys[1] add up to the real keys, same for values and altKeys
		std::vector<u32> expKeys(n), expValues(n), rKeys(n), rAltKeys(n);
		Matrix<u8> rVals(n, divCeil(valueBits, 8));
		for(u64 i =0; i < rVals.size();++i)
			rVals(i) ^= values[0](i) ^ values[1](i);

		std::unordered_map<u32, u32> expSum;
		for (u64 i = 0; i < n; ++i) {

			rKeys[i] = i+1;
			rAltKeys[i] = n + i + 1;

			if (i && prng.getBit())
			{
				auto prev = prng.get<u8>() % i;
				rKeys[i] = rKeys[prev];
			}

			keys[0][i] = prng.get<u32>() & ((1u << keyBits) - 1);
			altKeys[0][i] = prng.get<u32>() & ((1u << keyBits) - 1);
			keys[1][i] = rKeys[i] ^ keys[0][i];
			altKeys[1][i] = rAltKeys[i] ^ altKeys[0][i];

			if (expSum.contains(rKeys[i]))
				expKeys[i] = rAltKeys[i];
			else
				expKeys[i] = rKeys[i];

			u64 v = 0;
			copyBytesMin(v, rVals[i]);
			expSum[rKeys[i]] ^= v;
		}
		for (u64 i = 0; i < n; ++i) {
			auto key = keys[0][i] ^ keys[1][i];
			expValues[i] = std::exchange(expSum[key], 0);
			//std::cout << "k " << rKeys[i] << " " << rVals[i] << " -> " << expKeys[i] << " " << expValues[i] << std::endl;
		}

		// Setup sockets
		auto sock = coproto::LocalAsyncSocket::makePair();
		auto Mtx = [](auto& v) { return MatrixView<u8>((u8*)v.data(), v.size(), sizeof(v[0])); }; 

		// Run protocol
		auto res = macoro::sync_wait(
			macoro::when_all_ready(
				dedup[0].dedup(Mtx(keys[0]), values[0], Mtx(altKeys[0]), prng, sock[0]),
				dedup[1].dedup(Mtx(keys[1]), values[1], Mtx(altKeys[1]), prng, sock[1])
			));

		std::get<0>(res).result();
		std::get<1>(res).result();

		// Reconstruct outputs
		std::vector<u8> vv(rVals.cols());
		for (u64 i = 0; i < n; ++i) {
			auto key = keys[0][i] ^ keys[1][i];
			for(u64 j = 0; j < rVals.cols(); ++j) {
				vv[j] = values[0][i][j] ^ values[1][i][j];
			}
			u64 v = 0;
			copyBytesMin(v, vv.data());


			if (key != expKeys[i])
				throw RTE_LOC;
			if (v != expValues[i])
				throw RTE_LOC;
		}
	}
}
