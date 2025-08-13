#include "RevCuckoo_Tests.h"
#include "libOTe/Dpf/RevCuckoo/BinarySolver.h"
#include "libOTe/Dpf/RevCuckooDmpf.h"

namespace osuCrypto
{


	void setBase(std::array<BinarySolver, 2>& s)
	{
		PRNG prng(block(342132135, 23512351235));
		auto baseCount = s[0].baseOtCount();
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
		s[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		s[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
	}

	void BinSolver_multiply_test(const oc::CLP& cmd)
	{
		u64 m = 19;
		u64 cc = 40 + m;
		u64 bitCount = 11;
		std::array<BinarySolver, 2> s;
		s[0].init(0, m, cc, 10);
		s[1].init(1, m, cc, 10);
		setBase(s);

		PRNG prng(block(3423345222341334, 2394871239472938));

		BitVector a(m), a0(m), a1(m);
		Matrix<u8>
			b(m, divCeil(bitCount, 8)),
			b0(m, divCeil(bitCount, 8)), c0(m, divCeil(bitCount, 8)),
			b1(m, divCeil(bitCount, 8)), c1(m, divCeil(bitCount, 8));

		for (u64 i = 0; i < m; ++i)
		{
			for (u64 j = 0; j < bitCount; ++j)
			{
				*BitIterator(b[i].data(), j) = prng.getBit();
				*BitIterator(b0[i].data(), j) = prng.getBit();
			}
			for (u64 j = 0; j < b.cols(); ++j)
				b1(i, j) = b(i, j) ^ b0(i, j);
		}
		a.randomize(prng);
		a0.randomize(prng);
		a1 = a ^ a0;
		auto sock = coproto::LocalAsyncSocket::makePair();

		macoro::sync_wait(macoro::when_all_ready(
			s[0].multiply(bitCount, a0.getSpan<u8>(), b0, c0, sock[0]),
			s[1].multiply(bitCount, a1.getSpan<u8>(), b1, c1, sock[1])
		));



		Matrix<u8> act(m, divCeil(bitCount, 8));
		Matrix<u8> exp(m, divCeil(bitCount, 8));
		for (u64 i = 0; i < m; ++i)
		{
			for (u64 j = 0; j < b.cols(); ++j)
			{
				act(i, j) = c0(i, j) ^ c1(i, j);
				exp(i, j) = a[i] * b(i, j);
				if (act(i, j) != exp(i, j))
				{
					std::cout << i << "  " << j << std::endl;
					std::cout << "a   " << a[i] << std::endl;
					std::cout << "b   " << int(b(i, j)) << std::endl;
					std::cout << "act " << int(act(i, j)) << std::endl;
					std::cout << "exp " << int(exp(i, j)) << std::endl;
					throw RTE_LOC;
				}
			}
		}
	}

	void BinSolver_multiplyMtx_test(const oc::CLP& cmd)
	{
		struct Param
		{
			u64 m, n, k;
		};


		//u64 m = cmd.getOr("m", 10);
		//u64 n = cmd.getOr("n", 10);
		//u64 k = cmd.getOr("k", 10);;
		u64 t = cmd.getOr("t", 10);

		for (auto p : {
			Param{ 10, 10, 10 },
			Param{ 10, 20, 10 },
			Param{ 20, 10, 10 },
			Param{ 20, 20, 10 },
			Param{ 10, 20, 20 },
			Param{ 20, 10, 20 }
			})
		{
			auto m = p.m;
			auto n = p.n;
			auto k = p.k;

			auto m8 = divCeil(m, 8);
			//auto n8 = divCeil(n, 8);
			auto k8 = divCeil(k, 8);

			PRNG prng(block(3423345222341334, 2394871239472938));

			for (u64 tt = 0; tt < t; ++tt)
			{

				std::array<BinarySolver, 2> s;
				auto numOts = std::min<u64>(n * m, m * k);
				s[0].mMult.init(0, numOts);
				s[1].mMult.init(1, numOts);

				{
					auto baseCount = s[0].mMult.baseOtCount();
					auto baseRecv = std::vector<block>(baseCount);
					auto baseSend = std::vector<std::array<block, 2>>(baseCount);
					BitVector baseChoice;
					baseRecv.resize(baseCount);
					baseSend.resize(baseCount);
					baseChoice.resize(baseCount);
					baseChoice.randomize(prng);
					for (u64 i = 0; i < baseCount; ++i)
					{
						baseSend[i][0] = prng.get();
						baseSend[i][1] = prng.get();
						baseRecv[i] = baseSend[i][baseChoice[i]];
					}
					s[0].mMult.setBaseOts(baseSend, baseRecv, baseChoice);
					s[1].mMult.setBaseOts(baseSend, baseRecv, baseChoice);
				}

				//u64 cc = 40 + m;
				//s[0].init(0, m, cc, 10);
				//s[1].init(1, m, cc, 10);
				//setBase(s);


				//     m         k		   k
				//   aaaaa     bbbbb     ccccc
				// n aaaaa * m bbbbb = n ccccc
				//   aaaaa     bbbbb     ccccc
				Matrix<u8> a(n, m8), a0(n, m8), a1(n, m8);
				Matrix<u8>
					b(m, k8),
					b0(m, k8), c0(n, k8),
					b1(m, k8), c1(n, k8);

				for (u64 i = 0; i < m; ++i)
				{
					for (u64 j = 0; j < k; ++j)
					{
						*BitIterator(b[i].data(), j) = prng.getBit();
						*BitIterator(b0[i].data(), j) = prng.getBit();
					}
					for (u64 j = 0; j < b.cols(); ++j)
						b1(i, j) = b(i, j) ^ b0(i, j);
				}
				for (u64 i = 0; i < n; ++i)
				{
					for (u64 j = 0; j < m; ++j)
					{
						*BitIterator(a[i].data(), j) = prng.getBit();
						*BitIterator(a0[i].data(), j) = prng.getBit();
					}
					for (u64 j = 0; j < a.cols(); ++j)
						a1(i, j) = a(i, j) ^ a0(i, j);
				}
				auto sock = coproto::LocalAsyncSocket::makePair();

				auto r = macoro::sync_wait(macoro::when_all_ready(
					s[0].multiplyMtx(k, a0, b0, c0, sock[0]),
					s[1].multiplyMtx(k, a1, b1, c1, sock[1])
				));
				std::get<0>(r).result();
				std::get<1>(r).result();

				Matrix<u8> act(n, k8);
				Matrix<u8> exp(n, k8);
				for (u64 i = 0; i < n; ++i)
				{
					for (u64 j = 0; j < k; ++j)
					{
						//a[i,*] * b[*,j] = c[i,j]
						for (u64 l = 0; l < m; ++l)
						{
							*BitIterator(exp[i].data(), j) ^=
								(*BitIterator(a[i].data(), l) &
									*BitIterator(b[l].data(), j));
						}
					}
				}

				for (u64 i = 0; i < n; ++i)
				{
					for (u64 j = 0; j < b.cols(); ++j)
					{

						//exp(i, j) = a[i] * b(i, j);
						act(i, j) = c0(i, j) ^ c1(i, j);
						if (act(i, j) != exp(i, j))
						{
							std::cout << i << "  " << j << std::endl;
							//std::cout << "a   " << a[i] << std::endl;
							//std::cout << "b   " << int(b(i, j)) << std::endl;
							std::cout << "act " << int(act(i, j)) << std::endl;
							std::cout << "exp " << int(exp(i, j)) << std::endl;
							throw RTE_LOC;
						}
					}
				}
			}
		}
	}

	void printMtx(u64 bits, MatrixView<u8> X, std::string name)
	{
		if (divCeil(bits, 8) != X.cols())
			throw RTE_LOC;

		std::cout << name << " [\n";
		for (u64 i = 0; i < X.rows(); ++i)
		{
			for (u64 j = 0; j < bits; ++j)
			{
				auto b = *BitIterator(X[i].data(), j);
				if (b)
					std::cout << Color::Green;
				std::cout << b << " ";
				if (b)
					std::cout << Color::Default;
			}
			std::cout << "\n";
		}
		std::cout << "]\n";
	}


	void BinSolver_firstOneBit_test(const oc::CLP& cmd)
	{
		PRNG prng(block(3423345222341334, 2394871239472938));
		u64 trials = cmd.getOr("t", 1);

		//u64 m = cmd.getOr("m", 4);
		//u64 c = cmd.getOr("ssp", 8) + m;
		for (u64 c = 2; c < 20; ++c)
		{
			auto m = c / 2;

			for (u64 tt = 0; tt < trials; ++tt)
			{
				std::array<BinarySolver, 2> s;
				s[0].init(0, m, c, 10);
				s[1].init(1, m, c, 10);

				setBase(s);


				std::array<std::vector<u8>, 2> Mi{
					std::vector<u8>(divCeil(c, 8)),
					std::vector<u8>(divCeil(c, 8)) };
				std::array<std::vector<u8>, 2> r{
					std::vector<u8>(divCeil(c, 8)),
					std::vector<u8>(divCeil(c, 8)) };

				prng.get(Mi[0].data(), Mi[0].size());
				prng.get(Mi[1].data(), Mi[1].size());

				//u64 v = 0b11010100100001000;
				//copyBytesMin(Mi[0], v);
				//setBytes(Mi[1], 0);

				std::vector<u8> plainM(divCeil(c, 8));
				std::vector<u8> plainR(divCeil(c, 8));
				for (u64 i = 0; i < plainM.size(); ++i)
					plainM[i] = Mi[0][i] ^ Mi[1][i];

				//s[0].firstOneBit(plainM, plainR);

				auto sock = coproto::LocalAsyncSocket::makePair();
				auto res = macoro::sync_wait(macoro::when_all_ready(
					s[0].firstOneBit(Mi[0], r[0], sock[0]),
					s[1].firstOneBit(Mi[1], r[1], sock[1])
				));
				std::get<0>(res).result();
				std::get<1>(res).result();


				//std::cout << "m ";
				//for (u64 i = 0; i < c; ++i)
				//{
				//	auto mm0 = BitIterator((u8*)Mi[0].data(), i);
				//	auto mm1 = BitIterator((u8*)Mi[1].data(), i);
				//	std::cout << (*mm0 ^ *mm1) << " ";
				//}
				//std::cout << std::endl;
				//std::cout << "s ";
				//std::vector<u8> sv(c);
				//for (u64 i = 0; i < c; ++i)
				//{
				//	auto ss0 = BitIterator((u8*)r[0].data(), i);
				//	auto ss1 = BitIterator((u8*)r[1].data(), i);
				//	sv[i] = (*ss0 ^ *ss1);
				//	std::cout << (int)sv[i] << " ";
				//}
				//std::cout << std::endl;

				bool found = false;
				u64 cnt = 0;
				for (u64 i = 0; i < c; ++i)
				{
					auto mm0 = BitIterator((u8*)Mi[0].data(), i);
					auto mm1 = BitIterator((u8*)Mi[1].data(), i);
					auto ss0 = BitIterator((u8*)r[0].data(), i);
					auto ss1 = BitIterator((u8*)r[1].data(), i);

					auto ss = *ss0 ^ *ss1;
					auto mm = *mm0 ^ *mm1;
					cnt += ss;
					if (!found)
					{
						if (mm)
							found = true;

						if (ss != mm)
							throw std::runtime_error(LOCATION);
					}
					else
					{
						if (ss)
							throw std::runtime_error(LOCATION);
					}
				}

				if (cnt != u64(found))
					throw std::runtime_error(LOCATION);
			}
		}
	}



	void BinSolver_solve_test(const oc::CLP& cmd)
	{

		u64 t = cmd.getOr("t", 10);

		PRNG prng(block(3423345222341334, 2394871239472938));

		for (u64 tt = 0; tt < t; ++tt)
		{

			u64 m = cmd.getOr("m", 10);
			u64 c = cmd.getOr("ssp", 8) + m;
			u64 g = cmd.getOr("g", 2);
			//auto m8 = divCeil(m, 8);
			auto c8 = divCeil(c, 8);
			auto g8 = divCeil(g, 8);

			std::array<BinarySolver, 2> s;
			s[0].init(0, m, c, g);
			s[1].init(1, m, c, g);
			setBase(s);

			std::array<Matrix<u8>, 2> Ms;
			Ms[0].resize(m, c8);
			Ms[1].resize(m, c8);

			std::array<Matrix<u8>, 2> xs;
			xs[0].resize(c, g8);
			xs[1].resize(c, g8);
			std::array<Matrix<u8>, 2> ys;
			ys[0].resize(m, g8);
			ys[1].resize(m, g8);


			std::vector<u8> skips(m);
			for (u64 i = 0; i < m; ++i)
			{
				skips[i] = prng.get<u8>() % 2; // Randomly skip some rows
				if (skips[i] == 0)
				{
					for (u64 j = 0; j < c; ++j)
					{
						*BitIterator(Ms[0][i].data(), j) = prng.getBit();
						*BitIterator(Ms[1][i].data(), j) = prng.getBit();
					}
				}


				for (u64 j = 0; j < g; ++j)
				{
					*BitIterator(ys[0][i].data(), j) = prng.getBit();
					*BitIterator(ys[1][i].data(), j) = prng.getBit();
				}
			}



			Matrix<u8> M(m, c8);
			for (auto i = 0ull; i < M.size(); ++i)
				M(i) = Ms[0](i) ^ Ms[1](i);
			Matrix<u8> y(m, g8);
			for (u64 i = 0; i < m; ++i)
			{
				if (skips[i])
					continue;

				for (u64 j = 0; j < y.cols(); ++j)
					y(i, j) = ys[0](i, j) ^ ys[1](i, j);
			}

			auto sock = coproto::LocalAsyncSocket::makePair();
			auto r = macoro::sync_wait(macoro::when_all_ready(
				s[0].solve(Ms[0], ys[0], xs[0], prng, sock[0]),
				s[1].solve(Ms[1], ys[1], xs[1], prng, sock[1])
			));

			std::get<0>(r).result();
			std::get<1>(r).result();

			Matrix<u8> x(c, g8);
			for (u64 i = 0; i < c; ++i)
				for (u64 j = 0; j < x.cols(); ++j)
					x(i, j) = xs[0](i, j) ^ xs[1](i, j);

			Matrix<u8> act(m, g8);
			for (u64 i = 0; i < m; ++i)
			{

				for (u64 j = 0; j < g; ++j)
				{
					//a[i,*] * b[*,j] = c[i,j]
					for (u64 l = 0; l < c; ++l)
					{
						*BitIterator(act[i].data(), j) ^=
							(*BitIterator(M[i].data(), l) &
								*BitIterator(x[l].data(), j));
					}
				}
			}

			if (act != y)
			{
				printMtx(c, M, "M");
				printMtx(1, x, "x");
				printMtx(8, act, "act");
				printMtx(8, y, "y");

				throw RTE_LOC;
			}
		}
	}

	void RevCuckoo_Proto_Test(const oc::CLP& cmd)
	{

		//using F = block;

		//// Initialize parameters
		//PRNG prng(block(231234, 321312));
		//u64 domain = cmd.getOr("domain", 32); // Domain size
		//u64 numPoints = cmd.getOr("numPoints", 4); // Number of points
		//u64 numSets = cmd.getOr("numSets", 1); // Number of sets
		//u64 numPartitions = cmd.getOr("numPartitions", 2); // Number of partitions
		//u64 linearSecParam = cmd.getOr("linearSecParam", 40); // Security parameter
		//u64 cuckooSecParam = cmd.getOr("cuckooSecParam", 2); // Cuckoo security parameter
		//bool print = cmd.isSet("print"); // Print flag

		//// Generate input points and values
		//std::vector<u64> points0(numPoints);
		//std::vector<u64> points1(numPoints);
		//std::vector<block> values0(numPoints);
		//std::vector<block> values1(numPoints);
		//std::unordered_map<u64, block> expMap;
		//for (u64 i = 0; i < numPoints; ++i)
		//{
		//	points1[i] = prng.get<u64>();
		//	points0[i] = (prng.get<u64>() % domain) ^ points1[i];
		//	values0[i] = prng.get();
		//	values1[i] = prng.get();
		//	auto p = points0[i] ^ points1[i];
		//	auto v = values0[i] ^ values1[i];
		//	expMap[p] = v;

		//	//std::cout << std::setw(4) << p << " | " << v << std::endl;
		//}
		////std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
		//auto ctx = DefaultCoeffCtx<F>{};

		//// Initialize RevCuckooDmpf instances
		//std::array<RevCuckooDmpf<F>, 2> dpf;
		//dpf[0].init(0, numPoints, numSets, domain, ctx, numPartitions, cuckooSecParam, linearSecParam);
		//dpf[1].init(1, numPoints, numSets, domain,ctx, numPartitions, cuckooSecParam, linearSecParam);
		//dpf[0].mPrint = print;
		//dpf[1].mPrint = print;

		//// Setup base OTs
		//auto baseCount0 = dpf[0].baseOtCount();
		//auto baseCount1 = dpf[1].baseOtCount();
		//std::array<std::vector<block>, 2> baseRecv;
		//std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		//std::array<BitVector, 2> baseChoice;
		//baseRecv[0].resize(baseCount0.mRecvCount);
		//baseRecv[1].resize(baseCount1.mRecvCount);
		//baseSend[0].resize(baseCount0.mSendCount);
		//baseSend[1].resize(baseCount1.mSendCount);
		//baseChoice[0].resize(baseCount0.mRecvCount);
		//baseChoice[1].resize(baseCount1.mRecvCount);
		//baseChoice[0].randomize(prng);
		//baseChoice[1].randomize(prng);
		//for (u64 i = 0; i < baseCount0.mRecvCount; ++i)
		//{
		//	baseSend[1][i] = prng.get();
		//	baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		//}
		//for (u64 i = 0; i < baseCount1.mRecvCount; ++i)
		//{
		//	baseSend[0][i] = prng.get();
		//	baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		//}
		//dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		//dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		//// Prepare output matrices
		//std::array<std::vector<block>, 2> output;
		//output[0].resize(domain);
		//output[1].resize(domain);


		//// Create sockets for communication
		//auto sock = coproto::LocalAsyncSocket::makePair();

		//// Expand the protocol
		//macoro::sync_wait(macoro::when_all_ready(
		//	dpf[0].expand(points0, values0, [&](auto i, auto v) { output[0][i] = v; }, prng, sock[0]),
		//	dpf[1].expand(points1, values1, [&](auto i, auto v) { output[1][i] = v; }, prng, sock[1])
		//));

		//// Verify the output
		//for (u64 i = 0; i < numPoints; ++i)
		//{
		//	auto iter = expMap.find(i);
		//	auto act = output[0][i] ^ output[1][i];
		//	auto exp = iter == expMap.end() ? ZeroBlock : iter->second;
		//	if (act != exp)
		//	{
		//		std::cout << "i " << i << std::endl;
		//		std::cout << "act " << act << std::endl;
		//		std::cout << "exp " << exp << std::endl;

		//		throw RTE_LOC;
		//	}
		//}

	}

	template<typename F, typename CoeffCtx>
	void RevCuckoo_iterative_impl(const oc::CLP& cmd)
	{
		// Initialize parameters
		PRNG prng(block(231234, 321312));
		u64 domain = cmd.getOr("domain", 32); // Domain size
		u64 numPoints = cmd.getOr("numPoints", 4); // Number of points
		u64 numSets = cmd.getOr("numSets", 6); // Number of sets
		u64 numPartitions = cmd.getOr("numPartitions", 2); // Number of partitions
		u64 linearSecParam = cmd.getOr("linearSecParam", 40); // Security parameter
		u64 cuckooSecParam = cmd.getOr("cuckooSecParam", 2); // Cuckoo security parameter
		u64 numValueSets = cmd.getOr("numValueSets", 3); // Number of different value sets to test
		bool print = cmd.isSet("print"); // Print flag
		bool printTimer = cmd.isSet("printTimer"); // Print timer flag

		Timer timer[2];

		// Generate input points (fixed for all iterations)
		Matrix<u64> points0(numSets, numPoints);
		Matrix<u64> points1(numSets, numPoints);
		Matrix<u64> actualPoints(numSets, numPoints);
		for (u64 i = 0; i < points1.size(); ++i)
		{
			points1(i) = prng.get<u64>();
			points0(i) = (prng.get<u64>() % domain) ^ points1(i);
			actualPoints(i) = points0(i) ^ points1(i);
		}

		auto ctx = CoeffCtx{};

		// Initialize RevCuckooDmpf instances
		std::array<RevCuckooDmpf<F>, 2> dpf;
		dpf[0].init(0, numPoints, numSets, domain, numPartitions, cuckooSecParam, linearSecParam);
		dpf[1].init(1, numPoints, numSets, domain, numPartitions, cuckooSecParam, linearSecParam);
		dpf[0].mPrint = print;
		dpf[1].mPrint = print;
		dpf[0].setTimer(timer[0]);
		dpf[1].setTimer(timer[1]);

		if (cmd.hasValue("print"))
		{
			dpf[0].mPrintIndex = cmd.getOr("print", 0);
			dpf[1].mPrintIndex = cmd.getOr("print", 0);
		}

		// Setup base OTs
		auto baseCount0 = dpf[0].baseOtCount();
		auto baseCount1 = dpf[1].baseOtCount();
		std::array<std::vector<block>, 2> baseRecv;
		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<BitVector, 2> baseChoice;
		baseRecv[0].resize(baseCount0.mRecvCount);
		baseRecv[1].resize(baseCount1.mRecvCount);
		baseSend[0].resize(baseCount0.mSendCount);
		baseSend[1].resize(baseCount1.mSendCount);
		baseChoice[0].resize(baseCount0.mRecvCount);
		baseChoice[1].resize(baseCount1.mRecvCount);
		baseChoice[0].randomize(prng);
		baseChoice[1].randomize(prng);
		for (u64 i = 0; i < baseCount0.mRecvCount; ++i)
		{
			baseSend[1][i] = prng.get();
			baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		}
		for (u64 i = 0; i < baseCount1.mRecvCount; ++i)
		{
			baseSend[0][i] = prng.get();
			baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		}
		dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		// Create sockets for communication
		auto sock = coproto::LocalAsyncSocket::makePair();
		//sock[0].enableLogging();
		//sock[1].enableLogging();

		// Phase 1: Setup points (called once)
		if (print)
		{
			std::cout << "Setting up points..." << std::endl;
		}
		auto r = macoro::sync_wait(macoro::when_all_ready(
			dpf[0].setPoints(points0, prng, sock[0]),
			dpf[1].setPoints(points1, prng, sock[1])
		));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// verify that the internal shares are correct.
		for (u64 s = 0, k = 0; s < numSets; ++s)
		{
			u64 f = dpf[0].mLeafShares.size() / numSets;
			std::set<u64> active;
			// Verify the output for this iteration
			for (u64 i = 0; i < f; ++i, ++k)
			{
				u64 unit = 0;
				for (u64 j = 0; j < dpf[0].mLeafShares[k].size(); ++j)
				{
					auto val = dpf[0].mLeafShares[k][j] ^ dpf[1].mLeafShares[k][j];
					bool tag = dpf[0].mLeafTags[k][j] ^ dpf[1].mLeafTags[k][j];

					if (val != ZeroBlock)
					{
						active.insert(dpf[0].mSparseSets[k][j]);
						++unit;
					}

					if ((val != ZeroBlock) != bool(tag))
						throw RTE_LOC;
				}

				if (unit > 1)
					throw RTE_LOC;
			}

			//if (active.size() < numPoints)
			//	throw RTE_LOC;

			for (auto p : actualPoints[s])
			{
				if (active.find(p) == active.end())
				{
					std::cout << "Point " << p << " not found in leaf shares." << std::endl;
					throw RTE_LOC;
				}
			}
		}

		// Phase 2: Multiple value expansions (called multiple times)
		for (u64 iteration = 0; iteration < numValueSets; ++iteration)
		{
			if (print)
			{
				std::cout << "Iteration " << iteration + 1 << " of " << numValueSets << std::endl;
			}

			// Generate different values for each iteration
			std::vector<F> values0(numPoints * numSets);
			std::vector<F> values1(numPoints * numSets);
			for (u64 i = 0; i < values1.size(); ++i)
			{
				values0[i] = prng.get();
				values1[i] = prng.get();
			}

			// Prepare output matrices for this iteration
			std::array<Matrix<F>, 2> output;
			output[0].resize(numSets, domain);
			output[1].resize(numSets, domain);

			// Expand values using the cached point setup
			auto r = macoro::sync_wait(macoro::when_all_ready(
				dpf[0].expand(values0, prng, sock[0], [&](auto j, auto i, auto v) { output[0](j, i) = v; }),
				dpf[1].expand(values1, prng, sock[1], [&](auto j, auto i, auto v) { output[1](j, i) = v; })
			));
			std::get<0>(r).result();
			std::get<1>(r).result();
			F zero;
			ctx.zero(zero);

			for (u64 s = 0; s < numSets; ++s)
			{
				std::unordered_map<u64, F> expectedMap;

				for (u64 i = 0; i < numPoints; ++i)
				{
					auto p = actualPoints[s][i];
					F v;
					ctx.plus(v, values0[s * numPoints + i], values1[s * numPoints + i]);
					ctx.plus(expectedMap[p], expectedMap[p], v);
				}


				// Verify the output for this iteration
				bool allCorrect = true;
				for (u64 i = 0; i < domain && allCorrect; ++i)
				{
					auto iter = expectedMap.find(i);
					F actual;
					ctx.plus(actual, output[0](s, i), output[1](s, i));

					auto expected = iter == expectedMap.end()
						? zero : iter->second;

					if (actual != expected)
					{
						allCorrect = false;
						//std::cout << "Iteration " << iteration << " failed at set "<<s<<", domain point " << i << std::endl;
						//std::cout << "Expected: " << expected << std::endl;
						//std::cout << "Actual: " << actual << std::endl;

						//// Show which input points map to this domain position
						//for (u64 j = 0; j < numPoints; ++j)
						//{
						//	if (actualPoints[s][j] == i)
						//	{
						//		std::cout << "Input point " << j << " maps to domain position " << i
						//			<< " with value " << (values0[j] ^ values1[j]) << std::endl;
						//	}
						//}
						//throw RTE_LOC;
					}
				}
				if (!allCorrect)
				{
					std::cout << "Iteration " << iteration + 1 << " failed verification for set " << s << std::endl;
					for (u64 i = 0; i < domain; ++i)
					{
						auto iter = expectedMap.find(i);
						F actual, neg;
						ctx.plus(actual, output[0](s, i), output[1](s, i));
						auto expected = iter == expectedMap.end() ? zero : iter->second;
						ctx.minus(neg, zero, expected);

						if (actual != expected)
							std::cout << Color::Red;
						std::cout << i << ": Exp " << expected << ", Act " << actual
							<< " = " << output[0](s, i) << " + " << output[1](s, i)
							<< ", negExp " << neg
							<< std::endl << Color::Default;
					}
					throw RTE_LOC;
				}
			}

		}


		if (printTimer)
		{
			for (u64 i = 0; i < 2; ++i)
			{
				std::cout << "Dpf " << i << " time: \n" << timer[i] << std::endl;
			}
		}

	}
	void RevCuckoo_iterative_Test(const oc::CLP& cmd)
	{
		RevCuckoo_iterative_impl<block, CoeffCtxGF128>(cmd);
		RevCuckoo_iterative_impl<u64, CoeffCtxInteger>(cmd);
	}



	void Goldreich_Proto_Test(const oc::CLP& cmd)
	{

		std::array<GoldreichHash, 2> hash;
		u64 n = 100; // Increased sample size for better statistical analysis
		u64 in = 8;  // Increased input size
		u64 out = 16; // Increased output size for better testing
		//bool v = cmd.isSet("v");
		//auto inBits = in * 8;
		//auto outBits = out * 8;

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
		//auto inBits = in * 8;
		auto outBits = out * 8;

		hash.init(0, n, in, out);
		block seed = block(2342143213662143, 4352452314532765);

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
			for (u64 j = 0; j < std::min<u64>(n, 10ull); ++j)
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
				u8 xorByte = rOut(i, j);
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
			std::cout << "Critical Value (a=0.05): " << chiSquareCritical << std::endl;
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
		//double bitChiSquare = 0.0;
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

		// We expect about 5% of bits to fail by random chance (at a=0.05)
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
}
