#include "BinarySolver_Tests.h"
#include "libOTe/Dpf/RevCuckoo/BinarySolver.h"

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
		//PRNG prng(block(3423345222341334, 2394871239472938));
		//u64 trials = cmd.getOr("t", 1);

		////u64 m = cmd.getOr("m", 4);
		////u64 c = cmd.getOr("ssp", 8) + m;
		//for (u64 c = 2; c < 20; ++c)
		//{
		//	auto c8 = divCeil(c, 8);
		//	auto m = c / 2;

		//	for (u64 tt = 0; tt < trials; ++tt)
		//	{
		//		std::array<BinarySolver, 2> s;
		//		s[0].init(0, m, c, 10);
		//		s[1].init(1, m, c, 10);

		//		setBase(s);


		//		std::array<std::vector<u8>, 2> Mi{
		//			std::vector<u8>(c8),
		//			std::vector<u8>(c8) };
		//		std::array<std::vector<u8>, 2> r{
		//			std::vector<u8>(c8),
		//			std::vector<u8>(c8) };

		//		prng.get(Mi[0].data(), Mi[0].size());
		//		prng.get(Mi[1].data(), Mi[1].size());

		//		//u64 v = 0b11010100100001000;
		//		//copyBytesMin(Mi[0], v);
		//		//setBytes(Mi[1], 0);

		//		std::vector<u8> plainM(c8);
		//		std::vector<u8> plainR(c8);
		//		for (u64 i = 0; i < c8; ++i)
		//			plainM[i] = Mi[0][i] ^ Mi[1][i];

		//		//s[0].firstOneBit(plainM, plainR);

		//		auto sock = coproto::LocalAsyncSocket::makePair();
		//		auto res = macoro::sync_wait(macoro::when_all_ready(
		//			s[0].firstOneBit(Mi[0], r[0], sock[0]),
		//			s[1].firstOneBit(Mi[1], r[1], sock[1])
		//		));
		//		std::get<0>(res).result();
		//		std::get<1>(res).result();


		//		//std::cout << "m ";
		//		//for (u64 i = 0; i < c; ++i)
		//		//{
		//		//	auto mm0 = BitIterator((u8*)Mi[0].data(), i);
		//		//	auto mm1 = BitIterator((u8*)Mi[1].data(), i);
		//		//	std::cout << (*mm0 ^ *mm1) << " ";
		//		//}
		//		//std::cout << std::endl;
		//		//std::cout << "s ";
		//		//std::vector<u8> sv(c);
		//		//for (u64 i = 0; i < c; ++i)
		//		//{
		//		//	auto ss0 = BitIterator((u8*)r[0].data(), i);
		//		//	auto ss1 = BitIterator((u8*)r[1].data(), i);
		//		//	sv[i] = (*ss0 ^ *ss1);
		//		//	std::cout << (int)sv[i] << " ";
		//		//}
		//		//std::cout << std::endl;

		//		bool found = false;
		//		u64 cnt = 0;
		//		for (u64 i = 0; i < c; ++i)
		//		{
		//			auto mm0 = BitIterator((u8*)Mi[0].data(), i);
		//			auto mm1 = BitIterator((u8*)Mi[1].data(), i);
		//			auto ss0 = BitIterator((u8*)r[0].data(), i);
		//			auto ss1 = BitIterator((u8*)r[1].data(), i);

		//			auto ss = *ss0 ^ *ss1;
		//			auto mm = *mm0 ^ *mm1;
		//			cnt += ss;
		//			if (!found)
		//			{
		//				if (mm)
		//					found = true;

		//				if (ss != mm)
		//					throw std::runtime_error(LOCATION);
		//			}
		//			else
		//			{
		//				if (ss)
		//					throw std::runtime_error(LOCATION);
		//			}
		//		}

		//		if (cnt != u64(found))
		//			throw std::runtime_error(LOCATION);
		//	}
		//}
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
				s[0].solveOne(Ms[0], ys[0], xs[0], prng, sock[0]),
				s[1].solveOne(Ms[1], ys[1], xs[1], prng, sock[1])
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

	void BinSolver_firstOneBitMany_test(const oc::CLP& cmd)
	{
		PRNG prng(block(111, 222));
		u64 trials = cmd.getOr("t", 1);
		u64 batch = cmd.getOr("batch", 4);

		for (u64 c = 2; c <= 32; c += 7)
		{
			auto c8 = divCeil(c, 8);
			auto m = std::max<u64>(1, c / 2);

			for (u64 tt = 0; tt < trials; ++tt)
			{
				std::array<BinarySolver, 2> s;
				// init with batch
				s[0].init(0, m, c, /*logG*/ 8, batch);
				s[1].init(1, m, c, /*logG*/ 8, batch);
				setBase(s);

				// Prepare batch matrices Mi per instance (m rows x c8 bytes)
				std::vector<Matrix<u8>> Mi0(batch), Mi1(batch);
				for (u64 b = 0; b < batch; ++b)
				{
					Mi0[b].resize(m, c8);
					Mi1[b].resize(m, c8);
					for (u64 i = 0; i < m; ++i)
					{
						// Randomize each row
						prng.get(Mi0[b][i].data(), c8);
						prng.get(Mi1[b][i].data(), c8);
					}
				}

				// For each row i, run the batched firstOneBit which extracts row i internally
				for (u64 i = 0; i < m; i+= 5)
				{
					// Output selection vectors per instance; store as 1 x c8 (a single row)
					std::vector<Matrix<u8>> r0(batch), r1(batch);
					for (u64 b = 0; b < batch; ++b)
					{
						r0[b].resize(m, c8);
						r1[b].resize(m, c8);
						setBytes(r0[b], 0);
						setBytes(r1[b], 0);
					}

					auto sock = coproto::LocalAsyncSocket::makePair();
					auto res = macoro::sync_wait(macoro::when_all_ready(
						s[0].firstOneBit(i, Mi0, r0, sock[0]),
						s[1].firstOneBit(i, Mi1, r1, sock[1])
					));
					std::get<0>(res).result();
					std::get<1>(res).result();

					// Verify each instance: r = first-one-hot(Mi0[i] ^ Mi1[i])
					for (u64 b = 0; b < batch; ++b)
					{
						bool found = false;
						u64 cnt = 0;
						for (u64 bitIdx = 0; bitIdx < c; ++bitIdx)
						{
							// Input bit for this instance/row
							auto mm0 = BitIterator(Mi0[b][i].data(), bitIdx);
							auto mm1 = BitIterator(Mi1[b][i].data(), bitIdx);
							auto mm = (*mm0) ^ (*mm1);

							// Output bit (selection) produced for this instance; row is 0 since we used 1 x c8
							auto ss0 = BitIterator(r0[b][i].data(), bitIdx);
							auto ss1 = BitIterator(r1[b][i].data(), bitIdx);
							auto ss = (*ss0) ^ (*ss1);

							cnt += ss;

							if (!found)
							{
								if (mm) found = true;
								if (ss != mm) throw RTE_LOC;
							}
							else
							{
								if (ss) throw RTE_LOC;
							}
						}
						if (cnt != u64(found)) throw RTE_LOC;
					}

					for (u64 b = 0; b < batch; ++b)
					{
						std::vector<u8> s0(c8), s1(c8);

						auto res = macoro::sync_wait(macoro::when_all_ready(
							s[0].firstOneBit(Mi0[b][i], s0, sock[0]),
							s[1].firstOneBit(Mi1[b][i], s1, sock[1])
						));
						std::get<0>(res).result();
						std::get<1>(res).result();

						for (u64 j = 0; j < c8; ++j)
						{
							auto exp = s0[j] ^ s1[j];
							auto act = r0[b][i][j] ^ r1[b][i][j];
							if (exp != act)
								throw RTE_LOC;
						}

					}

				}
			}
		}
	}

	void BinSolver_multiplyMany_test(const oc::CLP& cmd)
	{
		PRNG prng(block(333, 444));
		u64 m = cmd.getOr("rows", 17);
		u64 bitCount = cmd.getOr("bits", 11);
		u64 batch = cmd.getOr("batch", 3);

		std::array<BinarySolver, 2> s;
		// init batch. m acts as number of rows; cols/logG are irrelevant here but keep consistent.
		s[0].init(0, /*m*/ m, /*c*/ m + 8, /*logG*/ (u64)std::max<u64>(8, bitCount), batch);
		s[1].init(1, /*m*/ m, /*c*/ m + 8, /*logG*/ (u64)std::max<u64>(8, bitCount), batch);
		setBase(s);

		auto k8 = divCeil(bitCount, 8);

		// Build batch of instances
		std::vector<std::vector<u8>> a(batch), a0(batch), a1(batch);
		std::vector<Matrix<u8>> b(batch), b0(batch), b1(batch), c0(batch), c1(batch);

		for (u64 i = 0; i < batch; ++i)
		{
			auto m8 = divCeil(m, 8);
			a[i].resize(m8);
			a0[i].resize(m8);
			a1[i].resize(m8);
			prng.get(a[i].data(), a[i].size());
			prng.get(a0[i].data(), a0[i].size());
			for (u64 j = 0; j < m8; ++j)
				a1[i][j] = a[i][j] ^ a0[i][j];

			b[i].resize(m, k8);
			b0[i].resize(m, k8);
			b1[i].resize(m, k8);
			c0[i].resize(m, k8);
			c1[i].resize(m, k8);

			for (u64 r = 0; r < m; ++r)
			{
				for (u64 j = 0; j < bitCount; ++j)
				{
					*BitIterator(b[i][r].data(), j) = prng.getBit();
					*BitIterator(b0[i][r].data(), j) = prng.getBit();
				}
				for (u64 j = 0; j < k8; ++j)
					b1[i](r, j) = b[i](r, j) ^ b0[i](r, j);
			}
		}

		auto sock = coproto::LocalAsyncSocket::makePair();
		auto r = macoro::sync_wait(macoro::when_all_ready(
			s[0].multiplyMany(bitCount, a0, b0, c0, sock[0]),
			s[1].multiplyMany(bitCount, a1, b1, c1, sock[1])
		));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// Verify each instance
		for (u64 bIdx = 0; bIdx < batch; ++bIdx)
		{
			Matrix<u8> act(m, k8), exp(m, k8);
			for (u64 i = 0; i < m; ++i)
			{
				for (u64 j = 0; j < k8; ++j)
				{
					act(i, j) = c0[bIdx](i, j) ^ c1[bIdx](i, j);
				}
			}
			for (u64 i = 0; i < m; ++i)
			{
				auto ai = bit(a[bIdx], i);
				for (u64 j = 0; j < k8; ++j)
					exp(i, j) = ai ? b[bIdx](i, j) : 0;
			}
			if (act != exp) 
				throw RTE_LOC;
		}
	}

	void BinSolver_multiplyMtxMany_test(const oc::CLP& cmd)
	{
		PRNG prng(block(555, 666));
		u64 t = cmd.getOr("t", 5);
		u64 batch = cmd.getOr("batch", 3);

		struct Param { u64 m, n, k; };
		std::vector<Param> cases = {
			{10,10,10}, {10,20,10}, {20,10,10}, {20,20,10}, {10,20,20}, {20,10,20}
		};

		for (auto p : cases)
		{
			auto m = p.m, n = p.n, k = p.k;
			auto m8 = divCeil(m, 8);
			auto k8 = divCeil(k, 8);

			for (u64 tt = 0; tt < t; ++tt)
			{
				std::array<BinarySolver, 2> s;
				// Initialize DpfMult for the exact #OTs used by multiplyMtx (like original test)
				auto numOts = std::min<u64>(n * m, m * k) * batch;
				s[0].mMult.init(0, numOts);
				s[1].mMult.init(1, numOts);

				// Base OTs
				auto baseCount = s[0].mMult.baseOtCount();
				std::vector<block> baseRecv(baseCount);
				std::vector<std::array<block, 2>> baseSend(baseCount);
				BitVector baseChoice(baseCount);
				baseChoice.randomize(prng);
				for (u64 i = 0; i < baseCount; ++i)
				{
					baseSend[i][0] = prng.get();
					baseSend[i][1] = prng.get();
					baseRecv[i] = baseSend[i][baseChoice[i]];
				}
				s[0].mBatchSize = batch;
				s[1].mBatchSize = batch;
				s[0].mMult.setBaseOts(baseSend, baseRecv, baseChoice);
				s[1].mMult.setBaseOts(baseSend, baseRecv, baseChoice);

				// Build batch instances
				std::vector<Matrix<u8>> A(batch), A0(batch), A1(batch);
				std::vector<Matrix<u8>> B(batch), B0(batch), B1(batch), C0(batch), C1(batch);
				for (u64 b = 0; b < batch; ++b)
				{
					A[b].resize(n, m8);
					A0[b].resize(n, m8);
					A1[b].resize(n, m8);
					B[b].resize(m, k8);
					B0[b].resize(m, k8);
					B1[b].resize(m, k8);
					C0[b].resize(n, k8);
					C1[b].resize(n, k8);

					for (u64 i = 0; i < n; ++i)
					{
						for (u64 l = 0; l < m; ++l)
						{
							*BitIterator(A[b][i].data(), l) = prng.getBit();
							*BitIterator(A0[b][i].data(), l) = prng.getBit();
						}
						for (u64 j = 0; j < A[b].cols(); ++j)
							A1[b](i, j) = A[b](i, j) ^ A0[b](i, j);
					}
					for (u64 i = 0; i < m; ++i)
					{
						for (u64 j = 0; j < k; ++j)
						{
							*BitIterator(B[b][i].data(), j) = prng.getBit();
							*BitIterator(B0[b][i].data(), j) = prng.getBit();
						}
						for (u64 j = 0; j < B[b].cols(); ++j)
							B1[b](i, j) = B[b](i, j) ^ B0[b](i, j);
					}
				}

				// Build lists
				std::vector<MatrixView<const u8>> A0List, A1List, B0List, B1List;
				std::vector<MatrixView<u8>> C0List, C1List;
				for (u64 b = 0; b < batch; ++b)
				{
					A0List.emplace_back(A0[b]); A1List.emplace_back(A1[b]);
					B0List.emplace_back(B0[b]); B1List.emplace_back(B1[b]);
					C0List.emplace_back(C0[b]); C1List.emplace_back(C1[b]);
				}

				auto sock = coproto::LocalAsyncSocket::makePair();
				auto rr = macoro::sync_wait(macoro::when_all_ready(
					s[0].multiplyMtxMany(k, A0List, B0List, C0List, sock[0]),
					s[1].multiplyMtxMany(k, A1List, B1List, C1List, sock[1])
				));
				std::get<0>(rr).result();
				std::get<1>(rr).result();

				// Verify each instance
				for (u64 b = 0; b < batch; ++b)
				{
					Matrix<u8> act(n, k8), exp(n, k8);
					for (u64 i = 0; i < n; ++i)
						for (u64 j = 0; j < k8; ++j)
							act(i, j) = C0[b](i, j) ^ C1[b](i, j);

					for (u64 i = 0; i < n; ++i)
						for (u64 j = 0; j < k; ++j)
							for (u64 l = 0; l < m; ++l)
								*BitIterator(exp[i].data(), j) ^= (*BitIterator(A[b][i].data(), l) &
									*BitIterator(B[b][l].data(), j));

					if (act != exp) throw RTE_LOC;
				}
			}
		}
	}

	void BinSolver_solveMany_test(const oc::CLP& cmd)
	{
		PRNG prng(block(777, 888));
		u64 t = cmd.getOr("t", 5);
		u64 batch = cmd.getOr("batch", 3);

		for (u64 tt = 0; tt < t; ++tt)
		{
			u64 m = cmd.getOr("m", 10);
			u64 c = cmd.getOr("ssp", 8) + m;
			u64 g = cmd.getOr("g", 4);
			auto c8 = divCeil(c, 8);
			auto g8 = divCeil(g, 8);

			std::array<BinarySolver, 2> s;
			s[0].init(0, m, c, g, batch);
			s[1].init(1, m, c, g, batch);
			setBase(s);

			// Build batch clear problems
			std::vector<Matrix<u8>> M(batch), X(batch), Y(batch);
			for (u64 b = 0; b < batch; ++b)
			{
				M[b].resize(m, c8);
				X[b].resize(c, g8);
				Y[b].resize(m, g8);

				prng.get(M[b].data(), M[b].size());
				prng.get(X[b].data(), X[b].size());
				if (g % 8)
				{
					u8 mask = (1 << (g % 8)) - 1;
					for (u64 i = 0; i < c; ++i) X[b][i].back() &= mask;
				}

				// Y = M * X
				setBytes(Y[b], 0);
				for (u64 i = 0; i < m; ++i)
					for (u64 j = 0; j < g; ++j)
						for (u64 l = 0; l < c; ++l)
							*BitIterator(Y[b][i].data(), j) ^= (*BitIterator(M[b][i].data(), l) &
								*BitIterator(X[b][l].data(), j));
			}

			// Share inputs per batch
			std::vector<Matrix<u8>> M0(batch), M1(batch), Y0(batch), Y1(batch), X0(batch), X1(batch);
			for (u64 b = 0; b < batch; ++b)
			{
				M0[b].resize(m, c8); M1[b].resize(m, c8);
				Y0[b].resize(m, g8); Y1[b].resize(m, g8);
				X0[b].resize(c, g8); X1[b].resize(c, g8); // outputs

				prng.get(M0[b].data(), M0[b].size());
				for (u64 i = 0; i < M[b].size(); ++i) M1[b](i) = M[b](i) ^ M0[b](i);

				prng.get(Y0[b].data(), Y0[b].size());
				for (u64 i = 0; i < Y[b].size(); ++i) Y1[b](i) = Y[b](i) ^ Y0[b](i);

				setBytes(X0[b], 0);
				setBytes(X1[b], 0);
			}

			// Views for batched call
			std::vector<MatrixView<const u8>> M0v, M1v, Y0v, Y1v;
			std::vector<MatrixView<u8>> X0v, X1v;
			for (u64 b = 0; b < batch; ++b)
			{
				M0v.emplace_back(M0[b]); M1v.emplace_back(M1[b]);
				Y0v.emplace_back(Y0[b]); Y1v.emplace_back(Y1[b]);
				X0v.emplace_back(X0[b]); X1v.emplace_back(X1[b]);
			}

			auto sock = coproto::LocalAsyncSocket::makePair();
			auto r = macoro::sync_wait(macoro::when_all_ready(
				s[0].solve(M0v, Y0v, X0v, prng, sock[0]),
				s[1].solve(M1v, Y1v, X1v, prng, sock[1])
			));
			std::get<0>(r).result();
			std::get<1>(r).result();

			// Verify per instance
			for (u64 b = 0; b < batch; ++b)
			{
				Matrix<u8> Xrec(c, g8);
				for (u64 i = 0; i < Xrec.size(); ++i) Xrec(i) = X0[b](i) ^ X1[b](i);

				Matrix<u8> Ychk(m, g8);
				setBytes(Ychk, 0);
				for (u64 i = 0; i < m; ++i)
					for (u64 j = 0; j < g; ++j)
						for (u64 l = 0; l < c; ++l)
							*BitIterator(Ychk[i].data(), j) ^= (*BitIterator(M[b][i].data(), l) &
								*BitIterator(Xrec[l].data(), j));

				if (Ychk != Y[b]) throw RTE_LOC;
			}
		}
	}

}