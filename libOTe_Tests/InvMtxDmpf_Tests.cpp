#include "InvMtxDmpf_Tests.h"
#include "libOTe/Dpf/InvMtxDmpf/BinarySolver.h"

namespace osuCrypto
{


	void BinSolver_multiply_test(const oc::CLP& cmd)
	{
		u64 m = 19;
		u64 cc = 40 + m;
		u64 bitCount = 11;
		BinarySolver s[2];
		s[0].init(0, m, cc, 10);
		s[1].init(1, m, cc, 10);

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
		u64 m = cmd.getOr("m", 10);
		u64 n = cmd.getOr("n", 10);
		u64 k = cmd.getOr("k", 10);;
		u64 t = cmd.getOr("t", 10);

		auto m8 = divCeil(m, 8);
		auto n8 = divCeil(n, 8);
		auto k8 = divCeil(k, 8);

		PRNG prng(block(3423345222341334, 2394871239472938));

		for (u64 tt = 0; tt < t; ++tt)
		{


			BinarySolver s[2];
			u64 cc = 40 + m;
			s[0].init(0, m, cc, 10);
			s[1].init(1, m, cc, 10);



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

	void printMtx(u64 bits, MatrixView<u8> X, std::string name)
	{
		if (divCeil(bits, 8) != X.cols())
			throw RTE_LOC;

		std::cout << name<<" [\n";
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

	void BinSolver_solve_test(const oc::CLP& cmd)
	{

		u64 t = cmd.getOr("t", 10);

		PRNG prng(block(3423345222341334, 2394871239472938));

		for (u64 tt = 0; tt < t; ++tt)
		{

			u64 m = cmd.getOr("m", 10);
			u64 c = cmd.getOr("ssp", 8) + m;
			auto g = 1;
			auto m8 = divCeil(m, 8);
			auto c8 = divCeil(c, 8);
			auto g8 = divCeil(g, 8);

			BinarySolver s[2];
			s[0].init(0, m, c, g);
			s[1].init(1, m, c, g);

			std::array<Matrix<u8>, 2> Ms;
			Ms[0].resize(m, c8);
			Ms[1].resize(m, c8);

			std::array<Matrix<u8>, 2> xs;
			xs[0].resize(c, g8);
			xs[1].resize(c, g8);
			std::array<Matrix<u8>, 2> ys;
			ys[0].resize(m, g8);
			ys[1].resize(m, g8);

			if (tt == 0)
			{
				for (u64 i = 0; i < m; ++i)
				{
					for (u64 j = 0; j < m; ++j)
					{
						*BitIterator(Ms[0][i].data(), j) = i == j;
					}
				}
				setBytes(Ms[1], 0);
			}
			else
			{

				for (u64 i = 0; i < m; ++i)
				{
					for (u64 j = 0; j < c; ++j)
					{
						*BitIterator(Ms[0][i].data(), j) = prng.getBit();
						*BitIterator(Ms[1][i].data(), j) = prng.getBit();
					}


					for (u64 j = 0; j < g; ++j)
					{
						*BitIterator(ys[0][i].data(), j) = prng.getBit();
						*BitIterator(ys[1][i].data(), j) = prng.getBit();
					}
				}
			}


			Matrix<u8> M(m, c8);
			for (auto i = 0; i < M.size(); ++i)
				M(i) = Ms[0](i) ^ Ms[1](i);
			Matrix<u8> y(m, g8);
			for (u64 i = 0; i < m; ++i)
				for (u64 j = 0; j < y.cols(); ++j)
					y(i, j) = ys[0](i, j) ^ ys[1](i, j);

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


	void BinSolver_firstOneBit_test(const oc::CLP& cmd)
	{
		PRNG prng(block(3423345222341334, 2394871239472938));
		u64 trials = cmd.getOr("t",1);

		for (u64 tt = 0; tt < trials; ++tt)
		{

			u64 m = cmd.getOr("m", 4);
			u64 c = cmd.getOr("ssp", 8) + m;
			BinarySolver s[2];
			s[0].init(0, m, c, 10);
			s[1].init(1, m, c, 10);

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
			for (u64 i = 0; i < plainM.size();++i)
				plainM[i] = Mi[0][i] ^ Mi[1][i];

			//s[0].firstOneBit(plainM, plainR);

			auto sock = coproto::LocalAsyncSocket::makePair();
			macoro::sync_wait(macoro::when_all_ready(
				s[0].firstOneBit(Mi[0], r[0], sock[0]),
				s[1].firstOneBit(Mi[1], r[1], sock[1])
			));


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
					if(mm)
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

			if (cnt != 1)
				throw std::runtime_error(LOCATION);
		}
	}
}
