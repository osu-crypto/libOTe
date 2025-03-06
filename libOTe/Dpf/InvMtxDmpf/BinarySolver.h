#pragma once
#include "cryptoTools/Circuit/MxCircuit.h"
#include "cryptoTools/Common/Matrix.h"
#include "macoro/Task.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Common/Log.h"

namespace osuCrypto
{

	struct BinarySolver
	{
		u64 mPartyIdx = 0;

		// the rows of the system
		u64 mM = 0;

		// the columns of the system
		u64 mC = 0;

		// the bit count of the element.
		u64 mLogG = 0;

		void init(u64 partyIdx, u64 m, u64 c, u64 logG)
		{
			mPartyIdx = partyIdx;
			mM = m;
			mC = c;
			mLogG = logG;
		}

		u64 baseOtCount() const;

		void firstOneBit(span<const u8> Mi, span<u8> s)
		{
			auto depth = log2ceil(mC);
			std::vector<std::vector<u8>> M(depth);
			std::vector<u64> sizes(depth);
			sizes[0] = mC;
			M[0].assign(Mi.begin(), Mi.end());
			for (u64 d = 1; d < depth; ++d)
			{
				sizes[d] = divCeil(sizes[d - 1], 2);
				M[d].resize(sizes[d]);

				auto prev = BitIterator(M[d - 1].data());
				auto cur = BitIterator(M[d].data());
				for (u64 i = 0; i < sizes[d - 1]; i += 2)
				{
					u8 c0 = (*prev + 0);
					u8 c1 = (*prev + 1);
					auto both = c0 & c1;

					assert((c0 ^ c1 ^ both) == (c0 | c1));
					*cur++ = c0 ^ c1 ^ both;

					// if both are set, turn the second off.
					*(prev + 1) = *(prev + 1) ^ both;

					prev = prev + 2;
				}

				if (sizes[d] * 2 != sizes[d - 1])
					*cur = *prev;
			}

			// compute the AND with each parent. 
			for (u64 d = depth - 1; d != 0; --d)
			{
				auto cur = BitIterator(M[d].data());
				auto next = BitIterator(M[d - 1].data());

				for (u64 i = 0; i < sizes[d]; ++i)
				{
					*(next + 0) = *cur & *(next + 0);
					*(next + 1) = *cur & *(next + 1);

					++cur;
					next = next + 2;
				}
			}

			bool found = false;
			for (u64 i = 0; i < mM; ++i)
			{
				auto mm = BitIterator((u8*)Mi.data(), i);
				auto ss = BitIterator((u8*)M[0].data(), i);
				if (*mm)
				{
					found = true;
					if (*ss == 0)
						throw std::runtime_error(LOCATION);
				}
				else
				{
					if (*ss)
						throw std::runtime_error(LOCATION);
				}
			}

		}


		// compute matrix multiplication C = A*B
		//     m         k		   k
		//   aaaaa     bbbbb     ccccc
		// n aaaaa * m bbbbb = n ccccc
		//   aaaaa     bbbbb     ccccc
		task<> multiplyMtx(
			u64 k,
			MatrixView<const u8> A,
			MatrixView<const u8> B,
			MatrixView<u8> C,
			Socket& sock)
		{
			auto n = A.rows();
			auto m = B.rows();

			auto n8 = divCeil(n, 8);
			auto m8 = divCeil(m, 8);
			auto k8 = divCeil(k, 8);
			if (A.cols() != m8)
				throw RTE_LOC;
			if (B.cols() != k8)
				throw RTE_LOC;
			if (C.cols() != k8)
				throw RTE_LOC;
			if (C.rows() != n)
				throw RTE_LOC;

			//co_await printMtx(m, A, "A", sock);
			//co_await printMtx(k, B, "B", sock);


			BitVector ABits(n * m);

			Matrix<u8> BRows(n * m, k8);

			// flatten A into a bit vector
			for (u64 i = 0; i < n; ++i)
				for (u64 j = 0; j < m; ++j)
					ABits[i * m + j] = *BitIterator((u8*)A[i].data(), j);

			// n copies of B,  
			// B | B | B | ... | B
			// <------ n -------> 
			// each will be componet-wise scalar-vector multiplied with a row of A. i.e.
			//
			// A[i] * B    =>  A[i,j] * B[j]
			//
			// we will then need to add these together to get the result.

			auto iter = BRows.begin();
			for (u64 i = 0; i < n; ++i)
			{
				std::copy(B.begin(), B.end(), iter);
				iter += B.size();
			}

			//co_await print(ABits.size(), ABits.getSpan<u8>(), "ABits", sock);
			//co_await printMtx(k, BRows, "BRows", sock);

			// compute the scaler vector products.
			co_await multiply(k, ABits.getSpan<u8>(), BRows, BRows, sock);
			//co_await printMtx(k, BRows, "BRows", sock);

			// reduce the rows
			for (u64 i = 0; i < n; ++i)
				for (u64 j = 0; j < m; ++j)
					for (u64 l = 0; l < k8; ++l)
						C(i, l) ^= BRows(i * m + j, l);

		}

		// multiply each bit A[i] with row B[i] and write the result to C[i].
		// each row of B will have bitCount bits.
		task<> multiply(
			u64 bitCount,
			span<const u8> a,
			MatrixView<const u8> b,
			MatrixView<u8> c,
			Socket& sock)
		{
			MACORO_TRY{
			auto n = b.rows();
			if (a.size() != divCeil(n, 8))
				throw std::runtime_error(LOCATION);
			if (c.cols() != divCeil(bitCount, 8))
				throw std::runtime_error(LOCATION);
			if (c.rows() != n)
				throw std::runtime_error(LOCATION);
			if (b.cols() != divCeil(bitCount, 8))
				throw std::runtime_error(LOCATION);

			std::vector<u8> a2(a.size());
			Matrix<u8> b2(b.rows(), b.cols());

			co_await sock.send(std::vector<u8>(a.begin(), a.end()));
			co_await sock.send(std::vector<u8>(b.begin(), b.end()));

			co_await sock.recv(a2);
			co_await sock.recv(b2);

			for (u64 i = 0; i < a2.size(); ++i)
				a2[i] ^= a[i];
			for (u64 i = 0; i < b2.size(); ++i)
				b2(i) ^= b(i);

			PRNG prng(block(34123213));
			for (u64 i = 0; i < n; ++i)
			{
				auto aa = BitIterator(a2.data(), i);
				auto bb = BitIterator(b2[i].data());
				auto cc = BitIterator(c[i].data());
				for (u64 j = 0; j < bitCount; ++j)
				{
					auto v = (*aa & *bb);
					//std::cout << i << "  " << j << " : A " << (int)*aa << " B " << (int)*bb << " C " << (int)v << std::endl;
					if (mPartyIdx)
						*cc = v ^ prng.getBit();
					else
						*cc = prng.getBit();

					++bb;
					++cc;
				}
			}

			}MACORO_CATCH(e)
			{
				if (!sock.closed())
					co_await sock.close();
				std::rethrow_exception(e);
			}
		}

		// scans the Mi vector and sets s to be the unit vector with
		// the same first non-zero bit as Mi.
		task<> firstOneBit(span<const u8> Mi, span<u8> s, Socket& sock)
		{
			auto depth = log2ceil(mC);
			std::vector<std::vector<u8>> M(depth);
			std::vector<u64> sizes(depth);
			sizes[0] = mC;
			M[0].assign(Mi.begin(), Mi.end());

			// compute A binary tree where each node is the OR of its children.
			// If both children are set, set the second off.
			for (u64 d = 1; d < depth; ++d)
			{
				sizes[d] = divCeil(sizes[d - 1], 2);
				M[d].resize(sizes[d]);

				auto child = BitIterator(M[d - 1].data());
				auto prnt = BitIterator(M[d].data());
				BitVector a(sizes[d - 1] / 2);
				Matrix<u8> b(a.size(), 1);
				Matrix<u8> c(a.size(), 1);
				auto aIter = BitIterator(a.data());

				for (u64 i = 0; i < a.size(); ++i)
				{
					a[i] = *(child + 0);
					b(i) = *(child + 1);
					child = child + 2;
				}

				co_await multiply(1, a.getSpan<u8>(), b, c, sock);


				child = BitIterator(M[d - 1].data());
				for (u64 i = 0; i < a.size(); ++i)
				{
					auto both = c(i);

					auto c0 = *(child + 0);
					auto c1 = *(child + 1);

					// prnt = c0 or c1 = c0 ^ c1 ^ both
					*prnt++ = c0 ^ c1 ^ both;

					// if both are set, turn the second off.
					*(child + 1) = *(child + 1) ^ both;
					child = child + 2;
				}

				if (sizes[d] * 2 != sizes[d - 1])
					*prnt = *child;
			}

			// We now have the guarantee that the at most one chold is set
			// We will compute the AND of each parent with its child.
			// This could probably be optimized A bit more.
			//  - the levels could be computed in parallel.
			//  - maybe the previous multiplication could reduce the number of AND gates.
			for (u64 d = depth - 1; d != 0; --d)
			{
				auto cur = BitIterator(M[d].data());
				auto next = BitIterator(M[d - 1].data());

				BitVector a(sizes[d]);
				Matrix<u8> b(a.size(), 1);
				Matrix<u8> c(a.size(), 1);

				// pack both children into A single vector and do
				// scaler vector multiplication.
				for (u64 i = 0; i < sizes[d]; ++i)
				{
					a[i] = *cur;
					b(i) = *(next + 0) + 2 * *(next + 1);

					++cur;
					next = next + 2;
				}

				co_await multiply(2, a.getSpan<u8>(), b, c, sock);

				next = BitIterator(M[d - 1].data());
				for (u64 i = 0; i < sizes[d]; ++i)
				{
					*(next + 0) = (c(i) >> 0) & 1;
					*(next + 1) = (c(i) >> 1) & 1;
					next = next + 2;
				}
			}

			std::copy(M[0].begin(), M[0].end(), s.begin());

			co_await print(mC, Mi, "Mi", sock);
			co_await print(mC, s, "s", sock);
		}

		task<> printMtx(u64 bits, MatrixView<const u8> M, const char* name, Socket& sock)
		{
			co_await sock.send(std::vector<u8>(M.begin(), M.end()));
			std::vector<u8> r(M.size());
			co_await sock.recv(r);

			if (mPartyIdx)
			{

				for (u64 i = 0; i < r.size(); ++i)
					r[i] ^= M(i);

				std::cout << name << " = [\n";
				for (u64 i = 0; i < M.rows(); ++i)
				{
					for (u64 j = 0; j < bits; ++j)
					{
						auto bit = *BitIterator(&r[i * M.cols()], j);
						if (bit)
							std::cout << Color::Green;
						std::cout << bit << " ";
						if(bit) 
							std::cout << Color::Default;
					}

					if (i + 1 < M.rows())
						std::cout<<"," << std::endl;
					else
						std::cout << "]" << std::endl;
				}
			}
		}

		task<> print(u64 bits, span<const u8> M, const char* name, Socket& sock)
		{
			if (bits > M.size() * 8)
				throw std::runtime_error((co_await macoro::get_trace{}).str());
			

			co_await sock.send(std::vector<u8>(M.begin(), M.end()));
			std::vector<u8> r(M.size());
			co_await sock.recv(r);

			if (mPartyIdx)
			{

				for (u64 i = 0; i < r.size(); ++i)
					r[i] ^= M[i];

				std::cout << name << " = [\n";
				for (u64 j = 0; j < bits; ++j)
				{
					auto bit = *BitIterator(r.data(), j);
					if (bit)
						std::cout << Color::Green;
					std::cout << bit << " ";
					if (bit)
						std::cout << Color::Default;

				}
				std::cout<<"]" << std::endl;
			}
			co_await sock.send(char(0));
			co_await sock.recv<char>();
		}


		task<> solve(
			MatrixView<u8> M,
			MatrixView<u8> Y,
			MatrixView<u8> X,
			PRNG& prng,
			Socket& sock)
		{

			auto m8 = divCeil(mM, 8);
			auto c8 = divCeil(mC, 8);
			auto g8 = divCeil(mLogG, 8);

			if (M.rows() != mM || M.cols() != c8)
				throw std::runtime_error(LOCATION);
			if (Y.rows() != mM || Y.cols() != g8)
				throw std::runtime_error(LOCATION);
			if (X.rows() != mC || X.cols() != g8)
				throw std::runtime_error(LOCATION);

			// M transposed
			Matrix<u8> MT(mC, m8);

			// M || Y
			Matrix<u8> MY(mM, c8 + g8);

			// s * M
			Matrix<u8> V(mC, m8);

			// sum s* M
			std::vector<u8> v(m8);

			Matrix<u8> s(mM, c8);
			for (u64 i = 0; i < mM; ++i)
			{
				if (mPartyIdx)
					std::cout << "iteration i=" << i << std::endl;
				co_await printMtx(mC, M, "M", sock);


				co_await firstOneBit(M[i], s[i], sock);

				co_await print(mC, s[i], "s[i]", sock);


				// v = sum_{j in [C]} s[i,j] * M[*,j]
				transpose(M, MT);
				co_await multiply(mM, s[i], MT, V, sock);
				setBytes(v, 0);
				for (u64 j = 0; j < mC; ++j)
				{
					for (u64 k = 0; k < v.size(); ++k)
						v[k] ^= V(j, k);
				}

				co_await print(mM, v, "v", sock);

				// MY = M || Y
				for (u64 j = 0; j < mM; ++j)
				{
					if (j != i)
					{
						std::copy(M[i].begin(), M[i].end(), MY[j].begin());
						std::copy(Y[i].begin(), Y[i].end(), MY[j].begin() + M[j].size());
					}
					else
						setBytes(MY[i], 0);
				}


				co_await printMtx(mC, MY, "MY", sock);

				// MY = v * MY
				co_await multiply(MY.cols() * 8, v, MY, MY, sock);

				co_await printMtx(mC, MY, "v * MY", sock);

				// M = M + v * M
				// Y = Y + v * Y
				for (u64 j = 0; j < mM; ++j)
				{
					for (u64 k = 0; k < M.cols(); ++k)
						M(j, k) ^= MY(j, k);
					for (u64 k = 0; k < Y.cols(); ++k)
						Y(j, k) ^= MY(j, k + M.cols());
				}
			}


			co_await printMtx(mC, M, "final\nM", sock);

			// sigma  = sum_{i in [m]} s[i]
			std::vector<u8> sigma(s.cols()), negSigma(s.cols());
			for (u64 i = 0; i < s.rows(); ++i)
			{
				for (u64 j = 0; j < s.cols(); ++j)
					sigma[j] ^= s(i, j);
			}
			for (u64 j = 0; j < s.cols(); ++j)
				negSigma[j] = ~sigma[j];


			// X <- G^C * sigma
			prng.get(X.data(), X.size());
			co_await multiply(mLogG, negSigma, X, X, sock);

			// Y = Y + M * X
			Matrix<u8> Y2(mM, g8);
			co_await multiplyMtx(mLogG, M, X, Y2, sock);
			for (u64 i = 0; i < Y.size(); ++i)
				Y(i) ^= Y2(i);

			// X = X + s * Y
			Matrix<u8> X2(mC, g8);
			co_await multiplyMtx(mLogG, s, Y, X2, sock);
			for (u64 i = 0; i < X.size(); ++i)
				X(i) ^= X2(i);

		}
	};





}