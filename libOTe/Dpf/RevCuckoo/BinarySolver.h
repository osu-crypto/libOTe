#pragma once
#include "cryptoTools/Circuit/MxCircuit.h"
#include "cryptoTools/Common/Matrix.h"
#include "macoro/task.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Common/Log.h"
#include "libOTe/Dpf/DpfMult.h"

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

		u64 mBatchSize = 0;

		DpfMult mMult;

		bool mPrint = false;

		u64 mPrintIdx = 0;

		void init(u64 partyIdx, u64 m, u64 c, u64 logG, u64 batchSize = 1)
		{
			mPartyIdx = partyIdx;
			mM = m;
			mC = c;
			mLogG = logG;
			mBatchSize = batchSize;

			auto oneHot = mM * (2 * mC - 3);
			auto v = mM * mC;
			auto mUpdate = mM * mM;
			auto randX = mC;
			auto yy = std::min<u64>(mC * mM, mC * mLogG);
			auto cc = std::min<u64>(mC * mM, mM * mLogG);
			auto baseCount = cc + yy + randX + oneHot + v + mUpdate;

			mMult.init(partyIdx, baseCount * batchSize);
		}

		u64 baseOtCount() const
		{
			return mMult.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> sendOts,
			span<const block> recvOts,
			const BitVector& choices)
		{
			mMult.setBaseOts(sendOts, recvOts, choices);
		}

		void firstOneBit(span<const u8> Mi, span<u8> s)
		{
			auto depth = log2ceil(mC);
			std::vector<std::vector<u8>> M(depth + 1);
			std::vector<u64> sizes(depth + 1);
			sizes[0] = mC;
			M[0].assign(Mi.begin(), Mi.end());
			for (u64 d = 1; d <= depth; ++d)
			{
				sizes[d] = divCeil(sizes[d - 1], 2);
				M[d].resize(sizes[d]);

				auto prev = BitIterator(M[d - 1].data());
				auto cur = BitIterator(M[d].data());
				for (u64 i = 0; i < sizes[d - 1]; i += 2)
				{
					u8 c0 = *(prev + 0);
					u8 c1 = *(prev + 1);
					auto both = c0 & c1;

					assert((c0 ^ c1 ^ both) == (c0 | c1));
					*cur++ = c0 ^ c1 ^ both;

					// if both are set, turn the second off.
					*(prev + 1) = *(prev + 1) ^ both;

					prev = prev + 2;
				}


				//std::cout << "----------" << std::endl;
				//std::cout << "M[" << d -1<< "] = ";
				//for (u64 i = 0; i < sizes[d-1]; ++i)
				//{
				//	auto mm = BitIterator((u8*)M[d-1].data(), i);
				//	std::cout << *mm << " ";
				//}
				//std::cout << std::endl;

				//std::cout << "M["<<d<<"] = ";
				//for (u64 i = 0; i < sizes[d]; ++i)
				//{
				//	auto mm = BitIterator((u8*)M[d].data(), i);
				//	std::cout<<" " << *mm << "  ";
				//}
				//std::cout << std::endl;
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


				//std::cout << "----------" << std::endl;
				//std::cout << "M[" << d  << "] = ";
				//for (u64 i = 0; i < sizes[d]; ++i)
				//{
				//	auto mm = BitIterator((u8*)M[d].data(), i);
				//	std::cout <<" " << *mm << "  ";
				//}
				//std::cout << std::endl;

				//std::cout << "M[" << d-1 << "] = ";
				//for (u64 i = 0; i < sizes[d - 1]; ++i)
				//{
				//	auto mm = BitIterator((u8*)M[d - 1].data(), i);
				//	std::cout << *mm << " ";
				//}
				//std::cout << std::endl;
			}


			//std::cout << "S = " ;
			//for (u64 i = 0; i < mC; ++i)
			//{
			//	auto ss = BitIterator((u8*)M[0].data(), i);
			//	std::cout << *ss << " ";
			//}
			//std::cout << std::endl;

			bool found = false;
			for (u64 i = 0; i < mC; ++i)
			{
				auto mm = BitIterator((u8*)Mi.data(), i);
				auto ss = BitIterator((u8*)M[0].data(), i);
				if (!found)
				{
					found = true;
					if (*ss != *mm)
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
		task<> multiplyMtxMany(
			u64 k,
			auto&& /*span<MatrixView<const u8>>*/ A,
			auto&& /*span<MatrixView<const u8>>*/ B,
			auto&& /*span<MatrixView<u8>>*/ C,
			Socket& sock)
		{
			//for(u64 i = 0; i < mBatchSize; ++i)
			//{
			//	co_await multiplyMtx(k, A[i], B[i], C[i], sock);
			//}

			const u64 Bsz = mBatchSize;
			if (A.size() != Bsz || B.size() != Bsz || C.size() != Bsz)
				throw RTE_LOC;
			if (Bsz == 0)
				co_return;

			// Infer common dimensions from instance 0 and validate uniformity.
			auto n = A[0].rows();
			auto m = B[0].rows();
			auto m8 = divCeil(m, 8);
			auto k8 = divCeil(k, 8);
			if (A[0].cols() != m8 || B[0].cols() != k8 || C[0].rows() != n || C[0].cols() != k8)
				throw RTE_TRACE;

			for (u64 t = 0; t < Bsz; ++t)
			{
				if (A[t].rows() != n || A[t].cols() != m8) throw RTE_TRACE;
				if (B[t].rows() != m || B[t].cols() != k8) throw RTE_TRACE;
				if (C[t].rows() != n || C[t].cols() != k8) throw RTE_TRACE;
			}

			// Transpose trick to reduce OTs if beneficial: same decision for all instances.
			if (n * m > m * k)
			{
				auto n8 = divCeil(n, 8);
				std::vector<Matrix<u8>> At(Bsz), Bt(Bsz), Ct(Bsz);

				for (u64 t = 0; t < Bsz; ++t)
				{
					At[t].resize(m, n8);
					Bt[t].resize(k, m8);
					Ct[t].resize(k, n8);
					transpose(A[t], At[t]); // At = A^T (m x n8)
					transpose(B[t], Bt[t]); // Bt = B^T (k x m8)
				}

				co_await multiplyMtxMany(n, Bt, At, Ct, sock);

				for (u64 t = 0; t < Bsz; ++t)
					transpose(Ct[t], C[t]); // C = (Ct)^T
				co_return;
			}

			// Build one big multiplication instance:
			// - ABitsAll concatenates all A bits over the batch.
			// - BRowsAll contains for each instance t, n copies of B[t] stacked.
			const u64 rowsPerInst = n * m;
			const u64 totalRows = Bsz * rowsPerInst;

			BitVector ABitsAll; ABitsAll.reserve(totalRows);
			Matrix<u8> BRowsAll(totalRows, k8);

			// Fill ABitsAll
			u64 bitPos = 0;
			for (u64 t = 0; t < Bsz; ++t)
			{
				for (u64 i = 0; i < n; ++i)
				{
					const u8* dataPtr = A[t][i].data();
					ABitsAll.append(dataPtr, m);
					//for (u64 j = 0; j < m; ++j)
					//{
					//	ABitsAll[bitPos++] = *BitIterator((u8*)A[t][i].data(), j);
					//}
				}
			}

			// Fill BRowsAll with n copies of B[t] per instance t
			auto iter = BRowsAll.data();
			for (u64 t = 0; t < Bsz; ++t)
			{
				for (u64 i = 0; i < n; ++i)
				{
					//std::copy(B[t].begin(), B[t].end(), iter);
					assert(BRowsAll.data() + BRowsAll.size() >= iter + B[t].size());
					memcpy(&*iter, B[t].data(), B[t].size());

					iter += B[t].size();
				}
			}

			// Perform a single batched multiply
			co_await multiply(k, ABitsAll.getSpan<u8>(), BRowsAll, BRowsAll, sock);

			// Reduce rows back into each C[t]
			for (u64 t = 0; t < Bsz; ++t)
			{
				const u64 base = t * rowsPerInst;
				for (u64 i = 0; i < n; ++i)
				{
					for (u64 j = 0; j < m; ++j)
					{
						for (u64 l = 0; l < k8; ++l)
							C[t](i, l) ^= BRowsAll(base + i * m + j, l);
					}
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

			//auto n8 = divCeil(n, 8);
			auto m8 = divCeil(m, 8);
			auto k8 = divCeil(k, 8);
			if (A.cols() != m8)
				throw RTE_TRACE;
			if (B.cols() != k8)
				throw RTE_TRACE;
			if (C.cols() != k8)
				throw RTE_TRACE;
			if (C.rows() != n)
				throw RTE_TRACE;

			// fewer OTs if we transpose the matrices.
			if (n * m > m * k)
			{
				auto n8 = divCeil(n, 8);
				Matrix<u8> At(m, n8);
				Matrix<u8> Bt(k, m8);
				Matrix<u8> Ct(k, n8);

				//     m	     n         n
				//   bbbbb     aaaaa     ccccc
				// k bbbbb * m aaaaa = k ccccc
				//   bbbbb     aaaaa     ccccc
				transpose(A, At);
				transpose(B, Bt);
				co_await multiplyMtx(n, Bt, At, Ct, sock);
				transpose(Ct, C);
				co_return;
			}

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
				//std::copy(B.begin(), B.end(), iter);
				assert(BRows.data() + BRows.size() >= iter + B.size());
				memcpy(&*iter, B.data(), B.size());
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

		task<> multiplyMany(u64 bitCount, 
			span<std::vector<u8>> a, 
			auto&&/*span<MatrixView<u8>>*/ b, 
			auto&&/*span<MatrixView<u8>>*/ c, 
			Socket& sock)
		{
			if(a.size() != b.size() || a.size() != c.size())
				throw RTE_LOC;
			if (a.size() != mBatchSize)
				throw std::runtime_error(LOCATION " a.size() != b.size() != c.size() != mBatchSize");

			auto n = b[0].rows();
			auto n8 = divCeil(n, 8);
			auto m = b[0].cols();
			if(bitCount > m * 8)
				throw std::runtime_error(LOCATION " bitCount > b[0].cols() * 8");

			BitVector aa; aa.reserve(a.size() * b[0].rows());
			Matrix<u8> bb(b.size() * b[0].rows(), b[0].cols());
			Matrix<u8> cc(c.size() * c[0].rows(), c[0].cols());
			for(u64 i = 0; i < a.size(); ++i)
			{
				if (a[i].size() != a[0].size())
					throw std::runtime_error(LOCATION " a[i].size() != a[0].size()");
				if(a[i].size() != n8)
					throw std::runtime_error(LOCATION " a[i].size() != b[0].rows()");
				if (b[i].rows() != n || b[i].cols() != m)
					throw std::runtime_error(LOCATION " b[i].rows() != b[0].rows() || b[i].cols() != b[0].cols()");
				if (c[i].rows() != n || c[i].cols() != m)
					throw std::runtime_error(LOCATION " c[i].rows() != c[0].rows() || c[i].cols() != c[0].cols()");

				aa.append(a[i].data(), n);
				auto bbi = bb.submtx(i * n, n);
				copyBytes(bbi, b[i]);
				//std::copy(b[i].begin(), b[i].end(), bb.begin() + i * b[0].size());
			}

			co_await mMult.multiply(
				bitCount, aa.getSpan<u8>(), bb, cc, sock);

			// copy the result back to c.
			for (u64 i = 0; i < c.size(); ++i)
			{
				//std::copy(cc.begin() + i * c[0].size(), cc.begin() + (i + 1) * c[0].size(), c[i].begin());
				auto cci = cc.submtx(i *n,n);
				copyBytes(c[i], cci);
			}
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

				if (bitCount == 1)
				{
					BitVector B(b.size());
					BitVector C(c.size());
					for (u64 i = 0; i < b.size(); ++i)
						B[i] = b(i, 0) & 1;
					co_await mMult.multiplyBits(
						b.rows(), a, B.getSpan<u8>(), C.getSpan<u8>(), sock);

					for (u64 i = 0; i < c.size(); ++i)
						c(i, 0) = C[i];
				}
				else
				{
					co_await mMult.multiply(bitCount, a, b, c, sock);
					//auto last = bitCount % 8;
					//if (last)
					//{
					//	auto mask = ~0ull << last;
					//	for (u64 i = 0; i < c.rows(); ++i)
					//	{
					//		c(i, bitCount / 8) &= mask;
					//	}
					//}

					// check the result.
					if (mPrint)
					{
						std::vector<u8> aa(a.size());
						Matrix<u8> bb(b.rows(), b.cols());
						Matrix<u8> cc(c.rows(), c.cols());
						std::copy(a.begin(), a.end(), aa.begin());
						std::copy(b.begin(), b.end(), bb.begin());
						std::copy(c.begin(), c.end(), cc.begin());

						co_await sock.send(coproto::copy(aa));
						co_await sock.send(coproto::copy(bb));
						co_await sock.send(coproto::copy(cc));

						co_await sock.recv(aa);
						co_await sock.recv(bb);
						co_await sock.recv(cc);

						// Reconstruct the actual values
						for (u64 i = 0; i < aa.size(); ++i)
							aa[i] ^= a[i];
						for (u64 i = 0; i < bb.size(); ++i)
							bb(i) ^= b(i);
						for (u64 i = 0; i < cc.size(); ++i)
							cc(i) ^= c(i);

						// Verify the multiplication results
						bool allCorrect = true;
						for (u64 i = 0; i < b.rows(); ++i)
						{
							auto ai = bit(aa.data(), i);  // Get the i-th bit of a
							std::vector<u8> expected(b.cols());
							if (ai == 1)
								for (u64 j = 0; j < b.cols(); ++j)
									expected[j] = bb(i,j);

							//// Apply bit count mask if needed
							//if (bitCount % 8)
							//{
							//	u8 mask = (1 << (bitCount % 8)) - 1;
							//	expected.back() &= mask;
							//}

							// Check if actual result matches expected
							bool rowCorrect = true;
							for (u64 j = 0; j < b.cols(); ++j)
							{
								if (cc(i,j) != expected[j])
								{
									rowCorrect = false;
									break;
								}
							}

							if (!rowCorrect)
							{
								allCorrect = false;
								if (mPartyIdx)  // Only print from one party to avoid duplication
								{
									std::cout << Color::Red << "Multiplication error at row " << i << ":" << Color::Default << std::endl;
									std::cout << "  a[" << i << "] = " << (int)ai << std::endl;
									std::cout << "  b[" << i << "] = " << toHex(bb[i]) << std::endl;
									std::cout << "  expected  = " << toHex(expected) << std::endl;
									std::cout << "  actual    = " << toHex(cc[i]) << std::endl;
								}
							}
						}
						if (!allCorrect)
							throw std::runtime_error(LOCATION);

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
		//
		// In the first pass we will have the following access patter
		// 
		// 0 1 2 3 4 5 6 7 8 9 10 11   | # 
		// 0   2   4   6   8   10	   | 6
		// 0       4       8		   | 3
		// 0               8		   | 2
		// 0						   | 1
		//
		// During this we will AND together children and then set the
		// parent as the OR of the children. In addition, if both children
		// are set, we will turn the second child off. This will require
		// mC-1 AND gates.
		//
		// In the second pass we will have the following the same 
		// access pattern except that we skip the root as its unnecessary.
		// We will compute the AND of each parent with its children. We pack 
		// the children into a single vector and do a scalar-vector and so
		// this requires mC-2 AND gates.
		// 
		// In total we use 2 mC - 3 AND gates.
		// 
		task<> firstOneBit(span<const u8> Mi, span<u8> s, Socket& sock)
		{
			auto depth = log2ceil(mC);
			std::vector<std::vector<u8>> M(depth + 1);
			std::vector<u64> sizes(depth + 1);
			sizes[0] = mC;
			M[0].assign(Mi.begin(), Mi.end());

			// compute A binary tree where each node is the OR of its children.
			// If both children are set, set the second off.
			for (u64 d = 1; d <= depth; ++d)
			{
				sizes[d] = divCeil(sizes[d - 1], 2);
				M[d].resize(divCeil(sizes[d], 8));

				auto child = BitIterator(M[d - 1].data());
				auto prnt = BitIterator(M[d].data());
				BitVector a(sizes[d - 1] / 2);
				Matrix<u8> b(a.size(), 1);
				Matrix<u8> c(a.size(), 1);

				for (u64 i = 0; i < a.size(); ++i)
				{
					a[i] = *(child + 0);
					b(i) = *(child + 1);
					child = child + 2;
				}

				auto idx2 = mMult.mOtIdx;
				co_await multiply(1, a.getSpan<u8>(), b, c, sock);

				if (idx2 + a.size() != mMult.mOtIdx)
					throw std::runtime_error((co_await macoro::get_trace{}).str());

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

				//std::cout << "---------" << std::endl;
				//co_await print(sizes[d - 1], M[d-1],
				//	(std::string("M[") + std::to_string(d-1) + "]").c_str(), sock);
				//co_await print(sizes[d], M[d],
				//	(std::string("M[") + std::to_string(d) + "]").c_str(), sock);

			}

			// We now have the guarantee that the at most one child is set
			// We will compute the AND of each parent with its child.
			// This could probably be optimized A bit more.
			//  - the levels could be computed in parallel.
			//  - maybe the previous multiplication could reduce the number of AND gates.
			for (u64 d = depth - 1; d != 0; --d)
			{
				auto cur = BitIterator(M[d].data());
				auto next = BitIterator(M[d - 1].data());

				//auto ss = sizes[d] + (sizes[d - 1] & 1);// divCeil(sizes[d - 1], 2);

				auto ss = sizes[d - 1] / 2;
				BitVector a(ss);
				Matrix<u8> b(a.size(), 1);
				Matrix<u8> c(a.size(), 1);

				// pack both children into A single vector and do
				// scaler vector multiplication.
				for (u64 i = 0; i < ss; ++i)
				{
					a[i] = *cur;
					b(i) = *(next + 0) + 2 * *(next + 1);

					++cur;
					next = next + 2;
				}

				co_await multiply(2, a.getSpan<u8>(), b, c, sock);

				next = BitIterator(M[d - 1].data());
				for (u64 i = 0; i < ss; ++i)
				{
					*(next + 0) = (c(i) >> 0) & 1;
					*(next + 1) = (c(i) >> 1) & 1;
					next = next + 2;
				}

				if (ss != sizes[d])
				{
					*next = *cur;
				}

			}

			//std::copy(M[0].begin(), M[0].end(), s.begin());
			copyBytes(s, M[0]);
		}



		// scans the Mi vector and sets s to be the unit vector with
		// the same first non-zero bit as Mi.
		//
		// In the first pass we will have the following access patter
		// 
		// 0 1 2 3 4 5 6 7 8 9 10 11   | # 
		// 0   2   4   6   8   10	   | 6
		// 0       4       8		   | 3
		// 0               8		   | 2
		// 0						   | 1
		//
		// During this we will AND together children and then set the
		// parent as the OR of the children. In addition, if both children
		// are set, we will turn the second child off. This will require
		// mC-1 AND gates.
		//
		// In the second pass we will have the following the same 
		// access pattern except that we skip the root as its unnecessary.
		// We will compute the AND of each parent with its children. We pack 
		// the children into a single vector and do a scalar-vector and so
		// this requires mC-2 AND gates.
		// 
		// In total we use 2 mC - 3 AND gates.
		// 
		task<> firstOneBit(u64 i, span<Matrix<u8>> Mi, span<Matrix<u8>> s, Socket& sock)
		{
			auto depth = log2ceil(mC);
			std::vector<Matrix<u8>> M(depth + 1);
			std::vector<u64> sizes(depth + 1);
			sizes[0] = mC;

			if (Mi.size() != mBatchSize || s.size() != mBatchSize)
				throw RTE_LOC;

			M[0].resize(mBatchSize, Mi[0].cols());
			for (u64 b = 0; b < mBatchSize; ++b)
			{
				if (Mi[b].cols() != M[0].cols())
					throw RTE_LOC;

				copyBytes(M[0][b], Mi[b][i]);
			}

			// compute A binary tree where each node is the OR of its children.
			// If both children are set, set the second off.
			for (u64 d = 1; d <= depth; ++d)
			{
				sizes[d] = divCeil(sizes[d - 1], 2);
				M[d].resize(mBatchSize, divCeil(sizes[d], 8));

				auto size = sizes[d - 1] / 2;
				BitVector a(mBatchSize * size);
				Matrix<u8> B(a.size(), 1);
				Matrix<u8> C(a.size(), 1);
				auto aIter = a.begin();
				auto bIter = B.begin();
				for (u64 b = 0; b < mBatchSize; ++b)
				{
					auto child = BitIterator(M[d - 1][b].data());
					for (u64 i = 0; i < size; ++i)
					{
						*aIter++ = *(child + 0);
						*bIter++ = *(child + 1);
						child = child + 2;
					}
				}

				co_await multiply(1, a.getSpan<u8>(), B, C, sock);

				auto cIter = C.begin();
				for (u64 b = 0; b < mBatchSize; ++b)
				{
					auto child = BitIterator(M[d - 1][b].data());
					auto prnt = BitIterator(M[d][b].data());
					for (u64 i = 0; i < size; ++i)
					{
						auto both = *cIter++;

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
				//std::cout << "---------" << std::endl;
				//co_await print(sizes[d - 1], M[d-1],
				//	(std::string("M[") + std::to_string(d-1) + "]").c_str(), sock);
				//co_await print(sizes[d], M[d],
				//	(std::string("M[") + std::to_string(d) + "]").c_str(), sock);

			}

			// We now have the guarantee that the at most one child is set
			// We will compute the AND of each parent with its child.
			// This could probably be optimized A bit more.
			//  - the levels could be computed in parallel.
			//  - maybe the previous multiplication could reduce the number of AND gates.
			for (u64 d = depth - 1; d != 0; --d)
			{
				auto ss = sizes[d - 1] / 2;
				BitVector a(ss * mBatchSize);
				Matrix<u8> B(a.size(), 1);
				Matrix<u8> C(a.size(), 1);
				auto aIter = a.begin();
				auto bIter = B.begin();
				for (u64 b = 0; b < mBatchSize; ++b)
				{
					auto cur = BitIterator(M[d][b].data());
					auto next = BitIterator(M[d - 1][b].data());
					// pack both children into A single vector and do
					// scaler vector multiplication.
					for (u64 i = 0; i < ss; ++i)
					{
						*aIter++ = *cur;
						*bIter++ = *(next + 0) + 2 * *(next + 1);

						++cur;
						next = next + 2;
					}
				}

				co_await multiply(2, a.getSpan<u8>(), B, C, sock);

				auto cIter = C.begin();
				for (u64 b = 0; b < mBatchSize; ++b)
				{
					auto next = BitIterator(M[d - 1][b].data());
					for (u64 i = 0; i < ss; ++i)
					{
						*(next + 0) = (*cIter >> 0) & 1;
						*(next + 1) = (*cIter >> 1) & 1;
						next = next + 2;
						++cIter;
					}

					if (ss != sizes[d])
					{
						auto cur = BitIterator(M[d][b].data()) + ss;
						*next = *cur;
					}

				}
			}

			for (u64 b = 0; b < mBatchSize; ++b)
			{
				//std::copy(M[0][b].begin(), M[0][b].end(), s[b][i].begin());
				copyBytes(s[b][i], M[0][b]);
			}
		}



		void printMtx(u64 bits, MatrixView<const u8> M, const char* name)
		{
			std::cout << name << " = [\n";
			for (u64 i = 0; i < M.rows(); ++i)
			{
				for (u64 j = 0; j < bits; ++j)
				{
					auto b = bit(M[i], j);
					if (b)
						std::cout << Color::Green;
					std::cout << b << " ";
					if (b)
						std::cout << Color::Default;
				}

				if (i + 1 < M.rows())
					std::cout << "," << std::endl;
				else
					std::cout << "]" << std::endl;
			}
		}
		task<> printMtx(u64 bits, MatrixView<const u8> M, const char* name, Socket& sock)
		{
			co_await sock.send(std::vector<u8>(M.begin(), M.end()));
			Matrix<u8> r(M.rows(), M.cols());
			co_await sock.recv(r);

			for (u64 i = 0; i < r.size(); ++i)
				r(i) ^= M(i);

			if (mPartyIdx)
			{
				printMtx(bits, r, name);
			}

			co_await sock.send(char(0));
			co_await sock.recv<char>();
		}

		task<> printMtxV(u64 bits, auto&& M, const char* name, Socket& sock)
		{
			co_await printMtx(bits, M[mPrintIdx], name, sock);
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
				std::cout << "]" << std::endl;
			}
			co_await sock.send(char(0));
			co_await sock.recv<char>();
		}

		task<> printV(u64 bits, auto&& M, const char* name, Socket& sock)
		{
			return print(bits, M[mPrintIdx], name, sock);
		}

		task<> solveOne(
			MatrixView<const u8> MM,
			MatrixView<const u8> YY,
			MatrixView<u8> X,
			PRNG& prng,
			Socket& sock)
		{
			span< MatrixView<const u8>> m{ &MM,1 };
			span< MatrixView<const u8>> y{ &YY,1 };
			span< MatrixView<u8>> x{ &X,1 };
			return solve(m, y, x, prng, sock);
		}

		task<> solve(
			span<MatrixView<const u8>> MM,
			span<MatrixView<const u8>> YY,
			span<MatrixView<u8>> X,
			PRNG& prng,
			Socket& sock)
		{
			const u64 B = MM.size();
			if (B == 0 || YY.size() != B || X.size() != B)
				throw RTE_LOC;
			if (B != mBatchSize)
				throw RTE_LOC;

			auto m8 = divCeil(mM, 8);   // Number of bytes needed to store mM bits
			auto c8 = divCeil(mC, 8);   // Number of bytes needed to store mC bits  
			auto g8 = divCeil(mLogG, 8); // Number of bytes needed to store mLogG bits


			// Initialize working copies of the input matrices
			std::vector<Matrix<u8>> M(B), Y(B);

			// Pre-allocate per instance temporaries
			std::vector<Matrix<u8>> MT(B);        // M transposed
			std::vector<Matrix<u8>> MY(B);        // Concatenated matrix [M || Y] for row operations
			std::vector<Matrix<u8>> V(B);        // s * M (active column computation)
			std::vector<std::vector<u8>> v(B);	  // Sum of active columns (pivot elimination vector)
			std::vector<Matrix<u8>> s(B);		  // Support vectors (unit vectors for each pivot)

			for (u64 i = 0; i < B; ++i)
			{
				// Validate input dimensions
				if (MM[i].rows() != mM || MM[i].cols() != c8)
					throw std::runtime_error(LOCATION);
				if (YY[i].rows() != mM || YY[i].cols() != g8)
					throw std::runtime_error(LOCATION);
				if (X[i].rows() != mC || X[i].cols() != g8)
					throw std::runtime_error(LOCATION);
				M[i] = Matrix<u8>(MM[i].rows(), MM[i].cols());
				Y[i] = Matrix<u8>(YY[i].rows(), YY[i].cols());
				//std::copy(MM[i].begin(), MM[i].end(), M[i].begin());
				//std::copy(YY[i].begin(), YY[i].end(), Y[i].begin());
				copyBytes(M[i], MM[i]);
				copyBytes(Y[i], YY[i]);

				MT[i] = Matrix<u8>(mC, m8);        // M transposed
				MY[i] = Matrix<u8>(mM, c8 + g8);   // Concatenated matrix [M || Y] for row operations
				V[i] = Matrix<u8>(mC, m8);         // s * M (active column computation)
				v[i] = std::vector<u8>(m8);        // Sum of active columns (pivot elimination vector)
				s[i] = Matrix<u8>(mM, c8);         // Support vectors (unit vectors for each pivot)
			}

			// ===================================================================
			// STEP 1: ROW ELIMINATION - Gaussian elimination with pivot selection
			// ===================================================================
			for (u64 i = 0; i < mM; ++i)
			{
				if (mPartyIdx && mPrint)
					std::cout << "\n\niteration i=" << i << std::endl;
				if (mPrint)
				{
					co_await printMtxV(mLogG, Y, "current Y", sock);
					co_await printMtxV(mC, M, "current M", sock);
				}

				// Step 1a: Find pivot column and create unit vector
				// Find the first non-zero bit in row i and create a unit vector s_i
				// such that s_i[j] = 1 only for the pivot column j, 0 elsewhere
				//for (u64 b = 0; b < B; ++b)
				//	co_await firstOneBit(M[b][i], s[b][i], sock);
				co_await firstOneBit(i, M, s, sock);



				if (mPrint)
					co_await print(mC, s[i], "selection vector s[i]", sock);

				// Step 1b: Compute active column v := M * s_i
				// This gives us the column vector corresponding to the pivot column
				// v[k] = 1 means row k has a 1 in the pivot column and needs elimination
				std::vector<std::vector<u8>> si(B);
				for (u64 b = 0; b < B; ++b)
				{
					transpose(M[b], MT[b]);
					si[b].assign(s[b][i].begin(), s[b][i].end());
				}

				//for (u64 b = 0; b < B; ++b)
				//	co_await multiply(mM, s[b][i], MT[b], V[b], sock);
				co_await multiplyMany(mM, si, MT, V, sock);

				for (u64 b = 0; b < B; ++b)
				{
					setBytes(v[b], 0);
					for (u64 j = 0; j < mC; ++j)
					{
						for (u64 k = 0; k < v[b].size(); ++k)
							v[b][k] ^= V[b](j, k);
					}
				}

				if (mPrint)
					co_await printV(mM, v, "Active column v=M[*,j]", sock);


				// Step 1c: Prepare for row operations
				// Create the augmented matrix [M || Y] for simultaneous operations
				// Row i is set to zero since we don't subtract from the pivot row itself
				for (u64 b = 0; b < B; ++b)
				{
					for (u64 j = 0; j < mM; ++j)
					{
						if (j != i)
						{
							// Copy M[i] and Y[i] into MY[j] for row operations
							//std::copy(M[b][i].begin(), M[b][i].end(), MY[b][j].begin());
							//std::copy(Y[b][i].begin(), Y[b][i].end(), MY[b][j].begin() + M[b][j].size());
							auto dst = MY[b][j].data();
							auto n1 = M[b][i].size();
							auto n2 = Y[b][i].size();
							assert(MY[b][j].size() == n1 + n2);
							memcpy(dst, M[b][i].data(), n1);
							memcpy(dst + n1, Y[b][i].data(), n2);

						}
						else
							setBytes(MY[b][i], 0);// Zero out the pivot row in the working matrix
					}
				}

				//if (mPrint)
				//	co_await printMtx(MY.cols()*8, MY, " row updates [Mi || Yi]", sock);

				// Step 1c: Perform row operations for pivot elimination
				// For each row j ≠ i where v[j] = 1, subtract row i from row j
				// This eliminates the pivot bit from all other rows
				//for (u64 b = 0; b < B; ++b)
				//	co_await multiply(MY[b].cols() * 8, v[b], MY[b], MY[b], sock);
				co_await multiplyMany(MY[0].cols() * 8, v, MY, MY, sock);

				if (mPrint)
					co_await printMtxV(MY[0].cols() * 8, MY, "row updates v * [Mi || Yi]", sock);

				// Step 1c: Apply the elimination results back to M and Y
				// M_j := M_j ⊕ v_j * M_i (row operation on coefficient matrix)
				// Y_j := Y_j ⊕ v_j * Y_i (row operation on RHS vector)
				for (u64 b = 0; b < B; ++b)
				{
					for (u64 j = 0; j < mM; ++j)
					{
						for (u64 k = 0; k < M[b].cols(); ++k)
							M[b](j, k) ^= MY[b](j, k);
						for (u64 k = 0; k < Y[b].cols(); ++k)
							Y[b](j, k) ^= MY[b](j, k + M[b].cols());
					}
				}
			}

			if (mPrint)
				co_await printMtxV(mC, M, "Matrix M after elimination", sock);

			// ===================================================================
			// STEP 2: COMBINE SUPPORT VECTORS
			// ===================================================================
			// Compute σ := ⊕_{i ∈ [m]} s_i
			// σ[j] = 1 means column j is a pivot column (dependent variable)
			// σ[j] = 0 means column j is a free variable
			std::vector<std::vector<u8>> sigma(B), negSigma(B);
			for (u64 b = 0; b < B; ++b)
			{
				// Initialize sigma and negSigma for each instance
				sigma[b].resize(c8);
				negSigma[b].resize(c8);
				assert(c8 == s[b].cols());


				//std::vector<std::vector<u8>> sigma(s.cols()), negSigma(s.cols());
				for (u64 i = 0; i < s[b].rows(); ++i)
				{
					for (u64 j = 0; j < s[b].cols(); ++j)
						sigma[b][j] ^= s[b](i, j);
				}

				// Compute σ̄ := (1)^c ⊕ σ (complement for free variables)
				// negSigma represents the free variables that can be set randomly
				for (u64 j = 0; j < s[b].cols(); ++j)
					negSigma[b][j] = sigma[b][j] ^ -mPartyIdx;
			}

			if (mPrint)
				co_await printV(mC, sigma, "Support vector σ (pivot columns)", sock);

			// ===================================================================
			// STEP 3: SAMPLE FREE VARIABLES
			// ===================================================================
			// x ← G^c ⊙ σ̄ (assign random values to free variables)
			// The free variables (where negSigma[j] = 1) get random values
			for (u64 b = 0; b < B; ++b)
			{
				prng.get(X[b].data(), X[b].size());
				if (mLogG % 8)
				{
					// trim the last byte of X if mLogG is not a multiple of 8
					auto trailMask = (1 << (mLogG % 8)) - 1;
					for (u64 i = 0; i < X[b].rows(); ++i)
						X[b][i].back() &= trailMask;
				}
				//co_await multiply(mLogG, negSigma[b], X[b], X[b], sock);
			}
			co_await multiplyMany(mLogG, negSigma, X, X, sock);


			if (mPrint)
				co_await printMtxV(mLogG, X, "X after sampling free variables", sock);

			// ===================================================================
			// STEP 4: BACK-SUBSTITUTE
			// ===================================================================
			// y := y ⊕ M * x (update RHS to cancel the effect of free variables)
			std::vector<Matrix<u8>> Y2(B);
			for (u64 b = 0; b < B; ++b)
			{
				Y2[b] = Matrix<u8>(mM, g8);
				//co_await multiplyMtx(mLogG, M[b], X[b], Y2[b], sock);
			}
			co_await multiplyMtxMany(mLogG, M, X, Y2, sock);

			if (mPrint)
				co_await printMtxV(mLogG, Y2, "Y2=M * X (correction term)", sock);

			// Apply the correction: Y = Y + M*X
			for (u64 b = 0; b < B; ++b)
			{
				for (u64 i = 0; i < Y[b].size(); ++i)
					Y[b](i) ^= Y2[b](i);
			}

			// ===================================================================
			// STEP 5: RECOVER SOLUTION
			// ===================================================================
			// x := x ⊕ s · y (route final values using support vector permutation)
			// The support vectors s tell us where to place the solved values from y
			std::vector<Matrix<u8>> YT(B);// Y transposed for matrix multiplication
			std::vector<Matrix<u8>> XT(B);  // Result of s^T * Y^T
			std::vector<Matrix<u8>> X2(B);  // Final correction term
			for (u64 b = 0; b < B; ++b)
			{
				YT[b] = Matrix<u8>(mLogG, m8);// Y transposed for matrix multiplication
				XT[b] = Matrix<u8>(mLogG, c8);  // Result of s^T * Y^T
				X2[b] = Matrix<u8>(mC, g8);// Final correction term

				transpose(Y[b], YT[b]);
				//co_await multiplyMtx(mC, YT[b], s[b], XT[b], sock);
			}

			co_await multiplyMtxMany(mC, YT, s, XT, sock);

			for (u64 b = 0; b < B; ++b)
			{
				transpose(XT[b], X2[b]);

				// Apply the final correction: X = X + s * Y
				for (u64 i = 0; i < X[b].size(); ++i)
					X[b](i) ^= X2[b](i);
			}

			if (mPrint)
				co_await printMtxV(mLogG, X, "Final solution X", sock);


			if (mMult.mOtIdx != mMult.mTotalMults)
				throw RTE_LOC;

			if (mPrint)
			{
				for (auto b = 0; b < B; ++b)
				{

					Matrix<u8> M2(MM[b].rows(), MM[b].cols());
					Matrix<u8> Y2(YY[b].rows(), YY[b].cols());
					Matrix<u8> X2(X[b]);
					std::copy(MM[B].begin(), MM[B].end(), M2.begin());
					std::copy(YY[B].begin(), YY[B].end(), Y2.begin());

					co_await sock.send(std::vector<u8>(M2.begin(), M2.end()));
					co_await sock.send(std::vector<u8>(Y2.begin(), Y2.end()));
					co_await sock.send(std::vector<u8>(X2.begin(), X2.end()));
					co_await sock.recv(M2);
					co_await sock.recv(Y2);
					co_await sock.recv(X2);
					for (u64 i = 0; i < M2.size(); ++i)
						M2(i) ^= MM[b](i);
					for (u64 i = 0; i < Y2.size(); ++i)
						Y2(i) ^= YY[b](i);
					for (u64 i = 0; i < X2.size(); ++i)
						X2(i) ^= X[b](i);

					if (mPartyIdx)
					{
						printMtx(mC, M2, "Final M");
						printMtx(mLogG, X2, "Final X");
						printMtx(mLogG, Y2, "Final Y");
						std::cout << "\n" << Color::Blue << "=== Verifying M * X = Y ===" << Color::Default << std::endl;
					}

					// Compute M * X using bit-wise matrix multiplication
					Matrix<u8> computed_Y(M2.rows(), Y[b].cols());
					std::fill(computed_Y.begin(), computed_Y.end(), 0);
					std::vector<u8> skips(M[b].rows(), true);

					// For each row i of M and each column j of Y
					for (u64 i = 0; i < M[b].rows(); ++i)
					{
						for (u64 j = 0; j < M2.cols(); ++j)
							if (M2(i, j))
								skips[i] = false;
						if (skips[i])
							continue;

						for (u64 k = 0; k < mC; ++k)  // k iterates over columns of M / rows of X
						{
							// Get the k-th bit of M[i]
							auto M_ik = *BitIterator(M2[i].data(), k);
							if (mPartyIdx)
								std::cout << M_ik << " ";

							if (M_ik)  // Only add if the bit is set
							{
								// Add X[k] to computed_Y[i]
								for (u64 j = 0; j < Y2.cols(); ++j)
								{
									computed_Y(i, j) ^= X2(k, j);
								}
							}
						}
						std::cout << "\n";
					}

					// Compare computed_Y with actual Y
					bool isCorrect = true;
					u64 errorCount = 0;
					for (u64 i = 0; i < Y2.rows(); ++i)
					{
						BitVector ey(computed_Y[i].data(), mLogG);
						BitVector ay(Y2[i].data(), mLogG);
						if (ey != ay && !skips[i])
						{
							isCorrect = false;
							errorCount++;
							if (mPartyIdx && errorCount <= 10)  // Limit error output
							{
								std::cout << Color::Red << "Mismatch at " << i << "): \n"
									<< "  act = " << ay << "\n"
									<< "  exp = " << ey << "\n"
									<< "      = " << BitVector(M2[i].data(), mC) << "\n"
									<< "      * Y \n";

								std::cout << Color::Default;
							}
						}
					}


					// Sync both parties
					co_await sock.send(char(isCorrect ? 1 : 0));
					char otherResult;
					co_await sock.recv(otherResult);

					if (mPartyIdx)
					{
						if (isCorrect && otherResult == 1)
						{
							std::cout << Color::Green << "Both parties agree: Verification PASSED"
								<< Color::Default << std::endl;
						}
						else if (!isCorrect || otherResult == 0)
						{
							std::cout << Color::Red << "Verification FAILED (Party " << mPartyIdx
								<< ": " << (isCorrect ? "PASS" : "FAIL")
								<< ", Other party: " << (otherResult ? "PASS" : "FAIL") << ")"
								<< Color::Default << std::endl;
						}
					}

					if (!otherResult || !isCorrect)
						throw RTE_LOC;

				}
			}
		}

		void clear()
		{
			mMult.clear();	
			mPrint = false;
			mPrintIdx = 0;
			mBatchSize = 1;
			mM = 0;
			mC = 0;
			mLogG = 0;
		}
	};





}