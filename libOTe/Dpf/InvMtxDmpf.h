#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Dpf/SparseDpf.h"
#include "InvMtxDmpf/Dedup.h"
#include "InvMtxDmpf/GoldreichHash.h"
#include "InvMtxDmpf/WaksmanPermute.h"
#include "InvMtxDmpf/BinarySolver.h"
#include "SparseDpf.h"
namespace osuCrypto
{

	struct InvMtxDmpf
	{

		u64 mPartyIdx = 0;

		// t
		u64 mNumPoints = 0;

		// N
		u64 mDomain = 0;

		// the required bits to represent the domain plus 1
		u64 mIndexBitCount = 0; // log2ceil(mDomain+1);

		// w
		u64 mNumPartitions = 0;

		// m
		u64 mPartitionSize = 0;

		// lambda
		u64 mLinearSecParam = 0;

		u64 mCuckooSecParam = 0;

		// |G|
		u64 mValueByteCount = 0;

		bool mPrint = false;

		Dedup mDedup;
		std::vector<GoldreichHash> mGoldreichHash;
		WaksmanPermute mWaksmanPermute;
		std::vector<BinarySolver> mBinarySolver;
		SparseDpf mSparseDpf;

		void init(
			u64 partyIdx,
			u64 numPoints,
			u64 domain,
			u64 valueByteCount,
			u64 numPartitions = 2,
			u64 cuckooSecParam = 2,
			u64 linearSecParam = 40)
		{
			mPartyIdx = partyIdx;
			mNumPoints = numPoints;
			mDomain = domain;
			mIndexBitCount = log2ceil(mDomain + 1);
			mNumPartitions = numPartitions;
			mCuckooSecParam = cuckooSecParam;
			mLinearSecParam = linearSecParam;
			mValueByteCount = valueByteCount;


			switch (numPartitions)
			{
			case 2:
				// nextPowerOfTwo(mNumPoints * 2 / mPartitionSize);
				mPartitionSize = 1ull << log2ceil(divCeil(2 * numPoints, mNumPartitions));
				break;
			case 3:
				// nextPowerOfTwo(mNumPoints * 1.5 / mPartitionSize);
				mPartitionSize = 1ull << log2ceil(divCeil(3 * numPoints, 2 * mNumPartitions));
				break;
			default:
				throw std::runtime_error("numPartitions must be 2 or 3. " LOCATION);
			}

			mDedup.init(mPartyIdx, mNumPoints, mIndexBitCount);

			auto f = mNumPartitions * mPartitionSize;
			auto c = mPartitionSize + mLinearSecParam;

			mWaksmanPermute.init(mPartyIdx, f);

			mGoldreichHash.resize(mNumPartitions);
			for (auto& hash : mGoldreichHash)
				hash.init(mPartyIdx, mPartitionSize, divCeil(mIndexBitCount, 8), divCeil(c, 8));

			mBinarySolver.resize(mNumPartitions);
			for (auto& solver : mBinarySolver)
				solver.init(mPartyIdx, mPartitionSize, c, log2ceil(mPartitionSize));

			auto denseDepth = log2ceil(f) + 2;
			mSparseDpf.init(mPartyIdx, f, mDomain, denseDepth);

		}

		struct BaseCount
		{
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		BaseCount baseOtCount() const
		{
			auto count0 = mDedup.baseOtCount();
			auto count2 = mWaksmanPermute.baseOtCount();
			auto count3 = mSparseDpf.baseOtCount();
			auto recv = count0.mRecvCount + count2.mRecvCount + count3;
			auto send = count0.mSendCount + count2.mSendCount + count3;
			for (auto& hash : mGoldreichHash)
			{
				auto count = hash.baseOtCount();
				recv += count.mRecvCount;
				send += count.mSendCount;
			}

			for (auto& solver : mBinarySolver)
			{
				auto count = solver.baseOtCount();
				recv += count;
				send += count;
			}

			return { recv, send };
		}

		void setBaseOts(
			span<const std::array<block, 2>>baseSend,
			span<const block>  baseRecv,
			const BitVector& recvChoice)
		{
			auto counts = baseOtCount();
			if (baseRecv.size() != counts.mRecvCount ||
				baseSend.size() != counts.mSendCount ||
				recvChoice.size() != counts.mRecvCount)
				throw std::runtime_error("baseRecv or baseSend is too small. " LOCATION);

			u64 rIdx = 0, sIdx = 0;
			auto set = [&](auto& sub) {
				auto counts = sub.baseOtCount();
				u64 rc, sc;
				if constexpr (std::is_same_v<std::remove_reference_t<decltype(counts)>, u64>)
				{
					rc = counts;
					sc = counts;
				}
				else
				{
					rc = counts.mRecvCount;
					sc = counts.mSendCount;
				}
				auto recv = baseRecv.subspan(rIdx, rc);
				auto bits = recvChoice.subvec(rIdx, rc);
				auto send = baseSend.subspan(sIdx, sc);
				sub.setBaseOts(send, recv, bits);
				};

			set(mDedup);
			set(mWaksmanPermute);
			for (auto& hash : mGoldreichHash)
				set(hash);
			for (auto& solver : mBinarySolver)
				set(solver);
			set(mSparseDpf);
		}

		// compute the inner product of h and s.
		// h is a vector of bits, s is a matrix of bits.
		u64 innerProd(span<const u8> h, MatrixView<const u8> s)
		{
			if (divCeil(s.rows(), 8) != h.size())
				throw std::runtime_error("h and s size mismatch. " LOCATION);
			if (s.cols() > sizeof(u64))
				throw std::runtime_error("s.cols() must be at most sizeof(u64). " LOCATION);

			u64 res = 0;
			u64 val = 0;
			for (u64 i = 0; i < s.rows(); ++i)
			{
				copyBytesMin(val, s[i]);
				res ^= bit(h, i) * val; // XOR the bit with the value
			}
			return res;
		}

		template<typename Output>
		macoro::task<> expand(
			span<u64> points,
			span<block> values,
			Output&& output,
			PRNG& prng,
			coproto::Socket& sock)
		{
			// Check input parameters
			if (points.size() != values.size() || points.size() != mNumPoints)
				throw std::runtime_error("points and values size mismatch. " LOCATION);

			if (mPrint)
				co_await print(points, values, sock, "input*");
			// Step 2: Deduplication
			Matrix<u8> A(points.size(), divCeil(mIndexBitCount, 8));
			Matrix<u8> altKeys(points.size(), divCeil(mIndexBitCount, 8));
			Matrix<u8> B(values.size(), sizeof(block));
			copyBytes(B, values); // Copy values to B

			// Convert points to u32 for deduplication
			for (u64 i = 0; i < points.size(); ++i)
			{
				copyBytesMin(A[i], points[i]);
				copyBytesMin(altKeys[i], mDomain);  // Use indices as alternate keys
			}

			if (mPrint)
				co_await print(A, {}, B, sock, "input");

			// Step 2: Deduplication of [A], [B]
			co_await mDedup.dedup(A, B, altKeys, prng, sock);

			if (mPrint)
				co_await print(A, {}, B, sock, "dedup");


			// Step 3-4: Apply hash functions and generate permutation
			auto f = mNumPartitions * mPartitionSize;
			auto c = mPartitionSize + mLinearSecParam;

			// Step 5-6: Setup A and B matrices
			Matrix<u8> AB(f, A.cols() + B.cols());
			for (u64 i = 0; i < points.size(); ++i)
			{
				copyBytesMin(AB[i], A[i]); // Copy A
				copyBytesMin(AB[i].subspan(A.cols()), B[i]); // Copy B
			}
			for (u64 i = points.size(); i < f; ++i)
			{
				copyBytesMin(AB[i].subspan(0, A.cols()), mDomain * mPartyIdx); // default the extras 
			}

			// Step 7: Permute (A||b) by π
			co_await mWaksmanPermute.apply(AB, prng.get<block>(), sock);

			// extract the parts
			A.resize(f, A.cols()); // Resize A to f rows
			B.resize(f, B.cols()); // Resize A to f rows
			for (u64 i = 0; i < f; ++i)
			{
				copyBytesMin(A[i], AB[i].subspan(0, A.cols())); // Copy A from AB
				copyBytesMin(B[i], AB[i].subspan(A.cols(), B.cols())); // Copy B from AB
			}

			if (mPrint)
				co_await print(A, {}, B, sock, "perm");


			std::vector<block> hashSeed(mNumPartitions);
			{
				AES aes(block(523234789928736, 754378923479832796));
				for (u64 i = 0; i < mNumPartitions; ++i)
				{
					aes.ecbEncBlock(block(i), hashSeed[i]);
				}
			}

			// Step 8: Construct M_i using hash functions
			Matrix<u8> M(AB.rows(), divCeil(c, 8));
			Matrix<u8> S(c * mNumPartitions, divCeil(log2ceil(mPartitionSize), 8));
			std::vector<task<>> tasks;
			std::vector<Socket> socks(mNumPartitions);
			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				auto M_i = M.submtx(i * mPartitionSize, mPartitionSize);
				auto A_i = A.submtx(i * mPartitionSize, mPartitionSize);
				socks[i] = sock.fork(); // Fork socket for each partition

				//mGoldreichHash[i].mPrint = true;
				tasks.push_back(mGoldreichHash[i].hash(A_i, M_i, socks[i], hashSeed[i]));
			}
			auto res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();

			if (mPrint)
				co_await print(A, M, B, sock, "hash*");

			// Prepare y_i vector (0, 1, ..., m-1)
			Matrix<u8> Y_i(mPartitionSize, divCeil(log2ceil(mPartitionSize), 8));
			for (u64 j = 0; j < mPartitionSize; ++j)
			{
				auto val = j * mPartyIdx;
				copyBytesMin(Y_i[j], val);
			}

			// Step 8-9: Create the matrices M_i and solve linear systems
			Matrix<u8> HDomain(mNumPartitions, M.cols());
			Matrix<u8> ADomain(1, A.cols());
			copyBytesMin(ADomain, mDomain);
			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				auto M_i = M.submtx(i * mPartitionSize, mPartitionSize);
				auto S_i = S.submtx(i * c, c);

				//mGoldreichHash[i].mPrint = mPrint && mPartyIdx;
				mGoldreichHash[i].hash(ADomain, HDomain.submtx(i, 1), hashSeed[i]);
				if (mPartyIdx)
				{
					for (u64 j = 0; j < M_i.rows(); ++j)
						for (u64 k = 0; k < M_i.cols(); ++k)
							M_i(j, k) ^= HDomain(i, k); // XOR the hash into M_i
				}
				//mBinarySolver[i].mPrint = mPrint;

				// Step 9: Binary solver to compute [s_i] = bin-solver([M_i], [y_i])
				tasks.push_back(mBinarySolver[i].solve(M_i, Y_i, S_i, prng, socks[i]));
			}

			if (mPrint)
				co_await print(A, M, B, sock, "hash");

			res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();


			// Step 10: Reveal([s_i]), implicit in step 11
			co_await sock.send(coproto::copy(S));
			{
				Matrix<u8> SRecv(S.rows(), S.cols());
				co_await sock.recv(SRecv);
				for (u64 i = 0; i < S.size(); ++i)
				{
					S(i) ^= SRecv(i);
				}
				if (mPrint && mPartyIdx)
				{
					for (u64 j = 0; j < mNumPartitions; ++j)
					{
						auto Sj = S.submtx(j * c, c);
						std::cout << "S[" << j << "]: ";
						for (u64 i = 0; i < Sj.rows(); ++i)
							std::cout << toHex(Sj[i]) << " ";
						std::cout << std::endl;
					}
				}
			}

			// Step 11: Calculate h_i,j via hash function
			// This step is handled by SparseDpf configuration below
			Matrix<u8> H(mDomain * mNumPartitions, mGoldreichHash[0].mOutBytes);
			Matrix<u8> I(mDomain, mGoldreichHash[0].mInBytes);
			for (u64 i = 0; i < mDomain; ++i)
				copyBytesMin(I[i], i);

			for (u64 j = 0; j < mNumPartitions; ++j)
				mGoldreichHash[j].hash(I,
					H.submtx(j * mDomain, mDomain), hashSeed[j]);


			if (mPartyIdx && mPrint)
			{
				//std::cout << " ------------ h* ------------- " << std::endl;

				//for (u64 i = 0; i < mDomain; ++i)
				//{
				//	std::cout << i << ": ";
				//	for (u64 j = 0; j < mNumPartitions; ++j)
				//	{
				//		std::cout << toHex(H[i + j * mDomain]) << ", ";
				//	}
				//	std::cout << std::endl;
				//}
				std::cout << " ------------ h ------------- " << std::endl;
			}

			// Step 13-14: Compute S_j and invoke sparse-DPF
			std::vector<std::vector<u32>> sparseSets(f);

			// Configure sparse points for SparseDpf
			std::vector<u8> Hij(H.cols());
			for (u64 i = 0; i < mDomain; ++i)
			{
				if (mPartyIdx && mPrint)
					std::cout << i << ": ";
				for (u64 j = 0; j < mNumPartitions; ++j)
				{
					copyBytes(Hij, H[i + j * mDomain]);
					for (u64 k = 0; k < Hij.size(); ++k)
						Hij[k] ^= HDomain(j, k);

					u64 h = innerProd(Hij, S.submtx(j * c, c)) + j * mPartitionSize;
					if (mPartyIdx && mPrint)
						std::cout << h << " = " << toHex(Hij) << " * Sj, ";
					sparseSets[h].push_back(i);
				}
				if (mPartyIdx && mPrint)
					std::cout << std::endl;
			}

			// Step 15-16: Initialize and compute final output
			std::vector<block> y(mDomain, ZeroBlock);
			std::vector<u64> A64(A.rows());
			std::vector<block> BB(A.rows());
			for (u64 i = 0; i < A.rows(); ++i)
			{
				copyBytesMin(A64[i], A[i]);
				copyBytes(BB[i], B[i]);
			}

			std::vector<std::vector<block>> shares(f);
			for (u64 j = 0; j < f; ++j)
			{
				shares[j].resize(sparseSets[j].size());

				if (mPartyIdx && mPrint)
				{
					for (u64 i = 0; i < sparseSets[j].size(); ++i)
					{
						std::cout << sparseSets[j][i] << ", ";
					}
					std::cout << std::endl;
				}
			}

			// Step 14: Invoke sparse-DPF for each S_j set
			co_await mSparseDpf.expand(
				A64,
				BB,
				[&](u64 r, u64 i, block val, u8 tag) {
					// Step 17: Output final result
					shares[r][i] = val;
					auto idx = sparseSets[r][i];
					y[idx] = y[idx] ^ val;
				},
				prng,
				sparseSets,
				sock
			);

			if (mPrint)
			{
				co_await sock.send(coproto::copy(A64));
				co_await sock.send(coproto::copy(BB));
				for (u64 i = 0; i < shares.size(); ++i)
				{
					co_await sock.send(coproto::copy(shares[i]));
				}
				std::vector<u64> A64Recv(A64.size());
				std::vector<block> BBRecv(BB.size());
				co_await sock.recv(A64Recv);
				co_await sock.recv(BBRecv);

				for (u64 i = 0; i < shares.size(); ++i)
				{
					std::vector<block> sharesRecv(shares[i].size());
					co_await sock.recv(sharesRecv);
					if (mPartyIdx)
					{

						std::cout << "shares[" << i << "] @ " << (A64[i] ^ A64Recv[i])
							<< " " << (BB[i] ^ BBRecv[i]) << ":\n";
						for (u64 j = 0; j < shares[i].size(); ++j)
						{
							std::cout << sparseSets[i][j] << " "
								<< (shares[i][j] ^ sharesRecv[j]) << std::endl;
						}
						std::cout << std::endl;
					}
				}
			}


			for (u64 i = 0; i < y.size(); ++i)
			{
				output(i, y[i]);
			}

			co_return;
		}


		task<> print(MatrixView<u8> keys, MatrixView<u8> hash, MatrixView<u8> values, coproto::Socket& sock, const std::string& name) const
		{
			Matrix<u8> keysCopy = keys;
			Matrix<u8> hashCopy = hash;
			Matrix<u8> valuesCopy = values;
			if (keysCopy.size())
			{
				co_await sock.send(coproto::copy(keysCopy));
				co_await sock.recv(keysCopy);
			}
			if (hashCopy.size())
			{
				co_await sock.send(coproto::copy(hashCopy));
				co_await sock.recv(hashCopy);
			}
			co_await sock.send(coproto::copy(valuesCopy));
			co_await sock.recv(valuesCopy);

			for (u64 i = 0; i < keys.size(); ++i)
				keysCopy(i) ^= keys(i);
			for (u64 i = 0; i < values.size(); ++i)
				valuesCopy(i) ^= values(i);
			for (u64 i = 0; i < hashCopy.size(); ++i)
				hashCopy(i) ^= hash(i);

			auto reverse = [](span<u8> b) {
				for (u64 i = 0; i < b.size() / 2; ++i)
					std::swap(b[i], b[b.size() - 1 - i]);
				return b;
				};

			if (mPartyIdx)
			{
				std::cout << name << std::endl;
				for (u64 i = 0; i < valuesCopy.rows(); ++i)
				{
					std::cout << i << ": ";

					if (keysCopy.size())
					{
						u64 k = 0;
						copyBytesMin(k, keysCopy[i]);
						std::cout << std::setw(4) << k;
					}
					std::cout << " | ";
					if (hashCopy.size())
					{
						std::cout << toHex(hashCopy[i]);
					}
					std::cout << " | " << toHex(reverse(valuesCopy[i])) << std::endl;

				}
				std::cout << "------------------------" << std::endl;
			}
		}


		task<> print(span<u64> keys, span<block> values, coproto::Socket& sock, const std::string& name) const
		{
			std::vector<u64> keysCopy(keys.begin(), keys.end());
			std::vector<block> valuesCopy(values.begin(), values.end());
			co_await sock.send(coproto::copy(keysCopy));
			co_await sock.send(coproto::copy(valuesCopy));
			co_await sock.recv(keysCopy);
			co_await sock.recv(valuesCopy);

			for (u64 i = 0; i < keys.size(); ++i)
				keysCopy[i] ^= keys[i];
			for (u64 i = 0; i < values.size(); ++i)
				valuesCopy[i] ^= values[i];

			if (mPartyIdx)
			{
				std::cout << name << std::endl;
				for (u64 i = 0; i < keys.size(); ++i)
				{

					u64 k = 0;
					copyBytesMin(k, keysCopy[i]);

					std::cout << i << ": " << std::setw(4) << k << " | " << valuesCopy[i] << std::endl;

				}
				std::cout << "------------------------" << std::endl;
			}
		}

	};

}