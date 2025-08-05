#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Dpf/SparseDpf.h"
#include "RevCuckoo/Dedup.h"
#include "RevCuckoo/GoldreichHash.h"
#include "RevCuckoo/WaksmanPermute.h"
#include "RevCuckoo/BinarySolver.h"
#include "SparseDpf.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "cryptoTools/Common/Timer.h"
namespace osuCrypto
{

	template<typename T, typename CoeffCtx = DefaultCoeffCtx<T>>
	struct RevCuckooDmpf : TimerAdapter
	{

		u64 mPartyIdx = 0;

		// t
		u64 mNumPointsPerSet = 0;

		u64 mNumSets = 0;

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

		// arbitrary seed for the hash function
		block mHashSeed = block(3498747860745238796ull, 2347966293789782347ull);

		bool mPrint = false;

		u64 mPrintIndex = ~0;

		std::vector<Dedup> mDedup;
		std::vector<GoldreichHash> mGoldreichHash;
		std::vector<WaksmanPermute> mWaksmanPermute;
		std::vector<BinarySolver> mBinarySolver;
		SparseDpf mSparseDpf;

		// the leaf values for the sparse DPFs.
		std::vector<std::vector<block>> mLeafShares;

		// the leaf tags for the sparse DPFs.
		std::vector<std::vector<u8>> mLeafTags;

		std::vector<std::span<u32>> mSparseSets;
		std::unique_ptr<u32[]> mSparseSetBuf;

		DpfMult mMultiplier;

		DpfMult::MultSession mMultSession;

		// temp storage 
		using VecT = typename CoeffCtx::template Vec<T>;

		VecT mTempOutput;
		std::vector<VecT> mExpanded;


		bool mCharacteristicTwo = true;

		void init(
			u64 partyIdx,
			u64 numPointsPerSet,
			u64 numSets,
			u64 domain,
			u64 numPartitions = 2,
			u64 cuckooSecParam = 2,
			u64 linearSecParam = 40,
			bool characteristicTwo = false)
		{
			mPartyIdx = partyIdx;
			mNumPointsPerSet = numPointsPerSet;
			mNumSets = numSets;
			mDomain = domain;
			mIndexBitCount = log2ceil(mDomain + 1);
			mNumPartitions = numPartitions;
			mCuckooSecParam = cuckooSecParam;
			mLinearSecParam = linearSecParam;


			switch (numPartitions)
			{
			case 2:
				// nextPowerOfTwo(mNumPointsPerSet * 2 / mPartitionSize);
				mPartitionSize = 1ull << log2ceil(divCeil(2 * numPointsPerSet, mNumPartitions));
				break;
			case 3:
				// nextPowerOfTwo(mNumPointsPerSet * 1.5 / mPartitionSize);
				mPartitionSize = 1ull << log2ceil(divCeil(3 * numPointsPerSet, 2 * mNumPartitions));
				break;
			default:
				throw std::runtime_error("numPartitions must be 2 or 3. " LOCATION);
			}

			auto f = mNumPartitions * mPartitionSize;
			auto c = mPartitionSize + mLinearSecParam;

			mDedup.resize(mNumSets);
			mWaksmanPermute.resize(mNumSets);

			for (u64 s = 0; s < mNumSets; ++s)
			{
				mDedup[s].init(mPartyIdx, mNumPointsPerSet, mIndexBitCount);
				mWaksmanPermute[s].init(mPartyIdx, f);

			}

			mGoldreichHash.resize(mNumPartitions * mNumSets);
			for (auto& hash : mGoldreichHash)
				hash.init(mPartyIdx, mPartitionSize, divCeil(mIndexBitCount, 8), divCeil(c, 8));

			mBinarySolver.resize(mNumPartitions * mNumSets);
			for (auto& solver : mBinarySolver)
				solver.init(mPartyIdx, mPartitionSize, c, log2ceil(mPartitionSize));

			auto denseDepth = log2ceil(f) + 2;
			mSparseDpf.init(mPartyIdx, mNumSets * f, mDomain, denseDepth);


			mCharacteristicTwo = characteristicTwo;
			if (mCharacteristicTwo == false)
			{
				mMultiplier.init(mPartyIdx, mNumSets * f);
			}

		}

		struct BaseCount
		{
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		BaseCount baseOtCount() const
		{
			auto count3 = mSparseDpf.baseOtCount();
			auto recv = count3;
			auto send = count3;

			for (auto& dedup : mDedup)
			{
				auto count = dedup.baseOtCount();
				recv += count.mRecvCount;
				send += count.mSendCount;
			}

			for (auto& permute : mWaksmanPermute)
			{
				auto count = permute.baseOtCount();
				recv += count.mRecvCount;
				send += count.mSendCount;
			}

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

			recv += mMultiplier.baseOtCount();
			send += mMultiplier.baseOtCount();

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

			for (auto& sub : mDedup)
				set(sub);
			for (auto& sub : mWaksmanPermute)
				set(sub);
			for (auto& hash : mGoldreichHash)
				set(hash);
			for (auto& solver : mBinarySolver)
				set(solver);

			set(mSparseDpf);

			if (mCharacteristicTwo == false)
				set(mMultiplier);
		}


		void bitMask(const uint8_t* bits, uint8_t* out, size_t size) {
			for (size_t i = 0; i < size; ++i) {
				uint8_t byte = bits[i];
				for (int j = 0; j < 8; ++j) {
					out[i * 8 + j] = -(int8_t)((byte >> j) & 1);
				}
			}
		}

		// compute the inner product of h and s.
		// h is a vector of bits, s is a matrix of bits.
		// h has `rows` bits. s has size (rows, cols).
		void innerProd(const u8* h, u64 hCount, const u8* s, u64 size, u8* outputs)
		{
			for (u64 i = 0; i < hCount; ++i)
			{
				u8 prod = 0;
				for (u64 j = 0; j < size; ++j)
				{
					auto sj = s + j * 8;
					auto hj = h[j];
					u8 masks[8];

					for (int k = 0; k < 8; ++k)
						masks[k] = -(int8_t)((hj >> k) & 1);

					for (int k = 0; k < 8; ++k)
						prod ^= masks[k] & sj[k];
				}
				h += size;
				outputs[i] ^= prod;
			}
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

		void buildSparseSets(
			u64 f,
			u64 c,
			std::vector<Matrix<u8>>& S,
			Matrix<u8>& H,
			Matrix<u8>& HDomain)
		{
			mSparseSets.resize(f * mNumSets);
			setTimePoint("sparseSets Begin");
			double expectedLoad = static_cast<double>(mNumPartitions * mDomain) / f;

			// Chernoff bound: for Poisson(λ), Pr[X ≥ λ + t] ≤ exp(-t²/(2(λ + t/3)))
			// Setting failure probability to 2^(-40), we get maxLoad ≈ λ + sqrt(2λ * 40 * ln(2)) + (80 * ln(2))/3
			u64 maxLoad = static_cast<u64>(expectedLoad + std::sqrt(2 * expectedLoad * mLinearSecParam * std::log(2.0)) + (mLinearSecParam * 2 * std::log(2.0)) / 3) + 1;

			std::vector<u32> sizes(mSparseSets.size());
			mSparseSetBuf = std::make_unique<u32[]>(f * mNumSets * maxLoad);
			//for (u64 i =0; i < mSparseSets.size(); ++i)
			//	mSparseSets[i] = std::span<u32>(mSparseSetsBuf.get() + i * maxLoad, maxLoad);

			setTimePoint("sparseSets alloc");


			constexpr auto stepSize = 32;
			auto stride = H.cols();
			auto d32 = mDomain / stepSize * stepSize;
			u8 h[stepSize];
			//u8 t[stepSize];
			// we assume at most this many partitions. 
			// this assumption is in the inner product 
			// where we assume the values being computed 
			// over is just a byte. Easily generalized...
			if (mPartitionSize > 256)
				throw RTE_LOC;

			assert(stride == divCeil(c, 8));



			for (u64 s = 0; s < mNumSets; ++s)
			{
				if (S[s].cols() != 1)
					throw RTE_LOC; // same assumption as mPartitionSize <= 256

				for (u64 j = 0; j < mNumPartitions; ++j)
				{
					auto HDj = HDomain.data(j);
					//auto* setj = mSparseSets.data() + s * f + j * mPartitionSize;
					auto setj = mSparseSetBuf.get() + (s * f + j * mPartitionSize) * maxLoad;
					auto sizej = &sizes[s * f + j * mPartitionSize];
					auto Hj = H.data(j * mDomain);

					std::vector<u8> Ssj(stride * 8);
					for (u64 i = 0; i < c; ++i)
						Ssj[i] = S[s](j* c + i);

					u8 HDOffset = 0;
					innerProd(HDj, 1, Ssj.data(), stride, &HDOffset);

					for (u64 i = 0; i < d32; i += stepSize)
					{
						//for (u64 k = 0; k < stepSize; ++k)
						//{
						//	auto Hij = Hj + (i+k) * stride;
						//	t[k] = HDOffset;
						//	innerProd(Hij, 1, Ssj.data(), stride, &t[k]);
						//}

						auto Hij = Hj + i * stride;
						memset(h, HDOffset, stepSize);
						innerProd(Hij, stepSize, Ssj.data(), stride, h);

						for (u64 k = 0; k < stepSize; ++k)
						{
							//if (t[k] != h[k])
							//	throw RTE_LOC;
							assert(h[k] < mPartitionSize && "bad sparse set index ");

							auto setjh = setj + h[k] * maxLoad;
							auto idx = sizej[h[k]]++;
							assert(idx < maxLoad && "Sparse set overflow. ");
							setjh[idx] = i + k;


							//setj[h[k]].push_back(i + k);
						}
					}

					for (u64 i = d32; i < mDomain; ++i)
					{
						auto Hij = Hj + i * stride;

						h[0] = HDOffset;
						innerProd(Hij, 1, Ssj.data(), stride, h);

						assert(h[0] < mPartitionSize);
						//setj[h[0]].push_back(i);

						auto setjh = setj + h[0] * maxLoad;
						auto idx = sizej[h[0]]++;
						assert(idx < maxLoad && "Sparse set overflow. ");
						setjh[idx] = i;
					}
				}
			}


			for (u64 i = 0; i < mSparseSets.size(); ++i)
				mSparseSets[i] = std::span<u32>(mSparseSetBuf.get() + i * maxLoad, sizes[i]);


			setTimePoint("sparseSets done");
		}




		macoro::task<> setPoints(
			Matrix<u64> points,
			PRNG& prng,
			coproto::Socket& sock)
		{
			MACORO_TRY{
				setTimePoint("setPoints");

			// Check input parameters
			if (points.rows() != mNumSets)
				throw std::runtime_error("points and values size mismatch. " LOCATION);
			if (points.cols() != mNumPointsPerSet)
				throw std::runtime_error("points and values size mismatch. " LOCATION);

			for (u64 s = 0; s < mNumSets; ++s)
			{
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print(points[s], sock, "input*");
			}


			// Step 2: Deduplication
			std::vector<Matrix<u8>> A(mNumSets);
			std::vector<Matrix<u8>> altKeys(mNumSets);

			std::vector<task<>> tasks;
			std::vector<Socket> socks(mNumSets * mNumPartitions);
			for (u64 s = 0; s < socks.size(); ++s)
				socks[s] = sock.fork(); // Fork socket for each partition

			for (u64 s = 0; s < mNumSets; ++s)
			{
				A[s].resize(mNumPointsPerSet, divCeil(mIndexBitCount, 8));
				altKeys[s].resize(mNumPointsPerSet, divCeil(mIndexBitCount, 8));

				// Convert points to u32 for deduplication
				for (u64 i = 0; i < mNumPointsPerSet; ++i)
				{
					copyBytesMin(A[s][i], points[s][i]);
					copyBytesMin(altKeys[s][i], mDomain * mPartyIdx);  // Use indices as alternate keys
				}

				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print(A[s], {}, sock, "input");


				// Step 2: Deduplication of [A], [B]
				tasks.push_back(mDedup[s].dedupKeys(A[s], altKeys[s], prng, socks[s]));
			}
			setTimePoint("dedup Begin");

			auto res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();
			setTimePoint("dedup done");

			// Step 3-4: Apply hash functions and generate permutation
			auto f = mNumPartitions * mPartitionSize;
			auto c = mPartitionSize + mLinearSecParam;
			auto piCtx = DpfMult::BitMatrixCoeffCtx(A[0].cols() * 8);
			std::vector<decltype(piCtx)::View<u8>> av(mNumSets);
			for (u64 s = 0; s < mNumSets; ++s)
			{
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print(A[s], {}, sock, "dedup");

				// Step 5-6: Setup A and B matrices
				A[s].resize(f, A[s].cols()); // Resize A to f rows
				for (u64 i = mNumPointsPerSet; i < f; ++i)
					copyBytesMin(A[s][i], mDomain * mPartyIdx); // default the extras 

				av[s] = decltype(piCtx)::View<u8>(A[s]);
				// Step 7: Permute (A||b) by π
				tasks.push_back(
					mWaksmanPermute[s].apply<u8>(av[s], socks[s], piCtx));
			}

			setTimePoint("perm Begin");

			// Step 7: Permute (A||b) by π
			res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();
			setTimePoint("perm done");

			std::vector<block> hashSeed(mNumPartitions);
			{
				AES aes(block(523234789928736, 754378923479832796));
				for (u64 i = 0; i < mNumPartitions; ++i)
				{
					aes.ecbEncBlock(block(i), hashSeed[i]);
				}
			}

			std::vector<Matrix<u8>> M(mNumSets);
			std::vector<Matrix<u8>> S(mNumSets);
			for (u64 s = 0, k = 0; s < mNumSets; ++s)
			{

				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print(A[s], {}, sock, "perm");


				// Step 8: Construct M_i using hash functions
				M[s].resize(A[s].rows(), divCeil(c, 8));
				S[s].resize(c * mNumPartitions, divCeil(log2ceil(mPartitionSize), 8));
				for (u64 i = 0; i < mNumPartitions; ++i, ++k)
				{
					auto M_i = M[s].submtx(i * mPartitionSize, mPartitionSize);
					auto A_i = A[s].submtx(i * mPartitionSize, mPartitionSize);

					//mGoldreichHash[i].mPrint = true;
					tasks.push_back(mGoldreichHash[k].hash(
						A_i, M_i, socks[k], hashSeed[i]));
				}

			}
			setTimePoint("hash Begin");

			res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();
			setTimePoint("done Begin");

			// Step 8-9: Create the matrices M_i and solve linear systems
			Matrix<u8> HDomain(mNumPartitions, M[0].cols());
			Matrix<u8> ADomain(1, A[0].cols());
			copyBytesMin(ADomain, mDomain);
			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				mGoldreichHash[i].hash(ADomain, HDomain.submtx(i, 1), hashSeed[i]);
			}

			std::vector<Matrix<u8>> Y_i(mNumSets);
			for (u64 s = 0, k = 0; s < mNumSets; ++s)
			{
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print(A[s], M[s], sock, "hash*");


				// Prepare y_i vector (0, 1, ..., m-1)
				Y_i[s].resize(mPartitionSize, divCeil(log2ceil(mPartitionSize), 8));
				for (u64 j = 0; j < mPartitionSize; ++j)
				{
					auto val = j * mPartyIdx;
					copyBytesMin(Y_i[s][j], val);
				}

				// Step 8-9: Create the matrices M_i and solve linear systems
				copyBytesMin(ADomain, mDomain);
				for (u64 i = 0; i < mNumPartitions; ++i, ++k)
				{
					auto M_i = M[s].submtx(i * mPartitionSize, mPartitionSize);
					auto S_i = S[s].submtx(i * c, c);

					//mGoldreichHash[i].mPrint = mPrint && mPartyIdx;
					if (mPartyIdx)
					{
						for (u64 j = 0; j < M_i.rows(); ++j)
							for (u64 k = 0; k < M_i.cols(); ++k)
								M_i(j, k) ^= HDomain(i, k); // XOR the hash into M_i
					}

					//mBinarySolver[k].mPrint = (k == 0);

					// Step 9: Binary solver to compute [s_i] = bin-solver([M_i], [y_i])
					tasks.push_back(mBinarySolver[k].solve(M_i, Y_i[s], S_i, prng, socks[k]));
				}

			}

			setTimePoint("solver Begin");
			res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();

			setTimePoint("solver done");

			for (u64 s = 0; s < mNumSets; ++s)
			{
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print(A[s], M[s], sock, "hash");
			}

			// Step 10: Reveal([s_i]), implicit in step 11
			for (u64 s = 0; s < mNumSets; ++s)
			{
				co_await sock.send(coproto::copy(S[s]));
			}

			for (u64 s = 0; s < mNumSets; ++s)
			{
				Matrix<u8> SRecv(S[s].rows(), S[s].cols());
				co_await sock.recv(SRecv);
				for (u64 i = 0; i < SRecv.size(); ++i)
				{
					S[s](i) ^= SRecv(i);
				}
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
				{
					for (u64 j = 0; j < mNumPartitions; ++j)
					{
						auto Sj = S[s].submtx(j * c, c);
						std::cout << "S[" << j << "]: ";
						for (u64 i = 0; i < Sj.rows(); ++i)
							std::cout << toHex(Sj[i]) << " ";
						std::cout << std::endl;
					}
				}
			}
			setTimePoint("reveal s");

			// Step 11: Calculate h_i,j via hash function
			// This step is handled by SparseDpf configuration below
			Matrix<u8> H(mDomain * mNumPartitions, mGoldreichHash[0].mOutBytes);
			Matrix<u8> I(mDomain, mGoldreichHash[0].mInBytes);
			for (u64 i = 0; i < mDomain; ++i)
				copyBytesMin(I[i], i);

			for (u64 j = 0; j < mNumPartitions; ++j)
				mGoldreichHash[j].hash(I,
					H.submtx(j * mDomain, mDomain), hashSeed[j]);



			// Step 13-14: Compute S_j and invoke sparse-DPF
			buildSparseSets(f, c, S, H, HDomain);

			// Step 15-16: Initialize and compute final output
			std::vector<block> y(mDomain, ZeroBlock);
			std::vector<u64> A64(mNumSets * f);

			for (u64 s = 0, j = 0; s < mNumSets; ++s)
				for (u64 i = 0; i < A[s].rows(); ++i, ++j)
				{
					copyBytesMin(A64[j], A[s][i]);
				}

			mLeafShares.resize(f * mNumSets);
			mLeafTags.resize(f * mNumSets);
			for (u64 j = 0; j < f * mNumSets; ++j)
			{
				mLeafShares[j].resize(mSparseSets[j].size());
				mLeafTags[j].resize(mSparseSets[j].size());

				auto s = j / f;
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
				{
					u64 actPoint;
					co_await sock.send(coproto::copy(A64[j]));
					co_await sock.recv(actPoint);
					actPoint ^= A64[j];

					if (mPartyIdx)
					{
						std::cout << "set " << j / f << ", " << (j % f) << ": ";
						for (u64 i = 0; i < mSparseSets[j].size(); ++i)
						{
							if (actPoint == mSparseSets[j][i])
								std::cout << Color::Green;

							std::cout << mSparseSets[j][i] << ", ";

							if (actPoint == mSparseSets[j][i])
								std::cout << Color::Default;
						}
						std::cout << std::endl;
					}
				}
			}
			setTimePoint("sparseDpf begin");

			// Step 14: Invoke sparse-DPF for each S_j set
			// in punctured mode.
			co_await mSparseDpf.expand(
				A64,
				{},
				[&](u64 r, u64 i, block val, u8 tag) {
					// Step 17: Output final result
					mLeafShares[r][i] = val;
					mLeafTags[r][i] = tag;
					//auto idx = sparseSets[r][i];
					//y[idx] = y[idx] ^ val;
				},
				prng,
				mSparseSets,
				sock
			);

			setTimePoint("sparseDpf done");

			// if not charactristic two, we need to conditionally negate
			// the leaf sums depending on the party with tag=1 on the
			// active leaf.
			if (mCharacteristicTwo == false)
			{
				std::vector<u8> d(mLeafTags.size());
				for (u64 k = 0; k < mLeafTags.size(); ++k)
				{
					for (u64 j = 0; j < mLeafTags[k].size(); ++j)
					{
						assert(mLeafTags[k][j] < 2);
						d[k] += mLeafTags[k][j];
					}
				}

				// d = 1 if P1 is going to apply the update
				// but p1 is going to substract the update.
				// so we need to neagte the payload.
				for (u64 j = 0; j < d.size(); ++j)
					d[j] = ((d[j] / 2) % 2) ^ (mPartyIdx & d[j]);

				// if d, then we need to negate the leaf sums.
				// we will compute the difference between gamma and -gamma.
				// diff = gamma - (-gamma)
				//
				// and then 
				// 
				// h = gamma - d * diff
				//   = gamma - d * (gamma - (-gamma))
				//   = (1-d) gamma + d * (-gamma)

				BitVector dBits(d.size());
				for (u64 k = 0; k < d.size(); ++k)
				{
					assert(d[k] < 2);
					dBits[k] = d[k];
				}

				mMultSession = co_await mMultiplier.setupMultiply(dBits.size(), dBits.getSpan<u8>(), sock);
			}

			setTimePoint("negate done");

			//if (mPrint)
			//{
			//	co_await sock.send(coproto::copy(A64));
			//	for (u64 i = 0; i < mLeafShares.size(); ++i)
			//	{
			//		co_await sock.send(coproto::copy(mLeafShares[i]));
			//	}
			//	std::vector<u64> A64Recv(A64.size());

			//	co_await sock.recv(A64Recv);

			//	for (u64 i = 0; i < mLeafShares.size(); ++i)
			//	{
			//		std::vector<block> sharesRecv(mLeafShares[i].size());
			//		co_await sock.recv(sharesRecv);

			//		auto s = i / f;
			//		if (mPartyIdx && mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
			//		{

			//			std::cout << "shares[" << (i / f) << "," << (i % f) << "] @ " << (A64[i] ^ A64Recv[i])
			//				<< ":\n";
			//			for (u64 j = 0; j < mLeafShares[i].size(); ++j)
			//			{
			//				std::cout << mSparseSets[i][j] << " "
			//					<< (mLeafShares[i][j] ^ sharesRecv[j]) << std::endl;
			//			}
			//			std::cout << std::endl;
			//		}
			//	}
			//}
			}
				MACORO_CATCH(ex)
			{
				co_await sock.close();
				std::rethrow_exception(ex);
			}

			co_return;
		}



		template<typename Output>
		macoro::task<> expandValues(
			auto&& values,
			Output&& output,
			PRNG& prng,
			coproto::Socket& sock,
			CoeffCtx ctx = {})
		{
			setTimePoint("expandValue");

			// Check input parameters
			if (values.size() != mNumPointsPerSet * mNumSets)
				throw std::runtime_error("points and values size mismatch. " LOCATION);

			// Step 2: Deduplication
			using VecT = typename CoeffCtx::template Vec<T>;
			std::vector<VecT> B(mNumSets);
			std::vector<task<>> tasks;
			std::vector<Socket> socks(mNumSets);
			auto valIter = values.begin();
			for (u64 s = 0; s < mNumSets; ++s)
			{

				B[s] = ctx.template makeVec<T>(mNumPointsPerSet);
				ctx.copy(valIter, valIter + mNumPointsPerSet, B[s].begin());
				valIter += mNumPointsPerSet;

				// Step 2: Deduplication of [A], [B]

				tasks.push_back(
					mDedup[s].dedupValues<T>(B[s], socks[s] = sock.fork(), ctx)
				);

				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print({}, B[s],
						sock, "input*", ctx);
			}


			setTimePoint("dedup begin");
			auto res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();
			setTimePoint("dedup done");

			// Step 3-4: Apply hash functions and generate permutation
			auto f = mNumPartitions * mPartitionSize;
			auto c = mPartitionSize + mLinearSecParam;


			for (u64 s = 0; s < mNumSets; ++s)
			{

				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print({}, {}, B[s], sock, "dedup", ctx);

				// Step 5-6: Setup A and B matrices
				ctx.resize(B[s], f);
				ctx.zero(B[s].begin() + mNumPointsPerSet, B[s].end());

				// Step 7: Permute (A||b) by π
				tasks.push_back(
					mWaksmanPermute[s].apply<T>(B[s], socks[s], ctx));
			}
			setTimePoint("perm begin");

			// Step 7: Permute (A||b) by π
			res = co_await macoro::when_all_ready(std::move(tasks));
			for (auto& r : res)
				r.result();
			setTimePoint("perm done");

			ctx.resize(mExpanded, f * mNumSets);
			for (u64 j = 0; j < mExpanded.size(); ++j)
			{
				if (mExpanded[j].size() != mSparseSets[j].size())
					ctx.resize(mExpanded[j], mSparseSets[j].size());
			}
			setTimePoint("expanded alloc done");

			VecT leafSums(f * mNumSets);
			ctx.zero(leafSums.begin(), leafSums.end());

			for (u64 s = 0; s < mNumSets; ++s)
			{
				if (mPrint && (mPrintIndex == ~0ull || mPrintIndex == s))
					co_await print({}, {}, B[s], sock, "perm", ctx);
			}

			// Step 15-16: Initialize and compute final output
			auto BB = ctx.template makeVec<T>(mExpanded.size());

			auto BBIter = BB.begin();
			for (u64 s = 0, i = 0; s < mNumSets; ++s)
			{
				ctx.copy(B[s].begin(), B[s].end(), BBIter);
				BBIter += f;
			}


#define SIMD8(VAR, STATEMENT) do{\
	{ constexpr u64 VAR = 0; STATEMENT; }\
	{ constexpr u64 VAR = 1; STATEMENT; }\
	{ constexpr u64 VAR = 2; STATEMENT; }\
	{ constexpr u64 VAR = 3; STATEMENT; }\
	{ constexpr u64 VAR = 4; STATEMENT; }\
	{ constexpr u64 VAR = 5; STATEMENT; }\
	{ constexpr u64 VAR = 6; STATEMENT; }\
	{ constexpr u64 VAR = 7; STATEMENT; }\
	}while(0)

			auto zero = ctx.make<T>();
			ctx.zero(zero);
			for (u64 j = 0; j < mExpanded.size(); ++j)
			{
				AES aes(mHashSeed);
				mHashSeed = aes.hashBlock(block(35434523452345, 2345324523452345234));

				auto n8 = mSparseSets[j].size() / 8 * 8;

				auto sIter = mExpanded[j].begin();
				auto lIter = mLeafShares[j].begin();
				if (mPartyIdx)
				{

					for (u64 i = 0; i < n8; i+=8)
					{
						SIMD8(q, ctx.fromBlock(sIter[i+q], aes.hashBlock(lIter[i+q])));
						SIMD8(q, ctx.minus(sIter[i+q], zero, sIter[i+q]));
						SIMD8(q, ctx.plus(leafSums[j], leafSums[j], sIter[i+q]));
					}

					for (u64 i = n8; i < mSparseSets[j].size(); ++i)
					{
						ctx.fromBlock(sIter[i], aes.hashBlock(lIter[i]));
						ctx.minus(sIter[i], zero, sIter[i]);
						ctx.plus(leafSums[j], leafSums[j], sIter[i]);
					}
				}
				else
				{

					for (u64 i = 0; i <n8; i+=8)
					{
						SIMD8(q, ctx.fromBlock(sIter[i+q], aes.hashBlock(lIter[i+q])));
						SIMD8(q, ctx.plus(leafSums[j], leafSums[j], sIter[i+q]));
					}
					for (u64 i = n8; i < mSparseSets[j].size(); ++i)
					{
						ctx.fromBlock(sIter[i], aes.hashBlock(lIter[i]));
						ctx.plus(leafSums[j], leafSums[j], sIter[i]);
					}
				}

			}
			setTimePoint("expandLeaves done");


			//////////
			// gamma = beta - sum_i y_i 
			auto gamma = ctx.template makeVec<T>(mExpanded.size());
			for (u64 k = 0; k < mExpanded.size(); ++k)
				ctx.minus(gamma[k], BB[k], leafSums[k]);


			// if not charactristic two, we need to conditionally negate
			// the leaf sums depending on the party with tag=1 on the
			// active leaf.
			if (ctx.template characteristicTwo<T>() == false)
			{
				if (mMultSession.mX.size() == 0)
					throw RTE_LOC; // characteristic two is false, but the multiplier session is not set.

				// we previously computed d, which is a vector of 0s and 1s
				// d = 1 if P1 is going to apply the update
				// but p1 is going to substract the update.
				// so we need to neagte the payload.
				// if d, then we need to negate the leaf sums.
				// we will compute the difference between gamma and -gamma.
				// diff = gamma - (-gamma)
				//
				// and then 
				// 
				// h = gamma - d * diff
				//   = gamma - d * (gamma - (-gamma))
				//   = (1-d) gamma + d * (-gamma)

				auto diff = ctx.template makeVec<T>(mLeafTags.size());
				for (u64 k = 0; k < mLeafTags.size(); ++k)
				{
					// diff[k] = gamma[k] - (-gamma[k]);
					ctx.plus(diff[k], gamma[k], gamma[k]);
				}

				co_await mMultSession.multiply<T>(diff.begin(), diff.end(), diff.begin(), sock, ctx);

				// now we have d * diff
				for (u64 k = 0; k < gamma.size(); ++k)
				{
					// leadSums[k] = gamma[k] - diff[k];
					//             = (1-d) gamma[k] + d * (-gamma[k])
					ctx.minus(gamma[k], gamma[k], diff[k]);
				}
			}

			///////////
			// reveal gamma
			co_await reveal(gamma, sock, ctx);

			setTimePoint("gamma done");

			auto temp = ctx.template makeVec<T>(8);
			if (mTempOutput.size() != mDomain)
				ctx.resize(mTempOutput, mDomain);

			for (u64 s = 0, k = 0; s < mNumSets; ++s)
			{
				//if (s)
				ctx.zero(mTempOutput.begin(), mTempOutput.end());
				auto out = mTempOutput.begin();;

				for (u64 j = 0; j < f; ++j, ++k)
				{
					auto n = mLeafShares[k].size();
					auto n8 = n / 8 * 8;
					auto sIter = mExpanded[k].begin();
					auto gammaK = gamma[k];
					auto setK = mSparseSets[k].data();
					auto tagK = mLeafTags[k].data();

					if (mPartyIdx)
					{
						for (u64 i = 0; i < n8; i += 8)
						{
							SIMD8(q, ctx.mask(temp[q], gammaK, block::allSame<u8>(-tagK[i + q])));
							SIMD8(q, ctx.minus(temp[q], sIter[i + q], temp[q]));
							//ctx.plus(temp[q], shares[k][i + q], temp[q]);
							u32 idx[8];
							SIMD8(q, idx[q] = setK[i + q]);
							SIMD8(q, ctx.plus(out[idx[q]], out[idx[q]], temp[q]));
						}
						for (u64 i = n8; i < mLeafShares[k].size(); ++i)
						{
							auto mask = block::allSame<u8>(-tagK[i]);
							ctx.mask(temp[0], gammaK, mask);
							ctx.minus(temp[0], sIter[i], temp[0]);
							//ctx.plus(temp[0], shares[k][i], temp[0]);
							auto idx = setK[i];
							ctx.plus(out[idx], out[idx], temp[0]);
						}
					}
					else
					{
						for (u64 i = 0; i < n8; i += 8)
						{
							SIMD8(q, ctx.mask(temp[q], gammaK, block::allSame<u8>(-tagK[i + q])));
							SIMD8(q, ctx.plus(temp[q], sIter[i+q], temp[q]));
							u32 idx[8];
							SIMD8(q, idx[q] = setK[i + q]);
							SIMD8(q, ctx.plus(out[idx[q]], out[idx[q]], temp[q]));
						}
						for (u64 i = n8; i < mLeafShares[k].size(); ++i)
						{
							auto mask = block::allSame<u8>(-tagK[i]);
							ctx.mask(temp[0], gammaK, mask);
							//ctx.minus(temp[0], shares[k][i], temp[0]);
							ctx.plus(temp[0], sIter[i], temp[0]);
							auto idx = setK[i];
							ctx.plus(out[idx], out[idx], temp[0]);
						}
					}
				}
				for (u64 i = 0; i < mDomain; ++i)
				{
					output(s, i, out[i]);
				}
			}

			setTimePoint("update done");


			co_return;
		}

		template<typename TT = T>
		task<> print(
			MatrixView<u8> keys,
			MatrixView<u8> hash,
			auto values,
			coproto::Socket& sock,
			const std::string& name,
			auto ctx
		) const
		{
			Matrix<u8> keysCopy = keys;
			Matrix<u8> hashCopy = hash;
			//Matrix<u8> valuesCopy = values;
			auto valuesCopy = ctx.template makeVec<TT>(values.size());
			ctx.copy(values.begin(), values.end(), valuesCopy.begin());
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
			if (values.size())
			{
				co_await sock.send(coproto::copy(valuesCopy));
				co_await sock.recv(valuesCopy);
			}

			for (u64 i = 0; i < keys.size(); ++i)
				keysCopy(i) ^= keys(i);
			for (u64 i = 0; i < values.size(); ++i)
			{
				ctx.plus(valuesCopy[i], valuesCopy[i], values[i]);
			}
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
				auto rows = std::max<u64>(values.size(), keys.rows());
				for (u64 i = 0; i < rows; ++i)
				{
					std::cout << i << ": ";

					if (keysCopy.size())
					{
						u64 k = 0;
						copyBytesMin(k, keysCopy[i]);

						std::cout << std::setw(4);
						if (k == mDomain)
							std::cout << "_";
						else
							std::cout << k;
					}
					std::cout << " | ";
					if (hashCopy.size())
					{
						std::cout << toHex(hashCopy[i]);
					}
					std::cout << " | ";

					if (valuesCopy.size())
						std::cout << ctx.str(valuesCopy[i]);

					std::cout << std::endl;

				}
				std::cout << "------------------------" << std::endl;
			}
		}


		task<> print(
			MatrixView<u8> keys,
			MatrixView<u8> hash,
			coproto::Socket& sock,
			const std::string& name
		) const
		{
			return print<block>(keys, hash, span<block>{}, sock, name, CoeffCtxGF2{});
		}


		template<typename TT = T>
		task<> print(span<u64> keys, auto values, coproto::Socket& sock, const std::string& name,
			auto ctx) const
		{
			std::vector<u64> keysCopy(keys.begin(), keys.end());
			auto valuesCopy = ctx.template makeVec<TT>(values.size());
			if (keysCopy.size())
				co_await sock.send(coproto::copy(keysCopy));
			if (values.size())
			{
				ctx.copy(values.begin(), values.end(), valuesCopy.begin());
				co_await sock.send(coproto::copy(valuesCopy));
			}
			if (keysCopy.size())
				co_await sock.recv(keysCopy);
			if (values.size())
				co_await sock.recv(valuesCopy);

			for (u64 i = 0; i < keys.size(); ++i)
				keysCopy[i] ^= keys[i];
			for (u64 i = 0; i < values.size(); ++i)
				ctx.plus(valuesCopy[i], valuesCopy[i], values[i]);

			if (mPartyIdx)
			{
				std::cout << name << std::endl;
				auto n = std::max<u64>(keys.size(), values.size());
				for (u64 i = 0; i < n; ++i)
				{

					u64 k = 0;
					if (keys.size())
						copyBytesMin(k, keysCopy[i]);

					std::cout << i << ": " << std::setw(4) << k << " | ";
					if (values.size())
						std::cout << valuesCopy[i] << std::endl;
					else
						std::cout << "N/A" << std::endl;

				}
				std::cout << "------------------------" << std::endl;
			}
		}

		task<> print(span<u64> keys, coproto::Socket& sock, const std::string& name) const
		{
			return print<block>(keys, span<block>{}, sock, name, CoeffCtxGF2{});
		}


		task<> reveal(auto&& gamma, Socket& sock, auto&& ctx)
		{
			auto other = ctx.template makeVec<T>(gamma.size());
			std::vector<u8> buffer(gamma.size() * ctx.template byteSize<T>());
			ctx.serialize(gamma.begin(), gamma.end(), buffer.begin());
			co_await sock.send(std::move(buffer));
			buffer.resize(gamma.size() * ctx.template byteSize<T>());
			co_await sock.recv(buffer);
			ctx.deserialize(buffer.begin(), buffer.end(), other.begin());
			for (u64 k = 0; k < gamma.size(); ++k)
				ctx.plus(gamma[k], gamma[k], other[k]);
		}


		//template<typename Output>
//macoro::task<> expand(
//	span<u64> points,
//	span<block> values,
//	Output&& output,
//	PRNG& prng,
//	coproto::Socket& sock)
//{
//	// Check input parameters
//	if (points.size() != values.size() || points.size() != mNumPointsPerSet)
//		throw std::runtime_error("points and values size mismatch. " LOCATION);

//	if (mPrint)
//		co_await print(points, values, sock, "input*");
//	// Step 2: Deduplication
//	Matrix<u8> A(points.size(), divCeil(mIndexBitCount, 8));
//	Matrix<u8> altKeys(points.size(), divCeil(mIndexBitCount, 8));
//	Matrix<u8> B(values.size(), sizeof(block));
//	copyBytes(B, values); // Copy values to B

//	// Convert points to u32 for deduplication
//	for (u64 i = 0; i < points.size(); ++i)
//	{
//		copyBytesMin(A[i], points[i]);
//		copyBytesMin(altKeys[i], mDomain);  // Use indices as alternate keys
//	}

//	if (mPrint)
//		co_await print(A, {}, B, sock, "input");

//	// Step 2: Deduplication of [A], [B]
//	co_await mDedup[0].dedup(A, B, altKeys, prng, sock);

//	if (mPrint)
//		co_await print(A, {}, B, sock, "dedup");


//	// Step 3-4: Apply hash functions and generate permutation
//	auto f = mNumPartitions * mPartitionSize;
//	auto c = mPartitionSize + mLinearSecParam;

//	// Step 5-6: Setup A and B matrices
//	Matrix<u8> AB(f, A.cols() + B.cols());
//	for (u64 i = 0; i < points.size(); ++i)
//	{
//		copyBytesMin(AB[i], A[i]); // Copy A
//		copyBytesMin(AB[i].subspan(A.cols()), B[i]); // Copy B
//	}
//	for (u64 i = points.size(); i < f; ++i)
//	{
//		copyBytesMin(AB[i].subspan(0, A.cols()), mDomain * mPartyIdx); // default the extras 
//	}

//	// Step 7: Permute (A||b) by π
//	co_await mWaksmanPermute[0].apply(AB, sock);

//	// extract the parts
//	A.resize(f, A.cols()); // Resize A to f rows
//	B.resize(f, B.cols()); // Resize A to f rows
//	for (u64 i = 0; i < f; ++i)
//	{
//		copyBytesMin(A[i], AB[i].subspan(0, A.cols())); // Copy A from AB
//		copyBytesMin(B[i], AB[i].subspan(A.cols(), B.cols())); // Copy B from AB
//	}

//	if (mPrint)
//		co_await print(A, {}, B, sock, "perm");


//	std::vector<block> hashSeed(mNumPartitions);
//	{
//		AES aes(block(523234789928736, 754378923479832796));
//		for (u64 i = 0; i < mNumPartitions; ++i)
//		{
//			aes.ecbEncBlock(block(i), hashSeed[i]);
//		}
//	}

//	// Step 8: Construct M_i using hash functions
//	Matrix<u8> M(AB.rows(), divCeil(c, 8));
//	Matrix<u8> S(c * mNumPartitions, divCeil(log2ceil(mPartitionSize), 8));
//	std::vector<task<>> tasks;
//	std::vector<Socket> socks(mNumPartitions);
//	for (u64 i = 0; i < mNumPartitions; ++i)
//	{
//		auto M_i = M.submtx(i * mPartitionSize, mPartitionSize);
//		auto A_i = A.submtx(i * mPartitionSize, mPartitionSize);
//		socks[i] = sock.fork(); // Fork socket for each partition

//		//mGoldreichHash[i].mPrint = true;
//		tasks.push_back(mGoldreichHash[i].hash(A_i, M_i, socks[i], hashSeed[i]));
//	}
//	auto res = co_await macoro::when_all_ready(std::move(tasks));
//	for (auto& r : res)
//		r.result();

//	if (mPrint)
//		co_await print(A, M, B, sock, "hash*");

//	// Prepare y_i vector (0, 1, ..., m-1)
//	Matrix<u8> Y_i(mPartitionSize, divCeil(log2ceil(mPartitionSize), 8));
//	for (u64 j = 0; j < mPartitionSize; ++j)
//	{
//		auto val = j * mPartyIdx;
//		copyBytesMin(Y_i[j], val);
//	}

//	// Step 8-9: Create the matrices M_i and solve linear systems
//	Matrix<u8> HDomain(mNumPartitions, M.cols());
//	Matrix<u8> ADomain(1, A.cols());
//	copyBytesMin(ADomain, mDomain);
//	for (u64 i = 0; i < mNumPartitions; ++i)
//	{
//		auto M_i = M.submtx(i * mPartitionSize, mPartitionSize);
//		auto S_i = S.submtx(i * c, c);

//		//mGoldreichHash[i].mPrint = mPrint && mPartyIdx;
//		mGoldreichHash[i].hash(ADomain, HDomain.submtx(i, 1), hashSeed[i]);
//		if (mPartyIdx)
//		{
//			for (u64 j = 0; j < M_i.rows(); ++j)
//				for (u64 k = 0; k < M_i.cols(); ++k)
//					M_i(j, k) ^= HDomain(i, k); // XOR the hash into M_i
//		}
//		//mBinarySolver[i].mPrint = mPrint;

//		// Step 9: Binary solver to compute [s_i] = bin-solver([M_i], [y_i])
//		tasks.push_back(mBinarySolver[i].solve(M_i, Y_i, S_i, prng, socks[i]));
//	}

//	if (mPrint)
//		co_await print(A, M, B, sock, "hash");

//	res = co_await macoro::when_all_ready(std::move(tasks));
//	for (auto& r : res)
//		r.result();


//	// Step 10: Reveal([s_i]), implicit in step 11
//	co_await sock.send(coproto::copy(S));
//	{
//		Matrix<u8> SRecv(S.rows(), S.cols());
//		co_await sock.recv(SRecv);
//		for (u64 i = 0; i < S.size(); ++i)
//		{
//			S(i) ^= SRecv(i);
//		}
//		if (mPrint && mPartyIdx)
//		{
//			for (u64 j = 0; j < mNumPartitions; ++j)
//			{
//				auto Sj = S.submtx(j * c, c);
//				std::cout << "S[" << j << "]: ";
//				for (u64 i = 0; i < Sj.rows(); ++i)
//					std::cout << toHex(Sj[i]) << " ";
//				std::cout << std::endl;
//			}
//		}
//	}

//	// Step 11: Calculate h_i,j via hash function
//	// This step is handled by SparseDpf configuration below
//	Matrix<u8> H(mDomain * mNumPartitions, mGoldreichHash[0].mOutBytes);
//	Matrix<u8> I(mDomain, mGoldreichHash[0].mInBytes);
//	for (u64 i = 0; i < mDomain; ++i)
//		copyBytesMin(I[i], i);

//	for (u64 j = 0; j < mNumPartitions; ++j)
//		mGoldreichHash[j].hash(I,
//			H.submtx(j * mDomain, mDomain), hashSeed[j]);


//	if (mPartyIdx && mPrint)
//	{
//		//std::cout << " ------------ h* ------------- " << std::endl;

//		//for (u64 i = 0; i < mDomain; ++i)
//		//{
//		//	std::cout << i << ": ";
//		//	for (u64 j = 0; j < mNumPartitions; ++j)
//		//	{
//		//		std::cout << toHex(H[i + j * mDomain]) << ", ";
//		//	}
//		//	std::cout << std::endl;
//		//}
//		//std::cout << " ------------ h ------------- " << std::endl;
//	}

//	// Step 13-14: Compute S_j and invoke sparse-DPF
//	std::vector<std::vector<u32>> sparseSets(f);

//	// Configure sparse points for SparseDpf
//	std::vector<u8> Hij(H.cols());
//	for (u64 i = 0; i < mDomain; ++i)
//	{
//		if (mPartyIdx && mPrint)
//			std::cout << i << ": ";
//		for (u64 j = 0; j < mNumPartitions; ++j)
//		{
//			copyBytes(Hij, H[i + j * mDomain]);
//			for (u64 k = 0; k < Hij.size(); ++k)
//				Hij[k] ^= HDomain(j, k);

//			u64 h = innerProd(Hij, S.submtx(j * c, c)) + j * mPartitionSize;
//			if (mPartyIdx && mPrint)
//				std::cout << h << " = " << toHex(Hij) << " * Sj, ";
//			sparseSets[h].push_back(i);
//		}
//		if (mPartyIdx && mPrint)
//			std::cout << std::endl;
//	}

//	// Step 15-16: Initialize and compute final output
//	std::vector<block> y(mDomain, ZeroBlock);
//	std::vector<u64> A64(A.rows());
//	std::vector<block> BB(A.rows());
//	for (u64 i = 0; i < A.rows(); ++i)
//	{
//		copyBytesMin(A64[i], A[i]);
//		copyBytes(BB[i], B[i]);
//	}

//	std::vector<std::vector<block>> shares(f);
//	for (u64 j = 0; j < f; ++j)
//	{
//		shares[j].resize(sparseSets[j].size());

//		if (mPartyIdx && mPrint)
//		{
//			for (u64 i = 0; i < sparseSets[j].size(); ++i)
//			{
//				std::cout << sparseSets[j][i] << ", ";
//			}
//			std::cout << std::endl;
//		}
//	}

//	// Step 14: Invoke sparse-DPF for each S_j set
//	co_await mSparseDpf.expand(
//		A64,
//		BB,
//		[&](u64 r, u64 i, block val, u8 tag) {
//			// Step 17: Output final result
//			shares[r][i] = val;
//			auto idx = sparseSets[r][i];
//			y[idx] = y[idx] ^ val;
//		},
//		prng,
//		sparseSets,
//		sock
//	);

//	if (mPrint)
//	{
//		co_await sock.send(coproto::copy(A64));
//		co_await sock.send(coproto::copy(BB));
//		for (u64 i = 0; i < shares.size(); ++i)
//		{
//			co_await sock.send(coproto::copy(shares[i]));
//		}
//		std::vector<u64> A64Recv(A64.size());
//		std::vector<block> BBRecv(BB.size());
//		co_await sock.recv(A64Recv);
//		co_await sock.recv(BBRecv);

//		for (u64 i = 0; i < shares.size(); ++i)
//		{
//			std::vector<block> sharesRecv(shares[i].size());
//			co_await sock.recv(sharesRecv);
//			if (mPartyIdx)
//			{

//				std::cout << "shares[" << i << "] @ " << (A64[i] ^ A64Recv[i])
//					<< " " << (BB[i] ^ BBRecv[i]) << ":\n";
//				for (u64 j = 0; j < shares[i].size(); ++j)
//				{
//					std::cout << sparseSets[i][j] << " "
//						<< (shares[i][j] ^ sharesRecv[j]) << std::endl;
//				}
//				std::cout << std::endl;
//			}
//		}
//	}


//	for (u64 i = 0; i < y.size(); ++i)
//	{
//		output(i, y[i]);
//	}

//	co_return;
//}

	};

}
#undef SIMD8