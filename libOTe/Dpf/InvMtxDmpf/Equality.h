#pragma once
#include "cryptoTools/Common/Defines.h"
#include "macoro/task.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "coproto/Socket/Socket.h"

namespace osuCrypto
{

	// this class implemented the quality check using a one-out-of-m OT, 
	// where each element is in {0,1,...,m-1}. This is done using a very 
	// simple protocol.
	// 
	// 1) [c] = [a] xor [b]
	// 2) P0 chooses a random bit [y]_0 
	// 3) P0 builds s = ([y]_0,...,[y]_0) \oplus unitVec([c]_0, 1)
	// 4) Parties invole a 1-oo-m OT with message s1,...,sm and choice bit [c]_1. 
	//    P1 receives [y]_1 := s_{[c]_1}.
	//
	// To implement the OT we use log2(m) 1-oo-2 OTs
	class OtEquality
	{
	public:

		u64 mPartyIdx = 0; // party index (0 or 1)

		u64 mN = 0; // number of elements

		u64 mBitCount = 0;// bit count of each element

		Matrix<u8> mSendMsg; // base OTs for the sender
		std::vector<u8> mRecvMsg; // base OTs for the receiver
		std::vector<u8> mChoices; // choices for the base OTs

		void init(u64 partyIdx, u64 n, u64 bitCount)
		{
			if (bitCount > 8)
				throw std::runtime_error("bitCount must be <= 8. " LOCATION);
			mPartyIdx = partyIdx;
			mN = n;
			mBitCount = bitCount;
		}

		struct BaseOtCount
		{
			u64 mRecvCount = 0; // number of receive OTs
			u64 mSendCount = 0; // number of send OTs 
		};

		// returns the number of base OTs needed for this protocol
		BaseOtCount baseOtCount() const
		{
			if (mPartyIdx == 0)
				return { 0, mBitCount * mN };
			else
				return { mBitCount * mN, 0 };
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			if (baseSendOts.size() != baseOtCount().mSendCount ||
				recvBaseOts.size() != baseOtCount().mRecvCount ||
				baseChoices.size() != baseOtCount().mRecvCount)
				throw std::runtime_error("base OTs size mismatch. " LOCATION);

			//mBaseSendOts.assign(baseSendOts.begin(), baseSendOts.end());
			//mRecvBaseOts.assign(recvBaseOts.begin(), recvBaseOts.end());

			if (baseChoices.size())
			{
				mChoices.resize(mN);
				mRecvMsg.resize(mN);
				RandomOracle oracle(1);
				for (u64 i = 0; i < mN; ++i)
				{
					mChoices[i] = 0;
					oracle.Reset();
					for (u64 j = 0; j < mBitCount; ++j)
					{
						mChoices[i] |= baseChoices[i * mBitCount + j] << j;
						oracle.Update(recvBaseOts[i * mBitCount + j]);
					}

					oracle.Final(mRecvMsg[i]);
					mRecvMsg[i] &= 1; // ensure it is a bit
				}
			}
			else
			{
				u64 N = 1ull << mBitCount;
				RandomOracle oracle(1);
				mSendMsg.resize(mN, N);

				for (u64 i = 0; i < mN; ++i)
				{
					for (u64 j = 0; j < N; ++j)
					{
						oracle.Reset();
						for (u64 k = 0; k < mBitCount; ++k)
						{
							u8 b = (j >> k) & 1ull;
							oracle.Update(baseSendOts[i * mBitCount + k][b]);
						}
						oracle.Final(mSendMsg(i, j));
						mSendMsg(i, j) &= 1;
					}
				}
			}
		}

		template<typename T>
		macoro::task<> equal(
			span<T> A,
			span<T> B,
			BitVector& y,
			coproto::Socket& sock,
			PRNG& prng)
		{
			static_assert(std::is_same_v<T, u8>, "not impl");

			if (A.size() != mN ||
				(B.size() != 0 && B.size() != mN))
				throw std::runtime_error("input size mismatch. " LOCATION);

			// C = A xor B
			std::vector<u8> C(A.size());
			y.resize(mN);
			//std::vector<u8> r(A.size());

			u64 M = 1ull << mBitCount;
			u64 mask = (1ull << mBitCount) - 1;

			if (B.size())
			{
				for (u64 i = 0; i < A.size(); ++i)
				{
					C[i] = A[i] ^ B[i];
				}
			}
			else
			{
				for (u64 i = 0; i < A.size(); ++i)
				{
					C[i] = A[i];
				}
			}

			if (mPartyIdx)
			{

				BitVector r;
				r.reserve(mN * mBitCount);
				for (u64 i = 0; i < A.size(); ++i)
				{
					auto v = (C[i] - mChoices[i]) & mask;
					r.append((u8*)&v, mBitCount);
				}

				co_await sock.send(std::move(r));
				BitVector delta(mN * M);
				co_await sock.recv(delta);
				for (u64 i = 0; i < A.size(); ++i)
				{
					y[i] = delta[i * M + C[i]] ^ mRecvMsg[i];
				}

			}
			else
			{
				BitVector r(mN * mBitCount);
				BitVector delta(mN * M);
				y.randomize(prng);

				co_await sock.recv(r);

				for (u64 i = 0; i < A.size(); ++i)
				{
					auto byte = (i * mBitCount) / 8;
					auto shift = (i * mBitCount) % 8;
					u16 v;
					copyBytesMin(v, r.getSpan<u8>().subspan(byte));
					v = (v >> shift) & mask;

					for (u64 j = 0; j < M; ++j)
					{
						delta[i * M + j] =
							mSendMsg(i, (j - v) & mask) ^
							(j == C[i] ? 1 : 0) ^
							y[i];
					}
				}
				co_await sock.send(std::move(delta));
			}


		}
	};


	class BitInject
	{
	public:
		u64 mPartyIdx = 0; // party index (0 or 1)
		u64 mN = 0; // number of elements
		u64 mM = 0;
		u64 mModulus = 0;

		std::vector<std::array<block, 2>> mSendMsg; // base OTs for the sender
		std::vector<block> mRecvMsg; // base OTs for the receiver
		BitVector mChoices; // choices for the base OTs
		void init(u64 partyIdx, u64 n, u64 m, u64 modulus)
		{
			mPartyIdx = partyIdx;
			mN = n;
			mM = m;
			mModulus = modulus;
		}

		struct BaseOtCount
		{
			u64 mRecvCount = 0; // number of receive OTs
			u64 mSendCount = 0; // number of send OTs 
		};
		// returns the number of base OTs needed for this protocol
		BaseOtCount baseOtCount() const
		{
			if (mPartyIdx == 0)
				return { 0, mM * mN };
			else
				return { mM * mN, 0 };
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			if (baseSendOts.size() != baseOtCount().mSendCount ||
				recvBaseOts.size() != baseOtCount().mRecvCount ||
				baseChoices.size() != baseOtCount().mRecvCount)
				throw std::runtime_error("base OTs size mismatch. " LOCATION);

			mSendMsg.assign(baseSendOts.begin(), baseSendOts.end());
			mRecvMsg.assign(recvBaseOts.begin(), recvBaseOts.end());
			mChoices = baseChoices;
		}

		template<typename U>
		U as(block b)
		{
			U u;
			static_assert(sizeof(block) >= sizeof(U));
			copyBytesMin(u, b);
			return u;
		}

		std::vector<u8> pack(span<u8> data)
		{
			// Determine the number of bits required to represent mModulus.
			auto bitCount = log2ceil(mModulus);
			size_t totalBits = data.size() * bitCount;
			std::vector<u8> p(divCeil(totalBits, 8), 0);

			unsigned int accumulator = 0;
			int bitsInAccumulator = 0;
			size_t byteIndex = 0;

			for (u8 value : data)
			{
				// Mask value to bitCount bits.
				u8 masked = value & ((1u << bitCount) - 1);
				accumulator |= (masked << bitsInAccumulator);
				bitsInAccumulator += bitCount;

				// Flush whole bytes from the accumulator.
				while (bitsInAccumulator >= 8)
				{
					p[byteIndex++] = static_cast<u8>(accumulator & 0xFF);
					accumulator >>= 8;
					bitsInAccumulator -= 8;
				}
			}

			// If any bits remain in the accumulator, flush them into the last byte.
			if (bitsInAccumulator > 0 && byteIndex < p.size())
			{
				p[byteIndex] = static_cast<u8>(accumulator & 0xFF);
			}
			return p;
		}
		Matrix<u8> unpack(span<const u8> data)
		{
			// Determine the number of bits used for each packed value.
			auto bitCount = log2ceil(mModulus);
			// Expected number of values is mN * mM.
			Matrix<u8> result(mN, mM);

			unsigned int accumulator = 0;
			int bitsInAccumulator = 0;
			size_t byteIndex = 0;
			size_t resultIndex = 0;

			while (byteIndex < data.size() && resultIndex < result.size())
			{
				// Shift in a whole byte.
				accumulator |= (static_cast<unsigned int>(data[byteIndex]) << bitsInAccumulator);
				bitsInAccumulator += 8;
				++byteIndex;

				// Extract as many values as possible from the accumulator.
				while (bitsInAccumulator >= static_cast<int>(bitCount) && resultIndex < result.size())
				{
					result(resultIndex++) = static_cast<u8>(accumulator & ((1u << bitCount) - 1));
					accumulator >>= bitCount;
					bitsInAccumulator -= bitCount;
				}
			}
			return result;
		}

		macoro::task<> inject(
			MatrixView<const u8> A,
			MatrixView<u8> B,
			coproto::Socket& sock,
			PRNG& prng)
		{
			if (A.rows() != mN || B.rows() != mN)
				throw RTE_LOC;
			if (A.cols() < divCeil(mM, 8))
				throw RTE_LOC;
			if (B.cols() != mM)
				throw RTE_LOC;



			if (mPartyIdx)
			{

				BitVector c(mN * mM);
				for (u64 i = 0; i < mN; ++i)
				{
					for (u64 j = 0; j < mM; ++j)
					{
						auto aij = bit(A[i], j);
						//std::cout << "a1(" << i << " " << j << ") = " << int(aij) << std::endl;
						//std::cout << "c (" << i << " " << j << ") = " << int(mChoices[i * mM + j]) << std::endl;
						c[i * mM + j] =
							aij ^
							mChoices[i * mM + j];
					}
				}
				//std::cout << "_--------" << std::endl;
				co_await sock.send(std::move(c));
				std::vector<u8> dd(divCeil(mN * mM * log2ceil(mModulus), 8));
				co_await sock.recv(dd);
				auto D = unpack(dd);
				for (u64 i = 0; i < mN; ++i)
				{
					for (u64 j = 0; j < mM; ++j)
					{
						auto mcc = as<u64>(mRecvMsg[i * mM + j]) % mModulus;
						auto aij = bit(A[i], j);
						B(i, j) = (mcc + D(i, j) * aij) % mModulus;
						//std::cout << "B(" << i << " " << j << ") " << int(B(i, j)) << " = "
						//	<< (mcc % mModulus) << " + " << int(D(i, j)) << " " << int(aij) << std::endl;
					}
				}
			}
			else
			{
				BitVector c(mN * mM);
				co_await sock.recv(c);

				Matrix<u8> D(mN, mM);
				for (u64 i = 0; i < mN; ++i)
				{
					for (u64 j = 0; j < mM; ++j)
					{
						auto cc = c[i * mM + j];
						auto aij = bit(A[i], j);
						auto m0 = as<u64>(mSendMsg[i * mM + j][cc]) % mModulus;
						auto m1 = as<u64>(mSendMsg[i * mM + j][!cc]) % mModulus;


						B(i, j) = (aij - m0 + mModulus) % mModulus;
						D(i, j) = (m0 - m1 + (1 - 2 * aij) + mModulus) % mModulus;


						//std::cout << "a1(" << i << " " << j << ") = " << int(aij) << std::endl;
						//std::cout << "B (" << i << " " << j << ") = " << int(B(i,j)) << " = " << aij << " - " << (m0 % mModulus) << std::endl;
						//std::cout << "D (" << i << " " << j << ") = " << int(D(i,j)) << " = " 
						//	<< (m0 % mModulus) << " - " << (m1 % mModulus) << " + " << (1 - 2 * aij) << std::endl;
					}
				}

				co_await sock.send(pack(D));

			}
		}
	};

	//
	class HybEquality
	{
	public:

		u64 mPartyIdx = 0; // party index (0 or 1)

		u64 mN = 0; // number of elements

		u64 mBitCount = 0;// bit count of each element

		OtEquality mOtEquality;
		BitInject mBitInj;

		void init(u64 partyIdx, u64 n, u64 bitCount)
		{
			mPartyIdx = partyIdx;
			mN = n;
			mBitCount = bitCount;

			auto inner = log2ceil(mBitCount + 1);
			mOtEquality.init(partyIdx, n, inner);
			mBitInj.init(partyIdx, n, mBitCount, mBitCount + 1);
		}


		struct BaseOtCount
		{
			u64 mRecvCount = 0; // number of receive OTs
			u64 mSendCount = 0; // number of send OTs 
		};
		BaseOtCount baseOtCount() const
		{
			auto b0 = mOtEquality.baseOtCount();
			auto b1 = mBitInj.baseOtCount();

			return {
				b0.mRecvCount + b1.mRecvCount,
				b0.mSendCount + b1.mSendCount
			};
		}


		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			auto b = baseOtCount();

			if (baseSendOts.size() != b.mSendCount ||
				recvBaseOts.size() != b.mRecvCount ||
				baseChoices.size() != b.mRecvCount)
				throw std::runtime_error("base OTs size mismatch. " LOCATION);

			auto b0 = mOtEquality.baseOtCount();
			auto b1 = mBitInj.baseOtCount();

			auto baseSendOts0 = baseSendOts.subspan(0, b0.mSendCount);
			auto baseSendOts1 = baseSendOts.subspan(b0.mSendCount, b1.mSendCount);
			auto recvBaseOts0 = recvBaseOts.subspan(0, b0.mRecvCount);
			auto recvBaseOts1 = recvBaseOts.subspan(b0.mRecvCount, b1.mRecvCount);
			auto baseChoices0 = baseChoices.subvec(0, b0.mRecvCount);
			auto baseChoices1 = baseChoices.subvec(b0.mRecvCount, b1.mRecvCount);

			mOtEquality.setBaseOts(baseSendOts0, recvBaseOts0, baseChoices0);
			mBitInj.setBaseOts(baseSendOts1, recvBaseOts1, baseChoices1);
		}


		template<typename T>
		macoro::task<> equal(
			span<T> A,
			span<T> B,
			BitVector& y,
			coproto::Socket& sock,
			PRNG& prng)
		{
			if (mBitCount > sizeof(T) * 8)
				throw RTE_LOC;

			if (A.size() != mN ||
				B.size() != mN)
				throw std::runtime_error("Matrix size mismatch. " LOCATION);
			// C = A xor B
			Matrix<u8> C(A.size(), sizeof(T));
			y.resize(mN);
			for (u64 i = 0; i < A.size(); ++i)
			{
				T ci = A[i] ^ B[i];
				copyBytes(C[i], ci);
			}

			Matrix<u8> bits(mN, mBitCount);

			//auto inner = log2ceil(mBitCount + 1);
			auto modulus = mBitInj.mModulus;
			co_await mBitInj.inject(C, bits, sock, prng);

			std::vector<u8> v(mN);

			for (u64 i = 0; i < mN; ++i)
			{
				for (u64 j = 0; j < mBitCount; ++j)
				{
					v[i] = (v[i] + bits(i, j)) % modulus;
				}
			}

			if (mPartyIdx)
			{
				for (auto& vv : v)
				{
					vv = (modulus - vv) % modulus;
				}
			}
			co_await mOtEquality.equal<u8>(v, {}, y, sock, prng);


		}
	};

}