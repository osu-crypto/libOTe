#pragma once
#include "cryptoTools/Common/Defines.h"
#include "macoro/task.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Common/CuckooIndex.h"

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
				//RandomOracle oracle(1);
				for (u64 i = 0; i < mN; ++i)
				{
					mChoices[i] = 0;
					//oracle.Reset();
					block sum = ZeroBlock;
					for (u64 j = 0; j < mBitCount; ++j)
					{
						mChoices[i] |= baseChoices[i * mBitCount + j] << j;
						//oracle.Update(recvBaseOts[i * mBitCount + j]);
						sum ^= recvBaseOts[i * mBitCount + j];
					}

					//oracle.Final(mRecvMsg[i]);
					auto blk = mAesFixedKey.hashBlock(sum);
					mRecvMsg[i] = blk.get<u8>(0) & 1; // ensure it is a bit
					//mRecvMsg[i] &= 1; // ensure it is a bit
				}
			}
			else
			{
				u64 N = 1ull << mBitCount;
				//RandomOracle oracle(1);
				mSendMsg.resize(mN, N);

				for (u64 i = 0; i < mN; ++i)
				{
					for (u64 j = 0; j < N; ++j)
					{
						//oracle.Reset();
						block sum = ZeroBlock;
						for (u64 k = 0; k < mBitCount; ++k)
						{
							u8 b = (j >> k) & 1ull;
							//oracle.Update(baseSendOts[i * mBitCount + k][b]);
							sum ^= baseSendOts[i * mBitCount + k][b];
						}
						auto blk = mAesFixedKey.hashBlock(sum);
						//oracle.Final(mSendMsg(i, j));
						mSendMsg(i, j) = blk.get<u8>(0) & 1;
					}
				}
			}
		}

		//  y[i] = (A[i] == B[i])
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
		Mod mMod; // modulus for the elements

		std::vector<std::array<block, 2>> mSendMsg; // base OTs for the sender
		std::vector<block> mRecvMsg; // base OTs for the receiver
		BitVector mChoices; // choices for the base OTs
		void init(u64 partyIdx, u64 n, u64 m, u64 modulus)
		{
			if (partyIdx > 1)
				throw RTE_LOC;
			if (!n || !m || !modulus)
				throw RTE_LOC;
					
			mPartyIdx = partyIdx;
			mN = n;
			mM = m;
			mModulus = modulus;
			mMod = Mod(mModulus);

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
			memcpy(&u, &b, sizeof(U));
			return u;
		}

		// take a vector of bytes, each less that mModulus, and pack them into a byte array.
		// each will take up log2(mModulus) bits.
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

		// Unpack a byte array into a matrix of u8 values, each less than mModulus.
		// Each value is packed into log2(mModulus) bits.
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

		void bitsToBytes(
			span<const u8> bits,
			span<u8> bytes)
		{
			auto totalBits = bytes.size();
			auto fullBytes = bytes.size() / 8;
			auto totalBytes = divCeil(totalBits, 8);

			if(bits.size() != totalBytes)
				throw std::runtime_error("bad sizes. " LOCATION);

			// Process 8 bytes (64 bits) at a time for SIMD optimization
			for (u64 byteIdx = 0; byteIdx < fullBytes; byteIdx += 8)
			{
				u64 remainingBytes = std::min<u64>(8ull, fullBytes - byteIdx);
				for (u64 k = 0; k < remainingBytes; ++k)
				{
					u8 packedByte = bits[byteIdx + k];
					u64 bitOffset = (byteIdx + k) * 8;
					// Unpack 8 bits into 8 bytes using bit manipulation
					for (u64 bit = 0; bit < 8; ++bit)
						bytes[bitOffset + bit] = (packedByte >> bit) & 1;
				}
			}
			// Handle remaining bits
			u64 remainingBits = totalBits % 8;
			if (remainingBits > 0) {
				u8 packedByte = bits[fullBytes];
				u64 bitOffset = fullBytes * 8;

				for (u64 bit = 0; bit < remainingBits; ++bit)
					bytes[bitOffset + bit] = (packedByte >> bit) & 1;
			}
		}

		macoro::task<> inject(
			MatrixView<const u8> A,
			MatrixView<u8> B,
			coproto::Socket& sock,
			PRNG& prng)
		{
			MACORO_TRY{
			if (A.rows() != mN || B.rows() != mN)
				throw RTE_LOC;
			if (A.cols() < divCeil(mM, 8))
				throw RTE_LOC;
			if (B.cols() != mM)
				throw RTE_LOC;

			u64 totalBits = mN * mM;
			u64 bytes = divCeil(totalBits, 8);
			//u64 fullBytes = totalBits / 8;
			auto m8 = divCeil(mM, 8);

			if (mPartyIdx)
			{


				// Pack all bits from A into AA using direct byte access
				// +1 to make sures its legal to access the byte after the last bit.
				std::vector<u8> AA(bytes + 1, 0);

				u64 outIndex = 0;
				for (u64 i = 0; i < mN; ++i)
				{
					auto ai = A.data(i);
					// Process full bytes first
					for (u64 j = 0; j < m8; ++j)
					{
						auto aij = ai[j];

						auto outByteIdx = outIndex / 8;
						auto outBitShift = outIndex % 8;

						// outIndex might not a multiple of 8, so we need to handle the bits carefully
						auto lowerBits = aij << outBitShift;
						auto upperBits = aij >> (8 - outBitShift);

						assert(outByteIdx + 1 < AA.size());
						AA.data()[outByteIdx] |= lowerBits;
						AA.data()[outByteIdx + 1] |= upperBits;

						outIndex += 8;
					}

					// we might have over stepped at the end. move outIndex back
					outIndex -= (m8 * 8 - mM);
				}
				AA.resize(bytes);

				AlignedUnVector<u8> c(bytes);
				auto choices = mChoices.getSpan<u8>();
				for (u64 i = 0; i < bytes; ++i)
					c[i] = AA[i] ^ choices[i];

				//std::cout << "_--------" << std::endl;
				co_await sock.send(std::move(c));
				std::vector<u8> dd(divCeil(totalBits * log2ceil(mModulus), 8));

				std::vector<u8> ABits(totalBits);
				// Convert packed AA to one-bit-per-byte ABits using SIMD-friendly approach
				bitsToBytes(AA, ABits);

				co_await sock.recv(dd);
				auto D = unpack(dd);
				for (u64 i = 0; i < totalBits; ++i)
				{
					auto aij = ABits.data()[i];
					auto mcc = mMod.mod(as<u64>(mRecvMsg.data()[i]));
					auto d = D.data()[i];
					auto v = mcc + d * aij;
					// v = v % mModulus
					v = v - (v >= mModulus) * mModulus;
					//if (v != (mcc + d * aij) % mModulus)
					//	throw RTE_LOC;
					B(i) = v;
				}
			}
			else
			{
				//BitVector c(mN * mM);
				AlignedUnVector<u8> c(bytes);
				std::vector<u8> CBits(totalBits), ABits(totalBits + 8);

				auto outIndex = 0;
				for (u64 i = 0; i < mN; ++i)
				{
					auto Ai = A.data(i);
					// Process 8 bytes (64 bits) at a time for SIMD optimization
					for (u64 k = 0; k < m8; ++k, outIndex += 8)
					{
						u8 packedByte = Ai[k];
						// Unpack 8 bits into 8 bytes using bit manipulation
						for (u64 bit = 0; bit < 8; ++bit)
							ABits.data()[outIndex + bit] = (packedByte >> bit) & 1;
					}

					// go back if we over stepped
					outIndex -= (m8 * 8 - mM);
				}
				ABits.resize(totalBits);

				co_await sock.recv(c);

				// Convert packed c to one-bit-per-byte ABits using SIMD-friendly approach
				bitsToBytes(c, CBits);
				Matrix<u8> D(mN, mM);
				for (u64 i = 0; i < totalBits; ++i)
				{
					auto cc = CBits[i];
					auto aij = ABits[i];//bit(A[i / mM], i % mM);//
					auto m0 = mMod.mod(as<u64>(mSendMsg[i][cc]));
					auto m1 = mMod.mod(as<u64>(mSendMsg[i][!cc]));

					auto b = aij - m0 + mModulus;
					b = b - (b >= mModulus) * mModulus; // b = b % mModulus
					b = b - (b >= mModulus) * mModulus; // b = b % mModulus

					auto d = m0 - m1 + (1 - 2 * aij) + mModulus;
					d = d - (d >= mModulus) * mModulus; // d = d % mModulus
					d = d - (d >= mModulus) * mModulus; // d = d % mModulus


					B(i) = b;
					D(i) = d;
				}

				co_await sock.send(pack(D));

			}
			} MACORO_CATCH(e)
			{
				clear();
				co_await sock.close();
				std::rethrow_exception(e);
			}
		}

		void clear()
		{
						mPartyIdx = 0;
			mN = 0;
			mM = 0;
			mModulus = 0;
			mMod = {};
			mSendMsg.clear();
			mRecvMsg.clear();
			mChoices.resize(0);
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
			MatrixView<u8> AView(reinterpret_cast<u8*>(A.data()), A.size(), sizeof(T));
			MatrixView<u8> BView(reinterpret_cast<u8*>(B.data()), B.size(), sizeof(T));
			if (A.size() != mN ||
				(B.size() != 0 && B.size() != mN))
				throw std::runtime_error("input size mismatch. " LOCATION);

			return equal(AView, BView, y, sock, prng);
		}

		macoro::task<> equal(
			MatrixView<u8> A,
			MatrixView<u8> B,
			BitVector& y,
			coproto::Socket& sock,
			PRNG& prng)
		{
			if (mBitCount > A.cols() * 8)
				throw RTE_LOC;
			if (A.cols() != B.cols())
				throw RTE_LOC;
			if (A.rows() != mN ||
				B.rows() != mN)
				throw std::runtime_error("Matrix size mismatch. " LOCATION);
			// C = A xor B
			Matrix<u8> C(A.rows(), A.cols());
			y.resize(mN);
			for (u64 i = 0; i < A.size(); ++i)
			{
				C(i) = A(i) ^ B(i);
			}

			Matrix<u8> bits(mN, mBitCount);

			//auto inner = log2ceil(mBitCount + 1);
			auto modulus = mBitInj.mModulus;
			co_await mBitInj.inject(C, bits, sock, prng);

			std::vector<u8> v(mN);

			for (u64 i = 0; i < mN; ++i)
			{
				u32 sum = 0;
				for (u64 j = 0; j < mBitCount; ++j)
				{
					sum = sum + bits(i, j);
				}
				v[i] = mBitInj.mMod.mod(sum);
			}

			if (mPartyIdx)
			{
				for (auto& vv : v)
				{
					// v = -v mod modulus
					vv = bool(vv) * (modulus - vv);
					assert(vv < modulus);
				}
			}
			co_await mOtEquality.equal<u8>(v, {}, y, sock, prng);


		}
	};

}