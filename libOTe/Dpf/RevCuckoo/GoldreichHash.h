#pragma once
#include "libOTe/Tools/Coproto.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/CompilerHints.h"
#include "../DpfMult.h"
#include <array>
#include <bit>
#include <stdexcept>
#include <vector>

namespace osuCrypto
{

	// This hash is inspired by the goldreich PRG.
	// 
	// In input x, it computes
	//   1) a = M0 * x
	//   2) b = M1 * x
	//   3) c = a * b
	//   4) y = M2 * (x || c)
	// 
	// where M0,M1,M2 are matrices, step 3 performs
	// elementwise multiplication of bits. M2 is compressing.
	//
	// This is not intended to be a cryptographic hash function.
	// Instead we want the output to be close to uniform
	// given that the seed is sampled randomly after the input
	// is fixed. 
	struct GoldreichHash
	{
		u64 mPartyIdx = 0;

		u64 mN = 0;

		u64 mInBytes = 0;

		u64 mOutBytes = 0;

		u64 mNumIntermediateBytes = 0;

		DpfMult mMult;

		bool mPrint = false;

		struct Cache
		{

			LinearCode f0; 
			LinearCode f1; 
			LinearCode f2;
			Cache() = default;
			Cache(const Cache&) = default;
			Cache&operator=(const Cache&) = default;

			Cache(block seed, u64 inBytes, u64 numIntermediateBytes, u64 outBytes)
			{
				PRNG fPrng(seed);
				f0.random(fPrng, inBytes * 8, numIntermediateBytes * 8);
				f1.random(fPrng, inBytes * 8, numIntermediateBytes * 8);
				f2.random(fPrng, (inBytes + numIntermediateBytes) * 8, outBytes * 8);
			}

		};

		void init(u64 partyIdx, u64 n, u64 inBytes, u64 outBytes)
		{
			if (partyIdx > 1)
				throw std::runtime_error("GoldreichHash: partyIdx must be 0 or 1. " LOCATION);
			if (n == 0)
				throw std::runtime_error("GoldreichHash: n must be > 0. " LOCATION);

			mPartyIdx = partyIdx;
			mN = n;
			mInBytes = inBytes;
			mOutBytes = outBytes;
			mNumIntermediateBytes = mOutBytes * 1;

			if (mNumIntermediateBytes * 8 > mInBytes * mInBytes * 8 * 8)
				throw std::runtime_error("GoldreichHash: mOutBytes * 2 <= mInBytes * mInBytes. " LOCATION);

			mMult.init(mPartyIdx, mN * mNumIntermediateBytes * 8);
		}

		auto cache(block seed) const
		{
			return Cache(seed, mInBytes, mNumIntermediateBytes, mOutBytes);
		}

		struct BaseOtCount {
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		BaseOtCount baseOtCount() const
		{
			auto c = mMult.baseOtCount();
			return { c, c };
		}


		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			mMult.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}


		void hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			block seed)
		{
			auto c = cache(seed);
			hash(x, y, c);
		}


		void hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			Cache& cache)
		{
			if (x.rows() != y.rows())
				throw std::runtime_error("GoldreichHash: x y size mismatch. " LOCATION);
			if (x.cols() != mInBytes)
				throw std::runtime_error("GoldreichHash: x size mismatch. " LOCATION);
			if (y.cols() != mOutBytes)
				throw std::runtime_error("GoldreichHash: y size mismatch. " LOCATION);


			//LinearCode f0; f0.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			//LinearCode f1; f1.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			//LinearCode f2; f2.random(fPrng, (mInBytes + mNumIntermediateBytes) * 8, mOutBytes * 8);

			std::vector<u8> A(mNumIntermediateBytes), B(mNumIntermediateBytes);
			std::vector<u8> buff(x.cols() + mNumIntermediateBytes);

			//if (mPrint)
			//{
			//	std::cout << "GoldreichHash: " << seed << std::endl;
			//}
			for (u64 i = 0; i < x.rows(); ++i)
			{
				cache.f0.encode(x[i], A);
				cache.f1.encode(x[i], B);


				for (u64 j = 0; j < B.size(); ++j)
					B[j] &= A[j];

				memcpy(buff.data(), x.data(i), x.cols());
				memcpy(buff.data() + x.cols(), B.data(), B.size());

				buff[0] ^= 1;
				cache.f2.encode(buff, y[i]);

				if (mPrint)
				{
					u64 xx = 0;
					copyBytesMin(xx, x[i]);
					std::cout << "H(" << std::setw(3) << xx << ") = " << toHex(y[i]) << std::endl;
				}
			}

		}

		// Public evaluation of inputs 0, ..., domain-1 after the bucket selector
		// has been revealed. Compose the selector into f2's byte tables, and
		// advance the linear f0/f1 inputs as the counter increments. `anchor` is
		// H(N); XORing its projection gives the RevCuckoo H(N)=0 convention.
		OC_NOINLINE void hashToBuckets(
			u64 domain,
			span<u32> buckets,
			Cache& cache,
			MatrixView<const u8> selector,
			span<const u8> anchor)
		{
			if (domain == 0 || domain != buckets.size() ||
				selector.rows() > mOutBytes * 8 || selector.cols() == 0 ||
				selector.cols() > sizeof(u32) || anchor.size() != mOutBytes ||
				cache.f2.plaintextU8Size() != mInBytes + mNumIntermediateBytes)
				throw std::invalid_argument("GoldreichHash projected dimensions mismatch. " LOCATION);
			const auto indexBits = std::bit_width(domain - 1);
			if (indexBits > mInBytes * 8)
				throw std::invalid_argument("GoldreichHash domain exceeds input width. " LOCATION);

			const auto inputBytes = cache.f2.plaintextU8Size();
			const auto tableStride = cache.f2.mPow2CodeSize;
			// Project each possible hash-output byte through the public selector.
			// This table is shared by all 256 values of every f2 input byte.
			std::vector<u32> projection(mOutBytes * 256);
			for (u64 outByte = 0; outByte < mOutBytes; ++outByte)
			{
				std::array<u32, 8> basis{};
				for (u64 bit = 0; bit < 8; ++bit)
				{
					const auto row = outByte * 8 + bit;
					if (row < selector.rows())
						for (u64 b = 0; b < selector.cols(); ++b)
							basis[bit] |= u32(selector(row, b)) << (8 * b);
				}
				auto table = projection.data() + outByte * 256;
				for (u32 value = 1; value < 256; ++value)
				{
					const auto bit = std::countr_zero(value);
					table[value] = table[value & (value - 1)] ^ basis[bit];
				}
			}

			// Compose the selector with f2's existing byte encoding table once.
			std::vector<u32> projectedF2(inputBytes * 256);
			for (u64 inByte = 0; inByte < inputBytes; ++inByte)
				for (u64 value = 0; value < 256; ++value)
				{
					const auto entry = reinterpret_cast<const u8*>(
						cache.f2.mG8.data() +
						(inByte * 256 + value) * tableStride);
					u32 result = 0;
					for (u64 outByte = 0; outByte < mOutBytes; ++outByte)
						result ^= projection[outByte * 256 + entry[outByte]];
					projectedF2[inByte * 256 + value] = result;
				}

			u32 anchorBucket = 0;
			for (u64 outByte = 0; outByte < mOutBytes; ++outByte)
				anchorBucket ^= projection[outByte * 256 + anchor[outByte]];

			// Since f0, f1, and the projected input contribution of f2 are
			// linear, going from i-1 to i toggles exactly bits 0..ctz(i).
			// Precompute each prefix once per independently seeded evaluator.
			std::vector<u8> deltaA(indexBits * mNumIntermediateBytes);
			std::vector<u8> deltaB(indexBits * mNumIntermediateBytes);
			std::vector<u32> deltaX(indexBits);
			for (u64 bit = 0; bit < indexBits; ++bit)
			{
				const auto inByte = bit / 8;
				const auto value = u64{ 1 } << (bit & 7);
				const auto tableIndex = inByte * 256 + value;
				const auto* columnA = reinterpret_cast<const u8*>(
					cache.f0.mG8.data() + tableIndex * cache.f0.mPow2CodeSize);
				const auto* columnB = reinterpret_cast<const u8*>(
					cache.f1.mG8.data() + tableIndex * cache.f1.mPow2CodeSize);
				for (u64 b = 0; b < mNumIntermediateBytes; ++b)
				{
					deltaA[bit * mNumIntermediateBytes + b] = columnA[b] ^
						(bit ? deltaA[(bit - 1) * mNumIntermediateBytes + b] : 0);
					deltaB[bit * mNumIntermediateBytes + b] = columnB[b] ^
						(bit ? deltaB[(bit - 1) * mNumIntermediateBytes + b] : 0);
				}
				deltaX[bit] = projectedF2[tableIndex] ^
					(bit ? deltaX[bit - 1] : 0);
			}

			std::vector<u8> A(mNumIntermediateBytes), B(mNumIntermediateBytes);
			// The public hash flips input bit zero before f2 encoding.
			u32 xBucket = projectedF2[1];
			for (u64 i = 0; i < domain; ++i)
			{
				if (i)
				{
					const auto change = std::countr_zero(i);
					const auto* changeA = deltaA.data() + change * mNumIntermediateBytes;
					const auto* changeB = deltaB.data() + change * mNumIntermediateBytes;
					for (u64 b = 0; b < mNumIntermediateBytes; ++b)
					{
						A[b] ^= changeA[b];
						B[b] ^= changeB[b];
					}
					xBucket ^= deltaX[change];
				}
				u32 bucket = anchorBucket ^ xBucket;
				for (u64 b = 0; b < mNumIntermediateBytes; ++b)
					bucket ^= projectedF2[(mInBytes + b) * 256 + (A[b] & B[b])];
				buckets[i] = bucket;
			}
		}

#define CO_TRACE (co_await macoro::get_trace()).str()
		task<> hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			Socket& sock,
			block seed)
		{
			auto c = cache(seed);
			co_await hash(x, y, sock, c);
		}
		task<> hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			Socket& sock,
			Cache& cache)
		{

			if (x.rows() != mN || x.cols() != mInBytes)
				throw std::runtime_error("GoldreichHash: x size mismatch. " + CO_TRACE);
			if (y.rows() != mN || y.cols() != mOutBytes)
				throw std::runtime_error("GoldreichHash: y size mismatch. " + CO_TRACE);

			Matrix<u8>
				A(mN, mNumIntermediateBytes),
				B(mN, mNumIntermediateBytes);

			for (u64 i = 0; i < mN; ++i)
			{
				cache.f0.encode(x[i], A[i]);
				cache.f1.encode(x[i], B[i]);
			}



			// B = A * B
			co_await mMult.multiplyBits(A.size() * 8, A, B, B, sock);

			//if(mPrint)
			//{
			//	auto AA = A;
			//	auto BB = B;
			//	co_await sock.send(coproto::copy(AA));
			//	co_await sock.send(coproto::copy(BB));
			//	co_await sock.recv(AA);
			//	co_await sock.recv(BB);

			//	for (u64 i = 0; i < AA.size(); ++i)
			//	{
			//		AA(i) ^= A(i);
			//		BB(i) ^= B(i);
			//	}

			//	for (u64 i = 0; i < 2; ++i)
			//	{
			//		//std::cout << "A[" << i << "] = " << toHex(AA[i]) << std::endl;
			//		if (mPartyIdx)
			//			std::cout << "&[" << i << "] = " << toHex(BB[i]) << std::endl;
			//	}
			//}

			// y[i] = f0 * (x[i] || B[i])
			std::vector<u8> buff(x.cols() + mNumIntermediateBytes);
			//cache.f2.random(fPrng, buff.size() * 8, mOutBytes * 8);
			for (u64 i = 0; i < mN; ++i)
			{
				span<u8> bb(buff);
				copyBytes(bb.subspan(0, x.cols()), x[i]);
				copyBytes(bb.subspan(x.cols(), B.cols()), B[i]);
				buff[0] ^= mPartyIdx;
				cache.f2.encode(buff, y[i]);
			}

			if (mPrint)
			{
				Matrix<u8> YY = y;
				Matrix<u8> XX(x.rows(), x.cols());
				copyBytes(XX, x);

				//auto BB = buff;
				co_await sock.send(coproto::copy(XX));
				co_await sock.send(coproto::copy(YY));
				co_await sock.recv(XX);
				co_await sock.recv(YY);

				for (u64 j = 0; j < YY.size(); ++j)
					YY(j) = YY(j) ^ y(j);
				for (u64 i = 0; i < XX.size(); ++i)
					XX(i) ^= x(i);

				if (mPartyIdx)
				{
					std::cout << "GoldreichHash: " << std::endl;
					for (u64 i = 0; i < mN; ++i)
					{

						u64 x = 0;
						copyBytesMin(x, XX[i]);
						std::cout << "H(" << std::setw(3) << x << ") = " << toHex(YY[i]) << std::endl;
						//std::cout << "p " << mPartyIdx << std::endl;
						//std::cout << "f[" << i << "] = " << toHex(BB) << " " << toHex(buff) << std::endl;
						//std::cout << "b[" << i << "] = " << toHex(BB) << " " << toHex(buff) << std::endl;
						//std::cout << "y[" << i << "] = " << toHex(yi) << " = " 
						//	<< toHex(y[i]) << " + " << toHex(YY[i]) << std::endl;
					}
				}
			}


		}

	};

}
