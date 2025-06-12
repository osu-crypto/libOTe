#pragma once
#include "libOTe/Tools/Coproto.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include "../DpfMult.h"

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
	// Instead we want that the output to be close ro uniform 
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
			if (x.rows() != y.rows())
				throw std::runtime_error("GoldreichHash: x y size mismatch. " LOCATION);
			if (x.cols() != mInBytes)
				throw std::runtime_error("GoldreichHash: x size mismatch. " LOCATION);
			if (y.cols() != mOutBytes)
				throw std::runtime_error("GoldreichHash: y size mismatch. " LOCATION);


			PRNG fPrng(seed);
			LinearCode f0; f0.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			LinearCode f1; f1.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			LinearCode f2; f2.random(fPrng, (mInBytes + mNumIntermediateBytes) * 8, mOutBytes * 8);

			std::vector<u8> A(mNumIntermediateBytes), B(mNumIntermediateBytes);
			std::vector<u8> buff(x.cols() + mNumIntermediateBytes);

			if (mPrint)
			{
				std::cout << "GoldreichHash: " << seed << std::endl;
			}
			for (u64 i = 0; i < x.rows(); ++i)
			{
				f0.encode(x[i], A);
				f1.encode(x[i], B);


				for (u64 j = 0; j < B.size(); ++j)
					B[j] &= A[j];

				memcpy(buff.data(), x.data(i), x.cols());
				memcpy(buff.data() + x.cols(), B.data(), B.size());

				buff[0] ^= 1;
				f2.encode(buff, y[i]);

				if (mPrint)
				{
					u64 xx = 0;
					copyBytesMin(xx, x[i]);
					std::cout << "H(" << std::setw(3) << xx << ") = " << toHex(y[i]) << std::endl;
				}
			}

		}

#define CO_TRACE (co_await macoro::get_trace()).str()

		task<> hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			Socket& sock,
			block seed)
		{

			if (x.rows() != mN || x.cols() != mInBytes)
				throw std::runtime_error("GoldreichHash: x size mismatch. " + CO_TRACE);
			if (y.rows() != mN || y.cols() != mOutBytes)
				throw std::runtime_error("GoldreichHash: y size mismatch. " + CO_TRACE);


			PRNG fPrng(seed);
			LinearCode f0; f0.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			LinearCode f1; f1.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);

			Matrix<u8>
				A(mN, mNumIntermediateBytes),
				B(mN, mNumIntermediateBytes);

			for (u64 i = 0; i < mN; ++i)
			{
				f0.encode(x[i], A[i]);
				f1.encode(x[i], B[i]);
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
			f0.random(fPrng, buff.size() * 8, mOutBytes * 8);
			for (u64 i = 0; i < mN; ++i)
			{
				span<u8> bb(buff);
				copyBytes(bb.subspan(0, x.cols()), x[i]);
				copyBytes(bb.subspan(x.cols(), B.cols()), B[i]);
				buff[0] ^= mPartyIdx;
				f0.encode(buff, y[i]);
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
					std::cout << "GoldreichHash: " << seed << std::endl;
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