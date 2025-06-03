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
	inline std::string toHex(span<u8> data) 
	{
		std::stringstream ss;
		for (auto b : data)
			ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
		return ss.str();
	}

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

			if (mNumIntermediateBytes > mInBytes * mInBytes)
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
			if (x.rows() != mN || x.cols() != mInBytes)
				throw std::runtime_error("GoldreichHash: x size mismatch. " LOCATION);
			if (y.rows() != mN || y.cols() != mOutBytes)
				throw std::runtime_error("GoldreichHash: y size mismatch. " LOCATION);


			PRNG fPrng(seed);
			LinearCode f0; f0.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			LinearCode f1; f1.random(fPrng, mInBytes * 8, mNumIntermediateBytes * 8);
			LinearCode f2; f2.random(fPrng, (mInBytes+mNumIntermediateBytes) * 8, mOutBytes * 8);

			std::vector<u8> A(mNumIntermediateBytes), B(mNumIntermediateBytes);
			std::vector<u8> buff(x.cols() + mNumIntermediateBytes);
			const bool print = false;

			for (u64 i = 0; i < mN; ++i)
			{
				f0.encode(x[i], A);
				f1.encode(x[i], B);


				for (u64 j = 0; j < B.size(); ++j)
					B[j] &= A[j];

				if (i < 2 && print)
				{
					std::cout << "&[" << i << "] = " << toHex(B) << " < " << std::endl;
				}

				memcpy(buff.data(), x.data(i), x.cols());
				memcpy(buff.data() + x.cols(), B.data(), B.size());

				buff[0] ^= 1;
				f2.encode(buff, y[i]);

				if (i < 2 && print)
				{
					std::cout << "b[" << i << "] = " << toHex(buff)  << " < " << std::endl;
					std::cout << "y[" << i << "] = " << toHex(y[i]) << " < " << std::endl;
				}
			}
		}

		task<> hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			Socket& sock,
			block seed)
		{

			if (x.rows() != mN || x.cols() != mInBytes)
				throw std::runtime_error("GoldreichHash: x size mismatch. " LOCATION);
			if (y.rows() != mN || y.cols() != mOutBytes)
				throw std::runtime_error("GoldreichHash: y size mismatch. " LOCATION);


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

			const bool print = false;
			if(print)
			{
				auto AA = A;
				auto BB = B;
				co_await sock.send(coproto::copy(AA));
				co_await sock.send(coproto::copy(BB));
				co_await sock.recv(AA);
				co_await sock.recv(BB);

				for (u64 i = 0; i < AA.size(); ++i)
				{
					AA(i) ^= A(i);
					BB(i) ^= B(i);
				}

				for (u64 i = 0; i < 2; ++i)
				{
					//std::cout << "A[" << i << "] = " << toHex(AA[i]) << std::endl;
					if (mPartyIdx)
						std::cout << "&[" << i << "] = " << toHex(BB[i]) << std::endl;
				}
			}

			// y[i] = f0 * (x[i] || B[i])
			std::vector<u8> buff(x.cols() + mNumIntermediateBytes);
			f0.random(fPrng, buff.size() * 8, mOutBytes * 8);
			for (u64 i = 0; i < mN; ++i)
			{
				span<u8> bb(buff);
				copyBytes(bb.subspan(0, x.cols()), x[i]);
				copyBytes(bb.subspan(x.cols(), B.cols()), B[i]);
				//memcpy(buff.data(), x.data(i), x.cols());
				//memcpy(buff.data() + x.cols(), B[i].data(), B.cols());

				buff[0] ^= mPartyIdx;
				f0.encode(buff, y[i]);

				if (i < 2 && print)
				{
					//std::cout << "yy[" << i << "] = " << toHex(y[i]) << std::endl;
					Matrix<u8> YY = y;

					auto BB = buff;
					co_await sock.send(coproto::copy(BB));
					co_await sock.send(coproto::copy(YY));
					co_await sock.recv(BB);
					co_await sock.recv(YY);

					std::vector<u8> yi(YY.cols());
					for (u64 j = 0; j < YY.cols(); ++j)
					{
						yi[j] = YY[i][j] ^ y[i][j];
					}

					for (u64 i = 0; i < BB.size(); ++i)
					{
						BB[i] ^= buff[i];
					}

					//if (mPartyIdx)
					{
						std::cout << "p " << mPartyIdx << std::endl;
						//std::cout << "f[" << i << "] = " << toHex(BB) << " " << toHex(buff) << std::endl;
						std::cout << "b[" << i << "] = " << toHex(BB) << " " << toHex(buff) << std::endl;
						std::cout << "y[" << i << "] = " << toHex(yi) << " = " 
							<< toHex(y[i]) << " + " << toHex(YY[i]) << std::endl;
					}
				}

			}

		}

	};

}