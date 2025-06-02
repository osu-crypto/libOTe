#pragma once
#include "libOTe/Tools/Coproto.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"


namespace osuCrypto
{


	struct GoldreichHash
	{
		u64 mPartyIdx = 0;

		u64 mN = 0;

		u64 mInBits = 0;

		u64 mOutBits = 0;

		u64 mNumIntermediate = 0;

		std::vector<std::array<block, 2>> mBaseSendOt;
		std::vector<block> mRecvBaseOts;
		oc::BitVector mBaseChoices;

		void init(u64 partyIdx, u64 n, u64 inBits, u64 outBits)
		{
			if (partyIdx > 1)
				throw std::runtime_error("GoldreichHash: partyIdx must be 0 or 1. " LOCATION);
			if (n == 0)
				throw std::runtime_error("GoldreichHash: n must be > 0. " LOCATION);

			mPartyIdx = partyIdx;
			mN = n;
			mInBits = inBits;
			mOutBits = outBits;
			mNumIntermediate = outBits * 2;

			if (mNumIntermediate > inBits * inBits)
				throw std::runtime_error("GoldreichHash: mNumIntermediate must be <= inBits * inBits. " LOCATION);

		}

		struct BaseOtCount {
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		BaseOtCount baseOtCount() const
		{
			return {
				mN * mNumIntermediate,
				mN * mNumIntermediate };
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

			mBaseSendOt.assign(baseSendOts.begin(), baseSendOts.end());
			mRecvBaseOts.assign(recvBaseOts.begin(), recvBaseOts.end());
			mBaseChoices = baseChoices;
		}


		task<> hash(
			MatrixView<const u8> x,
			MatrixView<u8> y,
			PRNG& prng,
			Socket& sock,
			block seed)
		{

			if (x.rows() != mN || x.cols() != divCeil(mInBits, 8))
				throw std::runtime_error("GoldreichHash: x size mismatch. " LOCATION);
			if (y.rows() != mN || y.cols() != divCeil(mOutBits, 8))
				throw std::runtime_error("GoldreichHash: y size mismatch. " LOCATION);
			if (mBaseSendOt.empty())
				throw std::runtime_error("GoldreichHash: base OTs not set. " LOCATION);


			PRNG prng(seed);
			LinearCode f0; f0.random(prng, mInBits, mNumIntermediate);
			LinearCode f1; f1.random(prng, mInBits, mNumIntermediate);

			Matrix<u8> a(mN, divCeil(mNumIntermediate, 8));
			Matrix<u8> b(mN, divCeil(mNumIntermediate, 8));

			for (u64 i = 0; i < mN; ++i)
			{
				f0.encode(x[i], a[i]);
				f1.encode(x[i], b[i]);
			}



		}

	};

}