#pragma once

#include "libOTe/config.h"
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)

#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{
	struct DpfMult
	{

		u64 mPartyIdx = 0;

		u64 mTotalMults = 0;

		oc::BitVector mChoiceBits;

		std::vector<block> mRecvOts;
		std::vector<std::array<block, 2>> mSendOts;

		u64 mOtIdx = 0;

		bool hasBaseOts() const { return mChoiceBits.size(); }

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		void init(
			u64 partyIdx,
			u64 n)
		{
			if (partyIdx > 1)
				throw RTE_LOC;

			mPartyIdx = partyIdx;
			mTotalMults = n;
			mOtIdx = 0;
			mSendOts.clear();
			mRecvOts.clear();
			mChoiceBits.resize(0);
		}


		// We are given two OTs, one in each direction. Let us denote them as
		// 
		//   a0                      b0
		//   c00                     c01
		// 
		//   b1                      a1
		//   c10                     c11
		// 
		// such that 
		// 
		//    a0 * b0 = (c00 + c01)
		//    a1 * b1 = (c10 + c11)
		// 
		// Note that we write these OTs in OLE format, that is for OT (m0,m1),(g,mg)
		// we have a0=g, b0=(m0+m1), c00=mg, c01=m0 and similar for the second 
		// instance.
		//
		// We first convert these two "OTs/OLEs" into a random beaver triple
		//
		// [a] * [b] = [c']
		// 
		// We do this by computing
		//
		// [a] = (a0, a1)
		// [b] = (b1, b0)
		// [c'] = (c00+c10+a0b1, c01+c11+a1b0)
		// 
		// As you can see, all 4 cross terms are present. Given this beaver triple
		// we can use the standard protocol. We reveal
		// 
		// phi   = [x] + [a]
		// theta = [y] + [b]
		// 
		// [zy] = [c'] + theta a + phi b + theta phi
		//      = ab + (y+b) a + (x+a) b + (y+b)(x+a)
		//      = ab + ab + ya + xb + ab + yx + ya + xb + ab
		//      = xy
		//
		macoro::task<> multiply(const oc::BitVector& x, span<const block> y, span<block> xy, coproto::Socket& sock)
		{
			if (x.size() != y.size() || x.size() != xy.size())
				throw RTE_LOC;
			if (x.size() + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			BitVector a0; a0.append(mChoiceBits, x.size(), mOtIdx);
			AlignedUnVector<block> A0(x.size()), C(x.size()), theta(x.size()), b1(x.size());
			for (u64 j = 0; j < x.size(); ++j)
			{
				A0[j] = block(-u64(a0[j]), -u64(a0[j]));
				auto c00 = mRecvOts[mOtIdx + j];

				auto c10 = mSendOts[mOtIdx + j][0];

				b1[j] = mSendOts[mOtIdx + j][0] ^ mSendOts[mOtIdx + j][1];
				// C0' = c00+c10+a0b1
				C[j] = c00 ^ c10 ^ (b1[j] & A0[j]);

				theta[j] = y[j] ^ b1[j];
			}
			auto phi = x ^ a0;
			while (phi.size() % 8)
				phi.pushBack(0);

			AlignedUnVector<block> buffer(theta.size() + phi.sizeBlocks());
			memcpy(buffer.data(), theta.data(), theta.size() * sizeof(block));
			memcpy(buffer.data() + theta.size(), phi.data(), phi.sizeBytes());

			co_await sock.send(std::move(buffer));

			buffer.resize(theta.size() + phi.sizeBlocks());
			co_await sock.recv(buffer);
			span<block> theta1(buffer.data(), theta.size());
			BitVector phi1((u8*)&buffer[theta.size()], phi.size());

			phi ^= phi1;
			for (u64 j = 0; j < x.size(); ++j)
			{
				auto Phi = block(-u64(phi[j]), -u64(phi[j]));
				theta[j] ^= theta1[j];
				xy[j] = C[j] ^ (theta[j] & A0[j]) ^ (Phi & b1[j]);

				if (mPartyIdx)
					xy[j] ^= theta[j] & Phi;
			}


			mOtIdx += x.size();

		}

		u64 baseOtCount() const { return mTotalMults; }

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			if (baseSendOts.size() != baseOtCount() ||
				recvBaseOts.size() != baseOtCount() ||
				baseChoices.size() != baseOtCount())
				throw RTE_LOC;

			mSendOts.clear();
			mRecvOts.clear();
			mSendOts.insert(mSendOts.end(), baseSendOts.begin(), baseSendOts.end());
			mRecvOts.insert(mRecvOts.end(), recvBaseOts.begin(), recvBaseOts.end());
			mChoiceBits = baseChoices;
			mOtIdx = 0;
		}


	};

}
#undef SIMD8

#endif // defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)
