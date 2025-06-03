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
	// this class implement binary scaler vector multiplication.
	// given a shared bit [x] and shared vector [y], this class
	// computes the shared vector [xy] = [x * y].
	//
	// this protocol used |x| OTs in both directions to execute the protocol.
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


		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi is a bit and yi 
		// is a vector.
		// 
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

			// our a share of a * b = c.
			BitVector a0; a0.append(mChoiceBits, x.size(), mOtIdx);

			// A0 = 11...1 * a , an expanded version of a used for masking.
			AlignedUnVector<block> A0(x.size());

			// our c share of a * b = c.
			AlignedUnVector<block> C(x.size());

			// theta = y + b
			AlignedUnVector<block> theta(x.size());

			// our b share of a * b = c
			AlignedUnVector<block> b1(x.size());

			for (u64 j = 0; j < x.size(); ++j)
			{
				A0[j] = block(-u64(a0[j]), -u64(a0[j]));
				auto c00 = mRecvOts[mOtIdx + j];
				auto c10 = mSendOts[mOtIdx + j][0];
				b1[j] = mSendOts[mOtIdx + j][0] ^ mSendOts[mOtIdx + j][1];

				// C0' = c00+c10+a0b1
				C[j] = c00 ^ c10 ^ (b1[j] & A0[j]);

				// theta = y + b
				theta[j] = y[j] ^ b1[j];
			}

			// phi = x + a
			auto phi = x ^ a0;
			while (phi.size() % 8)
				phi.pushBack(0);

			// reveal phi and theta
			auto thetaSize = theta.size() * sizeof(theta[0]);
			auto buffSize = thetaSize + phi.getSpan<u8>().size();
			AlignedUnVector<u8> buffer(buffSize);
			copyBytes(buffer.subspan(0, thetaSize), theta);
			copyBytes(buffer.subspan(thetaSize), phi.getSpan<u8>());
			co_await sock.send(std::move(buffer));
			buffer.resize(buffSize);
			co_await sock.recv(buffer);
			std::vector<block> theta1(theta.size());
			BitVector phi1(phi.size());
			copyBytes(theta1, buffer.subspan(0, thetaSize));
			copyBytes(phi1.getSpan<u8>(), buffer.subspan(thetaSize));

			// reconstruct phi
			phi ^= phi1;

			auto partyMask = block(-u64(mPartyIdx), -u64(mPartyIdx));
			for (u64 j = 0; j < x.size(); ++j)
			{
				// reconstruct theta
				theta[j] ^= theta1[j];

				// mask block of phi
				auto Phi = block(-u64(phi[j]), -u64(phi[j]));

				// [zy] = [c] + theta * [a] + phi * [b] + theta * phi
				xy[j] = C[j] ^ (theta[j] & A0[j]) ^ (Phi & b1[j]) ^ (partyMask & theta[j] & Phi);
			}


			mOtIdx += x.size();

		}

		static void packBits(span<u8> dest, MatrixView<u8> src, u64 bitCount)
		{
			if (dest.size() != divCeil(src.rows() * bitCount, 8))
				throw RTE_LOC;

			if (bitCount % 8 == 0)
			{
				auto bytes = divCeil(bitCount, 8);
				for (u64 i = 0; i < src.rows(); ++i)
				{
					copyBytes(dest.subspan(0, bytes), src[i].subspan(0, bytes));
					dest = dest.subspan(src.cols());
				}
			}
			else
			{
				auto dIter = BitIterator(dest.data());
				for (u64 i = 0; i < src.rows(); ++i)
				{
					auto sIter = BitIterator(src[i].data());
					for (u64 j = 0; j < bitCount; ++j)
					{
						*dIter = *sIter;
						++dIter;
						++sIter;
					}
				}
			}
		}

		static void unpackBits(Matrix<u8>& dest, span<u8> src, u64 bitCount)
		{
			if (src.size() != divCeil(dest.rows() * bitCount, 8))
				throw RTE_LOC;
			if (bitCount % 8 == 0)
			{
				auto bytes = divCeil(bitCount, 8);
				for (u64 i = 0; i < dest.rows(); ++i)
				{
					copyBytes(dest[i].subspan(0, bytes), src.subspan(0, bytes));
					src = src.subspan(dest.cols());
				}
			}
			else
			{
				auto sIter = BitIterator(src.data());
				for (u64 i = 0; i < dest.rows(); ++i)
				{
					auto dIter = BitIterator(dest[i].data());
					for (u64 j = 0; j < bitCount; ++j)
					{
						*dIter = *sIter;
						++dIter;
						++sIter;
					}
				}
			}
		}

		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi is a bit and yi 
		// is a vector.
		// This version generalizes to arbitrary length vector yi. Each row of
		// y is one vector.
		macoro::task<> multiply(
			u64 bitCount,
			span<const u8> x,
			MatrixView<const u8> y,
			MatrixView<u8> xy,
			coproto::Socket& sock)
		{
			u64 n = y.rows();

			if (x.size() != divCeil(y.rows(), 8) || y.rows() != xy.rows())
				throw RTE_LOC;
			if (y.cols() != xy.cols())
				throw RTE_LOC;
			if (divCeil(bitCount, 8) != y.cols())
				throw RTE_LOC;
			if (n + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			auto otIdx = mOtIdx;
			mOtIdx += n;


			auto expandSeed = [](span<u8> dst, block seed0, block seed1) {
				if (dst.size() < 16)
				{
					auto v = seed0 ^ seed1;
					copyBytesMin(dst, v);
				}
				else
				{
					AES aes0(seed0);
					AES aes1(seed1);
					for (u64 i = 0; dst.size(); ++i)
					{
						auto v = aes0.ecbEncBlock(block(i, i))
							^ aes1.ecbEncBlock(block(i, i));
						copyBytesMin(dst, v);
						dst = dst.subspan(std::min<u64>(16, dst.size()));
					}
				}
				};

			// our a share of a * b = c.
			BitVector a0; a0.append(mChoiceBits, n, otIdx);

			// A0 = 11...1 * a , an expanded version of a used for masking.
			std::vector<u8> A0(n);

			// our c share of a * b = c.
			Matrix<u8> C(n, y.cols());

			// theta = y + b
			Matrix<u8> theta(n, y.cols());

			// our b share of a * b = c
			Matrix<u8> b1(n, y.cols());

			std::vector<u8> c00c10(y.cols());//, c10(y.cols());
			for (u64 j = 0; j < n; ++j)
			{
				A0[j] = -a0[j];
				//A0[j] = block(-u64(a0[j]), -u64(a0[j]));
				expandSeed(c00c10, mRecvOts[otIdx + j], mSendOts[otIdx + j][0]);
				expandSeed(b1[j], mSendOts[otIdx + j][0], mSendOts[otIdx + j][1]);
				//b1[j] = mSendOts[otIdx + j][0] ^ mSendOts[otIdx + j][1];

				// C0' = c00+c10+a0b1
				for (u64 i = 0; i < y.cols(); ++i)
				{
					// C0' = c00+c10+a0b1
					C[j][i] = c00c10[i] ^ (b1[j][i] & A0[j]);

					// theta = y + b
					theta[j][i] = y[j][i] ^ b1[j][i];
				}
			}

			std::vector<u8> phi(x.size());;
			for (u64 i = 0; i < phi.size(); ++i)
				phi[i] = x[i] ^ a0.getSpan<u8>()[i];
			if (n % 8)
			{
				u8 mask = (1 << (n % 8)) - 1;
				phi.back() &= mask;
			}


			AlignedUnVector<u8> buffer;

			if (bitCount < 16)
			{
				// we will back the bits as an optimization.
				auto thetaSize = divCeil(n * bitCount, 8);
				buffer.resize(thetaSize + phi.size());

				packBits(buffer.subspan(0, thetaSize), theta, bitCount);
				copyBytes(buffer.subspan(thetaSize), phi);

				co_await sock.send(std::move(buffer));

				buffer.resize(thetaSize + phi.size());
				co_await sock.recv(buffer);

				Matrix<u8> theta1(theta.rows(), theta.cols());
				unpackBits(theta1, buffer.subspan(0, thetaSize), bitCount);
				std::vector<u8> phi1(phi.size());
				copyBytes(phi1, buffer.subspan(thetaSize));

				// reconstruct phi
				for (u64 j = 0; j < phi.size(); ++j)
					phi[j] ^= phi1[j];

				// reconstruct theta
				for (u64 j = 0; j < theta.size(); ++j)
					theta(j) ^= theta1(j);

			}
			else
			{
				buffer.resize(theta.size() + phi.size());

				copyBytes(buffer.subspan(0, theta.size()), theta);
				copyBytes(buffer.subspan(theta.size()), phi);

				co_await sock.send(std::move(buffer));

				buffer.resize(theta.size() + phi.size());
				co_await sock.recv(buffer);
				MatrixView<u8> theta1(buffer.data(), theta.rows(), theta.cols());
				std::vector<u8> phi1(phi.size());
				copyBytes(phi1, buffer.subspan(theta.size()));

				// reconstruct phi
				for (u64 j = 0; j < phi.size(); ++j)
					phi[j] ^= phi1[j];

				// reconstruct theta
				for (u64 j = 0; j < theta.size(); ++j)
					theta(j) ^= theta1(j);
			}

			u8 partyMask = -u8(mPartyIdx);
			for (u64 j = 0; j < n; ++j)
			{
				// mask block of phi
				u8 Phi = -*BitIterator(phi.data(), j);

				for (u64 i = 0; i < y.cols(); ++i)
				{
					// [zy] = [c] + theta * [a] + phi * [b] + theta * phi
					xy[j][i] = C[j][i] ^ (theta[j][i] & A0[j]) ^ (Phi & b1[j][i]) ^ (partyMask & theta[j][i] & Phi);

				}

				if (bitCount % 8)
				{
					u8 mask = (1 << (bitCount % 8)) - 1;
					xy[j].back() &= mask;
				}
			}

		}


		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi is a bit and yi 
		// is a vector.
		// This version generalizes to arbitrary length vector yi. Each row of
		// y is one vector.
		//
		//
		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi, yi are bits.
		// 
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
		// [zy] = [c'] + theta [a] + phi [b] + theta phi
		//      = ab + (y+b) a + (x+a) b + (y+b)(x+a)
		//      = ab + ab + ya + xb + ab + yx + ya + xb + ab
		//      = xy
		//
		macoro::task<> multiplyBits(
			const BitVector& x,
			const BitVector& y,
			BitVector& xy,
			coproto::Socket& sock)
		{

			auto n = x.size();
			if (y.size() != n)
				throw RTE_LOC;
			if (xy.size() != n)
				throw RTE_LOC;
			return multiplyBits(n, x.getSpan<const u8>(), y.getSpan<const u8>(), xy.getSpan<u8>(), sock);
		}


		macoro::task<> multiplyBits(
			u64 n,
			span<const u8> x,
			span<const u8> y,
			span<u8> xy,
			coproto::Socket& sock)
		{
			if (x.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (y.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (xy.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (n + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			u64 n8 = divCeil(n, 8);
			auto otIdx = mOtIdx;
			mOtIdx += n;

			// our a share of a * b = c.
			BitVector a0; a0.append(mChoiceBits, n, otIdx);
			BitVector b1(n);
			// our c share of a * b = c.
			BitVector c(n);

			auto a8 = a0.getSpan<u8>();
			auto b8 = b1.getSpan<u8>();
			auto c8 = c.getSpan<u8>();

			u8 c00c10;
			for (u64 j = 0; j < n; ++j)
			{
				b1[j] = lsb(mSendOts[otIdx + j][0] ^ mSendOts[otIdx + j][1]);
				c00c10 = lsb(mRecvOts[otIdx + j] ^ mSendOts[otIdx + j][0]);
				c[j] = c00c10 ^ (b1[j] & a0[j]);
			}

			AlignedUnVector<u8> phi(n8), theta(n8);
			for (u64 i = 0; i < n8; ++i)
			{
				phi[i] = x[i] ^ a8[i];
				theta[i] = y[i] ^ b8[i];
			}
			if (n % 8)
			{
				u8 mask = (1 << (n % 8)) - 1;
				phi.back() &= mask;
				theta.back() &= mask;
			}

			co_await sock.send(coproto::copy(theta));
			co_await sock.send(coproto::copy(phi));

			AlignedUnVector<u8> theta1(theta.size()), phi1(phi.size());
			co_await sock.recv(theta1);
			co_await sock.recv(phi1);
			for (u64 i = 0; i < n8; ++i)
			{
				phi[i] ^= phi1[i];
				theta[i] ^= theta1[i];
				xy[i] =
					c8[i] ^
					(theta[i] & a8[i]) ^
					(phi[i] & b8[i]) ^
					(-mPartyIdx & theta[i] & phi[i]);
			}
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
