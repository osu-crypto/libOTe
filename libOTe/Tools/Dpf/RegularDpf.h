#pragma once


#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{
	struct RegularDpf
	{
		enum class OutputFormat
		{
			// The i'th row holds the i'th leaf for all trees. 
			// The j'th tree is in the j'th column.
			ByLeafIndex,

			// The i'th row holds the i'th tree. 
			// The j'th leaf is in the j'th column.
			ByTreeIndex,

		};

		OutputFormat mOutputFormat = OutputFormat::ByLeafIndex;

		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		u64 mDepth = 0;

		std::vector<u64> mPoints;

		std::vector<block> mValues;

		oc::BitVector mChoiceBits;

		std::vector<block> mRecvOts;
		std::vector<std::array<block, 2>> mSendOts;

		u64 mOtIdx = 0;

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		void init(
			u64 partyIdx,
			u64 domain,
			span<u64> points,
			span<block> values)
		{
			if (partyIdx > 1)
				throw RTE_LOC;
			if (domain < 2)
				throw RTE_LOC;
			if (points.size() != values.size())
				throw RTE_LOC;

			mPartyIdx = partyIdx;
			mDomain = domain;
			mDepth = oc::log2ceil(domain);

			mPoints.clear();
			mValues.clear();
			mPoints.insert(mPoints.end(), points.begin(), points.end());
			mValues.insert(mValues.end(), values.begin(), values.end());

		}

#define SIMD8(VAR, STATEMENT) \
	{ constexpr u64 VAR = 0; STATEMENT; }\
	{ constexpr u64 VAR = 1; STATEMENT; }\
	{ constexpr u64 VAR = 2; STATEMENT; }\
	{ constexpr u64 VAR = 3; STATEMENT; }\
	{ constexpr u64 VAR = 4; STATEMENT; }\
	{ constexpr u64 VAR = 5; STATEMENT; }\
	{ constexpr u64 VAR = 6; STATEMENT; }\
	{ constexpr u64 VAR = 7; STATEMENT; }\
	do{}while(0)

		template<typename Output>
		macoro::task<> expand(
			Output&& output,
			PRNG& prng,
			coproto::Socket& sock)
		{
			if constexpr (std::is_same<std::remove_reference<Output>, Matrix<block>>::value)
			{
				if (output.rows() != mPoints.size())
					throw RTE_LOC;
				if (output.cols() != mDomain)
					throw RTE_LOC;
			}

			u64 numPoints = mPoints.size();
			u64 numPoints8 = numPoints / 8 * 8;


			// shares of S'
			//std::vector<Matrix<block>> s(mDepth + 2);
			auto pow2 = 1ull << log2ceil(mDomain);
			std::array<Matrix<block>, 2> s;
			s[mDepth & 1].resize(pow2, numPoints, oc::AllocType::Uninitialized);
			s[(mDepth & 1) ^ 1].resize(pow2/2, numPoints, oc::AllocType::Uninitialized);

			//s[0].resize(1, mPoints.size());
			prng.get<block>(s[0].data(), 1);


			// share of t
			std::array<Matrix<u8>, 2> t;
			t[0].resize(s[0].rows(), s[0].cols());
			t[1].resize(s[1].rows(), s[1].cols());
			for (u64 i = 0; i < numPoints; ++i)
				t[0](0,i) = mPartyIdx;
			//std::vector<Matrix<u8>> t(mDepth + 2);
			//t[0].resize(1, mPoints.size());
			//for (auto& tt : t[0])
			//	tt = mPartyIdx;

			std::array<AlignedUnVector<u8>, 2> tau;
			tau[0].resize(mPoints.size());
			tau[1].resize(mPoints.size());

			std::array<AES, 2> hashes{
				block(223142132554234532,345324534532452345),
				block(476657546875476456,849723947534923433),
			};
			std::array<AlignedUnVector<block>, 2> z, zg;
			z[0].resize(mPoints.size());
			z[1].resize(mPoints.size());
			zg[0].resize(mPoints.size());
			zg[1].resize(mPoints.size());
			AlignedUnVector<block> sigma(mPoints.size());
			BitVector negAlphaj(mPoints.size());
			AlignedUnVector<block> diff(mPoints.size());


			{
				//s[1].resize(2, mPoints.size());
				//t[1].resize(2, mPoints.size());

				setBytes(z[0], 0);
				setBytes(z[1], 0);

				auto spi = s[0][0];
				auto sc0 = s[1][0];
				auto sc1 = s[1][1];
				for (u64 k = 0; k < numPoints; ++k)
				{
					sc0[k] = hashes[0].hashBlock(spi[k]);
					sc1[k] = hashes[1].hashBlock(spi[k]);

					z[0][k] ^= sc0[k];
					z[1][k] ^= sc1[k];
				}
			}

			for (u64 iter = 1; iter <= mDepth; ++iter)
			{
				//auto& sp = s[iter - 1];
				auto& tp = t[(iter - 1) & 1];
				auto& sc = s[iter & 1];
				auto& tc = t[iter & 1];
				auto& sg = s[(iter + 1) & 1];

				auto size = 1ull << iter;
				auto size2 = 1ull << (iter + 1);

				if (iter != mDepth)
				{
					//sg.resize(size2, mPoints.size());
					//t[iter + 1].resize(size2, mPoints.size());

					setBytes(zg[0], 0);
					setBytes(zg[1], 0);
				}

				for (u64 k = 0; k < mPoints.size(); ++k)
				{
					auto alphaj = *oc::BitIterator(&mPoints[k], mDepth - iter);
					tau[0][k] = lsb(z[0][k]) ^ alphaj ^ mPartyIdx;
					tau[1][k] = lsb(z[1][k]) ^ alphaj;
					diff[k] = z[0][k] ^ z[1][k];
					negAlphaj[k] = alphaj ^ mPartyIdx;
				}

				co_await multiply(negAlphaj, diff, diff, sock);
				// sigma = z[1^alpha[j]]
				for (u64 k = 0; k < mPoints.size(); ++k)
					sigma[k] = diff[k] ^ z[0][k];

				// reveal
				u64 buffSize = sigma.size() * 16 + divCeil(mPoints.size() * 2, 8);
				AlignedUnVector<u8> buffer(buffSize);
				copyBytesMin(buffer, sigma);
				auto bitIter = BitIterator(&buffer[numPoints * 16]);
				for (u64 i = 0; i < mPoints.size(); ++i)
				{
					*bitIter++ = tau[0][i];
					*bitIter++ = tau[1][i];
				}
				if (bitIter.mByte >= buffer.data() + buffer.size() && bitIter.mShift)
					throw RTE_LOC;
				co_await sock.send(std::move(buffer));
				buffer.resize(buffSize);
				bitIter = BitIterator(&buffer[numPoints * 16]);
				co_await sock.recv(buffer);
				for (u64 k = 0; k < mPoints.size(); ++k)
				{
					block sk = *(block*)&buffer[k * sizeof(block)];
					sigma[k] ^= sk;
					tau[0][k] ^= *bitIter++;
					tau[1][k] ^= *bitIter++;
				}

				if (iter == mDepth)
				{

					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 2, L4 += 4)
					{
#if defined(NDEBUG)
						auto tpl = tp.data(L);
						auto scl0 = sc.data(L2 + 0);
						auto scl1 = sc.data(L2 + 1);
						auto tcl0 = tc.data(L2 + 0);
						auto tcl1 = tc.data(L2 + 1);
#else
						auto tpl = tp[L];
						auto scl0 = sc[L2 + 0];
						auto scl1 = sc[L2 + 1];
						auto tcl0 = tc[L2 + 0];
						auto tcl1 = tc[L2 + 1];
#endif 

						for (u64 k = 0; k < numPoints8; k += 8)
						{
							block T[8];
							SIMD8(q, T[q] = block::allSame<u64>(-tpl[k + q]) & sigma[k + q]);
							SIMD8(q, tcl0[k + q] = lsb(scl0[k + q]) ^ tpl[k + q] & tau[0][k + q]);
							SIMD8(q, tcl1[k + q] = lsb(scl1[k + q]) ^ tpl[k + q] & tau[1][k + q]);
							SIMD8(q, scl0[k + q] ^= T[q]);
							SIMD8(q, scl1[k + q] ^= T[q]);
						}

						for (u64 k = numPoints8; k < mPoints.size(); ++k)
						{
							auto T = block::allSame<u64>(-tpl[k + 0]) & sigma[k + 0];
							tc[L2 + 0][k] = lsb(sc[L2 + 0][k]) ^ tp[L][k] & tau[0][k];
							tc[L2 + 1][k] = lsb(sc[L2 + 1][k]) ^ tp[L][k] & tau[1][k];
							sc[L2 + 0][k] ^= T;
							sc[L2 + 1][k] ^= T;
						}
					}
				}
				else
				{

					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 2, L4 += 4)
					{
#if defined(NDEBUG)
						auto tpl = tp.data(L);
						auto scl0 = sc.data(L2 + 0);
						auto scl1 = sc.data(L2 + 1);
						auto tcl0 = tc.data(L2 + 0);
						auto tcl1 = tc.data(L2 + 1);

						auto sg00 = sg.data(L4 + 0);
						auto sg10 = sg.data(L4 + 1);
						auto sg01 = sg.data(L4 + 2);
						auto sg11 = sg.data(L4 + 3);
#else

						auto tpl = tp[L];
						auto scl0 = sc[L2 + 0];
						auto scl1 = sc[L2 + 1];
						auto tcl0 = tc[L2 + 0];
						auto tcl1 = tc[L2 + 1];

						auto sg00 = sg[L4 + 0];
						auto sg10 = sg[L4 + 1];
						auto sg01 = sg[L4 + 2];
						auto sg11 = sg[L4 + 3];
#endif

						for (u64 k = 0; k < numPoints8; k += 8)
						{
							block T[8];
							SIMD8(q, T[q] = block::allSame<u64>(-tpl[k + q]) & sigma[k + q]);
							SIMD8(q, tcl0[k + q] = lsb(scl0[k + q]) ^ tpl[k + q] & tau[0][k + q]);
							SIMD8(q, scl0[k + q] ^= T[q]);

							hashes[0].ecbEncBlocks<8>(&scl0[k], &sg10[k]);
							SIMD8(q, sg00[k + q] = AES::roundEnc(sg10[k + q], scl0[k + q]));
							SIMD8(q, sg10[k + q] = sg10[k + q] + scl0[k + q]);

							SIMD8(q, zg[0][k + q] ^= sg00[k + q]);
							SIMD8(q, zg[1][k + q] ^= sg10[k + q]);

							SIMD8(q, tcl1[k + q] = lsb(scl1[k + q]) ^ tpl[k + q] & tau[1][k + q]);
							SIMD8(q, scl1[k + q] ^= T[q]);

							hashes[0].ecbEncBlocks<8>(&scl1[k], &sg11[k]);
							SIMD8(q, sg01[k + q] = AES::roundEnc(sg11[k + q], scl1[k + q]));
							SIMD8(q, sg11[k + q] = sg11[k + q] + scl1[k + q]);
							SIMD8(q, zg[0][k + q] ^= sg01[k + q]);
							SIMD8(q, zg[1][k + q] ^= sg11[k + q]);
						}

						for (u64 k = numPoints8; k < mPoints.size(); ++k)
						{
							auto T = block::allSame<u64>(-tpl[k + 0]) & sigma[k + 0];

							tcl0[k] = lsb(scl0[k]) ^ tpl[k] & tau[0][k];
							scl0[k] ^= T;

							sg10[k] = hashes[0].ecbEncBlock(scl0[k]);
							sg00[k] = AES::roundEnc(sg10[k], scl0[k]);
							sg10[k] = sg10[k] + scl0[k];

							zg[0][k] ^= sg00[k];
							zg[1][k] ^= sg10[k];

							tcl1[k] = lsb(scl1[k]) ^ tpl[k] & tau[1][k];
							scl1[k] ^= T;
							
							sg11[k] = hashes[0].ecbEncBlock(scl1[k]);
							sg01[k] = AES::roundEnc(sg11[k], scl1[k]);
							sg11[k] = sg11[k] + scl1[k];

							zg[0][k] ^= sg01[k];
							zg[1][k] ^= sg11[k];
						}
					}
				}

				std::swap(z, zg);
			}

			if (mValues.size())
			{

				AlignedUnVector<block> gamma(mPoints.size());
				for (u64 k = 0; k < mPoints.size(); ++k)
				{
					diff[k] = zg[0][k] ^ zg[1][k] ^ mValues[k];
				}
				co_await sock.send(std::move(diff));
				co_await sock.recv(gamma);
				for (u64 k = 0; k < mPoints.size(); ++k)
				{
					gamma[k] = zg[0][k] ^ zg[1][k] ^ mValues[k] ^ gamma[k];
				}

				auto& sd = s[mDepth&1];
				auto& td = t[mDepth&1];
				for (u64 i = 0; i < mDomain; ++i)
				{
#if defined(NDEBUG) 
					auto sdi = sd.data(i);
					auto tdi = td.data(i);
#else
					auto sdi = sd[i];
					auto tdi = td[i];
#endif

					for (u64 k = 0; k < numPoints8; k += 8)
					{
						block T[8];

						SIMD8(q, T[q] = block::allSame<u64>(-tdi[k + q]) & gamma[k + q]);
						SIMD8(q, output(k + q, i) = sdi[k + q] ^ T[q]);
					}
					for (u64 k = numPoints8; k < mPoints.size(); ++k)
					{
						auto T = block::allSame<u64>(-tdi[k]) & gamma[k];
						output(k, i) = sdi[k] ^ T;
					}
				}
			}
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
				xy[j] = C[j] ^ theta[j] & A0[j] ^ Phi & b1[j];

				if (mPartyIdx)
					xy[j] ^= theta[j] & Phi;
			}


			mOtIdx += x.size();

		}

		u64 baseOtCount() const { return mDepth * mPoints.size(); }

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