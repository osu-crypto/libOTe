#pragma once


#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#include "DpfMult.h"
#include "libOTe/Tools/Foleage/FoleageUtils.h"

namespace osuCrypto
{
	struct TriDpf
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

		u64 mNumPoints = 0;

		//DpfMult mMultiplier;

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		void init(
			u64 partyIdx,
			u64 domain,
			u64 numPoints)
		{
			if (partyIdx > 1)
				throw RTE_LOC;
			if (domain < 2)
				throw RTE_LOC;
			if (!numPoints)
				throw RTE_LOC;

			mDepth = log3ceil(domain);
			mPartyIdx = partyIdx;
			mDomain = domain;
			mNumPoints = numPoints;
			//mMultiplier.init(partyIdx, numPoints * mDepth);
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

		template<
			typename Output
		>
		macoro::task<> expand(
			span<u64> points,
			span<block> values,
			Output&& output,
			PRNG& prng,
			coproto::Socket& sock)
		{
			if constexpr (std::is_same<std::remove_reference<Output>, Matrix<block>>::value)
			{
				if (output.rows() != mNumPoints)
					throw RTE_LOC;
				if (output.cols() != mDomain)
					throw RTE_LOC;
			}
			if (points.size() != mNumPoints)
				throw RTE_LOC;
			if (values.size() && values.size() != mNumPoints)
				throw RTE_LOC;

			for (u64 i = 0; i < mNumPoints; ++i)
			{
				u64 v = points[i];
				for (u64 j = 0; j < mDepth; ++j)
				{
					if ((v & 3) == 3)
						throw std::runtime_error("TriDpf: invalid point sharing. Expects the input points to be shared over Z_3^D where each Z_3 elements takes up 2 bits of a the value. " LOCATION);
					v >>= 2;
				}
				if(v)
					throw std::runtime_error("TriDpf: invalid point sharing. point is larger than 3^D " LOCATION);
			}

			u64 numPoints = points.size();
			u64 numPoints8 = numPoints / 8 * 8;


			// shares of S'
			auto pow2 = 1ull << log2ceil(mDomain);
			std::array<Matrix<block>, 2> s;
			s[mDepth & 1].resize(pow2, numPoints, oc::AllocType::Uninitialized);
			s[(mDepth & 1) ^ 1].resize(pow2 / 2, numPoints, oc::AllocType::Uninitialized);

			// share of t
			std::array<Matrix<u8>, 2> t;
			t[0].resize(s[0].rows(), s[0].cols());
			t[1].resize(s[1].rows(), s[1].cols());
			for (u64 i = 0; i < numPoints; ++i)
				t[0](0, i) = mPartyIdx;


#if defined(NDEBUG)
			auto getRow = [](auto&& m, u64 i) {return m.data(i); };
#else
			auto getRow = [](auto&& m, u64 i) {return m[i]; };
#endif
			std::array<AlignedUnVector<u8>, 2> tau;
			tau[0].resize(mNumPoints);
			tau[1].resize(mNumPoints);

			std::array<AlignedUnVector<block>, 2> z;
			z[0].resize(mNumPoints);
			z[1].resize(mNumPoints);
			AlignedUnVector<block> sigma(mNumPoints);
			BitVector negAlphaj(mNumPoints);
			AlignedUnVector<block> diff(mNumPoints);


			{
				// we skip level 0 and set level 1 to be random
				auto sc0 = s[1][0];
				auto sc1 = s[1][1];
				for (u64 k = 0; k < numPoints; ++k)
				{
					sc0[k] = prng.get<block>();
					sc1[k] = prng.get<block>();

					z[0][k] = sc0[k];
					z[1][k] = sc1[k];
				}
			}

			// at each iteration we first correct the parent level.
			// The parent level has two syblings which are random.
			// We need to correct the inactive child so that both parties
			// hold the same seed (a sharing of zero).
			//
			// we then expand the parent to level to get the children level.
			// We compute left and right sums for the children.
			for (u64 iter = 1; iter <= mDepth; ++iter)
			{
				// the grand parent level
				auto& tp = t[(iter - 1) & 1];

				// the parent level
				auto& sc = s[iter & 1];
				auto& tc = t[iter & 1];

				// the child level
				auto& sg = s[(iter + 1) & 1];

				auto size = 1ull << iter;

				//
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					auto alphaj = *oc::BitIterator(&points[k], mDepth - iter);
					tau[0][k] = lsb(z[0][k]) ^ alphaj ^ mPartyIdx;
					tau[1][k] = lsb(z[1][k]) ^ alphaj;
					diff[k] = z[0][k] ^ z[1][k];
					negAlphaj[k] = alphaj ^ mPartyIdx;
				}

				co_await mMultiplier.multiply(negAlphaj, diff, diff, sock);
				// sigma = z[1^alpha[j]]
				for (u64 k = 0; k < mNumPoints; ++k)
					sigma[k] = diff[k] ^ z[0][k];

				// reveal sigma and tau
				u64 buffSize = sigma.size() * 16 + divCeil(mNumPoints * 2, 8);
				AlignedUnVector<u8> sendBuff(buffSize), recvBuff(buffSize);
				copyBytesMin(sendBuff, sigma);
				auto sendBitIter = BitIterator(&sendBuff[numPoints * 16]);
				auto recvBitIter = BitIterator(&recvBuff[numPoints * 16]);
				for (u64 i = 0; i < mNumPoints; ++i)
				{
					*sendBitIter++ = tau[0][i];
					*sendBitIter++ = tau[1][i];
				}
				co_await sock.send(std::move(sendBuff));
				co_await sock.recv(recvBuff);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					block sk = *(block*)&recvBuff[k * sizeof(block)];
					sigma[k] ^= sk;
					tau[0][k] ^= *recvBitIter++;
					tau[1][k] ^= *recvBitIter++;
				}


				if (iter != mDepth)
				{

					setBytes(z[0], 0);
					setBytes(z[1], 0);

					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 2, L4 += 4)
					{
						// parent control bits
						auto tpl = getRow(tp, L);

						// child seed
						std::array scl{ getRow(sc, L2 + 0), getRow(sc, L2 + 1) };

						// child control bit
						std::array tcl{ getRow(tc, L2 + 0), getRow(tc, L2 + 1) };

						// grandchild seeds
						std::array sgl{ getRow(sg, L4 + 0), getRow(sg, L4 + 1), getRow(sg, L4 + 2), getRow(sg, L4 + 3) };

						for (u64 k = 0; k < numPoints8; k += 8)
						{
							block temp[8];
							SIMD8(q, temp[q] = block::allSame<u64>(-tpl[k + q]) & sigma[k + q]);
							SIMD8(q, tcl[0][k + q] = lsb(scl[0][k + q]) ^ tpl[k + q] & tau[0][k + q]);
							SIMD8(q, scl[0][k + q] ^= temp[q]);


							mAesFixedKey.ecbEncBlocks<8>(&scl[0][k], &sgl[1][k]);
							SIMD8(q, sgl[0][k + q] = AES::roundEnc(sgl[1][k + q], scl[0][k + q]));
							SIMD8(q, sgl[1][k + q] = sgl[1][k + q] + scl[0][k + q]);

							SIMD8(q, z[0][k + q] ^= sgl[0][k + q]);
							SIMD8(q, z[1][k + q] ^= sgl[1][k + q]);

							SIMD8(q, tcl[1][k + q] = lsb(scl[1][k + q]) ^ tpl[k + q] & tau[1][k + q]);
							SIMD8(q, scl[1][k + q] ^= temp[q]);

							mAesFixedKey.ecbEncBlocks<8>(&scl[1][k], &sgl[3][k]);
							SIMD8(q, sgl[2][k + q] = AES::roundEnc(sgl[3][k + q], scl[1][k + q]));
							SIMD8(q, sgl[3][k + q] = sgl[3][k + q] + scl[1][k + q]);
							SIMD8(q, z[0][k + q] ^= sgl[2][k + q]);
							SIMD8(q, z[1][k + q] ^= sgl[3][k + q]);
						}

						for (u64 k = numPoints8; k < mNumPoints; ++k)
						{
							auto temp = block::allSame<u64>(-tpl[k + 0]) & sigma[k + 0];

							tcl[0][k] = lsb(scl[0][k]) ^ tpl[k] & tau[0][k];
							scl[0][k] ^= temp;

							sgl[1][k] = mAesFixedKey.ecbEncBlock(scl[0][k]);
							sgl[0][k] = AES::roundEnc(sgl[1][k], scl[0][k]);
							sgl[1][k] = sgl[1][k] + scl[0][k];

							z[0][k] ^= sgl[0][k];
							z[1][k] ^= sgl[1][k];

							tcl[1][k] = lsb(scl[1][k]) ^ tpl[k] & tau[1][k];
							scl[1][k] ^= temp;

							sgl[3][k] = mAesFixedKey.ecbEncBlock(scl[1][k]);
							sgl[2][k] = AES::roundEnc(sgl[3][k], scl[1][k]);
							sgl[3][k] = sgl[3][k] + scl[1][k];

							z[0][k] ^= sgl[2][k];
							z[1][k] ^= sgl[3][k];
						}
					}
				}
			}


			// fixing the last layer
			{
				auto size = 1ull << mDepth;

				auto& tp = t[(mDepth - 1) & 1];
				auto& sc = s[mDepth & 1];
				auto& tc = t[mDepth & 1];
				for (u64 L = 0, L2 = 0; L2 < size; ++L, L2 += 2)
				{
					// parent control bits
					auto tpl = getRow(tp, L);

					// child seed
					std::array scl{ getRow(sc, L2 + 0), getRow(sc, L2 + 1) };

					// child control bit
					std::array tcl{ getRow(tc, L2 + 0), getRow(tc, L2 + 1) };

					for (u64 k = 0; k < numPoints8; k += 8)
					{
						block temp[8];
						SIMD8(q, temp[q] = block::allSame<u64>(-tpl[k + q]) & sigma[k + q]);
						SIMD8(q, tcl[0][k + q] = lsb(scl[0][k + q]) ^ tpl[k + q] & tau[0][k + q]);
						SIMD8(q, tcl[1][k + q] = lsb(scl[1][k + q]) ^ tpl[k + q] & tau[1][k + q]);
						SIMD8(q, scl[0][k + q] ^= temp[q]);
						SIMD8(q, scl[1][k + q] ^= temp[q]);
					}

					for (u64 k = numPoints8; k < mNumPoints; ++k)
					{
						auto temp = block::allSame<u64>(-tpl[k + 0]) & sigma[k + 0];
						tc[L2 + 0][k] = lsb(scl[0][k]) ^ tpl[k] & tau[0][k];
						tc[L2 + 1][k] = lsb(scl[1][k]) ^ tpl[k] & tau[1][k];
						sc[L2 + 0][k] ^= temp;
						sc[L2 + 1][k] ^= temp;
					}
				}
			}

			if (values.size())
			{

				AlignedUnVector<block> gamma(mNumPoints);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					diff[k] = z[0][k] ^ z[1][k] ^ values[k];
				}
				co_await sock.send(std::move(diff));
				co_await sock.recv(gamma);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					gamma[k] = z[0][k] ^ z[1][k] ^ values[k] ^ gamma[k];
				}

				auto& sd = s[mDepth & 1];
				auto& td = t[mDepth & 1];
				for (u64 i = 0; i < mDomain; ++i)
				{
					auto sdi = getRow(sd, i);
					auto tdi = getRow(td, i);

					for (u64 k = 0; k < numPoints8; k += 8)
					{
						block T[8];

						SIMD8(q, T[q] = block::allSame<u64>(-tdi[k + q]) & gamma[k + q]);
						SIMD8(q, output(k + q, i, sdi[k + q] ^ T[q], tdi[k + q]));
					}
					for (u64 k = numPoints8; k < mNumPoints; ++k)
					{
						auto T = block::allSame<u64>(-tdi[k]) & gamma[k];
						output(k, i, sdi[k] ^ T, tdi[k]);
					}
				}
			}
			else
			{
				auto& sd = s[mDepth & 1];
				auto& td = t[mDepth & 1];
				for (u64 i = 0; i < mDomain; ++i)
				{
					auto sdi = getRow(sd, i);
					auto tdi = getRow(td, i);
					for (u64 k = 0; k < numPoints8; k += 8)
					{
						SIMD8(q, output(k + q, i, sdi[k + q], tdi[k + q]));
					}
					for (u64 k = numPoints8; k < mNumPoints; ++k)
					{
						output(k, i, sdi[k], tdi[k]);
					}
				}
			}
		}


		u64 baseOtCount() const {
			return mMultiplier.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}


	};

}

#undef SIMD8