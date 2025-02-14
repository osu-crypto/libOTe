#pragma once


#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#include "DpfMult.h"

namespace osuCrypto
{
	struct RegularDpf
	{
		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		u64 mDepth = 0;

		u64 mNumPoints = 0;

		DpfMult mMultiplier;

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		// extracts the lsb of b and returns a block saturated with that bit.
		block tagBit(const block& b)
		{
			auto bit = b & block(0, 1);
			auto mask = _mm_sub_epi64(_mm_set1_epi64x(0), bit);
			return _mm_unpacklo_epi64(mask, mask);
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

			mDepth = log2ceil(domain);
			mPartyIdx = partyIdx;
			mDomain = domain;
			mNumPoints = numPoints;
			mMultiplier.init(partyIdx, numPoints * mDepth);
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

			u64 numPoints = points.size();
			u64 numPoints8 = numPoints / 8 * 8;


			// shares of S'
			auto pow2 = 1ull << log2ceil(mDomain);
			std::array<Matrix<block>, 3> s;
			s[mDepth % 3].resize(pow2, numPoints, oc::AllocType::Uninitialized);
			s[(mDepth + 2) % 3].resize(pow2 / 2, numPoints, oc::AllocType::Uninitialized);
			s[(mDepth + 1) % 3].resize(pow2 / 4, numPoints, oc::AllocType::Uninitialized);

			// share of t
			//std::array<Matrix<u8>, 2> t;
			//t[0].resize(s[0].rows(), s[0].cols());
			//t[1].resize(s[1].rows(), s[1].cols());
			//for (u64 i = 0; i < numPoints; ++i)
			//	t[0](0, i) = mPartyIdx;


#if defined(NDEBUG)
			auto getRow = [](auto&& m, u64 i) {return m.data(i); };
#else
			auto getRow = [](auto&& m, u64 i) {return m[i]; };
#endif
			//std::array<AlignedUnVector<u8>, 2> tau;
			//tau[0].resize(mNumPoints);
			//tau[1].resize(mNumPoints);

			std::array<AlignedUnVector<block>, 2> z;
			z[0].resize(mNumPoints);
			z[1].resize(mNumPoints);
			std::array<AlignedUnVector<block>, 2> sigma;
			sigma[0].resize(mNumPoints);
			sigma[1].resize(mNumPoints);
			AlignedUnVector<block> sigmaMult(mNumPoints);
			BitVector negAlphaj(mNumPoints);
			AlignedUnVector<block> diff(mNumPoints);
			std::array<block, 8> temp;

			{
				// we skip level 0 and set level 1 to be random
				auto sc0 = s[1][0];
				auto sc1 = s[1][1];

				auto tag = s[0][0];
				for (u64 k = 0; k < numPoints; ++k)
				{
					sc0[k] = prng.get<block>();
					sc1[k] = prng.get<block>();

					tag[k] = block::allSame<u8>(-mPartyIdx);

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
				auto& tp = s[(iter - 1) % 3];

				// the parent level
				auto& sc = s[iter % 3];
				//auto& tc = t[iter & 1];

				// the child level
				auto& sg = s[(iter + 1) % 3];

				auto size = 1ull << iter;

				//
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					u8 alphaj = *oc::BitIterator(&points[k], mDepth - iter);
					diff[k] = z[0][k] ^ z[1][k];
					*BitIterator(&diff[k]) = 0;

					negAlphaj[k] = alphaj ^ mPartyIdx;
				}

				co_await mMultiplier.multiply(negAlphaj, diff, diff, sock);
				// sigma = z[1^alpha[j]]
				std::vector<block> buff(mNumPoints + divCeil(mNumPoints, 128));
				auto z1LsbIter = BitIterator(&buff[mNumPoints]);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					u8 alphaj = *oc::BitIterator(&points[k], mDepth - iter);

					// sigmaMult[k] = na * msbs(z0+z1) + z0 + na
					//              =      msbs(z_na) + lsb(z0) + na
					sigmaMult[k] = diff[k] ^ z[0][k] ^ block(0, mPartyIdx ^ alphaj);

					buff[k] = sigmaMult[k];

					// lsb(z1) + a
					*z1LsbIter++ = lsb(z[1][k]) ^ alphaj;
				}
				//sigma[0] = msbs(z[alpha^1]) || 
				//sigma[1] = z[alpha^1] ^ unitVec(alpha, lsb(z[0]) ^ lsb(z[1]) ^ 1)[1]

				// reveal sigma and tau
				co_await sock.send(coproto::copy(buff));
				co_await sock.recv(buff);
				z1LsbIter = BitIterator(&buff[mNumPoints]);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					//std::cout << "sigma[0][k] = " << (sigmaMult[k] ^ diff[k]) << " = " << sigmaMult[k] << " ^ " << diff[k] << std::endl;
					u8 alphaj = *oc::BitIterator(&points[k], mDepth - iter);

					sigma[0][k] = sigmaMult[k] ^ buff[k];
					sigma[1][k] = sigma[0][k];
					*BitIterator(&sigma[1][k]) = *z1LsbIter++ ^ lsb(z[1][k]) ^ alphaj;

				}

				if (1)
				{
					co_await sock.send(coproto::copy(negAlphaj));
					co_await sock.send(coproto::copy(z[0]));
					co_await sock.send(coproto::copy(z[1]));
					BitVector negAlphaj2(mNumPoints);

					std::array<AlignedUnVector<block>, 2> z2;
					z2[0].resize(mNumPoints);
					z2[1].resize(mNumPoints);

					co_await sock.recv(negAlphaj2);
					co_await sock.recv(z2[0]);
					co_await sock.recv(z2[1]);

					auto negA = negAlphaj ^ negAlphaj2;
					for (u64 i = 0; i < mNumPoints; ++i)
					{
						auto na = negA[i];
						auto a = na ^ 1;
						block exp[2], zz[2];
						zz[0] = z[0][i] ^ z2[0][i];
						zz[1] = z[1][i] ^ z2[1][i];

						exp[0] = (zz[na] & ~OneBlock) ^ block(0, lsb(zz[0]) ^ na);
						exp[1] = (zz[na] & ~OneBlock) ^ block(0, lsb(zz[1]) ^ a);
						//std::cout << "a " << int(a) << std::endl;
						//std::cout 
						//	<< "z[0] " << zz[0] << " " << int(lsb(zz[0]))
						//	<< "\nz[1] " << zz[1] << " " << int(lsb(zz[1])) << std::endl;


						//exp[negA[i]] ^= block(0, 1);
						//std::cout << "e[0] " << exp[0] << "\ne[1] " << exp[1] << std::endl;
						//std::cout << "s[0] " << sigma[0][i] << "\ns[1] " << sigma[1][i] << std::endl;

						if (sigma[0][i] != exp[0])
						{
							std::cout << "exp " << exp[0] << " act " << sigma[0][i] << std::endl;
							std::cout << "a " << (1 ^ negA[i]) << std::endl;
							throw RTE_LOC;
						}
						if (sigma[1][i] != exp[1])
						{
							std::cout << "exp " << exp[1] << " act " << sigma[1][i] << std::endl;
							std::cout << "a " << (1 ^ negA[i]) << std::endl;
							throw RTE_LOC;
						}
					}

				}

				if (iter != mDepth)
				{
					//std::cout << std::endl;

					setBytes(z[0], 0);
					setBytes(z[1], 0);

					// we iterate over the parent tags. Each has two children. We expend
					// these two children into 4 grandchildren.
					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 2, L4 += 4)
					{
						// parent control bits
						auto parentTag = getRow(tp, L);

						// child seed
						std::array currentSeed{ getRow(sc, L2 + 0), getRow(sc, L2 + 1) };

						// grandchild seeds
						std::array childSeed{ getRow(sg, L4 + 0), getRow(sg, L4 + 1), getRow(sg, L4 + 2), getRow(sg, L4 + 3) };

						for (u64 k = 0; k < numPoints8; k += 8)
						{
							// for each child
							for (u64 j = 0; j < 2; ++j)
							{
								// update seed with correction
								SIMD8(q, currentSeed[j][k + q] ^= parentTag[k + q] & sigma[j][k + q]);

								// (s0', s1') = H(s)
								mAesFixedKey.ecbEncBlocks<8>(&currentSeed[j][k], &temp[0]);
								SIMD8(q, childSeed[j * 2 + 0][k + q] = AES::roundEnc(temp[q], childSeed[j * 2 + 1][k + q]));
								SIMD8(q, childSeed[j * 2 + 1][k + q] = childSeed[j * 2 + 1][k + q] + temp[q]);

								// z = z ^ s'
								SIMD8(q, z[0][k + q] ^= childSeed[j * 2 + 0][k + q]);
								SIMD8(q, z[1][k + q] ^= childSeed[j * 2 + 1][k + q]);

								// extract the tag from the seed
								SIMD8(q, currentSeed[j][k + q] = tagBit(currentSeed[j][k + q]));
							}

						}

						for (u64 k = numPoints8; k < mNumPoints; ++k)
						{
							for (u64 j = 0; j < 2; ++j)
							{
								//std::cout << "s[" << iter << "][" << L2 + j << "] " << currentSeed[j][k] << " -> ";

								currentSeed[j][k] ^= parentTag[k] & sigma[j][k];

								//std::cout << currentSeed[j][k]<<" " << int(lsb(currentSeed[j][k])) << " via " << (parentTag[k] & sigma[j][k]) << std::endl;

								temp[0] = mAesFixedKey.ecbEncBlock(currentSeed[j][k]);
								childSeed[j * 2 + 0][k] = AES::roundEnc(temp[0], currentSeed[j][k]);
								childSeed[j * 2 + 1][k] = temp[0] + currentSeed[j][k];

								z[0][k] ^= childSeed[j * 2 + 0][k];
								z[1][k] ^= childSeed[j * 2 + 1][k];

								//std::cout << "z1 += " << childSeed[j * 2 + 1][k] << std::endl;

								currentSeed[j][k] = tagBit(currentSeed[j][k]);
							}
						}
					}
				}
			}

			auto size = roundUpTo(mDomain, 2);
			Matrix<block> tags(size, mNumPoints);
			setBytes(diff, 0);

			// fixing the last layer
			{

				auto& tp = s[(mDepth - 1) % 3];
				auto& sc = s[mDepth % 3];
				auto& tc = tags;

				for (u64 L = 0, L2 = 0; L2 < size; ++L, L2 += 2)
				{
					// parent control bits
					auto parentTag = getRow(tp, L);

					// child seed
					std::array currentSeed{ getRow(sc, L2 + 0), getRow(sc, L2 + 1) };

					// child control bit
					std::array tag{ getRow(tc, L2 + 0), getRow(tc, L2 + 1) };

					for (u64 k = 0; k < numPoints8; k += 8)
					{
						for (u64 j = 0; j < 2; ++j)
						{

							SIMD8(q, temp[q] = currentSeed[j][k + q] ^ parentTag[k + q] & sigma[j][k + q]);
							SIMD8(q, tag[j][k + q] = tagBit(temp[q]));

							SIMD8(q, currentSeed[j][k + q] = AES::roundFn(temp[q], temp[q]));
							SIMD8(q, diff[k+q] ^= currentSeed[j][k+q]);

						}
					}

					for (u64 k = numPoints8; k < mNumPoints; ++k)
					{
						for (u64 j = 0; j < 2; ++j)
						{
							//std::cout << "s[" << mDepth << "][" << L2 + j << "] " << currentSeed[j][k] << " -> ";
							temp[0] = currentSeed[j][k] ^ parentTag[k] & sigma[j][k];
							tag[j][k] = tagBit(temp[0]);
							currentSeed[j][k] = AES::roundFn(temp[0], temp[0]);
							diff[k] ^= currentSeed[j][k];

							//std::cout << currentSeed[j][k] << " " << int(lsb(currentSeed[j][k])) << " via " << (parentTag[k] & sigma[j][k]) << std::endl;
						}
					}
				}
			}

			if (values.size())
			{

				AlignedUnVector<block> gamma(mNumPoints);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					diff[k] ^= values[k];
				}
				co_await sock.send(coproto::copy(diff));
				co_await sock.recv(gamma);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					gamma[k] ^= diff[k];
				}

				auto& sd = s[mDepth % 3];
				auto& td = tags; 
				for (u64 i = 0; i < mDomain; ++i)
				{
					auto sdi = getRow(sd, i);
					auto tdi = getRow(td, i);

					for (u64 k = 0; k < numPoints8; k += 8)
					{
						block T[8];
						SIMD8(q, T[q] = tdi[k + q] & gamma[k + q]);
						SIMD8(q, output(k + q, i, sdi[k + q] ^ T[q], tdi[k + q]));
					}
					for (u64 k = numPoints8; k < mNumPoints; ++k)
					{
						auto T = tdi[k] & gamma[k];
						output(k, i, sdi[k] ^ T, tdi[k]);
					}
				}
			}
			else
			{
				auto& sd = s[mDepth & 1];
				auto& td = tags;
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