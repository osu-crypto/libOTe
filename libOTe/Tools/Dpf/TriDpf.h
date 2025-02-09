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
	// a value representing (Z_3)^32.
	// The value is stored in 2 bits per Z_3 element.
	struct Trit32
	{
		u64 mVal = 0;

		Trit32() = default;
		Trit32(const Trit32&) = default;

		Trit32(u64 v)
		{
			fromInt(v);
		}

		Trit32& operator=(const Trit32&) = default;

		Trit32 operator+(const Trit32& t) const
		{
			u64 msbMask, lsbMask;
			setBytes(msbMask, 0b10101010);
			setBytes(lsbMask, 0b01010101);

			auto x0 = mVal;
			auto x1 = mVal >> 1;
			auto y0 = t.mVal;
			auto y1 = t.mVal >> 1;


			auto x1x0 = x1 ^ x0;
			auto z1 = (y0 ^ x0) & ~(x1x0 ^ y1);
			auto z0 = (x1 ^ y1) & ~(x1x0 ^ y0);

			Trit32 r;
			r.mVal = ((z1 << 1) & msbMask) | (z0 & lsbMask);

			for (u64 i = 0; i < 32; ++i)
			{
				auto a = (mVal >> (i * 2)) & 3;
				auto b = (mVal >> (i * 2)) & 3;
				auto c = (a + b) % 3;
				if (c != ((r.mVal >> (i * 2)) & 3))
					throw RTE_LOC;
			}
			return r;
		}

		u64 toInt() const
		{
			u64 r = 0;
			for (u64 i = 31; i < 32; --i)
			{
				r *= 3;
				r |= (mVal >> (i * 2)) & 3;
			}

			return r;
		}

		void fromInt(u64 v)
		{
			mVal = 0;
			for (u64 i = 0; i < 32; ++i)
			{
				mVal |= (v % 3) << (i * 2);
				v /= 3;
			}
		}


		// returns the i'th Z_3 element.
		u8 operator[](u64 i)
		{
			return (mVal >> (i*2)) & 3;
		}
	};

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

		// returns something similar to b % 3.
		u8 trit(block b)
		{
			auto v = b.get<u64>(0);
			return
				static_cast<u8>(v > 6148914691236517205ull) +
				static_cast<u8>(v > 12297829382473034410ull);
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
			span<Trit32> points,
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
				u64 v = points[i].mVal;
				for (u64 j = 0; j < mDepth; ++j)
				{
					if ((v & 3) == 3)
						throw std::runtime_error("TriDpf: invalid point sharing. Expects the input points to be shared over Z_3^D where each Z_3 elements takes up 2 bits of a the value. " LOCATION);
					v >>= 2;
				}
				if (v)
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
			std::array<AlignedUnVector<u8>, 3> tau;
			tau[0].resize(mNumPoints);
			tau[1].resize(mNumPoints);
			tau[2].resize(mNumPoints);
			std::array<AlignedUnVector<block>, 3> z;
			z[0].resize(mNumPoints);
			z[1].resize(mNumPoints);
			z[2].resize(mNumPoints);
			std::array<AlignedUnVector<u8>, 3> v;
			v[0].resize(mNumPoints);
			v[1].resize(mNumPoints);
			v[2].resize(mNumPoints);
			std::array<AlignedUnVector<block>, 3> sigma;
			sigma[0].resize(mNumPoints);
			sigma[1].resize(mNumPoints);
			sigma[2].resize(mNumPoints);


			{
				// we skip level 0 and set level 1 to be random
				auto sc0 = s[1][0];
				auto sc1 = s[1][1];
				auto sc2 = s[1][2];
				for (u64 k = 0; k < numPoints; ++k)
				{
					sc0[k] = prng.get<block>();
					sc1[k] = prng.get<block>();
					sc2[k] = prng.get<block>();

					z[0][k] = sc0[k];
					z[1][k] = sc1[k];
					z[2][k] = sc2[k];
				}
			}

			std::array<AES, 3> aes{
				AES(block(324532455457855483,3575765667434524523)),
				AES(block(456475435444364534,9923458239234989843)),
				AES(block(324532450985209453,5387987243989842789)) };

			// at each iteration we first correct the parent level.
			// The parent level has two syblings which are random.
			// We need to correct the inactive child so that both parties
			// hold the same seed (a sharing of zero).
			//
			// we then expand the parent to level to get the children level.
			// We compute left and right sums for the children.
			for (u64 iter = 1; iter <= mDepth; ++iter)
			{
				// the parent level
				auto& parentSeedBase = t[(iter - 1) & 1];

				// current level
				auto& seedBase = s[iter & 1];
				auto& tagBase = t[iter & 1];

				// the child level
				auto& childSeedBase = s[(iter + 1) & 1];
				//auto& childTagBase = t[(iter + 1) & 1];

				auto size = ipow(3, iter);

				{
					std::vector<u8> alphaj(numPoints);
					std::vector<block> zz(numPoints * 3); auto zzIter = zz.begin();
					std::vector<u8> vv(numPoints * 3); auto vvIter = vv.begin();
					for (u64 k = 0; k < numPoints; ++k)
					{
						alphaj[k] = points[k][mDepth - iter];
					}

					for (u64 k = 0; k < 3; ++k)
					{
						copyBytes(span<block>(zzIter, zzIter + numPoints), z[k]); zzIter += numPoints;
						copyBytes(span<u8>(vvIter, vvIter + numPoints), v[k]); vvIter += numPoints;
					}

					co_await sock.send(coproto::copy(alphaj));
					co_await sock.send(coproto::copy(zz));
					co_await sock.send(coproto::copy(vv));

					auto recvAlphaj = co_await sock.recv<std::vector<u8>>();
					co_await sock.recv(zz);
					co_await sock.recv(vv);

					zzIter = zz.begin();
					vvIter = vv.begin();
					for (u64 k = 0; k < 3; ++k)
					{
						for (u64 i = 0; i < numPoints; ++i)
						{
							sigma[k][i] = z[k][i] ^ *zzIter++;
							tau[k][i] = v[k][i] ^ *vvIter++ ^ 1;
							assert(v[k][i] < 2);
						}
					}

					for (u64 i = 0; i < numPoints; ++i)
					{
						assert(recvAlphaj[i] < 3);
						alphaj[i] = (alphaj[i] + recvAlphaj[i]) % 3;

						sigma[alphaj[i]][i] ^= oc::mAesFixedKey.ecbEncBlock(block(iter, i));
						tau[alphaj[i]][i] ^= 1;
					}
				}

				if (iter != mDepth)
				{
					for (u64 i = 0; i < 3; ++i)
					{
						setBytes(z[i], 0);
						setBytes(v[i], 0);
					}

					// we iterate over each parent control bit.
					// The parent has 3 "current" children.
					// We will expand these three children into 9 gradchildren
					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 3, L4 += 9)
					{
						// parent control bits, one for each tree.
						auto parentTag = getRow(parentSeedBase, L);

						// child seed, three for each tree.
						std::array seed{ getRow(seedBase, L2 + 0), getRow(seedBase, L2 + 1) , getRow(seedBase, L2 + 2) };

						// child control bit, tree for each tree.
						std::array tag{ getRow(tagBase, L2 + 0), getRow(tagBase, L2 + 1), getRow(tagBase, L2 + 2) };

						// grandchild seeds, nine for each tree.
						std::array<decltype(getRow(childSeedBase, L4 + 0)), 9> childSeed;
						for (u64 i = 0; i < 9; ++i)
							childSeed[i] = getRow(childSeedBase, L4 + i);

						//for (u64 k = 0; k < numPoints8; k += 8)
						//{
						//	block temp[8];
						//	SIMD8(q, temp[q] = block::allSame<u64>(-parentTag[k + q]) & sigma[k + q]);
						//	SIMD8(q, tag[0][k + q] = lsb(seed[0][k + q]) ^ parentTag[k + q] & tau[0][k + q]);
						//	SIMD8(q, seed[0][k + q] ^= temp[q]);


						//	mAesFixedKey.ecbEncBlocks<8>(&seed[0][k], &childSeed[1][k]);
						//	SIMD8(q, childSeed[0][k + q] = AES::roundEnc(childSeed[1][k + q], seed[0][k + q]));
						//	SIMD8(q, childSeed[1][k + q] = childSeed[1][k + q] + seed[0][k + q]);

						//	SIMD8(q, z[0][k + q] ^= childSeed[0][k + q]);
						//	SIMD8(q, z[1][k + q] ^= childSeed[1][k + q]);

						//	SIMD8(q, tag[1][k + q] = lsb(seed[1][k + q]) ^ parentTag[k + q] & tau[1][k + q]);
						//	SIMD8(q, seed[1][k + q] ^= temp[q]);

						//	mAesFixedKey.ecbEncBlocks<8>(&seed[1][k], &childSeed[3][k]);
						//	SIMD8(q, childSeed[2][k + q] = AES::roundEnc(childSeed[3][k + q], seed[1][k + q]));
						//	SIMD8(q, childSeed[3][k + q] = childSeed[3][k + q] + seed[1][k + q]);
						//	SIMD8(q, z[0][k + q] ^= childSeed[2][k + q]);
						//	SIMD8(q, z[1][k + q] ^= childSeed[3][k + q]);
						//}
						//auto& sigmaL = sigma[L % 3];

						for (u64 k = 0; k < mNumPoints; ++k)
						{
							for (u64 j = 0; j < 3; ++j)
							{
								// (s,t) = (s,t) ^ q * sigma_j
								tag[j][k] = trit(seed[j][k]) ^ parentTag[k] & tau[j][k];
								seed[j][k] ^= block::allSame<u64>(-parentTag[k + 0]) & sigma[j][k + 0];

								//
								for (u64 i = 0; i < 3; ++i)
								{
									auto s = aes[i].hashBlock(seed[j][k]);
									childSeed[j * 3 + i][k] = s;
									z[i][k] ^= s;
								}
							}

							//tag[1][k] = lsb(seed[1][k]) ^ parentTag[k] & tau[1][k];
							//seed[1][k] ^= temp;

							//childSeed[3][k] = mAesFixedKey.ecbEncBlock(seed[1][k]);
							//childSeed[2][k] = AES::roundEnc(childSeed[3][k], seed[1][k]);
							//childSeed[3][k] = childSeed[3][k] + seed[1][k];

							//z[0][k] ^= childSeed[2][k];
							//z[1][k] ^= childSeed[3][k];
						}
					}
				}
			}


			// fixing the last layer
			{
				auto size = ipow(3, mDepth);

				auto& parentTag = t[(mDepth - 1) & 1];
				auto& curSeed = s[mDepth & 1];
				auto& curTag = t[mDepth & 1];
				for (u64 L = 0, L2 = 0; L2 < size; ++L, L2 += 3)
				{
					// parent control bits
					auto tpl = getRow(parentTag, L);

					// child seed
					std::array scl{ getRow(curSeed, L2 + 0), getRow(curSeed, L2 + 1) };

					// child control bit
					std::array tcl{ getRow(curTag, L2 + 0), getRow(curTag, L2 + 1) };

					//for (u64 k = 0; k < numPoints8; k += 8)
					//{
					//	block temp[8];
					//	SIMD8(q, temp[q] = block::allSame<u64>(-parentTag[k + q]) & sigma[k + q]);
					//	SIMD8(q, tag[0][k + q] = lsb(seed[0][k + q]) ^ parentTag[k + q] & tau[0][k + q]);
					//	SIMD8(q, tag[1][k + q] = lsb(seed[1][k + q]) ^ parentTag[k + q] & tau[1][k + q]);
					//	SIMD8(q, seed[0][k + q] ^= temp[q]);
					//	SIMD8(q, seed[1][k + q] ^= temp[q]);
					//}

					for (u64 k = 0; k < mNumPoints; ++k)
					{
						for (u64 j = 0; j < 3; ++j)
						{
							curTag[L2 + j][k] = trit(scl[j][k]) ^ tpl[k] & tau[j][k];
							curSeed[L2 + j][k] ^= block::allSame<u64>(-tpl[k]) & sigma[j][k];;
						}


						//curTag[L2 + 0][k] = lsb(scl[0][k]) ^ tpl[k] & tau[0][k];
						//curTag[L2 + 1][k] = lsb(scl[1][k]) ^ tpl[k] & tau[1][k];
						//curSeed[L2 + 0][k] ^= block::allSame<u64>(-tpl[k + 0]) & sigma[k % 3][k + 0];;
						//curSeed[L2 + 1][k] ^= temp;
					}
				}
			}

			if (values.size())
			{

				AlignedUnVector<block> gamma(mNumPoints), diff(mNumPoints);
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

					//for (u64 k = 0; k < numPoints8; k += 8)
					//{
					//	block T[8];
					//	SIMD8(q, T[q] = block::allSame<u64>(-tdi[k + q]) & gamma[k + q]);
					//	SIMD8(q, output(k + q, i, sdi[k + q] ^ T[q], tdi[k + q]));
					//}
					for (u64 k = 0; k < mNumPoints; ++k)
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
			throw RTE_LOC;
			//return mMultiplier.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			throw RTE_LOC;
			//mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}


	};

}

#undef SIMD8