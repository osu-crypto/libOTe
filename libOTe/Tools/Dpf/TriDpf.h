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
			//u64 msbMask, lsbMask;
			//setBytes(msbMask, 0b10101010);
			//setBytes(lsbMask, 0b01010101);

			//auto x0 = mVal;
			//auto x1 = mVal >> 1;
			//auto y0 = t.mVal;
			//auto y1 = t.mVal >> 1;


			//auto x1x0 = x1 ^ x0;
			//auto z1 = (y0 ^ x0) & ~(x1x0 ^ y1);
			//auto z0 = (x1 ^ y1) & ~(x1x0 ^ y0);

			//r.mVal = ((z1 << 1) & msbMask) | (z0 & lsbMask);

			Trit32 r;
			for (u64 i = 0; i < 32; ++i)
			{
				auto a = t[i];
				auto b = (*this)[i];
				auto c = (a + b) % 3;

				r.mVal |= u64(c) << (i * 2);
				//if (c != ((r.mVal >> (i * 2)) & 3))
					//throw RTE_LOC;
			}
			return r;
		}


		Trit32 operator-(const Trit32& t) const
		{
			Trit32 r;
			for (u64 i = 0; i < 32; ++i)
			{
				auto a = t[i];
				auto b = (*this)[i];
				auto c = (b + 3 - a) % 3;

				r.mVal |= u64(c) << (i * 2);
			}
			return r;
		}


		bool operator==(const Trit32& t) const
		{
			return mVal == t.mVal;
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
		u8 operator[](u64 i) const
		{
			return (mVal >> (i * 2)) & 3;
		}
	};

	std::ostream& operator<<(std::ostream& o, const Trit32& t)
	{
		u64 m = 0;
		u64 v = t.mVal;
		while (v)
		{
			++m;
			v >>= 2;
		}
		if (!m)
			o << "0";
		else
		{
			for (u64 i = m - 1; i < m; --i)
			{
				o << int(t[i]);
			}
		}
		return o;
	}

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

		//// returns something similar to b % 3.
		//u8 trit(block b)
		//{
		//	auto v = b.get<u64>(0);
		//	return
		//		static_cast<u8>(v > 6148914691236517205ull) +
		//		static_cast<u8>(v > 12297829382473034410ull);
		//}

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
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
			auto pow3 = ipow(3, mDepth);
			std::array<Matrix<block>, 3> s;
			auto last = mDepth % 3;
			s[last].resize(pow3, numPoints, oc::AllocType::Uninitialized);
			s[(last + 2) % 3].resize(pow3 / 3, numPoints, oc::AllocType::Uninitialized);
			s[(last + 1) % 3].resize(pow3 / 9, numPoints, oc::AllocType::Uninitialized);

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
			//std::array<AlignedUnVector<u8>, 3> tau;
			//tau[0].resize(mNumPoints);
			//tau[1].resize(mNumPoints);
			//tau[2].resize(mNumPoints);
			std::array<AlignedUnVector<block>, 3> z;
			z[0].resize(mNumPoints);
			z[1].resize(mNumPoints);
			z[2].resize(mNumPoints);
			//std::array<AlignedUnVector<u8>, 3> v;
			//v[0].resize(mNumPoints);
			//v[1].resize(mNumPoints);
			//v[2].resize(mNumPoints);
			std::array<AlignedUnVector<block>, 3> sigma;
			sigma[0].resize(mNumPoints);
			sigma[1].resize(mNumPoints);
			sigma[2].resize(mNumPoints);


			{
				// we skip level 0 and set level 1 to be random
				auto t = s[0][0];
				auto sc0 = s[1][0];
				auto sc1 = s[1][1];
				auto sc2 = s[1][2];
				for (u64 k = 0; k < numPoints; ++k)
				{
					t[k] = block::allSame<u8>(-mPartyIdx);
					sc0[k] = prng.get<block>();
					sc1[k] = prng.get<block>();
					sc2[k] = prng.get<block>();

					z[0][k] = sc0[k];
					z[1][k] = sc1[k];
					z[2][k] = sc2[k];

					//std::cout << "seed " << sc0[k] << " " << sc1[k] << " " << sc2[k] << std::endl;
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
				{
					std::vector<u8> alphaj(numPoints);
					std::vector<block> zz(numPoints * 3); auto zzIter = zz.begin();
					for (u64 k = 0; k < numPoints; ++k)
					{
						alphaj[k] = points[k][mDepth - iter];
					}

					for (u64 k = 0; k < 3; ++k)
					{
						copyBytes(span<block>(zzIter, zzIter + numPoints), z[k]); zzIter += numPoints;
					}

					co_await sock.send(coproto::copy(alphaj));
					co_await sock.send(coproto::copy(zz));

					auto recvAlphaj = co_await sock.recv<std::vector<u8>>();
					co_await sock.recv(zz);

					zzIter = zz.begin();
					for (u64 k = 0; k < 3; ++k)
					{
						for (u64 i = 0; i < numPoints; ++i)
						{
							//if (v[k][i] > 2)
							//{
							//	throw RTE_LOC;
							//}
							//std::cout << "sigma = " << z[k][i] << " + " << *zzIter;
							sigma[k][i] = z[k][i] ^ *zzIter++;//^ OneBlock;

							//std::cout << " = " << sigma[k][i] << std::endl;
							//tau[k][i] = lsb(sigma[k][i]) ^ 1;
						}
					}

					for (u64 i = 0; i < numPoints; ++i)
					{
						assert(recvAlphaj[i] < 3);
						auto a = (alphaj[i] + recvAlphaj[i]) % 3;
						//std::cout << "alpha[" << (mDepth - iter) << "] = " << int(a) << " = " << int(alphaj[i]) << " + " << int(recvAlphaj[i]) << std::endl;

						auto r = (oc::mAesFixedKey.ecbEncBlock(block(iter, i)) & ~OneBlock);
						sigma[a][i] ^= r ^ OneBlock;
					}
				}


				//for (u64 k = 0; k < 3; ++k)
				//{
				//	for (u64 i = 0; i < numPoints; ++i)
				//	{
				//		tau[k][i] = lsb(sigma[k][i]);
				//	}
				//}

				//std::cout << "sigma[" << iter << "] " << sigma[0][0] << " " << sigma[1][0] << " " << sigma[2][0] << std::endl;
				//std::cout << "tau[" << iter << "]   " << int(tau[0][0]) << " " << int(tau[1][0]) << " " << int(tau[2][0]) << std::endl;

				// the parent level
				auto& parentBase = s[(iter - 1) % 3];

				// current level
				auto& seedBase = s[iter % 3];
				//auto& tagBase = t[iter % 3];

				// the child level
				auto& childBase = s[(iter + 1) % 3];
				//auto& childTagBase = t[(iter + 1) & 1];

				auto size = ipow(3, iter);

				if (iter != mDepth)
				{
					for (u64 i = 0; i < 3; ++i)
					{
						setBytes(z[i], 0);
						//setBytes(v[i], 0);
					}

					// we iterate over each parent control bit.
					// The parent has 3 "current" children.
					// We will expand these three children into 9 gradchildren
					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 3, L4 += 9)
					{
						// parent control bits, one for each tree.
						auto parentTag = getRow(parentBase, L);
						//auto parentSeed = getRow(seedBase, L);

						// child seed, three for each tree.
						std::array seed{ getRow(seedBase, L2 + 0), getRow(seedBase, L2 + 1) , getRow(seedBase, L2 + 2) };

						// child control bit, tree for each tree.
						//std::array tag{ getRow(tagBase, L2 + 0), getRow(tagBase, L2 + 1), getRow(tagBase, L2 + 2) };

						// grandchild seeds, nine for each tree.
						std::array<decltype(getRow(childBase, L4 + 0)), 9> childSeed;
						for (u64 i = 0; i < 9; ++i)
							childSeed[i] = getRow(childBase, L4 + i);


						for (u64 j = 0; j < 3; ++j)
						{
							for (u64 k = 0; k < mNumPoints; ++k)
							{

								// (s,t) = (s,t) ^ q * sigma_j
								//tag[j][k] = lsb(seed[j][k]) ^ parentTag[k] & tau[j][k];
								//seed[j][k] ^= block::allSame<u64>(-i64(parentTag[k + 0])) & sigma[j][k + 0];
								seed[j][k] ^= parentTag[k] & sigma[j][k];
								//tag[j][k] = lsb(seed[j][k]);
								//std::cout << mPartyIdx << " " << Trit32(L2 + j) << " " << seed[j][k] << " " << int(lsb(seed[j][k])) <<" " << parentTag[k] << std::endl;

								//
								for (u64 i = 0; i < 3; ++i)
								{
									auto s = aes[i].hashBlock(seed[j][k]);
									childSeed[j * 3 + i][k] = s;
									z[i][k] ^= s;
								}

								// replace the seed with the tag.
								seed[j][k] = block::allSame<u8>(-lsb(seed[j][k]));
							}
						}
					}
				}
			}
			AlignedUnVector<block> sums(mNumPoints);
			Matrix<u8> t(ipow(3, mDepth), mNumPoints);
			// fixing the last layer
			{
				auto size = ipow(3, mDepth);

				auto& parentTag = s[(mDepth - 1) % 3];
				auto& curSeed = s[mDepth % 3];
				//auto& curTag = t[mDepth & 1];

				for (u64 L = 0, L2 = 0; L2 < size; ++L, L2 += 3)
				{
					// parent control bits
					auto tpl = getRow(parentTag, L);

					// child seed
					std::array scl{ getRow(curSeed, L2 + 0), getRow(curSeed, L2 + 1), getRow(curSeed, L2 + 2) };

					// child control bit
					//std::array tcl{ getRow(curTag, L2 + 0), getRow(curTag, L2 + 1) , getRow(curTag, L2 + 2) };

					for (u64 j = 0; j < 3; ++j)
					{
						for (u64 k = 0; k < mNumPoints; ++k)
						{
							//curTag[L2 + j][k] = lsb(scl[j][k]) ^ tpl[k] & tau[j][k];
							auto s = curSeed[L2 + j][k] ^ tpl[k] & sigma[j][k];
							t[L2 + j][k] = lsb(s);
							curSeed[L2 + j][k] = /*convert_G*/ AES::roundFn(s, s);
							sums[k] = sums[k] ^ curSeed[L2 + j][k];
							//std::cout << mPartyIdx << " " << Trit32(L2 + j) << " " << curSeed[L2 + j][k] << " " << int(curTag[L2 + j][k]) << std::endl;
						}
					}
				}
			}
			//std::cout << "----------" << std::endl;

			if (values.size())
			{

				AlignedUnVector<block> gamma(mNumPoints), diff(mNumPoints);
				setBytes(diff, 0);
				auto& curSeed = s[mDepth % 3];

				for (u64 k = 0; k < mNumPoints; ++k)
				{
					diff[k] = sums[k] ^ values[k];
				}
				co_await sock.send(std::move(diff));
				co_await sock.recv(gamma);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					gamma[k] = sums[k] ^ values[k] ^ gamma[k];
				}

				auto& sd = s[mDepth % 3];
				//auto& td = t[mDepth & 1];
				for (u64 i = 0; i < mDomain; ++i)
				{
					auto sdi = getRow(sd, i);
					auto tdi = getRow(t, i);

					//for (u64 k = 0; k < numPoints8; k += 8)
					//{
					//	block T[8];
					//	SIMD8(q, T[q] = block::allSame<u64>(-tdi[k + q]) & gamma[k + q]);
					//	SIMD8(q, output(k + q, i, sdi[k + q] ^ T[q], tdi[k + q]));
					//}
					for (u64 k = 0; k < mNumPoints; ++k)
					{
						auto T = block::allSame<u8>(-tdi[k]) & gamma[k];
						auto V = sdi[k] ^ T;
						//std::cout << mPartyIdx << " " << Trit32(i) << " " << sdi[k] << " " << int(tdi[k]) << std::endl;

						output(k, i, V, tdi[k]);
					}
				}
			}
			else
			{
				auto& sd = s[mDepth % 3];
				auto& td = t;// [mDepth & 1] ;
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
			return mDepth * mNumPoints;
			//throw RTE_LOC;
			//return mMultiplier.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			//throw RTE_LOC;
			//mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}


	};

}

#undef SIMD8