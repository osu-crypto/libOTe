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
		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		u64 mDepth = 0;

		u64 mNumPoints = 0;

		u64 mOtIdx = 0;

		std::vector<std::array<block, 2>> mBaseSendOts;
		std::vector<block> mBaseRecvOts;
		std::vector<u8> mBaseChoice;

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
			mOtIdx = 0;
		}

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

			u64 numPoints8 = mNumPoints / 8 * 8;

			// shares of S'
			auto pow3 = ipow(3, mDepth);
			std::array<Matrix<block>, 3> s;
			auto last = mDepth % 3;
			s[last].resize(pow3, mNumPoints, oc::AllocType::Uninitialized);
			s[(last + 2) % 3].resize(pow3 / 3, mNumPoints, oc::AllocType::Uninitialized);
			s[(last + 1) % 3].resize(pow3 / 9, mNumPoints, oc::AllocType::Uninitialized);

#if defined(NDEBUG)
			auto getRow = [](auto&& m, u64 i) {return m.data(i); };
#else
			auto getRow = [](auto&& m, u64 i) {return m[i]; };
#endif
			Matrix<block> z(3, mNumPoints);
			Matrix<block> sigma(3, mNumPoints);


			{
				// we skip level 0 and set level 1 to be random
				auto t = s[0][0];
				auto sc0 = s[1][0];
				auto sc1 = s[1][1];
				auto sc2 = s[1][2];
				for (u64 k = 0; k < mNumPoints; ++k)
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
			// The parent level has two siblings which are random.
			// We need to correct the inactive child so that both parties
			// hold the same seed (a sharing of zero).
			//
			// we then expand the parent to level to get the children level.
			// We compute left and right sums for the children.
			for (u64 iter = 1; iter <= mDepth; ++iter)
			{

				co_await correctionWord(points, z, sigma, iter, sock);

				//std::cout << "sigma[" << iter << "] " << sigma[0][0] << " " << sigma[1][0] << " " << sigma[2][0] << std::endl;
				//std::cout << "tau[" << iter << "]   " << int(tau[0][0]) << " " << int(tau[1][0]) << " " << int(tau[2][0]) << std::endl;

				// the parent level
				auto& parentBase = s[(iter - 1) % 3];

				// current level
				auto& seedBase = s[iter % 3];

				// the child level
				auto& childBase = s[(iter + 1) % 3];

				auto size = ipow(3, iter);

				if (iter != mDepth)
				{
					for (u64 i = 0; i < 3; ++i)
					{
						setBytes(z[i], 0);
					}

					// we iterate over each parent control bit.
					// The parent has 3 "current" children.
					// We will expand these three children into 9 gradchildren
					for (u64 L = 0, L2 = 0, L4 = 0; L2 < size; ++L, L2 += 3, L4 += 9)
					{
						// parent control bits, one for each tree.
						auto parentTag = getRow(parentBase, L);

						// current seed, three for each tree.
						std::array seed{ getRow(seedBase, L2 + 0), getRow(seedBase, L2 + 1) , getRow(seedBase, L2 + 2) };

						// child seeds, nine for each tree.
						std::array<decltype(getRow(childBase, L4 + 0)), 9> childSeed;
						for (u64 i = 0; i < 9; ++i)
							childSeed[i] = getRow(childBase, L4 + i);


						for (u64 j = 0; j < 3; ++j)
						{
							for (u64 k = 0; k < mNumPoints; ++k)
							{
								auto seedjk = seed[j][k] ^ parentTag[k] & sigma[j][k];

								for (u64 i = 0; i < 3; ++i)
								{
									auto s = aes[i].hashBlock(seedjk);
									childSeed[j * 3 + i][k] = s;
									z[i][k] ^= s;
								}

								// replace the seed with the tag.
								seed[j][k] = block::allSame<u8>(-lsb(seedjk));
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

				auto& parentTags = s[(mDepth - 1) % 3];
				auto& curSeed = s[mDepth % 3];

				for (u64 L = 0, L2 = 0; L2 < size; ++L, L2 += 3)
				{
					// parent control bits
					auto parentTag = getRow(parentTags, L);

					// child seed
					std::array scl{ getRow(curSeed, L2 + 0), getRow(curSeed, L2 + 1), getRow(curSeed, L2 + 2) };

					for (u64 j = 0; j < 3; ++j)
					{
						for (u64 k = 0; k < mNumPoints; ++k)
						{
							auto s = curSeed[L2 + j][k] ^ parentTag[k] & sigma[j][k];
							t[L2 + j][k] = lsb(s);
							curSeed[L2 + j][k] = /*convert_G*/ AES::roundFn(s, s);//AES::roundFn is used to get rid of the correlation in the LSB.
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

					//for (u64 k = 0; k < mNumPoints8; k += 8)
					//{
					//	block T[8];
					//	SIMD8(q, T[q] = block::allSame<u64>(-tdi[k + q]) & gamma[k + q]);
					//	SIMD8(q, output(k + q, i, sdi[k + q] ^ T[q], tdi[k + q]));
					//}
					for (u64 k = 0; k < mNumPoints; ++k)
					{
						auto T = block::allSame<u8>(-tdi[k]) & gamma[k];
						auto V = sdi[k] ^ T;
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


		// we are going to create 3 ot message
		//
		// m0, m1, m2
		//
		// such that m_{-a0} = r || 1 for some random r.
		//
		// the receiver will use choice a1. 
		macoro::task<> correctionWord(span<Trit32> points, MatrixView<block> z, MatrixView<block> sigma, u64 iter, coproto::Socket& sock)
		{
			//{
			//	char x = 0;
			//	co_await sock.send(char{ x });
			//	co_await sock.recv(x);
			//}
			//std::cout << "=======" << iter << "======== " << std::endl;

			Matrix<block> sigmaShares(3, mNumPoints);
			AlignedUnVector<std::array<block, 3>> mask(mNumPoints);
			AlignedUnVector<std::array<block, 3>> recvBuffer(mNumPoints * 2);

			std::array<coproto::Socket, 2> socks;
			socks[0] = sock;
			socks[1] = sock.fork();
			if (mPartyIdx)
				std::swap(socks[0], socks[1]);


			auto H = [](const block& a, const block& b) -> block {
				RandomOracle ro(sizeof(block));
				ro.Update(a);
				ro.Update(b);
				block r;
				ro.Final(r);
				return r;
				};

			auto sender = [&]() -> macoro::task<> {
				PRNG prng(block(234134, 21452345 * mPartyIdx));

				BitVector correction(mNumPoints * 2);
				AlignedUnVector<std::array<block, 3>> sendBuffer(mNumPoints * 2);
				co_await socks[0].recv(correction);
				//auto sendIter = mBaseSendOts.begin() + mOtIdx;
				for (u64 i = 0; i < mNumPoints; ++i)
				{
					auto keys0 = mBaseSendOts[mOtIdx + i * 2 + 0];
					auto keys1 = mBaseSendOts[mOtIdx + i * 2 + 1];
					std::array<block, 3> k;// , m;
					//std::cout << "p" << mPartyIdx << std::endl;// "\n " << k[0] << "\n  " << k[1] << "\n  " << k[2] << std::endl;
					for (u64 j = 0; j < 3; ++j)
					{
						auto j0 = j & 1;
						auto j1 = j >> 1;

						auto b0 = j0 ^ correction[i * 2 + 0];
						auto b1 = j1 ^ correction[i * 2 + 1];
						auto k0 = keys0[b0];
						auto k1 = keys1[b1];

						k[j] = H(k0, k1);
						//std::cout << "k" << j << " " << k[j] << " = H( "
						//	<< std::hex << k0.get<u32>(0) << " " << b0 << " "
						//	<< std::hex << k1.get<u32>(0) << " " << b1 << " ) " << std::endl;
					}

					block r = prng.get<block>();
					*BitIterator(&r) = mPartyIdx;

					//std::array<block, 3> mask;// = prng.get();
					//mask[i] = prng.get();
					auto a = points[i][mDepth - iter];
					//std::cout << "a0 " << int(a) << std::endl;

					{

						// sendBuffer[i * 3 + 0] = kj ^ mask ^ unitVec(r, a);
						//                     0 = kj ^ mask ^ unitVec(r, a);
						//                  mask = kj ^ unitVec(r, a);

						mask[i] = PRNG(k[0], 3).get();
						//setBytes(mask[i], 0);
						mask[i][a] ^= r;
					}

					for (u64 j = 0; j < 2; ++j)
					{
						std::array<block,3> kj = PRNG(k[j+1], 3).get();
						//setBytes(kj, 0);

						//sendBuffer[i * 3 + j] = PRNG(k[j], 3).get();
						sendBuffer[i * 2 + j][0] = kj[0] ^ mask[i][0];
						sendBuffer[i * 2 + j][1] = kj[1] ^ mask[i][1];
						sendBuffer[i * 2 + j][2] = kj[2] ^ mask[i][2];
						sendBuffer[i * 2 + j][(j+1 + a) % 3] ^= r;

						//std::cout << "buffer " << j << std::endl
						//	<< " " << buffer[i * 3 + j][0] << "\n"
						//	<< " " << buffer[i * 3 + j][1] << "\n"
						//	<< " " << buffer[i * 3 + j][2] << "\n";
					}
				}

				co_await socks[0].send(std::move(sendBuffer));


				};

			auto recver = [&]() -> macoro::task<> {
				BitVector correction(mNumPoints * 2);
				for (u64 i = 0; i < mNumPoints; ++i)
				{
					auto a = points[i][mDepth - iter];
					correction[i * 2 + 0] = ((a >> 0) & 1) ^ mBaseChoice[mOtIdx + i * 2 + 0];
					correction[i * 2 + 1] = ((a >> 1) & 1) ^ mBaseChoice[mOtIdx + i * 2 + 1];
				}
				co_await socks[1].send(std::move(correction));

				co_await socks[1].recv(recvBuffer);
				};

			co_await macoro::when_all_ready(
				sender(),
				recver()
			);

			for (u64 i = 0; i < mNumPoints; ++i)
			{
				auto a = points[i][mDepth - iter];

				auto k = H(
					mBaseRecvOts[mOtIdx + i * 2 + 0],
					mBaseRecvOts[mOtIdx + i * 2 + 1]);
				//std::cout << "p" << mPartyIdx << " ka " << k << " = H( "
				//	<< std::hex << mBaseRecvOts[i * 2 + 0].get<u32>(0) << "  " << int(mBaseChoice[i * 2 + 0]) << " "
				//	<< std::hex << mBaseRecvOts[i * 2 + 1].get<u32>(0) << "  " << int(mBaseChoice[i * 2 + 0]) << " )" << " a1 " << int(a) << std::endl;

				//std::cout << "buffer " << std::endl
				//	<< " " << buffer[i * 3 + a][0] << "\n"
				//	<< " " << buffer[i * 3 + a][1] << "\n"
				//	<< " " << buffer[i * 3 + a][2] << "\n";
				std::array<block, 3> ka = PRNG(k, 3).get();
				//setBytes(ka, 0);

				sigma[0][i] = ka[0] ^ mask[i][0] ^ z[0][i];
				sigma[1][i] = ka[1] ^ mask[i][1] ^ z[1][i];
				sigma[2][i] = ka[2] ^ mask[i][2] ^ z[2][i];
				if (a)
				{
					sigma[0][i] ^= recvBuffer[i * 2 + a - 1][0];
					sigma[1][i] ^= recvBuffer[i * 2 + a - 1][1];
					sigma[2][i] ^= recvBuffer[i * 2 + a - 1][2];
				}

				//std::cout << "sigma " << std::endl
				//	<< " " << sigma[0][i] << " = " << std::hex << ka[0].get<u32>(0) << " + " << std::hex << buffer[i * 3 + a][0].get<u32>(0) << " + " << std::hex << z[0][i].get<u32>(0) << "\n"
				//	<< " " << sigma[1][i] << " = " << std::hex << ka[1].get<u32>(0) << " + " << std::hex << buffer[i * 3 + a][1].get<u32>(0) << " + " << std::hex << z[1][i].get<u32>(0) << "\n"
				//	<< " " << sigma[2][i] << " = " << std::hex << ka[2].get<u32>(0) << " + " << std::hex << buffer[i * 3 + a][2].get<u32>(0) << " + " << std::hex << z[2][i].get<u32>(0) << "\n\n";
			}
			co_await sock.send(Matrix<block>(sigma));

			co_await sock.recv(sigmaShares);

			for (u64 i = 0; i < mNumPoints; ++i)
			{
				for (u64 j = 0; j < 3; ++j)
				{
					//std::cout << "sigma = " << (sigma[j][i] ^ sigmaShares[j][i]) << " = " << sigma[j][i] << " ^ " << sigmaShares[j][i] << std::endl;
					sigma[j][i] ^= sigmaShares[j][i];//^ mask[i][j];
				}
			}

			mOtIdx += mNumPoints * 2;

			if (1)
			{
				std::vector<u8> alphaj(mNumPoints);
				std::vector<block> zz(mNumPoints * 3); auto zzIter = zz.begin();
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					alphaj[k] = points[k][mDepth - iter];
				}

				for (u64 k = 0; k < 3; ++k)
				{
					copyBytes(span<block>(zzIter, zzIter + mNumPoints), z[k]); zzIter += mNumPoints;
				}

				co_await sock.send(coproto::copy(alphaj));
				co_await sock.send(coproto::copy(zz));

				auto recvAlphaj = co_await sock.recv<std::vector<u8>>();
				co_await sock.recv(zz);

				zzIter = zz.begin();
				Matrix<block> sigma2(3, mNumPoints);
				for (u64 k = 0; k < 3; ++k)
				{
					std::cout << "sigma2 \n";
					for (u64 i = 0; i < mNumPoints; ++i)
					{
						std::cout << " " << (z[k][i] ^ *zzIter) << " = " << std::hex << z[k][i].get<u32>(0) << " ^ " << std::hex << zzIter->get<u32>(0) << std::endl;
						sigma2[k][i] = z[k][i] ^ *zzIter++;
						//sigma2[k][i] = ZeroBlock;
					}
				}

				for (u64 i = 0; i < mNumPoints; ++i)
				{
					assert(recvAlphaj[i] < 3);
					auto a = (alphaj[i] + recvAlphaj[i]) % 3;
					//auto r = (oc::mAesFixedKey.ecbEncBlock(block(iter, i)) | OneBlock);
					//sigma[a][i] ^= r;

					std::cout << sigma[0][i] << (a == 0 ? '<' : ' ') << std::endl;
					std::cout << sigma[1][i] << (a == 1 ? '<' : ' ') << std::endl;
					std::cout << sigma[2][i] << (a == 2 ? '<' : ' ') << std::endl;

					auto a1 = (a + 1) % 3;
					auto a2 = (a + 2) % 3;

					//if ((sigma[a][i].get<u8>(0) & 1) == 0)
					//	throw RTE_LOC;
					if (sigma[a1][i] != sigma2[a1][i])
					{
						std::cout << "sigma[" << a1 << "][" << i << "] " << sigma[a1][i] << " != exp " << sigma2[a1][i] << std::endl;
						throw RTE_LOC;
					}
					if (sigma[a2][i] != sigma2[a2][i])
						throw RTE_LOC;
				}
			}
		}

		u64 baseOtCount() const
		{
			return mDepth * mNumPoints * 2;
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			if (baseSendOts.size() != baseOtCount())
				throw RTE_LOC;
			if (recvBaseOts.size() != baseOtCount())
				throw RTE_LOC;
			if (baseChoices.size() != baseOtCount())
				throw RTE_LOC;

			mBaseSendOts.resize(baseOtCount());
			mBaseRecvOts.resize(mBaseSendOts.size());
			mBaseChoice.resize(mBaseSendOts.size());

			for (u64 i = 0; i < mBaseSendOts.size(); ++i)
			{
				mBaseSendOts[i] = baseSendOts[i];
				mBaseRecvOts[i] = recvBaseOts[i];
				mBaseChoice[i] = baseChoices[i];
			}
		}
	};

}

#undef SIMD8