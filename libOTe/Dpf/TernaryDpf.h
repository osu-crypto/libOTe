#pragma once


#include "libOTe/config.h"
#if defined(ENABLE_TERNARY_DPF) 

#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#include "DpfMult.h"
#include "libOTe/Triple/Foleage/FoleageUtils.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{

	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	struct TernaryDpf
	{
		using VecF = typename CoeffCtx::template Vec<F>;


		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		u64 mDepth = 0;

		u64 mNumPoints = 0;

		u64 mOtIdx = 0;

		AlignedUnVector<std::array<block, 2>> mBaseSendOts;
		AlignedUnVector<block> mBaseRecvOts;
		AlignedUnVector<u8> mBaseChoice;

		void init(
			u64 partyIdx,
			u64 domain,
			u64 numPoints)
		{
			if (partyIdx > 1)
				throw RTE_LOC;
			if (domain == 0)
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

		template<typename Output, typename Fs>
		macoro::task<> expand(
			span<F3x32> points,
			Fs&& values,
			Output&& output,
			PRNG& prng,
			coproto::Socket& sock,
			CoeffCtx ctx = {})
		{
			static_assert(std::is_same_v<F, std::remove_cvref_t<decltype(values[0])>>, "values must be a vector like type of F.");
			static_assert(
				std::is_invocable_v<Output, u64, u64, F, u8> ||
				std::is_invocable_v<Output, u64, u64, F>
				, "output must be a callback/lambda that callable with (u64 treeIdx, u64 leafIdx, F value, u8 tag) or  (u64 treeIdx, u64 leafIdx, F value) ");

			if (points.size() != mNumPoints)
				throw RTE_LOC;
			if (values.size() && values.size() != mNumPoints)
				throw RTE_LOC;

			if (mDomain == 1)
			{
				// trivial case where the domain is 1.
				if (values.size())
				{
					for (u64 i = 0; i < mNumPoints; ++i)
					{
						if constexpr(std::is_invocable_v<Output, u64, u64, F, u8>)
							output(i, 0, values[i], mPartyIdx);
						else
							output(i, 0, values[i]);
					}
				}
				else
				{
					VecF rand;
					ctx.resize(rand, 1);
					for (u64 i = 0; i < mNumPoints; ++i)
					{
						ctx.fromBlock(rand[0], prng.get<block>());
						if constexpr (std::is_invocable_v<Output, u64, u64, F, u8>)
							output(i, 0, rand[0], mPartyIdx);
						else
							output(i, 0, rand[0]);
					}
				}
				co_return;
			}


			for (u64 i = 0; i < mNumPoints; ++i)
			{
				u64 v = points[i].mVal;
				for (u64 j = 0; j < mDepth; ++j)
				{
					if ((v & 3) == 3)
						throw std::runtime_error("TernaryDpf: invalid point sharing. Expects the input points to be shared over Z_3^D where each Z_3 elements takes up 2 bits of a the value. " LOCATION);
					v >>= 2;
				}
				if (v)
					throw std::runtime_error("TernaryDpf: invalid point sharing. point is larger than 3^D " LOCATION);
			}

			u64 numPoints8 = mNumPoints / 8 * 8;
			auto pow3 = ipow(3, mDepth);

			u64 allocSize =
				sizeof(block) * mNumPoints * (pow3 + pow3 / 3 + pow3 / 9)/*seeds*/ +
				sizeof(block) * mNumPoints * 3 * 2/*z, sigma*/; //+
				//sizeof(u8) * mNumPoints * mDomain /*t*/
				;
			AlignedUnVector<u8> allocation(allocSize);
			auto allocIter = allocation.data();

			auto makeMatrix = [&]<typename T>(u64 rows, u64 cols, T) -> MatrixView<T>
				{
					auto ret = MatrixView<T>((T*)allocIter, rows, cols);
					allocIter += sizeof(T) * ret.size();
					if (allocIter > allocation.data() + allocSize)
						throw std::runtime_error("TernaryDpf: allocation error. " LOCATION);
					return ret;
				};

			// shares of S'
			std::array<MatrixView<block>, 3> s;
			auto last = mDepth % 3;
			s[(last + 0) % 3] = makeMatrix(pow3 / 1, mNumPoints, block{}); 
			s[(last + 2) % 3] = makeMatrix(pow3 / 3, mNumPoints, block{}); 
			s[(last + 1) % 3] = makeMatrix(pow3 / 9, mNumPoints, block{}); 

			auto getRow = [](auto&& m, u64 i) {return m[i]; };
			auto z = makeMatrix(3, mNumPoints, block{});
			auto sigma = makeMatrix(3, mNumPoints, block{});


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
				AES(block(324532455457855483ull,3575765667434524523ull)),
				AES(block(456475435444364534ull,9923458239234989843ull)),
				AES(block(324532450985209453ull,5387987243989842789ull)) };

			// at each iteration we first correct the parent level.
			// The parent level has two siblings which are random.
			// We need to correct the inactive child so that both parties
			// hold the same seed (a sharing of zero).
			//
			// we then expand the parent to level to get the children level.
			// We compute left and right sums for the children.
			for (u64 iter = 1; iter <= mDepth; ++iter)
			{

				co_await correctionWord(points, z, sigma, iter, prng, sock);

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
							auto sig = sigma[j].data();
							auto seedj = seed[j].data();

							for (u64 k = 0; k < numPoints8; k += 8)
							{
								block s[8];//, w[8];
								SIMD8(q, s[q] = seedj[k + q] ^ (parentTag[k + q] & sig[k + q]));

								for (u64 i = 0; i < 3; ++i)
								{
									auto child = childSeed[j * 3 + i].data();
									auto zi = z.data(i);

									auto w = &child[k];
									aes[i].hashBlocks<8>(s, w);
									//SIMD8(q, child[k + q] = w[q]);
									SIMD8(q, zi[k + q] ^= w[q]);
								}
		
								// replace the seed with the tag.
								SIMD8(q, seed[j][k+q] = tagBit(s[q]));
							}

							for (u64 k = numPoints8; k < mNumPoints; ++k)
							{
								auto seedjk = seed[j][k] ^ (parentTag[k] & sigma[j][k]);

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

			
			//auto size = ipow(3, mDepth);
			VecF sums, leafVals;
			ctx.resize(sums, mNumPoints);
			ctx.zero(sums.begin(), sums.end());
			ctx.resize(leafVals, mNumPoints * mDomain);
			Matrix<u8> t(mDomain, mNumPoints, AllocType::Uninitialized);
			//auto t = makeMatrix(mDomain, mNumPoints, u8{});

			// fixing the last layer
			{

				auto& parentTags = s[(mDepth - 1) % 3];
				auto& curSeed = s[mDepth % 3];
				auto leafIter = leafVals.data();

				for (u64 L = 0, L2 = 0; L2 < mDomain; ++L, L2 += 3)
				{
					// parent control bits
					auto parentTag = getRow(parentTags, L);
					auto m = std::min<u64>(3, mDomain - L2);


					for (u64 j = 0; j < m; ++j)
					{
						auto cs = curSeed.data(L2 + j);
						auto sig = sigma.data(j);
						auto tt = t.data(L2 + j);

						for (u64 k = 0; k < numPoints8; k+= 8)
						{
							block s[8];

							SIMD8(q, s[q] = cs[k + q] ^ (parentTag[k+q] & sig[k+q]));
							SIMD8(q, tt[k+q] = lsb(s[q]));
							SIMD8(q, ctx.fromBlock(leafIter[q], AES::roundFn(s[q], s[q])));
							SIMD8(q, ctx.plus(sums[k+q], sums[k+q], leafIter[q]));
							leafIter += 8;;
						}

						for (u64 k = numPoints8; k < mNumPoints; ++k)
						{
							auto s = cs[k] ^ (parentTag[k] & sig[k]);
							tt[k] = lsb(s);

							ctx.fromBlock(*leafIter, AES::roundFn(s, s));
							ctx.plus(sums[k], sums[k], *leafIter);
							++leafIter;
						}
					}
				}
			}

			allocation.clear();
			//std::cout << "----------" << std::endl;

			if (values.size())
			{
				VecF gamma, diff;
				ctx.resize(gamma, mNumPoints);
				ctx.resize(diff, mNumPoints);

				//auto& curSeed = s[mDepth % 3];

				for (u64 k = 0; k < mNumPoints; ++k)
				{
					ctx.plus(diff[k], values[k], sums[k]);
				}
				co_await sock.send(std::move(diff));
				co_await sock.recv(gamma);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					ctx.plus(gamma[k], gamma[k], sums[k]);
					ctx.plus(gamma[k], gamma[k], values[k]);
				}

				auto leafIter = leafVals.data();
				VecF temp;
				ctx.resize(temp, 1);
				for (u64 i = 0; i < mDomain; ++i)
				{
					//auto sdi = getRow(sd, i);
					auto tdi = getRow(t, i);

					//for (u64 k = 0; k < mNumPoints8; k += 8)
					//{
					//	block T[8];
					//	SIMD8(q, T[q] = block::allSame<u64>(-tdi[k + q]) & gamma[k + q]);
					//	SIMD8(q, output(k + q, i, sdi[k + q] ^ T[q], tdi[k + q]));
					//}
					for (u64 k = 0; k < mNumPoints; ++k)
					{
						ctx.mask(temp[0], gamma[k], block::allSame<u8>(-tdi[k]));
						ctx.plus(temp[0], temp[0], *leafIter++);
						//auto V = sdi[k] ^ T;
						if constexpr (std::is_invocable_v<Output, u64, u64, F, u8>)
							output(k, i, temp[0], tdi[k]);
						else
							output(k, i, temp[0]);

					}
				}
				if (leafIter != leafVals.data() + leafVals.size())
					throw RTE_LOC;
			}
			else
			{

				auto leafIter = leafVals.data();
				auto tagIter = t.data();
				for (u64 i = 0; i < mDomain; ++i)
				{
					for (u64 k = 0; k < mNumPoints; ++k)
					{
						if constexpr (std::is_invocable_v<Output, u64, u64, F, u8>)
							output(k, i, *leafIter++, *tagIter++);
						else
							output(k, i, *leafIter++);

					}
				}
				if (leafIter != leafVals.data() + leafVals.size())
					throw RTE_LOC;
			}
		}


		macoro::task<> correctionWord(
			span<F3x32> points, 
			MatrixView<block> z, 
			MatrixView<block> sigma, 
			u64 iter, 
			PRNG& prng,
			coproto::Socket& sock)
		{
			Matrix<block> sigmaShares(3, mNumPoints, AllocType::Uninitialized);
			Matrix<block> mask(mNumPoints, 3, AllocType::Uninitialized);
			Matrix<block> recvBuffer(mNumPoints * 2, 3, AllocType::Uninitialized);

			std::array<coproto::Socket, 2> socks;
			socks[0] = sock;
			socks[1] = sock.fork();
			if (mPartyIdx)
				std::swap(socks[0], socks[1]);

			auto expand3 = [](const block& k, span<block> r)  {
				r[0] = k;
				r[1] = k ^ block(3450136502437610243, 6108362938092146510);
				r[2] = k ^ block(3428970074314387014, 2030711220607601239);
				mAesFixedKey.hashBlocks<3>(r.data(), r.data());
				};


			auto sender = [&]() -> macoro::task<> {

				BitVector correction(mNumPoints * 2);
				AlignedUnVector<u8> sendBuffer(mNumPoints * 2 * sizeof(std::array<block, 3>));
				auto sendIter = sendBuffer.data();

				co_await socks[0].recv(correction);
				for (u64 i = 0; i < mNumPoints; ++i)
				{
					auto keys0 = mBaseSendOts[mOtIdx + i * 2 + 0];
					auto keys1 = mBaseSendOts[mOtIdx + i * 2 + 1];
					std::array<block, 3> k;
					for (u64 j = 0; j < 3; ++j)
					{
						auto j0 = j & 1;
						auto j1 = j >> 1;

						auto b0 = j0 ^ correction[i * 2 + 0];
						auto b1 = j1 ^ correction[i * 2 + 1];
						auto k0 = keys0[b0];
						auto k1 = keys1[b1];

						k[j] = k0 ^ k1;
					}

					block r = prng.get<block>();
					*BitIterator(&r) = mPartyIdx;

					auto a = points[i][mDepth - iter];
					expand3(k[0], mask[i]);
					mask(i,a) ^= r;

					for (u64 j = 0; j < 2; ++j)
					{
						std::array<block, 3> kj;
						expand3(k[j + 1], kj);
;
						kj[0] ^= mask(i,0);
						kj[1] ^= mask(i,1);
						kj[2] ^= mask(i,2);
						kj[(j + 1 + a) % 3] ^= r;
						memcpy(sendIter, &kj, sizeof(kj));
						sendIter += sizeof(kj);
					}
				}
				if (sendIter != sendBuffer.data() + sendBuffer.size())
					throw RTE_LOC;

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

				auto k = 
					mBaseRecvOts[mOtIdx + i * 2 + 0] ^ mBaseRecvOts[mOtIdx + i * 2 + 1];
				//std::cout << "p" << mPartyIdx << " ka " << k << " = H( "
				//	<< std::hex << mBaseRecvOts[i * 2 + 0].get<u32>(0) << "  " << int(mBaseChoice[i * 2 + 0]) << " "
				//	<< std::hex << mBaseRecvOts[i * 2 + 1].get<u32>(0) << "  " << int(mBaseChoice[i * 2 + 0]) << " )" << " a1 " << int(a) << std::endl;

				//std::cout << "buffer " << std::endl
				//	<< " " << buffer[i * 3 + a][0] << "\n"
				//	<< " " << buffer[i * 3 + a][1] << "\n"
				//	<< " " << buffer[i * 3 + a][2] << "\n";
				std::array<block, 3> ka;
				expand3(k, ka);

				sigma(0,i) = ka[0] ^ mask(i,0) ^ z(0,i);
				sigma(1,i) = ka[1] ^ mask(i,1) ^ z(1,i);
				sigma(2,i) = ka[2] ^ mask(i,2) ^ z(2,i);
				if (a)
				{
					sigma(0,i) ^= recvBuffer(i * 2 + a - 1,0);
					sigma(1,i) ^= recvBuffer(i * 2 + a - 1,1);
					sigma(2,i) ^= recvBuffer(i * 2 + a - 1,2);
				}

				//std::cout << "sigma " << std::endl
				//	<< " " << sigma[0][i] << " = " << std::hex << ka[0].get<u32>(0) << " + " << std::hex << buffer[i * 3 + a][0].get<u32>(0) << " + " << std::hex << z[0][i].get<u32>(0) << "\n"
				//	<< " " << sigma[1][i] << " = " << std::hex << ka[1].get<u32>(0) << " + " << std::hex << buffer[i * 3 + a][1].get<u32>(0) << " + " << std::hex << z[1][i].get<u32>(0) << "\n"
				//	<< " " << sigma[2][i] << " = " << std::hex << ka[2].get<u32>(0) << " + " << std::hex << buffer[i * 3 + a][2].get<u32>(0) << " + " << std::hex << z[2][i].get<u32>(0) << "\n\n";
			}
			co_await sock.send(Matrix<block>(sigma));

			co_await sock.recv(sigmaShares);

			for (u64 i = 0; i < sigma.size(); ++i)
			{
				sigma(i) ^= sigmaShares(i);//^ mask[i][j];
			}

			mOtIdx += mNumPoints * 2;

			if (0)
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


		// extracts the lsb of b and returns a block saturated with that bit.
		static block tagBit(const block& b)
		{
			auto bit = b & block(0, 1);
			auto mask = block(0,0).sub_epi64(bit);
			return mask.unpacklo_epi64(mask);
		}
	};

}

#undef SIMD8
#endif
