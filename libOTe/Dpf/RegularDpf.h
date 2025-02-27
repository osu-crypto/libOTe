#pragma once

#include "libOTe/config.h"
#if defined(ENABLE_REGULAR_DPF)


#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#include "DpfMult.h"

namespace osuCrypto
{
	struct RegularDpfKey
	{
		void resize(u64 domain, u64 numTrees)
		{
			auto depth = log2ceil(domain);
			if (depth == 0)
				throw RTE_LOC;

			mCorrectionWords.resize(depth, numTrees);
			mCorrectionBits.resize(depth, numTrees);
		}
		block mSeed;
		Matrix<block> mCorrectionWords;
		Matrix<u8> mCorrectionBits;
		std::vector<block> mLeafVals;

		bool operator==(const RegularDpfKey& o) const
		{
			return
				mSeed == o.mSeed &&
				mCorrectionWords == o.mCorrectionWords &&
				mCorrectionBits == o.mCorrectionBits &&
				mLeafVals == o.mLeafVals;
		}
	};

	inline std::ostream& operator<<(std::ostream& o, const RegularDpfKey& k)
	{
		o << k.mSeed << std::endl;
		for (u64 i = 0; i < k.mCorrectionWords.size(); ++i)
		{
			o << k.mCorrectionWords(i) << " " << int(k.mCorrectionBits(i)) << " ";
		}
		o << std::endl;
		for (u64 i = 0; i < k.mLeafVals.size(); ++i)
			o << k.mLeafVals[i] << " ";
		o << std::endl;

		return o;
	}

	struct RegularDpf
	{
		u64 mPartyIdx = 0;

		u64 mDomain = 0;

		u64 mDepth = 0;

		u64 mNumPoints = 0;

		DpfMult mMultiplier;

		// used to initialize the interactive protocols.
		void init(
			u64 partyIdx,
			u64 domain,
			u64 numPoints);

		// returns the number of OTs required for the protocol.
		// each party must have this many OTs as the sender and 
		// as the receiver.
		u64 baseOtCount() const;

		// set the base OTs.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices);

		// perform interactive full domain eval.
		// - points should be a secret sharing of the locations.
		// - values should be a secret sarhing of the values.
		// - seed should be a random seed.
		// - output should be a lambda of the form [](treeIdx, leadIdx, value, tag){...}
		// this will be called for each leaf value produced. tag is a zero/one secret sharing
		// indicating if this is the active leaf.
		// - sock is the network socket to the other party.
		template<typename Output>
		macoro::task<> expand(
			span<u64> points,
			span<block> values,
			block seed,
			Output&& output,
			coproto::Socket& sock);


		// perform interactive key generation.
		// - points should be a secret sharing of the locations.
		// - values should be a secret sarhing of the values.
		// - seed should be a random seed.
		// - outputKey is where the result is written to.
		// - sock is the network socket to the other party.
		macoro::task<> keyGen(
			span<u64> points,
			span<block> values,
			block seed,
			RegularDpfKey& outputKey,
			coproto::Socket& sock);


		// A static function that can generate a pair of keys. 
		// - domain is the number of leaf values.
		// - points is the plaintext list of locations.
		// - values is the plaintext list of values.
		// - prng is the source of randomness.
		// - keys is a list of two keys where the result is written.
		static void keyGen(
			u64 domain,
			span<u64> points,
			span<block> values,
			PRNG& prng,
			span<RegularDpfKey> keys);

		// A static function that performs non-interative
		// full domain evaluation. 
		// - partyIdx is this partie's index, 0 or 1.
		// - domain is the number of leaf values.
		// - key is the share of the FSS key.
		// - output should be a lambda of the form [](treeIdx, leadIdx, value, tag){...}
		// this will be called for each leaf value produced. tag is a zero/one secret sharing
		// indicating if this is the active leaf.
		template<typename Output>
		static void expand(
			u64 partyIdx,
			u64 domain,
			RegularDpfKey& key,
			Output&& output);


		// the internal implementation. This function can be called with 
		// different parameters. 
		//
		// For distributed keygen, points, values should be shared and seed is some 
		// random see. inputKey == nullptr, output = anything, and outputKey
		// should point to valid object.
		//
		// For interactive expand (without an existing key), the parameters are the same
		// except that outputKey should be null and output should be a lambda of the form
		// [](treeIdx, leadIdx, value, tag){...}
		// 
		// For non-interactive expand (with an existing key), points, values, seed are 
		// all ignored. inputKey should point to an existing dpf key. sock is ignored.
		// output should be a lambda as above.
		//
		template<typename Output>
		macoro::task<> implExpand(
			span<u64> points,
			span<block> values,
			block seed,
			RegularDpfKey* inputKey,
			Output&& output,
			coproto::Socket& sock,
			RegularDpfKey* outputKey);


		static u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		// extracts the lsb of b and returns a block saturated with that bit.
		static block tagBit(const block& b)
		{
			auto bit = b & block(0, 1);
			auto mask = block(0,0).sub_epi64(bit);
			return mask.unpacklo_epi64(mask);
		}
	};



	inline void RegularDpf::init(
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


	template<typename Output >
	macoro::task<> RegularDpf::expand(
		span<u64> points,
		span<block> values,
		block seed,
		Output&& output,
		coproto::Socket& sock)
	{
		return implExpand(points, values, seed, nullptr, output, sock, nullptr);
	}



	// distributed keygen, points, values should be shared and seed is some 
	// random see. inputKey == nullptr, output = anything, and outputKey
	// should point to valid object. Base OTs must be set.
	inline macoro::task<> RegularDpf::keyGen(
		span<u64> points,
		span<block> values,
		block seed,
		RegularDpfKey& outputKey,
		coproto::Socket& sock)
	{
		return implExpand(points, values, seed, nullptr, [](auto, auto, auto, auto) {}, sock, &outputKey);
	}

	// the internal implementation. This function can be called with 
	// different parameters. 
	//
	// For distributed keygen, points, values should be shared and seed is some 
	// random see. inputKey == nullptr, output = anything, and outputKey
	// should point to valid object.
	//
	// For interactive expand (without an existing key), the parameters are the same
	// except that outputKey should be null and output should be a lambda of the form
	// [](treeIdx, leadIdx, value, tag){...}
	// 
	// For non-interactive expand (with an existing key), points, values, seed are 
	// all ignored. inputKey should point to an existing dpf key. sock is ignored.
	// output should be a lambda as above.
	//
	template<typename Output>
	macoro::task<> RegularDpf::implExpand(
		span<u64> points,
		span<block> values,
		block seed,
		RegularDpfKey* inputKey,
		Output&& output,
		coproto::Socket& sock,
		RegularDpfKey* outputKey)
	{

		if (inputKey == nullptr)
		{
			if (points.size() != mNumPoints)
				throw RTE_LOC;
			if (values.size() && values.size() != mNumPoints)
				throw RTE_LOC;
		}
		else
		{
			if (outputKey)
				throw RTE_LOC;
		}

		u64 numPoints = mNumPoints;
		u64 numPoints8 = numPoints / 8 * 8;


		// shares of S'
		auto pow2 = 1ull << log2ceil(mDomain);
		std::array<Matrix<block>, 3> s;
		s[mDepth % 3].resize(pow2, numPoints, oc::AllocType::Uninitialized);
		s[(mDepth + 2) % 3].resize(pow2 / 2, numPoints, oc::AllocType::Uninitialized);
		s[(mDepth + 1) % 3].resize(pow2 / 4, numPoints, oc::AllocType::Uninitialized);

#if defined(NDEBUG)
		auto getRow = [](auto&& m, u64 i) {return m.data(i); };
#else
		auto getRow = [](auto&& m, u64 i) {return m[i]; };
#endif

		if (outputKey)
		{
			outputKey->resize(mDomain, numPoints);
		}

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
			if (inputKey)
				seed = inputKey->mSeed;

			// we skip level 0 and set level 1 to be random
			if (outputKey)
				outputKey->mSeed = seed;

			auto sc0 = s[1][0];
			auto sc1 = s[1][1];
			auto tag = s[0][0];
			PRNG basePeng(seed);
			for (u64 k = 0; k < numPoints; ++k)
			{
				sc0[k] = basePeng.get<block>();
				sc1[k] = basePeng.get<block>();
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

			if (inputKey)
			{
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					sigma[0][k] = inputKey->mCorrectionWords(iter - 1, k);
					sigma[1][k] = sigma[0][k];
					*BitIterator(&sigma[1][k]) = inputKey->mCorrectionBits(iter - 1, k);
				}

			}
			else
			{
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
					sigmaMult[k] = diff[k] ^ z[0][k] ^ block(0, mPartyIdx ^ alphaj);
					buff[k] = sigmaMult[k];
					*z1LsbIter++ = lsb(z[1][k]) ^ alphaj;
				}

				// reveal sigma and tau
				co_await sock.send(coproto::copy(buff));
				co_await sock.recv(buff);
				z1LsbIter = BitIterator(&buff[mNumPoints]);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					u8 alphaj = *oc::BitIterator(&points[k], mDepth - iter);
					auto sigma1Bit = *z1LsbIter++ ^ lsb(z[1][k]) ^ alphaj;
					sigma[0][k] = buff[k] ^ sigmaMult[k];
					sigma[1][k] = sigma[0][k];
					*BitIterator(&sigma[1][k]) = sigma1Bit;
					if (outputKey)
					{
						outputKey->mCorrectionWords(iter - 1, k) = sigma[0][k];
						outputKey->mCorrectionBits(iter - 1, k) = sigma1Bit;
					}
				}
			}

			if (0)
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

			if (iter != mDepth)
			{
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
							SIMD8(q, childSeed[j * 2 + 0][k + q] = AES::roundEnc(temp[q], currentSeed[j][k + q]));
							SIMD8(q, childSeed[j * 2 + 1][k + q] = temp[q].add_epi64(currentSeed[j][k + q]));

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
							currentSeed[j][k] ^= parentTag[k] & sigma[j][k];

							temp[0] = mAesFixedKey.ecbEncBlock(currentSeed[j][k]);
							childSeed[j * 2 + 0][k] = AES::roundEnc(temp[0], currentSeed[j][k]);
							childSeed[j * 2 + 1][k] = temp[0].add_epi64(currentSeed[j][k]);

							z[0][k] ^= childSeed[j * 2 + 0][k];
							z[1][k] ^= childSeed[j * 2 + 1][k];

							currentSeed[j][k] = tagBit(currentSeed[j][k]);
						}
					}
				}
			}
		}

		if (!values.size() && outputKey)
			co_return;

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
						SIMD8(q, temp[q] = currentSeed[j][k + q] ^ (parentTag[k + q] & sigma[j][k + q]));
						SIMD8(q, tag[j][k + q] = tagBit(temp[q]));
						SIMD8(q, currentSeed[j][k + q] = AES::roundEnc(temp[q], temp[q]));
						SIMD8(q, diff[k + q] ^= currentSeed[j][k + q]);
					}
				}

				for (u64 k = numPoints8; k < mNumPoints; ++k)
				{
					for (u64 j = 0; j < 2; ++j)
					{
						temp[0] = currentSeed[j][k] ^ (parentTag[k] & sigma[j][k]);
						tag[j][k] = tagBit(temp[0]);


						auto rr  = AES::roundEnc(temp[0], temp[0]);
						diff[k] ^= rr;
						currentSeed[j][k] = rr;
					}
				}
			}
		}

		if (values.size() || (inputKey && inputKey->mLeafVals.size()))
		{
			AlignedUnVector<block> gamma(mNumPoints);
			if (inputKey)
			{
				std::copy(inputKey->mLeafVals.begin(), inputKey->mLeafVals.end(), gamma.begin());
			}
			else
			{
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
			}

			if (outputKey)
			{
				outputKey->mLeafVals.insert(outputKey->mLeafVals.end(), gamma.begin(), gamma.end());
			}
			else
			{
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
		}
		else
		{
			auto& sd = s[mDepth % 3];
			auto& td = tags;
			for (u64 i = 0; i < mDomain; ++i)
			{
				auto sdi = getRow(sd, i);
				auto tdi = getRow(td, i);
				for (u64 k = 0; k < mNumPoints; ++k)
				{
					output(k, i, sdi[k], tdi[k]);
				}
			}
		}
	}


	inline u64 RegularDpf::baseOtCount() const {
		return mMultiplier.baseOtCount();
	}

	inline void RegularDpf::setBaseOts(
		span<const std::array<block, 2>> baseSendOts,
		span<const block> recvBaseOts,
		const oc::BitVector& baseChoices)
	{
		mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
	}


	inline void RegularDpf::keyGen(
		u64 domain,
		span<u64> points,
		span<block> values,
		PRNG& prng,
		span<RegularDpfKey> keys)
	{
		if (keys.size() != 2)
			throw RTE_LOC;
		if (values.size() != points.size() && values.size() != 0)
			throw RTE_LOC;

		auto depth = log2ceil(domain);
		keys[0].resize(domain, values.size());
		keys[1].resize(domain, values.size());

		auto seed0 = prng.get<block>();
		auto seed1 = prng.get<block>();
		std::array<PRNG, 2> prngs{ seed0, seed1 };
		keys[0].mSeed = prngs[0].getSeed();
		keys[1].mSeed = prngs[1].getSeed();
		for (u64 i = 0; i < values.size(); ++i)
		{
			std::array<block, 2> parentTags;
			std::array<std::array<block, 2>, 2> seeds;

			for (u64 p = 0; p < 2; ++p)
			{
				prngs[p].get(seeds[p].data(), seeds[p].size());
				parentTags[p] = block::allSame(-p);
			}

			for (u64 iter = 1; iter <= depth; ++iter)
			{
				auto a = *BitIterator(&points[i], depth - iter);
				auto na = a ^ 1;

				auto diff = seeds[0][na] ^ seeds[1][na];
				u8 tau[2];
				tau[0] = lsb(seeds[0][0] ^ seeds[1][0]) ^ na;
				tau[1] = lsb(seeds[0][1] ^ seeds[1][1]) ^ a;

				// we want   diff || lsbs[0] ^ na || lsbs[1] ^ a
				*BitIterator(&diff) = tau[0];

				block sigma[2];
				sigma[0] = diff;
				sigma[1] = diff;
				*BitIterator(&sigma[1]) = tau[1];

				for (u64 p = 0; p < 2; ++p)
				{
					keys[p].mCorrectionWords(iter - 1, i) = diff;
					keys[p].mCorrectionBits(iter - 1, i) = tau[1];

					seeds[p][0] ^= sigma[0] & parentTags[p];
					seeds[p][1] ^= sigma[1] & parentTags[p];
					parentTags[p] = tagBit(seeds[p][a]);
				}

				if (seeds[0][na] != seeds[1][na])
					throw RTE_LOC;
				if (lsb(seeds[0][a] ^ seeds[1][a]) != 1)
					throw RTE_LOC;
				if ((parentTags[0] ^ parentTags[1]) != AllOneBlock)
					throw RTE_LOC;

				for (u64 p = 0; p < 2; ++p)
				{
					if (iter != depth)
					{
						auto seed = seeds[p][a];
						auto temp = mAesFixedKey.ecbEncBlock(seed);
						seeds[p][0] = AES::roundEnc(temp, seed);
						seeds[p][1] = temp.add_epi64(seed);
					}
				}
			}

			if (values.size())
			{
				auto a = *BitIterator(&points[i], 0);
				auto na = a ^ 1;

				if (seeds[0][na] != seeds[1][na])
					throw RTE_LOC;

				for (u64 p = 0; p < 2; ++p)
				{
					seeds[p][a] = AES::roundEnc(seeds[p][a], seeds[p][a]);
				}

				auto diff = seeds[0][a] ^ seeds[1][a];
				auto gamma = diff ^ values[i];
				keys[0].mLeafVals.push_back(gamma);
				keys[1].mLeafVals.push_back(gamma);
			}
		}
	}

	template<typename Output>
	void RegularDpf::expand(
		u64 partyIdx,
		u64 domain,
		RegularDpfKey& key,
		Output&& output)
	{
		RegularDpf d;
		d.init(partyIdx, domain, key.mCorrectionBits.cols());
		coproto::Socket sock;
		return macoro::sync_wait(d.implExpand({}, {}, {}, &key, output, sock, nullptr));
	}

}

#undef SIMD8

#endif