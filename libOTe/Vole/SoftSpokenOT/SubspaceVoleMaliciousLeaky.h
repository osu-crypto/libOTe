#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include "SubspaceVole.h"

namespace osuCrypto
{

	class SubspaceVoleMaliciousBase
	{
	public:

		// Modulus from "Table of Low-Weight Binary Irreducible Polynomials". Equivalently, this is a^64
		// in GF(2^64), where a is the generator of GF(2^64).
		static constexpr u64 gf64mod = (1 << 4) | (1 << 3) | (1 << 1) | 1;

		// Also from that table.
		static constexpr u64 gfMods[] =
		{
			1,
			3,
			(1ul << 2) | (1ul << 1) | 1ul,
			(1ul << 3) | (1ul << 1) | 1ul,
			(1ul << 4) | (1ul << 1) | 1ul,
			(1ul << 5) | (1ul << 2) | 1ul,
			(1ul << 6) | (1ul << 1) | 1ul,
			(1ul << 7) | (1ul << 1) | 1ul,
			(1ul << 8) | (1ul << 4) | (1ul << 3) | (1ul << 1) | 1ul,
			(1ul << 9) | (1ul << 1) | 1ul,
			(1ul << 10) | (1ul << 3) | 1ul,
			(1ul << 11) | (1ul << 2) | 1ul,
			(1ul << 12) | (1ul << 3) | 1ul,
			(1ul << 13) | (1ul << 4) | (1ul << 3) | (1ul << 1) | 1ul,
			(1ul << 14) | (1ul << 5) | 1ul,
			(1ul << 15) | (1ul << 1) | 1ul,
			(1ul << 16) | (1ul << 5) | (1ul << 3) | (1ul << 1) | 1ul,
			(1ul << 17) | (1ul << 3) | 1ul,
			(1ul << 18) | (1ul << 3) | 1ul,
			(1ul << 19) | (1ul << 5) | (1ul << 2) | (1ul << 1) | 1ul,
			(1ul << 20) | (1ul << 3) | 1ul,
			(1ul << 21) | (1ul << 2) | 1ul,
			(1ul << 22) | (1ul << 1) | 1ul,
			(1ul << 23) | (1ul << 5) | 1ul,
			(1ul << 24) | (1ul << 4) | (1ul << 3) | (1ul << 1) | 1ul,
			(1ul << 25) | (1ul << 3) | 1ul,
			(1ul << 26) | (1ul << 4) | (1ul << 3) | (1ul << 1) | 1ul,
			(1ul << 27) | (1ul << 5) | (1ul << 2) | (1ul << 1) | 1ul,
			(1ul << 28) | (1ul << 1) | 1ul,
			(1ul << 29) | (1ul << 2) | 1ul,
			(1ul << 30) | (1ul << 1) | 1ul,
			(1ul << 31) | (1ul << 3) | 1ul,
		};

		// PRNG that universal hash keys are generated from.
		PRNG hashKeyPrng;

		// Low half is x^2 in GF(2^64) and high half is x^2 * a^64, where a is the generator of GF(2^64)
		// over GF(2), and x is the universal hash key.
		block hashKeySqAndA64 = ZeroBlock;

		// Universal hash key.
		u64 hashKey = 0;

		// Maximum number of times a hash key can be used before being replaced.
		static constexpr u64 maxHashKeyUsage = 1024 * 1024;
		u64 hashKeyUseCount = ~0ull;


		SubspaceVoleMaliciousBase() = default;
		SubspaceVoleMaliciousBase(SubspaceVoleMaliciousBase&& o)
			: hashKeyPrng(std::move(o.hashKeyPrng))
			, hashKeySqAndA64(std::exchange(o.hashKeySqAndA64, ZeroBlock))
			, hashKey(std::exchange(o.hashKey, 0))
			, hashKeyUseCount(std::exchange(o.hashKeyUseCount, ~0ull))
		{}

		SubspaceVoleMaliciousBase& operator=(SubspaceVoleMaliciousBase&& o)
		{
			if (this != &o)
			{
				hashKeyPrng = std::move(o.hashKeyPrng);
				hashKeySqAndA64 = std::exchange(o.hashKeySqAndA64, ZeroBlock);
				hashKey = std::exchange(o.hashKey, 0);
				hashKeyUseCount = std::exchange(o.hashKeyUseCount, ~0ull);
			}
			return *this;
		}

		bool hasChallenge() const
		{
			return hashKeyUseCount != ~0ull;
		}

		void requireChallenge() const
		{
			if (!hasChallenge())
				throw std::logic_error("Malicious subspace VOLE challenge is not initialized. " LOCATION);
		}

		void clearChallenge()
		{
			hashKeyPrng = PRNG{};
			hashKeySqAndA64 = ZeroBlock;
			hashKey = 0;
			hashKeyUseCount = ~0ull;
		}

		// inHalf == 0 => input in low 64 bits. High 64 bits of output should be ignored.
		template <int inHalf>
		static block mulA64(block in)
		{
			block mod = toBlock(gf64mod);
			block mul = in.clmulepi64_si128<inHalf != 0>(mod);

			// Output can include 4 bits in the high half. Multiply again (producing an 8 bit result) to
			// reduce these into the low 64 bits.
			block reduced = mul.clmulepi64_si128<0x01>(mod);
			return mul ^ reduced;
		}

		// Reduce a polynomial modulo the GF(2^64) modulus. High 64 bits of output should be ignored.
		static block reduce(block in)
		{
			block highReduce = mulA64<1>(in);
			return highReduce ^ in;
		}

		static u64 reduceU64(block in)
		{
			return reduce(in).get<u64>()[0];
			//return _mm_extract_epi64(reduce(in), 0);
		}

		void setupHash()
		{
			hashKey = hashKeyPrng.get<u64>();
			hashKeyUseCount = 0;

			block hashKeyBlock = toBlock(hashKey);
			// Might be possible to make this more efficient since it is the Frobenious automorphism.
			block hashKeySq = reduce(hashKeyBlock.clmulepi64_si128<0x00>(hashKeyBlock));
			block hashKeySqA64 = mulA64<0>(hashKeySq);
			//hashKeySqAndA64 = _mm_unpacklo_epi64(hashKeySq, hashKeySqA64);
			hashKeySqAndA64 = hashKeySq.unpacklo_epi64(hashKeySqA64);
		}

		bool rekeyCheck()
		{
			if (++hashKeyUseCount < maxHashKeyUsage)
				return false;
			setupHash();
			return true;
		}

		void addSubtotalAfterRekey(block* hashes, block* subtotals, u64 count)
		{
			for (u64 i = 0; i < count; ++i)
			{
				subtotals[i] ^= hashes[i];
				hashes[i] = block::allSame(0);
			}
		}

		OC_FORCEINLINE void mulHash(block& hash) const
		{
			block hashMul0 = hash.clmulepi64_si128<0x00>(hashKeySqAndA64);
			block hashMul1 = hash.clmulepi64_si128<0x11>(hashKeySqAndA64);
			hash = hashMul0 ^ hashMul1;
		}

		OC_FORCEINLINE void updateHash(block& hash, block in) const
		{
			assert(hashKeyUseCount != ~0ull && "setupHash() must be called first");

			block inMul = in.clmulepi64_si128<0x00>(toBlock(hashKey));
			block inHigh = in.srli_si128<8>();
			hash ^= inMul ^ inHigh;
			mulHash(hash);
		}

		static u64 finalHashRows(u64 fieldBits)
		{
			return divCeil(40, fieldBits);
		}

		// The final hash is a random matrix in GF(2^mFieldBits), with finalHashRows() rows and 64
		// columns. Each row is stored in mFieldBits non-consecutive u64s, with the 1 component of all
		// rows followed by the a component of all rows, etc.
		void getFinalHashKey(u64* finalHashKey, u64 fieldBits)
		{
			hashKeyPrng.get(finalHashKey, finalHashRows(fieldBits) * fieldBits);
		}

		// Apply the final hash to a 64 bit vector. Output is a sequence of packed 64 bit integers, with
		// all bits in the 1 component in the first integer, etc.
		static OC_FORCEINLINE void getFinalHashSubfield(
			const u64* finalHashKey, u64 x, u64* finalHash, u64 fieldBits)
		{
			for (u64 i = 0; i < fieldBits; ++i)
			{
				u64 output = 0;
				for (u64 j = 0; j < finalHashRows(fieldBits); ++j, ++finalHashKey)
					output |= (u64)(popcount(*finalHashKey & x) & 1) << j;
				finalHash[i] = output;
			}
		}

		// For when x is a 64 dimensional vector over GF(2^mFieldBits). Again, output is packed.
		static OC_FORCEINLINE void getFinalHash(
			const u64* finalHashKey, const u64* x, u64* finalHash, u64 fieldBits)
		{
			memset(finalHash, 0, fieldBits * sizeof(u64));

			u64 mod = gfMods[fieldBits];
			int rows = finalHashRows(fieldBits);
			for (int i = 0; i < rows; ++i)
			{
				u64 outputRowNoPopcnt[2 * SmallFieldVoleBase::fieldBitsMax - 1] = { 0 };

				// Don't bother with fast multiplication for now.
				for (int j = 0; j < (int)fieldBits; ++j)
					for (int k = 0; k < (int)fieldBits; ++k)
						outputRowNoPopcnt[j + k] ^= finalHashKey[j * rows + i] & x[k];

				u64 outputRow = 0;
				for (int j = 2 * fieldBits - 2; j >= std::max((int)fieldBits - 1, 0); --j)
					outputRow = outputRow << 1 | (popcount(outputRowNoPopcnt[j]) & 1ul);
				for (int j = (int)fieldBits - 2; j >= 0; --j)
				{
					outputRow = outputRow << 1 | (popcount(outputRowNoPopcnt[j]) & 1ul);

					// Apply modular reduction to put it in GF(2^mFieldBits)
					outputRow ^= -((outputRow >> fieldBits) & 1ul) & mod;
				}

				// Transpose bits to fit into output.
				for (int j = 0; j < (int)fieldBits; ++j)
					finalHash[j] |= ((outputRow >> j) & 1ul) << i;
			}
		}
	};

	// Adds a leaky (through selective abort attack) consistency check for the SubspaceVole protocol.
	// From Sec. 4 of SoftSpokenOT.

	template<typename Code>
	class SubspaceVoleMaliciousSender : public SubspaceVoleSender<Code>, public SubspaceVoleMaliciousBase
	{
	public:

		static constexpr bool mMalicious = true;

		AlignedUnVector<block> hashU;
		AlignedUnVector<block> subtotalU;
		AlignedUnVector<block> hashV;
		AlignedUnVector<block> subtotalV;

		using Base = SubspaceVoleMaliciousBase;
		using Sender = SubspaceVoleSender<Code>;
		using Sender::code;
		using Sender::hasSeed;


		SubspaceVoleMaliciousSender() = default;

		SubspaceVoleMaliciousSender(SubspaceVoleMaliciousSender&& o)
			: Sender(std::move(o))
			, Base(std::move(o))
			, hashU(std::move(o.hashU))
			, subtotalU(std::move(o.subtotalU))
			, hashV(std::move(o.hashV))
			, subtotalV(std::move(o.subtotalV))
		{
			o.hashU.clear();
			o.subtotalU.clear();
			o.hashV.clear();
			o.subtotalV.clear();
		}

		SubspaceVoleMaliciousSender& operator=(SubspaceVoleMaliciousSender&& o)
		{
			if (this != &o)
			{
				Sender::operator=(std::move(o));
				Base::operator=(std::move(o));
				hashU = std::move(o.hashU);
				subtotalU = std::move(o.subtotalU);
				hashV = std::move(o.hashV);
				subtotalV = std::move(o.subtotalV);
				o.hashU.clear();
				o.subtotalU.clear();
				o.hashV.clear();
				o.subtotalV.clear();
			}
			return *this;
		}

		void init(u64 fieldBits, u64 numVoles)
		{
			SmallFieldVoleBase::baseOtCount(fieldBits, numVoles);
			Code code(divCeil(gOtExtBaseOtCount, fieldBits));
			if (numVoles != code.length())
				throw RTE_LOC;

			SmallFieldVoleSender vole;
			vole.init(fieldBits, numVoles, true);
			AlignedUnVector<block> nextHashU(code.dimension());
			AlignedUnVector<block> nextSubtotalU(code.dimension());
			const auto paddedV = roundUpTo(vole.vPadded(), 4);
			AlignedUnVector<block> nextHashV(paddedV);
			AlignedUnVector<block> nextSubtotalV(paddedV);

			this->mCode = std::move(code);
			Sender::mVole = std::move(vole);
			hashU = std::move(nextHashU);
			subtotalU = std::move(nextSubtotalU);
			hashV = std::move(nextHashV);
			subtotalV = std::move(nextSubtotalV);
			
			clearHashes();
		}

		SubspaceVoleMaliciousSender copy() const
		{
			SubspaceVoleMaliciousSender r;
			(Sender&)r = Sender::copy();
			r.hashU.resize(hashU.size());
			r.subtotalU.resize(subtotalU.size());
			r.hashV.resize(hashV.size());
			r.subtotalV.resize(subtotalV.size());
			r.clearHashes();
			return r;
		}


		u64 vPadded() const { return roundUpTo(Sender::vPadded(), 4); }

		void requireHashState() const
		{
			if (!Sender::mVole.mInit ||
				(u64)hashU.size() != code().dimension() ||
				(u64)subtotalU.size() != code().dimension() ||
				(u64)hashV.size() != vPadded() ||
				(u64)subtotalV.size() != vPadded())
				throw std::logic_error("Malicious subspace VOLE sender hash state is not initialized. " LOCATION);
		}

		void generateRandom(u64 blockIdx, const AES& aes, span<block> randomU, span<block> outV)
		{
			if ((u64)randomU.size() != code().dimension() ||
				(u64)outV.size() != vPadded())
				throw RTE_LOC;
			if (!hasSeed())
				throw std::logic_error("Malicious subspace VOLE sender is not ready to generate. " LOCATION);
			Sender::generateRandom(blockIdx, aes, randomU, outV.subspan(0, Sender::vPadded()));
		}

		void generateChosen(u64 blockIdx, const AES& aes, span<const block> chosenU, span<block> outV)
		{
			if ((u64)chosenU.size() != code().dimension() ||
				(u64)outV.size() != vPadded())
				throw RTE_LOC;
			if (!hasSeed())
				throw std::logic_error("Malicious subspace VOLE sender is not ready to generate. " LOCATION);
			Sender::generateChosen(blockIdx, aes, chosenU, outV.subspan(0, Sender::vPadded()));
		}



		void setChallenge(block seed)
		{
			hashKeyPrng.SetSeed(seed);
			setupHash();
		}

		void hash(span<const block> u, span<const block> v)
		{
			requireChallenge();
			requireHashState();
			if ((u64)u.size() != code().dimension() ||
				(u64)v.size() != vPadded())
				throw RTE_LOC;
			for (u64 i = 0; i < code().dimension(); ++i)
				updateHash(hashU[i], u[i]);
			for (u64 i = 0; i < Sender::vSize(); i += 4)
				// Unrolled for ILP.
				for (u64 j = 0; j < 4; ++j)
					updateHash(hashV[i + j], v[i + j]);
			if (rekeyCheck())
				addSubtotalAfterRekey();
		}

		using SubspaceVoleMaliciousBase::addSubtotalAfterRekey;

		void addSubtotalAfterRekey()
		{
			addSubtotalAfterRekey(hashU.data(), subtotalU.data(), code().dimension());
			addSubtotalAfterRekey(hashV.data(), subtotalV.data(), Sender::vSize());
		}

		void clearHashes()
		{
			std::fill(hashU.begin(), hashU.end(), ZeroBlock);
			std::fill(subtotalU.begin(), subtotalU.end(), ZeroBlock);
			std::fill(hashV.begin(), hashV.end(), ZeroBlock);
			std::fill(subtotalV.begin(), subtotalV.end(), ZeroBlock);
		}

		[[nodiscard]]
		task<> sendResponse(Socket& chl)
		{
			MACORO_TRY{
			requireChallenge();
			requireHashState();
			u64 fieldBits = Sender::mVole.mFieldBits;
			u64 numVoles = Sender::mVole.mNumVoles;

			u64 finalHashKey[64]; // Non-tight upper bound on size.
			getFinalHashKey(finalHashKey, fieldBits);

			addSubtotalAfterRekey();

			u64 rows = finalHashRows(fieldBits);
			u64 bytesPerHash = divCeil(rows * fieldBits, 8);
			u64 dim = code().dimension();
			u64 numHashes = dim + numVoles;
			std::vector<u64> finalHashes(fieldBits * numHashes);
			for (u64 i = 0; i < dim; ++i)
				getFinalHashSubfield(
					finalHashKey, reduceU64(subtotalU[i]), &finalHashes[i * fieldBits], fieldBits);

			for (u64 i = 0; i < numVoles; ++i)
			{
				u64 reducedHashes[SmallFieldVoleBase::fieldBitsMax];
				for (u64 j = 0; j < fieldBits; ++j)
					reducedHashes[j] = reduceU64(subtotalV[i * fieldBits + j]);

				getFinalHash(
					finalHashKey, reducedHashes,
					&finalHashes[(dim + i) * fieldBits], fieldBits);
			}

			clearHashes();

			std::vector<u8> finalHashesPacked(bytesPerHash * numHashes);
			for (u64 i = 0; i < numHashes; ++i)
			{
				u64 output = 0;
				for (u64 j = 0; j < fieldBits; ++j)
					output |= finalHashes[i * fieldBits + j] << j * rows;
				memcpy(&finalHashesPacked[bytesPerHash * i], &output, bytesPerHash);
			}

			co_await(chl.send(finalHashesPacked));
			} MACORO_CATCH(eptr) {
				Sender::mVole.clearSeed();
				clearChallenge();
				clearHashes();
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}
	};

	template<typename Code>
	class SubspaceVoleMaliciousReceiver : public SubspaceVoleReceiver<Code>, public SubspaceVoleMaliciousBase
	{
	public:
		static constexpr bool mMalicious = true;

		AlignedUnVector<block> mHashW;
		AlignedUnVector<block> mSubtotalW;

		using Base = SubspaceVoleMaliciousBase;
		using Receiver = SubspaceVoleReceiver<Code>;
		using Receiver::code;
		using Receiver::hasSeed;
		

		SubspaceVoleMaliciousReceiver() = default;
		SubspaceVoleMaliciousReceiver(SubspaceVoleMaliciousReceiver&& o)
			: Receiver(std::move(o))
			, Base(std::move(o))
			, mHashW(std::move(o.mHashW))
			, mSubtotalW(std::move(o.mSubtotalW))
		{
			o.mHashW.clear();
			o.mSubtotalW.clear();
		}

		SubspaceVoleMaliciousReceiver& operator=(SubspaceVoleMaliciousReceiver&& o)
		{
			if (this != &o)
			{
				Receiver::operator=(std::move(o));
				Base::operator=(std::move(o));
				mHashW = std::move(o.mHashW);
				mSubtotalW = std::move(o.mSubtotalW);
				o.mHashW.clear();
				o.mSubtotalW.clear();
			}
			return *this;
		}


		SubspaceVoleMaliciousReceiver copy() const
		{
			SubspaceVoleMaliciousReceiver r;
			r.mHashW.resize(mHashW.size());
			r.mSubtotalW.resize(mSubtotalW.size());
			(Receiver&)r = Receiver::copy();
			r.clearHashes();
			return r;
		}


		void init(u64 fieldBits_, u64 numVoles_)
		{
			SmallFieldVoleBase::baseOtCount(fieldBits_, numVoles_);
			Code code(divCeil(gOtExtBaseOtCount, fieldBits_));
			if (numVoles_ != code.length())
				throw RTE_LOC;

			SmallFieldVoleReceiver vole;
			vole.init(fieldBits_, numVoles_, true);
			AlignedUnVector<block> correctionU(vole.uPadded());
			const auto paddedW = roundUpTo(vole.wPadded(), 4);
			AlignedUnVector<block> nextHashW(paddedW);
			AlignedUnVector<block> nextSubtotalW(paddedW);

			this->mCode = std::move(code);
			Receiver::mVole = std::move(vole);
			Receiver::mCorrectionU = std::move(correctionU);
			mHashW = std::move(nextHashW);
			mSubtotalW = std::move(nextSubtotalW);
			clearHashes();
		}

		task<> expand(Socket& chl, PRNG& prng, u64 numThreads)
		{
			return Receiver::mVole.expand(chl, prng, numThreads, true);
		}

		bool hasDeferredConsistencyFailure() const
		{
			return Receiver::mVole.mConsistencyFailed;
		}

		u64 wPadded() const { return roundUpTo(Receiver::wPadded(), 4); }

		void requireHashState() const
		{
			if (!Receiver::mVole.mInit ||
				(u64)mHashW.size() != wPadded() ||
				(u64)mSubtotalW.size() != wPadded())
				throw std::logic_error("Malicious subspace VOLE receiver hash state is not initialized. " LOCATION);
		}

		void generateRandom(u64 blockIdx, const AES& aes, span<block> outW)
		{
			if ((u64)outW.size() != wPadded())
				throw RTE_LOC;
			if (!hasSeed())
				throw std::logic_error("Malicious subspace VOLE receiver is not ready to generate. " LOCATION);
			Receiver::generateRandom(blockIdx, aes, outW.subspan(0, Receiver::wPadded()));
		}

		void generateChosen(u64 blockIdx, const AES& aes, span<block> outW)
		{
			if ((u64)outW.size() != wPadded())
				throw RTE_LOC;
			if (!hasSeed())
				throw std::logic_error("Malicious subspace VOLE receiver is not ready to generate. " LOCATION);
			Receiver::generateChosen(blockIdx, aes, outW.subspan(0, Receiver::wPadded()));
		}

		[[nodiscard]]
		auto sendChallenge(PRNG& prng, Socket& chl)
		{
			block seed = prng.get<block>();
			hashKeyPrng.SetSeed(seed);
			setupHash();
			return chl.send(std::move(seed));
		}

		void hash(span<const block> w)
		{
			requireChallenge();
			requireHashState();
			if ((u64)w.size() != wPadded())
				throw RTE_LOC;
			for (u64 i = 0; i < Receiver::wSize(); i += 4)
				// Unrolled for ILP.
				for (u64 j = 0; j < 4; ++j)
					updateHash(mHashW[i + j], w[i + j]);

			if (rekeyCheck())
				addSubtotalAfterRekey();
		}

		using SubspaceVoleMaliciousBase::addSubtotalAfterRekey;

		void addSubtotalAfterRekey()
		{
			addSubtotalAfterRekey(mHashW.data(), mSubtotalW.data(), Receiver::wSize());
		}

		void clearHashes()
		{
			std::fill(mHashW.begin(), mHashW.end(), ZeroBlock);
			std::fill(mSubtotalW.begin(), mSubtotalW.end(), ZeroBlock);
		}

		task<> checkResponse(Socket& chl)
		{
			MACORO_TRY{
			requireChallenge();
			requireHashState();
			auto fieldBits = u64{};
			auto numVoles = u64{};
			auto rows = u64{};
			auto bytesPerHash = u64{};
			auto dim = u64{};
			auto numSenderHashes = u64{};
			auto senderBytes = u64{};
			auto finalHashW = AlignedUnVector<u64>{};
			auto senderFinalHashesPackedU8 = AlignedUnVector<u8>{};
			auto senderFinalUHashesPacked = AlignedUnVector<u64>{};
			auto senderFinalHashesPacked = AlignedUnVector<u64>{};
			auto senderFinalHashes = AlignedUnVector<u64>{};
			auto finalHashKey = std::array<u64, 64>{};

			fieldBits = Receiver::mVole.mFieldBits;
			numVoles = Receiver::mVole.mNumVoles;

			getFinalHashKey(finalHashKey.data(), fieldBits);

			addSubtotalAfterRekey();
			finalHashW.resize(roundUpTo(numVoles, 4) * fieldBits);
			for (u64 i = 0; i < numVoles; ++i)
			{
				u64 reducedHashes[SmallFieldVoleBase::fieldBitsMax];
				for (u64 j = 0; j < fieldBits; ++j)
					reducedHashes[j] = reduceU64(mSubtotalW[i * fieldBits + j]);

				getFinalHash(finalHashKey.data(), reducedHashes, &finalHashW[i * fieldBits], fieldBits);
			}

			clearHashes();

			rows = finalHashRows(fieldBits);
			bytesPerHash = divCeil(rows * fieldBits, 8);
			dim = code().dimension();
			numSenderHashes = dim + numVoles;
			senderBytes = bytesPerHash * numSenderHashes;
			senderFinalHashesPackedU8.resize(senderBytes);
			senderFinalUHashesPacked.resize(dim);
			senderFinalHashesPacked.resize(2 * numVoles);
			senderFinalHashes.resize(2 * numVoles * fieldBits);

			co_await (chl.recv(senderFinalHashesPackedU8));

			for (u64 i = 0; i < dim; ++i)
			{
				u64 hash = 0;
				memcpy(&hash, &senderFinalHashesPackedU8[bytesPerHash * i], bytesPerHash);
				senderFinalUHashesPacked[i] = hash;
			}

			for (u64 i = 0; i < numVoles; ++i)
			{
				u64 hash = 0;
				memcpy(&hash, &senderFinalHashesPackedU8[bytesPerHash * (dim + i)], bytesPerHash);
				senderFinalHashesPacked[numVoles + i] = hash;
			}

			// Encode the packed U values, as code expects only one input per field element.
			code().encode(&senderFinalUHashesPacked[0], &senderFinalHashesPacked[0]);

			// Unpack both U's and V's hashes.
			for (u64 i = 0; i < 2 * numVoles; ++i)
			{
				u64 hash = senderFinalHashesPacked[i];
				u64 mask = ((u64)1 << rows) - 1;
				for (u64 j = 0; j < fieldBits; ++j)
					senderFinalHashes[i * fieldBits + j] = (hash >> j * rows) & mask;
			}

			{

				const u64* finalHashU = &senderFinalHashes[0];
				const u64* finalHashV = &senderFinalHashes[numVoles * fieldBits];

				Receiver::mVole.sharedFunctionXorGF(finalHashU, finalHashW.data(), gfMods[fieldBits]);
				const bool consistent = std::equal(
					finalHashW.data(), finalHashW.data() + numVoles * fieldBits, finalHashV);
				if (!consistent || Receiver::mVole.mConsistencyFailed)
					throw std::runtime_error("Failed subspace VOLE consistency check");
			}
			} MACORO_CATCH(eptr) {
				Receiver::mVole.clearSeed();
				clearChallenge();
				clearHashes();
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}
	};


}
#endif
