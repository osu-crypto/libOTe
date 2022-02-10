#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include "SubspaceVole.h"

namespace osuCrypto
{
namespace SoftSpokenOT
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
	block hashKeySqAndA64;

	// Universal hash key.
	u64 hashKey;

	// Maximum number of times a hash key can be used before being replaced.
	static constexpr size_t maxHashKeyUsage = 1024 * 1024;
	size_t hashKeyUseCount = 0;

	// inHalf == 0 => input in low 64 bits. High 64 bits of output should be ignored.
	template <int inHalf>
	static block mulA64(block in)
	{
		block mod = toBlock(gf64mod);
		block mul = _mm_clmulepi64_si128(in, mod, inHalf != 0);

		// Output can include 4 bits in the high half. Multiply again (producing an 8 bit result) to
		// reduce these into the low 64 bits.
		block reduced = _mm_clmulepi64_si128(mul, mod, 0x01);
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
		return _mm_extract_epi64(reduce(in), 0);
	}

	void setupHash()
	{
		hashKey = hashKeyPrng.get<u64>();
		hashKeyUseCount = 0;

		block hashKeyBlock = toBlock(hashKey);
		// Might be possible to make this more efficient since it is the Frobenious automorphism.
		block hashKeySq = reduce(_mm_clmulepi64_si128(hashKeyBlock, hashKeyBlock, 0x00));
		block hashKeySqA64 = mulA64<0>(hashKeySq);
		hashKeySqAndA64 = _mm_unpacklo_epi64(hashKeySq, hashKeySqA64);
	}

	bool rekeyCheck()
	{
		if (++hashKeyUseCount < maxHashKeyUsage)
			return false;
		setupHash();
		return true;
	}

	void addSubtotalAfterRekey(block* hashes, block* subtotals, size_t count)
	{
		for (size_t i = 0; i < count; ++i)
		{
			subtotals[i] ^= hashes[i];
			hashes[i] = block::allSame(0);
		}
	}

	TRY_FORCEINLINE void mulHash(block& hash) const
	{
		block hashMul0 = _mm_clmulepi64_si128(hash, hashKeySqAndA64, 0x00);
		block hashMul1 = _mm_clmulepi64_si128(hash, hashKeySqAndA64, 0x11);
		hash = hashMul0 ^ hashMul1;
	}

	TRY_FORCEINLINE void updateHash(block& hash, block in) const
	{
		block inMul = _mm_clmulepi64_si128(in, toBlock(hashKey), 0x00);
		block inHigh = _mm_srli_si128(in, 8);
		hash ^= inMul ^ inHigh;
		mulHash(hash);
	}

	static size_t finalHashRows(size_t fieldBits)
	{
		return divCeil(40, fieldBits);
	}

	// The final hash is a random matrix in GF(2^fieldBits), with finalHashRows() rows and 64
	// columns. Each row is stored in fieldBits non-consecutive u64s, with the 1 component of all
	// rows followed by the a component of all rows, etc.
	void getFinalHashKey(u64* finalHashKey, size_t fieldBits)
	{
		hashKeyPrng.get(finalHashKey, finalHashRows(fieldBits) * fieldBits);
	}

	// Apply the final hash to a 64 bit vector. Output is a sequence of packed 64 bit integers, with
	// all bits in the 1 component in the first integer, etc.
	static TRY_FORCEINLINE void getFinalHashSubfield(
		const u64* finalHashKey, u64 x, u64* finalHash, size_t fieldBits)
	{
		for (size_t i = 0; i < fieldBits; ++i)
		{
			u64 output = 0;
			for (size_t j = 0; j < finalHashRows(fieldBits); ++j, ++finalHashKey)
				output |= (u64) (popcount(*finalHashKey & x) & 1) << j;
			finalHash[i] = output;
		}
	}

	// For when x is a 64 dimensional vector over GF(2^fieldBits). Again, output is packed.
	static TRY_FORCEINLINE void getFinalHash(
		const u64* finalHashKey, const u64* x, u64* finalHash, size_t fieldBits)
	{
		memset(finalHash, 0, fieldBits * sizeof(u64));

		u64 mod = gfMods[fieldBits];
		int rows = finalHashRows(fieldBits);
		for (int i = 0; i < rows; ++i)
		{
			u64 outputRowNoPopcnt[2 * SmallFieldVoleBase::fieldBitsMax - 1] = {0};

			// Don't bother with fast multiplication for now.
			for (int j = 0; j < (int) fieldBits; ++j)
				for (int k = 0; k < (int) fieldBits; ++k)
					outputRowNoPopcnt[j + k] ^= finalHashKey[j * rows + i] & x[k];

			u64 outputRow = 0;
			for (int j = 2 * fieldBits - 2; j >= std::max((int) fieldBits - 1, 0); --j)
				outputRow = outputRow << 1 | (popcount(outputRowNoPopcnt[j]) & 1ul);
			for (int j = (int) fieldBits - 2; j >= 0; --j)
			{
				outputRow = outputRow << 1 | (popcount(outputRowNoPopcnt[j]) & 1ul);

				// Apply modular reduction to put it in GF(2^fieldBits)
				outputRow ^= -((outputRow >> fieldBits) & 1ul) & mod;
			}

			// Transpose bits to fit into output.
			for (int j = 0; j < (int) fieldBits; ++j)
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
	std::unique_ptr<block[]> hashU;
	std::unique_ptr<block[]> subtotalU;
	std::unique_ptr<block[]> hashV;
	std::unique_ptr<block[]> subtotalV;

	using Sender = SubspaceVoleSender<Code>;
	using Sender::code;

	SubspaceVoleMaliciousSender(SmallFieldVoleSender vole_, Code code_) :
		Sender(std::move(vole_), std::move(code_)),
		hashU(new block[Sender::uSize()]),
		subtotalU(new block[Sender::uSize()]),
		hashV(new block[vPadded()]),
		subtotalV(new block[vPadded()])
	{
		clearHashes();
	}

	size_t vPadded() const { return roundUpTo(Sender::vPadded(), 4); }

	void generateRandom(size_t blockIdx, const AES& aes, span<block> randomU, span<block> outV)
	{
		Sender::generateRandom(blockIdx, aes, randomU, outV.subspan(0, Sender::vPadded()));
	}

	void generateChosen(size_t blockIdx, const AES& aes, span<const block> chosenU, span<block> outV)
	{
		Sender::generateChosen(blockIdx, aes, chosenU, outV.subspan(0, Sender::vPadded()));
	}

	void recvChallenge(Channel& chl)
	{
		block seed;
		chl.recv(&seed, 1);
		hashKeyPrng.SetSeed(seed);
		setupHash();
	}

	void hash(span<const block> u, span<const block> v)
	{
		for (size_t i = 0; i < code().dimension(); ++i)
			updateHash(hashU[i], u[i]);
		for (size_t i = 0; i < Sender::vSize(); i += 4)
			// Unrolled for ILP.
			for (size_t j = 0; j < 4; ++j)
				updateHash(hashV[i + j], v[i + j]);

		if (rekeyCheck())
			addSubtotalAfterRekey();
	}

	using SubspaceVoleMaliciousBase::addSubtotalAfterRekey;

	void addSubtotalAfterRekey()
	{
		addSubtotalAfterRekey(hashU.get(), subtotalU.get(), code().dimension());
		addSubtotalAfterRekey(hashV.get(), subtotalV.get(), Sender::vSize());
	}

	void clearHashes()
	{
		std::fill_n(hashU.get(), Sender::uSize(), block::allSame(0));
		std::fill_n(subtotalU.get(), Sender::uSize(), block::allSame(0));
		std::fill_n(hashV.get(), vPadded(), block::allSame(0));
		std::fill_n(subtotalV.get(), vPadded(), block::allSame(0));
	}

	void sendResponse(Channel& chl)
	{
		size_t fieldBits = Sender::vole.fieldBits;
		size_t numVoles = Sender::vole.numVoles;

		u64 finalHashKey[64]; // Non-tight upper bound on size.
		getFinalHashKey(finalHashKey, fieldBits);

		addSubtotalAfterRekey();

		size_t rows = finalHashRows(fieldBits);
		size_t bytesPerHash = divCeil(rows * fieldBits, 8);
		size_t dim = code().dimension();
		size_t numHashes = dim + numVoles;
		std::vector<u64> finalHashes(fieldBits * numHashes);
		for (size_t i = 0; i < dim; ++i)
			getFinalHashSubfield(
				finalHashKey, reduceU64(subtotalU[i]), &finalHashes[i * fieldBits], fieldBits);

		for (size_t i = 0; i < numVoles; ++i)
		{
			u64 reducedHashes[SmallFieldVoleBase::fieldBitsMax];
			for (size_t j = 0; j < fieldBits; ++j)
				reducedHashes[j] = reduceU64(subtotalV[i * fieldBits + j]);

			getFinalHash(
				finalHashKey, reducedHashes,
				&finalHashes[(dim + i) * fieldBits], fieldBits);
		}

		clearHashes();

		std::vector<u8> finalHashesPacked(bytesPerHash * numHashes);
		for (size_t i = 0; i < numHashes; ++i)
		{
			u64 output = 0;
			for (size_t j = 0; j < fieldBits; ++j)
				output |= finalHashes[i * fieldBits + j] << j * rows;
			memcpy(&finalHashesPacked[bytesPerHash * i], &output, bytesPerHash);
		}

		chl.asyncSend(std::move(finalHashesPacked));
	}
};

template<typename Code>
class SubspaceVoleMaliciousReceiver : public SubspaceVoleReceiver<Code>, public SubspaceVoleMaliciousBase
{
public:
	std::unique_ptr<block[]> hashW;
	std::unique_ptr<block[]> subtotalW;

	using Receiver = SubspaceVoleReceiver<Code>;
	using Receiver::code;

	SubspaceVoleMaliciousReceiver(SmallFieldVoleReceiver vole_, Code code_) :
		Receiver(std::move(vole_), std::move(code_)),
		hashW(new block[wPadded()]),
		subtotalW(new block[wPadded()])
	{
		clearHashes();
	}

	size_t wPadded() const { return roundUpTo(Receiver::wPadded(), 4); }

	void generateRandom(size_t blockIdx, const AES& aes, span<block> outW)
	{
		Receiver::generateRandom(blockIdx, aes, outW.subspan(0, Receiver::wPadded()));
	}

	void generateChosen(size_t blockIdx, const AES& aes, span<block> outW)
	{
		Receiver::generateChosen(blockIdx, aes, outW.subspan(0, Receiver::wPadded()));
	}

	void sendChallenge(PRNG& prng, Channel& chl)
	{
		block seed = prng.get<block>();
		chl.asyncSendCopy(&seed, 1);
		hashKeyPrng.SetSeed(seed);
		setupHash();
	}

	void hash(span<const block> w)
	{
		for (size_t i = 0; i < Receiver::wSize(); i += 4)
			// Unrolled for ILP.
			for (size_t j = 0; j < 4; ++j)
				updateHash(hashW[i + j], w[i + j]);

		if (rekeyCheck())
			addSubtotalAfterRekey();
	}

	using SubspaceVoleMaliciousBase::addSubtotalAfterRekey;

	void addSubtotalAfterRekey()
	{
		addSubtotalAfterRekey(hashW.get(), subtotalW.get(), Receiver::wSize());
	}

	void clearHashes()
	{
		std::fill_n(hashW.get(), wPadded(), block::allSame(0));
		std::fill_n(subtotalW.get(), wPadded(), block::allSame(0));
	}

	void checkResponse(Channel& chl)
	{
		size_t fieldBits = Receiver::vole.fieldBits;
		size_t numVoles = Receiver::vole.numVoles;

		u64 finalHashKey[64]; // Non-tight upper bound on size.
		getFinalHashKey(finalHashKey, fieldBits);

		addSubtotalAfterRekey();

		std::unique_ptr<u64[]> finalHashW(new u64[roundUpTo(numVoles, 4) * fieldBits]);
		for (size_t i = 0; i < numVoles; ++i)
		{
			u64 reducedHashes[SmallFieldVoleBase::fieldBitsMax];
			for (size_t j = 0; j < fieldBits; ++j)
				reducedHashes[j] = reduceU64(subtotalW[i * fieldBits + j]);

			getFinalHash(finalHashKey, reducedHashes, &finalHashW[i * fieldBits], fieldBits);
		}

		clearHashes();

		size_t rows = finalHashRows(fieldBits);
		size_t bytesPerHash = divCeil(rows * fieldBits, 8);
		size_t dim = code().dimension();
		size_t numSenderHashes = dim + numVoles;
		size_t senderBytes = bytesPerHash * numSenderHashes;
		std::unique_ptr<u8[]> senderFinalHashesPackedU8(new u8[senderBytes]);
		std::unique_ptr<u64[]> senderFinalUHashesPacked(new u64[dim]);
		std::unique_ptr<u64[]> senderFinalHashesPacked(new u64[2 * numVoles]);
		std::unique_ptr<u64[]> senderFinalHashes(new u64[2 * numVoles * fieldBits]);
		chl.recv(senderFinalHashesPackedU8.get(), senderBytes);

		for (size_t i = 0; i < dim; ++i)
		{
			u64 hash = 0;
			memcpy(&hash, &senderFinalHashesPackedU8[bytesPerHash * i], bytesPerHash);
			senderFinalUHashesPacked[i] = hash;
		}

		for (size_t i = 0; i < numVoles; ++i)
		{
			u64 hash = 0;
			memcpy(&hash, &senderFinalHashesPackedU8[bytesPerHash * (dim + i)], bytesPerHash);
			senderFinalHashesPacked[numVoles + i] = hash;
		}

		// Encode the packed U values, as code expects only one input per field element.
		code().encode(&senderFinalUHashesPacked[0], &senderFinalHashesPacked[0]);

		// Unpack both U's and V's hashes.
		for (size_t i = 0; i < 2 * numVoles; ++i)
		{
			u64 hash = senderFinalHashesPacked[i];
			u64 mask = ((u64) 1 << rows) - 1;
			for (size_t j = 0; j < fieldBits; ++j)
				senderFinalHashes[i * fieldBits + j] = (hash >> j * rows) & mask;
		}

		const u64* finalHashU = &senderFinalHashes[0];
		const u64* finalHashV = &senderFinalHashes[numVoles * fieldBits];

		Receiver::vole.sharedFunctionXorGF(finalHashU, finalHashW.get(), gfMods[fieldBits]);
		if (!std::equal(finalHashW.get(), finalHashW.get() + numVoles * fieldBits, finalHashV))
			throw std::runtime_error("Failed subspace VOLE consistency check");;
	}
};

}
}
#endif
