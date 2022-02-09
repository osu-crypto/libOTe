#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Classes for Sect. 3.1 of SoftSpokenOT paper. Silent, so malicious security is easy. Outputs
// vectors u, v to sender and Delta, w to receiver such that: w - v = u cdot Delta, where cdot means
// componentwise product. u is a vector over GF(2), but Delta, v, and w are vectors over
// GF(2^fieldBits). Really, it outputs 128 of these (u, v)s and Ws at a time, packed into blocks.
// Delta, v, and w have fieldBits blocks for every block of u, to represent the larger finite field.
// The bits of the finite field are stored in little endian order.

// Commonalities between sender and receiver.
class SmallFieldVoleBase
{
public:
	static constexpr size_t fieldBitsMax = 31;

	const size_t fieldBits;
	const size_t numVoles;

	// 2D array, with one row for each VOLE and one column for each field element (minus one for the
	// receiver). Since the receiver doesn't know the zeroth seed, the columns are all shifted by 1
	// for them.
	std::unique_ptr<block[]> seeds;

	static constexpr size_t numBaseOTsNeeded(size_t fieldBits, size_t numVoles)
	{
		return fieldBits * numVoles;
	}

	size_t numBaseOTs() const
	{
		return fieldBits * numVoles;
	}

	size_t fieldSize() const
	{
		return (size_t) 1 << fieldBits;
	}

	SmallFieldVoleBase(size_t fieldBits_, size_t numVoles_) :
		fieldBits(fieldBits_),
		numVoles(numVoles_)
	{
		if (fieldBits < 1 || fieldBits > fieldBitsMax)
			throw RTE_LOC;
	}

private:
	// Helper to convert generateImpl into a non-member function.
	template<size_t fieldBitsConst, typename T, T Func>
	struct call_member_func;

	friend class SmallFieldVoleSender;
	friend class SmallFieldVoleReceiver;
};

class SmallFieldVoleSender : public SmallFieldVoleBase
{
public:
	// Instead of special casing the last few VOLEs when the number of AES calls wouldn't be a
	// multiple of superBlkSize, just pad the seeds and output. The output must be sized for
	// numVolesPadded VOLEs, rather than numVoles, and the extra output values will be garbage. This
	// wastes a few AES calls, but saving them wouldn't have helped much because you still have to
	// pay for the AES latency.
	const size_t numVolesPadded;

	SmallFieldVoleSender(size_t fieldBits_, size_t numVoles_);

	// seeds must be the OT messages from numVoles instances of 2**fieldBits - 1 of 2**fieldBits OT,
	// with each OT occupying a contiguous memory range.
	SmallFieldVoleSender(size_t fieldBits_, size_t numVoles_, span<const block> seeds_);

	// Uses a PPRF to implement the 2**fieldBits - 1 of 2**fieldBits OTs out of 1 of 2 base OTs. The
	// messages of the base OTs must be in baseMessages.
	SmallFieldVoleSender(size_t fieldBits_, size_t numVoles_,
		Channel& chl, PRNG& prng, span<const std::array<block, 2>> baseMessages, size_t numThreads,
		bool malicious);

	// The number of useful blocks in u, v.
	size_t uSize() const { return numVoles; }
	size_t vSize() const { return fieldBits * numVoles; }

	// ... plus the number of padding blocks at the end where garbage may be written.
	size_t uPadded() const { return numVolesPadded; }
	size_t vPadded() const { return fieldBits * numVolesPadded; }


	// outV outputs the values for v, i.e. xor_x x * PRG(seed[x]). outU gives the values for u (the
	// xor of all PRG evaluations).
	void generate(size_t blockIdx, block* outU, block* outV) const
	{
		generatePtr(*this, blockIdx, outU, outV);
	}

	void generate(size_t blockIdx, span<block> outU, span<block> outV) const
	{
#ifndef NDEBUG
		if ((size_t) outU.size() != uPadded())
			throw RTE_LOC;
		if ((size_t) outV.size() != vPadded())
			throw RTE_LOC;
#endif

		return generate(blockIdx, outU.data(), outV.data());
	}

	static size_t computeNumVolesPadded(size_t fieldBits, size_t numVoles)
	{
		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
			return roundUpTo(numVoles, superBlkSize >> fieldBits);
		else // > 1 super block per VOLE.
			return numVoles;
	}

private:
	void (*const generatePtr)(const SmallFieldVoleSender&,
		size_t, block* BOOST_RESTRICT, block* BOOST_RESTRICT);

	template<size_t fieldBitsConst>
	TRY_FORCEINLINE void generateImpl(size_t blockIdx,
		block* BOOST_RESTRICT outV, block* BOOST_RESTRICT outU) const;

	template<size_t fieldBitsConst, typename T, T Func>
	friend struct call_member_func;

	// Select specialized implementation of generate.
	static decltype(generatePtr) selectGenerateImpl(size_t fieldBits);
};

class SmallFieldVoleReceiver : public SmallFieldVoleBase
{
public:
	BitVector delta;
	std::unique_ptr<u8[]> deltaUnpacked; // Each bit of delta becomes a byte, either 0 or 0xff.

	// Same as for SmallFieldVoleSender, except that the AES operations are performed in differently
	// sized chunks for the receiver.
	const size_t numVolesPadded;

	SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_);
	SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_, BitVector delta_);

	// seeds must be the OT messages from numVoles instances of 2**fieldBits - 1 of 2**fieldBits OT,
	// with each OT occupying a contiguous memory range. The choice bits (i.e. the indices of the
	// punctured points) from these OTs must be concatenated together into delta (in little endian),
	// which must then be uniformly random for security. seeds must be ordered so that the delta'th
	// seed in a vole (the one that is unknown to the receiver) would be in position -1 (in general,
	// i gets stored at (i ^ delta) - 1).
	SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_, span<const block> seeds_, BitVector delta_);

	// Uses a PPRF to implement the 2**fieldBits - 1 of 2**fieldBits OTs out of 1 of 2 base OTs. The
	// messages and choice bits (which must be uniformly random) of the base OTs must be in
	// baseMessages and choices.
	SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_,
		Channel& chl, PRNG& prng, span<const block> baseMessages, BitVector choices,
		size_t numThreads, bool malicious);

	// The number of useful blocks in w.
	size_t wSize() const { return fieldBits * numVoles; }

	// wSize plus the number of padding blocks at the end where garbage may be written.
	size_t wPadded() const { return fieldBits * numVolesPadded; }

	// The VOLE outputs secret shares shares of u cdot Delta, where u is in GF(2)^numVoles, Delta is
	// in GF(2^fieldBits)^numVoles, and cdot represents the componentwise product. This computes the
	// cdot Delta operation (i.e. the secret shared function) on 128 vectors at once. The output is
	// XORed into product, which must be padded to length wPadded().
	template<typename T>
	inline void sharedFunctionXor(const T* u, T* product);

	template<typename T>
	void sharedFunctionXor(span<const T> u, span<T> product)
	{
#ifndef NDEBUG
		if ((size_t) u.size() != numVoles)
			throw RTE_LOC;
		if ((size_t) product.size() != wPadded())
			throw RTE_LOC;
#endif
		sharedFunctionXor(u.data(), product.data());
	}

	// Same, but on values in GF(2^fieldBits)^numVoles instead of GF(2)^numVoles. modulus is the
	// modulus of the GF(2^fieldBits) field being used.
	template<typename T>
	inline void sharedFunctionXorGF(const T* BOOST_RESTRICT u, T* BOOST_RESTRICT product, u64 modulus);

	// Helper for above. See below class for specialization on block.
	template<typename T>
	inline static T allSame(u8 in)
	{
		// Use sign extension.
		return (typename std::make_signed<T>::type) (i8) in;
	}

	// outW outputs the values for w, i.e. xor_x x * PRG(seed[x]). If correction is passed, its
	// effect is the same as running sharedFunctionXor(correction, outW) after this function.
	void generate(size_t blockIdx, block* outW, const block* correction = nullptr) const
	{
		generatePtr(*this, blockIdx, outW, correction);
	}

	void generate(
		size_t blockIdx, span<block> outW, span<const block> correction = span<block>()) const
	{
#ifndef NDEBUG
		if ((size_t) outW.size() != wPadded())
			throw RTE_LOC;
		if (correction.data() && (size_t) correction.size() != numVoles)
			throw RTE_LOC;
#endif

		return generate(blockIdx, outW.data(), correction.data());
	}

	static size_t computeNumVolesPadded(size_t fieldBits, size_t numVoles)
	{
		size_t volesPadded;
		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
			volesPadded = roundUpTo(numVoles, divNearest(superBlkSize, (1 << fieldBits) - 1));
		else // > 1 super block per VOLE.
			volesPadded = numVoles;

		// Padding for sharedFunctionXor.
		return std::max(volesPadded, roundUpTo(numVoles, 4));
	}

private:
	void (*const generatePtr)(const SmallFieldVoleReceiver&,
		size_t, block* BOOST_RESTRICT, const block* BOOST_RESTRICT);

	template<size_t fieldBitsConst>
	TRY_FORCEINLINE void generateImpl(
		size_t blockIdx, block* BOOST_RESTRICT outW, const block* BOOST_RESTRICT correction) const;

	template<size_t fieldBitsConst, typename T, T Func>
	friend struct call_member_func;

	// Select specialized implementation of generate.
	static decltype(generatePtr) selectGenerateImpl(size_t fieldBits);

	template<typename T>
	TRY_FORCEINLINE void sharedFunctionXorGFImpl(
		const T* BOOST_RESTRICT u, T* BOOST_RESTRICT product, u64 modulus,
		size_t nVole, size_t chunk);
};

template<> inline block SmallFieldVoleReceiver::allSame<block>(u8 in)
{
	return block::allSame(in);
}

template<typename T>
void SmallFieldVoleReceiver::sharedFunctionXor(const T* u, T* product)
{
	for (size_t nVole = 0; nVole < numVoles; nVole += 4)
	{
		T uBlock[4];
		for (size_t i = 0; i < 4; ++i)
			uBlock[i] = u[nVole + i];

		for (size_t bit = 0; bit < fieldBits; ++bit)
			for (size_t i = 0; i < 4; ++i)
				product[(nVole + i) * fieldBits + bit] ^=
					uBlock[i] & allSame<T>(deltaUnpacked[(nVole + i) * fieldBits + bit]);
	}
}

template<typename T>
TRY_FORCEINLINE void SmallFieldVoleReceiver::sharedFunctionXorGFImpl(
	const T* BOOST_RESTRICT u, T* BOOST_RESTRICT product, u64 modulus, size_t nVole, size_t step)
{
	T products[4][2 * SmallFieldVoleBase::fieldBitsMax - 1] = {0};

	// Don't bother with fast multiplication for now.
	for (size_t bitU = 0; bitU < fieldBits; ++bitU)
		for (size_t bitD = 0; bitD < fieldBits; ++bitD)
			for (size_t i = 0; i < step; ++i)
				products[i][bitU + bitD] ^= u[(nVole + i) * fieldBits + bitU] &
					allSame<T>(deltaUnpacked[(nVole + i) * fieldBits + bitD]);

	// Apply modular reduction to put the result in GF(2^fieldBits). Again, don't bother with
	// fast techinques.
	for (size_t j = 2 * fieldBits - 2; j >= fieldBits; --j)
		for (size_t k = 1; k <= fieldBits; ++k)
			if ((modulus >> (fieldBits - k)) & 1)
				for (size_t i = 0; i < step; ++i)
					products[i][j - k] ^= products[i][j];

	// XOR out
	for (size_t j = 0; j < fieldBits; ++j)
		for (size_t i = 0; i < step; ++i)
			product[(nVole + i) * fieldBits + j] ^= products[i][j];
}

template<typename T>
void SmallFieldVoleReceiver::sharedFunctionXorGF(
	const T* BOOST_RESTRICT u, T* BOOST_RESTRICT product, u64 modulus)
{
	size_t nVole;
	for (nVole = 0; nVole + 4 <= numVoles; nVole += 4)
		sharedFunctionXorGFImpl(u, product, modulus, nVole, 4);
	for (; nVole < numVoles; ++nVole)
		sharedFunctionXorGFImpl(u, product, modulus, nVole, 1);
}

namespace tests
{
void xorReduction();
}

}
}

#endif
