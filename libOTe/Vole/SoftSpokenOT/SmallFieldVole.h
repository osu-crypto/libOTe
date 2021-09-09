#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"

namespace osuCrypto
{

// Class for Sec. 3.1 and 3.2 of SoftSpokenOT paper. Silent, so malicious security is easy.

// Commonalities between sender and receiver.
struct SubspaceVoleBase
{
	static constexpr size_t fieldBitsMax = 31;

	size_t fieldBits;
	size_t numVoles;

	// 2D array, with one row for each VOLE and one column for each field element (minus one for the
	// receiver). Since the receiver doesn't know the zeroth seed, the columns are all shifted by 1
	// for them.
	std::unique_ptr<block[]> seeds;

	size_t fieldSize() const
	{
		return (size_t) 1 << fieldBits;
	}

	SubspaceVoleBase(size_t fieldBits_, size_t numVoles_) :
		fieldBits(fieldBits_),
		numVoles(numVoles_)
	{
		if (fieldBits < 1 || fieldBits > fieldBitsMax)
			throw RTE_LOC;
	}
};

struct SubspaceVoleSender : public SubspaceVoleBase
{
	SubspaceVoleSender(size_t fieldBits_, size_t numVoles_);

	// Instead of special casing last few VOLEs when the number of AES calls wouldn't be a multiple
	// of superBlkSize, just pad the seeds and output. The output must be sized for numVolesPadded()
	// VOLEs, rather than numVoles, and the extra output values will be garbage. This wastes a few
	// AES calls, but saving them wouldn't have helped much because you still have to pay for the
	// AES latency.
	size_t numVolesPadded() const
	{
		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
			return roundUpTo(numVoles, superBlkSize / fieldSize());
		else // > 1 super block per VOLE.
			return numVoles;
	}

	// outV outputs the values for V, i.e. xor_x x * PRG(seed[x]). outU gives the values for U (the
	// xor of all PRG evaluations).
	void generateNthBlock(size_t blockIdx, block* outV, block* outU) const
	{
		(this->*generateNthBlockPtr)(blockIdx, outV, outU);
	}

private:
	void (SubspaceVoleSender::*generateNthBlockPtr)(
		size_t, block* BOOST_RESTRICT, block* BOOST_RESTRICT) const;

	template<size_t fieldBitsConst>
	void generateNthBlockImpl(size_t blockIdx, block* BOOST_RESTRICT outV, block* BOOST_RESTRICT outU) const;
};

struct SubspaceVoleReceiver : public SubspaceVoleBase
{
	SubspaceVoleReceiver(size_t fieldBits_, size_t numVoles_);

	// Same as for SubspaceVoleSender, except that the AES operations are performed in differently
	// sized chunks for the receiver.
	size_t numVolesPadded() const
	{
		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
			return roundUpTo(numVoles, divNearest(superBlkSize, fieldSize() - 1));
		else // > 1 super block per VOLE.
			return numVoles;
	}

	// outW outputs the values for W, i.e. xor_x x * PRG(seed[x]).
	void generateNthBlock(size_t blockIdx, block* outW) const
	{
		(this->*generateNthBlockPtr)(blockIdx, outW);
	}

private:
	void (SubspaceVoleReceiver::*generateNthBlockPtr)(size_t, block* BOOST_RESTRICT) const;

	template<size_t fieldBitsConst>
	void generateNthBlockImpl(size_t blockIdx, block* BOOST_RESTRICT outW) const;
};

}

#endif
