#pragma once
#include <libOTe/config.h>

#include <cryptoTools/Common/Defines.h>
#include "GenericLinearCode.h"

namespace osuCrypto
{

struct RepetitionCode : public GenericLinearCode<RepetitionCode>
{
	size_t n;

	RepetitionCode(size_t n_) : GenericLinearCode<RepetitionCode>(this), n(n_) {}

	size_t dimension() const { return 1; }
	size_t length() const { return n; }

	void encodeXor(const block* BOOST_RESTRICT message, block* BOOST_RESTRICT codeWord) const
	{
		for (size_t i = 0; i < n; ++i)
			codeWord[i] ^= message[0];
	}

	void encodeSyndrome(const block* BOOST_RESTRICT syndrome, block* BOOST_RESTRICT word) const
	{
		for (size_t i = 0; i < n - 1; ++i)
			word[i] = syndrome[i];
		word[n - 1] = toBlock(0UL);
	}

	void decodeInPlace(block* BOOST_RESTRICT wordInSyndromeOut, block* BOOST_RESTRICT message) const
	{
		block msg = wordInSyndromeOut[n - 1];
		*message = msg;
		for (size_t i = 0; i < n - 1; ++i)
			wordInSyndromeOut[i] ^= msg;
	}
};

}
