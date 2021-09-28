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

	template<typename T>
	void encodeXor(const T* BOOST_RESTRICT message, T* BOOST_RESTRICT codeWord) const
	{
		for (size_t i = 0; i < n; ++i)
			codeWord[i] ^= message[0];
	}

	template<typename T>
	void encodeSyndrome(const T* BOOST_RESTRICT syndrome, T* BOOST_RESTRICT word) const
	{
		for (size_t i = 0; i < n - 1; ++i)
			word[i] = syndrome[i];
		word[n - 1] = T(0);
	}

	template<typename T>
	void decodeInPlace(T* BOOST_RESTRICT wordInSyndromeOut, T* BOOST_RESTRICT message) const
	{
		T msg = wordInSyndromeOut[n - 1];
		*message = msg;
		for (size_t i = 0; i < n - 1; ++i)
			wordInSyndromeOut[i] ^= msg;
	}
};

}
