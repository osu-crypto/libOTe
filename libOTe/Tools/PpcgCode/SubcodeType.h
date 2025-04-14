#pragma once
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{

	enum class SubcodeType
	{
		// Perform a firstSubcode for G1 = (I || I || ...)
		Repeater,

		// Perform a block enumerator for G1 = diag(G11,...,G1q)
		Block,

		// Perform a systematic enumerator for G1 = ( I || ... )
		//Systematic,

		Accumulate
	};

}