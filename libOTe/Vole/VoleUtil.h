#pragma once

#include "cryptoTools/Common/Defines.h"


namespace osuCrypto
{
	// the required number of base OTs and VOLEs
	struct VoleBaseCount
	{
		// the required number of base OTs
		u64 mBaseOtCount = 0;
		// the required number of base Voles
		u64 mBaseVoleCount = 0;
	};
}