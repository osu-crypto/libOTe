#pragma once

#include "libOTe/Tools/LinearCode.h"
#include "libOTe/TwoChooseOne/KosDot/KosDotExtCheck.h"

#include <cryptoTools/Crypto/PRNG.h>

#include <mutex>

namespace osuCrypto::details
{
	// One compression map belongs to one family of KOS-Dot base choices. Split
	// extenders share this state because they retain the same choice vector.
	class KosDotCodeState
	{
	public:
		void initSender(PRNG& prng)
		{
			std::call_once(mInit, [&]()
			{
				mSeed = prng.get<block>();
				PRNG codePrng(mSeed);
				mCode.random(codePrng, KosDotCheckColumns, gOtExtBaseOtCount);
			});
		}

		bool initReceiver(block seed)
		{
			std::call_once(mInit, [&]()
			{
				mSeed = seed;
				PRNG codePrng(mSeed);
				mCode.random(codePrng, KosDotCheckColumns, gOtExtBaseOtCount);
			});
			return mSeed == seed;
		}

		block seed() const { return mSeed; }
		const LinearCode& code() const { return mCode; }

	private:
		std::once_flag mInit;
		block mSeed = ZeroBlock;
		LinearCode mCode;
	};
}
