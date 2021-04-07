#pragma once

#include <libOTe/config.h>
#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
namespace osuCrypto
{


	class NoisyVoleReceiver : public TimerAdapter
	{
	public:
		NoisyVoleReceiver() = default;
		~NoisyVoleReceiver() = default;


		void receive(span<block> y, span<block> z, PRNG& prng, OtSender& ot, Channel& chl);
		void receive(span<block> y, span<block> z, PRNG& prng, span<std::array<block,2>> otMsg, Channel& chl);

	};


}
#endif
