#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_SILENTOT


#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"


namespace osuCrypto
{


	struct SilentOtTriple : TimerAdapter
	{
		u64 mPartyIdx = 0;

        macoro::variant<SilentOtExtSender, SilentOtExtReceiver> mSendRecv;

		// the number of OTs/OLEs. Triples will be half this amount.
		u64 mN;

		MultType mMultType = MultType::ExConv7x24;

		enum class Type
		{
			Triple,
			OLE
		};

		// Intializes the protocol to generate n binary tiples or
		// n binary OLEs. Once called, baseOtCount() can be called to 
		// determine the required number of base OTs.
		void init(u64 partyIdx, u64 n, SilentSecType mal = SilentSecType::SemiHonest, Type type = Type::Triple);

		bool isInitialized() const { return mN > 0; }

		struct BaseOtCount
		{
			// the number of base OTs as sender.
			u64 mSendCount = 0;

			// choice bits to be used for the receive OTs.
			BitVector mRecvChoice;
		};

		// returns the number of base OTs required. 
		BaseOtCount baseOtCount(PRNG& prng) ;

		// sets the base OTs that will be used.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts);

		// returns true of the base OTs have been set.
		bool hasBaseOts() const;

		macoro::task<> genBaseOts(
			PRNG& prng, 
			Socket& sock,
			SilentBaseType baseType = SilentBaseType::BaseExtend);

		// The F2 OLE protocol. This will generate n OLEs.
		// A = (AMsb || ALsb), C = (CMsb || CLsb). This party will
		// output (A,C) while the other outputs (A',C') such that
		// A * A' = C + C'.
		macoro::task<> expand(
			span<block> A,
			span<block> C,
			PRNG& prng,
			coproto::Socket& sock);


		// The F2 beaver triple protocol. This will generate n beaver triples.
		// A * B = C. 
		macoro::task<> expand(
			span<block> A,
			span<block> B,
			span<block> C,
			PRNG& prng,
			coproto::Socket& sock);

	};

}

#endif