#include "OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <vector>
#include <cryptoTools/Network/Channel.h>


namespace osuCrypto
{
	task<> OtExtReceiver::genBaseOts(PRNG& prng, Socket& chl)
	{
#ifdef LIBOTE_HAS_BASE_OT
		auto base = DefaultBaseOT{};
		co_await genBaseOts(base, prng, chl);
#else
		throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
		co_return;
#endif
	}

	task<> OtExtReceiver::genBaseOts(OtSender& base, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		auto count = baseOtCount();
		auto msgs = std::vector<std::array<block, 2>>{};
		msgs.resize(count);
		co_await base.send(msgs, prng, chl);
		setBaseOts(msgs);

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> OtExtSender::genBaseOts(PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
#ifdef LIBOTE_HAS_BASE_OT
		auto base = DefaultBaseOT{};
		co_await genBaseOts(base, prng, chl);
#else
		throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
		co_return;
#endif

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> OtExtSender::genBaseOts(OtReceiver& base, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		auto count = baseOtCount();
		auto msgs = std::vector<block>{};
		auto bv = BitVector{};
		msgs.resize(count);
		bv.resize(count);
		bv.randomize(prng);
		co_await base.receive(bv, msgs, prng, chl);
		setBaseOts(msgs, bv);

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> OtReceiver::receiveChosen(
		const BitVector& choices,
		span<block> recvMessages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		auto temp = AlignedUnVector<std::array<block, 2>>(recvMessages.size());

		co_await(receive(choices, recvMessages, prng, chl));
		co_await(chl.recv(temp));

		auto iter = choices.begin();
		for (u64 i = 0; i < temp.size(); ++i)
		{
			recvMessages[i] = recvMessages[i] ^ temp[i][*iter];
			++iter;
		}

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> OtReceiver::receiveCorrelated(const BitVector& choices, span<block> recvMessages, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		auto  temp = AlignedUnVector<block>(recvMessages.size());

		co_await(receive(choices, recvMessages, prng, chl));
		co_await(chl.recv(temp));

		auto iter = choices.begin();
		for (u64 i = 0; i < temp.size(); ++i)
		{
			recvMessages[i] = recvMessages[i] ^ (zeroAndAllOne[*iter] & temp[i]);
			++iter;
		}

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> OtSender::sendChosen(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)

	{
		MACORO_TRY{
		auto temp = AlignedUnVector<std::array<block, 2>>(messages.size());

		co_await(send(temp, prng, chl));

		for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
		{
			temp[i][0] = temp[i][0] ^ messages[i][0];
			temp[i][1] = temp[i][1] ^ messages[i][1];
		}
		co_await(chl.send(std::move(temp)));

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}
}
