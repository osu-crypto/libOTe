#include "MasnyRindalKyber.h"
#ifdef ENABLE_MR_KYBER

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{

	task<> MasnyRindalKyber::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		static_assert(std::is_trivial<KyberOtRecvPKs>::value, "");
		static_assert(std::is_trivial<KyberOTCtxt>::value, "");

		auto n = choices.size();
		auto ot = std::vector<KyberOTRecver>{};
		auto pkBuff = std::vector<KyberOtRecvPKs>{};
		auto ctxts = std::vector<KyberOTCtxt>{};
		ot.resize(n);
		pkBuff.resize(n);
		ctxts.resize(n);

		for (u64 i = 0; i < n; ++i)
		{
			ot[i].b = choices[i];

			//get receivers message and secret coins
			KyberReceiverMessage(&ot[i], &pkBuff[i]);
		}

		co_await chl.send(std::move(pkBuff));
		co_await chl.recv(ctxts);

		for (u64 i = 0; i < n; ++i)
		{
			KyberReceiverStrings(&ot[i], &ctxts[i]);
			memcpy(&messages[i], ot[i].rot, sizeof(block));
		}
		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> MasnyRindalKyber::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		auto pkBuff = std::vector<KyberOtRecvPKs>{};
		auto ctxts = std::vector<KyberOTCtxt>{};
		auto ptxt = KyberOTPtxt{ };
		auto n = messages.size();
		pkBuff.resize(n);
		ctxts.resize(n);

		prng.get(messages.data(), messages.size());

		co_await chl.recv(pkBuff);

		for (u64 i = 0; i < n; ++i)
		{
			memcpy(ptxt.sot[0], &messages[i][0], sizeof(block));
			memset(ptxt.sot[0] + sizeof(block), 0, sizeof(ptxt.sot[0]) - sizeof(block));

			memcpy(ptxt.sot[1], &messages[i][1], sizeof(block));
			memset(ptxt.sot[1] + sizeof(block), 0, sizeof(ptxt.sot[1]) - sizeof(block));

			//get senders message, secret coins and ot strings
			KyberSenderMessage(&ctxts[i], &ptxt, &pkBuff[i]);
		}

		co_await chl.send(std::move(ctxts));

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}
}
#endif