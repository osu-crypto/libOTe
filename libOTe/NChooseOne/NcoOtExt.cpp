#include "NcoOtExt.h"

#ifdef LIBOTE_HAS_NCO

#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Network/Channel.h>
namespace osuCrypto
{

	task<> NcoOtExtReceiver::genBaseOts(PRNG& prng, Socket& chl)
	{ 
		MACORO_TRY{

		struct TT
		{
#ifdef ENABLE_IKNP
			IknpOtExtSender iknp;
#endif
#ifdef ENABLE_KOS
			KosOtExtSender kos;
#endif
#ifdef LIBOTE_HAS_BASE_OT
			DefaultBaseOT base;
#endif
		};

		auto count = getBaseOTCount();
		auto msgs = AlignedUnVector<std::array<block, 2>>{};
		auto sender = std::unique_ptr<TT>(new TT);
		msgs.resize(count);

#ifdef ENABLE_IKNP
		if (!isMalicious())
		{
			co_await(sender->iknp.genBaseOts(prng, chl));
			co_await(sender->iknp.send(msgs, prng, chl));
			co_await(setBaseOts(msgs, prng, chl));
			co_return;
		}
#endif

#ifdef ENABLE_KOS

		co_await(sender->kos.genBaseOts(prng, chl));
		co_await(sender->kos.send(msgs, prng, chl));

#elif defined LIBOTE_HAS_BASE_OT

		co_await(sender->base.send(msgs, prng, chl));
#else
		throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

		co_await(setBaseOts(msgs, prng, chl));


	} MACORO_CATCH(eptr) {
		if (!chl.closed()) co_await chl.close();
		std::rethrow_exception(eptr);
	}
	}


	task<> NcoOtExtSender::genBaseOts(PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		struct TT
		{
#ifdef ENABLE_IKNP
			IknpOtExtReceiver iknp;
#endif
#ifdef ENABLE_KOS
			KosOtExtReceiver kos;
#endif
#ifdef LIBOTE_HAS_BASE_OT
			DefaultBaseOT base;
#endif
		};

		auto count = getBaseOTCount();
		auto msgs = AlignedUnVector<block>{};
		auto bv = BitVector{};
		auto recver = std::unique_ptr<TT>(new TT);
		msgs.resize(count);
		bv.resize(count);
		bv.randomize(prng);

#ifdef ENABLE_IKNP
		if (!isMalicious())
		{
			co_await(recver->iknp.genBaseOts(prng, chl));
			co_await(recver->iknp.receive(bv, msgs, prng, chl));
			co_await(setBaseOts(msgs, bv, chl));
			co_return;
		}
#endif

#ifdef ENABLE_KOS
		co_await(recver->kos.genBaseOts(prng, chl));
		co_await(recver->kos.receive(bv, msgs, prng, chl));

#elif defined LIBOTE_HAS_BASE_OT

		co_await(recver->base.receive(bv, msgs, prng, chl));
#else 
		throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

		co_await(setBaseOts(msgs, bv, chl));


		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> NcoOtExtSender::sendChosen(MatrixView<block> messages, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		auto temp = Matrix<block>{};

		if (hasBaseOts() == false)
			throw std::runtime_error("call configure(...) and genBaseOts(...) first.");

		co_await(init(messages.rows(), prng, chl));

		co_await(recvCorrection(chl, messages.rows()));

		co_await(check(chl, prng.get<block>()));

		{

			auto numMsgsPerOT = messages.cols();
			std::array<u64, 2> choice{ 0,0 };
			u64& j = choice[0];

			temp.resize(messages.rows(), numMsgsPerOT);
			for (u64 i = 0; i < messages.rows(); ++i)
			{
				for (j = 0; j < messages.cols(); ++j)
				{
					encode(i, choice.data(), &temp(i, j));
					temp(i, j) = temp(i, j) ^ messages(i, j);
				}
			}
		}


		co_await(chl.send(std::move(temp)));

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> NcoOtExtReceiver::receiveChosen(
		u64 numMsgsPerOT,
		span<block> messages,
		span<u64> choices, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		auto temp = Matrix<block>{};

		if (hasBaseOts() == false)
			throw std::runtime_error("call configure(...) and genBaseOts(...) first.");

		co_await(init(messages.size(), prng, chl));

		{
			// must be at least 128 bits.
			std::array<u64, 2> choice{ 0,0 };
			auto& j = choice[0];

			for (u64 i = 0; i < messages.size(); ++i)
			{
				j = choices[i];
				encode(i, &j, &messages[i]);
			}
		}

		co_await(sendCorrection(chl, messages.size()));
		temp.resize(messages.size(), numMsgsPerOT);

		co_await(check(chl, prng.get<block>()));

		co_await(chl.recv(temp));

		for (u64 i = 0; i < messages.size(); ++i)
		{
			messages[i] = messages[i] ^ temp(i, choices[i]);
		}

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}
}
#endif
