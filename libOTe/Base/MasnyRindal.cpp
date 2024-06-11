#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/Tools/DefaultCurve.h"
#include "libOTe/Tools/Coproto.h"

#if !(defined(ENABLE_SODIUM) || defined(ENABLE_RELIC))
static_assert(0, "ENABLE_SODIUM or ENABLE_RELIC must be defined to build MasnyRindal");
#endif

#include <libOTe/Base/SimplestOT.h>

namespace osuCrypto
{
	namespace {
		const u64 step = 16;
	}

	task<> MasnyRindal::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		using namespace DefaultCurve;

		//MC_BEGIN(task<>, &choices, messages, &prng, &chl,            
		//    n = u64{},
		//    i = u64{},
		//    sk = std::vector<Number>{},
		//    buff = std::vector<u8>{},
		//    rrNot = Point{}, rr = Point{}, hPoint = Point{}
		//    );

		auto n = choices.size();

		Curve{}; // required to init relic
		auto buff = std::vector<u8>{};
		auto sk = std::vector<Number>{};
		sk.reserve(n);

		for (u64 i = 0; i < n;)
		{
				Curve{};// required to init relic (might be on new thread here)
				auto curStep = std::min<u64>(n - i, step);

				buff.resize(Point::size * 2 * curStep);

				for (u64 k = 0; k < curStep; ++k, ++i)
				{
					Point rrNot;
					rrNot.randomize(prng);

					u8* rrNotPtr = &buff[Point::size * (2 * k + (choices[i] ^ 1))];
					rrNot.toBytes(rrNotPtr);

					// TODO: Ought to do domain separation.
					auto hPoint = Point{};
					hPoint.fromHash(rrNotPtr, Point::size);

					sk.emplace_back(prng);
					auto rr = Point::mulGenerator(sk[i]);
					rr -= hPoint;
					rr.toBytes(&buff[Point::size * (2 * k + choices[i])]);
				}

			co_await chl.send(std::move(buff));
		}

		buff.resize(Point::size);
		co_await chl.recv(buff);

		Curve{};// required to init relic (might be on new thread here)
		Point Mb, k;
		Mb.fromBytes(buff.data());

		for (u64 i = 0; i < n; ++i)
		{
			k = Mb;
			k *= sk[i];

			RandomOracle ro(sizeof(block));
			ro.Update(k);
			ro.Update(i * 2 + choices[i]);
			ro.Final(messages[i]);
		}

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> MasnyRindal::send(span<std::array<block, 2>> messages, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		using namespace DefaultCurve;
		Curve{}; // required to init relic


		auto n = static_cast<u64>(messages.size());

		auto buff = std::vector<u8>{};
		buff.resize(Point::size);

		auto sk = Number{};
		sk.randomize(prng);

		Point Mb = Point::mulGenerator(sk);
		Mb.toBytes(buff.data());

		co_await chl.send(std::move(buff));


		for (u64 i = 0; i < n; )
		{
			auto curStep = std::min<u64>(n - i, step);
			buff.resize(Point::size * 2 * curStep);

			co_await chl.recv(buff);
			Curve{};// required to init relic (might be on new thread here)

			for (u64 k = 0; k < curStep; ++k, ++i)
			{
				for (u64 j = 0; j < 2; ++j)
				{
					auto r = Point{};
					r.fromBytes(&buff[Point::size * (2 * k + j)]);

					// TODO: Ought to do domain separation.
					auto pHash = Point{};
					pHash.fromHash(&buff[Point::size * (2 * k + (j ^ 1))], Point::size);

					r += pHash;
					r *= sk;

					RandomOracle ro(sizeof(block));
					ro.Update(r);
					ro.Update(i * 2 + j);
					ro.Final(messages[i][j]);
				}
			}
		}

		} MACORO_CATCH(eptr)
		{
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}
}
#endif
