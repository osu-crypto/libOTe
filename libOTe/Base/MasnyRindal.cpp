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
        using namespace DefaultCurve;

        Curve{};
        MC_BEGIN(task<>, &choices, messages, &prng, &chl,            
            n = u64{},
            i = u64{},
            sk = std::vector<Number>{},
            buff = std::vector<u8>{},
            rrNot = Point{}, rr = Point{}, hPoint = Point{}
            );

        n = choices.size();

        sk.reserve(n);

        for (i = 0; i < n;)
        {
            {
                Curve{};
                auto curStep = std::min<u64>(n - i, step);

                buff.resize(Point::size * 2 * curStep);

                for (u64 k = 0; k < curStep; ++k, ++i)
                {
                    rrNot.randomize(prng);

                    u8* rrNotPtr = &buff[Point::size * (2 * k + (choices[i] ^ 1))];
                    rrNot.toBytes(rrNotPtr);

                    // TODO: Ought to do domain separation.
                    hPoint.fromHash(rrNotPtr, Point::size);

                    sk.emplace_back(prng);
                    rr = Point::mulGenerator(sk[i]);
                    rr -= hPoint;
                    rr.toBytes(&buff[Point::size * (2 * k + choices[i])]);
                }

            }
            MC_AWAIT(chl.send(std::move(buff)));
        }

        buff.resize(Point::size);
        MC_AWAIT(chl.recv(buff));

        {
            Curve{};
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
        }

        MC_END();
    }


    task<> MasnyRindal::send(span<std::array<block, 2>> messages, PRNG& prng, Socket& chl)
    {
        using namespace DefaultCurve;
        Curve curve;
        MC_BEGIN(task<>, messages, &prng, &chl,
            n = u64{},
            i = u64{},
            curStep = u64{},
            buff = std::vector<u8>{},
            sk = Number{},
            pHash = Point{}, r = Point{}
        );

        n = static_cast<u64>(messages.size());

        buff.resize(Point::size);

        sk.randomize(prng);

        {
            Curve{};
            Point Mb = Point::mulGenerator(sk);
            Mb.toBytes(buff.data());
        }

        MC_AWAIT(chl.send(std::move(buff)));


        for (i = 0; i < n; )
        {
            curStep = std::min<u64>(n - i, step);
            buff.resize(Point::size * 2 * curStep);
            MC_AWAIT(chl.recv(buff));
            Curve{};

            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                for (u64 j = 0; j < 2; ++j)
                {
                    r.fromBytes(&buff[Point::size * (2 * k + j)]);

                    // TODO: Ought to do domain separation.
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

        MC_END();
    }
}
#endif
