#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/Tools/DefaultCurve.h"

#if !(defined(ENABLE_SODIUM) || defined(ENABLE_RELIC))
static_assert(0, "ENABLE_SODIUM or ENABLE_RELIC must be defined to build MasnyRindal");
#endif

#include <libOTe/Base/SimplestOT.h>

namespace osuCrypto
{
    const u64 step = 16;

    void MasnyRindal::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        using namespace DefaultCurve;
        Curve curve;

        auto n = choices.size();

        Point rrNot, rr, hPoint;

        std::vector<Number> sk; sk.reserve(n);

        u8 recvBuff[Point::size];
        auto fu = chl.asyncRecv(recvBuff, Point::size);

        for (u64 i = 0; i < n;)
        {
            auto curStep = std::min<u64>(n - i, step);

            std::vector<u8> sendBuff(Point::size * 2 * curStep);

            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                rrNot.randomize(prng);

                u8* rrNotPtr = &sendBuff[Point::size * (2 * k + (choices[i] ^ 1))];
                rrNot.toBytes(rrNotPtr);

                // TODO: Ought to do domain separation.
                hPoint.fromHash(rrNotPtr, Point::size);

                sk.emplace_back(prng);
                rr = Point::mulGenerator(sk[i]);
                rr -= hPoint;
                rr.toBytes(&sendBuff[Point::size * (2 * k + choices[i])]);
            }

            chl.asyncSend(std::move(sendBuff));
        }


        Point Mb, k;
        fu.get();
        Mb.fromBytes(recvBuff);

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

    void MasnyRindal::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        using namespace DefaultCurve;
        Curve curve;

        auto n = static_cast<u64>(messages.size());

        RandomOracle ro;

        u8 sendBuff[Point::size];

        Number sk(prng);
        Point Mb = Point::mulGenerator(sk);
        Mb.toBytes(sendBuff);
        chl.asyncSend(sendBuff, Point::size);

        u8 buff[Point::size * 2 * step];
        Point pHash, r;

        for (u64 i = 0; i < n; )
        {
            auto curStep = std::min<u64>(n - i, step);
            auto buffSize = curStep * Point::size * 2;
            chl.recv(buff, buffSize);

            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                for (u64 j = 0; j < 2; ++j)
                {
                    r.fromBytes(&buff[Point::size * (2 * k + j)]);

                    // TODO: Ought to do domain separation.
                    pHash.fromHash(&buff[Point::size * (2 * k + (j ^ 1))], Point::size);

                    r += pHash;
                    r *= sk;

                    ro.Reset(sizeof(block));
                    ro.Update(r);
                    ro.Update(i * 2 + j);
                    ro.Final(messages[i][j]);
                }
            }
        }
    }
}
#endif
