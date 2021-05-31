#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>
#include "DefaultCurve.h"

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
        using namespace default_curve;

        auto n = choices.size();
        const auto pointSize = Point::size;

        Curve curve;
        std::vector<Number> sk; sk.reserve(n);

        std::vector<u8> recvBuff(pointSize);
        auto fu = chl.asyncRecv(recvBuff.data(), pointSize);

        Point rrNot, rr, hPoint;

        for (u64 i = 0; i < n;)
        {
            auto curStep = std::min<u64>(n - i, step);

            std::vector<u8> sendBuff(pointSize * 2 * curStep);

            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                rrNot.randomize(prng);

                u8* rrNotPtr = &sendBuff[pointSize * (2 * k + (choices[i] ^ 1))];
                rrNot.toBytes(rrNotPtr);

                // TODO: Ought to do domain separation.
                hPoint.fromHash(rrNotPtr, pointSize);

                sk.emplace_back(prng);
                rr = Point::mulGenerator(sk[i]);
                rr -= hPoint;
                rr.toBytes(&sendBuff[pointSize * (2 * k + choices[i])]);
            }

            chl.asyncSend(std::move(sendBuff));
        }


        Point Mb, k;
        fu.get();
        Mb.fromBytes(recvBuff.data());

        for (u64 i = 0; i < n; ++i)
        {
            k = Mb;
            k *= sk[i];

            RandomOracle ro(sizeof(block));
            ro.Update(k);
            ro.Update(i);
            ro.Final(messages[i]);
        }
    }

    void MasnyRindal::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        using namespace default_curve;

        auto n = static_cast<u64>(messages.size());
        auto pointSize = Point::size;

        RandomOracle ro;

        std::vector<u8> buff(pointSize);
        Curve curve;

        Number sk(prng);
        Point Mb = Point::mulGenerator(sk);
        Mb.toBytes(buff.data());
        chl.asyncSend(std::move(buff));

        buff.resize(pointSize * 2 * step);
        Point pHash, r;

        for (u64 i = 0; i < n; )
        {
            auto curStep = std::min<u64>(n - i, step);
            auto buffSize = curStep * pointSize * 2;
            chl.recv(buff.data(), buffSize);

            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                for (u64 j = 0; j < 2; ++j)
                {
                    r.fromBytes(&buff[pointSize * (2 * k + j)]);

                    // TODO: Ought to do domain separation.
                    pHash.fromHash(&buff[pointSize * (2 * k + (j ^ 1))], int(pointSize));

                    r += pHash;
                    r *= sk;

                    ro.Reset(sizeof(block));
                    ro.Update(r);
                    ro.Update(i);
                    ro.Final(messages[i][j]);
                }
            }
        }
    }
}
#endif
