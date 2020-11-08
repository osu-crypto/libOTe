#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/RCurve.h>
#ifndef ENABLE_RELIC
static_assert(0, "ENABLE_RELIC must be defined to build MasnyRindal");
#endif

using Curve = oc::REllipticCurve;
using Point = oc::REccPoint;
using Brick = oc::REccPoint;
using Number = oc::REccNumber;

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

        auto n = choices.size();
        Curve curve;
        std::array<Point, 2> r{ curve, curve };
        auto g = curve.getGenerator();
        auto pointSize = g.sizeBytes();

        RandomOracle ro(sizeof(block));
        Point hPoint(curve);

        std::vector<u8> hashBuff(roundUpTo(pointSize, 16));
        std::vector<block> aesBuff((pointSize + 15) / 16);
        std::vector<Number> sk; sk.reserve(n);


        std::vector<u8> recvBuff(pointSize);
        auto fu = chl.asyncRecv(recvBuff.data(), pointSize);

        for (u64 i = 0; i < n;)
        {
            auto curStep = std::min<u64>(n - i, step);

            std::vector<u8> sendBuff(pointSize * 2 * curStep);
            auto sendBuffIter = sendBuff.data();


            for (u64 k = 0; k < curStep; ++k, ++i)
            {

                auto& rrNot = r[choices[i] ^ 1];
                auto& rr = r[choices[i]];

                rrNot.randomize();
                rrNot.toBytes(hashBuff.data());

                ep_map(hPoint, hashBuff.data(), int(pointSize));

                sk.emplace_back(curve, prng);

                rr = g * sk[i];
                rr -= hPoint;

                r[0].toBytes(sendBuffIter); sendBuffIter += pointSize;
                r[1].toBytes(sendBuffIter); sendBuffIter += pointSize;
            }

            if (sendBuffIter != sendBuff.data() + sendBuff.size())
                throw RTE_LOC;

            chl.asyncSend(std::move(sendBuff));
        }


        Point Mb(curve), k(curve);
        fu.get();
        Mb.fromBytes(recvBuff.data());

        for (u64 i = 0; i < n; ++i)
        {
            k = Mb;
            k *= sk[i];

            //lout << "g^ab  " << k << std::endl;

            k.toBytes(hashBuff.data());

            ro.Reset();
            ro.Update(hashBuff.data(), pointSize);
            ro.Update(i);
            ro.Final(messages[i]);
        }
    }

    void MasnyRindal::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        auto n = static_cast<u64>(messages.size());
        
        Curve curve;
        auto g = curve.getGenerator();
        RandomOracle ro(sizeof(block));
        auto pointSize = g.sizeBytes();


        Number sk(curve, prng);

        Point Mb = g;
        Mb *= sk;

        std::vector<u8> buff(pointSize), hashBuff(roundUpTo(pointSize, 16));
        std::vector<block> aesBuff((pointSize + 15) / 16);

        Mb.toBytes(buff.data());
        chl.asyncSend(std::move(buff));

        buff.resize(pointSize * 2 * step);
        Point pHash(curve), r(curve);

        for (u64 i = 0; i < n; )
        {
            auto curStep = std::min<u64>(n - i, step);

            auto buffSize = curStep * pointSize * 2;
            chl.recv(buff.data(), buffSize);
            auto buffIter = buff.data();


            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                std::array<u8*, 2> buffIters{
                    buffIter,
                    buffIter + pointSize
                };
                buffIter += pointSize * 2;

                for (u64 j = 0; j < 2; ++j)
                {
                    r.fromBytes(buffIters[j]);
                    ep_map(pHash, buffIters[j ^ 1], int(pointSize));

                    r += pHash;
                    r *= sk;

                    r.toBytes(hashBuff.data());
                    auto p = (block*)hashBuff.data();

                    ro.Reset();
                    ro.Update(hashBuff.data(), pointSize);
                    ro.Update(i);
                    ro.Final(messages[i][j]);
                }
            }

            if (buffIter != buff.data() + buffSize)
                throw RTE_LOC;
        }

    }
}
#endif