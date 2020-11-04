#include "MasnyRindalBasic.h"

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

    void MasnyRindalBasic::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        u64 pointSize = g.sizeBytes();
        u64 n = messages.size();
        
        Point hPoint(curve);
        std::vector<u8> sendBuff(2 * n * pointSize), recvBuff(n * pointSize), hashBuff(roundUpTo(pointSize, 16));

        std::vector<Number> sk; sk.reserve(n);
        std::array<Point, 2> B{ curve, curve };
        auto sendBuffIter = sendBuff.data();
        for (u64 i = 0; i < n; ++i)
        {
            sk.emplace_back(curve, prng);
            B[choices[i]] = g * sk[i];
            B[1 - choices[i]].randomize();
            B[1 - choices[i]].toBytes(hashBuff.data());

            ep_map(hPoint, hashBuff.data(), int(pointSize));
            B[choices[i]] -= hPoint;

            B[0].toBytes(sendBuffIter); sendBuffIter += pointSize;
            B[1].toBytes(sendBuffIter); sendBuffIter += pointSize;
        }

        chl.asyncSend(std::move(sendBuff));
        chl.recv(recvBuff.data(), recvBuff.size());
        auto recvBuffIter = recvBuff.data();
        for (u64 i = 0; i < n; ++i)
        {
            Point A(curve);
            A.fromBytes(recvBuffIter); recvBuffIter += pointSize;

            B[0] = A * sk[i];
            B[0].toBytes(hashBuff.data());
            RandomOracle ro(sizeof(block));
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(messages[i]);
        }
    }

    void MasnyRindalBasic::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        u64 pointSize = g.sizeBytes();
        u64 n = messages.size();
        
        Point hPoint(curve);
        std::vector<u8> sendBuff(n * pointSize), recvBuff(2 * n * pointSize), hashBuff(roundUpTo(pointSize, 16));

        std::vector<Number> sk; sk.reserve(n);
        std::array<Point, 2> B{ curve, curve };
        auto sendBuffIter = sendBuff.data();
        for (u64 i = 0; i < n; ++i)
        {
            sk.emplace_back(curve, prng);
            Point A = g * sk[i];
            A.toBytes(sendBuffIter); sendBuffIter += pointSize;
        }
        chl.asyncSend(std::move(sendBuff));

        Point Ba(curve);
        chl.recv(recvBuff.data(), recvBuff.size());
        auto recvBuffIter = recvBuff.data();
        for (u64 i = 0; i < n; ++i)
        {
            
            std::array<Point, 2> r{ curve, curve };
            r[0].fromBytes(recvBuffIter); recvBuffIter += pointSize;
            r[1].fromBytes(recvBuffIter); recvBuffIter += pointSize;

            r[1].toBytes(hashBuff.data());
            ep_map(hPoint, hashBuff.data(), int(pointSize));

            Ba = (r[0] + hPoint) * sk[i];
            Ba.toBytes(hashBuff.data());
            RandomOracle ro(sizeof(block));
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(messages[i][0]);
            ro.Reset();

            r[0].toBytes(hashBuff.data());
            ep_map(hPoint, hashBuff.data(), int(pointSize));

            Ba = (r[1] + hPoint) * sk[i];
            Ba.toBytes(hashBuff.data());
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(messages[i][1]);
        }
    }
}
#endif