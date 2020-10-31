#include "PopfOT.h"

#ifdef ENABLE_POPF

// #include "Popf.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/RCurve.h>
#ifndef ENABLE_RELIC
static_assert(0, "ENABLE_RELIC must be defined to build PopfOT");
#endif

using Curve = oc::REllipticCurve;
using Point = oc::REccPoint;
using Brick = oc::REccPoint;
using Number = oc::REccNumber;

namespace osuCrypto
{
    
    // UNSAFE, TO FIX LATER
    void EKEPopf::toBytes(u8* dest) const
    {
        // Copy or move? I'm not sure which to do here.
        // So I'll do neither for the moment.
        memcpy(dest, popfBuff.data(), size);
    }

    // UNSAFE, TO FIX LATER
    void EKEPopf::fromBytes(u8* src)
    {
        // Copy or move? I'm not sure which to do here.
        // So I'll do neither for the moment.
        memcpy(popfBuff.data(), src, size);
    }

    Point EKEPopf::eval(bool x)
    {
        std::vector<u8> buff(size);
        Point y;

        Rijndael256Enc::Block* p = (Rijndael256Enc::Block*)popfBuff.data();
        ICinv[x].decBlocks(p, aesBlocks, (Rijndael256Enc::Block*)buff.data());
        y.fromBytes(buff.data());
        return y;
    }

    void EKEPopf::program(bool x, Point y)
    {
        std::vector<u8> pointBuff(y.sizeBytes());

        y.toBytes(pointBuff.data());
        Rijndael256Enc::Block* p = (Rijndael256Enc::Block*)pointBuff.data();
        IC[x].encBlocks(p, aesBlocks, (Rijndael256Enc::Block*)popfBuff.data());
    }

    // template<class T>
    // void PopfOT<T>::receive(
    void PopfOT::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        Point gprime = curve.getGenerator();
        u64 pointSize = g.sizeBytes();
        u64 n = choices.size();

        EKEPopf popf;
        u64 popfSize = popf.sizeBytes();
        std::vector<u8> pointBuff(pointSize);
        std::vector<u8> hashBuff(roundUpTo(pointSize, 16));
        std::vector<Number> sk; sk.reserve(n);
        std::vector<u8> curveChoice; curveChoice.reserve(n);

        std::vector<u8> recvBuff(2*pointSize);
        chl.asyncRecv(recvBuff.data(), 2*pointSize);

        std::vector<u8> sendBuff(n * popfSize);
        auto sendBuffIter = sendBuff.data();

        Point B(curve);
        for (u64 i = 0; i < n; ++i)
        {
            curveChoice.emplace_back(prng.getBit());
            sk.emplace_back(curve, prng);
            if (curveChoice[i] == 0)
            {
                B = g * sk[i];
            } else
            {
                B = gprime * sk[i];
            }

            popf.program(choices[i], B);
            popf.toBytes(sendBuffIter);
            B.toBytes(pointBuff.data());
            sendBuffIter += popfSize;
        }

        chl.asyncSend(std::move(sendBuff));

        RandomOracle ro(sizeof(block));
        auto recvBuffIter = recvBuff.data();
        Point A(curve);
        A.fromBytes(recvBuffIter); recvBuffIter += pointSize;
        Point Aprime(curve);
        Aprime.fromBytes(recvBuffIter);
        for (u64 i = 0; i < n; ++i)
        {
            if (curveChoice[i] == 0)
            {
                B = A * sk[i];
            } else
            {
                B = Aprime * sk[i];
            }
            B.toBytes(hashBuff.data());
            RandomOracle ro(sizeof(block));
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(messages[i]);
        }
    }

    // template<class T>
    // void PopfOT<T>::send(
    void PopfOT::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        Point gprime = curve.getGenerator();
        u64 pointSize = g.sizeBytes();
        u64 n = static_cast<u64>(msg.size());
        RandomOracle ro(sizeof(block));

        EKEPopf popf;
        auto popfSize = popf.sizeBytes();
        std::vector<u8> sendBuff(2*pointSize);
        std::vector<u8> hashBuff(roundUpTo(pointSize, 16));

        Number sk(curve, prng);
        auto sendBuffIter = sendBuff.data();
        Point A = g * sk;
        Point Aprime = gprime * sk;
        A.toBytes(sendBuffIter); sendBuffIter += pointSize;
        Aprime.toBytes(sendBuffIter);

        chl.asyncSend(std::move(sendBuff));

        std::vector<u8> recvBuff(n * popfSize);
        chl.recv(recvBuff.data(), recvBuff.size());

        auto buffIter = recvBuff.data();

        Point Bz(curve), Bo(curve);
        for (u64 i = 0; i < n; ++i)
        {
            popf.fromBytes(buffIter);
            Bz = popf.eval(0);
            Bo = popf.eval(1);
            buffIter += popfSize;

            // We don't need to check which curve we're on since we use the same secret for both.
            Bz *= sk;
            Bz.toBytes(hashBuff.data());
            RandomOracle ro(sizeof(block));
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(msg[i][0]);

            Bo *= sk;
            Bo.toBytes(hashBuff.data());
            ro.Reset();
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(msg[i][1]);
        }
    }
}
#endif


