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

    static inline void blockToCurve(Point& p, Block256 b)
    {
        unsigned char buf[sizeof(Block256) + 1];
        buf[0] = 2;
        memcpy(&buf[1], b.data(), sizeof(b));
        p.fromBytes(buf);
    }

    static inline Block256 curveToBlock(const Point& p)
    {
        unsigned char buf[sizeof(Block256) + 1];
        p.toBytes(buf);
        return Block256(&buf[1]);
    }

    // UNSAFE, TO FIX LATER
    void EKEPopf::toBytes(u8* dest) const
    {
        // Copy or move? I'm not sure which to do here.
        // So I'll do neither for the moment.
        memcpy(dest, popfBuff.data(), sizeof(Block256));
    }

    // UNSAFE, TO FIX LATER
    void EKEPopf::fromBytes(u8* src)
    {
        // Copy or move? I'm not sure which to do here.
        // So I'll do neither for the moment.
        memcpy(popfBuff.data(), src, sizeof(Block256));
    }

    Point EKEPopf::eval(bool x)
    {
        Point y;
        blockToCurve(y, ICinv[x].decBlock(*(Rijndael256Enc::Block*) popfBuff.data()));
        return y;
    }

    void EKEPopf::program(bool x, Point y)
    {
        IC[x].encBlock(curveToBlock(y), *(Rijndael256Enc::Block*) popfBuff.data());
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
        assert(g.sizeBytes() == sizeof(Block256) + 1);
        u64 n = choices.size();

        EKEPopf popf;
        u64 popfSize = popf.sizeBytes();
        std::vector<Number> sk; sk.reserve(n);
        std::vector<u8> curveChoice; curveChoice.reserve(n);

        std::array<Block256, 2> recvBuff;
        chl.asyncRecv(recvBuff);

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
            }
            else
            {
                B = gprime * sk[i];
            }

            popf.program(choices[i], B);
            popf.toBytes(sendBuffIter);
            sendBuffIter += popfSize;
        }

        chl.asyncSend(std::move(sendBuff));

        Point A(curve);
        Point Aprime(curve);
        blockToCurve(A, recvBuff[0]);
        blockToCurve(Aprime, recvBuff[1]);
        for (u64 i = 0; i < n; ++i)
        {
            if (curveChoice[i] == 0)
            {
                B = A * sk[i];
            }
            else
            {
                B = Aprime * sk[i];
            }

            RandomOracle ro(sizeof(block));
            ro.Update(curveToBlock(B).data(), sizeof(Block256));
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
        assert(g.sizeBytes() == sizeof(Block256) + 1);
        u64 n = static_cast<u64>(msg.size());

        EKEPopf popf;
        auto popfSize = popf.sizeBytes();

        Number sk(curve, prng);
        Point A = g * sk;
        Point Aprime = gprime * sk;
        std::array<Block256, 2> sendBuff = {curveToBlock(A), curveToBlock(Aprime)};

        chl.asyncSend(sendBuff);

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
            RandomOracle ro(sizeof(block));
            ro.Update(curveToBlock(Bz).data(), sizeof(Block256));
            ro.Final(msg[i][0]);

            Bo *= sk;
            ro.Reset();
            ro.Update(curveToBlock(Bo).data(), sizeof(Block256));
            ro.Final(msg[i][1]);
        }
    }
}
#endif


