#include "SimplestOT.h"


#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#ifdef ENABLE_SIMPLESTOT

#if defined(ENABLE_SODIUM)
#include <cryptoTools/Crypto/SodiumCurve.h>
#elif defined(ENABLE_RELIC)
#include <cryptoTools/Crypto/RCurve.h>
#elif defined(ENABLE_MIRACL)
#include <cryptoTools/Crypto/Curve.h>
#endif

namespace osuCrypto
{
    namespace
    {
#if defined(ENABLE_SODIUM)
        using Point = Sodium::Rist25519;
        using Number = Sodium::Prime25519;
#elif defined(ENABLE_RELIC)
        using Curve = REllipticCurve;
        using Point = REccPoint;
        using Number = REccNumber;
#elif defined(ENABLE_MIRACL)
        using Curve = EllipticCurve;
        using Point = EccPoint;
        using Number = EccNumber;
#endif
    }

    void SimplestOT::receive(
        const BitVector& choices,
        span<block> msg,
        PRNG& prng,
        Channel& chl)
    {
        u64 n = msg.size();

#ifndef ENABLE_SODIUM
        Curve curve;
#endif
#if defined(ENABLE_SODIUM) || defined(ENABLE_RELIC)
        const auto pointSize = Point::size;
        Point A;
        std::array<Point, 2> B;
#else
        Point g = curve.getGenerator();

        const auto pointSize = g.sizeBytes();
        Point A(curve);
        std::array<Point, 2> B{ curve, curve };
#endif

        block comm = oc::ZeroBlock, seed;
        std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block));
#ifndef ENABLE_SODIUM
        std::vector<u8> hashBuff(pointSize);
#endif
        chl.recv(buff.data(), buff.size());
        A.fromBytes(buff.data());

        if (mUniformOTs)
            memcpy(&comm, &buff[pointSize], sizeof(block));

        buff.resize(pointSize * n);

        std::vector<Number> b; b.reserve(n);
        for (u64 i = 0; i < n; ++i)
        {
#if defined(ENABLE_SODIUM) || defined(ENABLE_RELIC)
            b.emplace_back(prng);
            B[0] = Point::mulGenerator(b[i]);
#else
            b.emplace_back(curve, prng);
            B[0] = g * b[i];
#endif
            B[1] = A + B[0];

            B[choices[i]].toBytes(&buff[pointSize * i]);
        }

        chl.asyncSend(std::move(buff));
        if (mUniformOTs)
        {
            chl.recv(seed);
            if (neq(comm, mAesFixedKey.ecbEncBlock(seed) ^ seed))
                throw std::runtime_error("bad decommitment " LOCATION);
        }

        for (u64 i = 0; i < n; ++i)
        {
            B[0] = A * b[i];
            RandomOracle ro(sizeof(block));
#ifdef ENABLE_SODIUM
            ro.Update(B[0]);
#else
            B[0].toBytes(hashBuff.data());
            ro.Update(hashBuff.data(), hashBuff.size());
#endif
            ro.Update(i);
            if (mUniformOTs) ro.Update(seed);
            ro.Final(msg[i]);
        }
    }

    void SimplestOT::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        u64 n = msg.size();

#ifndef ENABLE_SODIUM
        Curve curve;
#endif
#if defined(ENABLE_SODIUM) || defined(ENABLE_RELIC)
        const auto pointSize = Point::size;
        Number a(prng);
        Point A = Point::mulGenerator(a);
        Point B;
#else
        Point g = curve.getGenerator();

        const auto pointSize = g.sizeBytes();
        Number a(curve, prng);
        Point A = g * a;
        Point B(curve);
#endif

        std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block)), hashBuff(pointSize);
        A.toBytes(buff.data());

        block seed;
        if (mUniformOTs)
        {
            // commit to the seed
            seed = prng.get<block>();
            auto comm = mAesFixedKey.ecbEncBlock(seed) ^ seed;
            memcpy(&buff[pointSize], &comm, sizeof(block));
        }

        chl.asyncSend(std::move(buff));

        buff.resize(pointSize * n);
        chl.recv(buff.data(), buff.size());

        if (mUniformOTs)
        {
            // decommit to the seed now that we have their messages.
            chl.send(seed);
        }

        A *= a;
        for (u64 i = 0; i < n; ++i)
        {
            B.fromBytes(&buff[pointSize * i]);

            B *= a;
            RandomOracle ro(sizeof(block));
#ifdef ENABLE_SODIUM
            ro.Update(B);
#else
            B.toBytes(hashBuff.data());
            ro.Update(hashBuff.data(), hashBuff.size());
#endif
            ro.Update(i);
            if (mUniformOTs) ro.Update(seed);
            ro.Final(msg[i][0]);

            B -= A;
            ro.Reset();
#ifdef ENABLE_SODIUM
            ro.Update(B);
#else
            B.toBytes(hashBuff.data());
            ro.Update(hashBuff.data(), hashBuff.size());
#endif
            ro.Update(i);
            if (mUniformOTs) ro.Update(seed);
            ro.Final(msg[i][1]);
        }
    }
}
#endif

#ifdef ENABLE_SIMPLESTOT_ASM
extern "C"
{
    #include "../SimplestOT/ot_sender.h"
    #include "../SimplestOT/ot_receiver.h"
    #include "../SimplestOT/ot_config.h"
    #include "../SimplestOT/cpucycles.h"
    #include "../SimplestOT/randombytes.h"
}
namespace osuCrypto
{

    rand_source makeRandSource(PRNG& prng)
    {
        rand_source rand;
        rand.get = [](void* ctx, unsigned char* dest, unsigned long long length) {
            PRNG& prng = *(PRNG*)ctx;
            prng.get(dest, length);
        };
        rand.ctx = &prng;

        return rand;
    }

    void AsmSimplestOT::receive(
        const BitVector& choices,
        span<block> msg,
        PRNG& prng,
        Channel& chl)
    {
        RECEIVER receiver;

        u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
        u8 keys[4][SIMPLEST_OT_HASHBYTES];
        u8 cs[4];

        chl.recv(receiver.S_pack, sizeof(receiver.S_pack));
        receiver_procS(&receiver);

        receiver_maketable(&receiver);
        auto rand = makeRandSource(prng);

        for (u32 i = 0; i < msg.size(); i += 4)
        {
            auto min = std::min<u32>(4, msg.size() - i);

            for (u32 j = 0; j < min; j++)
                cs[j] = choices[i + j];

            receiver_rsgen(&receiver, Rs_pack, cs, rand);
            chl.asyncSendCopy(Rs_pack, sizeof(Rs_pack));
            receiver_keygen(&receiver, keys);

            for (u32 j = 0; j < min; j++)
                memcpy(&msg[i + j], keys[j], sizeof(block));
        }
    }

    void AsmSimplestOT::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        SENDER sender;

        u8 S_pack[SIMPLEST_OT_PACK_BYTES];
        u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
        u8 keys[2][4][SIMPLEST_OT_HASHBYTES];

        auto rand = makeRandSource(prng);
        sender_genS(&sender, S_pack, rand);
        chl.asyncSend(S_pack, sizeof(S_pack));

        for (u32 i = 0; i < msg.size(); i += 4)
        {
            chl.recv(Rs_pack, sizeof(Rs_pack));
            sender_keygen(&sender, Rs_pack, keys);

            auto min = std::min<u32>(4, msg.size() - i);
            for (u32 j = 0; j < min; j++)
            {
                memcpy(&msg[i + j][0], keys[0][j], sizeof(block));
                memcpy(&msg[i + j][1], keys[1][j], sizeof(block));
            }
        }
    }
}
#endif
