#include "MasnyRindalBasic.h"

#if defined(ENABLE_MR) && defined(ENABLE_SODIUM)

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/SodiumCurve.h>
#ifndef ENABLE_SODIUM
static_assert(0, "ENABLE_SODIUM must be defined to build MasnyRindalBasic");
#endif

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
        using namespace Sodium;

        u64 n = messages.size();

        Rist25519 hPoint;
        std::vector<Rist25519> sendBuff(2 * n), recvBuff(n);

        std::vector<Prime25519> sk; sk.reserve(n);
        std::array<Rist25519, 2> B;
        for (u64 i = 0; i < n; ++i)
        {
            sk.emplace_back(prng);
            B[choices[i]] = Rist25519::mulGenerator(sk[i]);
            B[1 - choices[i]] = Rist25519(prng);

            RandomOracle ro(Rist25519::fromHashLength); // TODO: Ought to do domain separation.
            ro.Update(B[1 - choices[i]]);
            hPoint = Rist25519::fromHash(ro);

            B[choices[i]] -= hPoint;

            sendBuff[2 * i] = B[0];
            sendBuff[2 * i + 1] = B[1];
        }

        chl.asyncSend(std::move(sendBuff));
        chl.recv(recvBuff.data(), recvBuff.size());
        for (u64 i = 0; i < n; ++i)
        {
            Rist25519 A = recvBuff[i];

            B[0] = A * sk[i];
            RandomOracle ro(sizeof(block));
            ro.Update(B[0]);
            ro.Final(messages[i]);
        }
    }

    void MasnyRindalBasic::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        using namespace Sodium;

        u64 n = messages.size();

        Rist25519 hPoint[2];
        std::vector<Rist25519> sendBuff(n), recvBuff(2 * n);

        std::vector<Prime25519> sk;
        for (u64 i = 0; i < n; ++i)
        {
            sk.emplace_back(prng);
            sendBuff[i] = Rist25519::mulGenerator(sk[i]);
        }
        chl.asyncSend(std::move(sendBuff));

        Rist25519 Ba;
        chl.recv(recvBuff.data(), recvBuff.size());
        for (u64 i = 0; i < n; ++i)
        {
            std::array<Rist25519, 2> r;
            r[0] = recvBuff[2 * i];
            r[1] = recvBuff[2 * i + 1];

            RandomOracle ro(Rist25519::fromHashLength); // TODO: Ought to do domain separation.
            ro.Update(r[1]);
            hPoint[0] = Rist25519::fromHash(ro);

            ro.Reset();
            ro.Update(r[0]);
            hPoint[1] = Rist25519::fromHash(ro);

            Ba = (r[0] + hPoint[0]) * sk[i];
            ro.Reset(sizeof(block));
            ro.Update(Ba);
            ro.Final(messages[i][0]);
            ro.Reset();

            Ba = (r[1] + hPoint[1]) * sk[i];
            ro.Update(Ba);
            ro.Final(messages[i][1]);
        }
    }
}
#endif
