#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/SodiumCurve.h>
#ifndef ENABLE_SODIUM
static_assert(0, "ENABLE_SODIUM must be defined to build MasnyRindal");
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
        using namespace Sodium;

        auto n = choices.size();

        RandomOracle ro;
        Rist25519 hPoint;

        std::vector<Prime25519> sk; sk.reserve(n);

        Rist25519 Mb;
        auto fu = chl.asyncRecv(Mb);

        for (u64 i = 0; i < n;)
        {
            auto curStep = std::min<u64>(n - i, step);

            std::vector<Rist25519> sendBuff(2 * curStep);

            for (u64 k = 0; k < curStep; ++k, ++i)
            {

                auto& rrNot = sendBuff[2 * k + (choices[i] ^ 1)];
                auto& rr = sendBuff[2 * k + choices[i]];

                rrNot = Rist25519(prng);
                ro.Reset(Rist25519::fromHashLength); // TODO: Ought to do domain separation.
                ro.Update(rrNot);
                hPoint = Rist25519::fromHash(ro);

                sk.emplace_back(prng);
#ifdef MASNY_RINDAL_SIM
#else
                rr = Rist25519::mulGenerator(sk[i]);
                rr -= hPoint;
#endif
            }

#ifdef MASNY_RINDAL_SIM
            SimplestOT::exp(curStep);
            SimplestOT::add(curStep);
#endif

            chl.asyncSend(std::move(sendBuff));
        }


        Rist25519 k;
        fu.get();

#ifdef MASNY_RINDAL_SIM
        SimplestOT::exp(n);
#endif

        for (u64 i = 0; i < n; ++i)
        {
            k = Mb;
#ifndef MASNY_RINDAL_SIM
            k *= sk[i];
#endif

            ro.Reset(sizeof(block));
            ro.Update(k);
            ro.Final(messages[i]);
        }
    }

    void MasnyRindal::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        using namespace Sodium;

        auto n = static_cast<u64>(messages.size());

        RandomOracle ro;

        Prime25519 sk(prng);
        Rist25519 Mb;
#ifdef MASNY_RINDAL_SIM
        SimplestOT::exp(1);
#else
        Mb = Rist25519::mulGenerator(sk);
#endif

        chl.asyncSend(Mb);

        std::vector<Rist25519> buff(2 * step);
        Rist25519 pHash, r;

        for (u64 i = 0; i < n; )
        {
            auto curStep = std::min<u64>(n - i, step);

            chl.recv(buff.data(), 2 * curStep);

            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                for (u64 j = 0; j < 2; ++j)
                {
                    r = buff[2 * k + j];
                    ro.Reset(Rist25519::fromHashLength); // TODO: Ought to do domain separation.
                    ro.Update(buff[2 * k + (j ^ 1)]);
                    pHash = Rist25519::fromHash(ro);

#ifndef MASNY_RINDAL_SIM
                    r += pHash;
                    r *= sk;
#endif

                    ro.Reset(sizeof(block));
                    ro.Update(r);
                    ro.Final(messages[i][j]);
                }
            }

#ifdef MASNY_RINDAL_SIM
            SimplestOT::add(2 * curStep);
            SimplestOT::exp(2 * curStep);
#endif
        }

    }
}
#endif
