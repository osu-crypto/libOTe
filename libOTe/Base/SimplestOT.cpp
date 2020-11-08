#include "SimplestOT.h"


#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#ifdef ENABLE_SIMPLESTOT
#include <cryptoTools/Crypto/SodiumCurve.h>

namespace osuCrypto
{
    void SimplestOT::receive(
        const BitVector& choices,
        span<block> msg,
        PRNG& prng,
        Channel& chl)
    {
        using namespace Sodium;

        u64 n = msg.size();

        unsigned char recvBuff[Rist25519::size + sizeof(block)];
        chl.recv(recvBuff, Rist25519::size + mUniformOTs * sizeof(block));

        block comm, seed;
        Rist25519 A;
        memcpy(A.data, recvBuff, Rist25519::size);

        if (mUniformOTs)
            memcpy(&comm, recvBuff + Rist25519::size, sizeof(block));

        std::vector<Rist25519> buff(n);

        std::vector<Prime25519> b; b.reserve(n);
        std::array<Rist25519, 2> B;
        for (u64 i = 0; i < n; ++i)
        {
            b.emplace_back(prng);
            B[0] = Rist25519::mulGenerator(b[i]);
            B[1] = A + B[0];

            buff[i] = B[choices[i]];
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
            ro.Update(B[0]);
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
        using namespace Sodium;

        u64 n = msg.size();

        unsigned char sendBuff[Rist25519::size + sizeof(block)];

        block seed = prng.get<block>();
        Prime25519 a(prng);
        Rist25519 A = Rist25519::mulGenerator(a);

        memcpy(sendBuff, A.data, Rist25519::size);

        if (mUniformOTs)
        {
            // commit to the seed
            auto comm = mAesFixedKey.ecbEncBlock(seed) ^ seed;
            memcpy(sendBuff + Rist25519::size, &comm, sizeof(block));
        }

        chl.asyncSend(sendBuff, Rist25519::size + mUniformOTs * sizeof(block));

        std::vector<Rist25519> buff(n);
        chl.recv(buff.data(), buff.size());

        if (mUniformOTs)
        {
            // decommit to the seed now that we have their messages.
            chl.send(seed);
        }

        A *= a;
        Rist25519 B, Ba;
        for (u64 i = 0; i < n; ++i)
        {
            B = buff[i];

            Ba = B * a;
            RandomOracle ro(sizeof(block));
            ro.Update(Ba);
            ro.Update(i);
            if (mUniformOTs) ro.Update(seed);
            ro.Final(msg[i][0]);

            Ba -= A;
            ro.Reset();
            ro.Update(Ba);
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
