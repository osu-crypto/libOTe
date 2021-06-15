#ifdef ENABLE_POPF_MOELLER

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Network/Channel.h>

namespace osuCrypto
{
    template<typename DSPopf>
    auto MoellerPopfOT<DSPopf>::blockToCurve(Block256 b) -> Monty25519
    {
        static_assert(Monty25519::size == sizeof(Block256),"");
        return Monty25519(b.data());
    }

    template<typename DSPopf>
    Block256 MoellerPopfOT<DSPopf>::curveToBlock(Monty25519 p, PRNG& prng)
    {
        p.data[Monty25519::size - 1] ^= prng.getBit() << 7;

        static_assert(Monty25519::size == sizeof(Block256),"");
        return Block256(p.data);
    }

    template<typename DSPopf>
    void MoellerPopfOT<DSPopf>::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        u64 n = choices.size();

        std::vector<Scalar25519> sk; sk.reserve(n);
        std::vector<u8> curveChoice; curveChoice.reserve(n);

        Monty25519 A[2];
        auto recvDone = chl.asyncRecv(A, 2);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> sendBuff(n);

        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            curveChoice.emplace_back(prng.getBit());
            sk.emplace_back(prng, false);
            Monty25519 g = (curveChoice[i] == 0) ?
                Monty25519::wholeGroupGenerator : Monty25519::wholeTwistGroupGenerator;
            Monty25519 B = g * sk[i];

            sendBuff[i] = popf.program(choices[i], curveToBlock(B, prng), prng);
        }

        chl.asyncSend(std::move(sendBuff));

        recvDone.wait();

        for (u64 i = 0; i < n; ++i)
        {
            Monty25519 B = A[curveChoice[i]] * sk[i];

            RandomOracle ro(sizeof(block));
            ro.Update(B);
            ro.Update(i);
            ro.Update((bool) choices[i]);
            ro.Final(messages[i]);
        }
    }

    template<typename DSPopf>
    void MoellerPopfOT<DSPopf>::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        u64 n = static_cast<u64>(msg.size());

        Scalar25519 sk(prng);
        Monty25519 A[2] = {
            Monty25519::wholeGroupGenerator * sk, Monty25519::wholeTwistGroupGenerator * sk};

        chl.asyncSend(A, 2);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> recvBuff(n);
        chl.recv(recvBuff.data(), recvBuff.size());


        Monty25519 Bz, Bo;
        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            Bz = blockToCurve(popf.eval(recvBuff[i], 0));
            Bo = blockToCurve(popf.eval(recvBuff[i], 1));

            // We don't need to check which curve we're on since we use the same secret for both.
            Bz *= sk;
            Bo *= sk;

            RandomOracle ro(sizeof(block));
            ro.Update(Bz);
            ro.Update(i);
            ro.Update((bool) 0);
            ro.Final(msg[i][0]);

            ro.Reset();
            ro.Update(Bo);
            ro.Update(i);
            ro.Update((bool) 1);
            ro.Final(msg[i][1]);
        }
    }
}
#endif


