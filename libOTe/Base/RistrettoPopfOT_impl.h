#ifdef ENABLE_POPF

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Network/Channel.h>

namespace osuCrypto
{
    template<typename DSPopf>
    void RistrettoPopfOT<DSPopf>::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        u64 n = choices.size();

        std::vector<Prime25519> sk; sk.reserve(n);

        Rist25519 A;
        auto recvDone = chl.asyncRecv(&A, 1);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> sendBuff(n);

        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            sk.emplace_back(prng);
            Rist25519 B = Rist25519::mulGenerator(sk[i]);

            sendBuff[i] = popf.program(choices[i], B, prng);
        }

        chl.asyncSend(std::move(sendBuff));

        recvDone.wait();

        for (u64 i = 0; i < n; ++i)
        {
            Rist25519 B = A * sk[i];

            RandomOracle ro(sizeof(block));
            ro.Update(B);
            ro.Update(i);
            ro.Update((bool) choices[i]);
            ro.Final(messages[i]);
        }
    }

    template<typename DSPopf>
    void RistrettoPopfOT<DSPopf>::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        u64 n = static_cast<u64>(msg.size());

        Prime25519 sk(prng);
        Rist25519 A = Rist25519::mulGenerator(sk);

        chl.asyncSend(&A, 1);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> recvBuff(n);
        chl.recv(recvBuff.data(), recvBuff.size());


        Rist25519 Bz, Bo;
        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            Bz = popf.eval(recvBuff[i], 0);
            Bo = popf.eval(recvBuff[i], 1);

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


