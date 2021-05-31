#ifdef ENABLE_POPF_RISTRETTO

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
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
        Curve curve;

        u64 n = choices.size();
        std::vector<Number> sk; sk.reserve(n);

        unsigned char recvBuff[Point::size];
        auto recvDone = chl.asyncRecv(recvBuff, Point::size);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> sendBuff(n);

        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            sk.emplace_back(prng);
            Point B = Point::mulGenerator(sk[i]);

            sendBuff[i] = popf.program(choices[i], std::move(B), prng);
        }

        chl.asyncSend(std::move(sendBuff));

        recvDone.wait();
        Point A;
        A.fromBytes(recvBuff);

        for (u64 i = 0; i < n; ++i)
        {
            Point B = A * sk[i];

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
        Curve curve;

        u64 n = static_cast<u64>(msg.size());

        Number sk(prng);
        Point A = Point::mulGenerator(sk);

        unsigned char sendBuff[Point::size];
        A.toBytes(sendBuff);
        chl.asyncSend(sendBuff, Point::size);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> recvBuff(n);
        chl.recv(recvBuff.data(), recvBuff.size());

        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            Point Bz = popf.eval(recvBuff[i], 0);
            Point Bo = popf.eval(recvBuff[i], 1);

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
