#ifdef ENABLE_POPF

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Network/Channel.h>

namespace osuCrypto
{
    template<typename DerivedDSPopf>
    void PopfOT<DerivedDSPopf>::blockToCurve(Point& p, Block256 b)
    {
        unsigned char buf[sizeof(Block256) + 1];
        buf[0] = 2;
        memcpy(&buf[1], b.data(), sizeof(b));
        p.fromBytes(buf);
    }

    template<typename DerivedDSPopf>
    Block256 PopfOT<DerivedDSPopf>::curveToBlock(const Point& p)
    {
        unsigned char buf[sizeof(Block256) + 1];
        p.toBytes(buf);
        return Block256(&buf[1]);
    }

    template<typename DerivedDSPopf>
    void PopfOT<DerivedDSPopf>::receive(
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

        std::vector<Number> sk; sk.reserve(n);
        std::vector<u8> curveChoice; curveChoice.reserve(n);

        std::array<Block256, 2> recvBuff;
        auto recvDone = chl.asyncRecv(recvBuff);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> sendBuff(n);

        Point B(curve);
        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

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

            sendBuff[i] = popf.program(choices[i], curveToBlock(B));
        }

        chl.asyncSend(std::move(sendBuff));

        recvDone.wait();

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

    template<typename DerivedDSPopf>
    void PopfOT<DerivedDSPopf>::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        Point gprime = curve.getGenerator();
        assert(g.sizeBytes() == sizeof(Block256) + 1);
        u64 n = static_cast<u64>(msg.size());

        Number sk(curve, prng);
        Point A = g * sk;
        Point Aprime = gprime * sk;
        std::array<Block256, 2> sendBuff = {curveToBlock(A), curveToBlock(Aprime)};

        chl.asyncSend(sendBuff);

        std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> recvBuff(n);
        chl.recv(recvBuff.data(), recvBuff.size());


        Point Bz(curve), Bo(curve);
        for (u64 i = 0; i < n; ++i)
        {
            auto factory = popfFactory;
            factory.Update(i);
            auto popf = factory.construct();

            blockToCurve(Bz, popf.eval(recvBuff[i], 0));
            blockToCurve(Bo, popf.eval(recvBuff[i], 1));

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


