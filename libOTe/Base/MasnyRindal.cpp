#include "MasnyRindal.h"

#ifdef ENABLE_MASNYRINDAL

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/RCurve.h>
using Curve = oc::REllipticCurve;
using Point = oc::REccPoint;
using Brick = oc::REccPoint;
using Number = oc::REccNumber;


namespace osuCrypto
{
    const u64 step = 16;

    void MasnyRindal::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        //std::this_thread::sleep_for(std::chrono::seconds(1));
        auto n = choices.size();
        Curve curve;
        std::array<Point, 2> r{ curve, curve };
        auto g = curve.getGenerator();
        auto pointSize = g.sizeBytes();

        RandomOracle ro(sizeof(block));
        block hash;
        Point hPoint(curve);

        std::vector<u8> hashBuff(pointSize);
        std::vector<Number> sk; sk.reserve(n);


        std::vector<u8> recvBuff(pointSize);
        auto fu = chl.asyncRecv(recvBuff.data(), pointSize);

        for (u64 i = 0; i < n;)
        {
            auto curStep = std::min<u64>(n - i, step);

            std::vector<u8> sendBuff(pointSize * 2 * curStep);
            auto sendBuffIter = sendBuff.data();


            for (u64 k = 0; k < curStep; ++k, ++i)
            {

                auto& rrNot = r[choices[i] ^ 1];
                auto& rr = r[choices[i]];

                rrNot.randomize(prng.get<block>());
                rrNot.toBytes(hashBuff.data());
                //lout << "rNot=r"<<(choices[i]^1)<<"  " << rrNot << std::endl;

                ro.Reset();
                ro.Update(hashBuff.data(), hashBuff.size());

                ro.Final<block>(hash);
                hPoint.randomize(hash);
                //lout << "H(rNot) " << hPoint << std::endl;

                sk.emplace_back(curve, prng);
                rr = g * sk[i];

                //lout << "g^a     " << rr << std::endl;

                rr -= hPoint;
                //lout << "g^a-h   " << rr << std::endl;

                //lout << "r0      " << r[0] << std::endl;
                //lout << "r1      " << r[1] << std::endl;

                r[0].toBytes(sendBuffIter); sendBuffIter += pointSize;
                r[1].toBytes(sendBuffIter); sendBuffIter += pointSize;
            }

            if (sendBuffIter != sendBuff.data() + sendBuff.size())
                throw RTE_LOC;


            //lout << std::endl;

            chl.asyncSend(std::move(sendBuff));
        }


        Point Mb(curve), k(curve);
        fu.get();
        Mb.fromBytes(recvBuff.data());
        //lout << "r Mb " << Mb << std::endl;

        for (u64 i = 0; i < n; ++i)
        {
            k = Mb;
            k *= sk[i];
            //lout << "g^ab  " << k << std::endl;

            k.toBytes(hashBuff.data());
            ro.Reset();
            ro.Update(hashBuff.data(), pointSize);
            ro.Final(messages[i]);
        }
    }

    void MasnyRindal::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        auto n = messages.size();
        
        Curve curve;
        auto g = curve.getGenerator();
        RandomOracle ro(sizeof(block));
        auto pointSize = g.sizeBytes();


        Number sk(curve, prng);
        Point Mb = g * sk;

        //lout << "s Mb " << Mb << std::endl;

        std::vector<u8> buff(pointSize), hashBuff(pointSize);
        Mb.toBytes(buff.data());
        chl.asyncSend(std::move(buff));

        buff.resize(pointSize * 2 * step);
        block hh;
        Point pHash(curve), r(curve);

        for (u64 i = 0; i < n; )
        {
            auto curStep = std::min<u64>(n - i, step);

            auto buffSize = curStep * pointSize * 2;
            chl.recv(buff.data(), buffSize);
            auto buffIter = buff.data();


            for (u64 k = 0; k < curStep; ++k, ++i)
            {
                std::array<u8*, 2> buffIters{
                    buffIter,
                    buffIter + pointSize
                };
                buffIter += pointSize * 2;

                for (u64 j = 0; j < 2; ++j)
                {

                    r.fromBytes(buffIters[j]);
                    ro.Reset();
                    ro.Update(buffIters[j ^ 1], pointSize);
                    ro.Final(hh);
                    pHash.randomize(hh);

                    //lout << "*r[" << j << "]  " << r << std::endl;
                    //lout << "s"<<j<<"      " << *(u64*)buffIters[j] << std::endl;

                    //lout << "*h(r[" << (j^1) << "]  " << pHash << std::endl;

                    r += pHash;

                    //lout << "g^a" << j << "  " << r << std::endl;


                    r *= sk;
                    //lout << "g^a" << j << "b  " << r << std::endl;

                    r.toBytes(hashBuff.data());
                    ro.Reset();
                    ro.Update(hashBuff.data(), pointSize);
                    ro.Final(messages[i][j]);
                }
            }

            if (buffIter != buff.data() + buffSize)
                throw RTE_LOC;
        }

    }
}
#endif