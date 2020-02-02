#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/RCurve.h>
#ifndef ENABLE_RELIC
#pragma error("ENABLE_RELIC must be defined to build MasnyRindal")
#endif

using Curve = oc::REllipticCurve;
using Point = oc::REccPoint;
using Brick = oc::REccPoint;
using Number = oc::REccNumber;

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
        //std::this_thread::sleep_for(std::chrono::seconds(1));
        auto n = choices.size();
        Curve curve;
        std::array<Point, 2> r{ curve, curve };
        auto g = curve.getGenerator();
        auto pointSize = g.sizeBytes();

        RandomOracle ro(sizeof(block));
        Point hPoint(curve);

        std::vector<u8> hashBuff(roundUpTo(pointSize, 16));
        std::vector<block> aesBuff((pointSize + 15) / 16);
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

                rrNot.randomize();
                rrNot.toBytes(hashBuff.data());
                //lout << "rNot=r"<<(choices[i]^1)<<"  " << rrNot << std::endl;


                //ro.Reset();
                //ro.Update(hashBuff.data(), pointSize);

                //ro.Final<block>(hash);
                //hPoint.randomize(hash);
                //lout << "H(rNot) " << hPoint << std::endl;
                ep_map(hPoint, hashBuff.data(), int(pointSize));

                sk.emplace_back(curve, prng);
#ifdef MASNY_RINDAL_SIM
#else
                rr = g * sk[i];
                rr -= hPoint;
#endif
                //lout << "g^a     " << rr << std::endl;

                //lout << "g^a-h   " << rr << std::endl;

                //lout << "r0      " << r[0] << std::endl;
                //lout << "r1      " << r[1] << std::endl;

                r[0].toBytes(sendBuffIter); sendBuffIter += pointSize;
                r[1].toBytes(sendBuffIter); sendBuffIter += pointSize;
            }

#ifdef MASNY_RINDAL_SIM
            SimplestOT::exp(curStep);
            SimplestOT::add(curStep);
            //std::this_thread::sleep_for(curStep * expTime);
#endif


            if (sendBuffIter != sendBuff.data() + sendBuff.size())
                throw RTE_LOC;


            //lout << std::endl; 

            chl.asyncSend(std::move(sendBuff));
        }


        Point Mb(curve), k(curve);
        fu.get();
        Mb.fromBytes(recvBuff.data());
        //lout << "r Mb " << Mb << std::endl;

#ifdef MASNY_RINDAL_SIM
        SimplestOT::exp(n);
        //std::this_thread::sleep_for(n * expTime);
#endif

        for (u64 i = 0; i < n; ++i)
        {
            k = Mb;
#ifndef MASNY_RINDAL_SIM
            k *= sk[i];
#endif

            //lout << "g^ab  " << k << std::endl;

            k.toBytes(hashBuff.data());
            if (0)
            {
                auto p = (block*)hashBuff.data();
                mAesFixedKey.ecbEncBlocks(p, aesBuff.size(), aesBuff.data());

                // TODO("make this secure");
                messages[i] = ZeroBlock;
                for (auto& b : aesBuff)
                    messages[i] = messages[i] ^ *p++ ^ b;
            }
            else
            {
                ro.Reset();
                ro.Update(hashBuff.data(), pointSize);
                ro.Final(messages[i]);
            }
        }
    }

    void MasnyRindal::send(span<std::array<block, 2>> messages, PRNG & prng, Channel & chl)
    {
        auto n = static_cast<u64>(messages.size());
        
        Curve curve;
        auto g = curve.getGenerator();
        RandomOracle ro(sizeof(block));
        auto pointSize = g.sizeBytes();


        Number sk(curve, prng);

        Point Mb = g;
#ifdef MASNY_RINDAL_SIM
        SimplestOT::exp(1);
        //std::this_thread::sleep_for(expTime);
#else
        Mb *= sk;
#endif


        //lout << "s Mb " << Mb << std::endl;


        std::vector<u8> buff(pointSize), hashBuff(roundUpTo(pointSize, 16));
        std::vector<block> aesBuff((pointSize + 15) / 16);

        Mb.toBytes(buff.data());
        chl.asyncSend(std::move(buff));

        buff.resize(pointSize * 2 * step);
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
                    //ro.Reset();
                    //ro.Update(buffIters[j ^ 1], pointSize);
                    //ro.Final(hh);
                    //pHash.randomize(hh);
                    ep_map(pHash, buffIters[j ^ 1], int(pointSize));

                    //lout << "*r[" << j << "]  " << r << std::endl;
                    //lout << "s"<<j<<"      " << *(u64*)buffIters[j] << std::endl;

                    //lout << "*h(r[" << (j^1) << "]  " << pHash << std::endl;


                    //lout << "g^a" << j << "  " << r << std::endl;


#ifndef MASNY_RINDAL_SIM
                    r += pHash;
                    r *= sk;
#endif
                    //lout << "g^a" << j << "b  " << r << std::endl;

                    r.toBytes(hashBuff.data());
                    auto p = (block*)hashBuff.data();

                    if (0)
                    {
                        mAesFixedKey.ecbEncBlocks(p, aesBuff.size(), aesBuff.data());

                        // TODO("make this secure");
                        messages[i][j] = ZeroBlock;
                        for (auto& b : aesBuff)
                        {
                            messages[i][j] = messages[i][j] ^ *p++ ^ b;
                        }
                    }
                    else
                    {

                        ro.Reset();
                        ro.Update(hashBuff.data(), pointSize);
                        ro.Final(messages[i][j]);
                    }
                }
            }

#ifdef MASNY_RINDAL_SIM
            SimplestOT::add(2 * curStep);
            SimplestOT::exp(2 * curStep);
                //std::this_thread::sleep_for(2*curStep * expTime);
#endif
            if (buffIter != buff.data() + buffSize)
                throw RTE_LOC;
        }

    }
}
#endif