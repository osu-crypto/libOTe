#include "naor-pinkas.h"

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#if defined(ENABLE_SODIUM)
#include <cryptoTools/Crypto/SodiumCurve.h>
#elif defined(ENABLE_RELIC)
#include <cryptoTools/Crypto/RCurve.h>
#endif

#define PARALLEL


#ifdef ENABLE_NP

#include <memory>

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
#endif
    }

    //static const  u64 minMsgPerThread(16);

    NaorPinkas::NaorPinkas()
    {

    }


    NaorPinkas::~NaorPinkas()
    {

    }


    void NaorPinkas::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& socket,
        u64 numThreads)
    {
        auto nSndVals(2);

#ifndef ENABLE_SODIUM
        Curve curve;
#endif
        const auto pointSize = Point::size;

        std::vector<std::thread> thrds(numThreads);
        std::vector<u8> sendBuff(messages.size() * pointSize);
        std::atomic<u32> remainingPK0s((u32)numThreads);

        std::vector<u8> cBuff(nSndVals * pointSize);
        auto cRecvFuture = socket.asyncRecv(cBuff.data(), cBuff.size()).share();
        block R;

        std::array<u8, RandomOracle::HashSize> comm, comm2;
        auto commFuture = socket.asyncRecv(comm);
        auto RFuture = socket.asyncRecv(R).share();

        for (u64 t = 0; t < numThreads; ++t)
        {
            auto seed = prng.get<block>();

            thrds[t] = std::thread(
                [t, numThreads, &messages, seed, pointSize,
                &sendBuff, &choices, cRecvFuture, &cBuff,
                &remainingPK0s, &socket, nSndVals,&RFuture,&R]()
            {

                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                PRNG prng(seed);

#ifndef ENABLE_SODIUM
                Curve curve;
#endif

                std::vector<Number> pK;
                std::vector<Point>
                    PK_sigma,
                    pC;

                pK.reserve(mEnd - mStart);
                PK_sigma.reserve(mEnd - mStart);
                pC.reserve(nSndVals);

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    pK.emplace_back(prng);
                    PK_sigma.emplace_back(Point::mulGenerator(pK[j]));
                }

                cRecvFuture.get();
                for (auto u = 0; u < nSndVals; u++)
                {
                    pC.emplace_back();
                    pC[u].fromBytes(&cBuff[pointSize * u]);
                }

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    u8 choice = choices[i];
                    Point PK0 = std::move(PK_sigma[j]);
                    if (choice != 0) {
                        PK0 = pC[choice] - PK0;
                    }

                    PK0.toBytes(&sendBuff[pointSize * i]);
                }

                if (--remainingPK0s == 0)
                    socket.asyncSend(std::move(sendBuff));

                RandomOracle ro(sizeof(block));

                std::vector<u8> hashBuff(pointSize);

                RFuture.get();

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // now compute g ^(a * k) = (g^a)^k
                    Point gka = pC[0] * pK[j];

                    auto nounce = i * nSndVals + choices[i];
                    ro.Reset();
                    ro.Update((u8*)&nounce, sizeof(nounce));
#ifdef ENABLE_SODIUM
                    ro.Update(gka);
#else
                    gka.toBytes(hashBuff.data());
                    ro.Update(hashBuff.data(), hashBuff.size());
#endif
                    ro.Update(R);
                    ro.Final(messages[i]);
                }
            });
        }

        for (auto& thrd : thrds)
            thrd.join();

        commFuture.get();
        RandomOracle ro;
        ro.Update(R);
        ro.Final(comm2);
        if (comm != comm2)
            throw std::runtime_error("bad commitment " LOCATION);

    }


    void NaorPinkas::send(
        span<std::array<block, 2>> messages,
        PRNG & prng,
        Channel& socket,
        u64 numThreads)
    {
        block R = prng.get<block>();
        // one out of nSndVals OT.
        u64 nSndVals(2);
        std::vector<std::thread> thrds(numThreads);
        //auto seed = prng.get<block>();

        std::vector<Point> pC;
        pC.reserve(nSndVals);

#ifndef ENABLE_SODIUM
        Curve curve;
#endif
        const auto pointSize = Point::size;
        Number alpha(prng);
        pC.emplace_back(Point::mulGenerator(alpha));

        std::vector<u8> sendBuff(nSndVals * pointSize);
        pC[0].toBytes(sendBuff.data());

        for (u64 u = 1; u < nSndVals; u++)
        {
            // TODO: Faster to use hash to curve to randomize?
            pC.emplace_back(Point::mulGenerator(Number(prng)));
            pC[u].toBytes(&sendBuff[pointSize * u]);
        }

        socket.asyncSend(std::move(sendBuff));

        // sends a commitment to R. This strengthens the security of NP01 to
        // make the protocol output uniform strings no matter what.
        RandomOracle ro;
        std::vector<u8> comm(RandomOracle::HashSize);
        ro.Update(R);
        ro.Final(comm.data());
        socket.send(comm);


        for (u64 u = 1; u < nSndVals; u++)
            pC[u] *= alpha;

        std::vector<u8> buff(pointSize * messages.size());
        auto recvFuture = socket.asyncRecv(buff.data(), buff.size()).share();

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([
                t, pointSize, &messages, recvFuture,
                    numThreads, &buff, &alpha, nSndVals, &pC,&socket,&R]()
            {
#ifndef ENABLE_SODIUM
                Curve curve;
#endif
                Point pPK0;
                const Number& alpha2 = alpha;
                const std::vector<Point>& c = pC;

#ifndef ENABLE_SODIUM
                std::vector<u8> hashInBuff(pointSize);
#endif

                RandomOracle ro(sizeof(block));
                recvFuture.get();

                if (t == 0)
                    socket.asyncSendCopy(R);


                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                for (u64 i = mStart; i < mEnd; i++)
                {

                    pPK0.fromBytes(&buff[pointSize * i]);
                    pPK0 *= alpha2;


                    auto nounce = i * nSndVals;
                    ro.Reset();
                    ro.Update((u8*)&nounce, sizeof(nounce));
#ifdef ENABLE_SODIUM
                    ro.Update(pPK0);
#else
                    pPK0.toBytes(hashInBuff.data());
                    ro.Update(hashInBuff.data(), hashInBuff.size());
#endif
                    ro.Update(R);
                    ro.Final(messages[i][0]);

                    for (u64 u = 1; u < nSndVals; u++)
                    {
                        Point fetmp = c[u] - pPK0;

                        ++nounce;
                        ro.Reset();
                        ro.Update((u8*)&nounce, sizeof(nounce));
#ifdef ENABLE_SODIUM
                        ro.Update(fetmp);
#else
                        fetmp.toBytes(hashInBuff.data());
                        ro.Update(hashInBuff.data(), hashInBuff.size());
#endif
                        ro.Update(R);
                        ro.Final(messages[i][u]);
                    }
                }
            });
        }

        for (auto& thrd : thrds)
            thrd.join();
    }
}

#endif
