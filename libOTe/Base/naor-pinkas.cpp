#include "naor-pinkas.h"

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/RCurve.h>


#include <cryptoTools/Crypto/Curve.h>

#define PARALLEL


#ifdef ENABLE_NP

#include <memory>

namespace osuCrypto
{

#ifdef ENABLE_RELIC
    using Curve = REllipticCurve;
    using Point = REccPoint;
    using Brick = REccPoint;
    using Number = REccNumber;
#else    
    using Curve = EllipticCurve;
    using Point = EccPoint;
    using Brick = EccBrick;
    using Number = EccNumber;
#endif
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
        // should generalize to 1 out of N by changing this. But isn't tested...
        auto nSndVals(2);
        Curve curve;
        auto g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();

        std::vector<std::thread> thrds(numThreads);
        std::vector<u8> sendBuff(messages.size() * fieldElementSize);
        std::atomic<u32> remainingPK0s((u32)numThreads);
        std::promise<void> PK0Prom;
        std::future<void> PK0Furture(PK0Prom.get_future());
        std::vector<u8> cBuff(nSndVals * fieldElementSize);
        auto cRecvFuture = socket.asyncRecv(cBuff.data(), cBuff.size()).share();
        block R;

        std::array<u8, RandomOracle::HashSize> comm, comm2;
        socket.asyncRecv(comm);
        auto RFuture = socket.asyncRecv(R).share();

        for (u64 t = 0; t < numThreads; ++t)
        {
            auto seed = prng.get<block>();

            thrds[t] = std::thread(
                [t, numThreads, &messages, seed, 
                &sendBuff, &choices, cRecvFuture, &cBuff,
                &remainingPK0s, &PK0Prom, nSndVals,&RFuture,&R]()
            {

                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                PRNG prng(seed);
                Curve curve;

                auto g = curve.getGenerator();
                u64 fieldElementSize = g.sizeBytes();

                Point PK0(curve);
                Brick bg(g);

                std::vector<Number> pK;
                std::vector<Point>
                    PK_sigma,
                    pC;

                pK.reserve(mEnd - mStart);
                PK_sigma.reserve(mEnd - mStart);
                pC.reserve(nSndVals);

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // get a random value from Z_p
                    pK.emplace_back(curve);
                    pK[j].randomize(prng);

                    // using brickexp which has the base of g, compute
                    //
                    //      PK_sigma[i] = g ^ pK[i]
                    //
                    // where pK[i] is just a random number in Z_p
                    PK_sigma.emplace_back(curve);
                    PK_sigma[j] = bg * pK[j];
                }


                cRecvFuture.get();
                auto pBufIdx = cBuff.begin();
                for (auto u = 0; u < nSndVals; u++)
                {
                    pC.emplace_back(curve);

                    pC[u].fromBytes(&*pBufIdx);
                    pBufIdx += fieldElementSize;
                }

                auto iter = sendBuff.data() + mStart * fieldElementSize;

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    u8 choice = choices[i];
                    if (choice != 0) {
                        PK0 = pC[choice] - PK_sigma[j]; 
                    }
                    else {
                        PK0 = PK_sigma[j];
                    }

                    PK0.toBytes(iter);
                    iter += fieldElementSize;
                }

                if (--remainingPK0s == 0)
                    PK0Prom.set_value();

                // resuse this space, not the data of PK0...
                auto& gka = PK0;
                RandomOracle sha(sizeof(block));

                std::vector<u8>buff(fieldElementSize);
                Brick bc(pC[0]);

                RFuture.get();


                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // now compute g ^(a * k) = (g^a)^k
                    gka = bc * pK[j];
                    gka.toBytes(buff.data());

                    sha.Reset();
                    sha.Update((u8*)&i, sizeof(i));
                    sha.Update(buff.data(), buff.size());
                    sha.Update(R);
                    sha.Final(messages[i]);
                }
            }); 
        }

        PK0Furture.get();

        socket.asyncSend(std::move(sendBuff));

        for (auto& thrd : thrds)
            thrd.join();

        //block comm = *(block*)(cBuff.data() + nSndVals * fieldElementSize);
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
        auto seed = prng.get<block>();
        Curve curve;
        Number alpha(curve, prng), tmp(curve);
        const Point g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        std::vector<u8> sendBuff(nSndVals * fieldElementSize);
        std::vector<Point> pC;
        pC.reserve(nSndVals);


		pC.emplace_back(curve);
        pC[0] = g * alpha;
        pC[0].toBytes(sendBuff.data());

        for (u64 u = 1; u < nSndVals; u++)
        {
            pC.emplace_back(curve);
            tmp.randomize(prng);

			pC[u] = g * tmp;
            pC[u].toBytes(sendBuff.data() + u * fieldElementSize);
        }

        socket.asyncSend(std::move(sendBuff));

        // sends a commitment to R. This strengthens the security of NP01 to 
        // make the protocol output uniform strings no matter what.
        RandomOracle ro;
        std::vector<u8> comm(RandomOracle::HashSize);
        ro.Update(R);
        ro.Final(comm.data());
        socket.asyncSend(std::move(comm));


        for (u64 u = 1; u < nSndVals; u++)
            pC[u] = pC[u] * alpha;

        std::vector<u8> buff(fieldElementSize * messages.size());
        auto recvFuture = socket.asyncRecv(buff.data(), buff.size()).share();

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([
                t, seed, fieldElementSize, &messages, recvFuture,
                    numThreads, &buff, &alpha, nSndVals, &pC,&socket,&R]()
            {
                Curve curve;
                Point pPK0(curve), PK0a(curve), fetmp(curve);
                Number alpha2(curve, alpha);

                std::vector<Point> c;
                c.reserve(nSndVals);
                for (u64 i = 0; i < nSndVals; ++i)
                    c.emplace_back(curve, pC[i]);

                std::vector<u8> hashInBuff(fieldElementSize);
                RandomOracle sha(sizeof(block));
                recvFuture.get();

                if (t == 0)
                    socket.asyncSendCopy(R);
                

                for (u64 i = 0; i < u64(messages.size()); i++)
                {

                    pPK0.fromBytes(buff.data() + i * fieldElementSize);
                    PK0a = pPK0 * alpha2;
                    PK0a.toBytes(hashInBuff.data());

                    sha.Reset();
                    sha.Update((u8*)&i, sizeof(i));
                    sha.Update(hashInBuff.data(), hashInBuff.size());
                    sha.Update(R);
                    sha.Final(messages[i][0]);

                    for (u64 u = 1; u < nSndVals; u++)
                    {
                        fetmp = c[u] - PK0a;
                        fetmp.toBytes(hashInBuff.data());

                        sha.Reset();
                        sha.Update((u8*)&i, sizeof(i));
                        sha.Update(hashInBuff.data(), hashInBuff.size());
                        sha.Update(R);
                        sha.Final(messages[i][u]);
                    }
                }
            });
        }

        for (auto& thrd : thrds)
            thrd.join();
    }
}

#endif
