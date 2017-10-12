#include "naor-pinkas.h"

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/Curve.h>
#include <cryptoTools/Crypto/sha1.h>
#include <cryptoTools/Network/Channel.h>

#define PARALLEL


#include <memory>

namespace osuCrypto
{
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
        const auto& params = k233;
        block seed = prng.get<block>();

        EllipticCurve curve(params, seed);
        auto& g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();

        std::vector<std::thread> thrds(numThreads);
        std::vector<u8> sendBuff(messages.size() * fieldElementSize);
        std::atomic<u32> remainingPK0s((u32)numThreads);
        std::promise<void> PK0Prom;
        std::future<void> PK0Furture(PK0Prom.get_future());
        std::vector<u8> cBuff(nSndVals * fieldElementSize);
        auto cRecvFuture = socket.asyncRecv(cBuff.data(), cBuff.size()).share();

        for (u64 t = 0; t < numThreads; ++t)
        {
            seed = prng.get<block>();

            thrds[t] = std::thread(
                [t, numThreads, &messages, seed, params,
                &sendBuff, &choices, cRecvFuture, &cBuff,
                &remainingPK0s, &PK0Prom, nSndVals]()
            {

                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                PRNG prng(seed);
                EllipticCurve curve(params, prng.get<block>());

                auto& g = curve.getGenerator();
                u64 fieldElementSize = g.sizeBytes();

                EccPoint PK0(curve);
                EccBrick bg(g);

                std::vector<EccNumber> pK;
                std::vector<EccPoint>
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
                SHA1 sha;

                std::vector<u8>buff(fieldElementSize);
                EccBrick bc(pC[0]);

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // now compute g ^(a * k) = (g^a)^k
                    gka = bc * pK[j];
                    gka.toBytes(buff.data());

                    sha.Reset();
                    sha.Update((u8*)&i, sizeof(i));
                    sha.Update(buff.data(), buff.size());
                    sha.Final(messages[i]);
                }
            });
        }

        PK0Furture.get();

        socket.asyncSend(std::move(sendBuff));

        for (auto& thrd : thrds)
            thrd.join();

    }


    void NaorPinkas::send(
        span<std::array<block, 2>> messages,
        PRNG & prng,
        Channel& socket,
        u64 numThreads)
    {
        // one out of nSndVals OT.
        u64 nSndVals(2);
        auto& params = k233;
        std::vector<std::thread> thrds(numThreads);
        auto seed = prng.get<block>();
        EllipticCurve curve(params, seed);
        EccNumber alpha(curve, prng), tmp(curve);
        const EccPoint& g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        std::vector<u8> sendBuff(nSndVals * fieldElementSize);
        std::vector<EccPoint> pC;
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

        for (u64 u = 1; u < nSndVals; u++)
            pC[u] = pC[u] * alpha;

        std::vector<u8> buff(fieldElementSize * messages.size());
        auto recvFuture = socket.asyncRecv(buff.data(), buff.size()).share();

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([
                t, seed, fieldElementSize, &messages, recvFuture,
                    numThreads, &buff, &alpha, nSndVals, &pC, &params]()
            {
                EllipticCurve curve(params, seed);
                EccPoint pPK0(curve), PK0a(curve), fetmp(curve);
                EccNumber alpha2(curve, alpha);

                std::vector<EccPoint> c;
                c.reserve(nSndVals);
                for (u64 i = 0; i < nSndVals; ++i)
                    c.emplace_back(curve, pC[i]);

                std::vector<u8> hashInBuff(fieldElementSize);
                SHA1 sha;
                recvFuture.get();

                for (u64 i = 0; i < u64(messages.size()); i++)
                {

                    pPK0.fromBytes(buff.data() + i * fieldElementSize);
                    PK0a = pPK0 * alpha2;
                    PK0a.toBytes(hashInBuff.data());

                    sha.Reset();
                    sha.Update((u8*)&i, sizeof(i));
                    sha.Update(hashInBuff.data(), hashInBuff.size());
                    sha.Final(messages[i][0]);

                    for (u64 u = 1; u < nSndVals; u++)
                    {
                        fetmp = c[u] - PK0a;
                        fetmp.toBytes(hashInBuff.data());

                        sha.Reset();
                        sha.Update((u8*)&i, sizeof(i));
                        sha.Update(hashInBuff.data(), hashInBuff.size());
                        sha.Final(messages[i][u]);
                    }
                }
            });
        }

        for (auto& thrd : thrds)
            thrd.join();
    }
}
