#include "naor-pinkas.h"

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/SodiumCurve.h>

#define PARALLEL


#ifdef ENABLE_NP

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
        using namespace Sodium;

        // should generalize to 1 out of N by changing this. But isn't tested...
        auto nSndVals(2);
        u64 pointSize = Rist25519::size;

        std::vector<std::thread> thrds(numThreads);
        std::vector<u8> sendBuff(messages.size() * pointSize);
        std::atomic<u32> remainingPK0s((u32)numThreads);
        std::promise<void> PK0Prom;
        std::future<void> PK0Furture(PK0Prom.get_future());
        std::vector<Rist25519> pC(nSndVals);
        auto cRecvFuture = socket.asyncRecv(pC.data(), pC.size()).share();
        block R;

        std::array<u8, RandomOracle::HashSize> comm, comm2;
        socket.asyncRecv(comm);
        auto RFuture = socket.asyncRecv(R).share();

        for (u64 t = 0; t < numThreads; ++t)
        {
            auto seed = prng.get<block>();

            thrds[t] = std::thread(
                [t, numThreads, &messages, seed,
                &sendBuff, &choices, cRecvFuture, &pC,
                &remainingPK0s, &PK0Prom, nSndVals,&RFuture,&R]()
            {

                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                PRNG prng(seed);

                u64 pointSize = Rist25519::size;

                Rist25519 PK0;

                std::vector<Prime25519> pK;
                std::vector<Rist25519> PK_sigma;

                pK.reserve(mEnd - mStart);
                PK_sigma.reserve(mEnd - mStart);

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // get a random value from Z_p
                    pK.emplace_back(prng);

                    // using brickexp which has the base of g, compute
                    //
                    //      PK_sigma[i] = g ^ pK[i]
                    //
                    // where pK[i] is just a random number in Z_p
                    PK_sigma.emplace_back(Rist25519::mulGenerator(pK[j]));
                }

                cRecvFuture.get();

                auto iter = sendBuff.data() + mStart * pointSize;

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    u8 choice = choices[i];
                    if (choice != 0) {
                        PK0 = pC[choice] - PK_sigma[j];
                    }
                    else {
                        PK0 = PK_sigma[j];
                    }

                    memcpy(iter, PK0.data, pointSize);
                    iter += pointSize;
                }

                if (--remainingPK0s == 0)
                    PK0Prom.set_value();

                // resuse this space, not the data of PK0...
                auto& gka = PK0;
                RandomOracle sha(sizeof(block));

                RFuture.get();


                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // now compute g ^(a * k) = (g^a)^k
                    gka = pC[0] * pK[j];


                    auto nounce = i * nSndVals + choices[i];
                    sha.Reset();
                    sha.Update((u8*)&nounce, sizeof(nounce));
                    sha.Update(gka);
                    sha.Update(R);
                    sha.Final(messages[i]);
                }
            });
        }

        PK0Furture.get();

        socket.asyncSend(std::move(sendBuff));

        for (auto& thrd : thrds)
            thrd.join();

        //block comm = *(block*)(cBuff.data() + nSndVals * pointSize);
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
        using namespace Sodium;

        block R = prng.get<block>();
        // one out of nSndVals OT.
        u64 nSndVals(2);
        std::vector<std::thread> thrds(numThreads);
        //auto seed = prng.get<block>();
        Prime25519 alpha(prng);
        u64 pointSize = Rist25519::size;
        std::vector<Rist25519> pC;
        pC.reserve(nSndVals);


        pC.emplace_back(Rist25519::mulGenerator(alpha));

        for (u64 u = 1; u < nSndVals; u++)
            pC.emplace_back(Rist25519::mulGenerator(Prime25519(prng)));

        socket.asyncSend(pC);

        // sends a commitment to R. This strengthens the security of NP01 to
        // make the protocol output uniform strings no matter what.
        RandomOracle ro;
        std::vector<u8> comm(RandomOracle::HashSize);
        ro.Update(R);
        ro.Final(comm.data());
        socket.asyncSend(std::move(comm));


        for (u64 u = 1; u < nSndVals; u++)
            pC[u] = pC[u] * alpha;

        std::vector<Rist25519> buff(messages.size());
        auto recvFuture = socket.asyncRecv(buff.data(), buff.size()).share();

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([
                t, pointSize, &messages, recvFuture,
                    numThreads, &buff, &alpha, nSndVals, &pC,&socket,&R]()
            {
                Rist25519 pPK0, PK0a, fetmp;
                Prime25519 alpha2(alpha);

                std::vector<Rist25519> c;
                c.reserve(nSndVals);
                for (u64 i = 0; i < nSndVals; ++i)
                    c.emplace_back(pC[i]);

                RandomOracle sha(sizeof(block));
                recvFuture.get();

                if (t == 0)
                    socket.asyncSendCopy(R);


                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                for (u64 i = mStart; i < mEnd; i++)
                {

                    pPK0 = buff[i];
                    PK0a = pPK0 * alpha2;


                    auto nounce = i * nSndVals;
                    sha.Reset();
                    sha.Update((u8*)&nounce, sizeof(nounce));
                    sha.Update(PK0a);
                    sha.Update(R);
                    sha.Final(messages[i][0]);

                    for (u64 u = 1; u < nSndVals; u++)
                    {
                        fetmp = c[u] - PK0a;

                        ++nounce;
                        sha.Reset();
                        sha.Update((u8*)&nounce, sizeof(nounce));
                        sha.Update(fetmp);
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
