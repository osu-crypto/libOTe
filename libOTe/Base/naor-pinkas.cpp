#include "naor-pinkas.h"
#include "Common/Log.h"
#include <memory>
#include "Common/Timer.h"
#include "Crypto/Curve.h"

#define PARALLEL

#include "Common/ByteStream.h"
#include "Common/BitVector.h"
#include "Crypto/sha1.h"

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
        ArrayView<block> messages,
        PRNG& prng,
        Channel& socket,
        u64 numThreads)
    {
        // should generalize to 1 out of N by changing this. But isn't tested...
        auto nSndVals(2);
        //auto eccSecLevel = LT;

        //auto numThreads = (messages.size() + minMsgPerThread - 1) / minMsgPerThread;
        const auto& params = k233;

        block seed = prng.get<block>();

        EllipticCurve curve(params, seed);
        auto& g = curve.getGenerator();

        //std::unique_ptr<pk_crypto> mainPkGen(new ecc_field(eccSecLevel, (u8*)&seed));
        //uint32_t fieldElementSize = mainPkGen->fe_byte_size();
        u64 fieldElementSize = g.sizeBytes();

        std::vector<std::thread> thrds(numThreads);
        std::unique_ptr<ByteStream> sendBuff(new ByteStream());
        sendBuff->resize(messages.size() * fieldElementSize);



        std::atomic<u32> remainingPK0s((u32)numThreads);
        std::promise<void>/* recvProm,*/ PK0Prom;
        //std::shared_future<void> recvFuture(recvProm.get_future());
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

                    //std::cout << "rand? " << pK[j] << std::endl;

                    // using brickexp which has the base of g, compute
                    //
                    //      PK_sigma[i] = g ^ pK[i]
                    //
                    // where pK[i] is just a random number in Z_p
                    PK_sigma.emplace_back(curve);
                    PK_sigma[j] = bg * pK[j];

                    //std::cout << "c " << PK_sigma[j] << std::endl;
                    //std::cout << "v " << g * pK[j] << std::endl;
                }


                cRecvFuture.get();
                auto pBufIdx = cBuff.begin();

                for (auto u = 0; u < nSndVals; u++)
                {
                    pC.emplace_back(curve);

                    pC[u].fromBytes(&*pBufIdx);
                    pBufIdx += fieldElementSize;
                }


                auto iter = sendBuff->data() + mStart * fieldElementSize;


                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    u8 choice = choices[i];

                    if (choice != 0) {
                        PK0 = pC[choice] - PK_sigma[j]; // ->set_div(, );
                    }
                    else {
                        PK0 = PK_sigma[j];
                    }

                    PK0.toBytes(iter);
                    iter += fieldElementSize;

                    //std::cout
                    //    << "for msg " << i << "  (recver)" << std::endl
                    //    << "  PK0:        " << PK0->toString() << std::endl
                    //    << "  PK_sigma:   " << PK_sigma[j]->toString() << std::endl
                    //    << "  choice:     " << choice << std::endl
                    //    << "  pC[choice]: " << pC[choice]->toString() << std::endl;

                }

                //std::cout << *sendBuff << std::endl;

                if (--remainingPK0s == 0)
                    PK0Prom.set_value();

                //socket.asyncSend(std::move(sendBuff));



                //u8 shaBuff[SHA1::HashSize];

                ByteStream bs;
                bs.resize(SHA1::HashSize);

                // resuse this space, not the data of PK0...
                auto& gka = PK0;
                SHA1 sha;

                std::vector<u8>buff(fieldElementSize);
                //std::unique_ptr<brickexp>bc(thrdPkGen->get_brick(pC[0]));
                EccBrick bc(pC[0]);

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // now compute g ^(a * k) = (g^a)^k 

                    gka = bc * pK[j];
                    gka.toBytes(buff.data());

                    sha.Reset();
                    sha.Update((u8*)&i, sizeof(i));
                    sha.Update(buff.data(), buff.size());
                    sha.Final(bs.data());

                    messages[i] = *(block*)bs.data();

                    //std::cout
                    //    << "for msg " << i << ", " << choices[i] << "  (recver)" << std::endl
                    //    << "  pDec[i]:    " << gka << std::endl
                    //    << "  msg         " << messages[i]  << "  " << ByteStream(buff.data(), buff.size()) << "   " << bs << std::endl;
                }


                //for (auto ptr : pK)
                //    delete ptr;
                //for (auto ptr : PK_sigma)
                //    delete ptr;
                //for (auto ptr : pC)
                //    delete ptr;
            });
        }

        PK0Furture.get();

        socket.asyncSend(std::move(sendBuff));

        for (auto& thrd : thrds)
            thrd.join();

    }


    void NaorPinkas::send(
        ArrayView<std::array<block, 2>> messages,
        PRNG & prng,
        Channel& socket,
        u64 numThreads)
    {
        // one out of nSndVals OT.
        u64 nSndVals(2);
        auto& params = k233;

        //auto numThreads = (messages.size() + minMsgPerThread - 1) / minMsgPerThread;

        std::vector<std::thread> thrds(numThreads);



        auto seed = prng.get<block>();
        EllipticCurve curve(params, seed);
        //std::unique_ptr<ecc_field> mainPk(new ecc_field(LT, (u8*)&seed));

        //std::unique_ptr<num>
        EccNumber
            alpha(curve, prng),//(mainPk->get_rnd_num()),
                               //PKr(curve),//(mainPk->get_num()),
            tmp(curve);

        //std::unique_ptr<fe>
        const EccPoint&
            g = curve.getGenerator();

        //std::cout << "send g " << g << std::endl;

        u64 fieldElementSize = g.sizeBytes();// ->fe_byte_size();


        std::unique_ptr<ByteStream> sendBuff(new ByteStream());
        sendBuff->resize(nSndVals * fieldElementSize);


        std::vector<EccPoint> pC;
        pC.reserve(nSndVals);

        pC.emplace_back(curve);
        pC[0] = g * alpha;// ->set_pow(g.get(), alpha.get());
        pC[0].toBytes(sendBuff->data());


        //std::cout << "send c[0] " << pC[0] << std::endl;

        for (u64 u = 1; u < nSndVals; u++)
        {
            pC.emplace_back(curve);
            //pC[u] = mainPk->get_fe();
            //tmp.reset(mainPk->get_rnd_num());
            tmp.randomize(prng);

            //pC[u]->set_pow(g.get(), tmp.get());
            pC[u] = g * tmp;// ->set_pow(g.get(), tmp.get());

                            //std::cout << "send c["<< u <<"] " << pC[0] << " = g * " << tmp << std::endl;


            pC[u].toBytes(sendBuff->data() + u * fieldElementSize);
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
                //std::unique_ptr<ecc_field> thrdPK(new ecc_field(LT, (u8*)&seed));

                //std::unique_ptr<fe>
                EccPoint
                    pPK0(curve),//(thrdPK->get_fe()),
                    PK0a(curve),//(thrdPK->get_fe()),
                    fetmp(curve);//(thrdPK->get_fe());


                EccNumber alpha2(curve, alpha);

                std::vector<EccPoint> c;
                c.reserve(nSndVals);

                for (u64 i = 0; i < nSndVals; ++i)
                {
                    c.emplace_back(curve, pC[i]);
                }

                std::vector<u8> hashInBuff(fieldElementSize);
                u8 shaBuff[SHA1::HashSize];
                SHA1 sha;


                //auto mStart = t * messages.size() / numThreads;
                //auto mEnd = (t + 1) * messages.size() / numThreads;

                recvFuture.get();

                for (u64 i = 0; i < messages.size(); i++)
                {

                    pPK0.fromBytes(buff.data() + i * fieldElementSize);
                    //pPK0->import_from_bytes(buff.data() + i * fieldElementSize);

                    //std::cout
                    //    << "for msg " << i << "  (sender)" << std::endl
                    //    << "  pPK0[i]:    " << pPK0 << std::endl;


                    PK0a = pPK0 * alpha2;
                    //PK0a->set_pow(pPK0.get(), alpha.get());
                    PK0a.toBytes(hashInBuff.data());

                    sha.Reset();
                    sha.Update((u8*)&i, sizeof(i));
                    sha.Update(hashInBuff.data(), hashInBuff.size());
                    sha.Final(shaBuff);

                    messages[i][0] = *(block*)shaBuff;

                    //std::cout
                    //    << "for msg " << i << ", 0  (sender)" << std::endl
                    //    << "  PK0^a:    " << PK0a << std::endl;

                    for (u64 u = 1; u < nSndVals; u++)
                    {
                        fetmp = c[u] - PK0a;// ->set_div(pC[u], PK0a.get());
                        fetmp.toBytes(hashInBuff.data());

                        //std::cout
                        //    << "for msg " << i << ", " << u << "  (sender)" << std::endl
                        //    << "  c^a/PK0^a:    " << fetmp<< std::endl;

                        sha.Reset();
                        sha.Update((u8*)&i, sizeof(i));
                        sha.Update(hashInBuff.data(), hashInBuff.size());
                        sha.Final(shaBuff);

                        messages[i][u] = *(block*)shaBuff;
                    }
                }
            });
        }


        for (auto& thrd : thrds)
            thrd.join();

        //for (auto ptr : pC)
        //    delete ptr;
    }



}
