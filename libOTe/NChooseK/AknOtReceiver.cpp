#include "AknOtReceiver.h"
#ifdef ENABLE_AKN
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "libOTe/Base/BaseOT.h"
//#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"

namespace osuCrypto
{

    AknOtReceiver::AknOtReceiver()
    {
    }


    AknOtReceiver::~AknOtReceiver()
    {
    }

    void AknOtReceiver::init(u64 totalOTCount, u64 numberOfOnes, double p,
        OtExtReceiver & ots, span<Channel> chls, PRNG & prng)
    {

        auto& chl0 = chls[0];

        if (ots.hasBaseOts() == false)
        {

#ifdef LIBOTE_HAS_BASE_OT
            std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;

            DefaultBaseOT base;
            base.send(baseMsg, prng, chl0, 2);
            ots.setBaseOts(baseMsg, prng, chl0);
#else
            throw std::runtime_error("Base OTs not set");
#endif
        }

        mMessages.resize(totalOTCount);
        mChoices.nChoosek(totalOTCount, numberOfOnes, prng);


        std::vector<PRNG> cncGens(chls.size());
        u32 px = (u32)(u32(-1) * p);

        std::atomic<u32> remaining((u32)chls.size());
        std::promise<void> cncGenProm, doneProm;
        std::shared_future<void> cncGenFuture(cncGenProm.get_future()),doneFuture(doneProm.get_future());

        std::mutex finalMtx;
        block totalSum(ZeroBlock);
        std::vector<std::array<std::vector<u64>, 2>> threadsZeroOnesList(chls.size());

        //Timer timer;
        auto routine = [&](u64 t, block extSeed, OtExtReceiver& otExt, Channel& chl)
        {
            // round up to the next 128 to make sure we aren't wasting OTs in the extension...
            u64 start = std::min<u64>(roundUpTo(t *     mMessages.size() / chls.size(), 128), mMessages.size());
            u64 end = std::min<u64>(roundUpTo((t + 1) * mMessages.size() / chls.size(), 128), mMessages.size());

            span<block> range(
                mMessages.begin() + start,
                mMessages.begin() + end);

            //TODO("do something smarter than a copy...");
            BitVector choices;
            choices.copy(mChoices, start, end - start);

            // do the OT extension for this range of messages.
            PRNG prng(extSeed);
            //std::cout << IoStream::lock << "recv 0 "  << end << std::endl;
            otExt.receive(choices, range, prng, chl);


            // ok, OTs are done.
            if (t == 0)
            {
                setTimePoint("AknOt.Recv.extDone");
                // if thread 0, get the seed that determines the cut and choose.
                block cncRootSeed;
                chl.recv((u8*)&cncRootSeed, sizeof(block));
                PRNG gg(cncRootSeed);

                setTimePoint("AknOt.Recv.CncSeedReceived");
                // use this seed to create more PRNGs
                for (auto& b : cncGens)
                    b.SetSeed(gg.get<block>());

                // signal the other threads...
                cncGenProm.set_value();
            }
            else
            {
                // wait for the above signal if not threads 0
                cncGenFuture.get();
            }

            // a local to core the XOR of our OT messages that are in this range
            block partialSum(ZeroBlock);

            // a buffer of choice bits that were sampled. We aare going to seed these is groups of 4096 bits
            std::unique_ptr<BitVector> choiceBuff(new BitVector(std::min<u64>(u64(4096), end - start)));

            // get some iters to make life easy.
            auto openChoiceIter = choiceBuff->begin();
            auto choiceIter = mChoices.begin() + start;

            // the index of the current openChoiceIter.
            u64 j = 0;

            //create a local list of ones and zero indices.
            std::array<std::vector<u64>,2> zeroOneLists;

            // compute the expected size of these list plus a bit.
            double oneFrac(double(numberOfOnes) / mMessages.size());
            u64 expectZerosCount((u64)(mMessages.size() *(1 - oneFrac) / chls.size() * 1.5));
            u64 expectOnesCount((u64)(mMessages.size() * oneFrac / chls.size() * 1.5));

            // reserve that must space.
            zeroOneLists[0].reserve(expectZerosCount);
            zeroOneLists[1].reserve(expectOnesCount);
            // now lets do the sampling.
            for (u64 i = start; i < end; ++i)
            {

                // this is the value of our choice bit at index i
                const u8 cc = *choiceIter;
                ++choiceIter;

                // if cc = 1, then this OT message should be opened.
                auto vv = cncGens[t].get<u32>();
                const u8 c = (vv <= px) & 1;
                if (c)
                {
                    // ok, this is an opened OT.

                    // check if out oen buffer is full, if so, send it and get a new one
                    if (j == choiceBuff->size())
                    {
                        chl.asyncSend(std::move(choiceBuff));
                        choiceBuff.reset(new BitVector(std::min<u64>(u64(4096), end - i)));
                        openChoiceIter = choiceBuff->begin();
                        j = 0;

                    }
                    // copy our choice bit into the buffer
                    *openChoiceIter = cc;
                    ++openChoiceIter;
                    ++j;

                    //if (cc == 0 && dynamic_cast<LzKosOtExtReceiver*>(&ots))
                    //{
                    //    // if this is a zero message and our OT extension class is
                    //    // LzKosOtExtReceiver, then we need to hash the 0-message now
                    //    // because it was lazy and didn't ;)

                    //    RandomOracle sha(sizeof(block));
                    //    sha.Update(mMessages[i]);
                    //    sha.Final(mMessages[i]);
                    //}

                    // keep a running sum of the OT messages that are opened in this thread.
                    partialSum = partialSum ^ mMessages[i];

                }
                else
                {
                    // this OT message wasn't opened. Keep track of its idx in the corresponding list.
                    zeroOneLists[cc].push_back(i);
                }
            }

            // see if we have part of the buffer still to send.
            if (j)
            {
                // truncate it to size and send
                choiceBuff->resize(j);
                chl.asyncSend(std::move(choiceBuff));
            }



            {
                // update the total sum we our share of it
                std::lock_guard<std::mutex>lock(finalMtx);
                //std::cout << "local ones " << zeroOneLists[1].size() << std::endl;
                totalSum = totalSum ^ partialSum;
            }

            // now move the list list into the shared list.
            // We didn't initially do this to prevent false sharing
            threadsZeroOnesList[t][0] = std::move(zeroOneLists[0]);
            threadsZeroOnesList[t][1] = std::move(zeroOneLists[1]);


            // now indicate that we are done. If we are last, set the promise.
            u32 d = --remaining;
            if (d == 0)
                doneProm.set_value();


            if (t == 0)
            {
                // if we are thread 0, then wait for all threads to finish.
                setTimePoint("AknOt.Recv.RecvcncDone");

                if (d)
                    doneFuture.get();

                // all other threads have finished.

                // send the other guy the sum of our ot messages as proof.
                chl0.asyncSendCopy((u8*)&totalSum, sizeof(block));


                // now merge and shuffle all the indices for the one OT messages
                u64 totalOnesCount(0);
                for (u64 i = 0; i < threadsZeroOnesList.size(); ++i)
                    totalOnesCount += threadsZeroOnesList[i][1].size();


                //std::cout << "total one " << totalOnesCount << std::endl;

                mOnes.resize(totalOnesCount);
                auto iter = mOnes.begin();

                for (u64 i = 0; i < threadsZeroOnesList.size(); ++i)
                {
                    std::copy(threadsZeroOnesList[i][1].begin(), threadsZeroOnesList[i][1].end(), iter);
                    //memcpy(iter, threadsZeroOnesList[i][1].data(), threadsZeroOnesList[i][1].size() * sizeof(u64));
                    iter += threadsZeroOnesList[i][1].size();
                }
                std::random_shuffle(mOnes.begin(), mOnes.begin(), prng);

            }

            if (t == 1 || chls.size() == 1)
            {
                // now merge and shuffle all the indices for the zero OT messages
                // the second thread will do this is there are more than on thread.

                if (d)
                    doneFuture.get();


                u64 totalZerosCount(0);
                for (u64 i = 0; i < threadsZeroOnesList.size(); ++i)
                    totalZerosCount += threadsZeroOnesList[i][0].size();

                mZeros.resize(totalZerosCount);
                auto iter = mZeros.begin();

                for (u64 i = 0; i < threadsZeroOnesList.size(); ++i)
                {
                    std::copy(threadsZeroOnesList[i][0].begin(), threadsZeroOnesList[i][0].end(), iter);
                    //memcpy(iter, threadsZeroOnesList[i][0].data(), threadsZeroOnesList[i][0].size() * sizeof(u64));
                    iter += threadsZeroOnesList[i][0].size();
                }

                std::random_shuffle(mZeros.begin(), mZeros.begin(), prng);
            }
        };



        // launch the threads to do the routine
        std::vector<std::thread> thrds(chls.size() - 1);
        std::vector<std::unique_ptr<OtExtReceiver>> parOts(chls.size() - 1);

        for (u64 i = 0; i < thrds.size(); ++i)
        {
            // split the OT to that it can be multi threaded.
            parOts[i] = std::move(ots.split());

            // create a seed for it.
            block seed = prng.get<block>();

            //compute the thread idk t
            u64 t = i + 1;

            // go!
            thrds[i] = std::thread([&, i ,t , seed]() {routine(t, seed, *parOts[i], chls[t]); });
        }

        // run  the first set in this thread.
        routine(0, prng.get<block>(), ots, chl0);


        // join any threads we may have spawned.
        for(auto& thrd : thrds)
            thrd.join();
        setTimePoint("AknOt.Recv.AllDone");
        //std::cout << timer;
        // all done
    }
}
#endif