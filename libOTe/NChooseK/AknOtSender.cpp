#include "AknOtSender.h"
#ifdef ENABLE_AKN

#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{

    AknOtSender::AknOtSender()
    {
    }


    AknOtSender::~AknOtSender()
    {
    }


    void AknOtSender::init(
        u64 totalOTCount,
        u64 cutAndChooseThreshold,
        double p,
        OtExtSender & ots,
        span<Channel>  chls,
        PRNG & prng)
    {
        setTimePoint("AknOt.Send.start");



        auto& chl0 = chls[0];

        if (ots.hasBaseOts() == false)
        {
#ifdef LIBOTE_HAS_BASE_OT
            std::array<block, gOtExtBaseOtCount> baseMsg;
            BitVector choices(gOtExtBaseOtCount);
            choices.randomize(prng);

            //crypto crpto(128, prng.get<block>());
            DefaultBaseOT base;
            base.receive(choices, baseMsg,prng, chl0, 2);

            ots.setBaseOts(baseMsg, choices, chl0);
#else
            throw std::runtime_error("Base OTs not set");
#endif
            //timer.setTimePoint("baseDone");
            //std::cout << timer;
        }

        mMessages.resize(totalOTCount);
        mSampled.resize(totalOTCount);

        auto cncRootSeed = prng.get<block>();
        PRNG gg(cncRootSeed);
        std::vector<PRNG> cncGens(chls.size()); ;
        for (auto& b : cncGens)
            b.SetSeed(gg.get<block>());

        //otMessages.resize(totalOTCount);

        std::atomic<u32> extRemaining((u32)chls.size());
        std::promise<void> extDoneProm;
        std::shared_future<void> extDoneFuture(extDoneProm.get_future());

        std::vector<std::unique_ptr<OtExtSender>> parOts(chls.size()-1);
        std::vector<std::thread> parThrds(chls.size()-1);

        u32 px = (u32)(u32(-1) * p);

        std::mutex finalMtx;
        u64 totalOnesCount(0);
        block totalSum(ZeroBlock);

        auto routine = [&](u64 t, block extSeed, OtExtSender& otExt, Channel& chl)
        {
            // round up to the next 128 to make sure we aren't wasting OTs in the extension...
            u64 start = std::min<u64>(roundUpTo(t *     mMessages.size() / chls.size(), 128), mMessages.size());
            u64 end = std::min<u64>(roundUpTo((t + 1) * mMessages.size() / chls.size(), 128), mMessages.size());

            span<std::array<block, 2>> range(
                (mMessages.begin() + start),
                (mMessages.begin() + end));

            PRNG prng(extSeed);
            //std::cout << IoStream::lock << "send 0 " << end << std::endl;

            otExt.send(range, prng, chl);


            //std::cout << IoStream::unlock;

            if (--extRemaining)
                extDoneFuture.get();
            else
                extDoneProm.set_value();

            if (t == 0)
            {
                setTimePoint("AknOt.Send.ExtDone");
                chl.asyncSend((u8*)&cncRootSeed, sizeof(block));
            }

            u64 sampleCount(0);

            auto sampleIter = mSampled.begin() + start;
            block partialSum(ZeroBlock);
            u64 onesCount(0);

            std::vector<u8> choiceBuff;
            chl.recv(choiceBuff);
			auto choiceIter = BitIterator(choiceBuff.data(), 0);
            u64 bitsRemaining = choiceBuff.size() * 8;

            for (u64 i = start; i < end; ++i)
            {
                auto vv = cncGens[t].get<u32>();
                u8 c = (vv <= px);
                *sampleIter = c;
                ++sampleIter;



                if (c)
                {
                    if (bitsRemaining-- == 0)
                    {
                        chl.recv(choiceBuff);
                        bitsRemaining = choiceBuff.size() * 8 - 1;
						choiceIter = BitIterator(choiceBuff.data(), 0);
                    }

                    ++sampleCount;
                    u8 cc = *choiceIter;
      //              if (cc == 0 && dynamic_cast<LzKosOtExtSender*>(&ots))
      //              {
      //                  // if this is a zero message and our OT extension class is
      //                  // LzKosOtExtSender, then we need to hash the 0-message now
      //                  // because it was lazy and didn't ;)
      //                  RandomOracle sha(sizeof(block));
      //                  sha.Update(mMessages[i][0]);
						//sha.Final(mMessages[i][0]);
      //              }

                    partialSum = partialSum ^ mMessages[i][cc];
                    onesCount += cc;
                    ++choiceIter;
                }
            }

            std::lock_guard<std::mutex>lock(finalMtx);
            totalOnesCount += onesCount;
            totalSum = totalSum ^ partialSum;
        };

        for (u64 i = 0; i < parOts.size(); ++i)
        {
            parOts[i] = std::move(ots.split());
            auto seed = prng.get<block>();
            parThrds[i] = std::thread([&,seed, i]()
            {
                auto  t = i + 1;
                routine(t,seed, *parOts[i], chls[t]);
            });
        }

        routine(0, prng.get<block>(), ots, chl0);
        for (auto& thrd : parThrds)
            thrd.join();


        block proof;
        chl0.recv((u8*)&proof, sizeof(block));
        if (totalOnesCount > cutAndChooseThreshold ||
            neq(proof, totalSum))
        {
            std::cout << "cnc failed. total ones Count = " << totalOnesCount << "  and threshold "<< cutAndChooseThreshold  << std::endl
                << "my computed block  = " << totalSum << "  vs " << proof  <<std::endl;
            throw std::runtime_error("failed cut and choose");
        }

        setTimePoint("AknOt.Send.Done");

    }
}
#endif