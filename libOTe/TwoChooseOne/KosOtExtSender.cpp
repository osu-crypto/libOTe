#include "KosOtExtSender.h"
#ifdef ENABLE_KOS
//#define KOS_DEBUG
#include "libOTe/config.h"
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include "TcoOtDefines.h"

namespace osuCrypto
{
    KosOtExtSender::KosOtExtSender(SetUniformOts, span<block> baseRecvOts, const BitVector& choices)
    {
        setUniformBaseOts(baseRecvOts, choices);
    }

    void KosOtExtSender::setUniformBaseOts(span<block> baseRecvOts, const BitVector& choices)
    {
        mBaseChoiceBits = choices;

        mGens.resize(gOtExtBaseOtCount);
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    KosOtExtSender KosOtExtSender::splitBase()
    {
        if (!hasBaseOts())
            throw std::runtime_error("base OTs have not been set. " LOCATION);

        std::array<block, gOtExtBaseOtCount> baseRecvOts;
        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();
        return KosOtExtSender(SetUniformOts{}, baseRecvOts, mBaseChoiceBits);
    }

    std::unique_ptr<OtExtSender> KosOtExtSender::split()
    {
        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();

        return std::make_unique<KosOtExtSender>(SetUniformOts{}, baseRecvOts, mBaseChoiceBits);
    }

    void KosOtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices, Channel& chl)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");

        BitVector delta(128);
        chl.recv(delta);

        mBaseChoiceBits = choices;
        mBaseChoiceBits ^= delta;

        mGens.resize(gOtExtBaseOtCount);
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void KosOtExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {
        if (hasBaseOts() == false)
            genBaseOts(prng, chl);

        setTimePoint("Kos.send.start");

        // round up
        u64 numOtExt = roundUpTo(messages.size() + 128, 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        //u64 numBlocks = numSuperBlocks * superBlkSize;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t;
        std::vector<std::array<block, superBlkSize>> u(128 * commStepSize);

        span<block> tv((block*)t.data(), superBlkSize * 128);

        std::array<block, 128> choiceMask;
        block delta = *(block*)mBaseChoiceBits.data();

        for (u64 i = 0; i < 128; ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }

        std::array<block, 128> extraBlocks;


        // The next OT message to be computed
        auto mIter = messages.begin();

        // Our current location of u.
        // The end iter of u. When uIter == uEnd, we need to
        // receive the next part of the OT matrix.
        block* uIter = (block*)u.data() + superBlkSize * 128 * commStepSize;
        block* uEnd = uIter;


        // The other party either need to commit
        // to a random value or we will generate 
        // it via Fiat Shamir.
        RandomOracle fs(sizeof(block));

        Commit theirSeedComm;
        if(mFiatShamir == false)
            chl.recv(theirSeedComm.data(), theirSeedComm.size());


#ifdef KOS_DEBUG
        auto mStart = mIter;
#endif

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // We will generate of the matrix to fill
            // up t. Then we will transpose t.
            block* tIter = (block*)t.data();

            // cIter is the current choice bit, expanded out to be 128 bits.
            block* cIter = choiceMask.data();

            // check if we have run out of the u matrix
            // to consume. If so, receive some more.
            if (uIter == uEnd)
            {
                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
                u64 size = step * superBlkSize * 128 * sizeof(block);

                //std::cout << "recv u " << std::endl;
                chl.recv((u8*)u.data(), size);
                uIter = (block*)u.data();

                if (mFiatShamir)
                    fs.Update((u8*)u.data(), size);
            }

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, tIter);
                mGens[colIdx].mBlockIdx += superBlkSize;

                uIter[0] = uIter[0] & *cIter;
                uIter[1] = uIter[1] & *cIter;
                uIter[2] = uIter[2] & *cIter;
                uIter[3] = uIter[3] & *cIter;
                uIter[4] = uIter[4] & *cIter;
                uIter[5] = uIter[5] & *cIter;
                uIter[6] = uIter[6] & *cIter;
                uIter[7] = uIter[7] & *cIter;

                tIter[0] = tIter[0] ^ uIter[0];
                tIter[1] = tIter[1] ^ uIter[1];
                tIter[2] = tIter[2] ^ uIter[2];
                tIter[3] = tIter[3] ^ uIter[3];
                tIter[4] = tIter[4] ^ uIter[4];
                tIter[5] = tIter[5] ^ uIter[5];
                tIter[6] = tIter[6] ^ uIter[6];
                tIter[7] = tIter[7] ^ uIter[7];

                ++cIter;
                uIter += 8;
                tIter += 8;
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            transpose128x1024(t);


            //std::array<block, 2>* mStart = mIter;
            auto mEnd = mIter + std::min<u64>(128 * superBlkSize, messages.end() - mIter);

            // compute how many rows are unused.
            //u64 unusedCount = (mIter - mEnd + 128 * superBlkSize);

            // compute the begin and end index of the extra rows that
            // we will compute in this iters. These are taken from the
            // unused rows what we computed above.
            //block* xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

            tIter = (block*)t.data();
            block* tEnd = (block*)t.data() + 128 * superBlkSize;

            // Due to us transposing 1024 rows, the OT messages
            // are interleaved within t. we have to step 8 rows
            // of t to get to the next message.
            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter)[0] = *tIter;
                    (*mIter)[1] = *tIter ^ delta;

                    tIter += superBlkSize;
                    mIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }

#ifdef KOS_DEBUG
            if ((superBlkIdx + 1) % commStepSize == 0)
            {
                auto nn = 128 * superBlkSize * commStepSize;
                BitVector choice(nn);

                std::vector<block> temp(nn);
                chl.recv(temp);
                chl.recv(choice);

                u64 begin = mStart - messages.begin();
                auto mm = std::min<u64>(nn, messages.size() - begin);
                for (u64 j = 0; j < mm; ++j)
                {
                    auto rowIdx = j + begin;
                    auto v = temp[j];
                    if (neq(v, messages[rowIdx][choice[j]]))
                    {
                        std::cout << rowIdx << std::endl;
                        throw std::runtime_error("");
                    }
                }
            }
#endif
        }

        for (u64 i = 0; i < 128; ++i)
            extraBlocks[i] = t[i][superBlkSize - 1];

#ifdef KOS_DEBUG
        BitVector choices(128);
        std::vector<block> xtraBlk(128);
        chl.recv(xtraBlk);
        chl.recv(choices);

        bool failed = false;
        for (u64 i = 0; i < 128; ++i)
        {
            if (neq(xtraBlk[i], choices[i] ? extraBlocks[i] ^ delta : extraBlocks[i]))
            {
                std::cout << "extra " << i << std::endl;
                std::cout << xtraBlk[i] << "  " << (u32)choices[i] << std::endl;
                std::cout << extraBlocks[i] << "  " << (extraBlocks[i] ^ delta) << std::endl;

                failed = true;
            }
        }
        if (failed)
            throw std::runtime_error("");
#endif
        setTimePoint("Kos.send.transposeDone");

        block seed;

        if (mFiatShamir)
        {
            fs.Final(seed);
        }
        else
        {
            seed = prng.get<block>();
            chl.asyncSend((u8*)&seed, sizeof(block));
            block theirSeed;
            chl.recv((u8*)&theirSeed, sizeof(block));
            setTimePoint("Kos.send.cncSeed");
            if (Commit(theirSeed) != theirSeedComm)
                throw std::runtime_error("bad commit " LOCATION);
            seed = seed ^ theirSeed;
            //PRNG commonPrng(seed ^ theirSeed);
        }


        hash(messages, chl, seed, extraBlocks, delta);

    }


    void KosOtExtSender::hash(
        span<std::array<block, 2>> messages,
        Channel& chl, 
        block seed, 
        std::array<block, 128>& extraBlocks,
        block delta)
    {

        PRNG commonPrng(seed);

        block  qi, qi2;
        block q2 = ZeroBlock;
        block q1 = ZeroBlock;

        RandomOracle sha;
        u8 hashBuff[20];


        u64 doneIdx = 0;
        std::array<block, 128> challenges;

        setTimePoint("Kos.send.checkStart");

        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());
            u64 stop = std::min<u64>(messages.size(), doneIdx + 128);
            for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
            {
                mul128(messages[dd][0], challenges[i], qi, qi2);
                q1 = q1 ^ qi;
                q2 = q2 ^ qi2;
            }

            if (mHashType == HashType::RandomOracle)
            {
                for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
                {
                    // hash the message without delta
                    sha.Reset();
                    sha.Update(dd);
                    sha.Update((u8*)&messages[dd][0], sizeof(block));
                    sha.Final(hashBuff);
                    messages[dd][0] = *(block*)hashBuff;

                    // hash the message with delta
                    sha.Reset();
                    sha.Update(dd);
                    sha.Update((u8*)&messages[dd][1], sizeof(block));
                    sha.Final(hashBuff);
                    messages[dd][1] = *(block*)hashBuff;
                }
            }
            else
            {
                span<block> hh(messages[doneIdx].data(), 2 * (stop - doneIdx));
                mAesFixedKey.hashBlocks(hh, hh);
            }

            doneIdx = stop;
        }


        for (auto& blk : extraBlocks)
        {
            block chii = commonPrng.get<block>();

            mul128(blk, chii, qi, qi2);
            q1 = q1 ^ qi;
            q2 = q2 ^ qi2;
        }

        setTimePoint("Kos.send.checkSummed");


        //std::cout << IoStream::unlock;

        std::vector<u8> data(sizeof(block) * 2);

        chl.recv(data.data(), data.size());
        setTimePoint("Kos.send.proofReceived");

        block& received_x = ((block*)data.data())[0];
        block& received_t = ((block*)data.data())[1];
        //block& received_t2 = ((block*)data.data())[2];

        auto q = q1.gf128Reduce(q2);

        // check t = x * Delta + q
        auto t = received_x.gf128Mul(delta) ^ q;

        if (eq(t, received_t))
        {
            //std::cout << "\tCheck passed\n";
        }
        else
        {
            std::cout << "OT Ext Failed Correlation check failed" << std::endl;
            //std::cout << "rec t = " << received_t << std::endl;
            //std::cout << "tmp1  = " << t1 << std::endl;
            //std::cout << "q  = " << q1 << std::endl;
            throw std::runtime_error("Exit");;
        }
        setTimePoint("Kos.send.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}

#endif
