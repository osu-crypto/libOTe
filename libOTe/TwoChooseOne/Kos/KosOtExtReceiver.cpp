#include "KosOtExtReceiver.h"
#ifdef ENABLE_KOS

#include "libOTe/Tools/Tools.h"
#include "libOTe/config.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>

#include "libOTe/TwoChooseOne/TcoOtDefines.h"

using namespace std;
//#define KOS_DEBUG

namespace osuCrypto
{
    KosOtExtReceiver::KosOtExtReceiver(SetUniformOts, span<std::array<block, 2>> baseOTs)
    {
        setUniformBaseOts(baseOTs);
    }

    void KosOtExtReceiver::setUniformBaseOts(span<std::array<block, 2>> baseOTs)
    {
        if (baseOTs.size() != gOtExtBaseOtCount)
            throw std::runtime_error(LOCATION);

        mGens.resize(gOtExtBaseOtCount);
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }

        mHasBase = true;
        mUniformBase = true;
    }

    void KosOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs)
    {
        setUniformBaseOts(baseOTs);
        mUniformBase = false;
    }

    KosOtExtReceiver KosOtExtReceiver::splitBase()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        if (!hasBaseOts())
            throw std::runtime_error("base OTs have not been set. " LOCATION);

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return KosOtExtReceiver(SetUniformOts{}, baseRecvOts);
    }

    std::unique_ptr<OtExtReceiver> KosOtExtReceiver::split()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return std::make_unique<KosOtExtReceiver>(SetUniformOts{}, baseRecvOts);
    }

    task<> KosOtExtReceiver::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Socket& chl)
    {

        // we are going to process OTs in blocks of 128 * superBlkSize messages.
        u64 numOtExt = roundUpTo(choices.size() + 128, 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        u64 numBlocks = numSuperBlocks * superBlkSize;

        MC_BEGIN(task<>, this, &choices, messages, &prng, &chl,
            numSuperBlocks, numBlocks,
            myComm = Commit{},
            seed = block{},
            fs = RandomOracle(sizeof(block)),
            choices2 = BitVector{},
            t0 = AlignedUnVector<std::array<block, superBlkSize>>{ 128 },
            t0v = span<block>{},
            choiceBlocks = span<block>{},
            extraBlocks = AlignedArray<block, 128>{},
            mIter = span<block>::iterator{},
            step = u64{},
            superBlkIdx = u64{},
            uBuff = AlignedUnVector<block>{},
            uIter = (block*)nullptr,
            uEnd = (block*)nullptr,
            tIter = (block*)nullptr,
            cIter = (block*)nullptr,
            theirSeed = block{},
            diff = block{}
        );

        if (hasBaseOts() == false)
            MC_AWAIT(genBaseOts(prng, chl));

        setTimePoint("Kos.recv.start");

        if (mUniformBase==false)
        {
            diff = prng.get();
            MC_AWAIT(chl.send(std::move(diff)));

            {
                auto iter = BitIterator((u8*)&diff, 0);

                mGens.resize(gOtExtBaseOtCount);
                for (u64 i = 0; i < gOtExtBaseOtCount; i++)
                {
                    if (*iter)
                        std::swap(mGens[i][0], mGens[i][1]);

                    ++iter;
                }
            }
            mUniformBase = true;
        }

        assert((u64)t0.data() % 32 == 0);
        if (mFiatShamir == false)
        {
            seed = prng.get<block>();
            myComm = Commit(seed);
            MC_AWAIT(chl.send(std::move(myComm)));
        }

        // turn the choice vbitVector into an array of blocks.
        choices2.resize(numBlocks * 128);
        assert(choices2.size() >= choices.size() + 128);
        choices2 = choices;
        choices2.resize(numBlocks * 128);

        choiceBlocks = choices2.getSpan<block>();
        choiceBlocks.back() = prng.get();

        // this will be used as temporary buffers of 128 columns,
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        t0v = span<block>((block*)t0.data(), superBlkSize * 128);


        
        mIter = messages.begin();

        step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
        uBuff.resize(step * 128 * superBlkSize);

        // get an array of blocks that we will fill.
        uIter = (block*)uBuff.data();
        uEnd = uIter + uBuff.size();

#ifdef KOS_DEBUG
        auto mStart = mIter;
#endif

        // NOTE: We do not transpose a bit-matrix of size numRow * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do.
        for (superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // this will store the next 128 rows of the matrix u
            tIter = (block*)t0.data();
            cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;

            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the column indexed by colIdx. This is done with
                // AES in counter mode acting as a PRNG. We don'tIter use the normal
                // PRNG interface because that would result in a data copy when
                // we move it into the T0,T1 matrices. Instead we do it directly.
                mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, superBlkSize, tIter);
                mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, superBlkSize, uIter);

                // increment the counter mode idx.
                mGens[colIdx][0].mBlockIdx += superBlkSize;
                mGens[colIdx][1].mBlockIdx += superBlkSize;

                uIter[0] = uIter[0] ^ cIter[0];
                uIter[1] = uIter[1] ^ cIter[1];
                uIter[2] = uIter[2] ^ cIter[2];
                uIter[3] = uIter[3] ^ cIter[3];
                uIter[4] = uIter[4] ^ cIter[4];
                uIter[5] = uIter[5] ^ cIter[5];
                uIter[6] = uIter[6] ^ cIter[6];
                uIter[7] = uIter[7] ^ cIter[7];

                uIter[0] = uIter[0] ^ tIter[0];
                uIter[1] = uIter[1] ^ tIter[1];
                uIter[2] = uIter[2] ^ tIter[2];
                uIter[3] = uIter[3] ^ tIter[3];
                uIter[4] = uIter[4] ^ tIter[4];
                uIter[5] = uIter[5] ^ tIter[5];
                uIter[6] = uIter[6] ^ tIter[6];
                uIter[7] = uIter[7] ^ tIter[7];

                uIter += 8;
                tIter += 8;
            }

            if (uIter == uEnd)
            {

                if (mFiatShamir)
                {
                    fs.Update(uBuff.data(), uBuff.size());
                }
                //std::cout << "send u " << std::endl;

                // send over u buffer
                MC_AWAIT(chl.send(std::move(uBuff)));

                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx - 1, (u64)commStepSize);

                if (step)
                {
                    uBuff.resize(step * 128 * superBlkSize);
                    uIter = (block*)uBuff.data();
                    uEnd = uIter + uBuff.size();
                }
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            transpose128x1024((block*)t0.data());



            auto mEnd = mIter + std::min<u64>(128 * superBlkSize, messages.end() - mIter);

            tIter = (block*)t0.data();
            block* tEnd = (block*)t0.data() + 128 * superBlkSize;

            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter) = *tIter;

                    tIter += superBlkSize;
                    mIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }

#ifdef KOS_DEBUG
            if ((superBlkIdx + 1) % commStepSize == 0)
            {
                span<block> msgs(mStart, mEnd);
                mStart = mEnd;
fix...
                chl.send(msgs);
                chl.send(cIter, superBlkSize);
            }
#endif
        }

        for (u64 i = 0; i < 128; ++i)
            extraBlocks[i] = t0[i][superBlkSize - 1];


#ifdef KOS_DEBUG
fix...
        chl.send((u8*)extraBlocks.data(), sizeof(block) * 128);
        BitVector cc;
        cc.copy(choices2, choices2.size() - 128, 128);
        chl.send(cc);
#endif
        //std::cout << "uBuff " << (bool)uBuff << "  " << (uEnd - uIter) << std::endl;
        setTimePoint("Kos.recv.transposeDone");

        if (mFiatShamir)
        {
            fs.Final(seed);
        }
        else
        {
            MC_AWAIT(chl.recv(theirSeed));
            MC_AWAIT(chl.send(std::move(seed)));
            seed = seed ^ theirSeed;
        }

        setTimePoint("Kos.recv.cncSeed");


        uBuff = hash(messages, choiceBlocks, seed, extraBlocks);

        MC_AWAIT(chl.send(std::move(uBuff)));

        MC_END();

    }

    AlignedUnVector<block> KosOtExtReceiver::hash(
        span<block> messages,
        span<block> choiceBlocks,
        block seed,
        std::array<block, 128>& extraBlocks)
    {
        PRNG commonPrng(seed);

        // this buffer will be sent to the other party to prove we used the
        // same value of r in all of the column vectors...
        AlignedUnVector<block> correlationData(2);
        block& x = correlationData[0];
        block& t = correlationData[1];
        block t2;
        //block& t2 = correlationData[2];
        x = t = t2 = ZeroBlock;
        block ti, ti2;

        RandomOracle sha(sizeof(block));

        u64 doneIdx = (0);
        //std::cout << IoStream::lock;

        std::array<block, 2> zeroOneBlk{ ZeroBlock, AllOneBlock };
        std::array<block, 128> challenges;

        std::array<block, 8> expendedChoiceBlk;
        std::array<std::array<u8, 16>, 8>& expendedChoice = *reinterpret_cast<std::array<std::array<u8, 16>, 8>*>(&expendedChoiceBlk);

        block mask = block(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());

            u64 stop = std::min<u64>(messages.size(), doneIdx + 128);

            expendedChoiceBlk[0] = mask & choiceBlocks[blockIdx].srai_epi16(0);
            expendedChoiceBlk[1] = mask & choiceBlocks[blockIdx].srai_epi16(1);
            expendedChoiceBlk[2] = mask & choiceBlocks[blockIdx].srai_epi16(2);
            expendedChoiceBlk[3] = mask & choiceBlocks[blockIdx].srai_epi16(3);
            expendedChoiceBlk[4] = mask & choiceBlocks[blockIdx].srai_epi16(4);
            expendedChoiceBlk[5] = mask & choiceBlocks[blockIdx].srai_epi16(5);
            expendedChoiceBlk[6] = mask & choiceBlocks[blockIdx].srai_epi16(6);
            expendedChoiceBlk[7] = mask & choiceBlocks[blockIdx].srai_epi16(7);

            for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
            {
                x = x ^ (challenges[i] & zeroOneBlk[expendedChoice[i % 8][i / 8]]);

                // multiply over polynomial ring to avoid reduction
                mul128(messages[dd], challenges[i], ti, ti2);
                t = t ^ ti;
                t2 = t2 ^ ti2;
            }


            if (mHashType == HashType::RandomOracle)
            {
                for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
                {
                    // hash it
                    sha.Reset();
                    sha.Update(dd);
                    sha.Update((u8*)&messages[dd], sizeof(block));
                    sha.Final(messages[dd]);
                }
            }
            else
            {
                span<block> hh(messages.data() + doneIdx, stop - doneIdx);
                mAesFixedKey.TmmoHashBlocks(hh, hh, [mTweak = doneIdx]() mutable {
                    return block(mTweak++);
                    });

            }

            doneIdx = stop;
        }


        doneIdx = choiceBlocks.size() * 128 - 128;
        auto iter = BitIterator((u8*)&choiceBlocks[choiceBlocks.size() - 1]);
        for (block& blk : extraBlocks)
        {
            // and check for correlation
            block chij = commonPrng.get<block>();

            if (*iter) x = x ^ chij;
            ++iter;

            // multiply over polynomial ring to avoid reduction
            mul128(blk, chij, ti, ti2);

            t = t ^ ti;
            t2 = t2 ^ ti2;
        }

        t = t.gf128Reduce(t2);

        setTimePoint("Kos.recv.done");
        return correlationData;
        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}
#endif