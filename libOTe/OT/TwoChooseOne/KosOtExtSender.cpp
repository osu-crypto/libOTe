#include "KosOtExtSender.h"

#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"
#include "Crypto/Commit.h"

namespace osuCrypto
{
    //#define OTEXT_DEBUG

    using namespace std;




    std::unique_ptr<OtExtSender> KosOtExtSender::split()
    {

        std::unique_ptr<OtExtSender> ret(new KosOtExtSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void KosOtExtSender::setBaseOts(ArrayView<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");


        mBaseChoiceBits = choices;
        for (int i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void KosOtExtSender::send(
        ArrayView<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {

        const u8 superBlkSize(8);

        u64 statSecParm = 40;

        // round up
        u64 numOTExt = ((messages.size() + 127 + statSecParm) / 128) * 128;
        // we are going to process OTs in blocks of 128 * superblkSize messages.
        u64 numSuperBlocks = (numOTExt / 128 + superBlkSize - 1) / superBlkSize;
        u64 numBlocks = numSuperBlocks * superBlkSize;

        // the index of the last OT that we have completed.
        u64 doneIdx = 0;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t, u, t0;
        std::array<block, 128> choiceMask;
        block delta = *(block*)mBaseChoiceBits.data();

        for (u64 i = 0; i < 128; ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }

        std::array<block, 128> extraBlocks;
        u64 extraIdx = 0;


        Commit theirSeedComm;
        chl.recv(theirSeedComm.data(), theirSeedComm.size());


        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want use to stop.
            // the code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min(u64(128) * superBlkSize, messages.size() - doneIdx);

            block * tIter = (block*)t.data();
            block * uIter = (block*)u.data();
            block * cIter = choiceMask.data();

            chl.recv(u.data(), superBlkSize * 128 * sizeof(block));

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
            sse_transpose128x1024(t);



            // This is the index of where we will store the matrix long term.
            // doneIdx is the starting row. l is the offset into the blocks of 128 bits.
            // __restrict isn't crucial, it just tells the compiler that this pointer
            // is unique and it shouldn't worry about pointer aliasing. 
            block* __restrict mTIter = (block*)messages.data() + doneIdx;
            block* extraEnd = t.back().data() + t.back().size();

            for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
            {
                // because we transposed 1024 rows, the indexing gets a bit weird. But this
                // is the location of the next row that we want. Keep in mind that we had long
                // **contiguous** columns. 
                block* __restrict tIter = (((block*)t.data()) + j);

                // do the copy!
                u64 k = 0;
                for (; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                {
                    mTIter[0] = *tIter;
                    mTIter[1] = *tIter ^ delta;

                    //Log::out << "s mgs[" << (mTIter - (block*)messages.data()) / 2 << "][0] " << *mTIter << Log::endl;
                    //Log::out << "s mgs[" << (mTIter - (block*)messages.data()) / 2 << "][1] " << mTIter[1] << Log::endl;


                    tIter += superBlkSize;
                    mTIter += 2;
                }

                for (; tIter < extraEnd && k < 128 && extraIdx < 128; ++k)
                {
                    extraBlocks[extraIdx] = *(tIter);

                    tIter += superBlkSize;
                    ++extraIdx;
                }
            }


            //std::vector<block> choice(superBlkSize);
            BitVector choice(128 * superBlkSize);
            chl.recv(u.data(), superBlkSize * 128 * sizeof(block));
            chl.recv(choice.data(), sizeof(block) * superBlkSize);

            for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++rowIdx, ++j)
            {
                if (neq(((block*)u.data())[j], messages[rowIdx][choice[j]]))
                {
                    Log::out << rowIdx << Log::endl;
                    throw std::runtime_error("");
                }
            }

            doneIdx = stopIdx;
        }

        block seed = prng.get<block>();
        chl.asyncSend(&seed, sizeof(block));
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        PRNG commonPrng(seed ^ theirSeed);

        block  chii, qi, qi2;
        block q2 = ZeroBlock;
        block q1 = ZeroBlock;

        SHA1 sha;
        u8 hashBuff[20];
        doneIdx = 0;
        for (u64 blkIdx = 0; doneIdx <  messages.size(); ++blkIdx)
        {

            u32 stopIdx = (u32)std::min(u64(gOtExtBaseOtCount), messages.size() - doneIdx);

            for (u32 blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
            {

                chii = commonPrng.get<block>();

                mul128(messages[doneIdx][0], chii, qi, qi2);
                q1 = q1  ^ qi;
                q2 = q2 ^ qi2;

                // hash the message without delta
                sha.Reset();
                sha.Update((u8*)&messages[doneIdx][0], sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx][0] = *(block*)hashBuff;

                // hash the message with delta
                sha.Reset();
                sha.Update((u8*)&messages[doneIdx][1], sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx][1] = *(block*)hashBuff;
            }
        }

        for (auto& blk : extraBlocks)
        {
            chii = commonPrng.get<block>();
            mul128(blk, chii, qi, qi2);
            q1 = q1  ^ qi;
            q2 = q2 ^ qi2;
        }

        block t1, t2;
        std::vector<char> data(sizeof(block) * 3);

        chl.recv(data.data(), data.size());

        block& received_x = ((block*)data.data())[0];
        block& received_t = ((block*)data.data())[1];
        block& received_t2 = ((block*)data.data())[2];

        // check t = x * Delta + q 
        mul128(received_x, delta, t1, t2);
        t1 = t1 ^ q1;
        t2 = t2 ^ q2;

        if (eq(t1, received_t) && eq(t2, received_t2))
        {
            //Log::out << "\tCheck passed\n";
        }
        else
        {
            Log::out << "OT Ext Failed Correlation check failed" << Log::endl;
            Log::out << "rec t = " << received_t << Log::endl;
            Log::out << "tmp1  = " << t1 << Log::endl;
            Log::out << "q  = " << q1 << Log::endl;
            throw std::runtime_error("Exit");;
        }

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}
