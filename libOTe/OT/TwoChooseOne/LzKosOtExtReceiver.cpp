#include "LzKosOtExtReceiver.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "Common/BitVector.h"
#include "Crypto/Commit.h"
#include "Common/ByteStream.h"

using namespace std;

namespace osuCrypto
{
    void LzKosOtExtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseOTs)
    {
        if (baseOTs.size() != gOtExtBaseOtCount)
            throw std::runtime_error(LOCATION);

        for (int i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }


        mHasBase = true;
    }
    std::unique_ptr<OtExtReceiver> LzKosOtExtReceiver::split()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        std::unique_ptr<OtExtReceiver> ret(new LzKosOtExtReceiver());

        ret->setBaseOts(baseRecvOts);

        return std::move(ret);
    }


    void LzKosOtExtReceiver::receive(
        const BitVector& choices,
        ArrayView<block> messages,
        PRNG& prng,
        Channel& chl/*,
                    std::atomic<u64>& doneIdx*/)
    {
        if (choices.size() == 0) return;

        if (mHasBase == false || choices.size() != messages.size())
            throw std::runtime_error(LOCATION);

        // round up
        auto numOTExt = ((choices.size() + 127) / 128) * 128;

        // we are going to process OTs in blocks of 128 messages.
        u64 numBlocks = numOTExt / gOtExtBaseOtCount + 1;

        // column vector form of t0, the receivers primary masking matrix
        // We only ever have 128 of them in memory at a time. Since we only
        // use it once and dont need to keep it around.
        std::array<block, gOtExtBaseOtCount> t0;


        SHA1 sha;
        u8 hashBuff[SHA1::HashSize];

        // commit to as seed which will be used to 
        block seed = prng.get<block>();
        Commit myComm(seed);
        chl.asyncSend(myComm.data(), myComm.size());

        // turn the choice vbitVector into an array of blocks. 
        BitVector choices2(numBlocks * 128);
        choices2 = choices;
        choices2.resize(numBlocks * 128);
        auto choiceBlocks = choices2.getArrayView<block>();

#ifdef OTEXT_DEBUG
        ByteStream debugBuff;
        chl.recv(debugBuff);
        block debugDelta; debugBuff.consume(debugDelta);

        Log::out << "delta" << Log::endl << debugDelta << Log::endl;
#endif 

        std::vector<block> extraBlocks;
        extraBlocks.reserve(256);

        u64 dIdx(0), doneIdx(0);
        for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
        {
            // this will store the next 128 rows of the matrix u
            std::unique_ptr<ByteStream> uBuff(new ByteStream(gOtExtBaseOtCount * sizeof(block)));
            uBuff->setp(gOtExtBaseOtCount * sizeof(block));

            // get an array of blocks that we will fill. 
            auto u = uBuff->getArrayView<block>();

            for (u64 colIdx = 0; colIdx < gOtExtBaseOtCount; colIdx++)
            {
                // use the base key material from the base OTs to 
                // extend the i'th column of t0 and t1    
                t0[colIdx] = mGens[colIdx][0].get<block>();

                // This is t1[colIdx]
                block t1i = mGens[colIdx][1].get<block>();

                // compute the next column of u (within this block) as this ha
                u[colIdx] = t1i ^ (t0[colIdx] ^ choiceBlocks[blkIdx]);

                //Log::out << "Receiver sent u[" << colIdx << "]=" << u[colIdx] <<" = " << t1i <<" + " << t0[colIdx] << " + " << choiceBlocks[blkIdx] << Log::endl;
            }

            // send over u buffer
            chl.asyncSend(std::move(uBuff));

            // transpose t0 in place
            sse_transpose128(t0);

#ifdef OTEXT_DEBUG 
            chl.recv(debugBuff); assert(debugBuff.size() == sizeof(t0));
            block* q = (block*)debugBuff.data();
#endif
            // now finalize and compute the correlation value for this block that we just processes
            u32 blkRowIdx;
            u32 stopIdx = (u32)std::min(u64(gOtExtBaseOtCount), messages.size() - doneIdx);
            for (blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++dIdx)
            {
#ifdef OTEXT_DEBUG
                u8 choice = mChoiceBits[dIdx];
                block expected = choice ? (q[blkRowIdx] ^ debugDelta) : q[blkRowIdx];
                Log::out << (int)choice << " " << expected << Log::endl;

                if (t0[blkRowIdx] != expected)
                {
                    Log::out << "- " << t0[blkRowIdx] << Log::endl;
                    throw std::runtime_error(LOCATION);
                }
#endif
                messages[dIdx] = t0[blkRowIdx];

            }

            for (; blkRowIdx < gOtExtBaseOtCount; ++blkRowIdx, ++dIdx)
            {
                extraBlocks.push_back(t0[blkRowIdx]);
            }

            doneIdx = std::min((u64)dIdx, messages.size());

        }


        // do correlation check and hashing
        // For the malicious secure OTs, we need a random PRNG that is chosen random 
        // for both parties. So that is what this is. 
        PRNG commonPrng;
        //random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));
        chl.asyncSendCopy(&seed, sizeof(block));
        commonPrng.SetSeed(seed ^ theirSeed);

        // this buffer will be sent to the other party to prove we used the 
        // same value of r in all of the column vectors...
        std::unique_ptr<ByteStream> correlationData(new ByteStream(3 * sizeof(block)));
        correlationData->setp(correlationData->capacity());
        block& x = correlationData->getArrayView<block>()[0];
        block& t = correlationData->getArrayView<block>()[1];
        block& t2 = correlationData->getArrayView<block>()[2];
        x = t = t2 = ZeroBlock;
        block chij, ti, ti2;

        //std::array<block, gOtExtBaseOtCount> enc;

        dIdx = (0), doneIdx = (0);
        auto extraBlocksIter = extraBlocks.begin();
        for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
        {
            u32 blkRowIdx;
            u32 stopIdx = (u32)std::min(u64(gOtExtBaseOtCount), messages.size() - doneIdx);

            //mAesFixedKey.ecbEncBlocks(messages.data() + dIdx, stopIdx, enc.data());

            for (blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++dIdx)
            {

                // and check for correlation
                chij = commonPrng.get<block>();
                if (choices2[dIdx]) x = x ^ chij;

                // multiply over polynomial ring to avoid reduction
                mul128(messages[dIdx], chij, ti, ti2);

                t = t ^ ti;
                t2 = t2 ^ ti2;

                //messages[dIdx] = messages[dIdx] ^ enc[blkRowIdx];
                // hash it
                if (choices2[dIdx])
                {
                    sha.Reset();
                    sha.Update((u8*)&messages[dIdx], sizeof(block));
                    sha.Final(hashBuff);
                    messages[dIdx] = *(block*)hashBuff;
                }
            }



            for (; blkRowIdx < gOtExtBaseOtCount; ++blkRowIdx, ++dIdx)
            {
                // and check for correlation
                chij = commonPrng.get<block>();
                if (choices2[dIdx]) x = x ^ chij;

                // multiply over polynomial ring to avoid reduction
                mul128(*extraBlocksIter++, chij, ti, ti2);

                t = t ^ ti;
                t2 = t2 ^ ti2;
            }

            doneIdx = std::min((u64)dIdx, messages.size());
        }
        chl.asyncSend(std::move(correlationData));

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}
