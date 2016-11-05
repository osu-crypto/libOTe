#include "IknpOtExtReceiver.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"
#include "Common/BitVector.h"

using namespace std;

namespace osuCrypto
{

    void IknpOtExtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseOTs)
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


    std::unique_ptr<OtExtReceiver> IknpOtExtReceiver::split()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        std::unique_ptr<OtExtReceiver> ret(new IknpOtExtReceiver());

        ret->setBaseOts(baseRecvOts);

        return std::move(ret);
    }


    void IknpOtExtReceiver::receive(
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
        u64 numBlocks = numOTExt / gOtExtBaseOtCount;

        // column vector form of t0, the receivers primary masking matrix
        // We only ever have 128 of them in memory at a time. Since we only
        // use it once and dont need to keep it around.
        std::array<block, gOtExtBaseOtCount> t0;


        SHA1 sha;
        u8 hashBuff[SHA1::HashSize];

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
        u64 doneIdx(0);
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
            for (blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
            {
#ifdef OTEXT_DEBUG
                u8 choice = mChoiceBits[doneIdx];
                block expected = choice ? (q[blkRowIdx] ^ debugDelta) : q[blkRowIdx];
                Log::out << (int)choice << " " << expected << Log::endl;

                if (t0[blkRowIdx] != expected)
                {
                    Log::out << "- " << t0[blkRowIdx] << Log::endl;
                    throw std::runtime_error(LOCATION);
                }
#endif

                // hash it
                sha.Reset();
                sha.Update((u8*)&t0[blkRowIdx], sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx] = *(block*)hashBuff;

            }
        }


        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }
}
