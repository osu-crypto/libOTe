#include "LzKosOtExtSender.h"

#include "OT/Tools/Tools.h"
#include "Common/ByteStream.h"
#include "Crypto/Commit.h"
#include "Common/Log.h"
#include "Common/BitVector.h"

namespace osuCrypto
{
    //#define OTEXT_DEBUG

    using namespace std;

#define SHA_HASH


    std::unique_ptr<OtExtSender> LzKosOtExtSender::split()
    {

        std::unique_ptr<OtExtSender> ret(new LzKosOtExtSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void LzKosOtExtSender::setBaseOts(ArrayView<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");


        mBaseChoiceBits = choices;
        for (int i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void LzKosOtExtSender::send(
        ArrayView<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl/*,
                    std::atomic<u64>& doneIdx*/)
    {
        if (messages.size() == 0) return;

        if (mBaseChoiceBits.size() != gOtExtBaseOtCount)
            throw std::runtime_error("must set base first");

        // round up
        u64 numOTExt = ((messages.size() + 127) / 128) * 128;


        SHA1 sha;
        u8 hashBuff[SHA1::HashSize];

        block delta = *(block*)mBaseChoiceBits.data();

        u64 doneIdx = 0;
        std::array<block, gOtExtBaseOtCount> q;
        ByteStream buff;
#ifdef OTEXT_DEBUG
        Log::out << "sender delta " << delta << Log::endl;
        buff.append(delta);
        chl.AsyncSendCopy(buff);
#endif

        Commit theirSeedComm;
        chl.recv(theirSeedComm.data(), theirSeedComm.size());


        std::vector<block> extraBlocks;
        extraBlocks.reserve(256);

        // add one for the extra 128 OTs used for the correlation check
        u64 numBlocks = numOTExt / gOtExtBaseOtCount + 1;
        for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
        {

            chl.recv(buff);
            assert(buff.size() == sizeof(block) * gOtExtBaseOtCount);

            // u = t0 + t1 + x 
            auto u = buff.getArrayView<block>();

            for (int colIdx = 0; colIdx < gOtExtBaseOtCount; colIdx++)
            {
                // a column vector sent by the receiver that hold the correction mask.
                q[colIdx] = mGens[colIdx].get<block>();

                if (mBaseChoiceBits[colIdx])
                {
                    // now q[i] = t0[i] + Delta[i] * x
                    q[colIdx] = q[colIdx] ^ u[colIdx];
                }
            }

            sse_transpose128(q);

#ifdef OTEXT_DEBUG
            buff.setp(0);
            buff.append((u8*)&q, sizeof(q));
            chl.AsyncSendCopy(buff);
#endif

            u32 blkRowIdx = 0;
            u32 stopIdx = (u32)std::min(u64(gOtExtBaseOtCount), messages.size() - doneIdx);
            for (; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
            {
                messages[doneIdx][0] = q[blkRowIdx];
                messages[doneIdx][1] = q[blkRowIdx] ^ delta;
            }

            for (; blkRowIdx < gOtExtBaseOtCount; ++blkRowIdx)
            {
                extraBlocks.push_back(q[blkRowIdx]);
            }
        }

        block seed = prng.get<block>();
        chl.asyncSend(&seed, sizeof(block));
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        //random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
        PRNG commonPrng(seed ^ theirSeed);

        block  chii, qi, qi2;
        block q2 = ZeroBlock;
        block q1 = ZeroBlock;

        //Log::out << "sender size " << messages.size() + extraBlocks.size() << Log::endl;

        //std::array<std::array<block,2>, gOtExtBaseOtCount> enc;
#ifndef SHA_HASH
        std::array<block, 128> temp,temp2;
#endif
        doneIdx = 0;
        for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
        {

            u32 blkRowIdx = 0;
            u32 stopIdx = (u32)std::min(u64(gOtExtBaseOtCount), messages.size() - doneIdx);


            //mAesFixedKey.ecbEncBlocks(messages.data()->data() + 2 * doneIdx, stopIdx * 2, enc.data()->data());

            for (; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
            {
                //auto& msg0 = messages[doneIdx][0];
                //auto msg1 = msg0 ^ delta;

                chii = commonPrng.get<block>();

                //Log::out << "s " << doneIdx << "  " << msg0 << Log::endl;


                mul128(messages[doneIdx][0], chii, qi, qi2);
                q1 = q1  ^ qi;
                q2 = q2 ^ qi2;

                // hash the message without delta

                //messages[doneIdx][0] = messages[doneIdx][0] ^ enc[blkRowIdx][0];
                //messages[doneIdx][1] = messages[doneIdx][1] ^ enc[blkRowIdx][1];

                //sha.Reset();
                //sha.Update((u8*)&messages[doneIdx][0], sizeof(block));
                //sha.Final(hashBuff);
                //messages[doneIdx][0] = *(block*)hashBuff;
#ifdef SHA_HASH
                // hash the message with delta
                sha.Reset();
                sha.Update((u8*)&messages[doneIdx][1], sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx][1] = *(block*)hashBuff;
#else

                temp[blkRowIdx] = messages[doneIdx][1];
#endif // SHA_HASH
            }

#ifndef SHA_HASH
            mAesFixedKey.ecbEncBlocks(temp.data(), stopIdx, temp2.data());

            blkRowIdx = 0;
            doneIdx -= stopIdx;
            for (; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
            {
                messages[doneIdx][1] = messages[doneIdx][1] ^ temp2[blkRowIdx];
            }
#endif //SHA_HASH
        }

        for (auto& blk : extraBlocks)
        {
            //Log::out << "s " << doneIdx++ << "  " << blk << Log::endl;
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
