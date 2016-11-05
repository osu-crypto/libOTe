#include "IknpOtExtSender.h"

#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"

namespace osuCrypto
{
    //#define OTEXT_DEBUG

    using namespace std;



    std::unique_ptr<OtExtSender> IknpOtExtSender::split()
    {

        std::unique_ptr<OtExtSender> ret(new IknpOtExtSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void IknpOtExtSender::setBaseOts(ArrayView<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");


        mBaseChoiceBits = choices;
        for (int i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void IknpOtExtSender::send(
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


        u64 doneIdx = 0;
        std::array<block, gOtExtBaseOtCount> q;
        block delta = *(block*)mBaseChoiceBits.data();
        ByteStream buff;
#ifdef OTEXT_DEBUG
        Log::out << "sender delta " << delta << Log::endl;
        buff.append(delta);
        chl.AsyncSendCopy(buff);
#endif

        // add one for the extra 128 OTs used for the correlation check
        u64 numBlocks = numOTExt / gOtExtBaseOtCount;
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
            u32 stopIdx = (u32)std::min(u64(gOtExtBaseOtCount), messages.size() - doneIdx);
            u32 blkRowIdx = 0;
            for (; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
            {
                auto& msg0 = q[blkRowIdx];
                auto msg1 = q[blkRowIdx] ^ delta;

                // hash the message without delta
                sha.Reset();
                sha.Update((u8*)&msg0, sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx][0] = *(block*)hashBuff;

                // hash the message with delta
                sha.Reset();
                sha.Update((u8*)&msg1, sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx][1] = *(block*)hashBuff;

            }
        }
    }


}
