#include "PRNG.h"
#include <algorithm>
#include <cstring>
#include <Common/Log.h>

namespace osuCrypto {


    //block mSeed;
    //std::vector<block> mBuffer, mIndexArray;
    //AES mAes;
    //u64 mBytesIdx, mBlockIdx, mBufferByteCapacity;

#define DEFAULT_BUFF_SIZE 64
    PRNG::PRNG() :
        mSeed(ZeroBlock),
        mBuffer(DEFAULT_BUFF_SIZE),
        mIndexArray(DEFAULT_BUFF_SIZE, ZeroBlock),
        mAes(mSeed),
        mBytesIdx(0),
        mBlockIdx(0),
        mBufferByteCapacity(sizeof(block) * DEFAULT_BUFF_SIZE)
    {
    }


    PRNG::PRNG(const block& seed)
        :
        mSeed(seed),
        mBuffer(DEFAULT_BUFF_SIZE),
        mIndexArray(DEFAULT_BUFF_SIZE, ZeroBlock),
        mAes(mSeed),
        mBytesIdx(0),
        mBlockIdx(0),
        mBufferByteCapacity(sizeof(block) * DEFAULT_BUFF_SIZE)
    {
        refillBuffer();
    }

    PRNG::PRNG(PRNG && s) :
        mSeed(s.mSeed),
        mBuffer(std::move(s.mBuffer)),
        mIndexArray(std::move(s.mIndexArray)),
        mAes(std::move(s.mAes)),
        mBytesIdx(s.mBytesIdx),
        mBlockIdx(s.mBlockIdx),
        mBufferByteCapacity(s.mBufferByteCapacity)
    {
        s.mSeed = ZeroBlock;
        s.mBuffer.resize(0);
        s.mIndexArray.resize(0);
        memset(&s.mAes, 0, sizeof(AES));
        s.mBytesIdx = 0;
        s.mBlockIdx = 0;
        s.mBufferByteCapacity = 0;
    }


    void PRNG::SetSeed(const block& seed)
    {
        mSeed = seed;
        mAes.setKey(seed);
        mBlockIdx = 0;

        if (mBuffer.size() == 0)
        {
            mBuffer.resize(DEFAULT_BUFF_SIZE);
            mIndexArray.resize(DEFAULT_BUFF_SIZE);
            mBufferByteCapacity = (sizeof(block) * DEFAULT_BUFF_SIZE);
        }


        refillBuffer();
    }

    const block PRNG::getSeed() const
    {
        return mSeed;
    }

    //void PRNG::get(u8 * dest, u64 length)
    //{

    //    u8* destu8 = (u8*)dest;
    //    while (length)
    //    {
    //        u64 step = std::min(length, mBufferByteCapacity - mBytesIdx);

    //        memcpy(destu8, ((u8*)mBuffer.data()) + mBytesIdx, step);

    //        destu8 += step;
    //        length -= step;
    //        mBytesIdx += step;

    //        if (mBytesIdx == mBufferByteCapacity)
    //            refillBuffer();
    //    }
    //}


    void PRNG::refillBuffer()
    {
        for (u64 i = 0; i < mBuffer.size(); ++i)
        {
            ((u64*)&mIndexArray[i])[0] = mBlockIdx++;
            ((u64*)&mIndexArray[i])[1] = 0;
        }
        mAes.ecbEncBlocks(mIndexArray.data(), mBuffer.size(), mBuffer.data());

        mBytesIdx = 0;
    }
}
