#include "Rr17NcoOtSender.h"
#include <cryptoTools/Common/ByteStream.h>

#include <cryptoTools/Common/Log.h>
namespace osuCrypto
{


    bool Rr17NcoOtSender::hasBaseOts() const
    {
        return mKos.hasBaseOts();
    }

    void Rr17NcoOtSender::setBaseOts(
        ArrayView<block> baseRecvOts, const BitVector & choices)
    {
        mKos.setBaseOts(baseRecvOts, choices);
    }

    std::unique_ptr<NcoOtExtSender> Rr17NcoOtSender::split()
    {
        auto ret = std::unique_ptr<NcoOtExtSender>(new Rr17NcoOtSender());

        std::vector<block> baseOts(mKos.mBaseChoiceBits.size());

        for (u64 i = 0; i < baseOts.size(); ++i)
        {
            baseOts[i] = mKos.mGens[i].get<block>();
        }

        ret->setBaseOts(baseOts, mKos.mBaseChoiceBits);
        ((Rr17NcoOtSender*)ret.get())->mEncodeSize = mEncodeSize;

        return std::move(ret);
    }

    void Rr17NcoOtSender::init(u64 numOtExt, PRNG& prng, Channel& chl)
    {

        mMessages.resize(numOtExt * mEncodeSize);
        prng.mAes.ecbEncCounterMode(prng.mBlockIdx, mMessages.size() * 2, (block*)mMessages.data());
        prng.mBlockIdx += mMessages.size() * 2;

        mCorrectionIdx = 0;
        mCorrection.resize(mMessages.size());

        u8* buff(new u8[mMessages.size() * sizeof(std::array<block, 2>)]);
        ArrayView<std::array<block, 2>> view((std::array<block, 2>*)buff, mMessages.size());
        //std::cout << "ots = " << log2(view.size()) << std::endl;
        //std::cout << IoStream::lock;
        mKos.send(view, prng, chl);

        //for (u64 i = 0; i < view.size(); ++i)
        //{
        //    std::cout << "s msg " << i << " " << mMessages[i][0] << " " << mMessages[i][1] << std::endl;
        //    std::cout << "s kos " << i << " " << view[i][0] << " " << view[i][1] << std::endl;
        //}

        auto stepSize = 1 << 24;
        auto count = (mMessages.size() + stepSize - 1) / stepSize;

        for (u64 step = 0; step < count; ++step)
        {

            auto curSize = std::min<u64>(stepSize, mMessages.size() - step * stepSize);

            //std::cout << "send " << step << " "  << count<< std::endl;

            for (u64 i = 0, j = stepSize * step; i < curSize; ++i, ++j)
            {

                view[j][0] = view[j][0] ^ mMessages[j][0];
                view[j][1] = view[j][1] ^ mMessages[j][1];
                //std::cout << "s view " << j << " " << view[j][0] << " " << view[j][1] << std::endl;
            }

            if (step == count - 1)
            {
                chl.asyncSend(buff + step * stepSize, curSize * sizeof(std::array<block,2>), [buff]() 
                {
                    delete[] buff; 
                });
            }
            else
            {
                chl.asyncSend(buff + step * stepSize, curSize * sizeof(std::array<block, 2>));
            }
        }
        //std::cout << IoStream::unlock;

    }

    //static const u8 bitMasks[8]{ 0,1,3,7,15,31,63, 127 };

    //inline block shiftRight(block v, u8 n)
    //{
    //    auto v1 = _mm_srli_epi64(v, n);
    //    auto v2 = _mm_srli_si128(v, 8);
    //    v2 = _mm_slli_epi64(v2, 64 - (n));
    //    return _mm_or_si128(v1, v2);
    //}

    //block loadFromBit(u8* data, u64 bitPosition)
    //{

    //    data += bitPosition / 8;
    //    bitPosition = bitPosition % 8;

    //    block ret = toBlock(data);
    //    shiftRight(ret, bitPosition);

    //    *(u8*)&ret |= data[sizeof(block)] & bitMasks[bitPosition];

    //    return ret;
    //}

    void Rr17NcoOtSender::encode(
        u64 otIdx,
        const block* choiceWord,
        u8* dest,
        u64 destSize)
    {

//#ifndef NDEBUG
//        if (choiceWord.size() != 1)
//            throw std::runtime_error(LOCATION);
//#endif
        //BitVector mCorrections;

        block correction = toBlock(mCorrection.data() + otIdx * mEncodeSize / 8);
        block choice = choiceWord[0] ^ correction;

        BitIterator iter((u8*)&choice, 0);
        otIdx *= mEncodeSize;

        //encoding = ZeroBlock;
        //for (u64 i = 0; i < mEncodeSize; ++i)
        //    encoding = encoding  ^ mMessages[otIdx++][*iter++];

        SHA1 sha;
        u8 buff[SHA1::HashSize];

        for (u64 i = 0; i < mEncodeSize; ++i)
            sha.Update(mMessages[otIdx++][*iter++]);

        sha.Update((u8*)choiceWord, mEncodeSize / 8);
        sha.Final(buff);
        memcpy(dest, buff, std::min<u64>(SHA1::HashSize, destSize));
        //encoding = *(block*)buff;
    }

    void Rr17NcoOtSender::getParams(
        bool maliciousSecure,
        u64 compSecParm,
        u64 statSecParam,
        u64 inputBitCount,
        u64 inputCount,
        u64 & inputBlkSize,
        u64 & baseOtCount)
    {
        if (maliciousSecure == false)
            throw std::runtime_error(LOCATION);

        if (compSecParm != 128)
            throw std::runtime_error(LOCATION);

        if (inputBitCount > 128)
            throw std::runtime_error(LOCATION);

        mEncodeSize = roundUpTo(inputBitCount, 8);
        inputBlkSize = (inputBitCount + 127) / 128;
        baseOtCount = 128;
    }

    void Rr17NcoOtSender::recvCorrection(Channel & chl, u64 recvCount)
    {
        auto size = recvCount * mEncodeSize / 8;
        chl.recv(mCorrection.data() + mCorrectionIdx, size);
        mCorrectionIdx += size;
    }


    void Rr17NcoOtSender::check(Channel & chl, block seed)
    {
    }


}
