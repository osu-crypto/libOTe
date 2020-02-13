#include "Rr17NcoOtSender.h"
#ifdef ENABLE_RR

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/RandomOracle.h>
namespace osuCrypto
{


    bool Rr17NcoOtSender::hasBaseOts() const
    {
        return mKos.hasBaseOts();
    }

    void Rr17NcoOtSender::setBaseOts(
        span<block> baseRecvOts, const BitVector & choices, Channel& chl)
    {
        mKos.setBaseOts(baseRecvOts, choices, chl);
    }

    std::unique_ptr<NcoOtExtSender> Rr17NcoOtSender::split()
    {
        auto p = new Rr17NcoOtSender;
        auto ret = std::unique_ptr<NcoOtExtSender>(p);
        p->mKos = mKos.splitBase();
        p->mInputByteCount = mInputByteCount;

        //if (hasBaseOts())
        //{

        //    std::vector<block> baseOts(mKos.mBaseChoiceBits.size());

        //    for (u64 i = 0; i < baseOts.size(); ++i)
        //    {
        //        baseOts[i] = mKos.mGens[i].get<block>();
        //    }

        //    ret->setBaseOts(baseOts, mKos.mBaseChoiceBits);
        //}
        //((Rr17NcoOtSender*)ret.get())

        return std::move(ret);
    }

    void Rr17NcoOtSender::init(u64 numOtExt, PRNG& prng, Channel& chl)
    {
        if (hasBaseOts() == false)
            genBaseOts(prng, chl);

        mMessages.resize(numOtExt * mInputByteCount * 8);
        prng.mAes.ecbEncCounterMode(prng.mBlockIdx, mMessages.size() * 2, (block*)mMessages.data());
        prng.mBlockIdx += mMessages.size() * 2;

        mCorrectionIdx = 0;
        mCorrection.resize(mMessages.size());

        u8* buff(new u8[mMessages.size() * sizeof(std::array<block, 2>)]);
        span<std::array<block, 2>> view((std::array<block, 2>*)buff, mMessages.size());
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
                auto chunk = span<u8>(buff + step * stepSize, curSize * sizeof(std::array<block, 2>));
                chl.asyncSend(std::move(chunk), [buff]() 
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


    void Rr17NcoOtSender::encode(
        u64 otIdx,
        const void* input,
        void* dest,
        u64 destSize)
    {

//#ifndef NDEBUG
//        if (choiceWord.size() != 1)
//            throw std::runtime_error(LOCATION);
//#endif
        //BitVector mCorrections;
        block correction = toBlock(mCorrection.data() + otIdx * mInputByteCount);
        block choice = ZeroBlock;
        memcpy(&choice, input, mInputByteCount);
        choice = choice ^ correction;

        BitIterator iter((u8*)&choice, 0);
        otIdx *= mInputByteCount * 8;

        //encoding = ZeroBlock;
        //for (u64 i = 0; i < mEncodeSize; ++i)
        //    encoding = encoding  ^ mMessages[otIdx++][*iter++];

        RandomOracle sha;
        u8 buff[RandomOracle::HashSize];

        for (u64 i = 0; i < (mInputByteCount*8); ++i)
            sha.Update(mMessages[otIdx++][*iter++]);

        sha.Update((u8*)input, mInputByteCount);
        sha.Final(buff);
        memcpy(dest, buff, std::min<u64>(RandomOracle::HashSize, destSize));
        //encoding = *(block*)buff;
    }

    void Rr17NcoOtSender::configure(
        bool maliciousSecure,
        u64 statSecParam,
        u64 inputBitCount)
    {
        if (maliciousSecure == false)
            throw std::runtime_error(LOCATION);

        if (inputBitCount > 128)
            throw std::runtime_error(LOCATION);

        mInputByteCount = (inputBitCount + 7) / 8; 
    }

    void Rr17NcoOtSender::recvCorrection(Channel & chl, u64 recvCount)
    {
        auto size = recvCount * mInputByteCount;
        chl.recv(mCorrection.data() + mCorrectionIdx, size);
        mCorrectionIdx += size;
    }


    void Rr17NcoOtSender::check(Channel & chl, block seed)
    {
    }


}
#endif