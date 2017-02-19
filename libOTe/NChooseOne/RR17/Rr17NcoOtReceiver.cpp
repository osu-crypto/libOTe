#include "Rr17NcoOtReceiver.h"
#include <cryptoTools/Common/ByteStream.h>
#include <cryptoTools/Common/Log.h>

namespace osuCrypto
{


    Rr17NcoOtReceiver::Rr17NcoOtReceiver()
    {
    }


    Rr17NcoOtReceiver::~Rr17NcoOtReceiver()
    {
    }
    bool Rr17NcoOtReceiver::hasBaseOts() const
    {
        return mKos.hasBaseOts();
    }
    void Rr17NcoOtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseRecvOts)
    {
        mKos.setBaseOts(baseRecvOts);
    }
    std::unique_ptr<NcoOtExtReceiver> Rr17NcoOtReceiver::split()
    {
        auto ret = std::unique_ptr<NcoOtExtReceiver>(new Rr17NcoOtReceiver());

        std::vector<std::array<block,2>> baseOts(mKos.mGens.size());

        for (u64 i = 0; i < baseOts.size(); ++i)
        {
            baseOts[i][0] = mKos.mGens[i][0].get<block>();
            baseOts[i][1] = mKos.mGens[i][1].get<block>();
        }

        ret->setBaseOts(baseOts);

        ((Rr17NcoOtReceiver*)ret.get())->mEncodeSize = mEncodeSize;

        return std::move(ret);
    }
    void Rr17NcoOtReceiver::init(u64 numOtExt, PRNG& prng, Channel& chl)
    {
        mMessages.resize(mEncodeSize * numOtExt);
        mChoices.resize(mEncodeSize * numOtExt);
        //std::cout << "ots = " << log2(mMessages.size()) << std::endl;

#ifndef NDEBUG
        mDebugEncodeFlags = std::move(BitVector(numOtExt));
#endif // !NDEBUG

        mChoices.randomize(prng);
        mSendIdx = 0;

        mKos.receive(mChoices, mMessages, prng, chl);


        auto stepSize = 1 << 24;
        auto count = (mMessages.size() + stepSize - 1) / stepSize;

        Buff buff(std::min<u64>(mMessages.size(), stepSize) * sizeof(std::array<block, 2>));
        auto view = buff.getArrayView<std::array<block, 2>>();
        auto choiceIter = mChoices.begin();

        //std::cout << IoStream::lock;
        for (u64 step = 0; step < count; ++step)
        {

            auto curSize = std::min<u64>(stepSize, mMessages.size() - step * stepSize);

            chl.recv(buff.data(), curSize * sizeof(std::array<block, 2>));
            //std::cout << "recv " << *(block*)buff.data() << " c " << count << " s " << curSize << std::endl;
            //std::cout << "recv " << ((block*)buff.data())[600 * 2] << " c " << count << " s " << curSize << std::endl;

            for (u64 i = 0, j = step * stepSize; i < curSize; ++i, ++j)
            {
                //std::cout << "r kos " << " " << j << " " << mMessages[j] << " " << *choiceIter << std::endl;
                //std::cout << "r msg " << " " << j << " " << view[i][0] << " " << view[i][1] << std::endl;

                mMessages[j] = mMessages[j] ^ view[i][*choiceIter++];
                //std::cout << "r Msg " << " " << j << " " << mMessages[j] << " " << *choiceIter << std::endl;

            }
        }
        //std::cout << IoStream::unlock;

    }
     
    void Rr17NcoOtReceiver::encode(
        u64 otIdx, 
        const ArrayView<block> choiceWord, 
        block & encoding)
    {
#ifndef NDEBUG
        if (mDebugEncodeFlags[otIdx])
            throw std::runtime_error(LOCATION);
        
        mDebugEncodeFlags[otIdx] = 1;
#endif


        otIdx *= mEncodeSize;


        auto iter = mChoices.data() + otIdx / 8;
        auto cIter = (u8*)choiceWord.data();
        for (u64 i = 0; i < mEncodeSize / 8; ++i, ++iter, ++cIter)
        {
            *iter = *iter ^ *cIter;
        }

        //encoding = ZeroBlock;
        //for (u64 i = 0; i < mEncodeSize; ++i)
        //    encoding = encoding ^ mMessages[otIdx++];


        SHA1 sha;
        sha.Update((u8*)(mMessages.data() + otIdx), mEncodeSize * sizeof(block));


        sha.Update((u8*)choiceWord.data(), mEncodeSize / 8);

        u8 buff[SHA1::HashSize];
        sha.Final(buff);

        encoding = toBlock(buff);
    }

    void Rr17NcoOtReceiver::zeroEncode(u64 otIdx)
    {
        // no op
    }

    void Rr17NcoOtReceiver::getParams(
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

    void Rr17NcoOtReceiver::sendCorrection(Channel & chl, u64 sendCount)
    {
        auto size = sendCount * mEncodeSize / 8;
        chl.asyncSend(mChoices.data() + mSendIdx, size);
        mSendIdx += size;
    }

    void Rr17NcoOtReceiver::check(Channel & chl, block seed)
    {
        // no op
    }
}
