#include "Rr17NcoOtReceiver.h"
#include "cryptoTools/Common/ByteStream.h"

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
        mMessage.resize(mEncodeSize * numOtExt);
        mChoices.resize(mEncodeSize * numOtExt);

#ifndef NDEBUG
        mDebugEncodeFlags = std::move(BitVector(numOtExt));
#endif // !NDEBUG

        mChoices.randomize(prng);
        mSendIdx = 0;

        mKos.receive(mChoices, mMessage, prng, chl);


        Buff buff;
        chl.recv(buff);
        auto view = buff.getArrayView<std::array<block, 2>>();

        if (view.size() != mMessage.size())
            throw std::runtime_error(LOCATION);

        auto choiceIter = mChoices.begin();

        for (u64 i = 0; i < mMessage.size(); ++i)
        {
            mMessage[i] = mMessage[i] ^ view[i][*choiceIter++];
        }
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

        SHA1 sha;
        sha.Update((u8*)(mMessage.data() + otIdx), mEncodeSize * sizeof(block));


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
        chl.send(mChoices.data() + mSendIdx, size);
        mSendIdx += size;
    }

    void Rr17NcoOtReceiver::check(Channel & chl, block seed)
    {
        // no op
    }
}
