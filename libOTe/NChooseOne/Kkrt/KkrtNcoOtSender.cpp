#include "KkrtNcoOtSender.h"
#ifdef ENABLE_KKRT
#include <cryptoTools/Network/IOService.h>
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include "KkrtDefines.h"
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    using namespace std;

    void KkrtNcoOtSender::setBaseOts(
        span<block> baseRecvOts,
        const BitVector & choices)
    {
        if (choices.size() != u64(baseRecvOts.size()))
            throw std::runtime_error("size mismatch");

        if (choices.size() != u64(mGens.size()))
            throw std::runtime_error("only multiples of 128 are supported");


        mBaseChoiceBits = choices;
        mGens.resize(choices.size());
        mGensBlkIdx.resize(choices.size(), 0);

        for (u64 i = 0; i < u64(baseRecvOts.size()); i++)
        {
            mGens[i].setKey(baseRecvOts[i]);
        }

        mChoiceBlks.resize(choices.size() / (sizeof(block) * 8));
        for (u64 i = 0; i < mChoiceBlks.size(); ++i)
        {
            mChoiceBlks[i] = toBlock(mBaseChoiceBits.data() + (i * sizeof(block)));
        }
    }

    KkrtNcoOtSender KkrtNcoOtSender::splitBase()
    {
        KkrtNcoOtSender raw;
        raw.mGens.resize(mGens.size());
        raw.mInputByteCount = mInputByteCount;
        raw.mMultiKeyAES = mMultiKeyAES;

        if (hasBaseOts())
        {

            std::vector<block> base(mGens.size());

            // use some of the OT extension PRNG to new base OTs
            for (u64 i = 0; i < base.size(); ++i)
            {
                mGens[i].ecbEncCounterMode(mGensBlkIdx[i]++, 1, &base[i]);
                //base[i] = mGens[i].get<block>();
            }
            raw.setBaseOts(base, mBaseChoiceBits);
        }
#ifdef OC_NO_MOVE_ELISION 
        return std::move(raw);
#else
        return raw;
#endif
    }

    std::unique_ptr<NcoOtExtSender> KkrtNcoOtSender::split()
    {
        return std::make_unique<KkrtNcoOtSender>((splitBase()));
    }

    task<> KkrtNcoOtSender::init(
        u64 numOTExt, PRNG& prng, Socket& chl)
    {

        MC_BEGIN(task<>,this, numOTExt, &prng, &chl,
            seed = block{}, 
            theirSeed = block{},
            comm = std::array<u8, RandomOracle::HashSize>{}
            );

        if (hasBaseOts() == false)
            MC_AWAIT( genBaseOts(prng, chl));


        {
            seed = prng.get<block>();
            RandomOracle hasher;
            hasher.Update(seed);
            hasher.Final(comm);
        }

        MC_AWAIT(chl.send(std::move(comm)));

        
        {


            static const u8 superBlkSize(8);

            // round up
            numOTExt = ((numOTExt + 127) / 128) * 128;

            // We need two matrices, one for the senders matrix T^i_{b_i} and
            // one to hold the correction values. This is sometimes called
            // the u = T0 + T1 + C matrix in the papers.
            mT.resize(numOTExt, mGens.size() / 128);
            //char c;
            //chl.recv(&c, 1);

            mCorrectionVals.resize(numOTExt, mGens.size() / 128);

            // The receiver will send us correction values, this is the index of
            // the next one they will send.
            mCorrectionIdx = 0;

            // we are going to process OTs in blocks of 128 * superblkSize messages.
            u64 numSuperBlocks = (numOTExt / 128 + superBlkSize - 1) / superBlkSize;

            // the index of the last OT that we have completed.
            u64 doneIdx = 0;

        // a temp that will be used to transpose the sender's matrix
        AlignedArray<std::array<block, superBlkSize>, 128> t;

            u64 numCols = mGens.size();

            for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
            {
                // compute at what row does the user want use to stop.
                // the code will still compute the transpose for these
                // extra rows, but it is thrown away.
                u64 stopIdx
                    = doneIdx
                    + std::min<u64>(u64(128) * superBlkSize, mT.bounds()[0] - doneIdx);

                // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
                for (u64 i = 0; i < numCols / 128; ++i)
                {
                    // generate the columns using AES-NI in counter mode.
                    for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                    {
                        mGens[colIdx].ecbEncCounterMode(mGensBlkIdx[colIdx], superBlkSize, ((block*)t.data() + superBlkSize * tIdx));
                        mGensBlkIdx[colIdx] += superBlkSize;
                    }

                    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                    // each 128 bits wide.
                    transpose128x1024(t);

                    // This is the index of where we will store the matrix long term.
                    // doneIdx is the starting row. i is the offset into the blocks of 128 bits.
                    // __restrict isn't crucial, it just tells the compiler that this pointer
                    // is unique and it shouldn't worry about pointer aliasing.
                    block* __restrict mTIter = mT.data() + doneIdx * mT.stride() + i;

                    for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                    {
                        // because we transposed 1024 rows, the indexing gets a bit weird. But this
                        // is the location of the next row that we want. Keep in mind that we had long
                        // **contiguous** columns.
                        block* __restrict tIter = (((block*)t.data()) + j);

                        // do the copy!
                        for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                        {
                            *mTIter = *tIter;

                            tIter += superBlkSize;
                            mTIter += mT.stride();
                        }
                    }

                }

                doneIdx = stopIdx;
            }
        }

        MC_AWAIT(chl.recv(theirSeed));
        MC_AWAIT(chl.send(std::move(seed)));

        {

            std::array<block, 4> keys;
            PRNG(seed ^ theirSeed).get(keys.data(), keys.size());
            mMultiKeyAES.setKeys(keys);
        }

        MC_END();
    }

    void KkrtNcoOtSender::encode(u64 otIdx, const void * input, void * dest, u64 destSize)
    {

#ifndef NDEBUG
        if (eq(mCorrectionVals[otIdx][0], ZeroBlock))
            throw std::invalid_argument("appears that we haven't received the receiver's choice yet. " LOCATION);
#endif // !NDEBUG
#define KKRT_WIDTH 4
        //static const int width(4);

        block word = ZeroBlock;
        memcpy(&word, input, mInputByteCount);

        std::array<block, KKRT_WIDTH> choice{ word ,word ,word ,word }, code;
        mMultiKeyAES.ecbEncNBlocks(choice.data(), code.data());

        auto* corVal = mCorrectionVals.data() + otIdx * mCorrectionVals.stride();
        auto* tVal = mT.data() + otIdx * mT.stride();


        // This is the hashing phase. Here we are using pseudo-random codewords.
        // That means we assume inputword is a hash of some sort.
#if KKRT_WIDTH == 4
		code[0] = code[0] ^ word;
		code[1] = code[1] ^ word;
		code[2] = code[2] ^ word;
		code[3] = code[3] ^ word;

		block t00 = corVal[0] ^ code[0];
		block t01 = corVal[1] ^ code[1];
		block t02 = corVal[2] ^ code[2];
		block t03 = corVal[3] ^ code[3];
		block t10 = t00 & mChoiceBlks[0];
		block t11 = t01 & mChoiceBlks[1];
		block t12 = t02 & mChoiceBlks[2];
		block t13 = t03 & mChoiceBlks[3];

		code[0] = tVal[0] ^ t10;
		code[1] = tVal[1] ^ t11;
		code[2] = tVal[2] ^ t12;
		code[3] = tVal[3] ^ t13;
#else
        
            for (u64 i = 0; i < KKRT_WIDTH; ++i)
            {
                code[i] = code[i] ^ word;

                block t0 = corVal[i] ^ code[i];
                block t1 = t0 & mChoiceBlks[i];

                code[i]
                    = tVal[i]
                    ^ t1;
            }
#endif

#ifdef KKRT_SHA_HASH
        RandomOracle  sha1(destSize);
        // hash it all to get rid of the correlation.
        sha1.Update((u8*)code.data(), sizeof(block) * mT.stride());
        sha1.Final((u8*)dest);
#else
        std::array<block, 10> aesBuff;
        mAesFixedKey.ecbEncBlocks(code.data(), mT.stride(), aesBuff.data());

        auto val = ZeroBlock;
        for (u64 i = 0; i < mT.stride(); ++i)
            val = val ^ code[i] ^ aesBuff[i];

        memcpy(dest, hashBuff, std::min(destSize, sizeof(block)));
#endif


    }


    void KkrtNcoOtSender::configure(
        bool maliciousSecure,
        u64 statSecParam,
        u64 inputBitCount)
    {

        if (maliciousSecure) throw std::runtime_error(LOCATION);
        if (inputBitCount > 128) throw std::runtime_error(LOCATION);

        mInputByteCount = (inputBitCount + 7) / 8;
        mGens.resize(128 * 4);
    }

    u64 KkrtNcoOtSender::getBaseOTCount() const
    {
        if (mGens.size())
            return mGens.size();
        else
            throw std::runtime_error("must call configure(...) before getBaseOTCount() " LOCATION);
    }

    task<> KkrtNcoOtSender::recvCorrection(Socket & chl, u64 recvCount)
    {

#ifndef NDEBUG
        if (recvCount > mCorrectionVals.bounds()[0] - mCorrectionIdx)
            throw std::runtime_error("bad receiver, will overwrite the end of our buffer" LOCATION);
#endif // !NDEBUG

        // receive the next OT correction values. This will be several rows of the form u = T0 + T1 + C(w)
        // there c(w) is a pseudo-random code.
        auto dest = mCorrectionVals.begin() + (mCorrectionIdx * mCorrectionVals.stride());
        // update the index of there we should store the next set of correction values.
        mCorrectionIdx += recvCount;
        MC_BEGIN(task<>, this, &chl, dest, recvCount);
        MC_AWAIT(chl.recv(span<block>(&*dest, recvCount * mCorrectionVals.stride())));
        MC_END();
    }

    //u64 KkrtNcoOtSender::recvCorrection(Channel & chl)
    //{

    //    // receive the next OT correction values. This will be several rows of the form u = T0 + T1 + C(w)
    //    // there c(w) is a pseudo-random code.
    //    auto dest = mCorrectionVals.data() + i32(mCorrectionIdx * mCorrectionVals.stride());
    //    auto maxReceiveCount = (mCorrectionVals.rows() - mCorrectionIdx) * mCorrectionVals.stride();

    //    ReceiveAtMost<block> receiver(dest, maxReceiveCount);
    //    chl.recv(receiver);

    //    // check that the number of blocks received is ok.
    //    if (receiver.receivedSize() % mCorrectionVals.stride())
    //        throw std::runtime_error("An even number of correction blocks were not sent. " LOCATION);

    //    // compute how many corrections were received.
    //    auto numCorrections = receiver.receivedSize() / mCorrectionVals.stride();

    //    // update the index of there we should store the next set of correction values.
    //    mCorrectionIdx += numCorrections;

    //    return numCorrections;
    //}



}
#endif