#include "libOTe/Base/naor-pinkas.h"
#include "OosNcoOtReceiver.h"
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include  <mmintrin.h>
#include "OosDefines.h"
#include <cryptoTools/Common/ByteStream.h>
using namespace std;

namespace osuCrypto
{
    OosNcoOtReceiver::OosNcoOtReceiver(LinearCode & code, u64 statSecParam)
        :mHasBase(false),
        mStatSecParam(statSecParam),
        mCode(code)
    {}
    void OosNcoOtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseRecvOts)
    {

        if (baseRecvOts.size() % 128 != 0)
            throw std::runtime_error("rt error at " LOCATION);

        mGens.resize(baseRecvOts.size());

        for (u64 i = 0; i < mGens.size(); i++)
        {
            mGens[i][0].SetSeed(baseRecvOts[i][0]);
            mGens[i][1].SetSeed(baseRecvOts[i][1]);
        }
        mHasBase = true;
    }
    void OosNcoOtReceiver::init(u64 numOtExt, PRNG& prng, Channel& chl)
    {
        u64 doneIdx = 0;
        if (mHasBase == false)
            throw std::runtime_error("rt error at " LOCATION);


        const u8 superBlkSize(8);

        //TODO("Make the statistical sec param a parameter");
        // = 40;

        // this will be used as temporary buffers of 128 columns, 
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        std::array<std::array<block, superBlkSize>, 128> t0;
        std::array<std::array<block, superBlkSize>, 128> t1;

        // round up and add the extra OT used in the check at the end
        numOtExt = roundUpTo(numOtExt + mStatSecParam, 128);

        // we are going to process OTs in blocks of 128 * superblkSize messages.
        u64 numSuperBlocks = ((numOtExt) / 128 + superBlkSize - 1) / superBlkSize;
        u64 numCols = mGens.size();

        // The is the index of the last correction value u = T0 ^ T1 ^ c(w)
        // that was sent to the sender.
        mCorrectionIdx = 0;

        // We need three matrices, T0, T1, and mW. T1, T0 will hold the expanded 
        // and transposed rows that we got the using the base OTs as PRNG seed. 
        // mW will hold the record of all the words that we encoded. They will 
        // be used in the Check that is done at the end.
        mW = std::move(MatrixView<block>(numOtExt, mCode.plaintextBlkSize()));
        mT0 = std::move(MatrixView<block>(numOtExt, numCols / 128));
        mT1 = std::move(MatrixView<block>(numOtExt, numCols / 128));

        // An extra debugging check that can be used. Each one
        // gets marked as used, makes use we don't encode twice.
#ifndef NDEBUG
        mEncodeFlags.resize(numOtExt, 0);
#endif

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns 
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for  
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector  
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do. 
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want us to stop.
            // The code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min<u64>(u64(128) * superBlkSize, numOtExt - doneIdx);


            for (u64 i = 0; i < numCols / 128; ++i)
            {

                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    // generate the column indexed by colIdx. This is done with
                    // AES in counter mode acting as a PRNG. We don't use the normal
                    // PRNG interface because that would result in a data copy when 
                    // we mode it into the T0,T1 matrices. Instead we do it directly.
                    mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, superBlkSize, ((block*)t0.data() + superBlkSize * tIdx));
                    mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, superBlkSize, ((block*)t1.data() + superBlkSize * tIdx));

                    // increment the counter mode idx.
                    mGens[colIdx][0].mBlockIdx += superBlkSize;
                    mGens[colIdx][1].mBlockIdx += superBlkSize;
                }

                // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
                // each 128 bits wide.
                sse_transpose128x1024(t0);
                sse_transpose128x1024(t1);

                // This is the index of where we will store the matrix long term.
                // doneIdx is the starting row. i is the offset into the blocks of 128 bits.
                // __restrict isn't crucial, it just tells the compiler that this pointer
                // is unique and it shouldn't worry about pointer aliasing. 
                block* __restrict mT0Iter = mT0.data() + mT0.size()[1] * doneIdx + i;
                block* __restrict mT1Iter = mT1.data() + mT1.size()[1] * doneIdx + i;

                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    // because we transposed 1024 rows, the indexing gets a bit weird. But this
                    // is the location of the next row that we want. Keep in mind that we had long
                    // **contiguous** columns. 
                    block* __restrict t0Iter = ((block*)t0.data()) + j;
                    block* __restrict t1Iter = ((block*)t1.data()) + j;

                    // do the copy!
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        *mT0Iter = *(t0Iter);
                        *mT1Iter = *(t1Iter);

                        t0Iter += superBlkSize;
                        t1Iter += superBlkSize;

                        mT0Iter += mT0.size()[1];
                        mT1Iter += mT0.size()[1];
                    }
                }
            }


            doneIdx = stopIdx;
        }

    }


    std::unique_ptr<NcoOtExtReceiver> OosNcoOtReceiver::split()
    {
        auto* raw = new OosNcoOtReceiver(mCode, mStatSecParam);

        std::vector<std::array<block, 2>> base(mGens.size());

        for (u64 i = 0; i < base.size(); ++i)
        {
            base[i][0] = mGens[i][0].get<block>();
            base[i][1] = mGens[i][1].get<block>();
        }
        raw->setBaseOts(base);

        return std::unique_ptr<NcoOtExtReceiver>(raw);
    }

    void OosNcoOtReceiver::encode(
        u64 otIdx,
        const ArrayView<block> choice,
        // Output: the encoding of the plaintext
        block & val)
    {
#ifndef NDEBUG
        if (choice.size() != mCode.plaintextBlkSize())
            throw std::invalid_argument("");

        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extension");

        mEncodeFlags[otIdx] = 1;
#endif // !NDEBUG

        // use this for two thing, to store the code word and 
        // to store the zero message from base OT matrix transposed.
        std::array<block, 10> codeword;
        mCode.encode((ArrayView<block>)choice, (ArrayView<block>)codeword);




        block* t0Val = mT0.data() + mT0.size()[1] * otIdx;
        block* t1Val = mT1.data() + mT0.size()[1] * otIdx;
        block* wVal = mW.data() + mW.size()[1] * otIdx;


        // encode the correction value as u = T0 + T1 + c(w), there c(w) is a pseudo-random codeword.

        if (mT0.size()[1] == 4)
        {

            // this code here is optimized for codewords of size ~ 128 * 4.
            // Also assume that the word to be encoded is of size ~ 128 * 1.
#ifndef NDEBUG
            if (mW.size()[1] != 1) throw std::runtime_error(LOCATION);
#endif
            wVal[0] = choice[0];

            t1Val[0] = t1Val[0] ^ codeword[0];
            t1Val[1] = t1Val[1] ^ codeword[1];
            t1Val[2] = t1Val[2] ^ codeword[2];
            t1Val[3] = t1Val[3] ^ codeword[3];

            t1Val[0] = t1Val[0] ^ t0Val[0];
            t1Val[1] = t1Val[1] ^ t0Val[1];
            t1Val[2] = t1Val[2] ^ t0Val[2];
            t1Val[3] = t1Val[3] ^ t0Val[3];

#ifdef OOS_SHA_HASH
            SHA1  sha1;
            u8 hashBuff[SHA1::HashSize];
            // now hash it to remove the correlation.
            sha1.Update((u8*)t0Val, mT0.size()[1] * sizeof(block));
            sha1.Final(hashBuff);
            val = toBlock(hashBuff);
#else
            //H(x) = AES_f(H'(x)) + H'(x), where  H'(x) = AES_f(x_0) + x_0 + ... +  AES_f(x_n) + x_n. 
            mAesFixedKey.ecbEncFourBlocks(t0Val, codeword.data());

            codeword[0] = codeword[0] ^ t0Val[0];
            codeword[1] = codeword[1] ^ t0Val[1];
            codeword[2] = codeword[2] ^ t0Val[2];
            codeword[3] = codeword[3] ^ t0Val[3];

            val = codeword[0] ^ codeword[1];
            codeword[2] = codeword[2] ^ codeword[3];

            val = val ^ codeword[2];

            mAesFixedKey.ecbEncBlock(val, codeword[0]);
            val = val ^ codeword[0];
#endif

        }
        else
        {
            // copy the input word that was used. This will be used in the 
            // check step below.
            for (u64 i = 0; i < mW.size()[1]; ++i)
            {
                wVal[i] = choice[i];
            }

            for (u64 i = 0; i < mT0.size()[1]; ++i)
            {
                // reuse mT1 as the place we store the correlated value. 
                // this will later get sent to the sender.
                t1Val[i]
                    = codeword[i]
                    ^ t0Val[i]
                    ^ t1Val[i];
            }

#ifdef OOS_SHA_HASH
            SHA1  sha1;
            u8 hashBuff[SHA1::HashSize];
            // now hash it to remove the correlation.
            sha1.Update((u8*)t0Val, mT0.size()[1] * sizeof(block));
            sha1.Final(hashBuff);
            val = toBlock(hashBuff);
#else
            //H(x) = AES_f(H'(x)) + H'(x),     where  H'(x) = AES_f(x_0) + x_0 + ... +  AES_f(x_n) + x_n. 
            mAesFixedKey.ecbEncBlocks(t0Val, mT0.size()[1], codeword.data());

            val = ZeroBlock;
            for (u64 i = 0; i < mT0.size()[1]; ++i)
                val = val ^ codeword[i] ^ t0Val[i];


            mAesFixedKey.ecbEncBlock(val, codeword[0]);
            val = val ^ codeword[0];
#endif
        }



    }

    void OosNcoOtReceiver::zeroEncode(u64 otIdx)
    {
#ifndef NDEBUG
        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extension");

        mEncodeFlags[otIdx] = 1;
#endif // !NDEBUG

        block* t0Val = mT0.data() + mT0.size()[1] * otIdx;
        block* t1Val = mT1.data() + mT0.size()[1] * otIdx;
        block* wVal = mW.data() + mW.size()[1] * otIdx;

        // This codeword will be all zero. We assume the zero message is a valid codeword.
        for (u64 i = 0; i < mW.size()[1]; ++i)
        {
            wVal[i] = ZeroBlock;
        }

        // This is here in the case that you done want to encode a message.
        // It s more efficient since we don't call SHA.
        for (u64 i = 0; i < mT0.size()[1]; ++i)
        {
            // encode the zero message. We assume the zero message is a valid codeword.
            // Also, reuse mT1 as the place we store the correlated value. 
            // this will later get sent to the sender.
            t1Val[i]
                = t0Val[i]
                ^ t1Val[i];
        }
    }


    void OosNcoOtReceiver::getParams(
        bool maliciousSecure,
        u64 compSecParm,
        u64 statSecParam,
        u64 inputBitCount,
        u64 inputCount,
        u64 & inputBlkSize,
        u64 & baseOtCount)
    {
        inputBlkSize = mCode.plaintextBlkSize();
        baseOtCount = mCode.codewordBlkSize() * 128;
    }

    void OosNcoOtReceiver::sendCorrection(Channel & chl, u64 sendCount)
    {

#ifndef NDEBUG
        for (u64 i = mCorrectionIdx; i < sendCount + mCorrectionIdx; ++i)
        {
            if (mEncodeFlags[i] == 0)
                throw std::runtime_error("an item was not encoded. " LOCATION);
        }

#endif

        // this is potentially dangerous. We don't have a guarantee that mT1 will still exist when 
        // the network gets around to sending this. Oh well.
        TODO("Make this memory safe");
        chl.asyncSend(mT1.data() + (mCorrectionIdx * mT1.size()[1]), mT1.size()[1] * sendCount * sizeof(block));

        mCorrectionIdx += sendCount;
    }

    void OosNcoOtReceiver::check(Channel & chl, block wordSeed)
    {
        PRNG prng(wordSeed);
        u64 statSecParam(40);

        // first we need to do is the extra statSecParam number of correction
        // values. This will just be for random inputs and are used to mask
        // out true choices that were used in the remaining correction values.
        std::unique_ptr<ByteStream> wBuff(new Buff(sizeof(block) * statSecParam * mW.size()[1]));
        std::unique_ptr<ByteStream> tBuff(new Buff(sizeof(block) * statSecParam * mT0.size()[1]));
        
        // get two arrays of block into these buff.
        auto tSum = tBuff->getArrayView<block>();
        auto wSum = wBuff->getArrayView<block>();

        // generate random words.
        prng.get(wSum.data(), wSum.size());

        // view them as matrix to make life easier.
        MatrixView<block> words(wSum.begin(), wSum.end(), mCode.plaintextBlkSize());
        block seed;

        // encode each random word.
        for (u64 i = 0; i < statSecParam; ++i)
        {
            // the correction value is stored internally
            encode(mCorrectionIdx + i, words[i], seed);

            // initialize the tSum array with the T0 value used to encode these
            // random words.
            for (u64 j = 0; j < mT0.size()[1]; ++j)
            {
                tSum[i * mT0.size()[1] + j] = mT0[mCorrectionIdx + i][j];
            }
        }

        // now send the internally stored correction values.
        sendCorrection(chl, statSecParam);

        // the sender will now tell us the random challenge seed.
        chl.recv(&seed, sizeof(block));


        // This AES will work as a PRNG, using AES-NI in counter mode.
        AES aes(seed);
        // the index of the AES counter.
        u64 aesIdx(0);

        // the index of the row that we are doing.
        u64 k = 0;

        // This will be used as a fast way to multiply the random challenge bits
        // by the rows. zeroAndAllOneBlocks[0] will always be 00000.....00000,
        // and  zeroAndAllOneBlocks[1] will hold 111111.....111111. 
        // Multiplication is then just and array index and an & operation.
        // i.e.  x * block  <==>   block & zeroAndAllOneBlocks[x]
        // This is so much faster than if(x) sum[l] = sum[l] ^ block
        std::array<block, 2> zeroAndAllOneBlocks{ ZeroBlock, AllOneBlock };
        u64 codeSize = mT0.size()[1];

        // This will make the us send all of out input words
        // and the complete T0 matrix. For DEBUG only
#ifdef OOS_CHECK_DEBUG
        chl.send(mT0.data(), mT0.size()[0] * mT0.size()[1] * sizeof(block));
        chl.send(mW.data(), mW.size()[0] * mW.size()[1] * sizeof(block));
#endif

        // this will hold out random x^(l)_i values that we compute from the seed. 
        std::vector<block> challengeBuff(statSecParam);

        // since we don't want to do bit shifting, this larger array
        // will be used to hold each bit of challengeBuff as a whole
        // byte. See below for how we do this efficiently.
        std::vector<block> expandedBuff(statSecParam * 8);
        u8* byteView = (u8*)expandedBuff.data();

        // This will be used to compute expandedBuff
        block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

        // get raw pointer to this data. faster than normal indexing.
        auto mT0Iter = mT0.data();
        auto mWIter = mW.data();

        // compute the index that we should stop at. We process 128 rows at a time.
        u64 lStop = (mCorrectionIdx - statSecParam + 127) / 128;
        for (u64 l = 0; l < lStop; ++l)
        {

            // generate statSecParam * 128 bits using AES-NI in counter mode.
            aes.ecbEncCounterMode(aesIdx, statSecParam, challengeBuff.data());
            aesIdx += statSecParam;

            // now expand each of these bits into its own byte. This is done with the 
            // right shift instruction _mm_srai_epi16. and then we mask to get only
            // the bottom bit. Doing the 8 times gets us each bit in its own byte.
            for (u64 i = 0; i < statSecParam; ++i)
            {
                expandedBuff[i * 8 + 0] = mask & _mm_srai_epi16(challengeBuff[i], 0);
                expandedBuff[i * 8 + 1] = mask & _mm_srai_epi16(challengeBuff[i], 1);
                expandedBuff[i * 8 + 2] = mask & _mm_srai_epi16(challengeBuff[i], 2);
                expandedBuff[i * 8 + 3] = mask & _mm_srai_epi16(challengeBuff[i], 3);
                expandedBuff[i * 8 + 4] = mask & _mm_srai_epi16(challengeBuff[i], 4);
                expandedBuff[i * 8 + 5] = mask & _mm_srai_epi16(challengeBuff[i], 5);
                expandedBuff[i * 8 + 6] = mask & _mm_srai_epi16(challengeBuff[i], 6);
                expandedBuff[i * 8 + 7] = mask & _mm_srai_epi16(challengeBuff[i], 7);
            }

            // compute when we should stop of this set.

            u64 stopIdx = std::min<u64>(mCorrectionIdx - statSecParam - k, u64(128));
            k += 128;

            // get an integrator to the challenge bit
            u8* xIter = byteView;

            if (codeSize == 4)
            {

                //  vvvvvvvvvvvv   OPTIMIZED for codeword size 4   vvvvvvvvvvvv
                for (u64 i = 0; i < stopIdx; ++i, mT0Iter += 4)
                {
                    // get the index of the first summation.
                    auto tSumIter = tSum.data();

                    // For this row, iterate through all statSecParam challenge
                    // bits and add the row in if they are set to 1. We process
                    // two rows at a time.
                    for (u64 j = 0; j < statSecParam / 2; ++j, tSumIter += 8)
                    {
                        // get the challenge bits.
                        u8 x0 = *xIter++;
                        u8 x1 = *xIter++;

                        // dereference the challenge bits into blocks
                        // of either 000....0000 or 11111....111111
                        block mask0 = zeroAndAllOneBlocks[x0];
                        block mask1 = zeroAndAllOneBlocks[x1];

                        // now add the i'th row of T0 if the bit is 1.
                        // Otherwise this is a no op. Equiv. to an if(x).
                        auto t0x0 = *(mT0Iter + 0) & mask0;
                        auto t0x1 = *(mT0Iter + 1) & mask0;
                        auto t0x2 = *(mT0Iter + 2) & mask0;
                        auto t0x3 = *(mT0Iter + 3) & mask0;
                        auto t0x4 = *(mT0Iter + 0) & mask1;
                        auto t0x5 = *(mT0Iter + 1) & mask1;
                        auto t0x6 = *(mT0Iter + 2) & mask1;
                        auto t0x7 = *(mT0Iter + 3) & mask1;

                        // add them into the running totals.
                        tSumIter[0] = tSumIter[0] ^ t0x0;
                        tSumIter[1] = tSumIter[1] ^ t0x1;
                        tSumIter[2] = tSumIter[2] ^ t0x2;
                        tSumIter[3] = tSumIter[3] ^ t0x3;
                        tSumIter[4] = tSumIter[4] ^ t0x4;
                        tSumIter[5] = tSumIter[5] ^ t0x5;
                        tSumIter[6] = tSumIter[6] ^ t0x6;
                        tSumIter[7] = tSumIter[7] ^ t0x7;
                    }
                }

                xIter = byteView;
                for (u64 i = 0; i < stopIdx; ++i, ++mWIter)
                {
                    // now do the same but for the input words.
                    auto wSumIter = wSum.data();

                    for (u64 j = 0; j < statSecParam / 8; ++j, wSumIter += 8)
                    {
                        // we processes 8 rows of words at a time. Do the 
                        // same masking trick.
                        auto wx0 = (*mWIter & zeroAndAllOneBlocks[xIter[0]]);
                        auto wx1 = (*mWIter & zeroAndAllOneBlocks[xIter[1]]);
                        auto wx2 = (*mWIter & zeroAndAllOneBlocks[xIter[2]]);
                        auto wx3 = (*mWIter & zeroAndAllOneBlocks[xIter[3]]);
                        auto wx4 = (*mWIter & zeroAndAllOneBlocks[xIter[4]]);
                        auto wx5 = (*mWIter & zeroAndAllOneBlocks[xIter[5]]);
                        auto wx6 = (*mWIter & zeroAndAllOneBlocks[xIter[6]]);
                        auto wx7 = (*mWIter & zeroAndAllOneBlocks[xIter[7]]);

                        // add them into the running totals.
                        wSumIter[0] = wSumIter[0] ^ wx0;
                        wSumIter[1] = wSumIter[1] ^ wx1;
                        wSumIter[2] = wSumIter[2] ^ wx2;
                        wSumIter[3] = wSumIter[3] ^ wx3;
                        wSumIter[4] = wSumIter[4] ^ wx4;
                        wSumIter[5] = wSumIter[5] ^ wx5;
                        wSumIter[6] = wSumIter[6] ^ wx6;
                        wSumIter[7] = wSumIter[7] ^ wx7;

                        xIter += 8;
                    }
                }

                //  ^^^^^^^^^^^^^   OPTIMIZED for codeword size 4   ^^^^^^^^^^^^^
            }
            else
            {
                //  vvvvvvvvvvvv       general codeword size        vvvvvvvvvvvv

                for (u64 i = 0; i < stopIdx; ++i, mT0Iter += codeSize)
                {

                    auto tSumIter = tSum.data();

                    // For this row, iterate through all statSecParam challenge
                    // bits and add the row in if they are set to 1. We process
                    // two rows at a time.
                    for (u64 j = 0; j < statSecParam; ++j, tSumIter += codeSize)
                    {
                        block mask0 = zeroAndAllOneBlocks[*xIter++];
                        for (u64 m = 0; m < codeSize; ++m)
                        {
                            // now add the i'th row of T0 if the bit is 1.
                            // Otherwise this is a no op. Equiv. to an if(x).
                            tSumIter[m] = tSumIter[m] ^ (*(mT0Iter + m) & mask0);
                        }
                    }
                }

                if (mW.size()[1] != 1)
                    throw std::runtime_error("generalize this code vvvvvv " LOCATION);

                xIter = byteView;
                for (u64 i = 0; i < stopIdx; ++i, ++mWIter)
                {
                    auto wSumIter = wSum.data();

                    // now do the same but for the input words.
                    for (u64 j = 0; j < statSecParam / 8; ++j, wSumIter += 8)
                    {

                        // we processes 8 rows of words at a time. Do the 
                        // same masking trick.
                        auto wx0 = (*mWIter & zeroAndAllOneBlocks[xIter[0]]);
                        auto wx1 = (*mWIter & zeroAndAllOneBlocks[xIter[1]]);
                        auto wx2 = (*mWIter & zeroAndAllOneBlocks[xIter[2]]);
                        auto wx3 = (*mWIter & zeroAndAllOneBlocks[xIter[3]]);
                        auto wx4 = (*mWIter & zeroAndAllOneBlocks[xIter[4]]);
                        auto wx5 = (*mWIter & zeroAndAllOneBlocks[xIter[5]]);
                        auto wx6 = (*mWIter & zeroAndAllOneBlocks[xIter[6]]);
                        auto wx7 = (*mWIter & zeroAndAllOneBlocks[xIter[7]]);

                        // add them into the running totals.
                        wSumIter[0] = wSumIter[0] ^ wx0;
                        wSumIter[1] = wSumIter[1] ^ wx1;
                        wSumIter[2] = wSumIter[2] ^ wx2;
                        wSumIter[3] = wSumIter[3] ^ wx3;
                        wSumIter[4] = wSumIter[4] ^ wx4;
                        wSumIter[5] = wSumIter[5] ^ wx5;
                        wSumIter[6] = wSumIter[6] ^ wx6;
                        wSumIter[7] = wSumIter[7] ^ wx7;


                        xIter += 8;
                    }
                }

                //  ^^^^^^^^^^^^^      general codeword size        ^^^^^^^^^^^^^
            }

        }

        // send over our summations.
        chl.asyncSend(std::move(tBuff));
        chl.asyncSend(std::move(wBuff));
    }
}
