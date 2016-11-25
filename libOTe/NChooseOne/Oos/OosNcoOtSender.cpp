#include "OosNcoOtSender.h"
#include "Tools/Tools.h"
#include "Common/Log.h"
#include "OosDefines.h"
#include "Common/ByteStream.h"
namespace osuCrypto
{

    OosNcoOtSender::~OosNcoOtSender()
    {
    }

    void OosNcoOtSender::setBaseOts(
        ArrayView<block> baseRecvOts,
        const BitVector & choices)
    {
        if (choices.size() != baseRecvOts.size())
            throw std::runtime_error("size mismatch");

        if (choices.size() % (sizeof(block) * 8) != 0)
            throw std::runtime_error("only multiples of 128 are supported");


        mBaseChoiceBits = choices;
        mGens.resize(choices.size());

        for (u64 i = 0; i < baseRecvOts.size(); i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }

        mChoiceBlks.resize(choices.size() / (sizeof(block) * 8));
        for (u64 i = 0; i < mChoiceBlks.size(); ++i)
        {
            mChoiceBlks[i] = toBlock(mBaseChoiceBits.data() + (i * sizeof(block)));
        }
    }

    std::unique_ptr<NcoOtExtSender> OosNcoOtSender::split()
    {
        auto* raw = new OosNcoOtSender(mCode);

        std::vector<block> base(mGens.size());

        // use some of the OT extension PRNG to new base OTs
        for (u64 i = 0; i < base.size(); ++i)
        {
            base[i] = mGens[i].get<block>();
        }
        raw->setBaseOts(base, mBaseChoiceBits);

        return std::unique_ptr<NcoOtExtSender>(raw);
    }





    void OosNcoOtSender::init(
        u64 numOTExt)
    {
        const u8 superBlkSize(8);

        u64 statSecParm = 40;

        // round up
        numOTExt = ((numOTExt + 127 + statSecParm) / 128) * 128;

        // We need two matrices, one for the senders matrix T^i_{b_i} and 
        // one to hold the the correction values. This is sometimes called 
        // the u = T0 + T1 + C matrix in the papers.
        mCorrectionVals = std::move(MatrixView<block>(numOTExt, mGens.size() / 128));
        mT = std::move(MatrixView<block>(numOTExt, mGens.size() / 128));

        // The receiver will send us correction values, this is the index of
        // the next one they will send.
        mCorrectionIdx = 0;

        // we are going to process OTs in blocks of 128 * superblkSize messages.
        u64 numSuperBlocks = (numOTExt / 128 + superBlkSize - 1) / superBlkSize;

        // the index of the last OT that we have completed.
        u64 doneIdx = 0;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t;

        u64 numCols = mGens.size();


        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want use to stop.
            // the code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min(u64(128) * superBlkSize, mT.size()[0] - doneIdx);

            for (u64 i = 0; i < numCols / 128; ++i)
            {

                // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    // generate the columns using AES-NI in counter mode.
                    mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, ((block*)t.data() + superBlkSize * tIdx));
                    mGens[colIdx].mBlockIdx += superBlkSize;
                }

                // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
                // each 128 bits wide.
                sse_transpose128x1024(t);

                // This is the index of where we will store the matrix long term.
                // doneIdx is the starting row. l is the offset into the blocks of 128 bits.
                // __restrict isn't crucial, it just tells the compiler that this pointer
                // is unique and it shouldn't worry about pointer aliasing. 
                block* __restrict mTIter = mT.data() + doneIdx * mT.size()[1] + i;

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
                        mTIter += mT.size()[1];
                    }
                }

            }

            doneIdx = stopIdx;
        }
    }


    void OosNcoOtSender::encode(
        u64 otIdx,
        const ArrayView<block> plaintext,
        block& val)
    {

#ifndef NDEBUG
        if (plaintext.size() != mCode.plaintextBlkSize())
            throw std::invalid_argument("");
#endif // !NDEBUG

        // compute the codeword. We assume the
        // the codeword is less that 10 block = 1280 bits.
        std::array<block, 10> codeword;
        mCode.encode(plaintext, codeword);

#ifdef OOS_SHA_HASH
        SHA1  sha1;
        u8 hashBuff[SHA1::HashSize];
#else
        std::array<block, 10> aesBuff;
#endif
        // the index of the otIdx'th correction value u = t1 + t0 + c(w)
        // and the associated T value held by the sender.
        auto* corVal = mCorrectionVals.data() + otIdx * mCorrectionVals.size()[1];
        auto* tVal = mT.data() + otIdx * mT.size()[1];


        // This is the hashing phase. Here we are using
        //  codewords that we computed above. 
        if (mT.size()[1] == 4)
        {
            // use vector instructions if we can. You can optimize this
            // for your use case too.
            block t0 = corVal[0] ^ codeword[0];
            block t1 = corVal[1] ^ codeword[1];
            block t2 = corVal[2] ^ codeword[2];
            block t3 = corVal[3] ^ codeword[3];

            t0 = t0 & mChoiceBlks[0];
            t1 = t1 & mChoiceBlks[1];
            t2 = t2 & mChoiceBlks[2];
            t3 = t3 & mChoiceBlks[3];

            codeword[0] = tVal[0] ^ t0;
            codeword[1] = tVal[1] ^ t1;
            codeword[2] = tVal[2] ^ t2;
            codeword[3] = tVal[3] ^ t3;

#ifdef OOS_SHA_HASH
            // hash it all to get rid of the correlation.
            sha1.Update((u8*)codeword.data(), sizeof(block) * mT.size()[1]);
            sha1.Final(hashBuff);
            val = toBlock(hashBuff);
#else
            //H(x) = AES_f(H'(x)) + H'(x),     where  H'(x) = AES_f(x_0) + x_0 + ... +  AES_f(x_n) + x_n. 
            mAesFixedKey.ecbEncFourBlocks(codeword.data(), aesBuff.data());
            codeword[0] = codeword[0] ^ aesBuff[0];
            codeword[1] = codeword[1] ^ aesBuff[1];
            codeword[2] = codeword[2] ^ aesBuff[2];
            codeword[3] = codeword[3] ^ aesBuff[3];

            val =         codeword[0] ^ codeword[1];
            codeword[2] = codeword[2] ^ codeword[3];

            val = val ^ codeword[2];

            mAesFixedKey.ecbEncBlock(val, codeword[0]);
            val = val ^ codeword[0];
#endif
        }
        else
        {
            // this is the general case. slightly slower...
            for (u64 i = 0; i < mT.size()[1]; ++i)
            {
                block t0 = corVal[i] ^ codeword[i];
                block t1 = t0 & mChoiceBlks[i];

                codeword[i]
                    = tVal[i]
                    ^ t1;
            }
#ifdef OOS_SHA_HASH
            // hash it all to get rid of the correlation.
            sha1.Update((u8*)codeword.data(), sizeof(block) * mT.size()[1]);
            sha1.Final(hashBuff);
            val = toBlock(hashBuff);
#else
            //H(x) = AES_f(H'(x)) + H'(x),     where  H'(x) = AES_f(x_0) + x_0 + ... +  AES_f(x_n) + x_n. 
            mAesFixedKey.ecbEncBlocks(codeword.data(), mT.size()[1], aesBuff.data());

            val = ZeroBlock;
            for (u64 i = 0; i < mT.size()[1]; ++i)
                val = val ^ codeword[i] ^ aesBuff[i];


            mAesFixedKey.ecbEncBlock(val, codeword[0]);
            val = val ^ codeword[0];
#endif
        }
    }

    void OosNcoOtSender::getParams(
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

    void OosNcoOtSender::recvCorrection(Channel & chl, u64 recvCount)
    {

#ifndef NDEBUG
        if (recvCount > mCorrectionVals.size()[0] - mCorrectionIdx)
            throw std::runtime_error("bad receiver, will overwrite the end of our buffer" LOCATION);

#endif // !NDEBUG        


        // receive the next OT correction values. This will be several rows of the form u = T0 + T1 + C(w)
        // there c(w) is a pseudo-random code.
        auto dest = mCorrectionVals.begin() + (mCorrectionIdx * mCorrectionVals.size()[1]);
        chl.recv(dest,
            recvCount * sizeof(block) * mCorrectionVals.size()[1]);

        // update the index of there we should store the next set of correction values.
        mCorrectionIdx += recvCount;
    }

    void OosNcoOtSender::check(Channel & chl)
    {
        TODO("Use read seed");
        block seed = ZeroBlock;
        u64 statSecParam(40);

        if (statSecParam % 8) throw std::runtime_error("Must be a multiple of 8. " LOCATION);

        // first we need to receive the extra statSecParam number of correction
        // values. This will just be for random inputs and are used to mask
        // their true choices that were used in the remaining correction values.
        recvCorrection(chl, statSecParam);

        // now send them out challenge seed.
        chl.asyncSend(&seed, sizeof(block));

        // This AES will work as a PRNG, using AES-NI in counter mode.
        AES aes(seed);
        // the index of the AES counter.
        u64 aesIdx(0);

        // the index of the row that we are doing.
        u64 k = 0;

        // qSum will hold the summation over all the rows. We need 
        // statSecParam number of them. First initialize them, each 
        // with one of the dummy values that were just send. 
        std::vector<block> qSum(statSecParam * mT.size()[1]);
        for (u64 i = 0; i < statSecParam; ++i)
        {
            // The rows are most likely several blocks wide.
            for (u64 j = 0; j < mT.size()[1]; ++j)
            {
                qSum[i * mT.size()[1] + j]
                    = (mCorrectionVals[mCorrectionIdx - statSecParam + i][j]
                        & mChoiceBlks[j])
                    ^ mT[mCorrectionIdx - statSecParam + i][j];
            }
        }

        // This will make the receiver send all of their input words
        // and the complete T0 matrix. For DEBUG only
#ifdef OOS_CHECK_DEBUG
        Buff mT0Buff, mWBuff;
        chl.recv(mT0Buff);
        chl.recv(mWBuff);

        auto mT0 = mT0Buff.getMatrixView<block>(mCode.codewordBlkSize());
        auto mW = mWBuff.getMatrixView<block>(mCode.plaintextBlkSize());
#endif

        u64 codeSize = mT.size()[1];

        // This is an optimization trick. When iterating over the rows,
        // we want to multiply the x^(l)_i bit with the l'th row. To
        // do this we will index using zeroAndQ and & instead of of multiplication.
        // To make this work, the zeroAndQ[0] will always be 00000.....00000,
        // and  zeroAndQ[1] will hold the q_i row. This is so much faster than
        // if(x^(l)_i) qSum[l] = qSum[l] ^ q_i.
        std::array<std::array<block, 8>, 2> zeroAndQ;

        // set it all to zero initially.
        memset(zeroAndQ.data(), 0, zeroAndQ.size() * 2 * sizeof(block));

        // make sure that having this allocated on the stack is ok.
        if (codeSize < zeroAndQ.size()) throw std::runtime_error("Make this bigger. " LOCATION);


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
        auto corIter = mCorrectionVals.data();
        auto tIter = mT.data();

        // compute the index that we should stop at. We process 128 rows at a time.
        u64 blkStopIdx = (mCorrectionIdx - statSecParam + 127) / 128;
        for (u64 blkIdx = 0; blkIdx < blkStopIdx; ++blkIdx)
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
            u64 stopIdx = std::min(mCorrectionIdx - statSecParam - k, u64(128));
            k += 128;

            // get an integrator to the challenge bit
            u8* xIter = byteView;

            if (mT.size()[1] == 4)
            {
                //  vvvvvvvvvvvv   OPTIMIZED for codeword size 4   vvvvvvvvvvvv

                for (u64 i = 0; i < stopIdx; ++i, corIter += 4, tIter += 4)
                {

                    // compute q_i = (u_i & choice) ^ T_i
                    auto q0 = (corIter[0] & mChoiceBlks[0]);
                    auto q1 = (corIter[1] & mChoiceBlks[1]);
                    auto q2 = (corIter[2] & mChoiceBlks[2]);
                    auto q3 = (corIter[3] & mChoiceBlks[3]);

                    // place it in the one location of zeroAndQ. This will
                    // be used for efficient multiplication of q_i by the bit x^(l)_i
                    zeroAndQ[1][0] = q0 ^ tIter[0];
                    zeroAndQ[1][1] = q1 ^ tIter[1];
                    zeroAndQ[1][2] = q2 ^ tIter[2];
                    zeroAndQ[1][3] = q3 ^ tIter[3];

                    // This is meant to debug the check. If turned on,
                    // the receiver will have sent it's T0 and W matrix.
                    // This will let us identify the row that things go wrong...
#ifdef OOS_CHECK_DEBUG
                    u64 kk = k - 128;
                    std::vector<block> cw(mCode.codewordBlkSize());
                    mCode.encode(mW[kk], cw);

                    for (u64 j = 0; j < 4; ++j)
                    {
                        block tq = mT0[kk][j] ^ zeroAndQ[j][1];
                        block cb = cw[j] & mChoiceBlks[j];

                        if (neq(tq, cb))
                        {
                            throw std::runtime_error("");
                        }
                    }
#endif

                    // get a raw pointer into the first summation
                    auto qSumIter = qSum.data();

                    // iterate over the statSecParam of challenges. Process
                    // two of the value per loop. 
                    for (u64 j = 0; j < statSecParam / 2; ++j, qSumIter += 8)
                    {
                        u8 x0 = *xIter++;
                        u8 x1 = *xIter++;

                        // This is where the bit multiplication of 
                        // x^(l)_i * q_i happens. Its done with a single 
                        // array index instruction. If x is zero, then mask
                        // will hold the all zero string. Otherwise it holds
                        // the row q_i.
                        block* mask0 = zeroAndQ[x0].data();
                        block* mask1 = zeroAndQ[x1].data();

                        // Xor it in.
                        qSumIter[0] = qSumIter[0] ^ mask0[0];
                        qSumIter[1] = qSumIter[1] ^ mask0[1];
                        qSumIter[2] = qSumIter[2] ^ mask0[2];
                        qSumIter[3] = qSumIter[3] ^ mask0[3];
                        qSumIter[4] = qSumIter[4] ^ mask1[0];
                        qSumIter[5] = qSumIter[5] ^ mask1[1];
                        qSumIter[6] = qSumIter[6] ^ mask1[2];
                        qSumIter[7] = qSumIter[7] ^ mask1[3];
                    }
                }

                //  ^^^^^^^^^^^^^   OPTIMIZED for codeword size 4   ^^^^^^^^^^^^^
            }
            else
            {
                //  vvvvvvvvvvvv       general codeword size        vvvvvvvvvvvv

                for (u64 i = 0; i < stopIdx; ++i, corIter += codeSize, tIter += codeSize)
                {
                    for (u64 m = 0; m < codeSize; ++m)
                    {
                        // compute q_i = (u_i & choice) ^ T_i
                        // place it in the one location of zeroAndQ. This will
                        // be used for efficient multiplication of q_i by the bit x^(l)_i
                        zeroAndQ[1][m] = (corIter[m] & mChoiceBlks[m]) ^ tIter[m];
                    }

                    // This is meant to debug the check. If turned on,
                    // the receiver will have sent it's T0 and W matrix.
                    // This will let us identify the row that things go wrong...
#ifdef OOS_CHECK_DEBUG
                    u64 kk = k - 128;
                    std::vector<block> cw(mCode.codewordBlkSize());
                    mCode.encode(mW[kk], cw);

                    for (u64 j = 0; j < codeSize; ++j)
                    {
                        block tq = mT0[kk][j] ^ zeroAndQ[j][1];
                        block cb = cw[j] & mChoiceBlks[j];

                        if (neq(tq, cb))
                        {
                            throw std::runtime_error("");
                        }
                    }
#endif
                    // get a raw pointer into the first summation
                    auto qSumIter = qSum.data();

                    // iterate over the statSecParam of challenges. Process
                    // two of the value per loop. 
                    for (u64 j = 0; j < statSecParam; ++j, qSumIter += codeSize)
                    {

                        // This is where the bit multiplication of 
                        // x^(l)_i * q_i happens. Its done with a single 
                        // array index instruction. If x is zero, then mask
                        // will hold the all zero string. Otherwise it holds
                        // the row q_i.
                        block* mask0 = zeroAndQ[*xIter++].data();

                        for (u64 m = 0; m < codeSize; ++m)
                        {
                            // Xor it in.
                            qSumIter[m] = qSumIter[m] ^ mask0[m];
                        }
                    }
                }

                //  ^^^^^^^^^^^^^      general codeword size        ^^^^^^^^^^^^^
            }
        }

        std::vector<block> tSum(statSecParam * mT.size()[1]);
        std::vector<block> wSum(statSecParam * mCode.plaintextBlkSize());

        // now wait for the receiver's challenge answer.
        chl.recv(tSum.data(), tSum.size() * sizeof(block));
        chl.recv(wSum.data(), wSum.size() * sizeof(block));

        // a buffer to store codewords
        std::vector<block> cw(mCode.codewordBlkSize());

        // check each of the statSecParam number of challenges
        for (u64 l = 0; l < statSecParam; ++l)
        {
            
            ArrayView<block> word(
                wSum.begin() + l * mCode.plaintextBlkSize(),
                wSum.begin() + (l + 1) * mCode.plaintextBlkSize());

            // encode their l'th linear combination of choice words.
            mCode.encode(word, cw);

            // check that the linear relation holds.
            for (u64 j = 0; j < cw.size(); ++j)
            {
                block tq = tSum[l * cw.size() + j] ^ qSum[l * cw.size() + j];
                block cb = cw[j] & mChoiceBlks[j];

                if (neq(tq, cb))
                {
                    //std::cout << "bad OOS16 OT check. " << l << "m " << j << std::endl;
                    //return;
                    throw std::runtime_error("bad OOS16 OT check. " LOCATION);
                }
            }

        }

    }


}
