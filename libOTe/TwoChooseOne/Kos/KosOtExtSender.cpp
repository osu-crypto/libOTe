#include "KosOtExtSender.h"
#ifdef ENABLE_KOS

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Log.h"


namespace osuCrypto
{
    KosOtExtSender::KosOtExtSender(SetUniformOts, span<block> baseRecvOts, const BitVector& choices)
    {
        setUniformBaseOts(baseRecvOts, choices);
    }

    void KosOtExtSender::setUniformBaseOts(span<block> baseRecvOts, const BitVector& choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");

        mBaseChoiceBits = choices;

        mGens.resize(gOtExtBaseOtCount);
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }

        mUniformBase = true;
    }

    KosOtExtSender KosOtExtSender::splitBase()
    {
        if (!hasBaseOts())
            throw std::runtime_error("base OTs have not been set. " LOCATION);

        std::array<block, gOtExtBaseOtCount> baseRecvOts;
        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();
        return KosOtExtSender(SetUniformOts{}, baseRecvOts, mBaseChoiceBits);
    }

    std::unique_ptr<OtExtSender> KosOtExtSender::split()
    {
        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();

        return std::make_unique<KosOtExtSender>(SetUniformOts{}, baseRecvOts, mBaseChoiceBits);
    }

    void KosOtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices)
    {
        setUniformBaseOts(baseRecvOts, choices);
        mUniformBase = false;
    }

    bool gKosWarning = true;
    void KosWarning()
    {
#ifndef NO_KOS_WARNING
        // warn the user on program exit.
        struct Warned
        {
            ~Warned()
            {
                if (gKosWarning)
                {

                    std::cout << Color::Red << "WARNING: This program made use of the KOS OT extension protocol. "
                        << "The security of this protocol remains unclear and it is highly recommended to use the "
                        << "SoftSpoken protocol instead. See the associated paper for details. Rebuild the library "
                        << "with -DNO_KOS_WARNING=ON to disable this message."
                        << LOCATION << Color::Default << std::endl;
                }
            }
        };
        static Warned wardned;
#endif
    }

    task<> KosOtExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Socket& chl)
    {
        KosWarning();

        if (messages.size() == 0)
            throw RTE_LOC;

        u64 numOtExt = roundUpTo(messages.size() + 128, 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        MC_BEGIN(task<>,this, messages, &prng, &chl, numSuperBlocks,
            // a temp that will be used to transpose the sender's matrix
            t = AlignedUnVector<std::array<block, superBlkSize>>{ 128 },
            choiceMask =  AlignedArray<block, 128>{},
            extraBlocks = AlignedArray<block, 128> {},
            u = AlignedUnVector<std::array<block, superBlkSize>>(128 * commStepSize),
            tv = span<block>{},
            uIter = (block*)nullptr,
            tIter = (block*)nullptr,
            cIter = (block*)nullptr,
            uEnd = (block*)nullptr,
            mIter = span<std::array<block, 2>>::iterator{},

            // The other party either need to commit
            // to a random value or we will generate 
            // it via Fiat Shamir.
            fs = RandomOracle(sizeof(block)),
            theirSeedComm = Commit{},

            superBlkIdx = u64{},
            delta = block{},
            q = block{},
            seed = block{},
            theirSeed = block{},
            recvView = span<u8>{},
            recvStepSize = u64{},
            diff = BitVector{}

        );
        if (hasBaseOts() == false)
            MC_AWAIT(genBaseOts(prng, chl));

        if (mUniformBase == false)
        {
            diff.resize(mBaseChoiceBits.size());
            MC_AWAIT(chl.recv(diff.getSpan<u8>()));
            mBaseChoiceBits ^= diff;
            mUniformBase = true;
        }

        setTimePoint("Kos.send.start");


        tv = span<block>((block*)t.data(), superBlkSize * 128);

        delta = *(block*)mBaseChoiceBits.data();

        for (u64 i = 0; i < 128; ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }



        // The next OT message to be computed
        mIter = messages.begin();

        // Our current location of u.
        // The end iter of u. When uIter == uEnd, we need to
        // receive the next part of the OT matrix.
        uIter = (block*)u.data() + superBlkSize * 128 * commStepSize;
        uEnd = uIter;


        if (mFiatShamir == false)
            MC_AWAIT(chl.recv(theirSeedComm));

#ifdef KOS_DEBUG
        auto mStart = mIter;
#endif

        for (superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // We will generate of the matrix to fill
            // up t. Then we will transpose t.
            tIter = (block*)t.data();

            // cIter is the current choice bit, expanded out to be 128 bits.
            cIter = choiceMask.data();

            // check if we have run out of the u matrix
            // to consume. If so, receive some more.
            if (uIter == uEnd)
            {
                recvStepSize = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
                recvStepSize *= superBlkSize * 128 * sizeof(block);
                recvView = span<u8>((u8*)u.data(), recvStepSize);
                uIter = (block*)u.data();

                MC_AWAIT(chl.recv(recvView));

                if (mFiatShamir)
                    fs.Update(recvView.data(), recvView.size());
            }

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, tIter);
                mGens[colIdx].mBlockIdx += superBlkSize;

                uIter[0] = uIter[0] & *cIter;
                uIter[1] = uIter[1] & *cIter;
                uIter[2] = uIter[2] & *cIter;
                uIter[3] = uIter[3] & *cIter;
                uIter[4] = uIter[4] & *cIter;
                uIter[5] = uIter[5] & *cIter;
                uIter[6] = uIter[6] & *cIter;
                uIter[7] = uIter[7] & *cIter;

                tIter[0] = tIter[0] ^ uIter[0];
                tIter[1] = tIter[1] ^ uIter[1];
                tIter[2] = tIter[2] ^ uIter[2];
                tIter[3] = tIter[3] ^ uIter[3];
                tIter[4] = tIter[4] ^ uIter[4];
                tIter[5] = tIter[5] ^ uIter[5];
                tIter[6] = tIter[6] ^ uIter[6];
                tIter[7] = tIter[7] ^ uIter[7];

                ++cIter;
                uIter += 8;
                tIter += 8;
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            transpose128x1024((block*)t.data());


            //std::array<block, 2>* mStart = mIter;
            auto mEnd = mIter + std::min<u64>(128 * superBlkSize, messages.end() - mIter);

            // compute how many rows are unused.
            //u64 unusedCount = (mIter - mEnd + 128 * superBlkSize);

            // compute the begin and end index of the extra rows that
            // we will compute in this iters. These are taken from the
            // unused rows what we computed above.
            //block* xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

            tIter = (block*)t.data();
            block* tEnd = (block*)t.data() + 128 * superBlkSize;

            // Due to us transposing 1024 rows, the OT mMessages
            // are interleaved within t. we have to step 8 rows
            // of t to get to the next message.
            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter)[0] = *tIter;
                    (*mIter)[1] = *tIter ^ delta;

                    tIter += superBlkSize;
                    mIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }

#ifdef KOS_DEBUG
            if ((superBlkIdx + 1) % commStepSize == 0)
            {
                auto nn = 128 * superBlkSize * commStepSize;
                BitVector choice(nn);

                std::vector<block> temp(nn);
                chl.recv(temp);
                chl.recv(choice);

                u64 begin = mStart - messages.begin();
                auto mm = std::min<u64>(nn, messages.size() - begin);
                for (u64 j = 0; j < mm; ++j)
                {
                    auto rowIdx = j + begin;
                    auto v = temp[j];
                    if (neq(v, messages[rowIdx][choice[j]]))
                    {
                        std::cout << rowIdx << std::endl;
                        throw std::runtime_error("");
                    }
                }
            }
#endif
        }

        for (u64 i = 0; i < 128; ++i)
            extraBlocks[i] = t[i][superBlkSize - 1];

#ifdef KOS_DEBUG
        BitVector choices(128);
        std::vector<block> xtraBlk(128);
        chl.recv(xtraBlk);
        chl.recv(choices);

        bool failed = false;
        for (u64 i = 0; i < 128; ++i)
        {
            if (neq(xtraBlk[i], choices[i] ? extraBlocks[i] ^ delta : extraBlocks[i]))
            {
                std::cout << "extra " << i << std::endl;
                std::cout << xtraBlk[i] << "  " << (u32)choices[i] << std::endl;
                std::cout << extraBlocks[i] << "  " << (extraBlocks[i] ^ delta) << std::endl;

                failed = true;
            }
        }
        if (failed)
            throw std::runtime_error("");
#endif
        setTimePoint("Kos.send.transposeDone");


        if (mFiatShamir)
        {
            fs.Final(seed);
        }
        else
        {
            seed = prng.get<block>();
            MC_AWAIT(chl.send(std::move(seed)));
            //chl.asyncSend((u8*)&seed, sizeof(block));
            MC_AWAIT(chl.recv(theirSeed));
            //chl.recv((u8*)&theirSeed, sizeof(block));
            setTimePoint("Kos.send.cncSeed");
            if (Commit(theirSeed) != theirSeedComm)
                throw std::runtime_error("bad commit " LOCATION);
            seed = seed ^ theirSeed;
            //PRNG commonPrng(seed ^ theirSeed);
        }


        q = hash(messages, seed, extraBlocks);

        //std::vector<u8> data(sizeof(block) * 2);


        recvView = span<u8>((u8*)u.data(), 2 * sizeof(block));
        //chl.recv(data.data(), data.size());
        MC_AWAIT(chl.recv(recvView));
        setTimePoint("Kos.send.proofReceived");

        {
            block& received_x = u[0][0];
            block& received_t = u[0][1];


            // check t = x * Delta + q
            auto t = received_x.gf128Mul(delta) ^ q;

            if (eq(t, received_t))
            {
                //std::cout << "\tCheck passed\n";
            }
            else
            {
                std::cout << "OT Ext Failed Correlation check failed" << std::endl;
                //std::cout << "rec t = " << received_t << std::endl;
                //std::cout << "tmp1  = " << t1 << std::endl;
                //std::cout << "q  = " << q1 << std::endl;
                throw std::runtime_error("Exit");;
            }

            setTimePoint("Kos.send.done");
        }

        MC_END();
    }


    block KosOtExtSender::hash(
        span<std::array<block, 2>> messages,
        block seed,
        std::array<block, 128>& extraBlocks)
    {

        PRNG commonPrng(seed);

        block  qi, qi2;
        block q2 = ZeroBlock;
        block q1 = ZeroBlock;

        RandomOracle sha;
        u8 hashBuff[20];

        u64 doneIdx = 0;
        std::array<block, 128> challenges;

        setTimePoint("Kos.send.checkStart");

        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());
            u64 stop = std::min<u64>(messages.size(), doneIdx + 128);
            for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
            {
                mul128(messages[dd][0], challenges[i], qi, qi2);
                q1 = q1 ^ qi;
                q2 = q2 ^ qi2;
            }

            if (mHashType == HashType::RandomOracle)
            {
                for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
                {
                    // hash the message without delta
                    sha.Reset();
                    sha.Update(dd);
                    sha.Update((u8*)&messages[dd][0], sizeof(block));
                    sha.Final(hashBuff);
                    messages[dd][0] = *(block*)hashBuff;

                    // hash the message with delta
                    sha.Reset();
                    sha.Update(dd);
                    sha.Update((u8*)&messages[dd][1], sizeof(block));
                    sha.Final(hashBuff);
                    messages[dd][1] = *(block*)hashBuff;
                }
            }
            else
            {
                span<block> hh(&messages[doneIdx][0], 2 * (stop - doneIdx));
                mAesFixedKey.TmmoHashBlocks(hh, hh, [mTweak = doneIdx * 2]() mutable {
                    return block(mTweak++ >> 1);
                });
            }

            doneIdx = stop;
        }


        for (auto& blk : extraBlocks)
        {
            block chii = commonPrng.get<block>();

            mul128(blk, chii, qi, qi2);
            q1 = q1 ^ qi;
            q2 = q2 ^ qi2;
        }

        setTimePoint("Kos.send.checkSummed");


        //std::cout << IoStream::unlock;

        auto q = q1.gf128Reduce(q2);
        return q;

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}

#endif
