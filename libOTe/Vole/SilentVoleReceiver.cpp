#include "libOTe/Vole/SilentVoleReceiver.h"
#ifdef ENABLE_SILENT_VOLE
#include "libOTe/Vole/SilentVoleSender.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <libOTe/Tools/bitpolymul.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <cryptoTools/Common/ThreadBarrier.h>
#include <libOTe/Tools/LDPC/LdpcSampler.h>
//#include <bits/stdc++.h> 
#include "NoisyVoleReceiver.h"

namespace osuCrypto
{


    u64 getPartitions(u64 scaler, u64 p, u64 secParam);



    // sets the Iknp base OTs that are then used to extend
    void SilentVoleReceiver::setBaseOts(
        span<std::array<block, 2>> baseSendOts)
    {
#ifdef ENABLE_KOS
        mKosRecver.setUniformBaseOts(baseSendOts);
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    // return the number of base OTs IKNP needs
    u64 SilentVoleReceiver::baseOtCount() const {
#ifdef ENABLE_KOS
        return mKosRecver.baseOtCount();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    // returns true if the IKNP base OTs are currently set.
    bool SilentVoleReceiver::hasBaseOts() const {
#ifdef ENABLE_KOS
        return mKosRecver.hasBaseOts();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    };


    void SilentVoleReceiver::setSilentBaseOts(span<block> recvBaseOts)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first.");

        if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
            throw std::runtime_error("wrong number of silent base OTs");

        auto genOts = recvBaseOts.subspan(0, mGen.baseOtCount());
        auto gapOts = recvBaseOts.subspan(mGen.baseOtCount(), mGapOts.size());
        auto iknpOts = recvBaseOts.subspan(mGen.baseOtCount()+ mGapOts.size());

        mGen.setBase(genOts);
        std::copy(gapOts.begin(), gapOts.end(), mGapOts.begin());

        if (iknpOts.size())
            mKosSender.setUniformBaseOts(iknpOts, mIknpSendBaseChoice);

        mS.resize(mNumPartitions);
        mGen.getPoints(mS, getPprfFormat());

        auto j = mNumPartitions * mSizePer;

        for (u64 i = 0; i < (u64)gapOts.size(); ++i)
        {
            if (mGapBaseChoice[i])
            {
                mS.push_back(j + i);
            }
        }

        mState = State::HasBase;
    }

    BitVector SilentVoleReceiver::sampleBaseChoiceBits(PRNG& prng) {

        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first");

        auto choice = mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);

        mGapBaseChoice.resize(mGapOts.size());
        mGapBaseChoice.randomize(prng);
        choice.append(mGapBaseChoice);

        if (mKosSender.hasBaseOts() == false)
        {
            mIknpSendBaseChoice.resize(mKosSender.baseOtCount());
            mIknpSendBaseChoice.randomize(prng);
            choice.append(mIknpSendBaseChoice);
        }

        return choice;
    }

    void SilentVoleReceiver::genBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        setTimePoint("recver.gen.start");
#ifdef ENABLE_KOS
        mKosRecver.genBaseOts(prng, chl);
        //mIknpSender.genBaseOts(mIknpRecver, prng, chl);
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }


    void SilentVoleReceiver::genSilentBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        BitVector choice = sampleBaseChoiceBits(prng);
        std::vector<block> msg(choice.size());

        mKosRecver.mFiatShamir = true;
        mKosRecver.receive(choice, msg, prng, chl);

        setSilentBaseOts(msg);

        setTimePoint("recver.gen.done");
    };

    u64 SilentVoleReceiver::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");
        if(mKosSender.hasBaseOts())
            return mGen.baseOtCount() + mGapOts.size();
        else
            return mGen.baseOtCount() + mGapOts.size() + mKosSender.baseOtCount();

    }

    void SilverConfigure(
        u64 numOTs, u64 secParam,
        MultType mMultType,
        u64& mRequestedNumOTs,
        u64& mNumPartitions,
        u64& mSizePer,
        u64& mN2,
        u64& mN,
        u64& gap,
        SilverEncoder& mEncoder);

    void SilentVoleReceiver::configure(
        u64 numOTs,
        u64 secParam)
    {
        mState = State::Configured;
        u64 gap;
        SilverConfigure(numOTs, secParam,
            mMultType,
            mRequestedNumOTs,
            mNumPartitions,
            mSizePer,
            mN2,
            mN,
            gap,
            mEncoder);

        mGapOts.resize(gap);
        mGen.configure(mSizePer, mNumPartitions);
    }


    //sigma = 0   Receiver
    //
    //    u_i is the choice bit
    //    v_i = w_i + u_i * x
    //
    //    ------------------------ -
    //    u' =   0000001000000000001000000000100000...00000,   u_i = 1 iff i \in S 
    //
    //    v' = r + (x . u') = DPF(k0)
    //       = r + (000000x00000000000x000000000x00000...00000)
    //
    //    u = u' * H             bit-vector * H. Mapping n'->n bits
    //    v = v' * H           block-vector * H. Mapping n'->n block
    //
    //sigma = 1   Sender
    //
    //    x   is the delta
    //    w_i is the zero message
    //
    //    m_i0 = w_i
    //    m_i1 = w_i + x
    //
    //    ------------------------
    //    x
    //    r = DPF(k1)
    //
    //    w = r * H
    void SilentVoleReceiver::checkRT(Channel& chl) const
    {
        std::vector<block> mB(mA.size());
        chl.recv(mB.data(), mB.size());

        std::vector<block> beta;
        chl.recv(beta);

        auto cDelta = mB;
        for (u64 i = 0; i < cDelta.size(); ++i)
            cDelta[i] = cDelta[i] ^ mA[i];

        std::vector<block> exp(mN2);
        for (u64 i = 0; i < mNumPartitions; ++i)
        {
            auto j = mS[i];
            exp[j] = beta[i];
        }

        auto iter = mS.begin() + mNumPartitions;
        for (u64 i = 0,j = mNumPartitions* mSizePer; i < mGapOts.size(); ++i,++j)
        {
            if (mGapBaseChoice[i])
            {
                if (*iter != j)
                    throw RTE_LOC;
                ++iter;

                exp[j] = beta[mNumPartitions+i];
            }
        }

        if (iter != mS.end())
            throw RTE_LOC;

        bool failed = false;
        for (u64 i = 0; i < mN2; ++i)
        {
            if (neq(cDelta[i], exp[i]))
            {
                std::cout << i << " / " << mN2 << 
                    " cd = " << cDelta[i] << 
                    " exp= " << exp[i] << std::endl;
                failed = true;
            }
        }

        if (failed)
            throw RTE_LOC;

        std::cout << "debug check ok" << std::endl;

    }

    void SilentVoleReceiver::silentReceive(
        span<block> c,
        span<block> b,
        PRNG& prng,
        Channel& chl)
    {
        if (c.size() != b.size())
            throw RTE_LOC;

        silentReceiveInplace(c.size(), prng, chl);

        std::memcpy(c.data(), mC.data(), c.size() * sizeof(block));
        std::memcpy(b.data(), mA.data(), b.size() * sizeof(block));
        clear();
    }

    void SilentVoleReceiver::silentReceiveInplace(
        u64 n,
        PRNG& prng,
        Channel& chl)
    {
        gTimer.setTimePoint("recver.ot.enter");

        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(n);
        }

        if (mRequestedNumOTs != n)
            throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

        if (hasSilentBaseOts() == false)
        {
            // make sure we have IKNP base OTs.
            genSilentBaseOts(prng, chl);
        }

        if (mKosSender.hasBaseOts() == false)
            throw RTE_LOC;

        setTimePoint("recver.iknp.base2");
        gTimer.setTimePoint("recver.iknp.base2");

        // allocate mA
        if (mBackingSize < mN2)
        {
            mBackingSize = mN2;
            mBacking.reset(new block[mBackingSize]);
        }
        mA = span<block>(mBacking.get(), mN2);


        // sample the values of the noisy coordinate of c
        // and perform a noicy vole to get x+y = mD * c
        auto w = mNumPartitions + mGapOts.size();
        std::vector<block> y(w), c(w);
        prng.get<block>(y);

        if (mMalType == SilentSecType::Malicious)
        {

            mMalCheckSeed = prng.get();
            mMalCheckX = ZeroBlock;
            auto yIter = y.begin();

            for (u64 i  = 0; i < mNumPartitions; ++i)
            {
                auto s = mS[i];
                auto xs = mMalCheckSeed.gf128Pow(s + 1);
                mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
                ++yIter;
            }

            auto sIter = mS.begin() + mNumPartitions;
            for (u64 i = 0; i < mGapBaseChoice.size(); ++i)
            {
                if (mGapBaseChoice[i])
                {
                    auto s = *sIter;
                    auto xs = mMalCheckSeed.gf128Pow(s + 1);
                    mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
                    ++sIter;
                }
                ++yIter;
            }

            y.push_back(mMalCheckX);
            c.emplace_back();
        }

        mKosSender.mFiatShamir = true;
        NoisyVoleReceiver nv;
        nv.receive(y, c, prng, mKosSender, chl);


        block deltaShare;
        if (mMalType == SilentSecType::Malicious)
        {
            deltaShare = c.back();
            c.pop_back();
            y.pop_back();
        }

        // derandomize the random OTs for the gap 
        // to have the desired correlation.
        std::vector<block> gapVals(mGapOts.size());
        chl.recv(gapVals.data(), gapVals.size());
        for (u64 i = mN2 - mGapOts.size(), j = 0; i < mN2; ++i, ++j)
        {
            if (mGapBaseChoice[j])
                mA[i] = AES(mGapOts[j]).ecbEncBlock(ZeroBlock) ^ gapVals[j];
            else
                mA[i] = mGapOts[j];
        }

        setTimePoint("recver.expand.start");

        // expand the seeds into mA
        mGen.expand(chl, prng, mA.subspan(0, mNumPartitions*mSizePer), PprfOutputFormat::Interleaved, mNumThreads);

        if (mDebug)
        {
            checkRT(chl);
            setTimePoint("recver.expand.checkRT");
        }


        setTimePoint("recver.expand.pprf_transpose");
        gTimer.setTimePoint("recver.expand.pprf_transpose");


        // allocate the space for mC
        if (mC.capacity() >= mN2)
        {
            mC.resize(mN2);
            memset(mC.data(), 0, mC.size() * sizeof(block));
        }
        else
        {
            mC = std::vector<block>(mN2);
        }

        setTimePoint("recver.expand.zero");

        // populate the noisy coordinates of mC and 
        // update mA to be a secret share of mC * delta
        for (u64 i = 0; i < mNumPartitions; ++i)
        {
            auto pnt = mS[i];
            mC[pnt] = y[i];
            mA[pnt] = mA[pnt] ^ c[i];
        }
        for (u64 i = 0, j = mNumPartitions * mSizePer; i < mGapOts.size(); ++i, ++j)
        {
            if (mGapBaseChoice[i])
            {
                mC[j] = mC[j] ^ y[mNumPartitions + i];
                mA[j] = mA[j] ^ c[mNumPartitions + i];
            }
        }


        if (mMalType == SilentSecType::Malicious)
        {
            ferretMalCheck(chl, deltaShare, y);
        }

        if (mTimer)
            mEncoder.setTimer(getTimer());

        // compress both mA and mC in place.
        mEncoder.cirTransEncode2<block, block>(mA, mC);
        setTimePoint("recver.expand.cirTransEncode.a");

        // resize the buffers down to only contain the real elements.
        mA = span<block>(mBacking.get(), mRequestedNumOTs);
        mC.resize(mRequestedNumOTs);

        // make the protocol as done and that
        // mA,mC are ready to be consumed.
        mState = State::Default;
    }


    void SilentVoleReceiver::ferretMalCheck(
        Channel& chl, 
        block deltaShare,
        span<block> yy)
    {
        chl.asyncSendCopy(mMalCheckSeed);

        block xx = mMalCheckSeed;
        block sum0 = ZeroBlock;
        block sum1 = ZeroBlock;


        for (u64 i = 0; i < (u64)mA.size(); ++i)
        {
            block low, high;
            xx.gf128Mul(mA[i], low, high);
            sum0 = sum0 ^ low;
            sum1 = sum1 ^ high;
            //mySum = mySum ^ xx.gf128Mul(mA[i]);

            // xx = mMalCheckSeed^{i+1}
            xx = xx.gf128Mul(mMalCheckSeed);
        }
        block mySum = sum0.gf128Reduce(sum1);

        std::array<u8, 32> theirHash, myHash;
        RandomOracle ro(32);
        ro.Update(mySum ^ deltaShare);
        ro.Final(myHash);

        chl.recv(theirHash);

        if (theirHash != myHash)
            throw RTE_LOC;
    }


    void SilentVoleReceiver::clear()
    {
        mS = {};
        mA = {};
        mC = {};
        mBacking = {};
        mBackingSize = 0;
        mGen.clear();
    }


}
#endif
