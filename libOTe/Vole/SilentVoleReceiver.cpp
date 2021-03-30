#include "libOTe/Vole/SilentVoleReceiver.h"
#ifdef ENABLE_SILENTOT
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

    void SilentVoleReceiver::setSlientBaseOts(span<block> recvBaseOts)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first.");

        if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
            throw std::runtime_error("wrong number of silent base OTs");

        auto ss = mGen.baseOtCount();
        if (mIknpSender.hasBaseOts() == false)
        {
            span<block> mm = recvBaseOts.subspan(ss);
            mIknpSender.setBaseOts(mm, mIknpSendBaseChoice);
        }

        mGen.setBase(recvBaseOts.subspan(0,ss));
        mGen.getPoints(mS, getPprfFormat());

        mState = State::HasBase;
    }

    BitVector SilentVoleReceiver::sampleBaseChoiceBits(PRNG& prng) {

        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first");

        auto choice = mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);

        if (mIknpSender.hasBaseOts() == false)
        {
            mIknpSendBaseChoice.resize(mIknpSender.baseOtCount());
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
#ifdef ENABLE_IKNP
        mIknpRecver.genBaseOts(prng, chl);
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

        mIknpRecver.receive(choice, msg, prng, chl);

        setSlientBaseOts(msg);

        setTimePoint("recver.gen.done");
    };

    u64 SilentVoleReceiver::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");
        if(mIknpSender.hasBaseOts())
            return mGen.baseOtCount();
        else
            return mGen.baseOtCount() + mIknpSender.baseOtCount();

    }

    void SilentVoleReceiver::configure(
        u64 numOTs,
        u64 secParam)
    {
        mState = State::Configured;
        mRequestedNumOTs = numOTs;

        auto numPartitions = getPartitions(mScaler, numOTs, secParam);
        mSizePer = roundUpTo((numOTs * mScaler + numPartitions - 1) / numPartitions, 8);
        auto nn = mSizePer * numPartitions;
        auto mm = nn / mScaler;

        mN = mm;
        mN2 = nn;

        auto code = mMultType == MultType::slv11 ?
            LdpcDiagRegRepeaterEncoder::Weight11 :
            LdpcDiagRegRepeaterEncoder::Weight5;

        u64 colWeight = (u64)code;

        setTimePoint("config.begin");
        mEncoder.mL.init(mm, colWeight);
        setTimePoint("config.Left");
        mEncoder.mR.init(mm, code, true);
        setTimePoint("config.Right");

        mS.resize(numPartitions);

        auto extra = mEncoder.mR.mGap;
        mGen.configure(mSizePer, mS.size(), extra);
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
    //    v = v' * H		   block-vector * H. Mapping n'->n block
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

        //Matrix<block> rT2(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
        std::vector<block> mB(mA.size());
        chl.recv(mB.data(), mB.size());

        std::vector<block> beta(mS.size());
        chl.recv(beta);


        auto cDelta = mB;
        for (u64 i = 0; i < cDelta.size(); ++i)
            cDelta[i] = cDelta[i] ^ mA[i];

        //Matrix<block> R;

        //{
        //    if (rT1.cols() != 1)
        //        throw RTE_LOC;
        //    R = rT2;
        //}


        std::vector<block> exp(mN2);
        for (u64 i = 0; i < mS.size(); ++i)
        {
            exp[mS[i]] = beta[i];
        }

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

        if (mIknpSender.hasBaseOts() == false)
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
        std::vector<block> y(mGen.mPntCount), c(mGen.mPntCount);
        prng.get<block>(y);
        NoisyVoleReceiver nv;
        nv.receive(y, c, prng, mIknpSender, chl);

        setTimePoint("recver.expand.start");
        gTimer.setTimePoint("recver.expand.start");

        // expand the seeds into mA
        mGen.expand(chl, prng, mA, PprfOutputFormat::Interleaved, false);

        if (mDebug)
        {
            checkRT(chl);
            setTimePoint("recver.expand.checkRT");
        }


        // correct A by adding in the c values of the noisy coordinates.
        std::vector<u64> points(mGen.mPntCount);
        mGen.getPoints(points, PprfOutputFormat::Interleaved);
        for (u64 i = 0; i < points.size(); ++i)
        {
            auto pnt = points[i];
            mA(pnt) = mA(pnt) ^ c[i];
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

        // populate the noicy coordinates of mC
        for (u64 i = 0; i < points.size(); ++i)
        {
            auto pnt = points[i];
            mC[pnt] = mC[pnt] ^ y[i];
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