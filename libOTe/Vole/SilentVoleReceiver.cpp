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



        mGen.setBase(recvBaseOts);
        mGen.getPoints(mS, getPprfFormat());
    }

    void SilentVoleReceiver::genBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        setTimePoint("recver.gen.start");
#ifdef ENABLE_IKNP
        mIknpRecver.genBaseOts(prng, chl);
        mIknpSender.genBaseOts(mIknpRecver, prng, chl);
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

        // If we have IKNP base OTs, use them
        // to extend to get the silent base OTs.

#if defined(ENABLE_IKNP) || defined(LIBOTE_HAS_BASE_OT)

    #ifdef ENABLE_IKNP
        mIknpRecver.receive(choice, msg, prng, chl);
    #else
        // otherwise just generate the silent 
        // base OTs directly.
        DefaultBaseOT base;
        base.receive(choice, msg, prng, chl, mNumThreads);
        setTimePoint("recver.gen.baseOT");
    #endif
#else
        throw std::runtime_error("IKNP or base OTs must be enabled");
#endif
        mGen.setBase(msg);
        mGen.getPoints(mS, getPprfFormat());

        for (u64 i = 0; i < mS.size(); ++i)
        {
            if (mS[i] >= mN2)
            {
                for (u64 j = i; j < mS.size(); ++j)
                {
                    std::cout << Color::Red << "bad " << j << " " << mS[j] << " / " << mN2 << std::endl << Color::Default;
                    std::terminate();
                }
            }
        }

        setTimePoint("recver.gen.done");
    };

    void SilentVoleReceiver::genBase(
        u64 n,
        Channel& chl,
        PRNG& prng,
        u64 scaler,
        u64 secParam,
        SilentBaseType basetype,
        u64 threads)
    {
        switch (basetype)
        {
        case SilentBaseType::BaseExtend:
            // perform 128 normal base OTs
            genBaseOts(prng, chl);
        case SilentBaseType::Base:
            configure(n, scaler, secParam, threads);
            // do the silent specific OTs, either by extending
            // the exising base OTs or using a base OT protocol.
            genSilentBaseOts(prng, chl);
            break;
        default:
            std::cout << "known switch " LOCATION << std::endl;
            std::terminate();
            break;
        }
    }

    u64 SilentVoleReceiver::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");
        return mGen.baseOtCount();
    }

    void SilentVoleReceiver::configure(
        u64 numOTs,
        u64 scaler,
        u64 secParam,
        u64 numThreads)
    {
        mNumThreads = numThreads;
        mScaler = scaler;
        u64 numPartitions;
        u64 extra = 0;

        {
            assert(scaler == 2);
            auto mm = numOTs;
            u64 nn = mm * scaler;
            auto kk = nn - mm;


            auto code = mMultType == MultType::slv11 ?
                LdpcDiagRegRepeaterEncoder::Weight11 :
                LdpcDiagRegRepeaterEncoder::Weight5
                ;
            u64 colWeight = (u64)code;


            setTimePoint("config.begin");
            mEncoder.mL.init(mm, colWeight);
            setTimePoint("config.Left");
            mEncoder.mR.init(mm, code, true);
            setTimePoint("config.Right");
            
            extra = mEncoder.mR.mGap;

            mP = 0;
            mN = kk;
            mN2 = nn;
            numPartitions = getPartitions(scaler, mN, secParam);
        }


        mS.resize(numPartitions);
        mSizePer = roundUpTo((mN2 + numPartitions - 1) / numPartitions, 8);

        mGen.configure(mSizePer, mS.size(),extra);
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


    void SilentVoleReceiver::checkRT(span<Channel> chls, Matrix<block>& rT1)
    {

        Matrix<block> rT2(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
        chls[0].recv(rT2.data(), rT2.size());
        block delta;
        chls[0].recv(delta);

        for (u64 i = 0; i < rT1.size(); ++i)
            rT2(i) = rT2(i) ^ rT1(i);


        Matrix<block> R;

        {
            if (rT1.cols() != 1)
                throw RTE_LOC;
            R = rT2;
        }


        Matrix<block> exp(R.rows(), R.cols(), AllocType::Zeroed);
        for (u64 i = 0; i < mS.size(); ++i)
        {
            exp(mS[i]) = delta;
        }

        bool failed = false;
        for (u64 i = 0; i < R.rows(); ++i)
        {
            if (neq(R(i), exp(i)))
            {
                std::cout << i << " / " << R.rows() << " R= " << R(i) << " exp= " << exp(i) << std::endl;
                failed = true;
            }
        }

        if(failed)
            throw RTE_LOC;

        std::cout << "debug check ok" << std::endl;
        //for (u64 x = 0; x < rT.rows(); ++x)
        //{
        //    for (u64 y = 0; y < rT.cols(); ++y)
        //    {
        //        std::cout << rT(x, y) << " " << rT2(x, y) << " " << (rT(x,y) ^ rT2(x,y))<< std::endl;
        //    }
        //    std::cout << std::endl;
        //}
        setTimePoint("recver.expand.checkRT");

    }

    void SilentVoleReceiver::silentReceive(
        span<block> choices,
        span<block> messages,
        PRNG& prng,
        Channel& chl)
    {
        silentReceive(choices, messages, prng, { &chl,1 });
    }

    void SilentVoleReceiver::silentReceive(
        span<block> choices,
        span<block> messages,
        PRNG& prng,
        span<Channel> chls)
    {

        gTimer.setTimePoint("recver.ot.enter");

        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(messages.size(), 2, 128, chls.size());
        }

        if (static_cast<u64>(messages.size()) > mN)
            throw std::invalid_argument("messages.size() > n");

        if (mGen.hasBaseOts() == false)
        {
            // make sure we have IKNP base OTs.
            genSilentBaseOts(prng, chls[0]);
        }

        setTimePoint("recver.iknp.base2");
        gTimer.setTimePoint("recver.iknp.base2");

        // column major matrix. mN2 columns and 1 row of 128 bits (128 bit rows)

        // do the compression to get the final OTs.

        auto size = mGen.mDomain * mGen.mPntCount;
        assert(size >= mN2);
        rT.resize(size, 1, AllocType::Uninitialized);



        std::vector<block> y(mGen.mPntCount), c(mGen.mPntCount);
        prng.get<block>(y);

        if (mIknpSender.hasBaseOts() == false)
            mIknpSender.genBaseOts(mIknpRecver, prng, chls[0]);

        NoisyVoleReceiver nv;
        nv.receive(y, c, prng, mIknpSender, chls[0]);


        setTimePoint("recver.expand.start");
        gTimer.setTimePoint("recver.expand.start");

        mSum = mGen.expand(chls, prng, rT, PprfOutputFormat::Interleaved, false);

        std::vector<u64> points(mGen.mPntCount);
        mGen.getPoints(points, PprfOutputFormat::Interleaved);
        for (u64 i =0; i < points.size(); ++i)
        {
            auto pnt = points[i];
            rT(pnt) = rT(pnt) ^ c[i];
        }

        setTimePoint("recver.expand.pprf_transpose");
        gTimer.setTimePoint("recver.expand.pprf_transpose");

        if (mDebug)
        {
            checkRT(chls, rT);
        }

        ldpcMult(rT, messages, y, choices);

        clear();
    }

    void SilentVoleReceiver::ldpcMult(
        Matrix<block>& rT, span<block>& messages,
        span<block> y,
        span<block>& choices)
    {

        assert(rT.rows() >= mN2);
        assert(rT.cols() == 1);

        rT.resize(mN2, 1);

            Matrix<block> rT2(rT.size(), 1, AllocType::Zeroed);

            std::vector<u64> points(mGen.mPntCount);
            mGen.getPoints(points, PprfOutputFormat::Interleaved);
            for (u64 i = 0; i < points.size(); ++i)
            {
                auto pnt = points[i];
                rT2(pnt) = rT2(pnt) ^ y[i];
            }

            mEncoder.setTimer(getTimer());
            mEncoder.cirTransEncode2(span<block>(rT), span<block>(rT2));
            setTimePoint("recver.expand.cirTransEncode.a");

            std::memcpy(messages.data(), rT.data(), messages.size() * sizeof(block));
            setTimePoint("recver.expand.msgCpy");
            std::memcpy(choices.data(), rT2.data(), choices.size() * sizeof(block));
            setTimePoint("recver.expand.chcCpy");

    }


    void SilentVoleReceiver::clear()
    {
        mN = 0;
        mGen.clear();
    }


}
#endif