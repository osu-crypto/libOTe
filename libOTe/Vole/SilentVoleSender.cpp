#include "libOTe/Vole/SilentVoleSender.h"
#ifdef ENABLE_SILENTOT

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include <libOTe/Tools/bitpolymul.h>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ThreadBarrier.h"
#include "libOTe/Base/BaseOT.h"
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include "libOTe/Tools/LDPC/LdpcSampler.h"

#include "NoisyVoleSender.h"

namespace osuCrypto
{
    //extern u64 numPartitions;
    //extern u64 nScaler;

    u64 secLevel(u64 scale, u64 p, u64 points);
    u64 getPartitions(u64 scaler, u64 p, u64 secParam);

    u64 SilentVoleSender::baseOtCount() const
    {
#ifdef ENABLE_IKNP
        return mIknpSender.baseOtCount();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    bool SilentVoleSender::hasBaseOts() const
    {
#ifdef ENABLE_IKNP
        return mIknpSender.hasBaseOts();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif

    }

    void SilentVoleSender::genSilentBaseOts(PRNG& prng, Channel& chl)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        std::vector<std::array<block, 2>> msg(silentBaseOtCount());

        // If we have IKNP base OTs, use them
        // to extend to get the silent base OTs.
#if defined(ENABLE_IKNP) || defined(LIBOTE_HAS_BASE_OT)

    #ifdef ENABLE_IKNP
        mIknpSender.send(msg, prng, chl);
    #else
        // otherwise just generate the silent 
        // base OTs directly.
        DefaultBaseOT base;
        base.send(msg, prng, chl, mNumThreads);
        setTimePoint("sender.gen.baseOT");
#endif
#else
        throw std::runtime_error("IKNP or base OTs must be enabled");
#endif

        mGen.setBase(msg);


        for (u64 i = 0; i < mNumPartitions; ++i)
        {
            u64 mSi;
            do
            {
                auto si = prng.get<u64>() % mSizePer;
                mSi = si * mNumPartitions + i;
            } while (mSi >= mN2);
        }

        setTimePoint("sender.gen.done");
    }

    u64 SilentVoleSender::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        return mGen.baseOtCount();
    }

    void SilentVoleSender::setSlientBaseOts(
        span<std::array<block, 2>> sendBaseOts)
    {
        mGen.setBase(sendBaseOts);
    }

    void SilentVoleSender::genBase(
        u64 n, Channel& chl, PRNG& prng,
        u64 scaler, u64 secParam,
        SilentBaseType basetype, u64 threads)
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

    void SilentVoleSender::configure(
        u64 numOTs, u64 scaler, u64 secParam, u64 numThreads)
    {
        mScaler = scaler;

        //if (mMultType == MultType::ldpc)
        {
            assert(scaler == 2);
            auto mm = numOTs;
            //auto mm = numOTs;// nextPrime(numOTs) - 1;
            u64 nn = mm * scaler;
            auto kk = nn - mm;

            //auto code = LdpcDiagRegRepeaterEncoder::Weight11;
            //u64 colWeight = 11;

            auto code = LdpcDiagRegRepeaterEncoder::Weight5;
            u64 colWeight = 5;

            if (mEncoder.cols() != nn)
            {
                setTimePoint("config.begin");
                mEncoder.mL.init(mm, colWeight);
                setTimePoint("config.Left");
                mEncoder.mR.init(mm, code, true);
                setTimePoint("config.Right");
                
            }

            mP = 0;
            mN = kk;
            mN2 = nn;
            mNumPartitions = getPartitions(scaler, mN, secParam);

        }

        mNumThreads = numThreads;

        mSizePer = roundUpTo((mN2 + mNumPartitions - 1) / mNumPartitions, 8);

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


    void SilentVoleSender::checkRT(span<Channel> chls, Matrix<block>& rT)
    {
        chls[0].send(rT.data(), rT.size());
        chls[0].send(mGen.mValue);

        setTimePoint("sender.expand.checkRT");

    }

    void SilentVoleSender::clear()
    {
        mN = 0;
        mGen.clear();
    }

    //void SilentVoleSender::silentSend(
    //    span<std::array<block, 2>> messages,
    //    PRNG& prng,
    //    Channel& chl)
    //{
    //    silentSend(messages, prng, { &chl,1 });
    //}

    void SilentVoleSender::silentSend(
        block delta,
        span<block> messages,
        PRNG& prng,
        span<Channel> chls)
    {
        gTimer.setTimePoint("sender.ot.enter");


        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(messages.size(), 2, 128, chls.size());
        }

        if (static_cast<u64>(messages.size()) > mN)
            throw std::invalid_argument("messages.size() > n");

        if (mGen.hasBaseOts() == false)
        {
            genSilentBaseOts(prng, chls[0]);
        }

        setTimePoint("sender.expand.start");
        gTimer.setTimePoint("sender.expand.start");

        std::vector<block> beta(mGen.mPntCount);

        NoisyVoleSender nv;
        nv.send(delta, beta, prng, mIknpRecver, chls[0]);

        {
            auto size = mGen.mDomain * mGen.mPntCount;
            assert(size >= mN2);
            rT.resize(size, 1, AllocType::Uninitialized);

            mGen.expand(chls, beta, prng, rT, PprfOutputFormat::Interleaved, false);
            setTimePoint("sender.expand.pprf_transpose");
            gTimer.setTimePoint("sender.expand.pprf_transpose");

            if (mDebug)
            {
                checkRT(chls, rT);
            }

            ldpcMult(delta, rT, messages, chls.size());
        }

        clear();
    }


    void SilentVoleSender::ldpcMult(
        block delta,
        Matrix<block>& rT, span<block>& messages, u64 threads)
    {
        assert(rT.rows() >= mN2);
        assert(rT.cols() == 1);

        rT.resize(mN2, 1);


        block mask = OneBlock ^ AllOneBlock;

        mEncoder.setTimer(getTimer());
        mEncoder.cirTransEncode(span<block>(rT));
        setTimePoint("sender.expand.ldpc.cirTransEncode");

        std::memcpy(messages.data(), rT.data(), messages.size() * sizeof(block));
        setTimePoint("sender.expand.ldpc.msgCpy");

        //std::memcpy(messages.data(), rT.data(), messages.size() * sizeof(block));


    }

}

#endif