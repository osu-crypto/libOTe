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

        mIknpSender.send(msg, prng, chl);

        setSilentBaseOts(msg);
        setTimePoint("sender.gen.done");
    }

    u64 SilentVoleSender::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        if (mIknpRecver.hasBaseOts())
            return mGen.baseOtCount();
        else
            return mGen.baseOtCount() + mIknpRecver.baseOtCount();
    }

    void SilentVoleSender::setSilentBaseOts(
        span<std::array<block, 2>> sendBaseOts)
    {
        if (sendBaseOts.size() != silentBaseOtCount())
            throw RTE_LOC;

        if (mIknpRecver.hasBaseOts())
            mGen.setBase(sendBaseOts);
        else
        {
            auto m0 = sendBaseOts.subspan(0, mGen.baseOtCount());
            auto m1 = sendBaseOts.subspan(mGen.baseOtCount());
            mGen.setBase(m0);
            mIknpRecver.setBaseOts(m1);
        }
    }

    void SilentVoleSender::configure(
        u64 numOTs, u64 secParam)
    {
        mRequestedNumOTs = numOTs;

        mNumPartitions = getPartitions(mScaler, numOTs, secParam);
        mSizePer = roundUpTo((numOTs * mScaler + mNumPartitions - 1) / mNumPartitions, 8);
        auto nn = roundUpTo(mSizePer * mNumPartitions, mScaler);
        auto mm = nn / mScaler;

        mN = mm;
        mN2 = nn;

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
        auto extra = mEncoder.mR.mGap;

        mGen.configure(mSizePer, mNumPartitions, extra);

        mState = State::Configured;
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


    void SilentVoleSender::checkRT(Channel& chl) const
    {
        chl.send(mB);
        chl.send(mGen.mValue);
    }

    void SilentVoleSender::clear()
    {
        mBacking = {};
        mBackingSize = 0;
        mGen.clear();
    }

    void SilentVoleSender::silentSend(
        block delta,
        span<block> b,
        PRNG& prng,
        Channel& chl)
    {
        silentSendInplace(delta, b.size(), prng, chl);

        std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
        clear();

        setTimePoint("sender.expand.ldpc.msgCpy");
    }

    void SilentVoleSender::silentSendInplace(
        block delta,
        u64 n,
        PRNG& prng,
        Channel& chl)
    {
        gTimer.setTimePoint("sender.ot.enter");


        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(n, 128);
        }

        if (mRequestedNumOTs != n)
            throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

        if (mGen.hasBaseOts() == false)
        {
            genSilentBaseOts(prng, chl);
        }

        setTimePoint("sender.iknp.start");
        gTimer.setTimePoint("sender.iknp.base2");


        if (mIknpRecver.hasBaseOts() == false)
        {
            mIknpRecver.genBaseOts(mIknpSender, prng, chl);
            setTimePoint("sender.iknp.gen");
        }

        NoisyVoleSender nv;
        std::vector<block> beta(mGen.mPntCount);
        nv.send(delta, beta, prng, mIknpRecver, chl);
        gTimer.setTimePoint("sender.expand.start");


        if (mBackingSize < mN2)
        {
            mBackingSize = mN2;
            mBacking.reset(new block[mBackingSize]);
        }
        mB = span<block>(mBacking.get(), mN2);

        mGen.expand(chl, beta, prng, mB, PprfOutputFormat::Interleaved, false);
        setTimePoint("sender.expand.pprf_transpose");
        gTimer.setTimePoint("sender.expand.pprf_transpose");

        if (mDebug)
        {
            checkRT(chl);
            setTimePoint("sender.expand.checkRT");
        }

        if (mTimer)
            mEncoder.setTimer(getTimer());

        mEncoder.cirTransEncode(mB);
        setTimePoint("sender.expand.ldpc.cirTransEncode");

        mB = span<block>(mBacking.get(), mRequestedNumOTs);

        mState = State::Default;
    }


}

#endif