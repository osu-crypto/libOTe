#include "libOTe/Vole/SilentVoleSender.h"
#ifdef ENABLE_SILENT_VOLE

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
    u64 secLevel(u64 scale, u64 p, u64 points);
    u64 getPartitions(u64 scaler, u64 p, u64 secParam);

    u64 SilentVoleSender::baseOtCount() const
    {
#ifdef ENABLE_KOS
        return mKosSender.baseOtCount();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    bool SilentVoleSender::hasBaseOts() const
    {
#ifdef ENABLE_KOS
        return mKosSender.hasBaseOts();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    // sets the IKNP base OTs that are then used to extend
    void SilentVoleSender::setBaseOts(
        span<block> baseRecvOts,
        const BitVector& choices)
    {
#ifdef ENABLE_KOS
        mKosSender.setUniformBaseOts(baseRecvOts, choices);
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }


    void SilentVoleSender::genSilentBaseOts(PRNG& prng, Channel& chl)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        std::vector<std::array<block, 2>> msg(silentBaseOtCount());

        mKosSender.mFiatShamir = true;
        mKosSender.send(msg, prng, chl);

        setSilentBaseOts(msg);
        setTimePoint("sender.gen.done");
    }

    u64 SilentVoleSender::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        if (mKosRecver.hasBaseOts())
            return mGen.baseOtCount() + mGapOts.size();
        else
            return mGen.baseOtCount() + mGapOts.size() + mKosRecver.baseOtCount();
    }

    void SilentVoleSender::setSilentBaseOts(
        span<std::array<block, 2>> sendBaseOts)
    {
        if ((u64)sendBaseOts.size() != silentBaseOtCount())
            throw RTE_LOC;

        auto genOt = sendBaseOts.subspan(0, mGen.baseOtCount());
        auto gapOt = sendBaseOts.subspan(genOt.size(), mGapOts.size());
        auto iknpOt = sendBaseOts.subspan(genOt.size() + gapOt.size());

        mGen.setBase(genOt);
        std::copy(gapOt.begin(), gapOt.end(), mGapOts.begin());

        if(iknpOt.size())
            mKosRecver.setUniformBaseOts(iknpOt);
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

    void SilentVoleSender::configure(
        u64 numOTs, u64 secParam)
    {
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


    void SilentVoleSender::checkRT(Channel& chl, span<block> beta) const
    {
        chl.send(mB);
        chl.send(beta);

    }

    void SilentVoleSender::clear()
    {
        mB = {};
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
            // recvs data
            genSilentBaseOts(prng, chl);
        }

        mDelta = delta;

        setTimePoint("sender.iknp.start");
        gTimer.setTimePoint("sender.iknp.base2");


        if (mKosRecver.hasBaseOts() == false)
            throw RTE_LOC;

        // compute the correlation for the noisy coordinates.
        std::vector<block> beta(mNumPartitions + mGapOts.size());
        block deltaShare;
        {
            if (mMalType == SilentSecType::Malicious)
                beta.emplace_back();

            mKosRecver.mFiatShamir = true;
            NoisyVoleSender nv;
            //recvs data
            nv.send(delta, beta, prng, mKosRecver, chl);


            if (mMalType == SilentSecType::Malicious)
            {
                deltaShare = beta.back();
                beta.pop_back();
            }
        }

        // allocate B
        if (mBackingSize < mN2)
        {
            mBackingSize = mN2;
            mBacking.reset(new block[mBackingSize]);
        }
        mB = span<block>(mBacking.get(), mN2);

        // derandomize the random OTs for the gap 
        // to have the desired correlation.
        std::vector<block> gapVals(mGapOts.size());
        for (u64 i = mNumPartitions * mSizePer, j = 0; i < mN2; ++i, ++j)
        {
            auto v = mGapOts[j][0] ^ beta[mNumPartitions + j];
            gapVals[j] = AES(mGapOts[j][1]).ecbEncBlock(ZeroBlock) ^ v;
            mB[i] = mGapOts[j][0];
        }
        chl.send(std::move(gapVals));


        // sends data
        auto bb = span<block>(beta.data(), mNumPartitions);
        auto mbb = mB.subspan(0, mNumPartitions * mSizePer);
        mGen.expand(chl, bb, prng, mbb, PprfOutputFormat::Interleaved, mNumThreads);
        setTimePoint("sender.expand.pprf_transpose");
        gTimer.setTimePoint("sender.expand.pprf_transpose");

        if (mDebug)
        {
            checkRT(chl, beta);
            setTimePoint("sender.expand.checkRT");
        }


        if (mMalType == SilentSecType::Malicious)
        {
            ferretMalCheck(chl, deltaShare);
        }


        if (mTimer)
            mEncoder.setTimer(getTimer());

        mEncoder.cirTransEncode(mB);
        setTimePoint("sender.expand.ldpc.cirTransEncode");

        mB = span<block>(mBacking.get(), mRequestedNumOTs);

        mState = State::Default;
    }

    void SilentVoleSender::ferretMalCheck(Channel& chl, block deltaShare)
    {
        block X;
        chl.recv(X);

        auto xx = X;
        block sum0 = ZeroBlock;
        block sum1 = ZeroBlock;
        for (u64 i = 0; i < (u64)mB.size(); ++i)
        {
            block low, high;
            xx.gf128Mul(mB[i], low, high);
            sum0 = sum0 ^ low;
            sum1 = sum1 ^ high;

            xx = xx.gf128Mul(X);
        }

        block mySum = sum0.gf128Reduce(sum1);

        std::array<u8, 32> myHash;
        RandomOracle ro(32);
        ro.Update(mySum ^ deltaShare);
        ro.Final(myHash);

        chl.send(myHash);
    }
}

#endif