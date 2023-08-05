#include "libOTe/Vole/Silent/SilentVoleSender.h"
#ifdef ENABLE_SILENT_VOLE

#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"

#include "libOTe/Base/BaseOT.h"
#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/Tools/LDPC/LdpcSampler.h"


namespace osuCrypto
{
    u64 SilentVoleSender::baseOtCount() const
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        return mOtExtSender.baseOtCount();
#else
        throw std::runtime_error("soft spoken must be enabled");
#endif
    }

    bool SilentVoleSender::hasBaseOts() const
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        return mOtExtSender.hasBaseOts();
#else
        throw std::runtime_error("soft spoken must be enabled");
#endif
    }

    // sets the soft spoken base OTs that are then used to extend
    void SilentVoleSender::setBaseOts(
        span<block> baseRecvOts,
        const BitVector& choices)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        mOtExtSender.setBaseOts(baseRecvOts, choices);
#else
        throw std::runtime_error("soft spoken must be enabled");
#endif
    }


    task<> SilentVoleSender::genSilentBaseOts(PRNG& prng, Socket& chl, cp::optional<block> delta)
    {

#if defined ENABLE_MRR_TWIST && defined ENABLE_SSE
        using BaseOT = McRosRoyTwist;
#elif defined ENABLE_MR
        using BaseOT = MasnyRindal;
#elif defined ENABLE_MRR
        using BaseOT = McRosRoy;
#else
    using BaseOT = DefaultBaseOT;
#endif

        MC_BEGIN(task<>,this, delta, &prng, &chl, 
            msg = AlignedUnVector<std::array<block, 2>>(silentBaseOtCount()),
            baseOt = BaseOT{},
            prng2 = std::move(PRNG{}),
            xx = BitVector{},
            chl2 = Socket{},
            nv = NoisyVoleSender{},
            noiseDeltaShares = std::vector<block>{}
            );
        setTimePoint("SilentVoleSender.genSilent.begin");

        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        
        delta = delta.value_or(prng.get<block>());
        xx.append(delta->data(), 128);

        // compute the correlation for the noisy coordinates.
        noiseDeltaShares.resize(baseVoleCount());


        if (mBaseType == SilentBaseType::BaseExtend)
        {
#ifdef ENABLE_SOFTSPOKEN_OT

            if (mOtExtRecver.hasBaseOts() == false)
            {
                msg.resize(msg.size() + mOtExtRecver.baseOtCount());
                MC_AWAIT(mOtExtSender.send(msg, prng, chl));
                
                mOtExtRecver.setBaseOts(
                    span<std::array<block,2>>(msg).subspan(
                        msg.size() - mOtExtRecver.baseOtCount(),
                        mOtExtRecver.baseOtCount()));
                msg.resize(msg.size() - mOtExtRecver.baseOtCount());

                MC_AWAIT(nv.send(*delta, noiseDeltaShares, prng, mOtExtRecver, chl));
            }
            else
            {
                chl2 = chl.fork();
                prng2.SetSeed(prng.get());

                MC_AWAIT(
                    macoro::when_all_ready(
                        nv.send(*delta, noiseDeltaShares, prng2, mOtExtRecver, chl2),
                        mOtExtSender.send(msg, prng, chl)));
            }
#else

#endif
        }
        else
        {
            chl2 = chl.fork();
            prng2.SetSeed(prng.get());
            MC_AWAIT(
                macoro::when_all_ready(
                    nv.send(*delta, noiseDeltaShares, prng2, baseOt, chl2),
                    baseOt.send(msg, prng, chl)));
        }


        setSilentBaseOts(msg, noiseDeltaShares);
        setTimePoint("SilentVoleSender.genSilent.done");
        MC_END();
    }

    u64 SilentVoleSender::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        return mGen.baseOtCount() + mGapOts.size();
    }

    void SilentVoleSender::setSilentBaseOts(
        span<std::array<block, 2>> sendBaseOts, 
        span<block> noiseDeltaShares)
    {
        if ((u64)sendBaseOts.size() != silentBaseOtCount())
            throw RTE_LOC;

        if (noiseDeltaShares.size() != baseVoleCount())
            throw RTE_LOC;

        auto genOt = sendBaseOts.subspan(0, mGen.baseOtCount());
        auto gapOt = sendBaseOts.subspan(genOt.size(), mGapOts.size());

        mGen.setBase(genOt);
        std::copy(gapOt.begin(), gapOt.end(), mGapOts.begin());
        mNoiseDeltaShares.resize(noiseDeltaShares.size());
        std::copy(noiseDeltaShares.begin(), noiseDeltaShares.end(), mNoiseDeltaShares.begin());
    }

    void SilentVoleSender::configure(
        u64 numOTs, 
        SilentBaseType type,
        u64 secParam)
    {
        mBaseType = type;
        u64 gap = 0;

        switch (mMultType)
        {
        case osuCrypto::MultType::QuasiCyclic:
        {
            u64 p, s;

            QuasiCyclicConfigure(numOTs, secParam,
                2,
                mMultType,
                mRequestedNumOTs,
                mNumPartitions,
                mSizePer,
                mN2,
                mN,
                p,
                s
            );
#ifdef ENABLE_BITPOLYMUL
            mQuasiCyclicEncoder.init(p, s);
#else
            throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
            break;
        }
#ifdef ENABLE_INSECURE_SILVER
        case osuCrypto::MultType::slv5:
        case osuCrypto::MultType::slv11:

            SilverConfigure(numOTs, secParam,
                mMultType,
                mRequestedNumOTs,
                mNumPartitions,
                mSizePer,
                mN2,
                mN,
                gap,
                mEncoder);
            break;
#endif
        case osuCrypto::MultType::ExAcc7:
        case osuCrypto::MultType::ExAcc11:
        case osuCrypto::MultType::ExAcc21:
        case osuCrypto::MultType::ExAcc40:

            EAConfigure(numOTs, secParam,
                mMultType,
                mRequestedNumOTs,
                mNumPartitions,
                mSizePer,
                mN2,
                mN,
                mEAEncoder);
            break;
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:

            ExConvConfigure(numOTs, 128, mMultType, mRequestedNumOTs, mNumPartitions, mSizePer, mN2, mN, mExConvEncoder);
            break;
        default:
            throw RTE_LOC;
            break;
        }

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


    task<> SilentVoleSender::checkRT(Socket& chl, block delta) const
    {
        MC_BEGIN(task<>,this, &chl, delta);
        MC_AWAIT(chl.send(delta));
        MC_AWAIT(chl.send(mB));
        MC_AWAIT(chl.send(mNoiseDeltaShares));
        MC_END();
    }

    void SilentVoleSender::clear()
    {
        mB = {};
        mGen.clear();
    }

    task<> SilentVoleSender::silentSend(
        block delta,
        span<block> b,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, delta, b, &prng, &chl);
        
        MC_AWAIT(silentSendInplace(delta, b.size(), prng, chl));

        std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
        clear();

        setTimePoint("SilentVoleSender.expand.ldpc.msgCpy");
        MC_END();
    }

    task<> SilentVoleSender::silentSendInplace(
        block delta,
        u64 n,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, delta, n, &prng, &chl,
            gapVals = std::vector<block>{},
            deltaShare = block{},
            X = block{},
            hash = std::array<u8, 32>{},
            noiseShares = span<block>{},
            mbb = span<block>{}
        );
        setTimePoint("SilentVoleSender.ot.enter");


        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(n, SilentBaseType::BaseExtend);
        }

        if (mRequestedNumOTs != n)
            throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

        if (mGen.hasBaseOts() == false)
        {
            // recvs data
            MC_AWAIT(genSilentBaseOts(prng, chl, delta));
        }

        //mDelta = delta;

        setTimePoint("SilentVoleSender.start");
        //gTimer.setTimePoint("SilentVoleSender.iknp.base2");

        if (mMalType == SilentSecType::Malicious)
        {
            deltaShare = mNoiseDeltaShares.back();
            mNoiseDeltaShares.pop_back();
        }

        // allocate B
        mB.resize(0);
        mB.resize(mN2);

        // derandomize the random OTs for the gap 
        // to have the desired correlation.
        gapVals.resize(mGapOts.size());
        for (u64 i = mNumPartitions * mSizePer, j = 0; i < mN2; ++i, ++j)
        {
            auto v = mGapOts[j][0] ^ mNoiseDeltaShares[mNumPartitions + j];
            gapVals[j] = AES(mGapOts[j][1]).ecbEncBlock(ZeroBlock) ^ v;
            mB[i] = mGapOts[j][0];
        }

        if(gapVals.size())
            MC_AWAIT(chl.send(std::move(gapVals)));


        if (mTimer)
            mGen.setTimer(*mTimer);

        // program the output the PPRF to be secret shares of 
        // our secret share of delta * noiseVals. The receiver
        // can then manually add their shares of this to the
        // output of the PPRF at the correct locations.
        noiseShares = span<block>(mNoiseDeltaShares.data(), mNumPartitions);
        mbb = mB.subspan(0, mNumPartitions * mSizePer);
        MC_AWAIT(mGen.expand(chl, noiseShares, prng, mbb,
            PprfOutputFormat::Interleaved, true, mNumThreads));

        setTimePoint("SilentVoleSender.expand.pprf_transpose");
        if (mDebug)
        {
            MC_AWAIT(checkRT(chl, delta));
            setTimePoint("SilentVoleSender.expand.checkRT");
        }


        if (mMalType == SilentSecType::Malicious)
        {
            MC_AWAIT(chl.recv(X));
            hash = ferretMalCheck(X, deltaShare);
            MC_AWAIT(chl.send(std::move(hash)));
        }

        switch (mMultType)
        {
        case osuCrypto::MultType::QuasiCyclic:

#ifdef ENABLE_BITPOLYMUL

            if (mTimer)
                mQuasiCyclicEncoder.setTimer(getTimer());

            mQuasiCyclicEncoder.dualEncode(mB.subspan(0, mQuasiCyclicEncoder.size()));
#else
            throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
            setTimePoint("SilentVoleSender.expand.QuasiCyclic");
            break;
#ifdef ENABLE_INSECURE_SILVER
        case osuCrypto::MultType::slv5:
        case osuCrypto::MultType::slv11:

            if (mTimer)
                mEncoder.setTimer(getTimer());

            mEncoder.dualEncode<block>(mB);
            setTimePoint("SilentVoleSender.expand.Silver");
            break;
#endif
        case osuCrypto::MultType::ExAcc7:
        case osuCrypto::MultType::ExAcc11:
        case osuCrypto::MultType::ExAcc21:
        case osuCrypto::MultType::ExAcc40:
        {
            if (mTimer)
                mEAEncoder.setTimer(getTimer());
            AlignedUnVector<block> B2(mEAEncoder.mMessageSize);
            mEAEncoder.dualEncode<block>(mB.subspan(0,mEAEncoder.mCodeSize), B2);
            std::swap(mB, B2);

            setTimePoint("SilentVoleSender.expand.Silver");
            break;
        }
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:
            if (mTimer)
                mExConvEncoder.setTimer(getTimer());
            mExConvEncoder.dualEncode<block>(mB.subspan(0, mExConvEncoder.mCodeSize));
            break;
        default:
            throw RTE_LOC;
            break;
        }


        mB.resize(mRequestedNumOTs);

        mState = State::Default;
        mNoiseDeltaShares.clear();

        MC_END();
    }

    std::array<u8,32> SilentVoleSender::ferretMalCheck(block X, block deltaShare)
    {

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

        return myHash;
        //chl.send(myHash);
    }
}

#endif