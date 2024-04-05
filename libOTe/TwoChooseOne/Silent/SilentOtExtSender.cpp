#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"

#ifdef ENABLE_SILENTOT

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include <libOTe/Tools/bitpolymul.h>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ThreadBarrier.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"

namespace osuCrypto
{


    // sets the KOS base OTs that are then used to extend
    void SilentOtExtSender::setBaseOts(
        span<block> baseRecvOts,
        const BitVector& choices)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        if (!mOtExtSender)
            mOtExtSender.emplace();

        mOtExtSender->setBaseOts(baseRecvOts, choices);
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }

    // Returns an independent copy of this extender.
    std::unique_ptr<OtExtSender> SilentOtExtSender::split()
    {

#ifdef ENABLE_SOFTSPOKEN_OT
        auto ptr = new SilentOtExtSender;
        auto ret = std::unique_ptr<OtExtSender>(ptr);
        if (!mOtExtSender)
            throw RTE_LOC;
        ptr->mOtExtSender = mOtExtSender->splitBase();
        return ret;
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }

    // use the default base OT class to generate the
    // IKNP base OTs that are required.
    task<> SilentOtExtSender::genBaseOts(PRNG& prng, Socket& chl)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        if (!mOtExtSender)
            mOtExtSender.emplace();
        return mOtExtSender->genBaseOts(prng, chl);
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }


    u64 SilentOtExtSender::baseOtCount() const
    {
#ifdef ENABLE_SOFTSPOKEN_OT

        if (!mOtExtSender)
        {
            const_cast<macoro::optional<SoftSpokenMalOtSender>*>(&mOtExtSender)
                ->emplace();
        }
        return mOtExtSender->baseOtCount();
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }

    bool SilentOtExtSender::hasBaseOts() const
    {
#ifdef ENABLE_SOFTSPOKEN_OT

        if (!mOtExtSender)
            return false;
        return mOtExtSender->hasBaseOts();
#else
        throw std::runtime_error("KOS must be enabled");
#endif

    }

    task<> SilentOtExtSender::genSilentBaseOts(PRNG& prng, Socket& chl, bool useOtExtension)
    {
        MC_BEGIN(task<>, this, &prng, &chl, useOtExtension,
            msg = AlignedUnVector<std::array<block, 2>>(silentBaseOtCount()),
            base = DefaultBaseOT{}
        );

        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        // If we have IKNP base OTs, use them
        // to extend to get the silent base OTs.
#if defined(ENABLE_SOFTSPOKEN_OT) || defined(LIBOTE_HAS_BASE_OT)

#ifdef ENABLE_SOFTSPOKEN_OT
        if (useOtExtension)
        {
            if (!mOtExtSender)
                mOtExtSender.emplace();
            //mOtExtSender.mFiatShamir = true;
            MC_AWAIT(mOtExtSender->send(msg, prng, chl));
        }
        else
#endif
        {
            // otherwise just generate the silent 
            // base OTs directly.
            MC_AWAIT(base.send(msg, prng, chl));
            setTimePoint("sender.gen.baseOT");
        }
#else
        throw std::runtime_error("KOS or base OTs must be enabled");
#endif

        setSilentBaseOts(msg);

        setTimePoint("sender.gen.done");

        MC_END();
    }

    u64 SilentOtExtSender::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        auto n = mGen.baseOtCount();

        if (mMalType == SilentSecType::Malicious)
            n += 128;

        return n;
    }

    void SilentOtExtSender::setSilentBaseOts(
        span<std::array<block, 2>> sendBaseOts)
    {

        if ((u64)sendBaseOts.size() != silentBaseOtCount())
            throw RTE_LOC;

        auto genOt = sendBaseOts.subspan(0, mGen.baseOtCount());
        auto malOt = sendBaseOts.subspan(genOt.size());
        mMalCheckOts.resize((mMalType == SilentSecType::Malicious) * 128);

        mGen.setBase(genOt);
        std::copy(malOt.begin(), malOt.end(), mMalCheckOts.begin());
    }

    void SilentOtExtSender::configure(
        u64 numOTs, u64 scaler, u64 numThreads, SilentSecType malType)
    {
        mMalType = malType;
        mNumThreads = numThreads;
        u64 secParam = 128;
        mRequestNumOts = numOTs;;

        syndromeDecodingConfigure(mNumPartitions, mSizePer, mNoiseVecSize, secParam, mRequestNumOts, mMultType);


        mGen.configure(mSizePer, mNumPartitions);
    }

    task<> SilentOtExtSender::checkRT(Socket& chl)
    {
        MC_BEGIN(task<>,this, &chl);

        MC_AWAIT(chl.send(mB));
        MC_AWAIT(chl.send(mDelta));

        setTimePoint("sender.expand.checkRT");
        MC_END();
    }

    void SilentOtExtSender::clear()
    {
        mNoiseVecSize = 0;
        mRequestNumOts = 0;
        mSizePer = 0;
        mNumPartitions = 0;

        mB = {};
        mEncodeTemp = {};

        mDelta = block(0,0);

        mGen.clear();
    }

    task<> SilentOtExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, messages, &prng, &chl,
            correction = BitVector(messages.size()),
            iter = BitIterator{},
            i = u64{}
            );

        MC_AWAIT(silentSend(messages, prng, chl));
        MC_AWAIT(chl.recv(correction));
        iter = correction.begin();

        for (i = 0; i < static_cast<u64>(messages.size()); ++i)
        {
            u8 bit = *iter; ++iter;
            auto temp = messages[i];
            messages[i][0] = temp[bit];
            messages[i][1] = temp[bit ^ 1];
        }

        MC_END();
    }

    task<> SilentOtExtSender::silentSend(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, messages, &prng, &chl,
            type = ChoiceBitPacking::True
        );

        MC_AWAIT(silentSendInplace(prng.get(), messages.size(), prng, chl));
        hash(messages, type);
        clear();
        MC_END();
    }

    void SilentOtExtSender::hash(
        span<std::array<block, 2>> messages, ChoiceBitPacking type)
    {
        if (type == ChoiceBitPacking::True)
        {



            block mask = OneBlock ^ AllOneBlock;
            auto d = mDelta & mask;

            auto n8 = (u64)messages.size() / 8 * 8;

            std::array<block, 2>* m = messages.data();
            auto r = mB.data();

            for (u64 i = 0; i < n8; i += 8)
            {

                r[0] = r[0] & mask;
                r[1] = r[1] & mask;
                r[2] = r[2] & mask;
                r[3] = r[3] & mask;
                r[4] = r[4] & mask;
                r[5] = r[5] & mask;
                r[6] = r[6] & mask;
                r[7] = r[7] & mask;

                m[0][0] = r[0];
                m[1][0] = r[1];
                m[2][0] = r[2];
                m[3][0] = r[3];
                m[4][0] = r[4];
                m[5][0] = r[5];
                m[6][0] = r[6];
                m[7][0] = r[7];

                m[0][1] = r[0] ^ d;
                m[1][1] = r[1] ^ d;
                m[2][1] = r[2] ^ d;
                m[3][1] = r[3] ^ d;
                m[4][1] = r[4] ^ d;
                m[5][1] = r[5] ^ d;
                m[6][1] = r[6] ^ d;
                m[7][1] = r[7] ^ d;

                auto iter = (block*)m;
                mAesFixedKey.hashBlocks<8>(iter, iter);

                iter += 8;
                mAesFixedKey.hashBlocks<8>(iter, iter);


                m += 8;
                r += 8;
            }
            for (u64 i = n8; i < (u64)messages.size(); ++i)
            {
                messages[i][0] = (mB[i]) & mask;
                messages[i][1] = (mB[i] ^ d) & mask;

                messages[i][0] = mAesFixedKey.hashBlock(messages[i][0]);
                messages[i][1] = mAesFixedKey.hashBlock(messages[i][1]);

            }
        }
        else
        {
            throw RTE_LOC;
        }

        setTimePoint("sender.expand.ldpc.mHash");
    }

    task<> SilentOtExtSender::silentSend(
        block d,
        span<block> b,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, d, b, &prng, &chl);

        MC_AWAIT(silentSendInplace(d, b.size(), prng, chl));

        std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
        setTimePoint("sender.expand.ldpc.copy");
        clear();
        MC_END();
    }

    task<> SilentOtExtSender::silentSendInplace(
        block d,
        u64 n,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, d, n, &prng, &chl,
            i = u64{}, j = u64{},
            delta = AlignedUnVector<block>{}
        );

        setTimePoint("sender.expand.enter");

        if (isConfigured() == false)
        {
            configure(n, 2, mNumThreads, mMalType);
        }

        if (n != mRequestNumOts)
            throw std::invalid_argument("n != mRequestNumOts " LOCATION);

        if (hasSilentBaseOts() == false)
        {
            MC_AWAIT(genSilentBaseOts(prng, chl));
        }

        setTimePoint("sender.expand.start");

        mDelta = d;

        // allocate b
        mB.resize(mNoiseVecSize);
        
        delta.resize(1);
        delta[0] = mDelta;

        MC_AWAIT(mGen.expand(chl, delta, prng.get(), mB, PprfOutputFormat::Interleaved, true, mNumThreads));

        setTimePoint("sender.expand.pprf");

        if (mMalType == SilentSecType::Malicious)
        {
            MC_AWAIT(ferretMalCheck(chl, prng));
            setTimePoint("sender.expand.malcheck");
        }


        if (mDebug)
            MC_AWAIT(checkRT(chl));

        compress();

        setTimePoint("sender.expand.dualEncode");

        mB.resize(mRequestNumOts);

        MC_END();
    }


    task<> SilentOtExtSender::ferretMalCheck(Socket& chl, PRNG& prng)
    {
        MC_BEGIN(task<>,this, &chl, &prng,
            X = block{},
            xx = block{},
            sum0 = ZeroBlock,
            sum1 = ZeroBlock,
            mySum = block{},
            a = AlignedUnVector<block>(1),
            c = AlignedUnVector<block>(1),
            //deltaShare = block{},
            i = u64{},
            recver = NoisyVoleReceiver<block, block, CoeffCtxGF128>{},
            myHash = std::array<u8, 32>{},
            ro = RandomOracle(32)
            );

        MC_AWAIT(chl.recv(X));

        xx = X;
        for (i = 0; i < (u64)mB.size(); ++i)
        {
            block low, high;
            xx.gf128Mul(mB[i], low, high);
            sum0 = sum0 ^ low;
            sum1 = sum1 ^ high;
            //mySum = mySum ^ xx.gf128Mul(mB[i]);

            xx = xx.gf128Mul(X);
        }

        mySum = sum0.gf128Reduce(sum1);
        
        c[0] = mDelta;
        //a[0] = deltaShare;
        MC_AWAIT(recver.receive(c, a, prng, mMalCheckOts, chl, {}));

        ro.Update(mySum ^ a[0]);
        ro.Final(myHash);

        MC_AWAIT(chl.send(std::move(myHash)));

        MC_END();
    }

    void SilentOtExtSender::compress()
    {
        switch (mMultType)
        {
        case osuCrypto::MultType::QuasiCyclic:
        {

#ifdef ENABLE_BITPOLYMUL
            QuasiCyclicCode code;
            code.init2(mRequestNumOts, mNoiseVecSize);
            code.dualEncode(mB.subspan(0, code.size()));
#else
            throw std::runtime_error("ENABLE_BITPOLYMUL");
#endif
        }
            break;
        case osuCrypto::MultType::ExAcc7:
        case osuCrypto::MultType::ExAcc11:
        case osuCrypto::MultType::ExAcc21:
        case osuCrypto::MultType::ExAcc40:
        {
            EACode encoder;
            u64 expanderWeight = 0, _1;
            double _2;
            EAConfigure(mMultType, _1, expanderWeight, _2);
            encoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight);

            AlignedUnVector<block> B2(encoder.mMessageSize);
            encoder.dualEncode<block, CoeffCtxGF2>(mB, B2, {});
            std::swap(mB, B2);
            break;
        }
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:
        {

            u64 expanderWeight = 0, accWeight = 0, scaler = 0;
            double minDist = 0;
            ExConvConfigure(mMultType, scaler, expanderWeight, accWeight, minDist);
            assert(scaler == 2 && minDist > 0 && minDist < 1);

            ExConvCode exConvEncoder;
            exConvEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, accWeight);

            exConvEncoder.dualEncode<block, CoeffCtxGF2>(mB.begin(), {});
            break;
        }
        case osuCrypto::MultType::Tungsten:
        {
            experimental::TungstenCode encoder;
            encoder.config(oc::roundUpTo(mRequestNumOts, 8), mNoiseVecSize);
            
            encoder.dualEncode<block, CoeffCtxGF2>(mB.begin(), {}, mEncodeTemp);
            break;
        }
        default:
            throw RTE_LOC;
            break;
        }

         
    }
}

#endif