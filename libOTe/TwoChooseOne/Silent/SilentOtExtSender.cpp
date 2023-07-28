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

namespace osuCrypto
{


    // sets the KOS base OTs that are then used to extend
    void SilentOtExtSender::setBaseOts(
        span<block> baseRecvOts,
        const BitVector& choices)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        mOtExtSender.setBaseOts(baseRecvOts, choices);
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
        ptr->mOtExtSender = mOtExtSender.splitBase();
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
        return mOtExtSender.genBaseOts(prng, chl);
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }


    u64 SilentOtExtSender::baseOtCount() const
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        return mOtExtSender.baseOtCount();
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }

    bool SilentOtExtSender::hasBaseOts() const
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        return mOtExtSender.hasBaseOts();
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

            //mOtExtSender.mFiatShamir = true;
            MC_AWAIT(mOtExtSender.send(msg, prng, chl));
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

        auto n = mGen.baseOtCount() + mGapOts.size();

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
        auto gapOt = sendBaseOts.subspan(genOt.size(), mGapOts.size());
        auto malOt = sendBaseOts.subspan(genOt.size() + gapOt.size());
        mMalCheckOts.resize((mMalType == SilentSecType::Malicious) * 128);

        mGen.setBase(genOt);
        std::copy(gapOt.begin(), gapOt.end(), mGapOts.begin());
        std::copy(malOt.begin(), malOt.end(), mMalCheckOts.begin());
    }

    void SilentOtExtSender::configure(
        u64 numOTs, u64 scaler, u64 numThreads, SilentSecType malType)
    {
        mMalType = malType;
        mNumThreads = numThreads;

        mGapOts.resize(0);

        switch (mMultType)
        {
        case osuCrypto::MultType::QuasiCyclic:

            QuasiCyclicConfigure(numOTs, 128, scaler,
                mMultType,
                mRequestNumOts,
                mNumPartitions,
                mSizePer,
                mN2,
                mN,
                mP,
                mScaler);

            break;
#ifdef ENABLE_INSECURE_SILVER
        case osuCrypto::MultType::slv5:
        case osuCrypto::MultType::slv11:
        {
            if (scaler != 2)
                throw std::runtime_error("only scaler = 2 is supported for slv. " LOCATION);

            u64 gap;
            SilverConfigure(numOTs, 128,
                mMultType,
                mRequestNumOts,
                mNumPartitions,
                mSizePer,
                mN2,
                mN,
                gap,
                mEncoder);

            mGapOts.resize(gap);
            break;
        }
#endif
        case osuCrypto::MultType::ExAcc7:
        case osuCrypto::MultType::ExAcc11:
        case osuCrypto::MultType::ExAcc21:
        case osuCrypto::MultType::ExAcc40:

            EAConfigure(numOTs, 128, mMultType, mRequestNumOts, mNumPartitions, mSizePer, mN2, mN, mEAEncoder);
            break;
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:

            ExConvConfigure(numOTs, 128, mMultType, mRequestNumOts, mNumPartitions, mSizePer, mN2, mN, mExConvEncoder);
            break;
        default:
            throw RTE_LOC;
            break;
        }

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
        mN = 0;
        mN2 = 0;
        mRequestNumOts = 0;
        mSizePer = 0;
        mNumPartitions = 0;
        mP = 0;

        mB = {};

        mDelta = block(0,0);

        mGapOts = {};

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
            rT = MatrixView<block>{},
            gapVals = std::vector<block> {},
            i = u64{}, j = u64{}, main = u64{}
        );

        gTimer.setTimePoint("sender.ot.enter");
        setTimePoint("sender.expand.enter");

        if (isConfigured() == false)
        {
            configure(n, mScaler, mNumThreads, mMalType);
        }

        if (n != mRequestNumOts)
            throw std::invalid_argument("n != mRequestNumOts " LOCATION);

        if (hasSilentBaseOts() == false)
        {
            MC_AWAIT(genSilentBaseOts(prng, chl));
        }

        setTimePoint("sender.expand.start");
        gTimer.setTimePoint("sender.expand.start");

        mDelta = d;

        // allocate b
        mB.resize(mN2);

        //if (mMultType == MultType::QuasiCyclic)
        //{
        //    rT = MatrixView<block>(mB.data(), 128, mN2 / 128);

        //    MC_AWAIT(mGen.expand(chl, mDelta, prng, rT, PprfOutputFormat::InterleavedTransposed, mNumThreads));
        //    setTimePoint("sender.expand.pprf_transpose");
        //    gTimer.setTimePoint("sender.expand.pprf_transpose");

        //    if (mDebug)
        //        MC_AWAIT(checkRT(chl));

        //    randMulQuasiCyclic();
        //}
        //else
        {

            main = mNumPartitions * mSizePer;
            if (mGapOts.size())
            {
                // derandomize the random OTs for the gap 
                // to have the desired correlation.
                gapVals.resize(mGapOts.size());
                for (i = main, j = 0; i < mN2; ++i, ++j)
                {
                    auto v = mGapOts[j][0] ^ mDelta;
                    gapVals[j] = AES(mGapOts[j][1]).ecbEncBlock(ZeroBlock) ^ v;
                    mB[i] = mGapOts[j][0];
                    //std::cout << "jj " << j << " " <<i << " " << mGapOts[j][0] << " " << v << " " << beta[mNumPartitions + j] << std::endl;
                }
                MC_AWAIT(chl.send(std::move(gapVals)));
            }


            MC_AWAIT(mGen.expand(chl, { &mDelta,1 }, prng, mB.subspan(0, main), PprfOutputFormat::Interleaved, true, mNumThreads));


            if (mMalType == SilentSecType::Malicious)
                MC_AWAIT(ferretMalCheck(chl, prng));

            setTimePoint("sender.expand.pprf_transpose");
            gTimer.setTimePoint("sender.expand.pprf_transpose");

            if (mDebug)
                MC_AWAIT(checkRT(chl));

            compress();
        }

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
            deltaShare = block{},
            i = u64{},
            recver = NoisyVoleReceiver{},
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
        

        
        MC_AWAIT(recver.receive({ &mDelta,1 }, { &deltaShare,1 }, prng, mMalCheckOts, chl));

        ro.Update(mySum ^ deltaShare);
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
            code.init(mP, mScaler);
            code.dualEncode(mB.subspan(0, code.size()));
#else
            throw std::runtime_error("ENABLE_BITPOLYMUL");
#endif
        }
            break;
#ifdef ENABLE_INSECURE_SILVER
        case osuCrypto::MultType::slv5:
        case osuCrypto::MultType::slv11:

            if (mTimer)
                mEncoder.setTimer(getTimer());
            mEncoder.dualEncode<block>(mB);
            setTimePoint("sender.expand.ldpc.dualEncode");

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
            mEAEncoder.dualEncode<block>(mB.subspan(0, mEAEncoder.mCodeSize), B2);
            std::swap(mB, B2);
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


    }
//
//
//    void SilentOtExtSender::randMulQuasiCyclic()
//    {
//#ifdef ENABLE_BITPOLYMUL
//
//        const u64 rows(128);
//        auto nBlocks = mN / rows;
//        auto n2Blocks = mN2 / rows;
//        MatrixView<block> rT(mB.data(), rows, n2Blocks);
//        auto n64 = i64(nBlocks * 2);
//        std::vector<FFTPoly> a(mScaler - 1);
//        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);
//
//        std::unique_ptr<ThreadBarrier[]> brs(new ThreadBarrier[mScaler]);
//        for (u64 i = 0; i < mScaler; ++i)
//            brs[i].reset(mNumThreads);
//
//        auto routine = [&](u64 index)
//        {
//            u64 j = 0;
//            FFTPoly bPoly;
//            FFTPoly cPoly;
//
//            Matrix<block>tt(1, 2 * nBlocks, AllocType::Uninitialized);
//            auto temp128 = tt[0];
//
//            FFTPoly::DecodeCache cache;
//            for (u64 s = index + 1; s < mScaler; s += mNumThreads)
//            {
//                auto a64 = spanCast<u64>(temp128).subspan(n64);
//                PRNG pubPrng(toBlock(s));
//                pubPrng.get(a64.data(), a64.size());
//                a[s - 1].encode(a64);
//            }
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.randGen");
//
//            brs[j++].decrementWait();
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.randGenWait");
//
//            auto multAddReduce = [this, nBlocks, n64, &a, &bPoly, &cPoly, &temp128, &cache](span<block> b128, span<block> dest)
//            {
//                for (u64 s = 1; s < mScaler; ++s)
//                {
//                    auto& aPoly = a[s - 1];
//                    auto b64 = spanCast<u64>(b128).subspan(s * n64, n64);
//
//                    bPoly.encode(b64);
//
//                    if (s == 1)
//                    {
//                        cPoly.mult(aPoly, bPoly);
//                    }
//                    else
//                    {
//                        bPoly.multEq(aPoly);
//                        cPoly.addEq(bPoly);
//                    }
//                }
//
//                // decode c[i] and store it at t64Ptr
//                cPoly.decode(spanCast<u64>(temp128), cache, true);
//
//                for (u64 j = 0; j < nBlocks; ++j)
//                    temp128[j] = temp128[j] ^ b128[j];
//
//                // reduce s[i] mod (x^n - 1) and store it at cModP1[i]
//                modp(dest, temp128, mP);
//
//            };
//
//            for (u64 i = index; i < rows; i += mNumThreads)
//                multAddReduce(rT[i], cModP1[i]);
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.mulAddReduce");
//
//            brs[j++].decrementWait();
//
//
//            std::array<block, 128> tpBuffer;
//            auto numBlocks = (mRequestNumOts + 127) / 128;
//            auto begin = index * numBlocks / mNumThreads;
//            auto end = (index + 1) * numBlocks / mNumThreads;
//            for (u64 i = begin; i < end; ++i)
//            {
//                u64 j = i * tpBuffer.size();
//                auto min = std::min<u64>(tpBuffer.size(), mN - j);
//
//                for (u64 k = 0; k < tpBuffer.size(); ++k)
//                    tpBuffer[k] = cModP1(k, i);
//
//                transpose128(tpBuffer);
//
//                auto end = i * tpBuffer.size() + min;
//                for (u64 k = 0; j < end; ++j, ++k)
//                    mB[j] = tpBuffer[k];
//            }
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.transposeXor");
//        };
//
//        std::vector<std::thread> thrds(mNumThreads - 1);
//        for (u64 i = 0; i < thrds.size(); ++i)
//            thrds[i] = std::thread(routine, i);
//
//        routine(thrds.size());
//
//        for (u64 i = 0; i < thrds.size(); ++i)
//            thrds[i].join();
//
//
//#else
//    std::cout << "bit poly mul is not enabled. Please recompile with ENABLE_BITPOLYMUL defined. " LOCATION << std::endl;
//    throw RTE_LOC;
//#endif
//
//    }
}

#endif