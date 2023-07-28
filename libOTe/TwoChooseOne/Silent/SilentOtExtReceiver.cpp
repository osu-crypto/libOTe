#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#ifdef ENABLE_SILENTOT

#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include <libOTe/Tools/bitpolymul.h>
#include <libOTe/Tools/LDPC/LdpcSampler.h>
#include <libOTe/Vole/Noisy/NoisyVoleSender.h>
#include <libOTe/Base/BaseOT.h>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/ThreadBarrier.h>
#include "libOTe/Tools/QuasiCyclicCode.h"

namespace osuCrypto
{


    //u64 getPartitions(u64 scaler, u64 p, u64 secParam);


    // sets the KOS base OTs that are then used to extend
    void SilentOtExtReceiver::setBaseOts(
        span<std::array<block, 2>> baseSendOts) {
#ifdef ENABLE_SOFTSPOKEN_OT
        mOtExtRecver.setBaseOts(baseSendOts);
#else
        throw std::runtime_error("soft spoken ot must be enabled");
#endif
    }


    // return the number of base OTs soft spoken ot needs
    u64 SilentOtExtReceiver::baseOtCount() const {
#ifdef ENABLE_SOFTSPOKEN_OT
        return mOtExtRecver.baseOtCount();
#else
        throw std::runtime_error("soft spoken ot must be enabled");
#endif
    }

    // returns true if the soft spoken ot base OTs are currently set.
    bool SilentOtExtReceiver::hasBaseOts() const {
#ifdef ENABLE_SOFTSPOKEN_OT
        return mOtExtRecver.hasBaseOts();
#else
        throw std::runtime_error("soft spoken ot must be enabled");
#endif
    };

    void SilentOtExtReceiver::setSilentBaseOts(span<block> recvBaseOts)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first.");

        if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
            throw std::runtime_error("wrong number of silent base OTs");

        auto genOts = recvBaseOts.subspan(0, mGen.baseOtCount());
        auto gapOts = recvBaseOts.subspan(genOts.size(), mGapOts.size());
        auto malOts = recvBaseOts.subspan(genOts.size() + mGapOts.size());

        mGen.setBase(genOts);
        std::copy(gapOts.begin(), gapOts.end(), mGapOts.begin());
        std::copy(malOts.begin(), malOts.end(), mMalCheckOts.begin());

    }

    task<> SilentOtExtReceiver::genBaseOts(
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>, this, &prng, &chl);
        setTimePoint("recver.gen.start");
#ifdef ENABLE_SOFTSPOKEN_OT
        //mOtExtRecver.mFiatShamir = true;
        MC_AWAIT(mOtExtRecver.genBaseOts(prng, chl));
#else
        throw std::runtime_error("soft spoken ot must be enabled");
#endif
        MC_END();
    }
    // Returns an independent copy of this extender.
    std::unique_ptr<OtExtReceiver> SilentOtExtReceiver::split() {

#ifdef ENABLE_SOFTSPOKEN_OT
        auto ptr = new SilentOtExtReceiver;
        auto ret = std::unique_ptr<OtExtReceiver>(ptr);
        ptr->mOtExtRecver = mOtExtRecver.splitBase();
        return ret;
#else
        throw std::runtime_error("soft spoken ot must be enabled");
#endif
    };


    BitVector SilentOtExtReceiver::sampleBaseChoiceBits(PRNG& prng) {
        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first");

        auto choice = mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);

        if (mGapOts.size())
        {
            mGapBaseChoice.resize(mGapOts.size());
            mGapBaseChoice.randomize(prng);
            choice.append(mGapBaseChoice);
        }

        mS.resize(mNumPartitions);
        mGen.getPoints(mS, getPprfFormat());
        auto main = mNumPartitions * mSizePer;
        for (u64 i = 0; i < mGapBaseChoice.size(); ++i)
        {
            if (mGapBaseChoice[i])
            {
                mS.push_back(main + i);
            }
        }

        if (mMalType == SilentSecType::Malicious)
        {
            mMalCheckSeed = prng.get();
            mMalCheckX = ZeroBlock;

            for (auto s : mS)
            {
                auto xs = mMalCheckSeed.gf128Pow(s + 1);
                mMalCheckX = mMalCheckX ^ xs;
            }

            mMalCheckChoice.resize(0);
            mMalCheckChoice.append((u8*)&mMalCheckX, 128);

            mMalCheckOts.resize(128);
            choice.append(mMalCheckChoice);
        }

        return choice;
    }


    task<> SilentOtExtReceiver::genSilentBaseOts(
        PRNG& prng,
        Socket& chl, bool useOtExtension)
    {
        MC_BEGIN(task<>, this, &prng, &chl, useOtExtension,
            choice = sampleBaseChoiceBits(prng),
            msg = AlignedUnVector<block>{},
            base = DefaultBaseOT{}
        );

        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        msg.resize(choice.size());

        // If we have soft spoken ot base OTs, use them
        // to extend to get the silent base OTs.

#if defined(ENABLE_SOFTSPOKEN_OT) || defined(LIBOTE_HAS_BASE_OT)

#ifdef ENABLE_SOFTSPOKEN_OT
        if (useOtExtension)
        {
            //mKosRecver.mFiatShamir = true;
            MC_AWAIT(mOtExtRecver.receive(choice, msg, prng, chl));
        }
        else
#endif
        {
            // otherwise just generate the silent 
            // base OTs directly.
            MC_AWAIT(base.receive(choice, msg, prng, chl));
            setTimePoint("recver.gen.baseOT");
        }

#else
        throw std::runtime_error("soft spoken ot or base OTs must be enabled");
#endif
        setSilentBaseOts(msg);

        setTimePoint("recver.gen.done");

        MC_END();
    };

    u64 SilentOtExtReceiver::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");
        return
            mGen.baseOtCount() +
            mGapOts.size() +
            (mMalType == SilentSecType::Malicious) * 128;
    }


    void SilentOtExtReceiver::configure(
        u64 numOTs,
        u64 scaler,
        u64 numThreads,
        SilentSecType malType)
    {
        mMalType = malType;
        mNumThreads = numThreads;
        mGapOts.resize(0);

        switch (mMultType)
        {
        case osuCrypto::MultType::QuasiCyclic:

            QuasiCyclicConfigure(numOTs, 128, scaler,
                mMultType,
                mRequestedNumOts,
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
                mRequestedNumOts,
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

            EAConfigure(numOTs, 128, mMultType, mRequestedNumOts, mNumPartitions, mSizePer, mN2, mN, mEAEncoder);
            break;
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:

            ExConvConfigure(numOTs, 128, mMultType, mRequestedNumOts, mNumPartitions, mSizePer, mN2, mN, mExConvEncoder);
            break;
        default:
            throw RTE_LOC;
            break;
        }


        mS.resize(mNumPartitions);
        mGen.configure(mSizePer, mS.size());
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


    task<> SilentOtExtReceiver::checkRT(Socket& chl, MatrixView<block> rT1)
    {
        MC_BEGIN(task<>, this, &chl, rT1,
            rT2 = Matrix<block>(rT1.rows(), rT1.cols(), AllocType::Uninitialized),
            delta = block{},
            i = u64{},
            R = Matrix<block>{},
            exp = Matrix<block>{},
            failed = false
        );

        MC_AWAIT(chl.recv(rT2));
        MC_AWAIT(chl.recv(delta));

        for (i = 0; i < rT1.size(); ++i)
            rT2(i) = rT2(i) ^ rT1(i);

        if (
#ifdef ENABLE_INSECURE_SILVER
            mMultType == MultType::slv11 || mMultType == MultType::slv5 || 
#endif
            mMultType == MultType::QuasiCyclic)
        {
            if (rT1.cols() != 1)
                throw RTE_LOC;
            R = rT2;
        }
        else
        {
            //if (rT1.rows() != 128)
            throw RTE_LOC;

            //R.resize(rT1.cols() * 128, 1);
            //MatrixView<block> Rv(R);
            //MatrixView<block> rT2v(rT2);
            //transpose(rT2v, Rv);
        }

        exp.resize(R.rows(), R.cols(), AllocType::Zeroed);
        for (i = 0; i < mS.size(); ++i)
        {
            exp(mS[i]) = delta;
        }

        for (i = 0; i < R.rows(); ++i)
        {
            if (neq(R(i), exp(i)))
            {
                std::cout << i << " / " << R.rows() << " R= " << R(i) << " exp= " << exp(i) << std::endl;
                failed = true;
            }
        }

        if (failed)
            throw RTE_LOC;

        std::cout << "debug check ok" << std::endl;

        setTimePoint("recver.expand.checkRT");

        MC_END();

    }

    task<> SilentOtExtReceiver::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>, this, &choices, messages, &prng, &chl,
            randChoice = BitVector(messages.size())
        );
        MC_AWAIT(silentReceive(randChoice, messages, prng, chl, OTType::Random));
        randChoice ^= choices;
        MC_AWAIT(chl.send(std::move(randChoice)));
        MC_END();
    }

    task<> SilentOtExtReceiver::silentReceive(
        BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Socket& chl,
        OTType type)
    {
        MC_BEGIN(task<>, this, &choices, messages, &prng, &chl, type,
            packing = (type == OTType::Random) ?
            ChoiceBitPacking::True :
            ChoiceBitPacking::False
        );

        if (choices.size() != (u64)messages.size())
            throw RTE_LOC;

        MC_AWAIT(silentReceiveInplace(messages.size(), prng, chl, packing));

        if (type == OTType::Random)
        {
            hash(choices, messages, packing);
        }
        else
        {
            std::memcpy(messages.data(), mA.data(), messages.size() * sizeof(block));
            setTimePoint("recver.expand.ldpc.copy");

            auto cIter = choices.begin();
            for (u64 i = 0; i < choices.size(); ++i)
            {
                *cIter = mC[i];
                ++cIter;
            }
            setTimePoint("recver.expand.ldpc.copyBits");
        }

        clear();

        MC_END();
    }

    task<> SilentOtExtReceiver::silentReceiveInplace(
        u64 n,
        PRNG& prng,
        Socket& chl,
        ChoiceBitPacking type)
    {
        MC_BEGIN(task<>, this, n, &prng, &chl, type,
            gapVals = std::vector<block>{},
            rT = MatrixView<block>{},
            i = u64{}, j = u64{}, main = u64{}
        );

        gTimer.setTimePoint("recver.ot.enter");

        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(n, mScaler, mNumThreads, mMalType);
        }

        if (n != mRequestedNumOts)
            throw std::invalid_argument("messages.size() > n");

        if (mGen.hasBaseOts() == false)
        {
            // recvs data
            MC_AWAIT(genSilentBaseOts(prng, chl));
        }

        setTimePoint("recver.expand.start");
        gTimer.setTimePoint("recver.expand.start");


        mA.resize(mN2);
        mC.resize(0);

        //// do the compression to get the final OTs.
        //if (mMultType == MultType::QuasiCyclic)
        //{
        //	rT = MatrixView<block>(mA.data(), 128, mN2 / 128);

        //	// locally expand the seeds.
        //	MC_AWAIT(mGen.expand(chl, prng, rT, PprfOutputFormat::InterleavedTransposed, mNumThreads));
        //	setTimePoint("recver.expand.pprf_transpose");

        //	if (mDebug)
        //	{
        //		MC_AWAIT(checkRT(chl, rT));
        //	}

        //	randMulQuasiCyclic(type);

        //}
        //else
        {

            main = mNumPartitions * mSizePer;
            if (mGapOts.size())
            {
                // derandomize the random OTs for the gap 
                // to have the desired correlation.
                gapVals.resize(mGapOts.size());
                MC_AWAIT(chl.recv(gapVals));
                for (i = main, j = 0; i < mN2; ++i, ++j)
                {
                    if (mGapBaseChoice[j])
                        mA[i] = AES(mGapOts[j]).ecbEncBlock(ZeroBlock) ^ gapVals[j];
                    else
                        mA[i] = mGapOts[j];
                }
            }


            MC_AWAIT(mGen.expand(chl, prng, mA.subspan(0, main), PprfOutputFormat::Interleaved, true, mNumThreads));
            setTimePoint("recver.expand.pprf_transpose");
            gTimer.setTimePoint("recver.expand.pprf_transpose");


            if (mMalType == SilentSecType::Malicious)
                MC_AWAIT(ferretMalCheck(chl, prng));


            if (mDebug)
            {
                rT = MatrixView<block>(mA.data(), mN2, 1);
                MC_AWAIT(checkRT(chl, rT));
            }

            compress(type);
        }

        mA.resize(mRequestedNumOts);

        if (mC.size())
        {
            mC.resize(mRequestedNumOts);
        }

        MC_END();
    }


    task<> SilentOtExtReceiver::ferretMalCheck(Socket& chl, PRNG& prng)
    {
        MC_BEGIN(task<>, this, &chl, &prng,
            xx = block{},
            sum0 = block{},
            sum1 = block{},
            mySum = block{},
            deltaShare = block{},
            i = u64{},
            sender = NoisyVoleSender{},
            theirHash = std::array<u8, 32>{},
            myHash = std::array<u8, 32>{},
            ro = RandomOracle(32)
        );
        MC_AWAIT(chl.send(std::move(mMalCheckSeed)));

        xx = mMalCheckSeed;
        sum0 = ZeroBlock;
        sum1 = ZeroBlock;

        for (i = 0; i < (u64)mA.size(); ++i)
        {
            block low, high;
            xx.gf128Mul(mA[i], low, high);
            sum0 = sum0 ^ low;
            sum1 = sum1 ^ high;
            //mySum = mySum ^ xx.gf128Mul(mA[i]);

            // xx = mMalCheckSeed^{i+1}
            xx = xx.gf128Mul(mMalCheckSeed);
        }
        mySum = sum0.gf128Reduce(sum1);


        MC_AWAIT(sender.send(mMalCheckX, { &deltaShare,1 }, prng, mMalCheckOts, chl));
        ;
        ro.Update(mySum ^ deltaShare);
        ro.Final(myHash);

        MC_AWAIT(chl.recv(theirHash));

        if (theirHash != myHash)
            throw RTE_LOC;

        MC_END();
    }

    void SilentOtExtReceiver::hash(
        BitVector& choices,
        span<block> messages,
        ChoiceBitPacking type)
    {
        if (choices.size() != mRequestedNumOts)
            throw RTE_LOC;
        if ((u64)messages.size() != mRequestedNumOts)
            throw RTE_LOC;

        auto cIter = choices.begin();
        //std::array<block, 8> hashBuffer;

        auto n8 = mRequestedNumOts / 8 * 8;
        auto m = &messages[0];
        auto r = &mA[0];

        if (type == ChoiceBitPacking::True)
        {

            block mask = OneBlock ^ AllOneBlock;

            for (u64 i = 0; i < n8; i += 8)
            {
                // extract the choice bit from the LSB of r
                u32 b0 = r[0].testc(OneBlock);
                u32 b1 = r[1].testc(OneBlock);
                u32 b2 = r[2].testc(OneBlock);
                u32 b3 = r[3].testc(OneBlock);
                u32 b4 = r[4].testc(OneBlock);
                u32 b5 = r[5].testc(OneBlock);
                u32 b6 = r[6].testc(OneBlock);
                u32 b7 = r[7].testc(OneBlock);

                // pack the choice bits.
                choices.data()[i / 8] =
                    b0 ^
                    (b1 << 1) ^
                    (b2 << 2) ^
                    (b3 << 3) ^
                    (b4 << 4) ^
                    (b5 << 5) ^
                    (b6 << 6) ^
                    (b7 << 7);

                // mask of the choice bit which is stored in the LSB
                m[0] = r[0] & mask;
                m[1] = r[1] & mask;
                m[2] = r[2] & mask;
                m[3] = r[3] & mask;
                m[4] = r[4] & mask;
                m[5] = r[5] & mask;
                m[6] = r[6] & mask;
                m[7] = r[7] & mask;

                mAesFixedKey.hashBlocks<8>(m, m);

                m += 8;
                r += 8;
            }

            cIter = cIter + n8;
            for (u64 i = n8; i < (u64)messages.size(); ++i)
            {
                auto m = &messages[i];
                auto r = &mA[i];
                m[0] = r[0] & mask;

                m[0] = mAesFixedKey.hashBlock(m[0]);

                *cIter = r[0].testc(OneBlock);
                ++cIter;
            }
        }
        else
        {
            // not implemented.
            throw RTE_LOC;
        }
        setTimePoint("recver.expand.ldpc.mCopyHash");

    }

    void SilentOtExtReceiver::compress(ChoiceBitPacking packing)// )
    {

        setTimePoint("recver.expand.ldpc.mult");

        if (packing == ChoiceBitPacking::True)
        {
            // zero out the lsb of mA. We will store mC there.
            block mask = OneBlock ^ AllOneBlock;
            auto m8 = mN2 / 8 * 8;
            auto r = mA.data();
            for (u64 i = 0; i < m8; i += 8)
            {
                r[0] = r[0] & mask;
                r[1] = r[1] & mask;
                r[2] = r[2] & mask;
                r[3] = r[3] & mask;
                r[4] = r[4] & mask;
                r[5] = r[5] & mask;
                r[6] = r[6] & mask;
                r[7] = r[7] & mask;
                r += 8;
            }
            for (u64 i = m8; i < mN2; ++i)
            {
                mA[i] = mA[i] & mask;
            }

            // set the lsb of mA to be mC.
            for (auto p : mS)
                mA[p] = mA[p] | OneBlock;
            setTimePoint("recver.expand.ldpc.mask");

            switch (mMultType)
            {
            case osuCrypto::MultType::QuasiCyclic:
            {
#ifdef ENABLE_BITPOLYMUL
                QuasiCyclicCode code;
                code.init(mP, mScaler);
                code.dualEncode(mA.subspan(0, code.size()));
#else
                throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
            }
            break;
#ifdef ENABLE_INSECURE_SILVER
            case osuCrypto::MultType::slv5:
            case osuCrypto::MultType::slv11:

                if (mTimer)
                    mEncoder.setTimer(getTimer());
                mEncoder.dualEncode<block>(mA);
                break;
#endif
            case osuCrypto::MultType::ExAcc7:
            case osuCrypto::MultType::ExAcc11:
            case osuCrypto::MultType::ExAcc21:
            case osuCrypto::MultType::ExAcc40:
            {
                AlignedUnVector<block> A2(mEAEncoder.mMessageSize);
                mEAEncoder.dualEncode<block>(mA.subspan(0, mEAEncoder.mCodeSize), A2);
                std::swap(mA, A2);
                break;
            }
            case osuCrypto::MultType::ExConv7x24:
            case osuCrypto::MultType::ExConv21x24:
                if (mTimer)
                    mExConvEncoder.setTimer(getTimer());
                mExConvEncoder.dualEncode<block>(mA.subspan(0, mExConvEncoder.generatorCols()));
                break;
            default:
                throw RTE_LOC;
                break;
            }

            setTimePoint("recver.expand.ldpc.dualEncode");

        }
        else
        {
            // allocate and initialize mC
            //if (mChoiceSpanSize < mN2)
            //{
            //	mChoiceSpanSize = mN2;
            //	mChoicePtr.reset((new u8[mN2]()));
            //}
            //else
            mC.resize(mN2);
            std::memset(mC.data(), 0, mN2);
            auto cc = mC.data();
            for (auto p : mS)
                cc[p] = 1;


            switch (mMultType)
            {
            case osuCrypto::MultType::QuasiCyclic:
            {
#ifdef ENABLE_BITPOLYMUL
                QuasiCyclicCode code;
                code.init(mP, mScaler);
                code.dualEncode(mA.subspan(0, code.size()));
                code.dualEncode(mC.subspan(0, code.size()));
#else
                throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
            }
            break;
#ifdef ENABLE_INSECURE_SILVER
            case osuCrypto::MultType::slv5:
            case osuCrypto::MultType::slv11:
                mEncoder.dualEncode2<block, u8>(mA, mC);
                break;
#endif
            case osuCrypto::MultType::ExAcc7:
            case osuCrypto::MultType::ExAcc11:
            case osuCrypto::MultType::ExAcc21:
            case osuCrypto::MultType::ExAcc40:
            {
                AlignedUnVector<block> A2(mEAEncoder.mMessageSize);
                AlignedUnVector<u8> C2(mEAEncoder.mMessageSize);
                mEAEncoder.dualEncode2<block, u8>(
                    mA.subspan(0, mEAEncoder.mCodeSize), A2,
                    mC.subspan(0, mEAEncoder.mCodeSize), C2);

                std::swap(mA, A2);
                std::swap(mC, C2);
                break;
            }

            case osuCrypto::MultType::ExConv7x24:
            case osuCrypto::MultType::ExConv21x24:
                if (mTimer)
                    mExConvEncoder.setTimer(getTimer());
                mExConvEncoder.dualEncode2<block, u8>(
                    mA.subspan(0, mExConvEncoder.mCodeSize),
                    mC.subspan(0, mExConvEncoder.mCodeSize)
                    );
                break;
            default:
                throw RTE_LOC;
                break;
            }

            setTimePoint("recver.expand.ldpc.dualEncode");
        }
    }

    void SilentOtExtReceiver::clear()
    {
        mN = 0;
        mN2 = 0;
        mRequestedNumOts = 0;
        mSizePer = 0;

        mC = {};
        mA = {};

        mGen.clear();

        mGapOts = {};

        mS = {};
    }


}
#endif