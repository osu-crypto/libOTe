#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#ifdef ENABLE_SILENTOT
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <libOTe/Tools/bitpolymul.h>
#include <libOTe/Base/BaseOT.h>
#include <cryptoTools/Common/ThreadBarrier.h>
#include <libOTe/Tools/LDPC/LdpcSampler.h>

#include <libOTe/Vole/NoisyVoleSender.h>
//#include <bits/stdc++.h>

namespace osuCrypto
{


    u64 getPartitions(u64 scaler, u64 p, u64 secParam);



    // sets the Iknp base OTs that are then used to extend
    void SilentOtExtReceiver::setBaseOts(
        span<std::array<block, 2>> baseSendOts,
        PRNG& prng,
        Channel& chl) {

        setBaseOts(baseSendOts);
    }

    // sets the Iknp base OTs that are then used to extend
    void SilentOtExtReceiver::setBaseOts(
        span<std::array<block, 2>> baseSendOts) {
#ifdef ENABLE_KOS
        mKosRecver.setUniformBaseOts(baseSendOts);
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }


    // return the number of base OTs IKNP needs
    u64 SilentOtExtReceiver::baseOtCount() const {
#ifdef ENABLE_KOS
        return mKosRecver.baseOtCount();
#else
        throw std::runtime_error("KOS must be enabled");
#endif
    }

    // returns true if the IKNP base OTs are currently set.
    bool SilentOtExtReceiver::hasBaseOts() const {
#ifdef ENABLE_KOS
        return mKosRecver.hasBaseOts();
#else
        throw std::runtime_error("IKNP must be enabled");
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

    void SilentOtExtReceiver::genBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        setTimePoint("recver.gen.start");
#ifdef ENABLE_KOS
        mKosRecver.mFiatShamir = true;
        mKosRecver.genBaseOts(prng, chl);
#else
        throw std::runtime_error("KOS must be enabled");
#endif

    }
    // Returns an indpendent copy of this extender.
    std::unique_ptr<OtExtReceiver> SilentOtExtReceiver::split() {

        auto ptr = new SilentOtExtReceiver;
        auto ret = std::unique_ptr<OtExtReceiver>(ptr);
        ptr->mKosRecver = mKosRecver.splitBase();
        return ret;
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


    void SilentOtExtReceiver::genSilentBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        BitVector choice = sampleBaseChoiceBits(prng);
        std::vector<block, AlignedBlockAllocator> msg(choice.size());

        // If we have IKNP base OTs, use them
        // to extend to get the silent base OTs.

#if defined(ENABLE_KOS) || defined(LIBOTE_HAS_BASE_OT)

#ifdef ENABLE_KOS
        mKosRecver.mFiatShamir = true;
        mKosRecver.receive(choice, msg, prng, chl);
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
        setSilentBaseOts(msg);

        setTimePoint("recver.gen.done");
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

    void QuasiCyclicConfigure(
        u64 numOTs, u64 secParam,
        u64 scaler,
        MultType mMultType,
        u64& mRequestedNumOTs,
        u64& mNumPartitions,
        u64& mSizePer,
        u64& mN2,
        u64& mN,
        u64& mP,
        u64& mScaler);

    void SilentOtExtReceiver::configure(
        u64 numOTs,
        u64 scaler,
        u64 numThreads,
        SilentSecType malType)
    {
        mMalType = malType;
        mNumThreads = numThreads;

        if (mMultType == MultType::slv5 || mMultType == MultType::slv11)
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

        }
        else
        {
            QuasiCyclicConfigure(numOTs, 128, scaler,
                mMultType,
                mRequestedNumOts,
                mNumPartitions,
                mSizePer,
                mN2,
                mN,
                mP,
                mScaler);

            mGapOts.resize(0);
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


    void SilentOtExtReceiver::checkRT(Channel& chl, MatrixView<block> rT1)
    {

        Matrix<block> rT2(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
        chl.recv(rT2.data(), rT2.size());
        block delta;
        chl.recv(delta);

        for (u64 i = 0; i < rT1.size(); ++i)
            rT2(i) = rT2(i) ^ rT1(i);


        Matrix<block> R;

        if (mMultType == MultType::slv11 || mMultType == MultType::slv5)
        {
            if (rT1.cols() != 1)
                throw RTE_LOC;
            R = rT2;
        }
        else
        {
            if (rT1.rows() != 128)
                throw RTE_LOC;

            R.resize(rT1.cols() * 128, 1);
            MatrixView<block> Rv(R);
            MatrixView<block> rT2v(rT2);
            transpose(rT2v, Rv);
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

        if (failed)
            throw RTE_LOC;

        std::cout << "debug check ok" << std::endl;

        setTimePoint("recver.expand.checkRT");

    }

    void SilentOtExtReceiver::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& chl)
    {
        BitVector randChoice;
        silentReceive(randChoice, messages, prng, chl, OTType::Random);
        randChoice ^= choices;
        chl.asyncSend(std::move(randChoice));
    }

    void SilentOtExtReceiver::silentReceive(
        BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& chl,
        OTType type)
    {
        if (choices.size() != (u64)messages.size())
            throw RTE_LOC;

        auto packing = type == OTType::Random ?
            ChoiceBitPacking::True :
            ChoiceBitPacking::False;

        silentReceiveInplace(messages.size(), prng, chl, packing);

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
    }

    void SilentOtExtReceiver::silentReceiveInplace(
        u64 n,
        PRNG& prng,
        Channel& chl,
        ChoiceBitPacking type)
    {

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
            genSilentBaseOts(prng, chl);
        }

        setTimePoint("recver.expand.start");
        gTimer.setTimePoint("recver.expand.start");


        if (mBackingSize < mN2)
        {
            mBackingSize = mN2;
            mBacking = allocAlignedBlockArray(mBackingSize);
        }
        mA = span<block>(mBacking.get(), mN2);
        mC = {};

        // do the compression to get the final OTs.
        switch (mMultType)
        {
        case MultType::QuasiCyclic:
        {
            MatrixView<block> rT(mA.data(), 128, mN2 / 128);

            // locally expand the seeds.
            mGen.expand(chl, prng, rT, PprfOutputFormat::InterleavedTransposed, mNumThreads);
            setTimePoint("recver.expand.pprf_transpose");

            if (mDebug)
            {
                checkRT(chl, rT);
            }

            randMulQuasiCyclic(type);


            break;
        }
        case MultType::slv11:
        case MultType::slv5:
        {
            // derandomize the random OTs for the gap
            // to have the desired correlation.
            std::vector<block> gapVals(mGapOts.size());
            chl.recv(gapVals.data(), gapVals.size());
            auto main = mNumPartitions * mSizePer;
            for (u64 i = main, j = 0; i < mN2; ++i, ++j)
            {
                if (mGapBaseChoice[j])
                    mA[i] = AES(mGapOts[j]).ecbEncBlock(ZeroBlock) ^ gapVals[j];
                else
                    mA[i] = mGapOts[j];
            }


            mGen.expand(chl, prng, mA.subspan(0, main), PprfOutputFormat::Interleaved, mNumThreads);
            setTimePoint("recver.expand.pprf_transpose");
            gTimer.setTimePoint("recver.expand.pprf_transpose");


            if(mMalType == SilentSecType::Malicious)
                ferretMalCheck(chl, prng);


            if (mDebug)
            {
                MatrixView<block> rT(mA.data(), mN2, 1);
                checkRT(chl, rT);
            }

            ldpcMult(type);
        }
        break;
        default:
            break;
        }

        mA = span<block>(mBacking.get(), mRequestedNumOts);

        if (mC.size())
        {
            mC = span<u8>(mChoicePtr.get(), mRequestedNumOts);
        }
    }


    void SilentOtExtReceiver::ferretMalCheck(Channel& chl, PRNG& prng)
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
        block deltaShare;

        NoisyVoleSender sender;
        sender.send(mMalCheckX, { &deltaShare,1 }, prng, mMalCheckOts, chl);

        std::array<u8, 32> theirHash, myHash;
        RandomOracle ro(32);
        ro.Update(mySum ^ deltaShare);
        ro.Final(myHash);

        chl.recv(theirHash);

        if (theirHash != myHash)
            throw RTE_LOC;
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
        std::array<block, 8> hashBuffer;

        auto n8 = mRequestedNumOts / 8 * 8;
        auto m = &messages[0];
        auto r = &mA[0];

        if (type == ChoiceBitPacking::True)
        {

            block mask = OneBlock ^ AllOneBlock;

            for (u64 i = 0; i < n8; i += 8)
            {
                // mask of the choice bit which is stored in the LSB
                m[0] = r[0] & mask;
                m[1] = r[1] & mask;
                m[2] = r[2] & mask;
                m[3] = r[3] & mask;
                m[4] = r[4] & mask;
                m[5] = r[5] & mask;
                m[6] = r[6] & mask;
                m[7] = r[7] & mask;

                mAesFixedKey.ecbEnc8Blocks(m, hashBuffer.data());
                m[0] = m[0] ^ hashBuffer[0];
                m[1] = m[1] ^ hashBuffer[1];
                m[2] = m[2] ^ hashBuffer[2];
                m[3] = m[3] ^ hashBuffer[3];
                m[4] = m[4] ^ hashBuffer[4];
                m[5] = m[5] ^ hashBuffer[5];
                m[6] = m[6] ^ hashBuffer[6];
                m[7] = m[7] ^ hashBuffer[7];


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

                m += 8;
                r += 8;
            }

            cIter = cIter + n8;
            for (u64 i = n8; i < (u64)messages.size(); ++i)
            {
                auto m = &messages[i];
                auto r = &mA[i];
                m[0] = r[0] & mask;

                auto h = mAesFixedKey.ecbEncBlock(m[0]);
                m[0] = m[0] ^ h;

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

    void SilentOtExtReceiver::ldpcMult(ChoiceBitPacking packing)// )
    {

        setTimePoint("recver.expand.ldpc.mult");

        if (mTimer)
            mEncoder.setTimer(getTimer());

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

            // encode both mA and mC (which is the lsb of mA)
            mEncoder.cirTransEncode(mA);
            setTimePoint("recver.expand.ldpc.cirTransEncode");

        }
        else
        {
            // allocate and initialize mC
            if (mChoiceSpanSize < mN2)
            {
                mChoiceSpanSize = mN2;
                mChoicePtr.reset((new u8[mN2]()));
            }
            else
                std::memset(mChoicePtr.get(), 0, mN2);
            mC = span<u8>(mChoicePtr.get(), mN2);
            auto cc = mChoicePtr.get();
            // TODO: Consider making this constant time.
            for (auto p : mS)
                cc[p] = 1;

            // encode both the mA and mC vectors in place.
            mEncoder.cirTransEncode2<block, u8>(mA, mC);
            setTimePoint("recver.expand.ldpc.cirTransEncode");
        }
    }

    void bitShiftXor(span<block> dest, span<block> in, u8 bitShift);
    void modp(span<block> dest, span<block> in, u64 p);

    void SilentOtExtReceiver::randMulQuasiCyclic(ChoiceBitPacking packing)
    {
#ifdef ENABLE_BITPOLYMUL
        setTimePoint("recver.expand.QuasiCyclic");
        const u64 rows(128);
        auto nBlocks = mN / rows;
        auto n2Blocks = mN2 / rows;
        auto n64 = i64(nBlocks * 2);
        MatrixView<block> rT(mA.data(), rows, n2Blocks);

        std::vector<FFTPoly> a(mScaler - 1);
        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);

        std::array<ThreadBarrier, 2> brs;
        for (u64 i = 0; i < brs.size(); ++i)
            brs[i].reset(mNumThreads);

        setTimePoint("recver.expand.qc.Setup");

        auto routine = [&](u64 index)
        {
            if (index == 0)
                setTimePoint("recver.expand.qc.routine");

            FFTPoly cPoly;
            FFTPoly bPoly;
            Matrix<block>tt(1, 2 * nBlocks, AllocType::Uninitialized);
            auto temp128 = tt[0];
            FFTPoly::DecodeCache cache;

            for (u64 s = index + 1; s < mScaler; s += mNumThreads)
            {
                auto a64 = spanCast<u64>(temp128).subspan(n64);

                PRNG pubPrng(toBlock(s));
                pubPrng.get(a64.data(), a64.size());

                if (index == 0)
                    setTimePoint("recver.expand.qc.rand");
                a[s - 1].encode(a64);
            }

            brs[0].decrementWait();

            if (index == 0)
                setTimePoint("recver.expand.qc.randGen");

            auto multAddReduce = [this, nBlocks, n64, &a, &bPoly, &cPoly, &temp128, &cache](span<block> b128, span<block> dest)
            {
                for (u64 s = 1; s < mScaler; ++s)
                {
                    auto& aPoly = a[s - 1];
                    auto b64 = spanCast<u64>(b128).subspan(s * n64, n64);
                    bPoly.encode(b64);

                    if (s == 1)
                    {
                        cPoly.mult(aPoly, bPoly);
                    }
                    else
                    {
                        bPoly.multEq(aPoly);
                        cPoly.addEq(bPoly);
                    }
                }

                // decode c[i] and store it at t64Ptr
                cPoly.decode(spanCast<u64>(temp128), cache, true);

                for (u64 j = 0; j < nBlocks; ++j)
                    temp128[j] = temp128[j] ^ b128[j];

                // reduce s[i] mod (x^p - 1) and store it at cModP1[i]
                modp(dest, temp128, mP);
            };

            auto stop = packing == ChoiceBitPacking::True ?
                rows :
                rows + 1;

            for (u64 i = index; i < stop; i += mNumThreads)
            {

                bool computeCVec =
                    (i == 0 && packing == ChoiceBitPacking::True) ||
                    (i == rows);

                if (computeCVec)
                {
                    // the choice vector
                    BitVector sb(mN2);
                    for (u64 i = 0; i < mS.size(); ++i)
                        sb[mS[i]] = 1;

                    if (packing == ChoiceBitPacking::True)
                    {
                        // make the LSB of mA be the choice bit.
                        multAddReduce(sb.getSpan<block>(), cModP1[i]);
                    }
                    else
                    {
                        std::vector<block> c128(nBlocks);
                        multAddReduce(sb.getSpan<block>(), c128);

                        if (mChoiceSpanSize < mRequestedNumOts)
                        {
                            mChoiceSpanSize = mRequestedNumOts;
                            mChoicePtr.reset(new u8[mChoiceSpanSize]);
                        }

                        BitIterator iter((u8*)c128.data());
                        mC = span<u8>(mChoicePtr.get(), mRequestedNumOts);
                        for (u64 j = 0; j < mRequestedNumOts; ++j)
                        {
                            mC[j] = *iter;
                            ++iter;
                        }
                    }

                }
                else
                {
                    multAddReduce(rT[i], cModP1[i]);
                }
            }

            if (index == 0)
                setTimePoint("recver.expand.qc.mulAddReduce");

            brs[1].decrementWait();

            // transpose and copy into the mA vector.

            auto numBlocks = mRequestedNumOts / 128;
            auto begin = index * numBlocks / mNumThreads;
            auto end = (index + 1) * numBlocks / mNumThreads;
            for (u64 i = begin; i < end; ++i)
            {
                u64 j = i * 128;
                auto& tpBuffer = *(std::array<block, 128>*)(mA.data() + j);

                for (u64 k = 0; k < 128; ++k)
                    tpBuffer[k] = cModP1(k, i);

                transpose128(tpBuffer.data());
            }

            auto rem = mRequestedNumOts % 128;
            if (rem && index == 0)
            {
                AlignedBlockArray<128> tpBuffer;

                for (u64 j = 0; j < tpBuffer.size(); ++j)
                    tpBuffer[j] = cModP1(j, numBlocks);

                transpose128(tpBuffer.data());

                memcpy(mA.data() + numBlocks * 128, tpBuffer.data(), rem * sizeof(block));
            }

            if (index == 0)
                setTimePoint("recver.expand.qc.transposeXor");
        };


        std::vector<std::thread> thrds(mNumThreads - 1);
        for (u64 i = 0; i < thrds.size(); ++i)
            thrds[i] = std::thread(routine, i);

        routine(thrds.size());

        for (u64 i = 0; i < thrds.size(); ++i)
            thrds[i].join();
#else

        std::cout << "bit poly mul is not enabled. Please recompile with ENABLE_BITPOLYMUL defined. " LOCATION << std::endl;
        throw RTE_LOC;
#endif
    }

    void SilentOtExtReceiver::clear()
    {
        mN = 0;
        mN2 = 0;
        mRequestedNumOts = 0;
        mSizePer = 0;

        mC = {};
        mChoicePtr = {};
        mChoiceSpanSize = 0;

        mA = {};
        mBacking = {};
        mBackingSize = {};

        mGen.clear();

        mGapOts = {};

        mS = {};
    }


}
#endif
