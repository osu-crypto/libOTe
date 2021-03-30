#include "libOTe/TwoChooseOne/SilentOtExtSender.h"
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

namespace osuCrypto
{
    u64 secLevel(u64 scale, u64 p, u64 points)
    {
        auto x1 = std::log2(scale * p / double(p));
        auto x2 = std::log2(scale * p) / 2;
        return static_cast<u64>(points * x1 + x2);
    }

    u64 getPartitions(u64 scaler, u64 p, u64 secParam)
    {
        if (scaler < 2)
            throw std::runtime_error("scaler must be 2 or greater");

        u64 ret = 1;
        auto ss = secLevel(scaler, p, ret);
        while (ss < secParam)
        {
            ++ret;
            ss = secLevel(scaler, p, ret);
            if (ret > 1000)
                throw std::runtime_error("failed to find silent OT parameters");
        }
        return roundUpTo(ret, 8);
    }


    // sets the IKNP base OTs that are then used to extend
    void SilentOtExtSender::setBaseOts(
        span<block> baseRecvOts,
        const BitVector& choices,
        Channel& chl)
    {
#ifdef ENABLE_IKNP
        mIknpSender.setBaseOts(baseRecvOts, choices, chl);
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    // Returns an independent copy of this extender.
    std::unique_ptr<OtExtSender> SilentOtExtSender::split()
    {
        auto ptr = new SilentOtExtSender;
        auto ret = std::unique_ptr<OtExtSender>(ptr);
        ptr->mIknpSender = mIknpSender.splitBase();
        return ret;
    }

    // use the default base OT class to generate the
    // IKNP base OTs that are required.
    void SilentOtExtSender::genBaseOts(PRNG& prng, Channel& chl)
    {
#ifdef ENABLE_IKNP
        mIknpSender.genBaseOts(prng, chl);
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }


    u64 SilentOtExtSender::baseOtCount() const
    {
#ifdef ENABLE_IKNP
        return mIknpSender.baseOtCount();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif
    }

    bool SilentOtExtSender::hasBaseOts() const
    {
#ifdef ENABLE_IKNP
        return mIknpSender.hasBaseOts();
#else
        throw std::runtime_error("IKNP must be enabled");
#endif

    }

    void SilentOtExtSender::genSilentBaseOts(PRNG& prng, Channel& chl)
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

        setTimePoint("sender.gen.done");
    }

    u64 SilentOtExtSender::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        return mGen.baseOtCount();
    }

    void SilentOtExtSender::setSlientBaseOts(
        span<std::array<block, 2>> sendBaseOts)
    {
        mGen.setBase(sendBaseOts);
    }

    void SilentOtExtSender::configure(
        u64 numOTs, u64 scaler, u64 secParam, u64 numThreads)
    {
        mRequestNumOts = numOTs;
        mScaler = scaler;
        mNumThreads = numThreads;
        u64 extra = 0;

        if (mMultType == MultType::slv5 || mMultType == MultType::slv11)
        {
            if (scaler != 2)
                throw std::runtime_error("only scaler = 2 is supported for slv. " LOCATION);

            mNumPartitions = getPartitions(mScaler, numOTs, secParam);
            mSizePer = roundUpTo((numOTs * mScaler + mNumPartitions - 1) / mNumPartitions, 8);
            mN2 = roundUpTo(mSizePer * mNumPartitions, mScaler);
            mN = mN2 / mScaler;
            mP = 0;

            auto code = mMultType == MultType::slv11 ?
                LdpcDiagRegRepeaterEncoder::Weight11 :
                LdpcDiagRegRepeaterEncoder::Weight5;
            u64 colWeight = (u64)code;

            setTimePoint("config.begin");
            mEncoder.mL.init(mN, colWeight);
            setTimePoint("config.Left");
            mEncoder.mR.init(mN, code, true);
            setTimePoint("config.Right");

            throw RTE_LOC;
            extra = mEncoder.mR.mGap;
        }
        else
        {

            mP = nextPrime(std::max<u64>(numOTs, 128 * 128));
            mNumPartitions = getPartitions(scaler, mP, secParam);
            auto ss = (mP * scaler + mNumPartitions - 1) / mNumPartitions;
            mSizePer = roundUpTo(ss, 8);
            mN2 = mSizePer * mNumPartitions;
            mN = mN2 / scaler;
        }

        mGen.configure(mSizePer, mNumPartitions);
    }

    void SilentOtExtSender::checkRT(Channel& chl)
    {
        chl.asyncSendCopy(mB.data(), mB.size());
        chl.asyncSendCopy(mDelta);

        setTimePoint("sender.expand.checkRT");

    }

    void SilentOtExtSender::clear()
    {
        mN = 0;
        mN2 = 0;
        mRequestNumOts = 0;
        mSizePer = 0;
        mNumPartitions = 0;
        mP = 0;

        mBacking = {};
        mBackingSize = 0;
        mB = {};

        mDelta = block(0,0);

        mGen.clear();
    }

    void SilentOtExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {
        silentSend(messages, prng, chl);
        BitVector correction(messages.size());
        chl.recv(correction);
        auto iter = correction.begin();

        for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
        {
            u8 bit = *iter; ++iter;
            auto temp = messages[i][bit];
            messages[i][bit] = messages[i][bit ^ 1];
            messages[i][bit ^ 1] = temp;
        }
    }

    void SilentOtExtSender::silentSend(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {
        silentSendInplace(prng.get(), messages.size(), prng, chl);

        auto type = ChoiceBitPacking::True;
        hash(messages, type);
        clear();
    }

    void SilentOtExtSender::hash(
        span<std::array<block, 2>> messages, ChoiceBitPacking type)
    {
        if (type == ChoiceBitPacking::True)
        {



            block mask = OneBlock ^ AllOneBlock;
            auto d = mDelta & mask;

            auto n8 = messages.size() / 8 * 8;
            block hashBuffer[8];

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
                mAesFixedKey.ecbEnc8Blocks(iter, hashBuffer);

                iter[0] = iter[0] ^ hashBuffer[0];
                iter[1] = iter[1] ^ hashBuffer[1];
                iter[2] = iter[2] ^ hashBuffer[2];
                iter[3] = iter[3] ^ hashBuffer[3];
                iter[4] = iter[4] ^ hashBuffer[4];
                iter[5] = iter[5] ^ hashBuffer[5];
                iter[6] = iter[6] ^ hashBuffer[6];
                iter[7] = iter[7] ^ hashBuffer[7];

                iter += 8;
                mAesFixedKey.ecbEnc8Blocks(iter, hashBuffer);

                iter[0] = iter[0] ^ hashBuffer[0];
                iter[1] = iter[1] ^ hashBuffer[1];
                iter[2] = iter[2] ^ hashBuffer[2];
                iter[3] = iter[3] ^ hashBuffer[3];
                iter[4] = iter[4] ^ hashBuffer[4];
                iter[5] = iter[5] ^ hashBuffer[5];
                iter[6] = iter[6] ^ hashBuffer[6];
                iter[7] = iter[7] ^ hashBuffer[7];

                m += 8;
                r += 8;
            }
            for (u64 i = n8; i < messages.size(); ++i)
            {
                messages[i][0] = (mB[i]) & mask;
                messages[i][1] = (mB[i] ^ d) & mask;

                auto h = mAesFixedKey.ecbEncBlock(messages[i][0]);
                messages[i][0] = messages[i][0] ^ h;
                h = mAesFixedKey.ecbEncBlock(messages[i][1]);
                messages[i][1] = messages[i][1] ^ h;

            }
        }
        else
        {
            throw RTE_LOC;
        }

        setTimePoint("sender.expand.ldpc.mHash");
    }

    void SilentOtExtSender::silentSend(
        block d,
        span<block> b,
        PRNG& prng,
        Channel& chl)
    {
        silentSendInplace(d, b.size(), prng, chl);

        std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
        setTimePoint("sender.expand.ldpc.copy");
        clear();
    }

    void SilentOtExtSender::silentSendInplace(
        block d,
        u64 n,
        PRNG& prng,
        Channel& chl)
    {
        gTimer.setTimePoint("sender.ot.enter");
        setTimePoint("sender.expand.enter");

        if (isConfigured() == false)
        {
            configure(n, mScaler, 128, mNumThreads);
        }

        if (n != mRequestNumOts)
            throw std::invalid_argument("n != mRequestNumOts " LOCATION);

        if (hasSilentBaseOts() == false)
        {
            genSilentBaseOts(prng, chl);
        }

        setTimePoint("sender.expand.start");
        gTimer.setTimePoint("sender.expand.start");

        mDelta = d;

        // allocate b
        if (mBackingSize < mN2)
        {
            mBackingSize = mN2;
            mBacking.reset(new block[mBackingSize]);
        }
        mB = span<block>(mBacking.get(), mN2);

        switch (mMultType)
        {
        case MultType::QuasiCyclic:
        {
            MatrixView<block> rT(mB.data(), 128, mN2 / 128);

            mGen.expand(chl, mDelta, prng, rT, PprfOutputFormat::InterleavedTransposed, false);
            setTimePoint("sender.expand.pprf_transpose");
            gTimer.setTimePoint("sender.expand.pprf_transpose");

            if (mDebug)
                checkRT(chl);

            randMulQuasiCyclic();

            break;
        }
        case MultType::slv11:
        case MultType::slv5:
        {
            mGen.expand(chl, mDelta, prng, mB, PprfOutputFormat::Interleaved, false);
            setTimePoint("sender.expand.pprf_transpose");
            gTimer.setTimePoint("sender.expand.pprf_transpose");

            if (mDebug)
                checkRT(chl);

            ldpcMult();
            break;
        }
        default:
            throw RTE_LOC;
            break;
        }

        mB = span<block>(mBacking.get(), mRequestNumOts);
    }

    void bitShiftXor(span<block> dest, span<block> in, u8 bitShift)
    {
        if (bitShift > 127)
            throw RTE_LOC;
        if (u64(in.data()) % 16)
            throw RTE_LOC;

        if (bitShift >= 64)
        {
            bitShift -= 64;
            const int bitShift2 = 64 - bitShift;
            u8* inPtr = ((u8*)in.data()) + sizeof(u64);

            auto end = std::min<u64>(dest.size(), in.size() - 1);
            for (u64 i = 0; i < end; ++i, inPtr += sizeof(block))
            {
                block
                    b0 = toBlock(inPtr),
                    b1 = toBlock(inPtr + sizeof(u64));

                b0 = (b0 >> bitShift);
                b1 = (b1 << bitShift2);

                dest[i] = dest[i] ^ b0 ^ b1;
            }

            if (end != static_cast<u64>(dest.size()))
            {
                u64 b0 = *(u64*)inPtr;
                b0 = (b0 >> bitShift);

                *(u64*)(&dest[end]) ^= b0;
            }
        }
        else if (bitShift)
        {
            const int bitShift2 = 64 - bitShift;
            u8* inPtr = (u8*)in.data();

            auto end = std::min<u64>(dest.size(), in.size() - 1);
            for (u64 i = 0; i < end; ++i, inPtr += sizeof(block))
            {
                block
                    b0 = toBlock(inPtr),
                    b1 = toBlock(inPtr + sizeof(u64));

                b0 = (b0 >> bitShift);
                b1 = (b1 << bitShift2);

                //bv0.append((u8*)&b0, 128);
                //bv1.append((u8*)&b1, 128);

                dest[i] = dest[i] ^ b0 ^ b1;
            }

            if (end != static_cast<u64>(dest.size()))
            {
                block b0 = toBlock(inPtr);
                b0 = (b0 >> bitShift);

                //bv0.append((u8*)&b0, 128);

                dest[end] = dest[end] ^ b0;

                u64 b1 = *(u64*)(inPtr + sizeof(u64));
                b1 = (b1 << bitShift2);

                //bv1.append((u8*)&b1, 64);

                *(u64*)&dest[end] ^= b1;
            }



            //std::cout << " b0     " << bv0 << std::endl;
            //std::cout << " b1     " << bv1 << std::endl;
        }
        else
        {
            auto end = std::min<u64>(dest.size(), in.size());
            for (u64 i = 0; i < end; ++i)
            {
                dest[i] = dest[i] ^ in[i];
            }
        }
    }

    void modp(span<block> dest, span<block> in, u64 p)
    {
        auto pBlocks = (p + 127) / 128;
        auto pBytes = (p + 7) / 8;

        if (static_cast<u64>(dest.size()) < pBlocks)
            throw RTE_LOC;

        if (static_cast<u64>(in.size()) < pBlocks)
            throw RTE_LOC;

        auto count = (in.size() * 128 + p - 1) / p;

        memcpy(dest.data(), in.data(), pBytes);

        for (u64 i = 1; i < count; ++i)
        {
            auto begin = i * p;
            auto end = std::min<u64>(i * p + p, in.size() * 128);

            auto shift = begin & 127;
            auto beginBlock = in.data() + (begin / 128);
            auto endBlock = in.data() + ((end + 127) / 128);

            if (endBlock > in.data() + in.size())
                throw RTE_LOC;


            auto in_i = span<block>(beginBlock, endBlock);

            bitShiftXor(dest, in_i, static_cast<u8>(shift));
        }


        auto offset = (p & 7);
        if (offset)
        {
            u8 mask = (1 << offset) - 1;
            auto idx = p / 8;
            ((u8*)dest.data())[idx] &= mask;
        }

        auto rem = dest.size() * 16 - pBytes;
        if (rem)
            memset(((u8*)dest.data()) + pBytes, 0, rem);
    }


    void SilentOtExtSender::ldpcMult()
    {

        if(mTimer)
            mEncoder.setTimer(getTimer());
        mEncoder.cirTransEncode(mB);
        setTimePoint("sender.expand.ldpc.cirTransEncode");
    }


    void SilentOtExtSender::randMulQuasiCyclic()
    {
        using namespace bpm;
        const u64 rows(128);
        auto nBlocks = mN / rows;
        auto n2Blocks = mN2 / rows;
        MatrixView<block> rT(mB.data(), rows, n2Blocks);
        auto n64 = i64(nBlocks * 2);
        std::vector<FFTPoly> a(mScaler - 1);
        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);

        std::unique_ptr<ThreadBarrier[]> brs(new ThreadBarrier[mScaler]);
        for (u64 i = 0; i < mScaler; ++i)
            brs[i].reset(mNumThreads);

        auto routine = [&](u64 index)
        {
            u64 j = 0;
            FFTPoly bPoly;
            FFTPoly cPoly;

            Matrix<block>tt(1, 2 * nBlocks, AllocType::Uninitialized);
            auto temp128 = tt[0];

            FFTPoly::DecodeCache cache;
            for (u64 s = index + 1; s < mScaler; s += mNumThreads)
            {
                auto a64 = spanCast<u64>(temp128).subspan(n64);
                PRNG pubPrng(toBlock(s));
                pubPrng.get(a64.data(), a64.size());
                a[s - 1].encode(a64);
            }

            if (index == 0)
                setTimePoint("sender.expand.qc.randGen");

            brs[j++].decrementWait();

            if (index == 0)
                setTimePoint("sender.expand.qc.randGenWait");

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

            for (u64 i = index; i < rows; i += mNumThreads)
                multAddReduce(rT[i], cModP1[i]);

            if (index == 0)
                setTimePoint("sender.expand.qc.mulAddReduce");

            brs[j++].decrementWait();

            std::array<block, 8> hashBuffer;
            std::array<block, 128> tpBuffer;
            auto numBlocks = (mRequestNumOts + 127) / 128;
            auto begin = index * numBlocks / mNumThreads;
            auto end = (index + 1) * numBlocks / mNumThreads;
            for (u64 i = begin; i < end; ++i)
            {
                u64 j = i * tpBuffer.size();
                auto min = std::min<u64>(tpBuffer.size(), mN - j);

                for (u64 k = 0; k < tpBuffer.size(); ++k)
                    tpBuffer[k] = cModP1(k, i);

                transpose128(tpBuffer);

                auto end = i * tpBuffer.size() + min;
                for (u64 k = 0; j < end; ++j, ++k)
                    mB[j] = tpBuffer[k];
            }

            if (index == 0)
                setTimePoint("sender.expand.qc.transposeXor");
        };

        std::vector<std::thread> thrds(mNumThreads - 1);
        for (u64 i = 0; i < thrds.size(); ++i)
            thrds[i] = std::thread(routine, i);

        routine(thrds.size());

        for (u64 i = 0; i < thrds.size(); ++i)
            thrds[i].join();

    }
}

#endif