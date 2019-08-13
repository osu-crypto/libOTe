#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#ifdef ENABLE_SILENTOT
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <libOTe/Tools/bitpolymul.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <cryptoTools/Common/ThreadBarrier.h>
//#include <bits/stdc++.h> 

namespace osuCrypto
{
    //bool gUseBgicksPprf(true);

    //using namespace std;

    // Utility function to do modular exponentiation. 
    // It returns (x^y) % p 
    u64 power(u64 x, u64 y, u64 p)
    {
        u64 res = 1;      // Initialize result 
        x = x % p;  // Update x if it is more than or 
                    // equal to p 
        while (y > 0)
        {
            // If y is odd, multiply x with result 
            if (y & 1)
                res = (res * x) % p;

            // y must be even now 
            y = y >> 1; // y = y/2 
            x = (x * x) % p;
        }
        return res;
    }

    // This function is called for all k trials. It returns 
    // false if n is composite and returns false if n is 
    // probably prime. 
    // d is an odd number such that  d*2<sup>r</sup> = n-1 
    // for some r >= 1 
    bool millerTest(u64 d, PRNG& prng, u64 n)
    {
        // Pick a random number in [2..n-2] 
        // Corner cases make sure that n > 4 
        u64 a = 2 + prng.get<u64>() % (n - 4);

        // Compute a^d % n 
        u64 x = power(a, d, n);

        if (x == 1 || x == n - 1)
            return true;

        // Keep squaring x while one of the following doesn't 
        // happen 
        // (i)   d does not reach n-1 
        // (ii)  (x^2) % n is not 1 
        // (iii) (x^2) % n is not n-1 
        while (d != n - 1)
        {
            x = (x * x) % n;
            d *= 2;

            if (x == 1)     return false;
            if (x == n - 1) return true;
        }

        // Return composite 
        return false;
    }

    // It returns false if n is composite and returns true if n 
    // is probably prime.  k is an input parameter that determines 
    // accuracy level. Higher value of k indicates more accuracy. 
    bool isPrime(u64 n, PRNG& prng, u64 k = 20)
    {
        // Corner cases 
        if (n <= 1 || n == 4)  return false;
        if (n <= 3) return true;

        // Find r such that n = 2^d * r + 1 for some r >= 1 
        u64 d = n - 1;
        while (d % 2 == 0)
            d /= 2;

        // Iterate given nber of 'k' times 
        for (u64 i = 0; i < k; i++)
            if (!millerTest(d, prng, n))
                return false;

        return true;
    }


    u64 nextPrime(u64 n)
    {
        PRNG prng(ZeroBlock);

        while (isPrime(n, prng) == false)
            ++n;
        return n;
    }


    //// The number of DPF points that will be used.
    //u64 numPartitions = 8;

    //// defines n' = nScaler * n
    //u64 nScaler = 4;

    u64 getPartitions(u64 scaler, u64 p, u64 secParam);

    void SilentOtExtReceiver::genBase(
        u64 n,
        Channel& chl,
        PRNG& prng,
        u64 scaler,
        u64 secParam,
        bool mal,
        SilentBaseType basetype,
        u64 threads)
    {
        setTimePoint("recver.gen.start");
        configure(n, scaler, secParam, mal);

        auto count = mGen.baseOtCount();
        std::vector<block> msg(count);

        BitVector choice = mGen.sampleChoiceBits(mN2, true, prng);
        //BitVector choice(count);
        //choice.randomize(prng);

        switch (basetype)
        {
        case osuCrypto::SilentBaseType::None:
            break;
        case osuCrypto::SilentBaseType::Base:
        {
#ifdef LIBOTE_HAS_BASE_OT
            DefaultBaseOT base;
            base.receive(choice, msg, prng, chl, threads);
            setTimePoint("recver.gen.baseOT");
            break;
#else
            throw std::runtime_error("not base OTs");
#endif
        }
        case osuCrypto::SilentBaseType::BaseExtend:
        {
#ifdef LIBOTE_HAS_BASE_OT
            DefaultBaseOT base;
            std::array<std::array<block, 2>, 128> baseMsg;
            prng.get(baseMsg.data(), baseMsg.size());
            base.send(baseMsg, prng, chl, threads);
            setTimePoint("recver.gen.baseOT");
            IknpOtExtReceiver iknp;
            iknp.setBaseOts(baseMsg);
            iknp.receive(choice, msg, prng, chl);
            setTimePoint("recver.gen.baseExtension");
            break;
#else
            throw std::runtime_error("not base OTs");
#endif
        }
        case osuCrypto::SilentBaseType::Extend:
        {
            std::array<std::array<block, 2>, 128> baseMsg;
            IknpOtExtReceiver iknp;
            iknp.setBaseOts(baseMsg);
            iknp.receive(choice, msg, prng, chl);
            setTimePoint("recver.gen.baseExtension");
            break;
        }
        default:
            break;
        }

        //TODO("comment this out and fix bug");
        //memset(msg.data(), 0, msg.size() * 16);

        mGen.setBase(msg);
        mGen.getTransposedPoints(mS);

        for (u64 i = 0; i < mS.size(); ++i)
        {
            if (mS[i] >= mN2)
            {
                //auto s = mS.size();

                for (u64 j = i; j < mS.size(); ++j)
                    std::cout << Color::Red << "bad " << j << " " << mS[j] << " / " << mN2 << std::endl << Color::Default;


            }
            //throw std::runtime_error("known issue, (fixable, ask peter). " LOCATION);
        }
        //std::cout << "np " << mS.size() << std::endl;
        //std::cout << "sp " << mSizePer << std::endl;
        //std::cout << "p  " << mP << std::endl;
        //std::cout << "N  " << mN << std::endl;
        //std::cout << "N2 " << mN2 << std::endl;


        setTimePoint("recver.gen.done");

    }

    void SilentOtExtReceiver::configure(
        const u64& n, const u64& scaler, const u64& secParam,
        bool mal)
    {

        mP = nextPrime(n);
        mN = roundUpTo(mP, 128);
        mScaler = scaler;
        mN2 = scaler * mN;
        mMal = mal;

        auto numPartitions = getPartitions(scaler, mP, secParam);
        mS.resize(numPartitions);
        mSizePer = (mN2 + numPartitions - 1) / numPartitions;


     
            mGen.configure(mSizePer, mS.size());
        
    }

    u64 SilentOtExtReceiver::baseOtCount()
    {

            return mGen.baseOtCount();
        return 0;
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

/*
    Matrix<block> expandTranspose(BgiEvaluator::MultiKey & gen, u64 n)
    {
        Matrix<block> rT(128, n / 128, AllocType::Uninitialized);

        std::array<block, 128> tpBuffer;

        if (n % 128)
            throw RTE_LOC;
        if (gen.mNumKeys > tpBuffer.size())
            throw std::runtime_error("not implemented, generalize the following loop to enable. " LOCATION);

        u64 curBlock = 0;

        for (u64 i = 0, j = 0; i < n;)
        {
            auto blocks = gen.yeild();
            auto blockCount = std::min<u64>(n - i, blocks.size());

            auto min2 = std::min<u64>(tpBuffer.size() - curBlock, blockCount);

            memcpy(tpBuffer.data() + curBlock, blocks.data(), min2 * sizeof(block));
            curBlock += min2;

            if (curBlock == tpBuffer.size())
            {
                sse_transpose128(tpBuffer);
                curBlock = 0;

                for (u64 k = 0; k < tpBuffer.size(); ++k)
                {
                    rT(k, j) = tpBuffer[k];
                }

                ++j;

                if (min2 != blockCount)
                {
                    curBlock = blockCount - min2;
                    memcpy(tpBuffer.data(), blocks.data() + min2, curBlock * sizeof(block));
                }
            }


            i += blockCount;
        }

        return rT;
    }*/

    void SilentOtExtReceiver::checkRT(span<Channel> chls, Matrix<block>& rT1)
    {
        if (rT1.rows() != 128)
            throw RTE_LOC;

        Matrix<block> rT2(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
        chls[0].recv(rT2.data(), rT2.size());
        block delta;
        chls[0].recv(delta);

        for (u64 i = 0; i < rT1.size(); ++i)
            rT2(i) = rT2(i) ^ rT1(i);
         

        Matrix<block> R(rT1.cols() * 128, 1);
        MatrixView<block> Rv(R);
        MatrixView<block> rT2v(rT2);
        sse_transpose(rT2v, Rv);

        Matrix<block> exp(R.rows(), R.cols(), AllocType::Zeroed);
        for (u64 i = 0; i < mS.size(); ++i)
        {
            exp(mS[i]) = delta;
        }

        for (u64 i = 0; i < R.rows(); ++i)
        {
            if (neq(R(i), exp(i)))
            {
                std::cout << i << " / " << R.rows() << " " << R(i) << " " << exp(i) << std::endl;
                throw RTE_LOC;
            }
        }
        //for (u64 x = 0; x < rT.rows(); ++x)
        //{
        //    for (u64 y = 0; y < rT.cols(); ++y)
        //    {
        //        std::cout << rT(x, y) << " " << rT2(x, y) << " " << (rT(x,y) ^ rT2(x,y))<< std::endl;
        //    }
        //    std::cout << std::endl;
        //}
    }


    void SilentOtExtReceiver::receive(
        span<block> messages,
        BitVector& choices,
        PRNG& prng,
        Channel& chl)
    {
        receive(messages, choices, prng, { &chl,1 });
    }
    void SilentOtExtReceiver::receive(
        span<block> messages,
        BitVector& choices,
        PRNG& prng,
        span<Channel> chls)
    {
        setTimePoint("recver.expand.start");

        // column major matric. mN2 columns and 1 row of 128 bits (128 bit rows)
        //std::vector<block> r(mN2);
        Matrix<block> rT;

        rT.resize(128, mN2 / 128, AllocType::Uninitialized);
        mSum = mGen.expand(chls, prng, rT, true, mMal);
        setTimePoint("sender.expand.pprf_transpose");


        if (mDebug)
        {
            checkRT(chls, rT);
        }

        //setTimePoint("recver.expand.transpose");


        auto type = MultType::QuasiCyclic;

        switch (type)
        {
        case osuCrypto::MultType::Naive:
            randMulNaive(rT, messages);
            break;
        case osuCrypto::MultType::QuasiCyclic:
            randMulQuasiCyclic(rT, messages, choices, chls.size());
            break;
        default:
            break;
        }

        //auto dest = mul(rMtx, mtx);
        //auto dest2 = convert(messages);
        //for (u64 i = 0; i < dest.rows(); ++i)
        //{
        //    std::cout << i << ":";

        //    for (u64 j = 0; j < dest.cols(); ++j)
        //    {
        //        if (dest(i, j) != dest2(j, i))
        //            std::cout << Color::Red;

        //        std::cout << ", " << int(dest(i, j)) << " " << int(dest2(j, i)) << Color::Default;
        //    }

        //    std::cout << std::endl;
        //}
        //std::cout << std::endl;

    }


    void SilentOtExtReceiver::randMulNaive(Matrix<block>& rT, span<block>& messages)
    {
        std::vector<block> mtxColumn(rT.cols());
        PRNG pubPrng(ZeroBlock);

        for (i64 i = 0; i < messages.size(); ++i)
        {
            block& m = messages[i];
            BitIterator iter((u8*)& m, 0);
            mulRand(pubPrng, mtxColumn, rT, iter);
        }
        setTimePoint("recver.expand.mul");
    }


    void SilentOtExtReceiver::randMulQuasiCyclic(Matrix<block>& rT, span<block>& messages, BitVector& choices, u64 threads)
    {
        setTimePoint("recver.expand.QuasiCyclic");
        auto nBlocks = mN / 128;
        auto n2Blocks = mN2 / 128;
        auto n64 = i64(nBlocks * 2);

        const u64 rows(128);
        if (rT.rows() != rows)
            throw RTE_LOC;
        if (rT.cols() != n2Blocks)
            throw RTE_LOC;

        using namespace bpm;
        //std::cout << (a64.data()) << " " << (a.data()) << std::endl;
        //u64 * a64ptr = (u64*)a.data();

        BitVector sb(mN2);
        for (u64 i = 0; i < mS.size(); ++i)
        {
            sb[mS[i]] = 1;
        }
        //std::vector<bpm::FFTPoly> c(rows);
        std::vector<FFTPoly> a(mScaler - 1);

        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);

        if (static_cast<u64>(messages.size()) > mN)
            throw RTE_LOC;

        choices.resize(mN);

        std::array<ThreadBarrier, 2> brs;
        for (u64 i = 0; i < brs.size(); ++i)
            brs[i].reset(threads);

        //std::vector<std::array<int, 4>> counts(threads);

        setTimePoint("recver.expand.QuasiCyclicSetup");

        auto routine = [&](u64 index)
        {

            if (index == 0)
                setTimePoint("recver.expand.routine");

            //auto& count = counts[index];
            FFTPoly cPoly;
            FFTPoly bPoly;
            Matrix<block>tt(1, 2 * nBlocks, AllocType::Uninitialized);
            //std::vector<block> temp128(2 * nBlocks);
            auto temp128 = tt[0];
            FFTPoly::DecodeCache cache;


            for (u64 s = index + 1; s < mScaler; s += threads)
            {
                auto a64 = spanCast<u64>(temp128).subspan(n64);

                PRNG pubPrng(toBlock(s));

                //pubPrng.mAes.ecbEncCounterMode(0, nBlocks, temp128.data());
                pubPrng.get(a64.data(), a64.size());
                //mAesFixedKey.ecbEncCounterMode(s * nBlocks, nBlocks, temp128.data());
                if (index == 0)
                    setTimePoint("recver.expand.rand");
                a[s - 1].encode(a64);
            }



            brs[0].decrementWait();

            if (index == 0)
                setTimePoint("recver.expand.randGen");

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

            for (u64 i = index; i < rows + 1; i += threads)
            {
                if (i < rows)
                {
                    multAddReduce(rT[i], cModP1[i]);
                }
                else
                {
                    span<block> c128 = choices.getSpan<block>();
                    multAddReduce(sb.getSpan<block>(), c128);
                    choices.resize(messages.size());
                }
            }


            if (index == 0)
                setTimePoint("recver.expand.mulAddReduce");


            brs[1].decrementWait();




            //MatrixView<block> view(messages.begin(), messages.end(), 1);
            //sse_transpose(cModP1, view);
    //#define NO_HASH
            std::array<block, 8> hashBuffer;
            auto numBlocks = messages.size() / 128;
            auto begin = index * numBlocks / threads;
            auto end = (index + 1) * numBlocks / threads;
            for (u64 i = begin; i < end; ++i)

                //for (u64 i = index; i < numBlocks; i += threads)
            {
                u64 j = i * 128;
                auto& tpBuffer = *(std::array<block, 128>*)(messages.data() + j);

                //for (u64 j = 0, k = i; j < tpBuffer.size(); ++j, k += cModP1.cols())
                //	tpBuffer[j] = cModP1(k);

                for (u64 k = 0; k < 128; ++k)
                    tpBuffer[k] = cModP1(k, i);

                sse_transpose128(tpBuffer);

#ifndef NO_HASH
                for (u64 k = 0; k < 128; k += 8)
                {
                    mAesFixedKey.ecbEncBlocks(tpBuffer.data() + k, hashBuffer.size(), hashBuffer.data());

                    tpBuffer[k + 0] = tpBuffer[k + 0] ^ hashBuffer[0];
                    tpBuffer[k + 1] = tpBuffer[k + 1] ^ hashBuffer[1];
                    tpBuffer[k + 2] = tpBuffer[k + 2] ^ hashBuffer[2];
                    tpBuffer[k + 3] = tpBuffer[k + 3] ^ hashBuffer[3];
                    tpBuffer[k + 4] = tpBuffer[k + 4] ^ hashBuffer[4];
                    tpBuffer[k + 5] = tpBuffer[k + 5] ^ hashBuffer[5];
                    tpBuffer[k + 6] = tpBuffer[k + 6] ^ hashBuffer[6];
                    tpBuffer[k + 7] = tpBuffer[k + 7] ^ hashBuffer[7];
                }
#endif
            }

            auto rem = messages.size() % 128;
            if (rem && index == 0)
            {
                std::array<block, 128> tpBuffer;

                for (u64 j = 0; j < tpBuffer.size(); ++j)
                    tpBuffer[j] = cModP1(j, numBlocks);

                sse_transpose128(tpBuffer);

#ifndef NO_HASH
                for (i64 k = 0; k < rem; ++k)
                {
                    tpBuffer[k] = tpBuffer[k] ^ mAesFixedKey.ecbEncBlock(tpBuffer[k]);
                }
#endif

                memcpy(messages.data() + numBlocks * 128, tpBuffer.data(), rem * sizeof(block));
            }

            if (index == 0)
                setTimePoint("recver.expand.transposeXor");

        };


        std::vector<std::thread> thrds(threads - 1);
        for (u64 i = 0; i < thrds.size(); ++i)
            thrds[i] = std::thread(routine, i);

        routine(thrds.size());

        //auto totals = counts.back();
        for (u64 i = 0; i < thrds.size(); ++i)
        {
            thrds[i].join();
            //for (u64 j = 0; j < totals.size(); ++j)
            //{

            //	totals[j] += counts[i][j];
            //}
        }
        //		for (u64 i = 0; i < counts.size(); ++i)
        //			lout << "count[" << i << "] " << counts[i][0] << " " << counts[i][1] << " " << counts[i][2] << " " << counts[i][3] << std::endl;

        //		lout << "total " << totals[0] << " " << totals[1] << " " << totals[2] << " " << totals[3] << std::endl;
    }


}
#endif