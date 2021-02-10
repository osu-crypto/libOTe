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
#include <libOTe/Tools/LDPC/LdpcSampler.h>
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

    bool isPrime(u64 n)
    {
        PRNG prng(ZeroBlock);
        return isPrime(n, prng);
    }


    u64 nextPrime(u64 n)
    {
        PRNG prng(ZeroBlock);

        while (isPrime(n, prng) == false)
            ++n;
        return n;
    }

    u64 getPartitions(u64 scaler, u64 p, u64 secParam);

    void SilentOtExtReceiver::setSlientBaseOts(span<block> recvBaseOts)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure(...) must be called first.");

        if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
            throw std::runtime_error("wrong number of silent base OTs");



        mGen.setBase(recvBaseOts);
        mGen.getPoints(mS, getPprfFormat());
    }

    void SilentOtExtReceiver::genBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        setTimePoint("recver.gen.start");
        mIknpRecver.genBaseOts(prng, chl);
    }


    void SilentOtExtReceiver::genSilentBaseOts(
        PRNG& prng,
        Channel& chl)
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");

        BitVector choice = sampleBaseChoiceBits(prng);
        std::vector<block> msg(choice.size());

        // If we have IKNP base OTs, use them
        // to extend to get the silent base OTs.
        if (mIknpRecver.hasBaseOts())
        {
            mIknpRecver.receive(choice, msg, prng, chl);
        }
        else
        {
            // otherwise just generate the silent 
            // base OTs directly.
            DefaultBaseOT base;
            base.receive(choice, msg, prng, chl, mNumThreads);
            setTimePoint("recver.gen.baseOT");
        }

        mGen.setBase(msg);
        mGen.getPoints(mS, getPprfFormat());

        for (u64 i = 0; i < mS.size(); ++i)
        {
            if (mS[i] >= mN2)
            {
                for (u64 j = i; j < mS.size(); ++j)
                {
                    std::cout << Color::Red << "bad " << j << " " << mS[j] << " / " << mN2 << std::endl << Color::Default;
                    std::terminate();
                }
            }
        }

        setTimePoint("recver.gen.done");
    };

    void SilentOtExtReceiver::genBase(
        u64 n,
        Channel& chl,
        PRNG& prng,
        u64 scaler,
        u64 secParam,
        SilentBaseType basetype,
        u64 threads)
    {
        switch (basetype)
        {
            //case SilentBaseType::None:
            //{
            //    std::cout << Color::Red << "warning, insecure " LOCATION << std::endl << Color::Default;
            //    configure(n, scaler, secParam, threads);
            //    BitVector choices = sampleBaseChoiceBits(prng);
            //    std::vector<block> msg(choices.size());
            //    //PRNG prngz(ZeroBlock);
            //    //auto ss = lout << "recver:\n";
            //    for (u64 i = 0; i < msg.size(); ++i)
            //    {
            //        //std::array<block, 2> tt = prngz.get();
            //        msg[i] = toBlock(i, choices[i]);
            //    //    //ss << "msg[" << i << "]["<< int(choices[i])<<"] "
            //    //    //    << msg[i] << std::endl;
            //    }

            //    setSlientBaseOts(msg);
            //    break;
            //}
        case SilentBaseType::BaseExtend:
            // perform 128 normal base OTs
            genBaseOts(prng, chl);
        case SilentBaseType::Base:
            configure(n, scaler, secParam, threads);
            // do the silent specific OTs, either by extending
            // the exising base OTs or using a base OT protocol.
            genSilentBaseOts(prng, chl);
            break;
            //case SilentBaseType::Extend:
            //{
            //    std::cout << Color::Red << "warning, insecure " LOCATION << std::endl << Color::Default;
            //    std::vector<std::array<block, 2>> msg(gOtExtBaseOtCount);
            //    setBaseOts(msg, prng, chl);
            //    configure(n, scaler, secParam, threads);
            //    genSilentBaseOts(prng, chl);
            //    break;
            //}
        default:
            std::cout << "known switch " LOCATION << std::endl;
            std::terminate();
            break;
        }
    }

    u64 SilentOtExtReceiver::silentBaseOtCount() const
    {
        if (isConfigured() == false)
            throw std::runtime_error("configure must be called first");
        return mGen.baseOtCount();
    }

    void SilentOtExtReceiver::configure(
        u64 numOTs,
        u64 scaler,
        u64 secParam,
        u64 numThreads)
    {
        mNumThreads = numThreads;
        mScaler = scaler;
        u64 numPartitions;
        if (mMultType == MultType::ldpc)
        {
            assert(scaler == 2);
            auto mm = nextPrime(numOTs + 1) - 1;
            //auto mm = numOTs;// nextPrime(numOTs) - 1;
            u64 nn = mm * scaler;
            auto kk = nn - mm;

            u64 colWeight = 5;
            u64 diags = 5;
            u64 gap = 32;
            u64 gapWeight = 5;
            std::vector<u64> db{ 5,31 };
            PRNG pp(oc::ZeroBlock);
            
            if (mZpsDiagEncoder.cols() != nn)
            {
                setTimePoint("config.begin");
                mZpsDiagEncoder.mL.init(mm, colWeight);
                setTimePoint("config.Left");
                mZpsDiagEncoder.mR.init(mm, gap, gapWeight, db, true, pp);
                setTimePoint("config.Right");
                //auto mH = sampleTriangularBand(mm, nn, colWeight, gap, gapWeight, diags, 0, db, true, true, pp);
                //setTimePoint("config.sample");
                //mLdpcEncoder.init(std::move(mH), 0);
                //setTimePoint("config.init");
            }

            mP = 0;
            mN = kk;
            mN2 = nn;
            numPartitions = getPartitions(scaler, mN, secParam);

        }
        else
        {

            mP = nextPrime(numOTs);
            mN = roundUpTo(mP, 128);
            numPartitions = getPartitions(scaler, mP, secParam);
            mN2 = scaler * mN;
        }


        mS.resize(numPartitions);
        mSizePer = roundUpTo((mN2 + numPartitions - 1) / numPartitions, 8);

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


    void SilentOtExtReceiver::checkRT(span<Channel> chls, Matrix<block>& rT1)
    {

        Matrix<block> rT2(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
        chls[0].recv(rT2.data(), rT2.size());
        block delta;
        chls[0].recv(delta);

        for (u64 i = 0; i < rT1.size(); ++i)
            rT2(i) = rT2(i) ^ rT1(i);


        Matrix<block> R;

        if (mMultType == MultType::ldpc)
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

        if(failed)
            throw RTE_LOC;

        std::cout << "debug check ok" << std::endl;
        //for (u64 x = 0; x < rT.rows(); ++x)
        //{
        //    for (u64 y = 0; y < rT.cols(); ++y)
        //    {
        //        std::cout << rT(x, y) << " " << rT2(x, y) << " " << (rT(x,y) ^ rT2(x,y))<< std::endl;
        //    }
        //    std::cout << std::endl;
        //}
        setTimePoint("recver.expand.checkRT");

    }

    void SilentOtExtReceiver::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& chl)
    {
        BitVector randChoice;
        silentReceive(randChoice, messages, prng, { &chl,1 });
        randChoice ^= choices;
        chl.asyncSend(std::move(randChoice));
    }

    void SilentOtExtReceiver::silentReceive(
        BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& chl)
    {
        silentReceive(choices, messages, prng, { &chl,1 });
    }

    void SilentOtExtReceiver::silentReceive(
        BitVector& choices,
        span<block> messages,
        PRNG& prng,
        span<Channel> chls)
    {
        if (isConfigured() == false)
        {
            // first generate 128 normal base OTs
            configure(messages.size(), 2, 128, chls.size());
        }

        if (static_cast<u64>(messages.size()) > mN)
            throw std::invalid_argument("messages.size() > n");

        if (mGen.hasBaseOts() == false)
        {
            // make sure we have IKNP base OTs.
            if (mIknpRecver.hasBaseOts() == false)
                genBaseOts(prng, chls[0]);

            genSilentBaseOts(prng, chls[0]);
        }

        setTimePoint("recver.expand.start");

        // column major matrix. mN2 columns and 1 row of 128 bits (128 bit rows)

        // do the compression to get the final OTs.
        switch (mMultType)
        {
        case MultType::Naive:
        case MultType::QuasiCyclic:

            rT.resize(128, mN2 / 128, AllocType::Uninitialized);

            // locally expand the seeds.
            mSum = mGen.expand(chls, prng, rT, PprfOutputFormat::InterleavedTransposed, false);
            setTimePoint("recver.expand.pprf_transpose");

            if (mDebug)
            {
                checkRT(chls, rT);
            }

            if (mMultType == MultType::Naive)
                randMulNaive(rT, messages);
            else
                randMulQuasiCyclic(rT, messages, choices, mNumThreads);


            break;
        case MultType::ldpc:
        {

            auto size = mGen.mDomain * mGen.mPntCount;
            assert(size >= mN2);
            rT.resize(size, 1, AllocType::Uninitialized);

            mSum = mGen.expand(chls, prng, rT, PprfOutputFormat::Interleaved, false);
            setTimePoint("recver.expand.pprf_transpose");

            if (mDebug)
            {
                checkRT(chls, rT);

            }

            ldpcMult(rT, messages, choices);
        }
            break;
        default:
            break;
        }

        clear();
    }


    void SilentOtExtReceiver::randMulNaive(Matrix<block>& rT, span<block>& messages)
    {
        std::vector<block> mtxColumn(rT.cols());
        PRNG pubPrng(ZeroBlock);

        for (i64 i = 0; i < messages.size(); ++i)
        {
            block& m = messages[i];
            BitIterator iter((u8*)&m, 0);
            mulRand(pubPrng, mtxColumn, rT, iter);
        }
        setTimePoint("recver.expand.mul");
    }

    void SilentOtExtReceiver::ldpcMult(Matrix<block>& rT, span<block>& messages, BitVector& choices)
    {

        assert(rT.rows() >= mN2);
        assert(rT.cols() == 1);

        rT.resize(mN2, 1);

        setTimePoint("recver.expand.ldpc.mult");
        bool seperate = false;
        if (seperate)

        {

            if (mLdpcEncoder.mH.rows())
                mLdpcEncoder.cirTransEncode(span<block>(rT));
            else
                mZpsDiagEncoder.cirTransEncode(span<block>(rT));
            setTimePoint("recver.expand.ldpc.cirTransEncode");
            std::memcpy(messages.data(), rT.data(), messages.size() * sizeof(block));

            setTimePoint("recver.expand.ldpc.mCopy");

            std::vector<u8> cc(rT.size());
            std::vector<u64> points(mGen.mPntCount);
            mGen.getPoints(points, getPprfFormat());
            for (auto p : points)
            {
                cc[p] = 1;
            }

            if (mLdpcEncoder.mH.rows())
                mLdpcEncoder.cirTransEncode<u8>(cc);
            else
                mZpsDiagEncoder.cirTransEncode<u8>(cc);
            setTimePoint("recver.expand.ldpc.cirTransEncodeBits");

            choices.resize(messages.size());
            auto iter = choices.begin();
            for (u64 i = 0; i < messages.size(); ++i)
            {
                *iter = cc[i];
                ++iter;
            }
            setTimePoint("recver.expand.ldpc.bitCopy");
        }
        else
        {
            block mask = OneBlock ^ AllOneBlock;
            for (u64 i = 0; i < rT.size(); ++i)
            {
                rT(i) = rT(i) & mask;
            }
            std::vector<u64> points(mGen.mPntCount);
            mGen.getPoints(points, getPprfFormat());
            for (auto p : points)
            {
                rT(p) = rT(p) | OneBlock;
            }
            setTimePoint("recver.expand.ldpc.mask");

            if (mLdpcEncoder.mH.rows())
                mLdpcEncoder.cirTransEncode(span<block>(rT));
            else
                mZpsDiagEncoder.cirTransEncode(span<block>(rT));
            setTimePoint("recver.expand.ldpc.cirTransEncode");
            //std::memcpy(messages.data(), rT.data(), messages.size() * sizeof(block));
            choices.resize(messages.size());
            auto iter = choices.begin();
            for (u64 i = 0; i < messages.size(); ++i)
            {
                messages[i] = rT(i) & mask;
                //*iter = _mm_testc_si128(rT(i), OneBlock);
                *iter = (rT(i) & OneBlock) == OneBlock;
                ++iter;
            }




            setTimePoint("recver.expand.ldpc.mCopy");
        }


        std::array<block, 8> hashBuffer;
        auto nn = messages.size() / 8 * 8;
        auto rem = messages.size() - nn;
        auto iter = messages.data();
        auto end = iter + nn;
        for (; iter != end; iter += 8)
        {
            mAesFixedKey.ecbEnc8Blocks(iter, hashBuffer.data());

            iter[0] = iter[0] ^ hashBuffer[0];
            iter[1] = iter[1] ^ hashBuffer[1];
            iter[2] = iter[2] ^ hashBuffer[2];
            iter[3] = iter[3] ^ hashBuffer[3];
            iter[4] = iter[4] ^ hashBuffer[4];
            iter[5] = iter[5] ^ hashBuffer[5];
            iter[6] = iter[6] ^ hashBuffer[6];
            iter[7] = iter[7] ^ hashBuffer[7];
        }

        for (u64 i = 0; i < rem; ++i, ++iter)
        {
            auto h = mAesFixedKey.ecbEncBlock(*iter);
            *iter = *iter ^ h;
        }
        setTimePoint("recver.expand.ldpc.hash");

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

        setTimePoint("recver.expand.qc.Setup");

        auto routine = [&](u64 index)
        {

            if (index == 0)
                setTimePoint("recver.expand.qc.routine");

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
                setTimePoint("recver.expand.qc.mulAddReduce");


            brs[1].decrementWait();




            //MatrixView<block> view(messages.begin(), messages.end(), 1);
            //transpose(cModP1, view);
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

                transpose128(tpBuffer);

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

                transpose128(tpBuffer);

#ifndef NO_HASH
                for (i64 k = 0; k < rem; ++k)
                {
                    tpBuffer[k] = tpBuffer[k] ^ mAesFixedKey.ecbEncBlock(tpBuffer[k]);
                }
#endif

                memcpy(messages.data() + numBlocks * 128, tpBuffer.data(), rem * sizeof(block));
            }

            if (index == 0)
                setTimePoint("recver.expand.qc.transposeXor");

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

    void SilentOtExtReceiver::clear()
    {
        mN = 0;
        mGen.clear();
    }


}
#endif