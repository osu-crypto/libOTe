#include "libOTe/TwoChooseOne/BgciksOtExtReceiver.h"
#include "libOTe/TwoChooseOne/BgciksOtExtSender.h"
#include "libOTe/DPF/BgiGenerator.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <bitpolymul2/bitpolymul.h>

//#include <bits/stdc++.h> 

namespace osuCrypto
{

    //using namespace std;

    // Utility function to do modular exponentiation. 
    // It returns (x^y) % p 
    int power(u64 x, u64 y, u64 p)
    {
        u64 res = 1;      // Initialize result 
        x = x % p;  // Update x if it is more than or 
                    // equal to p 
        while (y > 0)
        {
            // If y is odd, multiply x with result 
            if (y & 1)
                res = (res*x) % p;

            // y must be even now 
            y = y >> 1; // y = y/2 
            x = (x*x) % p;
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


    // The number of DPF points that will be used.
    u64 numPartitions = 8;

    // defines n' = nScaler * n
    u64 nScaler = 4;

    void BgciksOtExtReceiver::genBase(u64 n, Channel & chl)
    {
        setTimePoint("recver.gen.start");

        mP = nextPrime(n);
        mN = roundUpTo(mP, 128);
        mN2 = nScaler * mN;


        mSizePer = (mN2 + numPartitions - 1) / numPartitions;
        auto groupSize = 8;
        auto depth = log2ceil((mSizePer + groupSize - 1) / groupSize) + 1;

        std::vector<std::vector<block>>
            k1(numPartitions), g1(numPartitions),
            k2(numPartitions), g2(numPartitions);

        PRNG prng(toBlock(n));
        mS.resize(numPartitions);
        std::vector<u64> S(numPartitions);
        mDelta = prng.get();


        for (u64 i = 0; i < numPartitions; ++i)
        {
            S[i] = prng.get<u64>() % mSizePer;

            mS[i] = S[i] * numPartitions + i;

            k1[i].resize(depth);
            k2[i].resize(depth);
            g1[i].resize(groupSize);
            g2[i].resize(groupSize);

            BgiGenerator::keyGen(S[i], mDelta, toBlock(i), k1[i], g1[i], k2[i], g2[i]);
        }

        mGen.init(k2, g2);
        setTimePoint("recver.gen.done");

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



    void BgciksOtExtReceiver::receive(
        span<block> messages,
        BitVector& choices,
        PRNG & prng,
        Channel & chl)
    {
        setTimePoint("recver.expand.start");

        // column major matric. mN2 columns and 1 row of 128 bits (128 bit rows)
        std::vector<block> r(mN2);

        for (u64 i = 0; i < r.size();)
        {
            auto blocks = mGen.yeild();
            auto min = std::min<u64>(r.size() - i, blocks.size());
            memcpy(r.data() + i, blocks.data(), min * sizeof(block));

            i += min;
        }
        setTimePoint("recver.expand.dpf");

        //auto rr = convert(r);
        //auto rMtx = transpose(rr);
        //Matrix<u8> mtx(mN2, mN);
        {
            std::vector<block>r2(mN2);
            chl.recv(r2);
            for (u64 i = 0; i < r2.size(); ++i)
            {
                bool ss = std::find(mS.begin(), mS.end(), i) != mS.end();
                auto v0 = r[i] ^ r2[i];
                auto v1 = (ss ? mDelta : ZeroBlock);
                if(neq(v0,v1))
                    std::cout << i << " " << (v0) << " " << v1 << std::endl;
            }
        }

        if (mN2 % 128) throw RTE_LOC;
        Matrix<block> rT(128, mN2 / 128, AllocType::Uninitialized);
        sse_transpose(r, rT);
        setTimePoint("recver.expand.transpose");

        //for (u64 i = 0; i < r.size(); i += 128)
        //{
        //    std::array<block, 128>& view = *(std::array<block, 128>*)(r.data() + i);
        //    sse_transpose128(view);
        //}

        auto type = MultType::QuasiCyclic;

        switch (type)
        {
        case osuCrypto::MultType::Naive:
            randMulNaive(rT, messages);
            break;
        case osuCrypto::MultType::QuasiCyclic:
            randMulQuasiCyclic(rT, messages, choices);
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


    void BgciksOtExtReceiver::randMulNaive(Matrix<block> &rT, span<block> &messages)
    {
        std::vector<block> mtxColumn(rT.cols());
        PRNG pubPrng(ZeroBlock);

        for (u64 i = 0; i < messages.size(); ++i)
        {
            block& m = messages[i];
            BitIterator iter((u8*)&m, 0);
            mulRand(pubPrng, mtxColumn, rT, iter);
        }
        setTimePoint("recver.expand.mul");
    }

    void BgciksOtExtReceiver::randMulQuasiCyclic(Matrix<block>& rT, span<block>& messages, BitVector& choices)
    {
        auto nBlocks = mN / 128;
        auto nBytes = mN / 8;
        auto n2Blocks = mN2 / 128;
        auto n64 = i64(nBlocks * 2);

        const u64 rows(128);
        if (rT.rows() != rows)
            throw RTE_LOC;
        if (rT.cols() != n2Blocks)
            throw RTE_LOC;


        std::vector<block> a(nBlocks);
        u64* a64ptr = (u64*)a.data();

        BitVector sb(mN2);
        for (u64 i = 0; i < mS.size(); ++i)
        {
            sb[mS[i]] = 1;
        }


        bpm::FFTPoly sPoly;
        bpm::FFTPoly aPoly;
        bpm::FFTPoly bPoly;

        PRNG pubPrng(ZeroBlock);

        //Matrix<block> c(rows, 2 * nBlocks, AllocType::Uninitialized);

        std::vector<bpm::FFTPoly> c(rows);

        for (u64 s = 0; s < nScaler; ++s)
        {
            pubPrng.get(a.data(), a.size());
            aPoly.encode({ a64ptr, n64 });

            for (u64 i = 0; i < rows; ++i)
            {
                //auto ci = c[i];

                //u64* c64ptr = (u64*)((s == 0)? ci.data() : temp.data());
                u64* b64ptr = (u64*)(rT[i].data() + s * nBlocks);

                //bitpolymul_2_128(c64ptr, a64ptr, b64ptr, nBlocks * 2);
                bPoly.encode({ b64ptr, n64 });

                if (s)
                {
                    bPoly.multEq(aPoly);
                    c[i].addEq(bPoly);
                }
                else
                {
                    c[i].mult(aPoly, bPoly);
                }
            }

            u64* s64ptr = (u64*)(sb.data() + s * nBytes);
            bPoly.encode({ s64ptr, n64 });

            if (s)
            {
                bPoly.multEq(aPoly);
                sPoly.addEq(bPoly);
            }
            else
            {
                sPoly.mult(aPoly, bPoly);
            }
        }

        setTimePoint("recver.expand.mul");

        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);
        std::vector<u64> temp(c[0].mPoly.size() + 2);
        bpm::FFTPoly::DecodeCache cache;

        u64* t64Ptr = (u64*)temp.data();
        auto t128Ptr = (block*)temp.data();
        for (u64 i = 0; i < rows; ++i)
        {
            // decode c[i] and store it at t64Ptr
            c[i].decode({ t64Ptr, 2 * n64 }, cache, true);

            // reduce s[i] mod (x^p - 1) and store it at cModP1[i]
            modp(cModP1[i], { t128Ptr, n64 }, mP);
            //memcpy(cModP1[i].data(), t64Ptr, nBlocks * sizeof(block));
        }

        choices.resize(0);
        choices.resize(mN);
        sPoly.decode({ t64Ptr, 2 * n64 }, cache, true);
        modp({ (block*)choices.data(), i64(nBlocks) }, { t128Ptr, n64 }, mP);
        //memcpy((block*)choices.data(), t64Ptr, nBlocks * sizeof(block));

        setTimePoint("recver.expand.decodeReduce");

        MatrixView<block> view(messages.begin(), messages.end(), 1);
        sse_transpose(cModP1, view);
        setTimePoint("recver.expand.transposeXor");

    }
}
//Matrix<u8> convert(span<block> b)
//{
//    Matrix<u8> ret(b.size(), 128);
//    BitIterator iter((u8*)b.data(), 0);

//    for (u64 i = 0; i < ret.size(); ++i)
//    {
//        ret(i) = *iter++;
//    }
//    return ret;
//}


//Matrix<u8> transpose(const Matrix<u8>& v)
//{
//    Matrix<u8> ret(v.cols(), v.rows());

//    for (u64 i = 0; i < v.rows(); ++i)
//    {
//        for (u64 j = 0; j < v.cols(); ++j)
//        {
//            ret(j, i) = v(i, j);
//        }
//    }
//    return ret;
//}


//void convertCol(Matrix<u8>& dest, u64 j, span<block> b)
//{
//    BitIterator iter((u8*)b.data(), 0);
//    for (u64 i = 0; i < dest.rows(); ++i)
//    {
//        dest(i, j) = *iter++;
//    }
//}



//Matrix<u8> mul(const Matrix<u8>& l, const Matrix<u8>& r)
//{
//    if (l.cols() != r.rows())
//        throw RTE_LOC;

//    Matrix<u8> ret(l.rows(), r.cols());

//    for (u64 i = 0; i < ret.rows(); ++i)
//    {
//        for (u64 j = 0; j < ret.cols(); ++j)
//        {
//            auto& x = ret(i, j);
//            x = 0;
//            for (u64 k = 0; k < r.rows(); ++k)
//            {
//                x ^= l(i, k) & r(k, j);
//            }
//        }

//    }
//    return ret;
//}
