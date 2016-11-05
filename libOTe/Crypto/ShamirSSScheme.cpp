#include "ShamirSSScheme.h"   

#include <iostream>   
using namespace std;
using namespace NTL;
//#include "NTL/ZZ_p.h"
#include "NTL/GF2EX.h" 
#include "NTL/GF2XFactoring.h"
//#include "Common/Log.h
#include "Common/Log.h"
#include <thread>



namespace osuCrypto
{



    ShamirSSScheme::ShamirSSScheme()
    {
        NTL::GF2X& P = mPrime;
        NTL::BuildIrred(P, 127);
        NTL::GF2E::init(P);
    }

    block ShamirSSScheme::init(u64 n, u64 k)
    {
        auto sec = initGF2X(n, k);
        block ret;
        NTL::BytesFromGF2X((u8*)&ret, sec, sizeof(block));
        //return ret;


        TODO("remove this hack, get NTL thread safe");
        return ZeroBlock;
    }


    NTL::GF2X ShamirSSScheme::initGF2X(u64 n, u64 k)
    {
        m_nN = (n);
        m_nK = (k);
        m_vPolynom.resize(k);
        for (u32 i = 0; i < m_nK; i++)
            NTL::random(m_vPolynom[i], 127);

        return m_vPolynom[0];
    }

    ShamirSSScheme::~ShamirSSScheme(void)
    {
    }


    void ShamirSSScheme::computeShares(ArrayView<block> shares, u64 threadCount)
    {
        if (shares.size() != m_nN)
            throw std::runtime_error(LOCATION);

        //Timer timer;
        //timer.setTimePoint("computeShareStart");

        return;

        if (threadCount == 0)
            threadCount = std::thread::hardware_concurrency();

        std::vector<std::thread> thrds(threadCount - 1);

        u8 one = 1;
        auto routine = [&](u64 t, u64 total)
        {
            u64 n = m_nN;
            // compute the region of the OTs im going to do
            u64 start = std::min(t *     n / total, n);
            u64 end = std::min((t + 1) * n / total, n);
            GF2X aux, share;

            //Log::out << t << "  " << start << "  " << end << Log::endl;

            TODO("remove this and actual implement FFT??");
            u64 ln = (u64)std::log2(m_nK);


            for (u32 i = (u32)start; (u64)i < end; i++)
            {
                share = 0;

                auto ii = i + 1;
                GF2X xi; 
                GF2XFromBytes(xi, (u8*)&ii, sizeof(ii));
                GF2XFromBytes(aux, (u8*)&one, sizeof(one));

                for (u32 j = 0; (u64)j < ln; j++)
                {

                    NTL::MulMod(aux, aux, xi, mPrime);
                    //aux = aux * xi;
                    //NTL::PowerMod(aux, xi, j, mPrime);
                    
                    share = (share + m_vPolynom[j] * aux) % mPrime;
                }

                NTL::BytesFromGF2X((u8*)&shares[i], share, sizeof(block));

                //Log::out << "share[" << i << "] " << share << Log::endl;

            }
        };

        //for (u64 i = 0; i < thrds.size(); ++i)
        //{
        //    thrds[i] = std::thread([&,i]() 
        //    {
        //        routine(i + 1, threadCount); 
        //    });
        //}

        routine(0, 1);

        //for (u64 i = 0; i < thrds.size(); ++i)
        //    thrds[i].join();



        //timer.setTimePoint("computeShareEnd");

        //Log::out << shares.size() << " shares computed ("<< m_nK * m_nN << " evals) in:" << Log::endl << timer << Log::endl;
        
    }

    void ShamirSSScheme::computeShares(ArrayView<NTL::GF2X> shares)
    {
        if (shares.size() != m_nN)
            throw std::runtime_error(LOCATION);

        GF2X aux, share;
        for (u32 i = 0; i < m_nN; i++)
        {
            share = 0;

            //GF2X xi = u32ToGf2X(i + 1);
            auto ii = i + 1;
            GF2X xi;// = u32ToGf2X(i + 1);
            GF2XFromBytes(xi, (u8*)&ii, sizeof(ii));


            for (u32 j = 0; j < m_nK; j++)
            {


                NTL::PowerMod(aux, xi, j, mPrime);
                
                share = (share + m_vPolynom[j] * aux) % mPrime;
            }

            shares[i] = share;

            //Log::out << "share[" << i << "] " << share << Log::endl;
        }
    }

    block ShamirSSScheme::reconstruct(const std::vector<u32>& xInts, const std::vector<block> &ys)
    {
        if (xInts.size() != ys.size())
        {
            cout << "People nr and secret nr are  not equal\n";
            throw std::runtime_error(LOCATION);
        }
        u64 k = xInts.size();

        std::vector<GF2X> x(xInts.size());
        for (u32 i = 0; i < k; i++)
        {
            auto xx = xInts[i] + 1;
            GF2XFromBytes(x[i], (u8*)&xx, sizeof(xx));
        }

        // we want to compute 
        //       P(x) = SUM_{i=1}^k   P_i(x)
        // where
        //     P_i(x)= y_i PROD_{j=1, j!=i}^k (x - x_j) / (x_i - x_j) 
        //    
        // Since we want to know P(x=0) and are in GF(2), this becomes
        //
        //     P_i(x)= y_i PROD_{j=1, j!=i}^k  x_j / (x_i - x_j) 

        TODO("remove this, implement FFT");
        u64 lnk = (u64) std::log2(k);


        GF2X secret, diff, prod, y, inv, quotent;
        for (u32 i = 0; i < k; i++)
        {
            prod = 1;
            for (u32 j = 0; j < lnk; j++)
            {
                if (x[j] != x[i])
                {
                    diff = x[j] - x[i];
                    NTL::InvMod(inv, diff, mPrime);
                    NTL::MulMod(quotent, x[j], inv, mPrime);
                    MulMod(prod, prod, quotent, mPrime);
                }
            }

            GF2XFromBytes(y, (u8*)&ys[i], sizeof(block));

            secret = (secret + y * prod) % mPrime;
        }

        TODO("remove this hack, get NTL thread safe");
        return ZeroBlock;

        //block ret = ZeroBlock;
        //NTL::BytesFromGF2X((u8*)&ret, secret, sizeof(block));
        //return ret;

    }

    NTL::GF2X ShamirSSScheme::reconstruct(const std::vector<u32>& xInts, const std::vector<NTL::GF2X> &ys)
    {
        //u32 peopleNr = (u32)vPeople.size();
        if (xInts.size() != ys.size())
        {
            cout << "People nr and secret nr are  not equal\n";
            throw std::runtime_error(LOCATION);
        }
        u64 k = xInts.size();

        // we want to compute 
        //       P(x) = SUM_{i=1}^k   P_i(x)
        // where
        //     P_i(x)= y_i PROD_{j=1, j!=i}^k (x - x_j) / (x_i - x_j) 
        //    
        // Since we want to know P(x=0) and are in GF(2), this becomes
        //
        //     P_i(x)= y_i PROD_{j=1, j!=i}^k  x_j / (x_i - x_j) 

        


        std::vector<GF2X> x(xInts.size());
        for (u32 i = 0; i < k; i++)
        {
            //x[i] = u32ToGf2X(xInts[i] + 1);
            auto xx = xInts[i] + 1;

            GF2XFromBytes(x[i], (u8*)&xx, sizeof(xx));

            //Log::out << "x[" << i << "] = " << x[i] << "    ( = " << xInts[i] + 1 << ")' "  << Log::endl;

        }

        
        GF2X secret, diff, prod, y, inv, quotent;
        for (u32 i = 0; i < k; i++)
        {
            prod = 1;
            for (u32 j = 0; j < k; j++)
            {
                if (x[j] != x[i])
                {
                    diff = x[j] - x[i];


                    NTL::InvMod(inv, diff, mPrime);
                    NTL::MulMod(quotent,x[j], inv, mPrime);

                    //Log::out << "1 ?= " << (diff * inv) % mPrime << " = " << inv << " * " << diff <</* "    (" <<x[j] << ", " << x[i] <<")" << */Log::endl;


                    MulMod(prod, prod, quotent, mPrime);
                }
            }

            //ZZ temp;
            //ZZFromBytes(temp, (u8*)&ys[i], sizeof(block));

            y = ys[i];

              
            secret = (secret + y * prod) % mPrime;
        }

        //Log::out << "secret " << secret << Log::endl;

        //return true;

        //block ret = ZeroBlock;
        //BytesFromZZ((u8*)&ret, conv<ZZ>(secret), sizeof(block));
        return secret;

    }

    //NTL::GF2X ShamirSSScheme::u32ToGf2X(u32 xx)
    //{
    //    NTL::GF2X x;

    //    u32 j = 0;
    //    while (xx)
    //    {

    //        SetCoeff(x, j, xx & 1);

    //        ++j;

    //        xx >>= 1;
    //    }

    //    return x;
    //}



}