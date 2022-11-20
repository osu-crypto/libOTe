


#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>

namespace osuCrypto
{

    class Perm
    {
    public:
        AlignedUnVector<u32> mPerm;

        void init(u64 n, PRNG& prng, bool swap = false)
        {
            mPerm.resize(n);
            std::iota(mPerm.begin(), mPerm.end(), 0);

            if (swap)
            {

                for (u64 i = 0; i < n; ++i)
                {
                    auto j = prng.get<u32>() % (n - i) + i;
                    std::swap(mPerm.data()[i], mPerm.data()[j]);
                }

            }
            else
            {

                for (u64 i = 0; i < n; ++i)
                {
                    auto j = prng.get<u32>() % (n - i) + i;
                    mPerm.data()[i] = j;
                    //std::swap(mPerm[i], mPerm[j]);
                }
            }
        }


        template<typename T>
        void apply(span<T> x)
        {
            auto n = mPerm.size();
            if (x.size() != n)
                throw RTE_LOC;
            T* __restrict xx = x.data();
            u32* __restrict  pp = mPerm.data();

            //for (u64 i = 0; i < n; ++i)
            //    std::swap(xx[i], xx[pp[i]]);
            //{

            //    auto& x0 = xx[0];
            //    auto& x1 = xx[pp[0]];

            //    auto t = x0;
            //    x0 = x1;
            //    x1 = t;
            //}
            u64 i = 0;
            //for (; i < n; i+=8)
            //{

            //    //for (u64 j = 0; j < 8; ++j, )
            //    //{
            //    _mm_prefetch((char*)(&xx[pp[i + 8]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 9]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 10]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 11]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 12]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 13]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 14]]), _MM_HINT_T1);
            //    _mm_prefetch((char*)(&xx[pp[i + 15]]), _MM_HINT_T1);

            //        auto& x0 = xx[i + 0];
            //        auto& x1 = xx[i + 1];
            //        auto& x2 = xx[i + 2];
            //        auto& x3 = xx[i + 3];
            //        auto& x4 = xx[i + 4];
            //        auto& x5 = xx[i + 5];
            //        auto& x6 = xx[i + 6];
            //        auto& x7 = xx[i + 7];

            //        auto& y0 = xx[pp[i + 0]];
            //        auto& y1 = xx[pp[i + 1]];
            //        auto& y2 = xx[pp[i + 2]];
            //        auto& y3 = xx[pp[i + 3]];
            //        auto& y4 = xx[pp[i + 4]];
            //        auto& y5 = xx[pp[i + 5]];
            //        auto& y6 = xx[pp[i + 6]];
            //        auto& y7 = xx[pp[i + 7]];

            //        auto t0 = x0;
            //        auto t1 = x1;
            //        auto t2 = x2;
            //        auto t3 = x3;
            //        auto t4 = x4;
            //        auto t5 = x5;
            //        auto t6 = x6;
            //        auto t7 = x7;

            //        x0 = y0;
            //        x1 = y1;
            //        x2 = y2;
            //        x3 = y3;
            //        x4 = y4;
            //        x5 = y5;
            //        x6 = y6;
            //        x7 = y7;
            //        
            //        y0 = t0;
            //        y1 = t1;
            //        y2 = t2;
            //        y3 = t3;
            //        y4 = t4;
            //        y5 = t5;
            //        y6 = t6;
            //        y7 = t7;
            //}

            for (; i < n; ++i)
            {
                auto jPre = pp[i + 16];
                _mm_prefetch((char*)(&xx[jPre]), _MM_HINT_T0);

                auto& x0 = xx[i];
                auto& x1 = xx[pp[i]];

                auto t = x0;
                x0 = x1;//^ xx[i - 1];
                x1 = t;
                //std::swap(x0, x1);
            }
        }

        template<typename T>
        void applyStep(span<T> x, u64 step, u64 offset)
        {
            auto n = mPerm.size();
            if (x.size() < (n - 1) * step + offset)
            {
                throw RTE_LOC;
            }



            // permute together the positions
            // x[step * 0 + i]
            // x[step * 1 + i]
            // ...
            // x[step * (n-1) + i]
            T* __restrict xx = x.data() + offset;
            u32* __restrict pp = mPerm.data();
            for (u64 i = 0; i < n; ++i)
            {
                auto jPre = pp[i + 128] * step;
                _mm_prefetch((char*)(&xx[jPre]), _MM_HINT_T0);
                auto j = pp[i] * step;

                std::swap(xx[i * step], xx[j]);
            }
        }
    };

    class SqrtPerm : public TimerAdapter
    {
    public:
        std::vector<Perm> mPerms;
        Perm mBinPerm;

        void init(u64 n, u64 m, PRNG& prng)
        {
            u64 b = n / m;
            if (b * m != n)
            {
                //std::cout << n << " " << b << std::endl;
                throw RTE_LOC;
            }

            mPerms.resize(b);
            for (auto& p : mPerms)
                p.init(m, prng, false);

            mBinPerm.init(b, prng, false);

        }


        template<typename T>
        void apply(span<T> x)
        {
            auto b = mPerms.size();
            auto m = mPerms[0].mPerm.size();
            auto n = b * m;
            if (x.size() != n)
                throw RTE_LOC;

            for (u64 i = 0; i < b; ++i)
                mPerms[i].apply(x.subspan(i * m, m));

            setTimePoint("bPerm ");

            //for (u64 i = 0; i < m; ++i)
            //{
            //    // permute together the positions
            //    // x[m * 0 + i]
            //    // x[m * 1 + i]
            //    // ...
            //    // x[m * (b-1) + i]
            //    mBinPerm.applyStep(x, m, i);
            //}
            //setTimePoint("xPerm");

        }
    };


}