


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

        void init(u64 n, PRNG& prng)
        {
            mPerm.resize(n);
            std::iota(mPerm.begin(), mPerm.end(), 0);
            for (u64 i = 0; i < n; ++i)
            {
                auto j = prng.get<u32>() % (n - i) + i;
                mPerm[i] = j;
                //std::swap(mPerm[i], mPerm[j]);
            }
        }


        template<typename T> 
        __declspec(noinline) void apply(span<T> x)
        {
            auto n = mPerm.size();
            if (x.size() != n)
                throw RTE_LOC;
            T* __restrict xx = x.data();
            u32* __restrict  pp = mPerm.data();

            //for (u64 i = 0; i < n; ++i)
            //    std::swap(xx[i], xx[pp[i]]);
            {

                auto& x0 = xx[0];
                auto& x1 = xx[pp[0]];

                auto t = x0;
                x0 = x1;
                x1 = t;
            }

            for (u64 i = 1; i < n; ++i)
            {
                auto jPre = pp[i + 128];
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
        __declspec(noinline) void applyStep(span<T> x, u64 step, u64 offset)
        {
            auto n = mPerm.size();
            if (x.size() < (n-1) * step + offset)
            {
                throw RTE_LOC;
            }



            // permute together the positions
            // x[step * 0 + i]
            // x[step * 1 + i]
            // ...
            // x[step * (n-1) + i]
            T*__restrict xx = x.data() + offset;
            u32* __restrict pp = mPerm.data();
            for (u64 i = 0; i < n; ++i)
            {
                auto jPre = pp[i+ 128] * step;
                _mm_prefetch((char*)(&xx[jPre]), _MM_HINT_T0);
                auto j = pp[i] * step;

                std::swap(xx[i * step], xx[j]);
            }
        }
    };

    class SqrtPerm: public TimerAdapter
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
                p.init(m, prng);

            mBinPerm.init(b, prng);

        }


        template<typename T>
        __declspec(noinline) void apply(span<T> x)
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