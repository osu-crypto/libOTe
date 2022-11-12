


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
            //T* xx = x.data();
            //u32* pp = mPerm.data();

            //for (u64 i = 0; i < n; ++i)
            //    std::swap(xx[i], xx[pp[i]]);

            for (u64 i = 0; i < n; ++i)
                std::swap(x.data()[i], x.data()[mPerm.data()[i]]);
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
            auto xx = x.data() + offset;
            for (u64 i = 0; i < n; ++i)
                std::swap(xx[i * step], xx[i * step]);
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