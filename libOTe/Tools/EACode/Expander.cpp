
#include "Expander.h"
#include "cryptoTools/Common/Range.h"

namespace osuCrypto
{
    template<typename T, u64 count>
    typename std::enable_if<count == 1, T>::type
        ExpanderCode::expandOne(const T* __restrict ee, detail::ExpanderModd& prng) const
    {
        auto r = prng.get();
        return ee[r];
    }

    template<typename T, typename T2, u64 count, bool Add>
    typename std::enable_if<count == 1>::type
        ExpanderCode::expandOne(
            const T* __restrict ee1,
            const T2* __restrict ee2,
            T* __restrict y1,
            T2* __restrict y2,
            detail::ExpanderModd& prng) const
    {
        auto r = prng.get();

        if (Add)
        {
            *y1 = *y1 ^ ee1[r];
            *y2 = *y2 ^ ee2[r];
        }
        else
        {

            *y1 = ee1[r];
            *y2 = ee2[r];
        }
    }


    template<typename T, u64 count>
    OC_FORCEINLINE typename std::enable_if<(count > 1), T>::type
        ExpanderCode::expandOne(const T* __restrict ee, detail::ExpanderModd& prng)const
    {
        if constexpr (count >= 8)
        {
            u64 rr[8];
            T w[8];
            rr[0] = prng.get();
            rr[1] = prng.get();
            rr[2] = prng.get();
            rr[3] = prng.get();
            rr[4] = prng.get();
            rr[5] = prng.get();
            rr[6] = prng.get();
            rr[7] = prng.get();

            w[0] = ee[rr[0]];
            w[1] = ee[rr[1]];
            w[2] = ee[rr[2]];
            w[3] = ee[rr[3]];
            w[4] = ee[rr[4]];
            w[5] = ee[rr[5]];
            w[6] = ee[rr[6]];
            w[7] = ee[rr[7]];

            auto ww =
                w[0] ^
                w[1] ^
                w[2] ^
                w[3] ^
                w[4] ^
                w[5] ^
                w[6] ^
                w[7];

            if constexpr (count > 8)
                ww = ww ^ expandOne<T, count - 8>(ee, prng);
            return ww;
        }
        else
        {

            auto r = prng.get();
            auto ww = expandOne<T, count - 1>(ee, prng);
            return ww ^ ee[r];
        }
    }


    template<typename T, typename T2, u64 count, bool Add>
    OC_FORCEINLINE typename std::enable_if<(count > 1)>::type
        ExpanderCode::expandOne(
            const T* __restrict ee1,
            const T2* __restrict ee2,
            T* __restrict y1,
            T2* __restrict y2,
            detail::ExpanderModd& prng)const
    {
        if constexpr (count >= 8)
        {
            u64 rr[8];
            T w1[8];
            T2 w2[8];
            rr[0] = prng.get();
            rr[1] = prng.get();
            rr[2] = prng.get();
            rr[3] = prng.get();
            rr[4] = prng.get();
            rr[5] = prng.get();
            rr[6] = prng.get();
            rr[7] = prng.get();

            w1[0] = ee1[rr[0]];
            w1[1] = ee1[rr[1]];
            w1[2] = ee1[rr[2]];
            w1[3] = ee1[rr[3]];
            w1[4] = ee1[rr[4]];
            w1[5] = ee1[rr[5]];
            w1[6] = ee1[rr[6]];
            w1[7] = ee1[rr[7]];

            w2[0] = ee2[rr[0]];
            w2[1] = ee2[rr[1]];
            w2[2] = ee2[rr[2]];
            w2[3] = ee2[rr[3]];
            w2[4] = ee2[rr[4]];
            w2[5] = ee2[rr[5]];
            w2[6] = ee2[rr[6]];
            w2[7] = ee2[rr[7]];

            auto ww1 =
                w1[0] ^
                w1[1] ^
                w1[2] ^
                w1[3] ^
                w1[4] ^
                w1[5] ^
                w1[6] ^
                w1[7];
            auto ww2 =
                w2[0] ^
                w2[1] ^
                w2[2] ^
                w2[3] ^
                w2[4] ^
                w2[5] ^
                w2[6] ^
                w2[7];

            if constexpr (count > 8)
            {
                T yy1;
                T2 yy2;
                expandOne<T, T2, count - 8, false>(ee1, ee2, &yy1, &yy2, prng);
                ww1 = ww1 ^ yy1;
                ww2 = ww2 ^ yy2;
            }

            if constexpr (Add)
            {
                *y1 = *y1 ^ ww1;
                *y2 = *y2 ^ ww2;
            }
            else
            {
                *y1 = ww1;
                *y2 = ww2;
            }

        }
        else
        {

            auto r = prng.get();
            if constexpr (Add)
            {
                auto w1 = ee1[r];
                auto w2 = ee2[r];
                expandOne<T, T2, count - 1, true>(ee1, ee2, y1, y2, prng);
                *y1 = *y1 ^ w1;
                *y2 = *y2 ^ w2;

            }
            else
            {

                T yy1;
                T2 yy2;
                expandOne<T, T2, count - 1, false>(ee1, ee2, &yy1, &yy2, prng);
                *y1 = ee1[r] ^ yy1;
                *y2 = ee2[r] ^ yy2;
            }
        }
    }



    template<typename T, bool Add>
    void ExpanderCode::expand(
        span<const T> e,
        span<T> w) const
    {
        assert(w.size() == mMessageSize);
        assert(e.size() == mCodeSize);
        detail::ExpanderModd prng(mSeed, mCodeSize);

        const T* __restrict  ee = e.data();
        T* __restrict  ww = w.data();

        auto main = mMessageSize / 8 * 8;
        u64 i = 0;

        for (; i < main; i += 8)
        {
#define CASE(I) \
                case I:\
                if constexpr(Add)\
                {\
                    ww[i + 0] = ww[i + 0] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 1] = ww[i + 1] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 2] = ww[i + 2] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 3] = ww[i + 3] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 4] = ww[i + 4] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 5] = ww[i + 5] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 6] = ww[i + 6] ^ expandOne<T, I>(ee, prng);\
                    ww[i + 7] = ww[i + 7] ^ expandOne<T, I>(ee, prng);\
                }\
                else\
                {\
                    ww[i + 0] = expandOne<T, I>(ee, prng);\
                    ww[i + 1] = expandOne<T, I>(ee, prng);\
                    ww[i + 2] = expandOne<T, I>(ee, prng);\
                    ww[i + 3] = expandOne<T, I>(ee, prng);\
                    ww[i + 4] = expandOne<T, I>(ee, prng);\
                    ww[i + 5] = expandOne<T, I>(ee, prng);\
                    ww[i + 6] = expandOne<T, I>(ee, prng);\
                    ww[i + 7] = expandOne<T, I>(ee, prng);\
                }\
                break

            switch (mExpanderWeight)
            {
                CASE(5);
                CASE(7);
                CASE(9);
                CASE(11);
                CASE(21);
                CASE(40);
            default:
                for (u64 jj = 0; jj < 8; ++jj)
                {
                    auto r = prng.get();
                    auto wv = ee[r];

                    for (auto j = 1ull; j < mExpanderWeight; ++j)
                    {
                        r = prng.get();
                        wv = wv ^ ee[r];
                    }
                    if constexpr (Add)
                        ww[i + jj] = ww[i + jj] ^ wv;
                    else
                        ww[i + jj] = wv;

                }
            }
#undef CASE
        }

        for (; i < mMessageSize; ++i)
        {
            auto wv = ee[prng.get()];
            for (auto j = 1ull; j < mExpanderWeight; ++j)
                wv = wv ^ ee[prng.get()];

            if constexpr (Add)
                ww[i] = ww[i] ^ wv;
            else
                ww[i] = wv;
        }
    }



    template<typename T, typename T2, bool Add>
    void ExpanderCode::expand(
        span<const T> e1,
        span<const T2> e2,
        span<T> w1,
        span<T2> w2
    ) const
    {
        assert(w1.size() == mMessageSize);
        assert(w2.size() == mMessageSize);
        assert(e1.size() == mCodeSize);
        assert(e2.size() == mCodeSize);
        detail::ExpanderModd prng(mSeed, mCodeSize);

        const T* __restrict  ee1 = e1.data();
        const T2* __restrict  ee2 = e2.data();
        T* __restrict  ww1 = w1.data();
        T2* __restrict  ww2 = w2.data();

        auto main = mMessageSize / 8 * 8;
        u64 i = 0;

        for (; i < main; i += 8)
        {
#define CASE(I) \
                case I:\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 0], &ww2[i + 0], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 1], &ww2[i + 1], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 2], &ww2[i + 2], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 3], &ww2[i + 3], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 4], &ww2[i + 4], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 5], &ww2[i + 5], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 6], &ww2[i + 6], prng);\
                expandOne<T, T2, I, Add>(ee1, ee2, &ww1[i + 7], &ww2[i + 7], prng);\
                break

            switch (mExpanderWeight)
            {
                CASE(5);
                CASE(7);
                CASE(9);
                CASE(11);
                CASE(21);
                CASE(40);
            default:
                for (u64 jj = 0; jj < 8; ++jj)
                {
                    auto r = prng.get();
                    auto wv1 = ee1[r];
                    auto wv2 = ee2[r];

                    for (auto j = 1ull; j < mExpanderWeight; ++j)
                    {
                        r = prng.get();
                        wv1 = wv1 ^ ee1[r];
                        wv2 = wv2 ^ ee2[r];
                    }
                    if constexpr (Add)
                    {
                        ww1[i + jj] = ww1[i + jj] ^ wv1;
                        ww2[i + jj] = ww2[i + jj] ^ wv2;
                    }
                    else
                    {

                        ww1[i + jj] = wv1;
                        ww2[i + jj] = wv2;
                    }
                }
            }
#undef CASE
        }

        for (; i < mMessageSize; ++i)
        {
            auto r = prng.get();
            auto wv1 = ee1[r];
            auto wv2 = ee2[r];
            for (auto j = 1ull; j < mExpanderWeight; ++j)
            {
                r = prng.get();
                wv1 = wv1 ^ ee1[r];
                wv2 = wv2 ^ ee2[r];

            }
            if constexpr (Add)
            {
                ww1[i] = ww1[i] ^ wv1;
                ww2[i] = ww2[i] ^ wv2;
            }
            else
            {
                ww1[i] = wv1;
                ww2[i] = wv2;
            }
        }
    }

#ifndef EXPANDER_INSTANTATIONS
    SparseMtx ExpanderCode::getB() const
    {
        //PRNG prng(mSeed);
        detail::ExpanderModd prng(mSeed, mCodeSize);
        PointList points(mMessageSize, mCodeSize);

        std::vector<u64> row(mExpanderWeight);

        {

            for (auto i : rng(mMessageSize))
            {
                row[0] = prng.get();
                //points.push_back(i, row[0]);
                for (auto j : rng(1, mExpanderWeight))
                {
                    //do {
                    row[j] = prng.get();
                    //} while
                    auto iter = std::find(row.data(), row.data() + j, row[j]);
                    if (iter != row.data() + j)
                    {
                        row[j] = ~0ull;
                        *iter = ~0ull;
                    }
                    //throw RTE_LOC;

                }
                for (auto j : rng(mExpanderWeight))
                {

                    if (row[j] != ~0ull)
                    {
                        //std::cout << row[j] << " ";
                        points.push_back(i, row[j]);
                    }
                    else
                    {
                        //std::cout << "* ";
                    }
                }
                //std::cout << std::endl;
            }
        }

        return points;
    }
#endif

}
