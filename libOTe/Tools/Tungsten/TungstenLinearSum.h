#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"


namespace osuCrypto
{


    SparseMtx getLinearSums(u64 n, u64 weight)
    {
        throw RTE_LOC;
        //auto mCodeSize = n;
        //auto mMessageSize = n / 2;

        //PointList ret(mMessageSize, mCodeSize);

        //details::SilverLeftEncoder L;

        //if (weight == 5)
        //    L.init(mCodeSize, SilverCode::code::Weight5);
        //else if (weight == 11)
        //{
        //    L.init(mCodeSize, SilverCode::code::Weight11);
        //}
        //else
        //{
        //    std::vector<double> s; s.push_back(0);
        //    while (s.size() != weight)
        //    {
        //        s.push_back((rand() % mCodeSize) / double(mCodeSize));
        //    }
        //    L.init(mCodeSize, s);
        //}
        //auto mWeight = L.mWeight;
        //auto mYs = L.mYs;

        //auto v = mYs;

        //for (u64 i = 0; i < mMessageSize; )
        //{
        //    auto end = mMessageSize;
        //    for (u64 j = 0; j < mWeight; ++j)
        //    {
        //        if (v[j] == mCodeSize)
        //            v[j] = 0;

        //        auto jEnd = mCodeSize - v[j] + i;
        //        end = std::min<u64>(end, jEnd);
        //    }

        //    while (i != end)
        //    {
        //        for (u64 j = 0; j < mWeight; ++j)
        //        {
        //            ret.push_back({ i, v[j]++ });
        //        }
        //        ++i;
        //    }

        //}
        //return ret;
    }

    template<typename T>
    void linearSums(span<T> e, span<T> w, u64 mExpanderWeight)
    {
        throw RTE_LOC;
        //auto mCodeSize = e.size();
        //auto mMessageSize = w.size();

        //details::SilverLeftEncoder L;

        //if (mExpanderWeight == 5)
        //    L.init(mCodeSize, SilverCode::code::Weight5);
        //else if (mExpanderWeight == 11)
        //{
        //    L.init(mCodeSize, SilverCode::code::Weight11);
        //}
        //else
        //{
        //    std::vector<double> s; s.push_back(0);
        //    while (s.size() != mExpanderWeight)
        //    {
        //        s.push_back((rand() % mCodeSize) / double(mCodeSize));
        //    }
        //    L.init(mCodeSize, s);
        //}
        //auto mWeight = L.mWeight;
        //auto mYs = L.mYs;

        //auto v = mYs;
        //T* __restrict pp = w.data();
        //const T* __restrict m = e.data();

        //for (u64 i = 0; i < mMessageSize; )
        //{
        //    auto end = mMessageSize;
        //    for (u64 j = 0; j < mWeight; ++j)
        //    {
        //        if (v[j] == mCodeSize)
        //            v[j] = 0;

        //        auto jEnd = mCodeSize - v[j] + i;
        //        end = std::min<u64>(end, jEnd);
        //    }
        //    T* __restrict P = &pp[i];
        //    T* __restrict PE = &pp[end];
        //    T* __restrict PE8 = &pp[(end - i) / 8 * 8 + i];

        //    switch (mWeight)
        //    {
        //    case 5:
        //    {
        //        const T* __restrict M0 = &m[v[0]];
        //        const T* __restrict M1 = &m[v[1]];
        //        const T* __restrict M2 = &m[v[2]];
        //        const T* __restrict M3 = &m[v[3]];
        //        const T* __restrict M4 = &m[v[4]];

        //        v[0] += end - i;
        //        v[1] += end - i;
        //        v[2] += end - i;
        //        v[3] += end - i;
        //        v[4] += end - i;
        //        i = end;

        //        while (P != PE)
        //        {
        //            T t = *M0
        //                ^ *M1
        //                ^ *M2
        //                ^ *M3
        //                ^ *M4
        //                ;

        //            if constexpr (std::is_same<block, T>::value)
        //                _mm_stream_si128((__m128i*)P, (__m128i)t);
        //            else
        //                *P = t;

        //            ++M0;
        //            ++M1;
        //            ++M2;
        //            ++M3;
        //            ++M4;
        //            ++P;
        //        }


        //        break;
        //    }
        //    case 11:
        //    {

        //        const T* __restrict M0 = &m[v[0]];
        //        const T* __restrict M1 = &m[v[1]];
        //        const T* __restrict M2 = &m[v[2]];
        //        const T* __restrict M3 = &m[v[3]];
        //        const T* __restrict M4 = &m[v[4]];
        //        const T* __restrict M5 = &m[v[5]];
        //        const T* __restrict M6 = &m[v[6]];
        //        const T* __restrict M7 = &m[v[7]];
        //        const T* __restrict M8 = &m[v[8]];
        //        const T* __restrict M9 = &m[v[9]];
        //        const T* __restrict M10 = &m[v[10]];

        //        v[0] += end - i;
        //        v[1] += end - i;
        //        v[2] += end - i;
        //        v[3] += end - i;
        //        v[4] += end - i;
        //        v[5] += end - i;
        //        v[6] += end - i;
        //        v[7] += end - i;
        //        v[8] += end - i;
        //        v[9] += end - i;
        //        v[10] += end - i;
        //        i = end;

        //        while (P != PE)
        //        {
        //            *P = *M0
        //                ^ *M1
        //                ^ *M2
        //                ^ *M3
        //                ^ *M4
        //                ^ *M5
        //                ^ *M6
        //                ^ *M7
        //                ^ *M8
        //                ^ *M9
        //                ^ *M10
        //                ;

        //            ++M0;
        //            ++M1;
        //            ++M2;
        //            ++M3;
        //            ++M4;
        //            ++M5;
        //            ++M6;
        //            ++M7;
        //            ++M8;
        //            ++M9;
        //            ++M10;
        //            ++P;
        //        }

        //        break;
        //    }
        //    default:
        //        while (i != end)
        //        {
        //            {
        //                auto row = v[0];
        //                pp[i] = m[row];
        //                ++v[0];
        //            }

        //            for (u64 j = 1; j < mWeight; ++j)
        //            {
        //                auto row = v[j];
        //                pp[i] = pp[i] ^ m[row];
        //                ++v[j];
        //            }
        //            ++i;
        //        }
        //        break;
        //    }

        //}
    }
}