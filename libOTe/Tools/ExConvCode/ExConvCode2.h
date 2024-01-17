// © 2023 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Tools/ExConvCode/Expander2.h"
#include "libOTe/Tools/EACode/Util.h"
#include "libOTe/Tools/Subfield/Subfield.h"

namespace osuCrypto
{

    template<typename T, typename = void>
    struct has_operator_star : std::false_type
    {};

    template <typename T>
    struct has_operator_star < T, std::void_t<
        // must have a operator*() member fn
        decltype(std::declval<T>().operator*())
        >>
        : std::true_type{};


    template<typename T, typename = void>
    struct is_iterator : std::false_type
    {};

    template <typename T>
    struct is_iterator < T, std::void_t<
        // must have a operator*() member fn
        // or be a pointer
        std::enable_if_t<
        has_operator_star<T>::value ||
        std::is_pointer_v<std::remove_reference_t<T>>
        >
        >>
        : std::true_type{};

    // The encoder for the generator matrix G = B * A. dualEncode(...) is the main function
    // config(...) should be called first.
    // 
    // B is the expander while A is the convolution.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a lower triangular n by n matrix with ones on the diagonal. The
    // mAccumulatorSize diagonals left of the main diagonal are uniformly random.
    // If mStickyAccumulator, then the first diagonal left of the main is always ones.
    //
    // See ExConvCode2Instantiations.cpp for how to instantiate new types that
    // dualEncode can be called on.
    //
    // https://eprint.iacr.org/2023/882
    class ExConvCode2 : public TimerAdapter
    {
    public:
        ExpanderCode2 mExpander;

        // configure the code. The default parameters are choses to balance security and performance.
        // For additional parameter choices see the paper.
        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight = 7,
            u64 accumulatorWeight = 16,
            bool systematic = true,
            block seed = block(9996754675674599, 56756745976768754));

        // the seed that generates the code.
        block mSeed = ZeroBlock;

        // The message size of the code. K.
        u64 mMessageSize = 0;

        // The codeword size of the code. n.
        u64 mCodeSize = 0;

        // The size of the accumulator.
        u64 mAccumulatorSize = 0;

        // is the code systematic (true=faster)
        bool mSystematic = true;

        // return n-k. code size n, message size k. 
        u64 parityRows() const { return mCodeSize - mMessageSize; }

        // return code size n.
        u64 parityCols() const { return mCodeSize; }

        // return message size k.
        u64 generatorRows() const { return mMessageSize; }

        // return code size n.
        u64 generatorCols() const { return mCodeSize; }

        // Compute w = G * e. e will be modified in the computation.
        // the computation will be done over F using CoeffCtx::plus
        template<
            typename F,
            typename CoeffCtx,
            typename SrcIter,
            typename DstIter
        >
        void dualEncode(SrcIter&& e, DstIter&& w);

        // Compute e[0,...,k-1] = G * e.
        // the computation will be done over F using CoeffCtx::plus
        template<
            typename F,
            typename CoeffCtx,
            typename Iter
        >
        void dualEncode(Iter&& e);

        // Compute e[0,...,k-1] = G * e.
        template<
            typename F,
            typename G,
            typename CoeffCtx,
            typename IterF,
            typename IterG
        >
        void dualEncode2(IterF&& e0, IterG&& e1)
        {
            dualEncode<F, CoeffCtx>(e0);
            dualEncode<G, CoeffCtx>(e1);
        }

        // Private functions ------------------------------------

        static void refill(PRNG& prng)
        {
            assert(prng.mBuffer.size() == 256);
            //block b[8];
            for (u64 i = 0; i < 256; i += 8)
            {
                block* __restrict b = prng.mBuffer.data() + i;
                block* __restrict k = prng.mBuffer.data() + (u8)(i - 8);

                b[0] = AES::roundEnc(b[0], k[0]);
                b[1] = AES::roundEnc(b[1], k[1]);
                b[2] = AES::roundEnc(b[2], k[2]);
                b[3] = AES::roundEnc(b[3], k[3]);
                b[4] = AES::roundEnc(b[4], k[4]);
                b[5] = AES::roundEnc(b[5], k[5]);
                b[6] = AES::roundEnc(b[6], k[6]);
                b[7] = AES::roundEnc(b[7], k[7]);
            }
        }

        // take x[i] and add it to the next 8 positions if the flag b is 1.
        // 
        // xx[j] += b[j] * x[i]
        //
        template<
            typename F,
            typename CoeffCtx,
            bool rangeCheck,
            typename Iter
        >
        OC_FORCEINLINE void accOne8(
            Iter&& xi,
            Iter&& xj,
            Iter&& end,
            u8 b);

        // accumulating row i. 
        template<
            typename F,
            typename CoeffCtx,
            bool rangeCheck,
            int AccumulatorSize,
            typename Iter
        >
        OC_FORCEINLINE void accOne(
            Iter&& xi,
            Iter&& end,
            u8* matrixCoeff,
            std::integral_constant<u64, AccumulatorSize>);

        // accumulating row i. generic version
        template<
            typename F,
            typename CoeffCtx,
            bool rangeCheck,
            typename Iter
        >
        OC_FORCEINLINE void accOne(
            Iter&& xi,
            Iter&& end,
            u8* matrixCoeff,
            std::integral_constant<u64, 0>);


        // accumulate x onto itself.
        template<
            typename F,
            typename CoeffCtx,
            typename Iter
        >
        void accumulate(Iter x)
        {
            switch (mAccumulatorSize)
            {
            case 16:
                accumulateFixed<F, CoeffCtx, 16, Iter>(std::forward<Iter>(x));
                break;
            case 24:
                accumulateFixed<F, CoeffCtx, 24, Iter>(std::forward<Iter>(x));
                break;
            default:
                // generic case
                accumulateFixed<F, CoeffCtx, 0, Iter>(std::forward<Iter>(x));
            }
        }

        // accumulate x onto itself.
        template<
            typename F,
            typename CoeffCtx,
            u64 AccumulatorSize,
            typename Iter
        >
        void accumulateFixed(Iter x);

    };
}


//#include "ExConvCode2Impl.h"

namespace osuCrypto
{

    // Compute w = G * e. e will be modified in the computation.
    template<
        typename F,
        typename CoeffCtx,
        typename SrcIter,
        typename DstIter
    >
    void ExConvCode2::dualEncode(SrcIter&& e, DstIter&& w)
    {

        static_assert(is_iterator<SrcIter>::value, "must pass in an iterator to the data, " __FUNCTION__);
        static_assert(is_iterator<DstIter>::value, "must pass in an iterator to the data");

        // try to deref the back. might bounds check.
        (void)*(e + mCodeSize - 1);
        (void)*(w + mMessageSize - 1);

        if (mSystematic)
        {
            dualEncode<F, CoeffCtx>(e);
            CoeffCtx::copy(w, w + mMessageSize, e);
            setTimePoint("ExConv.encode.memcpy");
        }
        else
        {

            setTimePoint("ExConv.encode.begin");

            accumulate<F, CoeffCtx>(e);

            setTimePoint("ExConv.encode.accumulate");

            mExpander.expand<F, CoeffCtx, false>(e, w);
            setTimePoint("ExConv.encode.expand");
        }
    }

    // Compute e[0,...,k-1] = G * e.
    template<typename F, typename CoeffCtx, typename Iter>
    void ExConvCode2::dualEncode(Iter&& e)
    {
        static_assert(is_iterator<Iter>::value, "must pass in an iterator to the data");

        (void)*(e + mCodeSize - 1);

        if (mSystematic)
        {
            auto d = e + mMessageSize;
            setTimePoint("ExConv.encode.begin");
            accumulate<F, CoeffCtx>(d);
            setTimePoint("ExConv.encode.accumulate");
            mExpander.expand<F, CoeffCtx, true>(d, e);
            setTimePoint("ExConv.encode.expand");
        }
        else
        {
            CoeffCtx::template Vec<F> w;
            CoeffCtx::resize(w, mMessageSize);
            dualEncode<F, CoeffCtx>(e, w.begin());
            CoeffCtx::copy(w.begin(), w.end(), e);
            //memcpy(e.data(), w.data(), w.size() * sizeof(T));
            setTimePoint("ExConv.encode.memcpy");

        }
    }


    //// Compute e[0,...,k-1] = G * e.
    //template<typename T0, typename T1, typename CoeffCtx>
    //void ExConvCode2::dualEncode2(span<T0> e0, span<T1> e1)
    //{
    //    if (e0.size() != mCodeSize)
    //        throw RTE_LOC;
    //    if (e1.size() != mCodeSize)
    //        throw RTE_LOC;

    //    if (mSystematic)
    //    {
    //        auto d0 = e0.subspan(mMessageSize);
    //        auto d1 = e1.subspan(mMessageSize);
    //        setTimePoint("ExConv.encode.begin");
    //        accumulate<T0, T1, CoeffCtx>(d0, d1);
    //        setTimePoint("ExConv.encode.accumulate");
    //        mExpander.expand<T0, T1, true>(
    //            d0, d1,
    //            e0.subspan(0, mMessageSize),
    //            e1.subspan(0, mMessageSize));
    //        setTimePoint("ExConv.encode.expand");
    //    }
    //    else
    //    {
    //        //oc::AlignedUnVector<T0> w0(mMessageSize);
    //        //dualEncode<T0, T1>(e, w);
    //        //memcpy(e.data(), w.data(), w.size() * sizeof(T));
    //        //setTimePoint("ExConv.encode.memcpy");

    //        // not impl.
    //        throw RTE_LOC;
    //    }
    //}


#ifdef ENABLE_SSE
    using My__m128 = __m128;
#else
    using My__m128 = block;

    inline My__m128 _mm_load_ps(float* b) { return *(block*)b; }

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_blendv_ps&ig_expand=557
    inline My__m128 _mm_blendv_ps(My__m128 a, My__m128 b, My__m128 mask)
    {
        My__m128 dst;
        for (u64 j = 0; j < 4; ++j)
        {
            if (mask.get<i32>(j) < 0)
                dst.set<u32>(j, b.get<u32>(j));
            else
                dst.set<u32>(j, a.get<u32>(j));
        }
        return dst;
    }


    inline My__m128 _mm_setzero_ps() { return ZeroBlock; }
#endif

    // take x[i] and add it to the next 8 positions if the flag b is 1.
    // 
    // xx[j] += b[j] * x[i]
    //
    template<
        typename F,
        typename CoeffCtx,
        bool rangeCheck,
        typename Iter
    >
    OC_FORCEINLINE void ExConvCode2::accOne8(
        Iter&& xi,
        Iter&& xj,
        Iter&& end,
        u8 b)
    {
        if constexpr (std::is_same<F, block>::value)
        {
            block rnd = block::allSame<u8>(b);

            block bshift[8];
            bshift[0] = rnd.slli_epi32<7>();
            bshift[1] = rnd.slli_epi32<6>();
            bshift[2] = rnd.slli_epi32<5>();
            bshift[3] = rnd.slli_epi32<4>();
            bshift[4] = rnd.slli_epi32<3>();
            bshift[5] = rnd.slli_epi32<2>();
            bshift[6] = rnd.slli_epi32<1>();
            bshift[7] = rnd;

            My__m128 bb[8];
            auto xii = _mm_load_ps((float*)(&*xi));
            My__m128 Zero = _mm_setzero_ps();

            // bbj = bj
            bb[0] = _mm_load_ps((float*)&bshift[0]);
            bb[1] = _mm_load_ps((float*)&bshift[1]);
            bb[2] = _mm_load_ps((float*)&bshift[2]);
            bb[3] = _mm_load_ps((float*)&bshift[3]);
            bb[4] = _mm_load_ps((float*)&bshift[4]);
            bb[5] = _mm_load_ps((float*)&bshift[5]);
            bb[6] = _mm_load_ps((float*)&bshift[6]);
            bb[7] = _mm_load_ps((float*)&bshift[7]);

            // bbj = bj * xi
            bb[0] = _mm_blendv_ps(Zero, xii, bb[0]);
            bb[1] = _mm_blendv_ps(Zero, xii, bb[1]);
            bb[2] = _mm_blendv_ps(Zero, xii, bb[2]);
            bb[3] = _mm_blendv_ps(Zero, xii, bb[3]);
            bb[4] = _mm_blendv_ps(Zero, xii, bb[4]);
            bb[5] = _mm_blendv_ps(Zero, xii, bb[5]);
            bb[6] = _mm_blendv_ps(Zero, xii, bb[6]);
            bb[7] = _mm_blendv_ps(Zero, xii, bb[7]);

            block tt[8];
            memcpy(tt, bb, 8 * 16);

            assert((((b >> 0) & 1) ? *xi : ZeroBlock) == tt[0]);
            assert((((b >> 1) & 1) ? *xi : ZeroBlock) == tt[1]);
            assert((((b >> 2) & 1) ? *xi : ZeroBlock) == tt[2]);
            assert((((b >> 3) & 1) ? *xi : ZeroBlock) == tt[3]);
            assert((((b >> 4) & 1) ? *xi : ZeroBlock) == tt[4]);
            assert((((b >> 5) & 1) ? *xi : ZeroBlock) == tt[5]);
            assert((((b >> 6) & 1) ? *xi : ZeroBlock) == tt[6]);
            assert((((b >> 7) & 1) ? *xi : ZeroBlock) == tt[7]);

            // xj += bj * xi
            if (rangeCheck && xj + 0 == end) return; CoeffCtx::plus(*(xj + 0), *(xj + 0), tt[0]);
            if (rangeCheck && xj + 1 == end) return; CoeffCtx::plus(*(xj + 1), *(xj + 1), tt[1]);
            if (rangeCheck && xj + 2 == end) return; CoeffCtx::plus(*(xj + 2), *(xj + 2), tt[2]);
            if (rangeCheck && xj + 3 == end) return; CoeffCtx::plus(*(xj + 3), *(xj + 3), tt[3]);
            if (rangeCheck && xj + 4 == end) return; CoeffCtx::plus(*(xj + 4), *(xj + 4), tt[4]);
            if (rangeCheck && xj + 5 == end) return; CoeffCtx::plus(*(xj + 5), *(xj + 5), tt[5]);
            if (rangeCheck && xj + 6 == end) return; CoeffCtx::plus(*(xj + 6), *(xj + 6), tt[6]);
            if (rangeCheck && xj + 7 == end) return; CoeffCtx::plus(*(xj + 7), *(xj + 7), tt[7]);
        }
        else
        {
            auto b0 = b & 1;
            auto b1 = b & 2;
            auto b2 = b & 4;
            auto b3 = b & 8;
            auto b4 = b & 16;
            auto b5 = b & 32;
            auto b6 = b & 64;
            auto b7 = b & 128;

            if (rangeCheck && xj + 0 == end) return; if (b0) CoeffCtx::plus(*(xj + 0), *(xj + 0), *xi);
            if (rangeCheck && xj + 1 == end) return; if (b1) CoeffCtx::plus(*(xj + 1), *(xj + 1), *xi);
            if (rangeCheck && xj + 2 == end) return; if (b2) CoeffCtx::plus(*(xj + 2), *(xj + 2), *xi);
            if (rangeCheck && xj + 3 == end) return; if (b3) CoeffCtx::plus(*(xj + 3), *(xj + 3), *xi);
            if (rangeCheck && xj + 4 == end) return; if (b4) CoeffCtx::plus(*(xj + 4), *(xj + 4), *xi);
            if (rangeCheck && xj + 5 == end) return; if (b5) CoeffCtx::plus(*(xj + 5), *(xj + 5), *xi);
            if (rangeCheck && xj + 6 == end) return; if (b6) CoeffCtx::plus(*(xj + 6), *(xj + 6), *xi);
            if (rangeCheck && xj + 7 == end) return; if (b7) CoeffCtx::plus(*(xj + 7), *(xj + 7), *xi);
        }
    }



    template<
        typename F,
        typename CoeffCtx,
        bool rangeCheck,
        typename Iter
    >
    OC_FORCEINLINE void ExConvCode2::accOne(
        Iter&& xi,
        Iter&& end,
        u8* matrixCoeff,
        std::integral_constant<u64, 0> _)
    {

        // xj += xi
        std::remove_reference_t<Iter> xj = xi + 1;
        if (!rangeCheck || xj < end)
        {
            CoeffCtx::plus(*xj, *xj, *xi);
            ++xj;
        }

        // xj += bj * xi
        u64 k = 0;
        for (; k < mAccumulatorSize - 7; k += 8)
        {
            accOne8<F, CoeffCtx, rangeCheck>(xi, xj, end, *matrixCoeff++);

            if constexpr (rangeCheck)
            {
                auto r = end - xj;
                xj += std::min<u64>(r, 8);
            }
            else
            {
                xj += 8;
            }
        }
        for (; k < mAccumulatorSize; )
        {
            auto b = *matrixCoeff++;

            for (u64 j = 0; j < 8 && k < mAccumulatorSize; ++j, ++k)
            {

                if (rangeCheck == false || (xj != end))
                {
                    if (b & 1)
                        CoeffCtx::plus(*xj, *xj, *xi);

                    ++xj;
                    b >>= 1;
                }

            }
        }
    }


    // add xi to all of the future locations
    template<
        typename F,
        typename CoeffCtx,
        bool rangeCheck,
        int AccumulatorSize,
        typename Iter
    >
    OC_FORCEINLINE void ExConvCode2::accOne(
        Iter&& xi,
        Iter&& end,
        u8* matrixCoeff,
        std::integral_constant<u64, AccumulatorSize>)
    {
        static_assert(AccumulatorSize, "should have called the other overload");
        static_assert(AccumulatorSize % 8 == 0, "must be a multiple of 8");

        // xj += xi
        std::remove_reference_t<Iter> xj = xi + 1;
        if (!rangeCheck || xj < end)
        {
            CoeffCtx::plus(*xj, *xj, *xi);
            ++xj;
        }

        // xj += bj * xi
        for (u64 k = 0; k < AccumulatorSize; k += 8)
        {
            accOne8<F, CoeffCtx, rangeCheck>(xi, xj, end, *matrixCoeff++);

            if constexpr (rangeCheck)
            {
                auto r = end - xj;
                xj += std::min<u64>(r, 8);
            }
            else
            {
                xj += 8;
            }
        }
    }

    // accumulate x onto itself.
    template<
        typename F,
        typename CoeffCtx,
        u64 AccumulatorSize,
        typename Iter
    >
    void ExConvCode2::accumulateFixed(Iter xi)
    {
        auto end = xi + (mCodeSize - mSystematic * mMessageSize);
        auto main = end - 1 - mAccumulatorSize;

        PRNG prng(mSeed ^ OneBlock);
        u8* mtxCoeffIter = (u8*)prng.mBuffer.data();
        auto mtxCoeffEnd = mtxCoeffIter + prng.mBuffer.size() * sizeof(block) - divCeil(mAccumulatorSize, 8);

        // AccumulatorSize == 0 is the generic case, otherwise
        // AccumulatorSize should be equal to mAccumulatorSize.
        static_assert(AccumulatorSize % 8 == 0);
        if (AccumulatorSize && mAccumulatorSize != AccumulatorSize)
            throw RTE_LOC;

        while (xi < main)
        {
            if (mtxCoeffIter > mtxCoeffEnd)
            {
                // generate more mtx coefficients
                refill(prng);
                mtxCoeffIter = (u8*)prng.mBuffer.data();
            }

            // add xi to the next positions
            accOne<F, CoeffCtx, false>(xi, end, mtxCoeffIter++, std::integral_constant<u64, AccumulatorSize>{});
            ++xi;
        }

        while (xi < end)
        {
            if (mtxCoeffIter > mtxCoeffEnd)
            {
                // generate more mtx coefficients
                refill(prng);
                mtxCoeffIter = (u8*)prng.mBuffer.data();
            }

            // add xi to the next positions
            accOne<F, CoeffCtx, true>(xi, end, mtxCoeffIter++, std::integral_constant<u64, AccumulatorSize>{});
            ++xi;
        }
    }

}