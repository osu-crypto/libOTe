// © 2023 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "ExpanderOld.h"
#include "libOTe/Tools/EACode/Util.h"
#ifdef LIBOTE_ENABLE_OLD_EXCONV

namespace osuCrypto
{

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
    // See ExConvCodeInstantiations.cpp for how to instantiate new types that
    // dualEncode can be called on.
    //
    // https://eprint.iacr.org/2023/882
    class ExConvCodeOld : public TimerAdapter
    {
    public:
        ExpanderCodeOld mExpander;

        // configure the code. The default parameters are choses to balance security and performance.
        // For additional parameter choices see the paper.
        void config(
            u64 messageSize,
            u64 codeSize = 0 /*2 * messageSize is default */,
            u64 expanderWeight = 7,
            u64 accumulatorSize = 16,
            bool systematic = true,
            block seed = block(99999, 88888))
        {
            if (codeSize == 0)
                codeSize = 2 * messageSize;

            if (accumulatorSize % 8)
                throw std::runtime_error("ExConvCode accumulator size must be a multiple of 8." LOCATION);

            mSeed = seed;
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mAccumulatorSize = accumulatorSize;
            mSystematic = systematic;
            mExpander.config(messageSize, codeSize - messageSize * systematic, expanderWeight, seed ^ CCBlock);
        }

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
        template<typename T>
        void dualEncode(span<T> e, span<T> w);

        // Compute e[0,...,k-1] = G * e.
        template<typename T>
        void dualEncode(span<T> e);


        // Compute e[0,...,k-1] = G * e.
        template<typename T0, typename T1>
        void dualEncode2(span<T0> e0, span<T1> e1);

        // get the expander matrix
        SparseMtx getB() const;

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const;

        // get the accumulator matrix
        SparseMtx getA() const;

        // Private functions ------------------------------------

        // generate the point list for accumulating row i.
        void accOne(
            PointList& pl,
            u64 i,
            u8* __restrict& ptr,
            PRNG& prng,
            block& rnd,
            u64& q,
            u64 qe,
            u64 size) const;

        // accumulating row i.
        template<typename T, bool rangeCheck, int width>
        void accOne(
            T* __restrict xx,
            u64 i,
            u8*& ptr,
            PRNG& prng,
            u64& q,
            u64 qe,
            u64 size);


        // accumulating row i.
        template<typename T0, typename T1, bool rangeCheck, int width>
        void accOne(
            T0* __restrict xx0,
            T1* __restrict xx1,
            u64 i,
            u8*& ptr,
            PRNG& prng,
            u64& q,
            u64 qe,
            u64 size);


        // accumulate x onto itself.
        template<typename T>
        void accumulate(span<T> x);


        // accumulate x onto itself.
        template<typename T0,typename T1>
        void accumulate(span<T0> x0, span<T1> x1);
    };
}

#endif