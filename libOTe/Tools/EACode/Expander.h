// © 2023 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "Util.h"

namespace osuCrypto
{

    // The encoder for the expander matrix B.
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    class ExpanderCode
    {
    public:

        void config(
            u64 messageSize,
            u64 codeSize = 0 /* default is 5* messageSize */,
            u64 expanderWeight = 21,
            block seed = block(33333, 33333))
        {
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mExpanderWeight = expanderWeight;
            mSeed = seed;

        }

        // the seed that generates the code.
        block mSeed = block(0, 0);

        // The message size of the code. K.
        u64 mMessageSize = 0;

        // The codeword size of the code. n.
        u64 mCodeSize = 0;

        // The row weight of the B matrix.
        u64 mExpanderWeight = 0;

        u64 parityRows() const { return mCodeSize - mMessageSize; }
        u64 parityCols() const { return mCodeSize; }

        u64 generatorRows() const { return mMessageSize; }
        u64 generatorCols() const { return mCodeSize; }



        template<typename T, u64 count>
        typename std::enable_if<(count > 1), T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng)const;

        template<typename T, typename T2, u64 count, bool Add>
        typename std::enable_if<(count > 1)>::type
            expandOne(
                const T* __restrict ee1,
                const T2* __restrict ee2,
                T* __restrict y1,
                T2* __restrict y2,
                detail::ExpanderModd& prng)const;

        template<typename T, u64 count>
        typename std::enable_if<count == 1, T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng) const;

        template<typename T, typename T2, u64 count, bool Add>
        typename std::enable_if<count == 1>::type
            expandOne(
                const T* __restrict ee1,
                const T2* __restrict ee2,
                T* __restrict y1,
                T2* __restrict y2,
                detail::ExpanderModd& prng) const;

        template<typename T, bool Add = false>
        void expand(
            span<const T> e,
            span<T> w) const;

        template<typename T, typename T2, bool Add>
        void expand(
            span<const T> e1,
            span<const T2> e2,
            span<T> w1,
            span<T2> w2
        ) const;

        SparseMtx getB() const;

    };
}
