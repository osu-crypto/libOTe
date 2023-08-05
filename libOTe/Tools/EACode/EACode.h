#pragma once
// © 2023 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "Expander.h"
#include "Util.h"

namespace osuCrypto
{
#if __cplusplus >= 201703L
#define EA_CONSTEXPR constexpr
#else
#define EA_CONSTEXPR
#endif
    // The encoder for the generator matrix G = B * A.
    // B is the expander while A is the accumulator.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a solid upper triangular n by n matrix
    // https://eprint.iacr.org/2022/1014
    class EACode : public ExpanderCode, public TimerAdapter
    {
    public:
        using ExpanderCode::config;
        using ExpanderCode::getB;


        // Compute w = G * e.
        template<typename T>
        void dualEncode(span<T> e, span<T> w);


        template<typename T, typename T2>
        void dualEncode2(
            span<T> e0,
            span<T> w0,
            span<T2> e1,
            span<T2> w1
        );


        template<typename T>
        void accumulate(span<T> x);
        template<typename T, typename T2>
        void accumulate(span<T> x, span<T2> x2);

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const;

        SparseMtx getA() const;
    };

#undef EA_CONSTEXPR
}
