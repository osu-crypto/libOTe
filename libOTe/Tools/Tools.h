#pragma once
// © 2016 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cassert>
namespace osuCrypto {





    static inline void mul128(block x, block y, block& xy1, block& xy2)
    {
        x.gf128Mul(y, xy1, xy2);
    }


    static inline void mul190(block a0, block a1, block b0, block b1, block& c0, block& c1, block& c2)
    {
        // c3c2c1c0 = a1a0 * b1b0
        block c4, c5;

        mul128(a0, b0, c0, c1);
        //mul128(a1, b1, c2, c3);
        a0 = (a0 ^ a1);
        b0 = (b0 ^ b1);
        mul128(a0, b0, c4, c5);
        c4 = (c4 ^ c0);
        c4 = (c4 ^ c2);
        c5 = (c5 ^ c1);
        //c5 = _mm_xor_si128(c5, c3);
        c1 = (c1 ^ c4);
        c2 = (c2 ^ c5);
    }

    static inline void mul256(block a0, block a1, block b0, block b1, block& c0, block& c1, block& c2, block& c3)
    {
        block c4, c5;
        mul128(a0, b0, c0, c1);
        mul128(a1, b1, c2, c3);
        a0 = (a0 ^ a1);
        b0 = (b0 ^ b1);
        mul128(a0, b0, c4, c5);
        c4 = (c4 ^ c0);
        c4 = (c4 ^ c2);
        c5 = (c5 ^ c1);
        c5 = (c5 ^ c3);
        c1 = (c1 ^ c4);
        c2 = (c2 ^ c5);

    }
    //{
    //    // c3c2c1c0 = a1a0 * b1b0
    //    block c4, c5;

    //    mul128(a0, b0, c0, c1);
    //    mul128(a1, b1, c2, c3);
    //    a0 = _mm_xor_si128(a0, a1);
    //    b0 = _mm_xor_si128(b0, b1);
    //    mul128(a0, b0, c4, c5);
    //    c4 = _mm_xor_si128(c4, c0);
    //    c4 = _mm_xor_si128(c4, c2);
    //    c5 = _mm_xor_si128(c5, c1);
    //    c5 = _mm_xor_si128(c5, c3);
    //    c1 = _mm_xor_si128(c1, c4);
    //    c2 = _mm_xor_si128(c2, c5);
    //}
    class PRNG;
    bool isPrime(u64 n, PRNG& prng, u64 k = 20);
    bool isPrime(u64 n);
    u64 nextPrime(u64 n);


    void print(std::array<block, 128>& inOut);
    u8 getBit(std::array<block, 128>& inOut, u64 i, u64 j);

    void eklundh_transpose128(block* inOut);
    inline void eklundh_transpose128(std::array<block, 128>& inOut) { eklundh_transpose128(inOut.data()); }
    void eklundh_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);

#ifdef OC_ENABLE_AVX2
    void avx_transpose128(block* inOut);
    void avx_transpose128x1024(block* inOut);
#endif
#ifdef OC_ENABLE_SSE2
    void sse_transpose128(block* inOut);
    void sse_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);
    inline void sse_transpose128(std::array<block, 128>& inOut) { sse_transpose128(inOut.data()); };
#endif
    void transpose(const MatrixView<block>& in, const MatrixView<block>& out);
    void transpose(const MatrixView<u8>& in, const MatrixView<u8>& out);


    // Input must be given the alignment of an AlignedBlockArray, i.e. 32 bytes with AVX or 16 bytes
    // without.
    inline void transpose128(block* inOut)
    {
#if defined(OC_ENABLE_AVX2)
        assert((u64)inOut % 32 == 0);
        avx_transpose128(inOut);
#elif defined(OC_ENABLE_SSE2)
        assert((u64)inOut % 16 == 0);
        sse_transpose128(inOut);
#else
        eklundh_transpose128(inOut);
#endif
    }

    inline void transpose128(std::array<block, 128>& inOut) { transpose128(inOut.data()); };


    inline void transpose128x1024(std::array<std::array<block, 8>, 128>& inOut)
    {

#if defined(OC_ENABLE_AVX2)
        avx_transpose128x1024(inOut[0].data());
#elif defined(OC_ENABLE_SSE2)
        sse_transpose128x1024(inOut);
#else
        eklundh_transpose128x1024(inOut);
#endif
    }

    inline void transpose128x1024(block* inOut)
    {
        transpose128x1024(*(std::array<std::array<block, 8>, 128>*)inOut);
    }
}
