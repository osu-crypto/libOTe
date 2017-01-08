#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
 
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/MatrixView.h"
#include <wmmintrin.h>
namespace osuCrypto {



    static inline void mul128(block x, block y, block& xy1, block& xy2)
    {
        auto t1 = _mm_clmulepi64_si128(x, y, (int)0x00);
        auto t2 = _mm_clmulepi64_si128(x, y, 0x10);
        auto t3 = _mm_clmulepi64_si128(x, y, 0x01);
        auto t4 = _mm_clmulepi64_si128(x, y, 0x11);

        t2 = _mm_xor_si128(t2, t3);
        t3 = _mm_slli_si128(t2, 8);
        t2 = _mm_srli_si128(t2, 8);
        t1 = _mm_xor_si128(t1, t3);
        t4 = _mm_xor_si128(t4, t2);

        xy1 = t1;
        xy2 = t4;
    }

    void eklundh_transpose128(std::array<block, 128>& inOut);
    void sse_transpose128(std::array<block, 128>& inOut);
    void print(std::array<block, 128>& inOut);
    u8 getBit(std::array<block, 128>& inOut, u64 i, u64 j);

    void sse_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);

    void sse_transpose(const MatrixView<block>& in, const MatrixView<block>& out);
    void sse_transpose(const MatrixView<u8>& in, const MatrixView<u8>& out);

}
