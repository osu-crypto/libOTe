#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
 
#include "Common/Defines.h"
#include "Common/MatrixView.h"

namespace osuCrypto {



    void pow128(block x, u16 p, block& xp1, block& xp2);
        void mul128(block x, block y, block &xy1 , block &xy2);

    void eklundh_transpose128(std::array<block, 128>& inOut);
    void sse_transpose128(std::array<block, 128>& inOut);
    void print(std::array<block, 128>& inOut);
    u8 getBit(std::array<block, 128>& inOut, u64 i, u64 j);

    void sse_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);

    void sse_transpose(MatrixView<block> in, MatrixView<block> out);
    void sse_transpose(MatrixView<u8> in, MatrixView<u8> out);

}
