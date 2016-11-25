#include "Tools.h"
#include "Common/Defines.h"
#include <wmmintrin.h>
#include "Common/MatrixView.h"
#ifndef _MSC_VER
#include <x86intrin.h>
#endif 

#include "Common/BitVector.h"
#include "Common/Log.h"

using std::array;

namespace osuCrypto {

    void mul128(block x, block y, block& xy1, block& xy2)
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



    void eklundh_transpose128(array<block, 128>& inOut)
    {
        const static u64 TRANSPOSE_MASKS128[7][2] = {
            { 0x0000000000000000, 0xFFFFFFFFFFFFFFFF },
            { 0x00000000FFFFFFFF, 0x00000000FFFFFFFF },
            { 0x0000FFFF0000FFFF, 0x0000FFFF0000FFFF },
            { 0x00FF00FF00FF00FF, 0x00FF00FF00FF00FF },
            { 0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F },
            { 0x3333333333333333, 0x3333333333333333 },
            { 0x5555555555555555, 0x5555555555555555 }
        };

        u32 width = 64;
        u32 logn = 7, nswaps = 1;

#ifdef TRANSPOSE_DEBUG
        stringstream input_ss[128];
        stringstream output_ss[128];
#endif

        // now transpose output in-place
        for (u32 i = 0; i < logn; i++)
        {
            u64 mask1 = TRANSPOSE_MASKS128[i][1], mask2 = TRANSPOSE_MASKS128[i][0];
            u64 inv_mask1 = ~mask1, inv_mask2 = ~mask2;

            // for width >= 64, shift is undefined so treat as x special case
            // (and avoid branching in inner loop)
            if (width < 64)
            {
                for (u32 j = 0; j < nswaps; j++)
                {
                    for (u32 k = 0; k < width; k++)
                    {
                        u32 i1 = k + 2 * width*j;
                        u32 i2 = k + width + 2 * width*j;

                        // t1 is lower 64 bits, t2 is upper 64 bits
                        // (remember we're transposing in little-endian format)
                        u64& d1 = ((u64*)&inOut[i1])[0];
                        u64& d2 = ((u64*)&inOut[i1])[1];

                        u64& dd1 = ((u64*)&inOut[i2])[0];
                        u64& dd2 = ((u64*)&inOut[i2])[1];

                        u64 t1 = d1;
                        u64 t2 = d2;

                        u64 tt1 = dd1;
                        u64 tt2 = dd2;

                        // swap operations due to little endian-ness
                        d1 = (t1 & mask1) ^ ((tt1 & mask1) << width);

                        d2 = (t2 & mask2) ^
                            ((tt2 & mask2) << width) ^
                            ((tt1 & mask1) >> (64 - width));

                        dd1 = (tt1 & inv_mask1) ^
                            ((t1 & inv_mask1) >> width) ^
                            ((t2 & inv_mask2)) << (64 - width);

                        dd2 = (tt2 & inv_mask2) ^
                            ((t2 & inv_mask2) >> width);
                    }
                }
            }
            else
            {
                for (u32 j = 0; j < nswaps; j++)
                {
                    for (u32 k = 0; k < width; k++)
                    {
                        u32 i1 = k + 2 * width*j;
                        u32 i2 = k + width + 2 * width*j;

                        // t1 is lower 64 bits, t2 is upper 64 bits
                        // (remember we're transposing in little-endian format)
                        u64& d1 = ((u64*)&inOut[i1])[0];
                        u64& d2 = ((u64*)&inOut[i1])[1];

                        u64& dd1 = ((u64*)&inOut[i2])[0];
                        u64& dd2 = ((u64*)&inOut[i2])[1];

                        //u64 t1 = d1;
                        u64 t2 = d2;

                        //u64 tt1 = dd1;
                        //u64 tt2 = dd2;

                        d1 &= mask1;
                        d2 = (t2 & mask2) ^
                            ((dd1 & mask1) >> (64 - width));

                        dd1 = (dd1 & inv_mask1) ^
                            ((t2 & inv_mask2)) << (64 - width);

                        dd2 &= inv_mask2;
                    }
                }
            }
            nswaps *= 2;
            width /= 2;
        }
#ifdef TRANSPOSE_DEBUG
        for (u32 colIdx = 0; colIdx < 128; colIdx++)
        {
            for (u32 blkIdx = 0; blkIdx < 128; blkIdx++)
            {
                output_ss[blkIdx] << inOut[offset + blkIdx].get_bit(colIdx);
            }
        }
        for (u32 colIdx = 0; colIdx < 128; colIdx++)
        {
            if (output_ss[colIdx].str().compare(input_ss[colIdx].str()) != 0)
            {
                cerr << "String " << colIdx << " failed. offset = " << offset << endl;
                exit(1);
            }
        }
        std::cout << "\ttranspose with offset " << offset << " ok\n";
#endif
    }






    //  load          column  y,y+1          (byte index)
    //                   __________________
    //                  |                  |
    //                  |                  |
    //                  |                  |
    //                  |                  |
    //  row  16*x, ..., |     # #          |
    //  row  16*(x+1)   |     # #          |     into  out  column wise
    //                  |                  |
    //                  |                  |
    //                  |                  |
    //                   ------------------
    //                    
    // note: out is a 16x16 bit matrix = 16 rows of 2 bytes each.
    //       out[0] stores the first column of 16 bytes,
    //       out[1] stores the second column of 16 bytes.
    void sse_loadSubSquare(array<block, 128>& in, array<block, 2>& out, u64 x, u64 y)
    {
        static_assert(sizeof(array<array<u8, 16>, 2>) == sizeof(array<block, 2>), "");
        static_assert(sizeof(array<array<u8, 16>, 128>) == sizeof(array<block, 128>), "");

        array<array<u8, 16>, 2>& outByteView = *(array<array<u8, 16>, 2>*)&out;
        array<array<u8, 16>, 128>& inByteView = *(array<array<u8, 16>, 128>*)&in;

        for (int l = 0; l < 16; l++)
        {
            outByteView[0][l] = inByteView[16 * x + l][2 * y];
            outByteView[1][l] = inByteView[16 * x + l][2 * y + 1];
        }
    }



    // given a 16x16 sub square, place its transpose into out at 
    // rows  16*x, ..., 16 *(x+1)  in byte  columns y, y+1. 
    void sse_transposeSubSquare(array<block, 128>& out, array<block, 2>& in, u64 x, u64 y)
    {
        static_assert(sizeof(array<array<u16, 8>, 128>) == sizeof(array<block, 128>), "");

        array<array<u16, 8>, 128>& outU16View = *(array<array<u16, 8>, 128>*)&out;
        

        for (int j = 0; j < 8; j++)
        {
            outU16View[16 * x + 7 - j][y] = _mm_movemask_epi8(in[0]);
            outU16View[16 * x + 15 - j][y] = _mm_movemask_epi8(in[1]);

            in[0] = _mm_slli_epi64(in[0], 1);
            in[1] = _mm_slli_epi64(in[1], 1);
        }
    }

    void print(array<block, 128>& inOut)
    {
        BitVector temp(128);

        for (u64 i = 0; i < 128; ++i)
        {

            temp.assign(inOut[i]);
            std::cout << temp << std::endl;
        }
        std::cout << std::endl;
    }
    
    u8 getBit(array<block, 128>& inOut, u64 i, u64 j)
    {
        BitVector temp(128);
        temp.assign(inOut[i]);

        return temp[j];

    }


    
    void sse_transpose128(array<block, 128>& inOut)
    {
        array<block, 2> a, b;

        for (int j = 0; j < 8; j++)
        {
            sse_loadSubSquare(inOut, a, j, j);
            sse_transposeSubSquare(inOut, a, j, j);

            for (int k = 0; k < j; k++)
            {
                sse_loadSubSquare(inOut, a, k, j);
                sse_loadSubSquare(inOut, b, j, k);
                sse_transposeSubSquare(inOut, a, j, k);
                sse_transposeSubSquare(inOut, b, k, j);
            }
        }
    }




    inline void sse_loadSubSquarex(array<array<block, 8>, 128>& in, array<block, 2>& out, u64 x, u64 y, u64 i)
    {
        typedef array<array<u8, 16>, 2> OUT_t;
        typedef array<array<u8, 128>, 128> IN_t;

        static_assert(sizeof(OUT_t) == sizeof(array<block, 2>), "");
        static_assert(sizeof(IN_t) == sizeof(array<array<block, 8>, 128>), "");

        OUT_t& outByteView = *(OUT_t*)&out;
        IN_t& inByteView = *(IN_t*)&in;

        auto x16 = (x * 16);

        auto i16y2 =  (i * 16) + 2 * y;
        auto i16y21 = (i * 16) + 2 * y + 1;


        outByteView[0][0] = inByteView[x16 + 0][i16y2];
        outByteView[1][0] = inByteView[x16 + 0][i16y21];
        outByteView[0][1] = inByteView[x16 + 1][i16y2];
        outByteView[1][1] = inByteView[x16 + 1][i16y21];
        outByteView[0][2] = inByteView[x16 + 2][i16y2];
        outByteView[1][2] = inByteView[x16 + 2][i16y21];
        outByteView[0][3] = inByteView[x16 + 3][i16y2];
        outByteView[1][3] = inByteView[x16 + 3][i16y21];
        outByteView[0][4] = inByteView[x16 + 4][i16y2];
        outByteView[1][4] = inByteView[x16 + 4][i16y21];
        outByteView[0][5] = inByteView[x16 + 5][i16y2];
        outByteView[1][5] = inByteView[x16 + 5][i16y21];
        outByteView[0][6] = inByteView[x16 + 6][i16y2];
        outByteView[1][6] = inByteView[x16 + 6][i16y21];
        outByteView[0][7] = inByteView[x16 + 7][i16y2];
        outByteView[1][7] = inByteView[x16 + 7][i16y21];
        outByteView[0][8] = inByteView[x16 + 8][i16y2];
        outByteView[1][8] = inByteView[x16 + 8][i16y21];
        outByteView[0][9] = inByteView[x16 + 9][i16y2];
        outByteView[1][9] = inByteView[x16 + 9][i16y21];
        outByteView[0][10] = inByteView[x16 + 10][i16y2];
        outByteView[1][10] = inByteView[x16 + 10][i16y21];
        outByteView[0][11] = inByteView[x16 + 11][i16y2];
        outByteView[1][11] = inByteView[x16 + 11][i16y21];
        outByteView[0][12] = inByteView[x16 + 12][i16y2];
        outByteView[1][12] = inByteView[x16 + 12][i16y21];
        outByteView[0][13] = inByteView[x16 + 13][i16y2];
        outByteView[1][13] = inByteView[x16 + 13][i16y21];
        outByteView[0][14] = inByteView[x16 + 14][i16y2];
        outByteView[1][14] = inByteView[x16 + 14][i16y21];
        outByteView[0][15] = inByteView[x16 + 15][i16y2];
        outByteView[1][15] = inByteView[x16 + 15][i16y21];

    }



    inline void sse_transposeSubSquarex(array<array<block, 8>, 128>& out, array<block, 2>& in, u64 x, u64 y, u64 i)
    {
        static_assert(sizeof(array<array<u16, 64>, 128>) == sizeof(array<array<block, 8>, 128>), "");

        array<array<u16, 64>, 128>& outU16View = *(array<array<u16, 64>, 128>*)&out;

        auto i8y = i * 8 + y;
        auto x16_7 = x * 16 + 7;
        auto x16_15 = x * 16 + 15;

        block b0 = _mm_slli_epi64(in[0], 0);
        block b1 = _mm_slli_epi64(in[0], 1);
        block b2 = _mm_slli_epi64(in[0], 2);
        block b3 = _mm_slli_epi64(in[0], 3);
        block b4 = _mm_slli_epi64(in[0], 4);
        block b5 = _mm_slli_epi64(in[0], 5);
        block b6 = _mm_slli_epi64(in[0], 6);
        block b7 = _mm_slli_epi64(in[0], 7);

        outU16View[x16_7 - 0][i8y] = _mm_movemask_epi8(b0);
        outU16View[x16_7 - 1][i8y] = _mm_movemask_epi8(b1);
        outU16View[x16_7 - 2][i8y] = _mm_movemask_epi8(b2);
        outU16View[x16_7 - 3][i8y] = _mm_movemask_epi8(b3);
        outU16View[x16_7 - 4][i8y] = _mm_movemask_epi8(b4);
        outU16View[x16_7 - 5][i8y] = _mm_movemask_epi8(b5);
        outU16View[x16_7 - 6][i8y] = _mm_movemask_epi8(b6);
        outU16View[x16_7 - 7][i8y] = _mm_movemask_epi8(b7);

       b0 = _mm_slli_epi64(in[1], 0);
       b1 = _mm_slli_epi64(in[1], 1);
       b2 = _mm_slli_epi64(in[1], 2);
       b3 = _mm_slli_epi64(in[1], 3);
       b4 = _mm_slli_epi64(in[1], 4);
       b5 = _mm_slli_epi64(in[1], 5);
       b6 = _mm_slli_epi64(in[1], 6);
       b7 = _mm_slli_epi64(in[1], 7);

        outU16View[x16_15 - 0][i8y] = _mm_movemask_epi8(b0);
        outU16View[x16_15 - 1][i8y] = _mm_movemask_epi8(b1);
        outU16View[x16_15 - 2][i8y] = _mm_movemask_epi8(b2);
        outU16View[x16_15 - 3][i8y] = _mm_movemask_epi8(b3);
        outU16View[x16_15 - 4][i8y] = _mm_movemask_epi8(b4);
        outU16View[x16_15 - 5][i8y] = _mm_movemask_epi8(b5);
        outU16View[x16_15 - 6][i8y] = _mm_movemask_epi8(b6);
        outU16View[x16_15 - 7][i8y] = _mm_movemask_epi8(b7);

    }


    // we have long rows of contiguous data data, 128 columns
    void sse_transpose128x1024(array<array<block, 8>, 128>& inOut)
    {
        array<block, 2> a, b;

        for (int i = 0; i < 8; ++i)
        {
            for (int j = 0; j < 8; j++)
            {
                sse_loadSubSquarex(inOut, a, j, j, i);
                sse_transposeSubSquarex(inOut, a, j, j, i);

                for (int k = 0; k < j; k++)
                {
                    sse_loadSubSquarex(inOut, a, k, j, i);
                    sse_loadSubSquarex(inOut, b, j, k, i);
                    sse_transposeSubSquarex(inOut, a, j, k, i);
                    sse_transposeSubSquarex(inOut, b, k, j, i);
                }
            }

        }


    }
}



