#include "Tools.h"
#include "cryptoTools/Common/Defines.h"
#include <wmmintrin.h>
#include "cryptoTools/Common/MatrixView.h"
#ifndef _MSC_VER
#include <x86intrin.h>
#endif 

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Log.h"

using std::array;

namespace osuCrypto {

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

        // now transpose output a-place
        for (u32 i = 0; i < logn; i++)
        {
            u64 mask1 = TRANSPOSE_MASKS128[i][1], mask2 = TRANSPOSE_MASKS128[i][0];
            u64 inv_mask1 = ~mask1, inv_mask2 = ~mask2;

            // for width >= 64, shift is undefined so treat as h special case
            // (and avoid branching a inner loop)
            if (width < 64)
            {
                for (u32 j = 0; j < nswaps; j++)
                {
                    for (u32 k = 0; k < width; k++)
                    {
                        u32 i1 = k + 2 * width*j;
                        u32 i2 = k + width + 2 * width*j;

                        // t1 is lower 64 bits, t2 is upper 64 bits
                        // (remember we're transposing a little-endian format)
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
                        // (remember we're transposing a little-endian format)
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
        for (u32 k = 0; k < 128; k++)
        {
            for (u32 blkIdx = 0; blkIdx < 128; blkIdx++)
            {
                output_ss[blkIdx] << inOut[offset + blkIdx].get_bit(k);
            }
        }
        for (u32 k = 0; k < 128; k++)
        {
            if (output_ss[k].str().compare(input_ss[k].str()) != 0)
            {
                cerr << "String " << k << " failed. offset = " << offset << endl;
                exit(1);
            }
        }
        std::cout << "\ttranspose with offset " << offset << " ok\n";
#endif
    }






    //  load          column  w,w+1          (byte index)
    //                   __________________
    //                  |                  |
    //                  |                  |
    //                  |                  |
    //                  |                  |
    //  row  16*h,      |     #.#          |
    //       ...,       |     ...          |
    //  row  16*(h+1)   |     #.#          |     into  u16OutView  column wise
    //                  |                  |
    //                  |                  |
    //                   ------------------
    //                    
    // note: u16OutView is a 16x16 bit matrix = 16 rows of 2 bytes each.
    //       u16OutView[0] stores the first column of 16 bytes,
    //       u16OutView[1] stores the second column of 16 bytes.
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



    // given a 16x16 sub square, place its transpose into u16OutView at 
    // rows  16*h, ..., 16 *(h+1)  a byte  columns w, w+1. 
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
    

    void sse_transpose(const MatrixView<block>& in, const MatrixView<block>& out)
    {
        MatrixView<u8> inn((u8*)in.data(), in.size()[0], in.size()[1] * sizeof(block), false);
        MatrixView<u8> outt((u8*)out.data(), out.size()[0], out.size()[1] * sizeof(block), false);

        sse_transpose(inn, outt);
    }

    void sse_transpose(const MatrixView<u8>& in, const MatrixView<u8>& out)
    {
        static const u64 chunkSize = 8;

        u64 bitWidth = in.size()[0];
        u64 subBlockWidth = bitWidth / 16;
        u64 subBlockHight = in.size()[1] / chunkSize;
        u64 leftOverHeight = in.size()[1] % chunkSize;


        if (in.size()[0] % 8 != 0)
            throw std::runtime_error(LOCATION);

        if (out.size()[1] < (bitWidth + 7) / 8)
            throw std::runtime_error(LOCATION);

        if (out.size()[0] != in.size()[1] * 8)
            throw std::runtime_error(LOCATION);

        array<block, chunkSize> a;
        array < array<u8, 16>, chunkSize>& dest = *(array < array<u8, 16>, chunkSize>*)&a;

        auto step = in.size()[1];

        auto
            step01 = step * 1,
            step02 = step * 2,
            step03 = step * 3,
            step04 = step * 4,
            step05 = step * 5,
            step06 = step * 6,
            step07 = step * 7,
            step08 = step * 8,
            step09 = step * 9,
            step10 = step * 10,
            step11 = step * 11,
            step12 = step * 12,
            step13 = step * 13,
            step14 = step * 14,
            step15 = step * 15;


        auto extra = (in.size()[0] % 16) ? 8 : 0;

        auto wStep = 16 * in.size()[1];
        auto hStep = chunkSize;
        auto wBackStep = wStep  * subBlockWidth - chunkSize;

        //auto start = in.data();
        auto outStart = out.data() + (7) * out.size()[1];

        for (u64 h = 0; h < subBlockHight; ++h)
        {
            // we are concerned with the output rows a range [16 * h, 16 * h + 15]

            for (u64 w = 0; w < subBlockWidth; ++w)
            {
                // we are concerned with the w'th section of 16 bits for the 16 output rows above.

                auto start = in.data() + h * hStep + w * wStep;

                auto src00 = start;
                auto src01 = start + step01;
                auto src02 = start + step02;
                auto src03 = start + step03;
                auto src04 = start + step04;
                auto src05 = start + step05;
                auto src06 = start + step06;
                auto src07 = start + step07;
                auto src08 = start + step08;
                auto src09 = start + step09;
                auto src10 = start + step10;
                auto src11 = start + step11;
                auto src12 = start + step12;
                auto src13 = start + step13;
                auto src14 = start + step14;
                auto src15 = start + step15;
                //start += wStep;

                //if (&src15[7] >= in.data() + in.size()[0] * in.size()[1])
                //{
                //    std::cout << "BAD" << std::endl;
                //    throw std::runtime_error(LOCATION); 
                //}


                dest[0][0] = src00[0]; dest[1][0] = src00[1];  dest[2][0] = src00[2]; dest[3][0] = src00[3];   dest[4][0] = src00[4];  dest[5][0] = src00[5];  dest[6][0] = src00[6]; dest[7][0] = src00[7];
                dest[0][1] = src01[0]; dest[1][1] = src01[1];  dest[2][1] = src01[2]; dest[3][1] = src01[3];   dest[4][1] = src01[4];  dest[5][1] = src01[5];  dest[6][1] = src01[6]; dest[7][1] = src01[7];
                dest[0][2] = src02[0]; dest[1][2] = src02[1];  dest[2][2] = src02[2]; dest[3][2] = src02[3];   dest[4][2] = src02[4];  dest[5][2] = src02[5];  dest[6][2] = src02[6]; dest[7][2] = src02[7];
                dest[0][3] = src03[0]; dest[1][3] = src03[1];  dest[2][3] = src03[2]; dest[3][3] = src03[3];   dest[4][3] = src03[4];  dest[5][3] = src03[5];  dest[6][3] = src03[6]; dest[7][3] = src03[7];
                dest[0][4] = src04[0]; dest[1][4] = src04[1];  dest[2][4] = src04[2]; dest[3][4] = src04[3];   dest[4][4] = src04[4];  dest[5][4] = src04[5];  dest[6][4] = src04[6]; dest[7][4] = src04[7];
                dest[0][5] = src05[0]; dest[1][5] = src05[1];  dest[2][5] = src05[2]; dest[3][5] = src05[3];   dest[4][5] = src05[4];  dest[5][5] = src05[5];  dest[6][5] = src05[6]; dest[7][5] = src05[7];
                dest[0][6] = src06[0]; dest[1][6] = src06[1];  dest[2][6] = src06[2]; dest[3][6] = src06[3];   dest[4][6] = src06[4];  dest[5][6] = src06[5];  dest[6][6] = src06[6]; dest[7][6] = src06[7];
                dest[0][7] = src07[0]; dest[1][7] = src07[1];  dest[2][7] = src07[2]; dest[3][7] = src07[3];   dest[4][7] = src07[4];  dest[5][7] = src07[5];  dest[6][7] = src07[6]; dest[7][7] = src07[7];
                dest[0][8] = src08[0]; dest[1][8] = src08[1];  dest[2][8] = src08[2]; dest[3][8] = src08[3];   dest[4][8] = src08[4];  dest[5][8] = src08[5];  dest[6][8] = src08[6]; dest[7][8] = src08[7];
                dest[0][9] = src09[0]; dest[1][9] = src09[1];  dest[2][9] = src09[2]; dest[3][9] = src09[3];   dest[4][9] = src09[4];  dest[5][9] = src09[5];  dest[6][9] = src09[6]; dest[7][9] = src09[7];
                dest[0][10] = src10[0]; dest[1][10] = src10[1];  dest[2][10] = src10[2]; dest[3][10] = src10[3];   dest[4][10] = src10[4];  dest[5][10] = src10[5];  dest[6][10] = src10[6]; dest[7][10] = src10[7];
                dest[0][11] = src11[0]; dest[1][11] = src11[1];  dest[2][11] = src11[2]; dest[3][11] = src11[3];   dest[4][11] = src11[4];  dest[5][11] = src11[5];  dest[6][11] = src11[6]; dest[7][11] = src11[7];
                dest[0][12] = src12[0]; dest[1][12] = src12[1];  dest[2][12] = src12[2]; dest[3][12] = src12[3];   dest[4][12] = src12[4];  dest[5][12] = src12[5];  dest[6][12] = src12[6]; dest[7][12] = src12[7];
                dest[0][13] = src13[0]; dest[1][13] = src13[1];  dest[2][13] = src13[2]; dest[3][13] = src13[3];   dest[4][13] = src13[4];  dest[5][13] = src13[5];  dest[6][13] = src13[6]; dest[7][13] = src13[7];
                dest[0][14] = src14[0]; dest[1][14] = src14[1];  dest[2][14] = src14[2]; dest[3][14] = src14[3];   dest[4][14] = src14[4];  dest[5][14] = src14[5];  dest[6][14] = src14[6]; dest[7][14] = src14[7];
                dest[0][15] = src15[0]; dest[1][15] = src15[1];  dest[2][15] = src15[2]; dest[3][15] = src15[3];   dest[4][15] = src15[4];  dest[5][15] = src15[5];  dest[6][15] = src15[6]; dest[7][15] = src15[7];


                auto out0 = outStart + (chunkSize * h + 0) * 8 * out.size()[1] + w * 2;
                auto out1 = outStart + (chunkSize * h + 1) * 8 * out.size()[1] + w * 2;
                auto out2 = outStart + (chunkSize * h + 2) * 8 * out.size()[1] + w * 2;
                auto out3 = outStart + (chunkSize * h + 3) * 8 * out.size()[1] + w * 2;
                auto out4 = outStart + (chunkSize * h + 4) * 8 * out.size()[1] + w * 2;
                auto out5 = outStart + (chunkSize * h + 5) * 8 * out.size()[1] + w * 2;
                auto out6 = outStart + (chunkSize * h + 6) * 8 * out.size()[1] + w * 2;
                auto out7 = outStart + (chunkSize * h + 7) * 8 * out.size()[1] + w * 2;

                for (int j = 0; j < 8; j++)
                {
                    *(u16*)out0 = _mm_movemask_epi8(a[0]);
                    *(u16*)out1 = _mm_movemask_epi8(a[1]);
                    *(u16*)out2 = _mm_movemask_epi8(a[2]);
                    *(u16*)out3 = _mm_movemask_epi8(a[3]);
                    *(u16*)out4 = _mm_movemask_epi8(a[4]);
                    *(u16*)out5 = _mm_movemask_epi8(a[5]);
                    *(u16*)out6 = _mm_movemask_epi8(a[6]);
                    *(u16*)out7 = _mm_movemask_epi8(a[7]);

                    out0 -= out.size()[1];
                    out1 -= out.size()[1];
                    out2 -= out.size()[1];
                    out3 -= out.size()[1];
                    out4 -= out.size()[1];
                    out5 -= out.size()[1];
                    out6 -= out.size()[1];
                    out7 -= out.size()[1];

                    a[0] = _mm_slli_epi64(a[0], 1);
                    a[1] = _mm_slli_epi64(a[1], 1);
                    a[2] = _mm_slli_epi64(a[2], 1);
                    a[3] = _mm_slli_epi64(a[3], 1);
                    a[4] = _mm_slli_epi64(a[4], 1);
                    a[5] = _mm_slli_epi64(a[5], 1);
                    a[6] = _mm_slli_epi64(a[6], 1);
                    a[7] = _mm_slli_epi64(a[7], 1);
                }

            }
        }


        for (u64 hh = 0; hh < leftOverHeight; ++hh)
        {
            for (u64 w = 0; w < subBlockWidth; ++w)
            {

                auto start = in.data() + subBlockHight * hStep + hh + w * wStep;

                dest[0][0] =  *(start         );
                dest[0][1] =  *(start + step01);
                dest[0][2] =  *(start + step02);
                dest[0][3] =  *(start + step03);
                dest[0][4] =  *(start + step04);
                dest[0][5] =  *(start + step05);
                dest[0][6] =  *(start + step06);
                dest[0][7] =  *(start + step07);
                dest[0][8] =  *(start + step08);
                dest[0][9] =  *(start + step09);
                dest[0][10] = *(start + step10);
                dest[0][11] = *(start + step11);
                dest[0][12] = *(start + step12);
                dest[0][13] = *(start + step13);
                dest[0][14] = *(start + step14);
                dest[0][15] = *(start + step15);


                auto out0 = outStart + (chunkSize * subBlockHight + hh) * 8 * out.size()[1] + w * 2;

                for (int j = 0; j < 8; j++)
                {
                    *(u16*)out0 = _mm_movemask_epi8(a[0]);

                    out0 -= out.size()[1];

                    a[0] = _mm_slli_epi64(a[0], 1);
                }
            }
        }

        if (extra)
        {
            for (u64 h = 0; h < subBlockHight; ++h)
            {
                // we are concerned with the output rows a range [16 * h, 16 * h + 15]

                auto start = in.data() + h * hStep + subBlockWidth * wStep;

                auto src00 = start;
                auto src01 = start + step01;
                auto src02 = start + step02;
                auto src03 = start + step03;
                auto src04 = start + step04;
                auto src05 = start + step05;
                auto src06 = start + step06;
                auto src07 = start + step07;

                dest[0][00] = src00[0]; dest[1][00] = src00[1];  dest[2][00] = src00[2]; dest[3][00] = src00[3];   dest[4][00] = src00[4];  dest[5][00] = src00[5];  dest[6][00] = src00[6]; dest[7][00] = src00[7];
                dest[0][01] = src01[0]; dest[1][01] = src01[1];  dest[2][01] = src01[2]; dest[3][01] = src01[3];   dest[4][01] = src01[4];  dest[5][01] = src01[5];  dest[6][01] = src01[6]; dest[7][01] = src01[7];
                dest[0][02] = src02[0]; dest[1][02] = src02[1];  dest[2][02] = src02[2]; dest[3][02] = src02[3];   dest[4][02] = src02[4];  dest[5][02] = src02[5];  dest[6][02] = src02[6]; dest[7][02] = src02[7];
                dest[0][03] = src03[0]; dest[1][03] = src03[1];  dest[2][03] = src03[2]; dest[3][03] = src03[3];   dest[4][03] = src03[4];  dest[5][03] = src03[5];  dest[6][03] = src03[6]; dest[7][03] = src03[7];
                dest[0][04] = src04[0]; dest[1][04] = src04[1];  dest[2][04] = src04[2]; dest[3][04] = src04[3];   dest[4][04] = src04[4];  dest[5][04] = src04[5];  dest[6][04] = src04[6]; dest[7][04] = src04[7];
                dest[0][05] = src05[0]; dest[1][05] = src05[1];  dest[2][05] = src05[2]; dest[3][05] = src05[3];   dest[4][05] = src05[4];  dest[5][05] = src05[5];  dest[6][05] = src05[6]; dest[7][05] = src05[7];
                dest[0][06] = src06[0]; dest[1][06] = src06[1];  dest[2][06] = src06[2]; dest[3][06] = src06[3];   dest[4][06] = src06[4];  dest[5][06] = src06[5];  dest[6][06] = src06[6]; dest[7][06] = src06[7];
                dest[0][07] = src07[0]; dest[1][07] = src07[1];  dest[2][07] = src07[2]; dest[3][07] = src07[3];   dest[4][07] = src07[4];  dest[5][07] = src07[5];  dest[6][07] = src07[6]; dest[7][07] = src07[7];

                auto out0 = outStart + (chunkSize * 8 * h + 0 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out1 = outStart + (chunkSize * 8 * h + 1 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out2 = outStart + (chunkSize * 8 * h + 2 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out3 = outStart + (chunkSize * 8 * h + 3 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out4 = outStart + (chunkSize * 8 * h + 4 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out5 = outStart + (chunkSize * 8 * h + 5 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out6 = outStart + (chunkSize * 8 * h + 6 * 8) * out.size()[1] + subBlockWidth * 2;
                auto out7 = outStart + (chunkSize * 8 * h + 7 * 8) * out.size()[1] + subBlockWidth * 2;

                for (int j = 0; j < 8; j++)
                {
                    *out0 = _mm_movemask_epi8(a[0]);
                    *out1 = _mm_movemask_epi8(a[1]);
                    *out2 = _mm_movemask_epi8(a[2]);
                    *out3 = _mm_movemask_epi8(a[3]);
                    *out4 = _mm_movemask_epi8(a[4]);
                    *out5 = _mm_movemask_epi8(a[5]);
                    *out6 = _mm_movemask_epi8(a[6]);
                    *out7 = _mm_movemask_epi8(a[7]);

                    out0 -= out.size()[1];
                    out1 -= out.size()[1];
                    out2 -= out.size()[1];
                    out3 -= out.size()[1];
                    out4 -= out.size()[1];
                    out5 -= out.size()[1];
                    out6 -= out.size()[1];
                    out7 -= out.size()[1];

                    a[0] = _mm_slli_epi64(a[0], 1);
                    a[1] = _mm_slli_epi64(a[1], 1);
                    a[2] = _mm_slli_epi64(a[2], 1);
                    a[3] = _mm_slli_epi64(a[3], 1);
                    a[4] = _mm_slli_epi64(a[4], 1);
                    a[5] = _mm_slli_epi64(a[5], 1);
                    a[6] = _mm_slli_epi64(a[6], 1);
                    a[7] = _mm_slli_epi64(a[7], 1);
                }
            }


            for (u64 hh = 0; hh < leftOverHeight; ++hh)
            {

                // we are concerned with the output rows a range [16 * h, 16 * h + 15]
                auto w = subBlockWidth;

                auto start = in.data() + subBlockHight * hStep + hh + w * wStep;

                dest[0][0] = *(start);
                dest[0][1] = *(start + step01);
                dest[0][2] = *(start + step02);
                dest[0][3] = *(start + step03);
                dest[0][4] = *(start + step04);
                dest[0][5] = *(start + step05);
                dest[0][6] = *(start + step06);
                dest[0][7] = *(start + step07);

                auto out0 = outStart + (chunkSize * subBlockHight + hh) * 8 * out.size()[1] + w * 2;

                for (int j = 0; j < 8; j++)
                {
                    *out0 = _mm_movemask_epi8(a[0]);

                    out0 -= out.size()[1];

                    a[0] = _mm_slli_epi64(a[0], 1);
                }
            }
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

        auto i16y2 = (i * 16) + 2 * y;
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



