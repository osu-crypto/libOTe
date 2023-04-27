// © 2023 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#pragma once
#include "cryptoTools/Crypto/PRNG.h"
#include <vector>
#ifdef ENABLE_AVX
#define LIBDIVIDE_AVX2
#elif ENABLE_SSE
#define LIBDIVIDE_SSE2
#endif
#include "libdivide.h"
namespace osuCrypto
{
    namespace detail
    {


        struct ExpanderModd
        {
            using value_type = u64;
            PRNG prng;
            u64 modVal, idx;
            AlignedUnVector<value_type> vals;
            libdivide::libdivide_u64_t mod;
            bool mIsPow2;
            std::vector<u64> mPow2Vals;
            u64 mPow2;
            value_type mPow2Mask;
            block mPow2MaskBlk;

            //static const auto numIdx = 

            ExpanderModd(block seed, u64 m)
                : prng(seed, 256)
                , modVal(m)
                , mod(libdivide::libdivide_u64_gen(m))
            {
                mPow2 = log2ceil(modVal);
                mIsPow2 = mPow2 == log2floor(modVal);
                //mIsPow2 = false;
                if (mIsPow2)
                {
                    mPow2Mask = modVal - 1;
                    //mPow2MaskBlk = std::array<value_type,4>{ mPow2Mask, mPow2Mask, mPow2Mask, mPow2Mask };
                    mPow2MaskBlk = std::array<value_type,2>{ mPow2Mask, mPow2Mask};
                    //mPow2Step = divCeil(mPow2, 8);
                    //mPow2Vals.resize(prng.mBufferByteCapacity / mPow2Step);
                    //vals = mPow2Vals;
                }
                else
                {
                    //throw RTE_LOC;
                }
                    //vals = span<u64>((u64*)prng.mBuffer.data(), prng.mBuffer.size() * 2);
                //std::cout << "mIsPow2 " << mIsPow2 << std::endl;
                vals.resize(prng.mBuffer.size() * sizeof(block) / sizeof(vals[0]));
                refill();
            }

            void refill()
            {
                idx = 0;

                assert(prng.mBuffer.size() == 256);
                //block b[8];
                for (u64 i = 0; i < 256; i += 8)
                {
                    //auto idx = mPrng.mBuffer[i].get<u8>();
                    block* __restrict b = prng.mBuffer.data() + i;
                    block* __restrict k = prng.mBuffer.data() + (u8)(i - 8);
                    //for (u64 j = 0; j < 8; ++j)
                    //{
                    //    b = b ^ mPrng.mBuffer.data()[idx[j]];
                    //}
                    b[0] = AES::roundEnc(b[0], k[0]);
                    b[1] = AES::roundEnc(b[1], k[1]);
                    b[2] = AES::roundEnc(b[2], k[2]);
                    b[3] = AES::roundEnc(b[3], k[3]);
                    b[4] = AES::roundEnc(b[4], k[4]);
                    b[5] = AES::roundEnc(b[5], k[5]);
                    b[6] = AES::roundEnc(b[6], k[6]);
                    b[7] = AES::roundEnc(b[7], k[7]);

                    b[0] = b[0] ^ k[0];
                    b[1] = b[1] ^ k[1];
                    b[2] = b[2] ^ k[2];
                    b[3] = b[3] ^ k[3];
                    b[4] = b[4] ^ k[4];
                    b[5] = b[5] ^ k[5];
                    b[6] = b[6] ^ k[6];
                    b[7] = b[7] ^ k[7];
                }

                auto src = prng.mBuffer.data();
                auto dst = (block*)vals.data();
                if (mIsPow2 )
                {
                    assert(prng.mBuffer.size() == 256);

                    for (u64 i = 0; i < 256; i += 8)
                    {
                        dst[i + 0] = src[i + 0] & mPow2MaskBlk;
                        dst[i + 1] = src[i + 1] & mPow2MaskBlk;
                        dst[i + 2] = src[i + 2] & mPow2MaskBlk;
                        dst[i + 3] = src[i + 3] & mPow2MaskBlk;
                        dst[i + 4] = src[i + 4] & mPow2MaskBlk;
                        dst[i + 5] = src[i + 5] & mPow2MaskBlk;
                        dst[i + 6] = src[i + 6] & mPow2MaskBlk;
                        dst[i + 7] = src[i + 7] & mPow2MaskBlk;
                        //vals[i]
                        //vals.data()[i] = *(u64*)ptr & mPow2Mask;
                        //ptr += mPow2Step;
                        //++ptr;
                    }
                }
                else
                {
                    memcpy(dst, src, vals.size() * sizeof(value_type));
                    //throw RTE_LOC;
                    //assert(vals.size() % 32 == 0);
                    for (u64 i = 0; i < vals.size(); i += 32)
                        doMod32(vals.data() + i, &mod, modVal);
                }
            }

            OC_FORCEINLINE u64 get()
            {
                if (idx == vals.size())
                    refill();

                return vals.data()[idx++];
            }


#ifdef ENABLE_AVX
            using block256 = __m256i;
            static inline block256 my_libdivide_u64_do_vec256(const block256& x, const libdivide::libdivide_u64_t* divider)
            {
                return libdivide::libdivide_u64_do_vec256(x, divider);
            }
#else
            using block256 = std::array<block, 2>;

            static inline block256 _mm256_loadu_si256(block256* p) { return *p; }

            static inline block256 my_libdivide_u64_do_vec256(const block256& x, const libdivide::libdivide_u64_t* divider)
            {
                block256 y;
                auto x64 = (u64*)&x;
                auto y64 = (u64*)&y;
                for (u64 i = 0; i < 4; ++i)
                {
                    y64[i] = libdivide::libdivide_u64_do(x64[i], divider);
                }

                return y;
            }
#endif


            static inline void doMod32(u64* vals, const libdivide::libdivide_u64_t* divider, const u64& modVal)
            {
                {
                    u64 i = 0;
                    block256 row256a = _mm256_loadu_si256((block256*)&vals[i]);
                    block256 row256b = _mm256_loadu_si256((block256*)&vals[i + 4]);
                    block256 row256c = _mm256_loadu_si256((block256*)&vals[i + 8]);
                    block256 row256d = _mm256_loadu_si256((block256*)&vals[i + 12]);
                    block256 row256e = _mm256_loadu_si256((block256*)&vals[i + 16]);
                    block256 row256f = _mm256_loadu_si256((block256*)&vals[i + 20]);
                    block256 row256g = _mm256_loadu_si256((block256*)&vals[i + 24]);
                    block256 row256h = _mm256_loadu_si256((block256*)&vals[i + 28]);
                    auto tempa = my_libdivide_u64_do_vec256(row256a, divider);
                    auto tempb = my_libdivide_u64_do_vec256(row256b, divider);
                    auto tempc = my_libdivide_u64_do_vec256(row256c, divider);
                    auto tempd = my_libdivide_u64_do_vec256(row256d, divider);
                    auto tempe = my_libdivide_u64_do_vec256(row256e, divider);
                    auto tempf = my_libdivide_u64_do_vec256(row256f, divider);
                    auto tempg = my_libdivide_u64_do_vec256(row256g, divider);
                    auto temph = my_libdivide_u64_do_vec256(row256h, divider);
                    //auto temp = libdivide::libdivide_u64_branchfree_do_vec256(row256, divider);
                    auto temp64a = (u64*)&tempa;
                    auto temp64b = (u64*)&tempb;
                    auto temp64c = (u64*)&tempc;
                    auto temp64d = (u64*)&tempd;
                    auto temp64e = (u64*)&tempe;
                    auto temp64f = (u64*)&tempf;
                    auto temp64g = (u64*)&tempg;
                    auto temp64h = (u64*)&temph;
                    vals[i + 0] -= temp64a[0] * modVal;
                    vals[i + 1] -= temp64a[1] * modVal;
                    vals[i + 2] -= temp64a[2] * modVal;
                    vals[i + 3] -= temp64a[3] * modVal;
                    vals[i + 4] -= temp64b[0] * modVal;
                    vals[i + 5] -= temp64b[1] * modVal;
                    vals[i + 6] -= temp64b[2] * modVal;
                    vals[i + 7] -= temp64b[3] * modVal;
                    vals[i + 8] -= temp64c[0] * modVal;
                    vals[i + 9] -= temp64c[1] * modVal;
                    vals[i + 10] -= temp64c[2] * modVal;
                    vals[i + 11] -= temp64c[3] * modVal;
                    vals[i + 12] -= temp64d[0] * modVal;
                    vals[i + 13] -= temp64d[1] * modVal;
                    vals[i + 14] -= temp64d[2] * modVal;
                    vals[i + 15] -= temp64d[3] * modVal;
                    vals[i + 16] -= temp64e[0] * modVal;
                    vals[i + 17] -= temp64e[1] * modVal;
                    vals[i + 18] -= temp64e[2] * modVal;
                    vals[i + 19] -= temp64e[3] * modVal;
                    vals[i + 20] -= temp64f[0] * modVal;
                    vals[i + 21] -= temp64f[1] * modVal;
                    vals[i + 22] -= temp64f[2] * modVal;
                    vals[i + 23] -= temp64f[3] * modVal;
                    vals[i + 24] -= temp64g[0] * modVal;
                    vals[i + 25] -= temp64g[1] * modVal;
                    vals[i + 26] -= temp64g[2] * modVal;
                    vals[i + 27] -= temp64g[3] * modVal;
                    vals[i + 28] -= temp64h[0] * modVal;
                    vals[i + 29] -= temp64h[1] * modVal;
                    vals[i + 30] -= temp64h[2] * modVal;
                    vals[i + 31] -= temp64h[3] * modVal;
                }
            }

        };
    }
}