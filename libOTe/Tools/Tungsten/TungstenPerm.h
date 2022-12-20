#pragma once
#include "SqrtPerm.h"

namespace osuCrypto
{




    // this expander/permuter first maps items into bins, every (i + j * NumBins)'th item 
    // is mapped to the i'th bin. These bins are then permuted
    // uniformly. The final expander is obtained by doing linear sums.
    template<typename T, int NumBins>
    struct TungstenBinPerm
    {
        static constexpr int c2 = 16;
        static constexpr int chunkSize = NumBins * c2;

        std::array<Perm, NumBins> mPerm;
        AlignedUnVector<T> mBuffer;
        std::array<T* __restrict, NumBins> mBins;

        void reset()
        {
            for (u64 i = 0; i < NumBins; ++i)
            {
                mBins[i] = mBuffer.data() + i * mPerm[i].mPerm.size();
            }
        }

        TungstenBinPerm(u64 size)
            : mBuffer(size)
        {
            if (size % NumBins)
                throw RTE_LOC;
            auto s = mBuffer.size() / NumBins;
            PRNG prng(CCBlock);
            for (u64 i = 0; i < NumBins; ++i)
            {
                mPerm[i].init(s, prng);
            }
            reset();
        }

        OC_FORCEINLINE void apply(T* __restrict xi, u64 k)
        {
            //assert(k < NumBins);
            //assert(mBins[k] < (k + 1) * mPerm[0].mPerm.size() + mBuffer.data());
            //*(T * __restrict)mBins[k] = *xi;
            //++mBins[k];
        }


        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            for (u64 i = 0; i < c2; ++i, ++x)
            {
                if (flush)
                {

                    if constexpr (NumBins == 8)
                    {
                        _mm_stream_si128((__m128i*)mBins[0]++, x[0]);
                        _mm_stream_si128((__m128i*)mBins[1]++, x[8]);
                        _mm_stream_si128((__m128i*)mBins[2]++, x[16]);
                        _mm_stream_si128((__m128i*)mBins[3]++, x[24]);
                        _mm_stream_si128((__m128i*)mBins[4]++, x[32]);
                        _mm_stream_si128((__m128i*)mBins[5]++, x[40]);
                        _mm_stream_si128((__m128i*)mBins[6]++, x[48]);
                        _mm_stream_si128((__m128i*)mBins[7]++, x[56]);
                    }
                    else if constexpr (NumBins == 16)
                    {

                        _mm_stream_si128((__m128i*)mBins[0]++, x[0]);
                        _mm_stream_si128((__m128i*)mBins[1]++, x[8]);
                        _mm_stream_si128((__m128i*)mBins[2]++, x[16]);
                        _mm_stream_si128((__m128i*)mBins[3]++, x[24]);
                        _mm_stream_si128((__m128i*)mBins[4]++, x[32]);
                        _mm_stream_si128((__m128i*)mBins[5]++, x[40]);
                        _mm_stream_si128((__m128i*)mBins[6]++, x[48]);
                        _mm_stream_si128((__m128i*)mBins[7]++, x[56]);

                        _mm_stream_si128((__m128i*)mBins[8 + 0]++, x[64 + 0]);
                        _mm_stream_si128((__m128i*)mBins[8 + 1]++, x[64 + 8]);
                        _mm_stream_si128((__m128i*)mBins[8 + 2]++, x[64 + 16]);
                        _mm_stream_si128((__m128i*)mBins[8 + 3]++, x[64 + 24]);
                        _mm_stream_si128((__m128i*)mBins[8 + 4]++, x[64 + 32]);
                        _mm_stream_si128((__m128i*)mBins[8 + 5]++, x[64 + 40]);
                        _mm_stream_si128((__m128i*)mBins[8 + 6]++, x[64 + 48]);
                        _mm_stream_si128((__m128i*)mBins[8 + 7]++, x[64 + 56]);
                    }
                    else
                    {
                        throw RTE_LOC;
                    }
                }
                else
                {

                    if constexpr (NumBins == 8)
                    {
                        *mBins[0]++ = x[0];
                        *mBins[1]++ = x[8];
                        *mBins[2]++ = x[16];
                        *mBins[3]++ = x[24];
                        *mBins[4]++ = x[32];
                        *mBins[5]++ = x[40];
                        *mBins[6]++ = x[48];
                        *mBins[7]++ = x[56];
                    }
                    else if constexpr (NumBins == 16)
                    {

                        *mBins[0]++ = x[0];
                        *mBins[1]++ = x[8];
                        *mBins[2]++ = x[16];
                        *mBins[3]++ = x[24];
                        *mBins[4]++ = x[32];
                        *mBins[5]++ = x[40];
                        *mBins[6]++ = x[48];
                        *mBins[7]++ = x[56];
                        *
                            *mBins[8 + 0]++ = x[64 + 0];
                        *mBins[8 + 1]++ = x[64 + 8];
                        *mBins[8 + 2]++ = x[64 + 16];
                        *mBins[8 + 3]++ = x[64 + 24];
                        *mBins[8 + 4]++ = x[64 + 32];
                        *mBins[8 + 5]++ = x[64 + 40];
                        *mBins[8 + 6]++ = x[64 + 48];
                        *mBins[8 + 7]++ = x[64 + 56];
                    }
                    else
                    {
                        throw RTE_LOC;
                    }
                }
            }
        }

        void finalize()
        {
            auto s = mBuffer.size() / NumBins;
            for (u64 j = 0; j < NumBins; ++j)
            {
                auto sub = mBuffer.subspan(s * j, s);
                mPerm[j].apply(sub);
            }
        }
    };

    // this expander/permuter maps chunks of inputs uniformly. The final expander is obtained by doing linear sums.
    template<typename T, int chunkSize_>
    struct TungstenPerm
    {
        static constexpr int chunkSize = chunkSize_;
        Perm mPerm;
        AlignedUnVector<T> mBuffer;
        u32* mPermIter;

        void reset()
        {
            mPermIter = mPerm.mPerm.data();
        }

        TungstenPerm(u64 size)
            : mBuffer(size)
        {
            if (size % chunkSize)
                throw RTE_LOC;
            PRNG prng(CCBlock);
            if (mPerm.mPerm.size() == 0)
                mPerm.init(mBuffer.size() / chunkSize, prng, true);
            reset();
        }

        void finalize()
        {
        }

        OC_FORCEINLINE void apply(T* __restrict x, u64 k)
        {}

        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            assert(mPermIter < mPerm.mPerm.data() + mPerm.mPerm.size());

            T* __restrict dst = &mBuffer.data()[*(u32 * __restrict)mPermIter * chunkSize];

            //for (u64 i = 0; i < chunkSize; ++i)
            //{
            //    std::cout << ">" << mIdx++ <<" -> " << 
            //}
            //std::cout<< ">" << *mPermIter << std::endl;
            ++mPermIter;

            //if constexpr (std::is_same_v<T, block> && flush)
            //{
            //    if constexpr (chunkSize == 8)
            //    {
            //        _mm_stream_si128((__m128i*)dst + 0, x[0]);
            //        _mm_stream_si128((__m128i*)dst + 1, x[1]);
            //        _mm_stream_si128((__m128i*)dst + 2, x[2]);
            //        _mm_stream_si128((__m128i*)dst + 3, x[3]);
            //        _mm_stream_si128((__m128i*)dst + 4, x[4]);
            //        _mm_stream_si128((__m128i*)dst + 5, x[5]);
            //        _mm_stream_si128((__m128i*)dst + 6, x[6]);
            //        _mm_stream_si128((__m128i*)dst + 7, x[7]);

            //    }
            //    else
            //        for (u64 i = 0; i < chunkSize; ++i)
            //            _mm_stream_si128((__m128i*)dst + i, x[i]);
            //}
            //else
            memcpy(dst, x, sizeof(*x) * chunkSize);
        }

        SparseMtx getMatrix() const
        {
            auto n = mPerm.mPerm.size() * chunkSize;
            PointList ret(n, n);

            u64 r = 0;
            for (auto p : mPerm.mPerm)
            {
                //std::cout << "<" << p << std::endl;

                for (u64 i = 0; i < chunkSize; ++i, ++r)
                {
                    ret.push_back({ p * chunkSize + i , r });
                }
            }
            return ret;
        }
    };

    // this exapnder/permuter does nothing.
    struct NoopPerm
    {
        static constexpr int chunkSize = 1;

        NoopPerm() = default;
        NoopPerm(u64 n) {}

        void reset()
        {
        }


        void finalize()
        {
        }

        template<typename T>
        OC_FORCEINLINE void apply(T* __restrict x, u64 k)
        {}

        template<typename T>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
        }
    };



}