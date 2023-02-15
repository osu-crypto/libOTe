#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).


#include "libOTe/config.h"
#include "cryptoTools/Common/CLP.h"
#include <vector>
#include "Mtx.h"
namespace osuCrypto
{
    DenseMtx computeSysGen(DenseMtx G);
    DenseMtx colSwap(DenseMtx G, std::vector<std::pair<u64, u64>>& swaps);

    DenseMtx computeGen(DenseMtx& H);
    DenseMtx computeGen(DenseMtx H, std::vector<std::pair<u64, u64>>& colSwaps);

    int minDist(std::string path, u64 numTHreads, bool verbose);
    int minDist2(const DenseMtx& mtx, u64 numTHreads, bool verbose);


    void ithCombination(u64 index, u64 n, std::vector<u64>& set);
    std::vector<u64> ithCombination(u64 index, u64 n, u64 k);
    u64 choose(u64 n, u64 k);


    struct NChooseK
    {
        u64 mN;
        u64 mK;
        u64 mI, mEnd;
        std::vector<u64> mSet;

        NChooseK(u64 n, u64 k, u64 begin = 0, u64 end = -1)
            : mN(n)
            , mK(k)
            , mI(begin)
            , mEnd(std::min<u64>(choose(n, k), end))
        {
            assert(k <= n);
            mSet = ithCombination(begin, n, k);
        }

        const std::vector<u64>& operator*() const
        {
            return mSet;
        }

        void operator++()
        {
            ++mI;
            assert(mI <= mEnd);

            u64 i = 0;
            while (i < mK - 1 && mSet[i] + 1 == mSet[i + 1])
                ++i;

            //if (i == mK - 1 && mSet.back() == mN - 1)
            //{
            //    mSet.clear();
            //    return;
            //    //assert(mSet.back() != mN - 1);
            //}

            ++mSet[i];
            for (u64 j = 0; j < i; ++j)
                mSet[j] = j;
        }

        explicit operator bool() const
        {
            return mI < mEnd;
        }

    };
#ifdef ENABLE_ALGO994
    extern int alg994;
    extern int num_saved_generators;
    extern int num_cores;
    extern int num_permutations;
    extern int print_matrices;
#endif

}

