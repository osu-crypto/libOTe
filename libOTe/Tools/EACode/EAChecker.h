// © 2023 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#pragma once
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/Tools/LDPC/Util.h"

namespace osuCrypto
{
    //struct Signature
    //{
    //    u64 mI;
    //    std::vector<u64> mIdx;
    //    Signature(std::vector<u64> idx, u64 i)
    //        : mI(i)
    //        , mIdx(std::move(idx))
    //    {
    //    }

        u64 hash(span<u64> mIdx, u64 b, u64 N)
        {
            //RandomOracle ro(sizeof(u64));

            //for (u64 j = 0; j < mIdx.size(); ++j)
            //    ro.Update(mIdx[j] * b / N);
            //u64 h;
            //ro.Final(h);
            //return h;

            block hh = ZeroBlock;
            for (u64 j = 0; j < mIdx.size(); ++j)
                hh = hh ^ mAesFixedKey.ecbEncBlock(block(mIdx[j], j));
            return hh.get<u64>(0);
        }

        std::vector<u64> ahash(span<u64> mIdx, u64 numBins, u64 N, double d, bool verbose)
        {
            std::vector<u64> H, B;
            H.push_back(hash(mIdx, numBins, N));

            auto binSize = N / numBins;
            auto threshold = N * d / numBins;

            u64 lastBin = numBins - 1;
            std::vector<i64> tweaks, tweakIdx;
            for (u64 j = 0; j < mIdx.size(); ++j)
            {
                auto bIdx = mIdx[j] * numBins / N;
                auto bRem = mIdx[j] - bIdx * N / numBins;


                //if (verbose)
                //    std::cout << bIdx << ", r " << bRem << " vs " << threshold << std::endl;
                if (bRem < threshold && bRem != 0)
                {
                    //if (verbose) 
                    //    std::cout << "v- " << bRem << " < " << threshold << std::endl;
                    tweakIdx.push_back(j);
                    tweaks.push_back(-1);
                }
                if (bRem > binSize - threshold && bRem != lastBin)
                {
                    //if (verbose)
                    //    std::cout << "v+ " << bRem << " < " << threshold << std::endl;
                    tweakIdx.push_back(j);
                    tweaks.push_back(1);
                }

                B.push_back(bIdx);
            }

            for (u64 i = 1; i < (1ull << tweakIdx.size()); ++i)
            {
                RandomOracle ro(sizeof(u64));
                BitIterator iIter((u8*)&i);
                auto bb = B;
                for (u64 j = 0; j < tweakIdx.size(); ++j)
                {
                    if (*iIter++)
                    {
                        bb[tweakIdx[j]] += tweaks[j];
                    }
                }

                //ro.Update(bb.data(), bb.size());
                //u64 h;
                //ro.Final(h);
                //H.push_back(h);
                 
                block hh = ZeroBlock;
                for (u64 j = 0; j < bb.size(); ++j)
                    hh = hh ^ mAesFixedKey.ecbEncBlock(block(bb[j], j));
                H.push_back(hh.get<u64>(0));
            }
            return H;
        }
    //};

        
    void EAChecker(CLP& cmd)
    {
        u64 seed = cmd.getOr("s", 0);
        u64 tt = cmd.getOr("t", 1);
        u64 nt = cmd.getOr("nt", 1);
        u64 n = cmd.getOr("n", 10000);
        u64 e = cmd.getOr("e", 5);

        u64 N = n * e;
        u64 k = cmd.getOr("k", 7);

        u64 b = cmd.getOr("b", 50);

        bool v = cmd.isSet("v");

        double d = cmd.getOr("d", 0.25);

        bool highWeight = cmd.isSet("hw");
        std::vector<std::thread> thrds(nt);
        std::mutex mutex;
        u64 mm = -1, m0 = -1;
        auto runOne = [&](u64 t, Matrix<u64>& sig)
        {

            std::vector<u64> xx(2 * k), ii;;

            std::unordered_map<u64, std::vector<u64>> sets;
            //sig.reserve(n);

            u64 max = 0, minDis = N, min0 = -1;
            PRNG prng(block(seed, t));
            for (u64 i = 0; i < n; ++i)
            {
                auto x = sig[i];
                //if (v)
                //    std::cout << i << ": ";
                for (u64 j = 0; j < k; ++j)
                {
                    x[j] = prng.get<u64>() % N;

                    //if (v)
                    //    std::cout << x[j] << " ";
                }
                //if (v)
                //    std::cout << std::endl;
                std::sort(x.begin(), x.end());
                u64 mm0 =0;
                for (u64 j = 0; j < k-1; j += 2)
                {
                    mm0 += x[j + 1] - x[j];
                }
                if (k & 1)
                    mm += N-x.back();


                min0 = std::min(min0, mm);
                //sig.emplace_back(x, i);

                auto H = ahash(sig[i], b, N, d, i == 709209);

                //if (i == 709209 || i == 483878)
                //{
                //    std::cout << "----------------------- " << i << std::endl;
                //    for (u64 j = 0; j < x.size(); ++j)
                //        std::cout << x[j] << " ";              
                //    std::cout << std::endl;
                //    for (u64 j = 0; j < x.size(); ++j)
                //        std::cout << x[j] * b / N << " ";
                //    std::cout << std::endl;
                //    for (u64 j = 0; j < x.size(); ++j)
                //    {
                //        auto bIdx = (x[j] * b / N);
                //        auto bStart = bIdx * N / b;
                //        auto f = (x[j] - bStart ) / double(N / b);
                //        std::cout << f << " ";
                //    }
                //    std::cout << std::endl;
                //    for (u64 j = 0; j < H.size(); ++j)
                //        std::cout << j << " " << H[j] << std::endl;
                //}

                for (auto h : H)
                {
                    auto& ss = sets[h];
                    ss.push_back(i);
                    if (ss.size() > max)
                    {
                        max = ss.size();

                        if (v)
                            std::cout << "m" << max << " " << i << std::endl;
                    }

                    if (highWeight)
                    {
                        u64 pow = 1ull << (ss.size() - 1);
                        for (u64 jj = 1; jj < pow; ++jj)
                        {
                            xx.clear();
                            xx.insert(xx.end(), x.begin(), x.end());
                            for (u64 j = 0; j < ss.size() - 1; ++j)
                            {
                                if (jj & (1ull << j))
                                {
                                    auto s2 = sig[ss[j]];
                                    xx.insert(xx.end(), s2.begin(), s2.end());
                                }
                            }

                            std::sort(xx.begin(), xx.end());
                            u64 d = 0;
                            for (u64 t = 0; t < xx.size() - 1; t += 2)
                            {
                                d += (xx[t + 1] - xx[t]);
                            }
                            if (xx.size() & 1)
                            {
                                d += (N - 1) - xx.back();
                            }

                            if (d < minDis)
                            {
                                ii = { { i } };
                                for (u64 j = 0; j < ss.size() - 1; ++j)
                                {
                                    if (jj & (1ull << j))
                                        ii.push_back(ss[j]);
                                }
                                minDis = d;
                                if (v)
                                    std::cout << minDis << std::endl;
                            }
                        }
                    }
                    else
                    {
                        for (u64 j = 0; j < ss.size() - 1; ++j)
                        {
                            //std::cout << ss[j] << " vs " << i << std::endl;

                            xx.clear();
                            xx.insert(xx.end(), x.begin(), x.end());
                            auto s2 = sig[ss[j]];
                            xx.insert(xx.end(), s2.begin(), s2.end());
                            std::sort(xx.begin(), xx.end());

                            u64 d = 0;
                            for (u64 t = 0; t < k; ++t)
                            {
                                if (xx[2 * t + 1] < xx[2 * t])
                                    throw RTE_LOC;
                                d += (xx[2 * t + 1] - xx[2 * t]);
                            }
                            if (d < minDis)
                            {
                                ii = { { i, ss[j] } };
                                minDis = d;
                                if (v)
                                    std::cout << minDis << std::endl;
                            }
                        }
                    }

                }
            }

            std::lock_guard<std::mutex> lock(mutex);
            std::cout << max << " " << minDis * 1.0 / N << " " << min0 *1.0 / N<<"   ( ";

            for (auto i : ii)
                std::cout << i << ", ";
            std::cout << " )" << std::endl;

            mm = std::min(mm, minDis);
            m0 = std::min(m0, min0);
        };
        for (u64 tIdx = 0; tIdx < nt; ++tIdx)
        {
            thrds[tIdx] = std::thread(
                [&,tIdx]{
                    Matrix<u64> sig(n, k);

                    for (u64 t = tIdx; t < tt; t += nt)
                    {
                        runOne(t, sig);
                    }
                });
        }

        for (u64 tIdx = 0; tIdx < nt; ++tIdx)
            thrds[tIdx].join();

        std::cout << "\n\n" << mm * 1.0 / N << " " << m0 * 1.0 / N  << std::endl;
    }
}