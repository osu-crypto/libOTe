#include "EAChecker.h"
#include <thread>

//#define USE_ANKERL_HASH
#ifdef USE_ANKERL_HASH
#include "out/unordered_dense/include/ankerl/unordered_dense.h"
#endif
namespace osuCrypto
{

    u64 hash(span<u64> mIdx, u64 b, u64 N)
    {
        block hh = ZeroBlock;
        for (u64 j = 0; j < mIdx.size(); ++j)
            hh = hh ^ mAesFixedKey.ecbEncBlock(block(mIdx[j], j));
        return hh.get<u64>(0);
    }

    // approx hash
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

            block hh = ZeroBlock;
            for (u64 j = 0; j < bb.size(); ++j)
                hh = hh ^ mAesFixedKey.ecbEncBlock(block(bb[j], j));
            H.push_back(hh.get<u64>(0));
        }
        return H;
    }


    // the (psuedo) minimum distance finder for EA codes.
    // section 4.2 https://eprint.iacr.org/2023/882
    void EAChecker(CLP& cmd)
    {
        u64 seed = cmd.getOr("s", 0);

        // trials
        u64 tt = cmd.getOr("t", 1);

        // threads
        u64 nt = cmd.getOr("nt", 1);

        // message size
        u64 n = cmd.getOr("n", 1ull<< cmd.getOr("nn", 10));

        // expansion factor
        u64 e = cmd.getOr("e", 5);

        // code size
        u64 N = n * e;

        // expander weight
        u64 bw = cmd.getOr("bw", 7);

        // number of bins
        u64 b = cmd.getOr("b", 50);

        // verbose
        bool v = cmd.isSet("v");

        // if an element is d close to a bin boundary, it is considered to be in both bins.
        double d = cmd.getOr("d", 0.25);

        // if true, consider all combinations of rows that hash to the same bin.
        bool highWeight = cmd.isSet("hw");

        // allow collisisons in the expander
        bool allowCollisions = cmd.isSet("ac");

        // regular expander
        bool regular = cmd.getOr("reg", 0);

        std::vector<std::thread> thrds(nt);
        std::mutex mutex;
        u64 gMinDist = -1, gMinDistSingle = -1;
        auto runOne = [&](u64 t, Matrix<u64>& sig) {

            std::vector<u64> xx(2 * bw), ii;;

            // the set of hashes that represent almost collissions
#ifdef USE_ANKERL_HASH
            ankerl::unordered_dense::map<u64, std::vector<u64>> sets;
#else
            std::unordered_map<u64, std::vector<u64>> sets;
#endif

            // current best min dist.
            u64 minDis = N;

            u64 minDistSingle = N;
            // maxBinSize bin size
            u64 maxBinSize = 0;
            //u64 maxBinSize = 0, minDis = N, min0 = -1;
            PRNG prng(block(seed, t));

            u64 step = n / bw;

            for (u64 i = 0; i < n; ++i)
            {
                // sample the row
                span<u64> x = sig[i];

                if (regular)
                {
                    for (u64 j = 0; j < bw; ++j)
                    {
                        x[j] = prng.get<u64>() % step + j * step;
                    }
                }
                else if (allowCollisions)
                {
                    for (u64 j = 0; j < bw; ++j)
                    {
                        x[j] = prng.get<u64>() % N;
                    }
                }
                else
                {
                    for (u64 j = 0; j < bw; ++j)
                    {
                        x[j] = prng.get<u64>() % N;
                        auto end = x.begin() + j;
                        while(std::find(x.begin(), end, x[j]) != end)
                            x[j] = prng.get<u64>() % N;
                    }
                }
                std::sort(x.begin(), x.end());

                // minimum distance of this item alone
                u64 mm0 = 0;
                for (u64 j = 0; j < bw - 1; j += 2)
                {
                    mm0 += x[j + 1] - x[j];
                }
                if (bw & 1)
                    mm0 += N - x.back();
                minDistSingle = std::min(minDistSingle, mm0);

                // hash the row and see if there are any similar rows.
                auto H = ahash(sig[i], b, N, d, false);

                for (auto h : H)
                {
                    auto& ss = sets[h];
                    ss.push_back(i);
                    if (ss.size() > maxBinSize)
                    {
                        maxBinSize = ss.size();

                        if (v)
                            std::cout << "maxBinSize " << maxBinSize << " " << i << std::endl;
                    }

                    // consider all combinations of rows that hash to the same bin.
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
                                    std::cout << "minDis " << minDis << std::endl;
                            }
                        }
                    }
                    else
                    {

                        // compare this row to all other rows that hash to the same bin.
                        for (u64 j = 0; j < ss.size() - 1; ++j)
                        {
                            xx.clear();
                            auto& x2 = sig[ss[j]];
                            std::merge(x.begin(), x.end(), x2.begin(), x2.end(), std::back_inserter(xx));
                            //xx.insert(xx.end(), x.begin(), x.end());
                            //auto s2 = sig[ss[j]];
                            //xx.insert(xx.end(), s2.begin(), s2.end());
                            //std::sort(xx.begin(), xx.end());

                            u64 d = 0;
                            for (u64 t = 0; t < bw; ++t)
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
                                    std::cout << "minDis " << minDis << std::endl;
                            }
                        }
                    }

                }
            }

            std::lock_guard<std::mutex> lock(mutex);
            std::cout <<"maxBinSize: " << maxBinSize << ", minDis: " << minDis * 1.0 / N << ", minDistSingle: " << minDistSingle * 1.0 / N << "   ( ";

            for (auto i : ii)
                std::cout << i << ", ";
            std::cout << " )" << std::endl;

            gMinDist = std::min(gMinDist, minDis);
            gMinDistSingle = std::min(gMinDistSingle, minDistSingle);

            std::cout << "size " << double(sets.size())/n << std::endl;
        };

        for (u64 tIdx = 0; tIdx < nt; ++tIdx)
        {
            thrds[tIdx] = std::thread(
                [&, tIdx] {
                    Matrix<u64> sig(n, bw);

                    for (u64 t = tIdx; t < tt; t += nt)
                    {
                        runOne(t, sig);
                    }
                });
        }

        for (u64 tIdx = 0; tIdx < nt; ++tIdx)
            thrds[tIdx].join();

        std::cout << "\n\ngMinDist:" << gMinDist * 1.0 / N << " gMinDistSingle: " << gMinDistSingle * 1.0 / N << std::endl;
    }
}