#include "Util.h"
//#include <Eigen/Dense>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"
#include <numeric>
#include <iomanip>
#include <future>
#include <cmath>

#include "Mtx.h"
#include <deque>

#ifdef ENABLE_ALGO994
extern "C" {
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/generations.h"
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
}
#endif

#include <fstream>

namespace osuCrypto
{




    //using Mtx = Eigen::Matrix<int, Eigen::Dynamic, Eigen::Dynamic>;

#ifdef ENABLE_ALGO994
    int alg994 = ALG_SAVED_UNROLLED;
    int num_saved_generators =  5;
    int num_cores = 4;
    int num_permutations = 5;
    int print_matrices = 0;
#endif

    int minDist(std::string path, u64 numTHreads, bool verbose)
    {
#ifdef ENABLE_ALGO994

        char* inputMatrix;
        int   info, k, n, dist;
        num_cores = numTHreads;

        // Read input matrix.
        info = read_char_matrix((char*)path.c_str(), &inputMatrix, &k, &n);
        if (info != 0) {
            fprintf(stderr, "\n");
            fprintf(stderr, "ERROR in read_char_matrix: ");
            fprintf(stderr, "Error while reading input file with matrix.\n\n\n");
        }

        assert(
            alg994 == ALG_BASIC || // 1
            alg994 == ALG_OPTIMIZED || // 2
            alg994 == ALG_STACK || // 3
            alg994 == ALG_SAVED || // 4
            alg994 == ALG_SAVED_UNROLLED || // 5
            alg994 == ALG_GRAY  // 10
        );

        // Compute distance of input matrix.
        dist = compute_distance_of_matrix_impl(inputMatrix, k, n,
            alg994,
            num_saved_generators,
            num_cores,
            num_permutations,
            print_matrices);

        // Remove matrices.
        free(inputMatrix);

        return dist;
#else
        throw std::runtime_error("also 994 not enabled. " LOCATION);
#endif
    }

    int minDist2(const DenseMtx& mtx, u64 nt, bool verbose)
    {
        std::string outPath("./deleteMe");
        std::fstream out(outPath, std::fstream::trunc | std::fstream::out);

        if (out.is_open() == false)
        {
            std::cout << "failed to open: " << outPath << std::endl;
            return 0;
        }

        std::vector<std::pair<u64, u64>> swaps;
        auto G = computeGen(mtx, swaps);

        out << G.rows() << " " << G.cols() << " matrix dimensions\n"
            << G << std::endl;

        out.close();

        u64 d;

        d = minDist(outPath, nt, false);

        std::remove(outPath.c_str());
        return (int)d;
    }


    u64 numNonzeroRows(const DenseMtx& mtx)
    {
        u64 r = 0;
        for (u64 i = 0; i < mtx.rows(); ++i)
        {
            if (mtx.row(i).isZero())
                ++r;
        }

        return mtx.rows() - r;
    }

    //u64 rank(const DenseMtx& mtx)
    //{
    //    DenseMtx m2 = gaussianElim(mtx);
    //    return numNonzeroRows(m2);
    //}

    void ithCombination(u64 index, u64 n, std::vector<u64>& set)
    {
        //'''Yields the items of the single combination that would be at the provided
        //(0-based) index in a lexicographically sorted list of combinations of choices
        //of k items from n items [0,n), given the combinations were sorted in 
        //descending order. Yields in descending order.
        //'''
        u64 nCk = 1;
        u64 nMinusI = n;
        u64 iPlus1 = 1;

        auto k = set.size();

        // nMinusI, iPlus1 in zip(range(n, n - k, -1), range(1, k + 1)):
        for (; nMinusI != n - k; --nMinusI, ++iPlus1)
        {
            nCk *= nMinusI;
            nCk /= iPlus1;
        }

        //std::cout << "nCk " << nCk << std::endl;

        auto curIndex = nCk;
        for (auto kk = k; kk != 0ull; --kk)//in range(k, 0, -1):
        {
            //std::cout << "kk " << kk << " " <<  nCk << std::endl;
            nCk *= kk;
            nCk /= n;
            while (curIndex - nCk > index) {
                curIndex -= nCk;
                nCk *= (n - kk);
                nCk -= nCk % kk;
                n -= 1;
                nCk /= n;
            }
            n -= 1;

            set[kk - 1] = n;
        }
    }


    std::vector<u64> ithCombination(u64 index, u64 n, u64 k)
    {
        std::vector<u64> set(k);
        ithCombination(index, n, set);
        return set;
    }

    u64 choose(u64 n, u64 k)
    {
        if (k == 0) return 1;
        return (n * choose(n - 1, k - 1)) / k;
    }



    DenseMtx computeGen(DenseMtx& H)
    {
        assert(H.rows() < H.cols());

        auto n = H.cols();
        auto m = H.rows();
        auto k = n - m;

        auto mtx = H.subMatrix(0, k, m, m);

        auto P = H.subMatrix(0, 0, m, k);

        for (u64 i = 0; i < m; ++i)
        {
            if (mtx(i, i) == 0)
            {
                for (u64 j = i + 1; j < m; ++j)
                {
                    if (mtx(j, i) == 1)
                    {
                        mtx.row(i).swap(mtx.row(j));
                        P.row(i).swap(P.row(j));
                        break;
                    }
                }

                if (mtx(i, i) == 0)
                {
                    std::cout << mtx << std::endl;
                    return {};
                }
            }

            for (u64 j = 0; j < m; ++j)
            {
                if (j != i && mtx(j, i))
                {
                    for (u64 l = 0; l < m; ++l)
                    {
                        mtx(j, l) ^= mtx(i, l);
                    }

                    for (u64 l = 0; l < k; ++l)
                        P(j, l) ^= P(i, l);
                }
            }

        }


        DenseMtx G(k, n);
        for (u64 i = 0; i < k; ++i)
            G(i, i) = 1;

        for (u64 i = 0; i < m; ++i)
        {
            for (u64 j = 0; j < k; ++j)
            {
                G(j, i + k) = P(i, j);
            }
        }


        return G;
    }



    DenseMtx computeGen(DenseMtx H, std::vector<std::pair<u64, u64>>& colSwaps)
    {
        assert(H.rows() < H.cols());

        auto n = H.cols();
        auto m = H.rows();
        auto k = n - m;
        colSwaps.clear();

        for (u64 row = 0, col = k; row < m; ++row, ++col)
        {
            //std::cout << row << std::endl << H << std::endl;;

            if (H(row, col) == 0)
            {
                bool found = false;
                // look fow a row swap
                for (u64 row2 = row + 1; row2 < m && found == false; ++row2)
                {
                    if (H(row2, col) == 1)
                    {
                        H.row(row).swap(H.row(row2));
                        found = true;
                    }
                }


                if (found == false)
                {
                    // look for a col swap

                    for (u64 col2 = 0; col2 < k && found == false; ++col2)
                    {
                        for (u64 row2 = row; row2 < m && found == false; ++row2)
                        {
                            if (H(row2, col2) == 1)
                            {
                                H.row(row).swap(H.row(row2));

                                // swap columns.
                                colSwaps.push_back({ col,col2 });
                                auto c0 = H.col(col);
                                auto c1 = H.col(col2);
                                std::swap_ranges(c0.begin(), c0.end(), c1.begin());
                                found = true;
                            }
                        }
                    }
                }

                if (found == false)
                {
                    // can not be put in systematic form.
                    //std::cout  << H << std::endl;

                    return {};
                }
            }


            // clear all other ones from the current column. 
            for (u64 row2 = 0; row2 < m; ++row2)
            {
                if (row2 != row && H(row2, col))
                {
                    // row2 = row ^ row2
                    for (u64 col2 = 0; col2 < n; ++col2)
                    {
                        H(row2, col2) ^= H(row, col2);
                    }
                }
            }

        }

        auto P = H.subMatrix(0, 0, m, k);

        DenseMtx G(k, n);
        for (u64 i = 0; i < k; ++i)
            G(i, i) = 1;

        for (u64 i = 0; i < m; ++i)
        {
            for (u64 j = 0; j < k; ++j)
            {
                G(j, i + k) = P(i, j);
            }
        }


        return G;
    }

    DenseMtx colSwap(DenseMtx G, std::vector<std::pair<u64, u64>>& swaps)
    {
        for (auto s : swaps)
        {
            auto col = s.first;
            auto col2 = s.second;

            auto c0 = G.col(col);
            auto c1 = G.col(col2);
            std::swap_ranges(c0.begin(), c0.end(), c1.begin());
        }
        return G;
    }

    DenseMtx computeSysGen(DenseMtx G)
    {
        auto n = G.cols();
        auto k = G.rows();
        //auto m = n - k;

        for (u64 row = 0, col = 0; row < k; ++row, ++col)
        {
            //std::cout << row << std::endl << H << std::endl;;

            if (G(row, col) == 0)
            {
                bool found = false;
                // look row a row swap
                for (u64 row2 = row + 1; row2 < k && found == false; ++row2)
                {
                    if (G(row2, col) == 1)
                    {
                        G.row(row).swap(G.row(row2));
                        found = true;
                    }
                }


                //if (found == false)
                //{
                //    // look for a col swap

                //    for (u64 col2 = 0; col2 < k && found == false; ++col2)
                //    {
                //        for (u64 row2 = row; row2 < m && found == false; ++row2)
                //        {
                //            if (H(row2, col2) == 1)
                //            {
                //                H.row(row).swap(H.row(row2));

                //                // swap columns.
                //                colSwaps.push_back({ col,col2 });
                //                auto c0 = H.col(col);
                //                auto c1 = H.col(col2);
                //                std::swap_ranges(c0.begin(), c0.end(), c1.begin());
                //                found = true;
                //            }
                //        }
                //    }
                //}

                if (found == false)
                {
                    // can not be put in systematic form.
                    std::cout <<"can not be put in systematic form.\n" << G << std::endl;

                    return {};
                }
            }


            // clear all other ones from the current column. 
            for (u64 row2 = 0; row2 < k; ++row2)
            {
                if (row2 != row && G(row2, col))
                {
                    // row2 = row ^ row2
                    for (u64 col2 = 0; col2 < n; ++col2)
                    {
                        G(row2, col2) ^= G(row, col2);
                    }
                }
            }

        }

        //auto P = H.subMatrix(0, 0, m, k);

        //DenseMtx G(k, n);
        //for (u64 i = 0; i < k; ++i)
        //    G(i, i) = 1;

        //for (u64 i = 0; i < m; ++i)
        //{
        //    for (u64 j = 0; j < k; ++j)
        //    {
        //        G(j, i + k) = P(i, j);
        //    }
        //}


        return G;
    }

}