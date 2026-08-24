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
#include <cstdio>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>

#include "Mtx.h"
#include <deque>

#ifdef ENABLE_ALGO994
extern "C" {
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/generations.h"
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
}
#endif

namespace osuCrypto
{

    namespace
    {
        // Computes C(n, k) when it is at most limit. If it is larger than
        // limit, returns true without overflowing the intermediate product.
        bool chooseExceeds(u64 n, u64 k, u64 limit, u64& value)
        {
            if (k > n)
            {
                value = 0;
                return false;
            }

            k = std::min(k, n - k);
            value = 1;
            if (k == 0)
                return value > limit;

            for (u64 i = 1; i <= k; ++i)
            {
                auto numerator = n - k + i;
                auto denominator = i;

                auto g = std::gcd(numerator, denominator);
                numerator /= g;
                denominator /= g;

                g = std::gcd(value, denominator);
                value /= g;
                denominator /= g;

                if (denominator != 1)
                    throw std::logic_error("Invalid binomial reduction. " LOCATION);
                if (numerator && value > limit / numerator)
                    return true;

                value *= numerator;
            }
            return false;
        }

#ifdef ENABLE_ALGO994
        struct TempFileCleanup
        {
            std::filesystem::path mPath;

            ~TempFileCleanup()
            {
                std::error_code ec;
                std::filesystem::remove(mPath, ec);
            }
        };

        using FilePtr = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

        std::pair<std::filesystem::path, FilePtr> openUniqueTempFile()
        {
            PRNG prng(sysRandomSeed());
            auto dir = std::filesystem::temp_directory_path();

            for (u64 attempt = 0; attempt < 32; ++attempt)
            {
                std::ostringstream name;
                name << "libote-min-dist-" << std::hex << std::setfill('0')
                    << std::setw(16) << prng.get<u64>()
                    << std::setw(16) << prng.get<u64>() << ".txt";
                auto path = dir / name.str();

                std::FILE* raw = nullptr;
#ifdef _WIN32
                if (fopen_s(&raw, path.string().c_str(), "wbx") == 0)
#else
                raw = std::fopen(path.string().c_str(), "wbx");
                if (raw)
#endif
                    return std::make_pair(std::move(path), FilePtr(raw, &std::fclose));
            }

            throw std::runtime_error("Failed to create a unique minimum-distance input file. " LOCATION);
        }
#endif
    }




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

        if (numTHreads == 0 || numTHreads > static_cast<u64>(std::numeric_limits<int>::max()))
            throw std::invalid_argument("Minimum-distance thread count is out of range. " LOCATION);

        static std::mutex backendMutex;
        std::lock_guard<std::mutex> lock(backendMutex);

        char* inputMatrix = nullptr;
        int   info, k = 0, n = 0, dist;
        num_cores = static_cast<int>(numTHreads);
        print_matrices = verbose ? 1 : 0;

        // Read input matrix.
        info = read_char_matrix((char*)path.c_str(), &inputMatrix, &k, &n);
        if (info != 0) {
            std::free(inputMatrix);
            throw std::runtime_error("Failed to read the minimum-distance input matrix. " LOCATION);
        }
        if (inputMatrix == nullptr || k < 0 || n < 0 || k > n)
        {
            std::free(inputMatrix);
            throw std::runtime_error("Minimum-distance input matrix has invalid dimensions. " LOCATION);
        }

        std::unique_ptr<char, decltype(&std::free)> matrix(inputMatrix, &std::free);

        if (!(
            alg994 == ALG_BASIC || // 1
            alg994 == ALG_OPTIMIZED || // 2
            alg994 == ALG_STACK || // 3
            alg994 == ALG_SAVED || // 4
            alg994 == ALG_SAVED_UNROLLED || // 5
            alg994 == ALG_GRAY  // 10
            ))
            throw std::invalid_argument("Unsupported minimum-distance algorithm. " LOCATION);

        // Compute distance of input matrix.
        dist = compute_distance_of_matrix_impl(matrix.get(), k, n,
            alg994,
            num_saved_generators,
            num_cores,
            num_permutations,
            print_matrices);

        return dist;
#else
        throw std::runtime_error("also 994 not enabled. " LOCATION);
#endif
    }

    int minDist2(const DenseMtx& mtx, u64 nt, bool verbose)
    {
#ifdef ENABLE_ALGO994
        std::vector<std::pair<u64, u64>> swaps;
        auto G = computeGen(mtx, swaps);
        if (G.rows() == 0)
            throw std::invalid_argument("Matrix cannot be converted to generator form. " LOCATION);

        std::ostringstream encoded;
        encoded << G.rows() << " " << G.cols() << " matrix dimensions\n"
            << G << std::endl;
        auto payload = encoded.str();

        auto opened = openUniqueTempFile();
        TempFileCleanup cleanup{ opened.first };
        auto file = std::move(opened.second);
        if (std::fwrite(payload.data(), 1, payload.size(), file.get()) != payload.size())
            throw std::runtime_error("Failed to write the minimum-distance input matrix. " LOCATION);
        if (std::fclose(file.release()) != 0)
            throw std::runtime_error("Failed to close the minimum-distance input matrix. " LOCATION);

        return minDist(opened.first.string(), nt, verbose);
#else
        (void)mtx;
        (void)nt;
        (void)verbose;
        throw std::runtime_error("algo 994 not enabled. " LOCATION);
#endif
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
        auto k = static_cast<u64>(set.size());
        if (k > n)
            throw std::invalid_argument("Combination size exceeds its domain. " LOCATION);

        auto total = choose(n, k);
        if (index >= total)
            throw std::out_of_range("Combination index is out of range. " LOCATION);

        auto remaining = index;
        auto upper = n;
        for (u64 kk = k; kk != 0; --kk)
        {
            if (upper < kk)
                throw std::logic_error("Invalid combination decomposition. " LOCATION);

            auto low = kk - 1;
            auto high = upper - 1;
            while (low < high)
            {
                auto mid = low + (high - low + 1) / 2;
                u64 candidate = 0;
                auto exceeds = chooseExceeds(mid, kk, remaining, candidate);
                if (!exceeds)
                    low = mid;
                else
                    high = mid - 1;
            }

            u64 contribution = 0;
            if (low >= kk)
            {
                if (chooseExceeds(low, kk, remaining, contribution))
                    throw std::logic_error("Invalid combination decomposition. " LOCATION);
            }
            set[kk - 1] = low;
            remaining -= contribution;
            upper = low;
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
        if (k > n)
            throw std::invalid_argument("Combination size exceeds its domain. " LOCATION);

        u64 value = 0;
        if (chooseExceeds(n, k, std::numeric_limits<u64>::max(), value))
            throw std::overflow_error("Binomial coefficient exceeds 64 bits. " LOCATION);
        return value;
    }



    DenseMtx computeGen(DenseMtx& H)
    {
        if (H.rows() >= H.cols())
            throw std::invalid_argument("Parity-check matrix must have fewer rows than columns. " LOCATION);

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
        if (H.rows() >= H.cols())
            throw std::invalid_argument("Parity-check matrix must have fewer rows than columns. " LOCATION);

        auto n = H.cols();
        auto m = H.rows();
        auto k = n - m;
        std::vector<std::pair<u64, u64>> swaps;

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
                                swaps.push_back({ col,col2 });
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


        colSwaps = std::move(swaps);
        return G;
    }

    DenseMtx colSwap(DenseMtx G, std::vector<std::pair<u64, u64>>& swaps)
    {
        for (auto s : swaps)
        {
            if (s.first >= G.cols() || s.second >= G.cols())
                throw std::invalid_argument("Generator column swap index is out of range. " LOCATION);
        }

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
        if (k > n)
            throw std::invalid_argument("Generator matrix has more rows than columns. " LOCATION);
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
