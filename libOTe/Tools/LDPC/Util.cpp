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
#include "LdpcSampler.h"

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

    bool isZero(const span<block>& sum)
    {
        for (auto& b : sum)
            if (b != oc::ZeroBlock)
            {
                return false;
                break;
            }
        return true;
    }
    bool isEq(const span<const block>& u, const span<const block>& v)
    {
        assert(u.size() == v.size());
        return memcmp(u.data(), v.data(), v.size_bytes()) == 0;
    }

    template <typename T>
    class queue
    {
    private:
        std::mutex              d_mutex;
        std::condition_variable d_condition;
        std::deque<T>           d_queue;
    public:
        void push(T const& value) {
            {
                std::unique_lock<std::mutex> lock(this->d_mutex);
                d_queue.push_front(value);
            }
            this->d_condition.notify_one();
        }
        T pop() {
            std::unique_lock<std::mutex> lock(this->d_mutex);
            this->d_condition.wait(lock, [=] { return !this->d_queue.empty(); });
            T rc(std::move(this->d_queue.back()));
            this->d_queue.pop_back();
            return rc;
        }
    };


    std::pair<double, std::vector<u64>> minDist(const DenseMtx& mtx, bool verbose, u64 numThreads)
    {
        assert(mtx.rows() < mtx.cols());

        u64 percision = 2;
        u64 p = (u64)std::pow(10, percision);


        std::mutex mut;
        queue<std::function<void()>> queue;
        std::vector<std::thread> thrds(numThreads);
        for (u64 i = 0; i < thrds.size(); ++i)
        {
            thrds[i] = std::thread([&queue]() {

                while (true)
                {
                    std::function<void()> fn =queue.pop();
                    
                    if (!fn)
                        return;
                    fn();
                }
                });
        }


        u64 dd = mtx.mData.cols();
#define ASSUME_DD_1
#ifdef ASSUME_DD_1
        if (dd != 1)
            throw RTE_LOC;
#endif
        for (u64 weight = 2; weight < mtx.rows(); ++weight)
        {
            auto total = choose(mtx.cols(), weight);
            u64 next = 0;
            std::atomic<u64> ii(0);
            //std::atomic<u64> rem = numThreads;

            bool done = false;
            using Ret = std::pair<double, std::vector<u64>>;
            std::vector<std::promise<Ret>> prom(numThreads);
            //auto fu = prom.get_future();



            for (u64 i = 0; i < numThreads; ++i)
            {
                queue.push([&, i, weight]() {


                    auto begin = i * total / numThreads;
                    auto end = (i + 1) * total / numThreads;
                    auto iter = NChooseK(mtx.cols(), weight, begin, end);
                    //u64& mI = iter.mI;
                    std::vector<u64> set;
#ifdef ASSUME_DD_1
                    block sum;
#else
                    std::vector<block> sum(dd);
#endif
                    while (begin++ != end && !done)
                    {
                        set = *iter;

                        if (verbose && ii >= next)
                        {
                            std::lock_guard<std::mutex> lock(mut);
                            if (verbose && ii >= next)
                            {
                                auto cur = ii * p / total;
                                next = (cur + 1) * total / p;;
                                std::cout << "\r" << weight << "." << std::setw(percision) << std::setfill('0') << cur << "       " << std::flush;
                            }
                        }
#ifdef ASSUME_DD_1
                        auto ptr = mtx.mData.data();
                        sum = ptr[set[0]];
                        for (u64 i = 1; i < weight; ++i)
                        {
                            auto col = ptr[set[i]];
                            sum = sum ^ col;
                        }

                        auto linDep = sum == oc::ZeroBlock;
#else

                        auto v = mtx.col(set[0]);
                        std::copy(v.data(), v.data() + dd, sum.data());

                        for (u64 i = 1; i < weight; ++i)
                        {
                            auto col = mtx.col(set[i]);
                            for (u64 j = 0; j < dd; ++j)
                                sum[j] = sum[j] ^ col[j];
                        }

                        auto linDep = isZero(sum);
#endif
                        if (linDep)
                        {
                            std::lock_guard<std::mutex> lock(mut);
                            if (verbose)
                            {
                                std::cout << std::endl;
                            }
                            done = true;

                            prom[i].set_value(std::make_pair(weight + ii / double(total), set));
                            return;
                        }

                        ++ii;


                        //++iter;
                        {
                            //++(mI);
                            //assert(mI <= iter.mEnd);

                            u64 i = 0;
                            while (i < iter.mK - 1 && iter.mSet[i] + 1 == iter.mSet[i + 1])
                                ++i;

                            ++iter.mSet[i];
                            for (u64 j = 0; j < i; ++j)
                                iter.mSet[j] = j;
                        }
                    }

                    prom[i].set_value({});
                    return;
                    });
            }


            Ret ret;
            for (u64 i = 0; i < numThreads; ++i)
            {
                auto cc = prom[i].get_future().get();
                if (cc.second.size())
                    ret = cc;
            }

            if (done)
            {
                for (u64 i = 0; i < numThreads; ++i)
                    queue.push({});
                for (u64 i = 0; i < numThreads; ++i)
                    thrds[i].join();
                return ret;
            }

        }
        assert(0);
        return {};
    }

    std::pair<double, std::vector<u64>> minDist(const DenseMtx& mtx, bool verbose)
    {
        assert(mtx.rows() < mtx.cols());

        u64 percision = 2;
        u64 p = (u64) pow(10, percision);

        for (u64 weight = 2; weight < mtx.rows(); ++weight)
        {
            auto iter = NChooseK(mtx.cols(), weight);
            auto total = choose(mtx.cols(), weight);
            u64 prev = -1;
            u64 ii = 0;
            std::vector<block> sum(mtx.mData.cols());

            while (iter)
            {
                auto& set = *iter;

                auto cur = ii * p / total;
                if (verbose && prev != cur)
                {
                    prev = cur;
                    std::cout << "\r" << weight << "." << std::setw(percision) << std::setfill('0') << cur << "       " << std::flush;
                }

                auto v = mtx.col(set[0]);
                std::copy(v.begin(), v.end(), sum.begin());

                for (u64 i = 1; i < set.size(); ++i)
                {
                    auto col = mtx.col(set[i]);
                    for (u64 j = 0; j < sum.size(); ++j)
                        sum[j] = sum[j] ^ col[j];
                }

                if (isZero(sum))
                {
                    if (verbose)
                        std::cout << std::endl;
                    return std::make_pair(weight + ii / double(total), set);
                }

                ++ii;
                ++iter;
            }
        }
        assert(0);
        return {};
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
                    //std::cout << mtx << std::endl;
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



    namespace tests
    {
        void computeGen_test(const oc::CLP& cmd)
        {
            u64 n = 30;
            u64 k = n / 4;
            u64 m = n - k;
            u64 t = 100;

            oc::PRNG prng(block(cmd.getOr("s", 0), 0));

            DenseMtx W(t, k);

            for (u64 i = 0; i < W.rows(); ++i)
                for (u64 j = 0; j < W.cols(); ++j)
                    W(i, j) = prng.getBit();

            DenseMtx H(m, n), G;

            while (G.rows() == 0)
            {
                for (u64 i = 0; i < H.rows(); ++i)
                {
                    //H(i, k + i) = 1;

                    for (u64 j = 0; j < H.cols(); ++j)
                        H(i, j) = prng.getBit();
                }

                G = computeGen(H);
            }

            //std::cout << H << std::endl;
            //std::cout << G << std::endl;

            auto C = W * G;

            auto S = H * C.transpose();

            for (u64 i = 0; i < S.rows(); ++i)
                for (u64 j = 0; j < S.cols(); ++j)
                    assert(S(i, j) == 0);
        }


        void computeGen_test2(const oc::CLP& cmd)
        {
            u64 n = 100;
            u64 k = n / 4;
            u64 m = n - k;
            u64 t = 100;

            oc::PRNG prng(block(cmd.getOr("s", 0), 0));

            DenseMtx W(t, k);

            for (u64 i = 0; i < W.rows(); ++i)
                for (u64 j = 0; j < W.cols(); ++j)
                    W(i, j) = prng.getBit();

            DenseMtx H(m, n), G;
            std::vector<std::pair<u64, u64>> swaps;

            while (G.rows() == 0)
            {
                for (u64 i = 0; i < H.rows(); ++i)
                {
                    //H(i, k + i) = 1;

                    for (u64 j = 0; j < H.cols(); ++j)
                        H(i, j) = prng.getBit();
                }

                G = computeGen(H, swaps);
            }



            //std::cout << H << std::endl;
            //std::cout << G << std::endl;

            auto C = W * G;

            for(auto s : swaps)
            {
                auto c0 = C.col(s.first);
                auto c1 = C.col(s.second);
                std::swap_ranges(c0.begin(), c0.end(), c1.begin());
            }

            auto S = H * C.transpose();

            for (u64 i = 0; i < S.rows(); ++i)
                for (u64 j = 0; j < S.cols(); ++j)
                    assert(S(i, j) == 0);
        }
    }

    struct selectPrt
    {
        const DenseMtx& mMtx;
        const std::vector<u64>& mCols;

        selectPrt(const DenseMtx& m, const std::vector<u64>& c)
            : mMtx(m)
            , mCols(c)
        {}
    };

    std::ostream& operator<<(std::ostream& o, const selectPrt& p)
    {
        for (u64 i = 0; i < p.mMtx.rows(); ++i)
        {
            auto iter = p.mCols.begin();
            for (u64 j = 0; j < p.mMtx.cols(); ++j)
            {
                if (iter != p.mCols.end() && *iter == j)
                    o << oc::Color::Green;

                o << p.mMtx(i, j) << " ";

                if (iter != p.mCols.end() && *iter == j)
                {
                    o << oc::Color::Default;
                    ++iter;
                }
            }

            o << std::endl;
        }
        return o;
    }

    //
    //DenseMtx uniformFixedColWeight(u64 rows, u64 cols, u64 w, PRNG& prng)
    //{
    //    DenseMtx mtx(rows, cols);
    //    mtx.setZero();
    //    std::vector<u64> rem; rem.reserve(cols * w);
    //    for (u64 i = 0; i < cols; ++i)
    //    {
    //        for (u64 j = 0; j < w; ++j)
    //            rem.push_back(i);
    //    }
    //
    //    std::shuffle(rem.begin(), rem.end(), prng);
    //
    //    while (rem.size())
    //    {
    //        auto i = prng.get<u64>() % rows;
    //        mtx(i, rem.back()) = 1;
    //        rem.pop_back();
    //    }
    //    return mtx;
    //}

    void rank(oc::CLP& cmd)
    {

        //u64 n = 6, k = 4;

        //NChooseK nCk(n, k);
        //u64 i = 0;
        //while (nCk)
        //{
        //    auto set0 = *nCk;
        //    auto set1 = ithCombination(i, n, k);

        //    std::cout << i << ":\n";
        //    for (u64 j = 0; j < k; ++j)
        //        std::cout << set0[j] << " ";
        //    std::cout << "  \n";
        //    for (u64 j = 0; j < k; ++j)
        //        std::cout << set1[j] << " ";
        //    std::cout << std::endl;

        //    ++i;
        //    ++nCk;
        //}
        //return;

        u64 rows = cmd.getOr("m", 20);
        u64 cols = static_cast<u64>(rows * cmd.getOr("e", 2.0));
        u64 weight = cmd.getOr("w", 4);
        auto gaps = cmd.getManyOr<u64>("g", { 0 });

        u64 trials = cmd.getOr("t", 1);
        bool verbose = cmd.isSet("v");
        u64 thrds = cmd.getOr("thrds", std::thread::hardware_concurrency());

        assert(cols > rows);
        assert(rows > weight);
        oc::PRNG prng(block(0, cmd.getOr("s", 0)));

        DenseMtx mtx(rows, cols);

        for (auto gap : gaps)
        {

            u64 dWeight = cmd.getOr("wd", (1 + gap) / 2);
            double avg = 0;

            for (u64 t = 0; t < trials; ++t)
            {
                mtx.setZero();


                if (gap)
                {
                    mtx = sampleTriangularBand(
                        rows, cols, weight, gap, dWeight, false, prng).dense();
                }
                else
                {
                    mtx = sampleFixedColWeight(rows, cols, weight, prng, false).dense();

                }

                auto d = minDist(mtx, verbose, thrds);

                if (verbose)
                {
                    std::cout << " " << d.first;
                    std::cout << "\n" << selectPrt(mtx, d.second) << std::endl;
                }

                avg += d.first;
            }


            std::cout << " ~~ " << gap << " " << avg / trials << std::endl;

        }
        //std::cout << "minDist = " << d.size() << std::endl
        //    << "[";
        //for (u64 i = 0; i < d.size(); ++i)
        //    std::cout << d[i] << " ";
        //std::cout << "]" << std::endl;


        //std::cout << selectPrt(mtx, d) << std::endl;

        //auto m2 = mtx.block(0, 0, rows, rows).transpose();
        //std::cout << m2 << std::endl << std::endl;

        //auto m3 = gaussianElim(m2);

        //std::cout << m3 << std::endl << std::endl;

        //auto r = rank(m3);
        //std::cout << "rank " << r << " / " << m3.rows() << std::endl;
        return;
        //Matrix5x3 m = Matrix5x3::Random();
        //std::cout << "Here is the matrix m:" << endl << m << endl;
        //Eigen::FullPivLU<Mtx> lu(mtx);
        //std::cout << "Here is, up to permutations, its LU decomposition matrix:"
        //    << std::endl << lu.matrixLU() << std::endl;
        //std::cout << "Here is the L part:" << std::endl;
        //Mtx l = Mtx::Identity();
        //l.block<5, 3>(0, 0).triangularView<StrictlyLower>() = lu.matrixLU();
        //cout << l << endl;
        //cout << "Here is the U part:" << endl;
        //Matrix5x3 u = lu.matrixLU().triangularView<Upper>();
        //cout << u << endl;
        //cout << "Let us now reconstruct the original matrix m:" << endl;
        //cout << lu.permutationP().inverse() * l * u * lu.permutationQ().inverse() << endl;
    }
}