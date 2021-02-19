#pragma once

#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Matrix.h"
//#include "C:\libs\eigen\Eigen\SparseCore"
#include <cassert>
#include <unordered_set>
#include <algorithm>

namespace osuCrypto
{
    void ldpc(CLP& cmd);

    template<typename T>
    struct diff
    {
        T& mL, & mR;
        std::vector<u64> mRIdx, mCIdx;
        std::vector<u64>* mWeights;
        diff(T& l, T& r, std::vector<u64> rIdx, std::vector<u64> cIdx, std::vector<u64>* weights = nullptr)
            :mL(l), mR(r), mRIdx(rIdx), mCIdx(cIdx)
            , mWeights(weights)
        {}

    };

    class LDPC
    {
    public:

        using Diff = diff<LDPC>;


        struct Columns
        {
            struct Column
            {
                Column() = delete;
                Column(const Column&) = delete;
                Column(Column&&) = delete;

                u64 mSize;
                u64* mExtra;


                span<u64> getMain(u64 width) {
                    auto b = ((u64*)this) + 2;
                    return span<u64>(b, std::min(width, mSize));
                }
                span<u64> getExtra(u64 width)
                {
                    assert(width < mSize);
                    assert(mExtra);
                    return span<u64>(mExtra, mSize - width);
                }

                u64* find(u64 row, u64 width)
                {
                    auto m = getMain(width);
                    for (auto& r : m)
                    {
                        if (row == r)
                            return &r;
                    }

                    if (mSize > width)
                    {
                        auto e = getExtra(width);
                        for (auto& r : e)
                            if (row == r)
                                return &r;
                    }

                    return nullptr;
                }

            };
            static_assert(sizeof(Column) == 2 * sizeof(u64), "s");
            Matrix<u64> mCore;
            std::vector<u64> mExtra;
            u64 mWidth;

            void init(u64 cols, span<std::array<u64, 2>> points, double scaling = 0);

            Column& col(u64 i)
            {
                return (*(Column*)&mCore(i, 0));
            }
            std::pair<bool, span<u64>> colMain(u64 i)
            {
                auto& c = col(i);
                return { c.mSize > mWidth, c.getMain(mWidth) };
            }

            span<u64> colExtra(u64 i)
            {
                return col(i).getExtra(mWidth);
            }
        };

        u64 mNumCols;
        Matrix<u64> mRows;
        Columns mColumns;
        //std::vector<u64> mColStartIdxs, mColData;


        std::pair<bool, span<u64>> colMain(u64 i)
        {
            return mColumns.colMain(i);
        }

        span<u64> colExtra(u64 i)
        {
            return mColumns.colExtra(i);
        }

        Columns::Column& col(u64 i)
        {
            return mColumns.col(i);
        }

        u64* colMinRowIdx(u64 i)
        {
            auto& col = mColumns.col(i);
            if (col.mSize)
            {
                auto m = col.getMain(mColumns.mWidth);
                auto min = std::min_element(m.begin(), m.end());
                if (col.mSize > mColumns.mWidth)
                {
                    auto e = col.getExtra(mColumns.mWidth);
                    auto min2 = std::min_element(e.begin(), e.end());
                    if (*min > * min2)
                        return &*min2;
                }
                return &*min;
            }
            return nullptr;
        }

        //std::vector<Column> mCols;
        LDPC() = default;
        LDPC(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points) {
            insert(rows, cols, rowWeight, points);
        }

        void insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points);

        void moveRows(u64 destIter, std::unordered_set<u64> srcRows);

        void swapRow(u64 r0, u64 r1);

        void moveCols(u64 destIter, std::unordered_set<u64> srcCols);

        void swapCol(u64 c0, u64 c1);

        u64 cols() const { return mNumCols; }
        u64 rows() const { return mRows.rows(); }

        // returns the hamming weight of row r where only the columns
        // indexed by { cBegin, ..., cols()-1 } are considered.
        u64 HamV(u64 r, u64 cBegin)
        {
            u64 h = 0;
            for (u64 i = 0; i < mRows.cols(); ++i)
            {
                auto col = mRows(r, i);
                h += (col >= cBegin);
            }
            return h;
        }


        void blockTriangulate(
            std::vector<u64>& R,
            std::vector<u64>& C,
            bool verbose);


        u64 rowWeight()
        {
            return mRows.cols();
        }

        void validate();

    };





    //class LDPC2
    //{
    //public:

    //    using diff = diff<LDPC2>;

    //    u64 mNumCols;
    //    Matrix<u64> mRows;
    //    std::vector<u64> mColStartIdxs, mColData;


    //    span<u64> col(u64 i)
    //    {
    //        auto b = mColStartIdxs[i];
    //        auto e = mColStartIdxs[i + 1];

    //        return span<u64>(mColData.data() + b, e - b);
    //    }


    //    LDPC2() = default;
    //    LDPC2(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points) { insert(rows, cols, rowWeight, points); }

    //    void insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points);

    //    u64 cols() const { return mNumCols; }
    //    u64 rows() const { return mRows.rows(); }



    //    void blockTriangulate(
    //        std::vector<u64>& R,
    //        std::vector<u64>& C,
    //        bool verbose,
    //        bool stats);

    //    u64 rowWeight()
    //    {
    //        return mRows.cols();
    //    }

    //    void validate();

    //};

    std::ostream& operator<<(std::ostream& o, const LDPC& s);

}