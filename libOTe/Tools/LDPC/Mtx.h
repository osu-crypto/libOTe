#pragma once

#include <vector>
#include <array>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include <cassert>
#include <algorithm>
#include <set>

#include <iostream>

namespace osuCrypto
{
    struct Point
    {
        u64 mRow, mCol;
    };
    class SparseMtx;

    struct PointList
    {
        PointList(const PointList&) = default;
        PointList(PointList&&) = default;

        PointList(u64 r, u64 c)
            : mRows(r), mCols(c)
        {}

        PointList(u64 r, u64 c, span<const Point> pp)
            : mRows(r), mCols(c)
        {
            for (auto p : pp)
                push_back(p);
        }
        using iterator = std::vector<Point>::iterator;

        u64 mRows, mCols;
        std::vector<Point> mPoints;
#ifndef NDEBUG
        std::set<std::pair<u64, u64>> ss;
#endif
        void push_back(const Point& p)
        {

            if (p.mRow >= mRows)
            {
                std::cout << "row out of bounds " << p.mRow << " / " << mRows << std::endl;
                throw RTE_LOC;
            }

            if (p.mCol >= mCols)
            {
                std::cout << "col out of bounds " << p.mCol << " / " << mCols << std::endl;
                throw RTE_LOC;
            }
#ifndef NDEBUG
            if (ss.insert({ p.mRow , p.mCol }).second == false)
            {
                std::cout << "duplicate (" << p.mRow << ", " << p.mCol << ") " << std::endl;
                throw RTE_LOC;
            }
#endif

            mPoints.push_back(p);
        }


        operator span<Point>()
        {
            return mPoints;
        }

        iterator begin()
        {
            return mPoints.begin();
        }
        iterator end()
        {
            return mPoints.end();
        }

    };
    class DenseMtx;

    template<typename T>
    class Vec
    {
    public:
        std::vector<T> mData;

        Vec() = default;
        Vec(const Vec&) = default;
        Vec(Vec&&) = default;
        Vec& operator=(const Vec&) = default;
        Vec& operator=(Vec&&) = default;


        Vec(u64 size)
            :
            mData(size) {}

        void resize(u64 size)
        {
            mData.resize(size);
        }

        u64 size() const
        {
            return mData.size();
        }

        Vec subVec(u64 offset, u64 size)
        {
            Vec v;
            v.mData.insert(v.mData.end(), mData.begin() + offset, mData.begin() + offset + size);
            return v;
        }


        Vec operator+(const Vec& o) const
        {
            if (size() != o.size())
                throw RTE_LOC;

            Vec v = o;
            for (u64 i = 0; i < size(); ++i)
                v.mData[i] = v.mData[i] ^ mData[i];

            return v;
        }

        T& operator[](u64 i)
        {
            return mData[i];
        }
        const T& operator[](u64 i)const
        {
            return mData[i];
        }

        bool operator==(const Vec<T>& o) const
        {
            return mData == o.mData;
        }
        bool operator!=(const Vec<T>& o) const
        {
            return mData != o.mData;
        }
    };

    //template<typename T> 
    inline std::ostream& operator<<(std::ostream& o, const Vec<block>& v)
    {
        for (u64 i = 0; i < v.size(); ++i)
        {
            o << (v[i].as<u64>()[0] &1) << " ";
        }

        return o;
    }

    class SparseMtx
    {
    public:

        class Row : public span<u64>
        {
        public:
            Row() = default;
            Row(const Row& r) = default;
            Row& operator=(const Row& r) = default;


            explicit Row(const span<u64>& r) { (span<u64>&)* this = r; }
            //Row& operator=(const span<u64>& r) { (span<u64>&)* this = r; return *this; }
        };
        class Col : public span<u64>
        {
        public:
            Col() = default;
            Col(const Col& r) = default;
            Col& operator=(const Col& r) = default;

            explicit Col(const span<u64>& r) { (span<u64>&)* this = r; }
            //Col& operator=(const span<u64>& r) { (span<u64>&)* this = r; return *this; }
        };

        class ConstRow : public span<const u64>
        {
        public:
            ConstRow() = default;
            ConstRow(const ConstRow&) = default;
            ConstRow(const Row& r) : span<const u64>(r) { };

            ConstRow& operator=(const ConstRow&) = default;
            ConstRow& operator=(const Row& r) { (span<const u64>&)* this = r; return *this; };
        };
        class ConstCol : public span<const u64>
        {
        public:
            ConstCol() = default;
            ConstCol(const ConstCol&) = default;
            ConstCol(const Col& r) : span<const u64>(r) { };

            ConstCol& operator=(const ConstCol&) = default;
            ConstCol& operator=(const Col& c) { (span<const u64>&)* this = c; return *this; };
        };

        SparseMtx() = default;
        SparseMtx(const SparseMtx&) = default;
        SparseMtx(SparseMtx&&) = default;
        SparseMtx& operator=(const SparseMtx&) = default;
        SparseMtx& operator=(SparseMtx&&) = default;


        SparseMtx(PointList& list)
        {
            init(list);
        }

        SparseMtx(u64 rows, u64 cols, span<Point> points)
        {
            init(rows, cols, points);
        }

        std::vector<u64> mDataRow, mDataCol;

        std::vector<Row> mRows;
        std::vector<Col> mCols;



        operator PointList() const
        {
            return PointList(mRows.size(), mCols.size(), points());
        }

        u64 rows() const { return mRows.size(); }
        u64 cols() const { return mCols.size(); }

        Row& row(u64 i) { return mRows[i]; }
        Col& col(u64 i) { return mCols[i]; }

        ConstRow row(u64 i) const { return mRows[i]; }
        ConstCol col(u64 i) const { return mCols[i]; }

        bool operator()(u64 i, u64 j) const
        {
            if (i >= mRows.size() || j >= mCols.size())
                throw RTE_LOC;
            auto iter = std::find(mRows[i].begin(), mRows[i].end(), j);
            return iter != mRows[i].end();
        }

        block hash() const
        {
            oc::RandomOracle ro(sizeof(block));
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto j : row(i))
                {
                    ro.Update(j);
                }

                ro.Update(i);
                u64 jj = -1;
                ro.Update(jj);
            }

            block b;
            ro.Final<block>(b);
            return b;
        }

        void init(PointList& list)
        {
            init(list.mRows, list.mCols, list.mPoints);
        }


        void init(u64 rows, u64 cols, span<Point> points)
        {
            std::vector<u64> rowSizes(rows);
            std::vector<u64> colSizes(cols);

#define INSERT_DEBUG
#ifdef INSERT_DEBUG
            std::set<std::pair<u64, u64>> set;
#endif // !NDEBUG

            for (u64 i = 0; i < u64(points.size()); ++i)
            {
#ifdef INSERT_DEBUG
                auto s = set.insert({ points[i].mRow , points[i].mCol });

                if (!s.second)
                {
                    std::cout << "dup " << points[i].mRow << " " << points[i].mCol << std::endl;
                    abort();
                }

                if (points[i].mRow >= rows)
                {
                    std::cout << "row out of bounds " << points[i].mRow << " " << rows << std::endl;
                    abort();
                }
                if (points[i].mCol >= cols)
                {
                    std::cout << "col out of bounds " << points[i].mCol << " " << cols << std::endl;
                    abort();
                }
#endif
                ++rowSizes[points[i].mRow];
                ++colSizes[points[i].mCol];

            }

            mRows.resize(rows);
            mCols.resize(cols);
            mDataRow.resize(points.size());
            mDataCol.resize(points.size());
            auto iter = mDataRow.data();
            for (u64 i = 0; i < rows; ++i)
            {
                mRows[i] = Row(span<u64>(iter, iter + rowSizes[i]));
                iter += rowSizes[i];
                rowSizes[i] = 0;
            }

            iter = mDataCol.data();
            for (u64 i = 0; i < cols; ++i)
            {
                mCols[i] = Col(span<u64>(iter, iter + colSizes[i]));
                iter += colSizes[i];
                colSizes[i] = 0;
            }

            for (u64 i = 0; i < u64(points.size()); ++i)
            {
                auto r = points[i].mRow;
                auto c = points[i].mCol;
                auto j = rowSizes[r]++;
                mRows[r][j] = c;
                auto k = colSizes[c]++;
                mCols[c][k] = r;
            }

            for (u64 i = 0; i < rows; ++i)
            {
                std::sort(row(i).begin(), row(i).end());
            }
            for (u64 i = 0; i < cols; ++i)
            {
                std::sort(col(i).begin(), col(i).end());
            }

#ifndef NDEBUG
            for (u64 i = 0; i < u64(points.size()); ++i)
            {
                auto row = mRows[points[i].mRow];
                auto col = mCols[points[i].mCol];
                assert(std::find(row.begin(), row.end(), points[i].mCol) != row.end());
                assert(std::find(col.begin(), col.end(), points[i].mRow) != col.end());
            }
#endif
        }

        template<typename IdxType>
        SparseMtx getCols(span<const IdxType> idx) const
        {
            PointList pnts(mRows.size(), idx.size());
            for (u64 i = 0; i < idx.size(); ++i)
            {
                for (auto r : mCols[idx[i]])
                {
                    pnts.push_back({ r,i });
                }
            }
            return pnts;
        }


        bool isSet(u64 row, u64 col)
        {
            assert(row < rows());
            assert(col < cols());

            auto iter = std::lower_bound(
                mCols[col].begin(),
                mCols[col].end(),
                row);
            return iter != mCols[col].end() && *iter == row;
        }

        bool validate()
        {
            std::vector<span<u64>::iterator> colIters(cols());
            for (u64 i = 0; i < cols(); ++i)
            {
                colIters[i] = mCols[i].begin();
            }

            for (u64 i = 0; i < rows(); ++i)
            {
                if (!std::is_sorted(mRows[i].begin(), mRows[i].end()))
                    return false;

                for (auto cc : mRows[i])
                {
                    if (cc >= cols())
                        return false;
                    if (colIters[cc] == mCols[cc].end())
                        return false;

                    if (*colIters[cc] != i)
                        return false;

                    ++colIters[cc];
                }
            }

            return true;
        }


        SparseMtx vConcat(const SparseMtx& o) const
        {
            if (cols() != o.cols())
                throw RTE_LOC;

            PointList pPnts = *this;
            pPnts.mRows += o.rows();
            for (auto p : o.points())
            {
                pPnts.push_back({ p.mRow + rows(), p.mCol });
            }

            return pPnts;
        }
        
        SparseMtx subMatrix(u64 row, u64 col, u64 rowCount, u64 colCount)
        {
            if (rowCount == 0 || colCount == 0)
                return {};

            SparseMtx R;

            auto rEnd = row + rowCount;
            auto cEnd = col + colCount;

            assert(rows() > row);
            assert(rows() >= rEnd);
            assert(cols() > col);
            assert(cols() >= cEnd);

            u64 total = 0;
            std::vector<std::array<span<u64>::iterator, 2>> rowIters(rEnd - row);
            std::vector<std::array<span<u64>::iterator, 2>> colIters(cEnd - col);

            for (u64 i = row, ii = 0; i < rEnd; ++i, ++ii)
            {
                auto& rowi = mRows[i];
                auto iter = std::lower_bound(rowi.begin(), rowi.end(), col);
                auto end = std::lower_bound(iter, rowi.end(), cEnd);

                rowIters[ii][0] = iter;
                rowIters[ii][1] = end;

#ifndef NDEBUG
                for (auto c : span<u64>(iter, end))
                {
                    assert(c < cols());
                    assert(c - col < colCount);
                }
#endif
                total += end - iter;
            }


            for (u64 i = col, ii = 0; i < cEnd; ++i, ++ii)
            {
                auto& coli = mCols[i];
                auto iter = std::lower_bound(coli.begin(), coli.end(), row);
                auto end = std::lower_bound(iter, coli.end(), rEnd);

                colIters[ii][0] = iter;
                colIters[ii][1] = end;


#ifndef NDEBUG
                for (auto r : span<u64>(iter, end))
                {
                    assert(r < rows());
                    assert(r - row < rowCount);
                }
#endif
            }

            R.mDataRow.resize(total);
            R.mDataCol.resize(total);

            R.mRows.resize(rEnd - row);
            R.mCols.resize(cEnd - col);

            auto iter = R.mDataRow.begin();
            for (u64 i = 0; i < rowIters.size(); ++i)
            {
                u64 size = (u64)std::distance(rowIters[i][0], rowIters[i][1]);

                //std::transform(rowIters[i][0], rowIters[i][1], iter, [&](const auto& src) {return src - col; });

                for (u64 j = 0; j < size; ++j)
                {
                    auto& cc = *(rowIters[i][0] + j);
                    auto& dd = *(iter + j);
                    dd = cc - col;
                    assert(dd < colCount);
                }
                if (size)
                    R.mRows[i] = Row(span<u64>(&*iter, size));
                iter += size;
            }

            iter = R.mDataCol.begin();
            for (u64 i = 0; i < colIters.size(); ++i)
            {
                auto size = (u64)std::distance(colIters[i][0], colIters[i][1]);
                //std::transform(colIters[i][0], colIters[i][1], iter, [&](const auto& src) {return src - row; });

                for (u64 j = 0; j < size; ++j)
                {
                    auto rr = *(colIters[i][0] + j);
                    *(iter + j) = rr - row;
                    assert(*(iter + j) < rowCount);
                }

                if (size)
                    R.mCols[i] = Col(span<u64>(&*iter, size));

                iter += size;
            }

            assert(R.validate());

            return R;
        }

        DenseMtx dense() const;

        std::vector<u8> mult(span<const u8> x) const
        {
            std::vector<u8> y(rows());
            multAdd(x, y);
            return y;
        }        
        
        template<typename T>
        Vec<T> mult(const Vec<T>& x) const
        {
            Vec<T> y(rows());
            multAdd(x, y);
            return y;
        }





        void multAdd(span<const u8> x, span<u8> y) const
        {
            assert(cols() == x.size());
            assert(y.size() == rows());
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto c : row(i))
                {
                    assert(c < cols());
                    y[i] ^= x[c];
                }
            }
        }


        template<typename T>
        void multAdd(const Vec<T>& x, Vec<T>& y) const
        {
            assert(cols() == x.size());
            assert(y.size() == rows());
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto c : row(i))
                {
                    assert(c < cols());
                    y[i] = y[i] ^ x[c];
                }
            }
        }


        std::vector<u8> operator*(span<const u8> x) const
        {
            return mult(x);
        }

        template<typename T> 
        Vec<T> operator*(const Vec<T>& x) const
        {
            return mult(x);
        }


        void mult(std::vector<u64>& dest, const ConstRow& src)
        {
            //assert(src.size() == rows());
            //assert(dest.size() == cols());

            assert(0);
            dest.clear();


            for (u64 i = 0; i < cols(); ++i)
            {
                u64 bit = 0;

                auto mIter = col(i).begin();
                auto mEnd = col(i).end();

                auto xIter = src.begin();
                auto xEnd = src.end();

                while (mIter != mEnd && xIter != xEnd)
                {
                    if (*mIter < *xIter)
                        ++mIter;
                    else if (*xIter < *mIter)
                        ++xIter;
                    else
                    {
                        bit ^= 1;
                        ++xIter;
                        ++mIter;
                    }
                }

                if (bit)
                    dest.push_back(i);
            }
        }

        void mult(std::vector<u64>& dest, const ConstCol& src)
        {
            //assert(src.size() == rows());
            //assert(dest.size() == cols());
            assert(0);
            dest.clear();


            for (u64 i = 0; i < cols(); ++i)
            {
                u64 bit = 0;

                auto mIter = row(i).begin();
                auto mEnd = row(i).end();

                auto xIter = src.begin();
                auto xEnd = src.end();

                while (mIter != mEnd && xIter != xEnd)
                {
                    if (*mIter < *xIter)
                        ++mIter;
                    else if (*xIter < *mIter)
                        ++xIter;
                    else
                    {
                        bit ^= 1;
                        ++xIter;
                        ++mIter;
                    }
                }

                if (bit)
                    dest.push_back(i);
            }
        }


        SparseMtx mult(const SparseMtx& X) const
        {
            assert(cols() == X.rows());



            //SparseMtx y;
            std::vector<Point> points;
            //std::vector<u64> res;
            for (u64 i = 0; i < rows(); ++i)
            {
                auto r = this->row(i);
                for (u64 j = 0; j < X.cols(); ++j)
                {
                    auto c = X.col(j);

                    u64 bit = 0;

                    span<const u64>::iterator mIter = r.begin();
                    span<const u64>::iterator mEnd = r.end();

                    span<const u64>::iterator xIter = c.begin();
                    span<const u64>::iterator xEnd = c.end();

                    while (mIter != mEnd && xIter != xEnd)
                    {
                        if (*mIter < *xIter)
                            ++mIter;
                        else if (*xIter < *mIter)
                            ++xIter;
                        else
                        {
                            bit ^= 1;
                            ++xIter;
                            ++mIter;
                        }
                    }

                    if (bit)
                    {
                        points.push_back({ i,j });
                    }
                }
            }

            return SparseMtx(rows(), X.cols(), points);
        }

        SparseMtx operator*(const SparseMtx& X) const
        {
            return mult(X);
        }


        SparseMtx operator+(const SparseMtx& X) const
        {
            return add(X);
        }


        bool operator==(const SparseMtx& X) const
        {
            return rows() == X.rows() &&
                cols() == X.cols() &&
                mDataCol.size() == X.mDataCol.size() &&
                mDataCol == X.mDataCol;
        }
        bool operator!=(const SparseMtx& X) const
        {
            return !(*this == X);
        }


        SparseMtx add(const SparseMtx& p) const
        {
            assert(rows() == p.rows());
            assert(cols() == p.cols());

            SparseMtx r;
            r.mDataCol.reserve(
                p.mDataCol.size() +
                mDataCol.size());

            r.mRows.resize(rows());
            r.mCols.resize(cols());

            u64 prev = 0;
            for (u64 i = 0; i < cols(); ++i)
            {
                auto c0 = col(i);
                auto c1 = p.col(i);

                auto b0 = c0.begin();
                auto b1 = c1.begin();
                auto e0 = c0.end();
                auto e1 = c1.end();

                // push the non-zero loctions in order.
                // skip when they are equal, i.e. 1+1=0
                while (b0 != e0 && b1 != e1)
                {
                    if (*b0 < *b1)
                        r.mDataCol.push_back(*b0++);
                    else if (*b0 > *b1)
                        r.mDataCol.push_back(*b1++);
                    else
                    {
                        ++b0;
                        ++b1;
                    }
                }

                // push any extra
                while (b0 != e0)
                    r.mDataCol.push_back(*b0++);
                while (b1 != e1)
                    r.mDataCol.push_back(*b1++);

                r.mCols[i] = Col(span<u64>(
                    r.mDataCol.begin() + prev,
                    r.mDataCol.end()));

                prev = r.mDataCol.size();
            }

            r.mDataRow.reserve(r.mDataCol.size());
            prev = 0;
            for (u64 i = 0; i < rows(); ++i)
            {
                auto c0 = row(i);
                auto c1 = p.row(i);

                auto b0 = c0.begin();
                auto b1 = c1.begin();
                auto e0 = c0.end();
                auto e1 = c1.end();

                while (b0 != e0 && b1 != e1)
                {
                    if (*b0 < *b1)
                        r.mDataRow.push_back(*b0++);
                    else if (*b0 > *b1)
                        r.mDataRow.push_back(*b1++);
                    else
                    {
                        ++b0; ++b1;
                    }
                }

                while (b0 != e0)
                    r.mDataRow.push_back(*b0++);
                while (b1 != e1)
                    r.mDataRow.push_back(*b1++);

                r.mRows[i] = Row(span<u64>(
                    r.mDataRow.begin() + prev,
                    r.mDataRow.end()));

                prev = r.mDataRow.size();
            }

            return r;
        }

        SparseMtx& operator+=(const SparseMtx& p)
        {
            *this = add(p);
            return *this;
        }


        SparseMtx invert() const;


        std::vector<Point> points() const
        {
            std::vector<Point> p; p.reserve(mDataCol.size());
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto c : row(i))
                    p.push_back({ i,c });
            }

            return p;
        }
    };


    inline std::ostream& operator<<(std::ostream& o, const SparseMtx& H)
    {
        for (u64 i = 0; i < H.rows(); ++i)
        {
            auto row = H.row(i);
            for (u64 j = 0, jj = 0; j < H.cols(); ++j)
            {
                if (jj != (u64)row.size() && j == row[jj])
                {
                    if (&o == &std::cout)
                        o << oc::Color::Green << "1 " << oc::Color::Default;
                    else
                        o << "1 ";
                    ++jj;
                }
                else
                    o << "0 ";
            }
            o << "\n";
        }

        return o;
    }




    class DenseMtx
    {
    public:
        // column major.
        Matrix<block> mData;
        u64 mRows = 0;

        DenseMtx() = default;
        DenseMtx(const DenseMtx&) = default;
        DenseMtx(DenseMtx&&) = default;

        DenseMtx& operator=(const DenseMtx&) = default;
        DenseMtx& operator=(DenseMtx&&) = default;


        DenseMtx(u64 rows, u64 cols)
        {
            resize(rows, cols);
        }


        void resize(u64 rows, u64 cols)
        {
            mRows = rows;
            mData.resize(cols, (rows + 127) / 128);
        }


        u64 rows() const { return mRows; }
        u64 cols() const { return mData.rows(); }

        oc::BitReference operator()(u64 row, u64 col) const
        {
            assert(row < rows());
            assert(col < cols());

            return oc::BitReference((u8*)&mData(col, 0), row);
        }

        bool operator==(const DenseMtx& m) const
        {
            return rows() == m.rows()
                && cols() == m.cols()
                && std::memcmp(mData.data(), m.mData.data(), mData.size() * sizeof(oc::block)) == 0;
        }


        struct Row
        {
            u64 mIdx;
            DenseMtx& mMtx;


            void swap(const Row& r)
            {
                assert(mMtx.cols() == r.mMtx.cols());

                for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
                {
                    u8 bit = r.mMtx(r.mIdx, colIdx);
                    r.mMtx(r.mIdx, colIdx) = mMtx(mIdx, colIdx);
                    mMtx(mIdx, colIdx) = bit;
                }
            }


            bool isZero() const
            {
                for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
                {
                    u8 bit = mMtx(mIdx, colIdx);
                    if (bit)
                        return false;
                }
                return true;
            }

            void operator^=(const Row& r)
            {
                for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
                {
                    mMtx(mIdx, colIdx) ^= r.mMtx(r.mIdx, colIdx);
                }
            }
        };

        void colIndexSet(u64 c, std::vector<u64>& set)const
        {
            set.clear();
            oc::BitIterator iter((u8*)col(c).data());
            for (u64 i = 0; i < rows(); ++i)
            {
                if (*iter)
                    set.push_back(i);
                ++iter;
            }
        }

        Row row(u64 i) const
        {
            return Row{ i, (DenseMtx&)*this };
        }

        DenseMtx selectColumns(span<u64> perm)
        {
            DenseMtx r(rows(), perm.size());

            for (u64 i = 0; i < (u64)perm.size(); ++i)
            {
                auto d = r.col(i);
                auto s = col(perm[i]);
                std::copy(s.begin(), s.end(), d.begin());
            }
            return r;
        }

        span<block> col(u64 i)
        {
            return mData[i];
        }
        span<const block> col(u64 i) const
        {
            return mData[i];
        }

        void setZero()
        {
            memset(mData.data(), 0, mData.size() * sizeof(oc::block));
        }

        void rowSwap(u64 i, u64 j)
        {
            if (i != j)
            {
                row(i).swap(row(j));
            }
        }

        SparseMtx sparse() const
        {
            std::vector<Point> points;
            for (u64 i = 0; i < rows(); ++i)
            {
                for (u64 j = 0; j < cols(); ++j)
                {
                    if ((*this)(i, j))
                        points.push_back({ i,j });
                }
            }

            SparseMtx s;
            s.init(rows(), cols(), points);

            return s;
        }


        DenseMtx mult(const DenseMtx& m)
        {
            assert(cols() == m.rows());

            DenseMtx ret(rows(), m.cols());


            for (u64 i = 0; i < ret.rows(); ++i)
            {
                for (u64 j = 0; j < ret.cols(); ++j)
                {
                    u8 v = 0;
                    for (u64 k = 0; k < cols(); ++k)
                    {
                        v = v ^ ((*this)(i, k) & m(k, j));
                    }

                    ret(i, j) = v;
                }
            }

            return ret;
        }
        DenseMtx add(DenseMtx& m)
        {
            assert(rows() == m.rows() && cols() == m.cols());

            auto ret = *this;
            for (u64 i = 0; i < mData.size(); ++i)
                ret.mData(i) = ret.mData(i) ^ m.mData(i);

            return  ret;
        }

        DenseMtx operator+(DenseMtx& m)
        {
            return add(m);
        }


        DenseMtx operator*(const DenseMtx& m)
        {
            return mult(m);
        }

        static DenseMtx Identity(u64 n)
        {
            DenseMtx I(n, n);

            for (u64 i = 0; i < n; ++i)
                I(i, i) = 1;

            return I;
        }

        DenseMtx upperTriangular() const
        {
            auto& mtx = *this;
            auto rows = mtx.rows();
            auto cols = mtx.cols();

            u64 colIdx = 0ull;
            for (u64 i = 0; i < rows; ++i)
            {
                while (mtx(i, colIdx) == 0)
                {
                    for (u64 j = i + 1; j < rows; ++j)
                    {
                        if (mtx(j, colIdx) == 1)
                        {
                            mtx.row(i).swap(mtx.row(j));
                            --colIdx;
                            break;
                        }
                    }

                    ++colIdx;

                    if (colIdx == cols)
                        return mtx;
                }

                for (u64 j = i + 1; j < rows; ++j)
                {
                    if (mtx(j, colIdx))
                    {
                        for (u64 k = 0; k < cols; ++k)
                        {
                            mtx(j, k) ^= mtx(i, k);
                        }
                    }
                }

            }

            return mtx;

        }

        DenseMtx gausianElimination() const
        {
            auto& mtx = *this;
            auto rows = mtx.rows();
            auto cols = mtx.cols();

            u64 colIdx = 0ull;
            for (u64 i = 0; i < rows; ++i)
            {
                while (mtx(i, colIdx) == 0)
                {
                    for (u64 j = i + 1; j < rows; ++j)
                    {
                        if (mtx(j, colIdx) == 1)
                        {
                            mtx.row(i).swap(mtx.row(j));
                            --colIdx;
                            break;
                        }
                    }

                    ++colIdx;

                    if (colIdx == cols)
                        return mtx;
                }

                for (u64 j = 0; j < rows; ++j)
                {
                    if (j != i && mtx(j, colIdx))
                    {
                        for (u64 k = 0; k < cols; ++k)
                        {
                            mtx(j, k) ^= mtx(i, k);
                        }
                    }
                }

            }

            return mtx;

        }


        DenseMtx invert() const;


        DenseMtx transpose() const
        {
            DenseMtx R(cols(), rows());
            for (u64 i = 0; i < rows(); ++i)
            {
                for (u64 j = 0; j < cols(); ++j)
                {
                    R(j, i) = (*this)(i, j);
                }
            }
            return R;
        }



        DenseMtx subMatrix(u64 row, u64 col, u64 rowCount, u64 colCount)
        {
            DenseMtx ret(rowCount, colCount);

            for (u64 i = 0, ii = row; i < rowCount; ++i, ++ii)
            {
                for (u64 j = 0, jj = col; j < colCount; ++j, ++jj)
                {
                    ret(i, j) = (*this)(ii, jj);
                }
            }
            return ret;
        }

    };




    inline std::ostream& operator<<(std::ostream& o, const DenseMtx& H)
    {
        for (u64 i = 0; i < H.rows(); ++i)
        {
            for (u64 j = 0; j < H.cols(); ++j)
            {
                if (H(i, j))
                {
                    if (&o == &std::cout)
                        o << oc::Color::Green << "1 " << oc::Color::Default;
                    else
                        o << "1 ";
                }
                else
                    o << "0 ";
            }
            o << "\n";
        }

        return o;
    }

    inline DenseMtx DenseMtx::invert() const
    {
        assert(rows() == cols());

        auto mtx = *this;
        auto n = this->rows();

        auto Inv = Identity(n);

        for (u64 i = 0; i < n; ++i)
        {
            if (mtx(i, i) == 0)
            {
                for (u64 j = i + 1; j < n; ++j)
                {
                    if (mtx(j, i) == 1)
                    {
                        mtx.row(i).swap(mtx.row(j));
                        Inv.row(i).swap(Inv.row(j));
                        break;
                    }
                }

                if (mtx(i, i) == 0)
                {
                    //std::cout << mtx << std::endl;
                    return {};
                }
            }

            for (u64 j = 0; j < n; ++j)
            {
                if (j != i && mtx(j, i))
                {
                    for (u64 k = 0; k < n; ++k)
                    {
                        mtx(j, k) ^= mtx(i, k);
                        Inv(j, k) ^= Inv(i, k);
                    }
                }
            }

        }

        return Inv;

    }

    inline DenseMtx SparseMtx::dense() const
    {
        DenseMtx mtx(rows(), cols());

        for (u64 i = 0; i < rows(); ++i)
        {
            for (auto j : row(i))
                mtx(i, j) = 1;
        }

        return mtx;
    }

    inline SparseMtx SparseMtx::invert() const
    {
        auto d = dense();
        d = d.invert();
        return d.sparse();
    }




    struct VecSortSet
    {
        std::vector<u64> mData;
        using iterator = std::vector<u64>::iterator;
        using constIerator = std::vector<u64>::const_iterator;



        iterator begin()
        {
            return mData.begin();
        }
        iterator end()
        {
            return mData.end();
        }
        iterator find(u64 i)
        {
            auto iter = lowerBound(i);
            if (iter != end() && *iter != i)
                iter = end();
            return iter;
        }
        iterator lowerBound(u64 i)
        {
            return std::lower_bound(begin(), end(), i);
        }


        constIerator begin() const
        {
            return mData.begin();
        }
        constIerator end()const
        {
            return mData.end();
        }
        constIerator find(u64 i)const
        {
            auto iter = lowerBound(i);
            if (iter != end() && *iter != i)
                iter = end();
            return iter;
        }
        constIerator lowerBound(u64 i)const
        {
            return std::lower_bound(begin(), end(), i);
        }

        void clear()
        {
            mData.clear();
        }

        template<class Iter>
        void insert(Iter b, Iter e)
        {
            auto s = e - b;
            mData.reserve(mData.size() + s);
            while (b != e)
            {
                if (size() == 0 || *b > mData.back())
                    mData.push_back(*b);
                else
                    insert(*b);

                ++b;
            }
        }

        void insert(u64 i)
        {
            auto iter = lowerBound(i);
            implInsert(i, iter);
        }

        void insertHint(u64 i, iterator iter)
        {
            assert(lowerBound(i) == iter);
            implInsert(i, iter);
        }

        void implInsert(u64 i, iterator iter)
        {
            if (iter == end())
            {
                mData.push_back(i);
            }
            else if (*iter > i)
            {
                auto p = iter - begin();
                mData.emplace_back();
                iter = begin() + p;

                while (iter != end())
                {
                    std::swap(i, *iter);
                    ++iter;
                }
            }
        }

        void erase(u64 i)
        {
            auto iter = lowerBound(i);
            assert(iter != end());
            erase(iter);
        }

        void erase(iterator iter)
        {
            auto e = end() - 1;
            while (iter < e)
            {
                *iter = *(iter + 1);
                ++iter;
            }
            mData.pop_back();
        }

        u64 size() const
        {
            return mData.size();
        }

        u64& operator[](u64 i)
        {
            return mData[i];
        }

        void operator ^=(const VecSortSet& o)
        {
            u64 i0 = 0;
            u64 i1 = 0;

            while (i0 != size() && i1 != o.size())
            {
                if (mData[i0] < o.mData[i1])
                {
                    ++i0;
                }
                else if (mData[i0] == o.mData[i1])
                {
                    erase(begin() + i0);
                    ++i1;
                }
                else
                {
                    insertHint(o.mData[i1], begin() + i0);
                    ++i1;
                    ++i0;
                }
            }

            insert(o.begin() + i1, o.end());
        }

    };


    struct VecSet
    {
        std::vector<u64> mData;
        using iterator = std::vector<u64>::iterator;
        using constIerator = std::vector<u64>::const_iterator;



        iterator begin()
        {
            return mData.begin();
        }
        iterator end()
        {
            return mData.end();
        }
        iterator find(u64 i)
        {
            auto iter = std::find(mData.begin(), mData.end(), i);
            return iter;
        }
        //iterator lowerBound(u64 i)
        //{
        //    return std::lower_bound(begin(), end(), i);
        //}


        constIerator begin() const
        {
            return mData.begin();
        }
        constIerator end()const
        {
            return mData.end();
        }
        constIerator find(u64 i)const
        {
            auto iter = std::find(mData.begin(), mData.end(), i);
            return iter;
        }
        //constIerator lowerBound(u64 i)const
        //{
        //    return std::lower_bound(begin(), end(), i);
        //}

        void clear()
        {
            mData.clear();
        }

        template<class Iter>
        void insert(Iter b, Iter e)
        {
            auto s = e - b;
            mData.reserve(mData.size() + s);
            while (b != e)
            {
                if (size() == 0 || *b > mData.back())
                    mData.push_back(*b);
                else
                    insert(*b);

                ++b;
            }
        }

        void insert(u64 i)
        {
            assert(find(i) == end());
            mData.push_back(i);
            //auto iter = lowerBound(i);
            //implInsert(i, iter);
        }

        //void insertHint(u64 i, iterator iter)
        //{
        //    assert(lowerBound(i) == iter);
        //    implInsert(i, iter);
        //}

        //void implInsert(u64 i, iterator iter)
        //{
        //    if (iter == end())
        //    {
        //        mData.push_back(i);
        //    }
        //    else if (*iter > i)
        //    {
        //        auto p = iter - begin();
        //        mData.emplace_back();
        //        iter = begin() + p;

        //        while (iter != end())
        //        {
        //            std::swap(i, *iter);
        //            ++iter;
        //        }
        //    }
        //}

        void erase(u64 i)
        {
            auto iter = find(i);
            assert(iter != end());
            erase(iter);
        }

        void erase(iterator iter)
        {
            auto e = end() - 1;
            while (iter < e)
            {
                *iter = *(iter + 1);
                ++iter;
            }
            mData.pop_back();
        }

        u64 size() const
        {
            return mData.size();
        }

        u64& operator[](u64 i)
        {
            return mData[i];
        }

        void operator ^=(const VecSortSet& o)
        {
            u64 i0 = 0;
            u64 i1 = 0;

            while (i0 != size() && i1 != o.size())
            {
                if (mData[i0] < o.mData[i1])
                {
                    ++i0;
                }
                else if (mData[i0] == o.mData[i1])
                {
                    erase(begin() + i0);
                    ++i1;
                }
                else
                {
                    insert(o.mData[i1]);
                    ++i1;
                    ++i0;
                }
            }

            insert(o.begin() + i1, o.end());
        }

    };



    struct DynSparseMtx
    {
        std::vector<VecSortSet> mRows;// , mCols;
        std::vector<VecSortSet> mCols;

        DynSparseMtx() = default;
        DynSparseMtx(const DynSparseMtx&) = default;
        DynSparseMtx(DynSparseMtx&&) = default;

        DynSparseMtx(const SparseMtx& m)
        {
            resize(m.rows(), m.cols());
            for (u64 i = 0; i < rows(); ++i)
            {
                auto r = m.row(i);
                row(i).insert(r.begin(), r.end());
            }
            for (u64 i = 0; i < cols(); ++i)
            {
                auto c = m.col(i);
                col(i).insert(c.begin(), c.end());
            }
        }

        void operator=(const SparseMtx& m)
        {
            resize(m.rows(), m.cols());
            for (u64 i = 0; i < rows(); ++i)
            {
                auto r = m.row(i);
                row(i).clear();
                row(i).insert(r.begin(), r.end());
            }
            for (u64 i = 0; i < cols(); ++i)
            {
                auto c = m.col(i);
                col(i).clear();
                col(i).insert(c.begin(), c.end());
            }
        }


        void operator=(const DenseMtx& m)
        {
            resize(m.rows(), m.cols());
            for (u64 i = 0; i < rows(); ++i)
            {
                row(i).clear();
            }
            for (u64 i = 0; i < cols(); ++i)
            {
                //auto c = m.col(i);
                col(i).clear();
            }

            for (u64 i = 0; i < rows(); ++i)
            {
                for (u64 j = 0; j < cols(); ++j)
                {
                    if (m(i, j))
                    {
                        col(j).insert(i);
                        row(i).insert(j);
                    }
                }
            }
        }

        DynSparseMtx& operator=(const DynSparseMtx&) = default;
        DynSparseMtx& operator=(DynSparseMtx&&) = default;

        VecSortSet& row(u64 i)
        {
            return mRows[i];
        }
        VecSortSet& col(u64 i)
        {
            //std::sort(mCols[i].begin(), mCols[i].end());
            return mCols[i];
        }
        const VecSortSet& row(u64 i)const
        {
            return mRows[i];
        }
        const VecSortSet& col(u64 i)const
        {
            return mCols[i];
        }


        u64 rows()const
        {
            return mRows.size();
        }
        u64 cols()const
        {
            return mCols.size();
        }

        void resize(u64 rows, u64 cols)
        {
            if (mRows.size() < rows)
            {
                for (u64 i = mRows.size() - 1; i <= rows; --i)
                    clearRow(i);
            }
            if (mCols.size() < cols)
            {
                for (u64 i = mCols.size() - 1; i <= cols; --i)
                    clearCol(i);
            }

            mRows.resize(rows);
            mCols.resize(cols);
        }
        void reserve(u64 rows, u64 cols)
        {
            mRows.reserve(rows);
            mCols.reserve(cols);
        }


        void clearRow(u64 i)
        {
            assert(i < mRows.size());
            for (auto c : mRows[i])
            {
                mCols[c].erase(i);
            }
        }
        void clearCol(u64 i)
        {
            assert(i < mCols.size());
            for (auto r : mCols[i])
            {
                mRows[r].erase(i);
            }
        }

        void pushBackCol(const VecSortSet& col)
        {
            pushBackCol(span<const u64>(col.mData));
        }
        void pushBackCol(span<const u64> col)
        {
            auto c = mCols.size();
            mCols.emplace_back();
            mCols.back().insert(col.begin(), col.end());

            for (u64 i = 0; i < (u64)col.size(); ++i)
            {
                mRows[col[i]].insert(c);
            }
        }

        void pushBackRow(const VecSortSet& row)
        {
            pushBackRow(row.mData);
        }

        void pushBackRow(span<const u64> row)
        {
            auto r = mRows.size();
            mRows.emplace_back();
            mRows.back().insert(row.begin(), row.end());

            for (u64 i = 0; i < (u64)row.size(); ++i)
            {
                mCols[row[i]].insert(r);
            }
        }
        void rowAdd(u64 r0, u64 r1)
        {

            u64 i0 = 0;
            u64 i1 = 0;
            auto& rr0 = row(r0);
            auto& rr1 = row(r1);

            while (i0 != rr0.size() && i1 != rr1.size())
            {
                auto colIdx0 = rr0.mData[i0];
                auto colIdx1 = rr1.mData[i1];
                if (colIdx0 < colIdx1)
                {
                    ++i0;
                }
                else if (colIdx0 == colIdx1)
                {
                    col(colIdx0).erase(r0);
                    rr0.erase(rr0.begin() + i0);
                    ++i1;
                }
                else
                {
                    col(colIdx1).insert(r0);
                    rr0.insertHint(colIdx1, rr0.begin() + i0);
                    ++i1;
                    ++i0;
                }
            }

            rr0.insert(rr1.begin() + i1, rr1.end());
            while (i1 != rr1.size())
            {
                auto colIdx = rr1.mData[i1];
                col(colIdx).insert(r0);
                ++i1;
            }
            validate();
        }

        void rowSwap(u64 r0, u64 r1)
        {
            validate();

            assert(r0 < rows());
            assert(r1 < rows());

            if (r0 == r1)
                return;

            u64 col0 = 0;
            u64 col1 = 0;

            auto& rr0 = mRows[r0];
            auto& rr1 = mRows[r1];

            while (col0 != rr0.size() && col1 != rr1.size())
            {
                if (rr0[col0] < rr1[col1])
                {
                    auto& c0 = mCols[rr0[col0]];
                    c0.erase(r0);
                    c0.insert(r1);
                    ++col0;
                }
                else if (rr0[col0] > rr1[col1])
                {
                    auto& c1 = mCols[rr1[col1]];
                    c1.erase(r1);
                    c1.insert(r0);
                    ++col1;
                }
                else
                {
                    ++col1;
                    ++col0;
                }
            }




            while (col0 != rr0.size())
            {
                auto& c0 = mCols[rr0[col0]];
                c0.erase(r0);
                c0.insert(r1);
                ++col0;
            }
            while (col1 != rr1.size())
            {
                auto& c1 = mCols[rr1[col1]];
                c1.erase(r1);
                c1.insert(r0);
                ++col1;
            }

            std::swap(mRows[r0], mRows[r1]);

            validate();
        }

        bool operator()(u64 r, u64 c) const
        {
            return mRows[r].find(c) != mRows[r].end();
        }

        void validate()
        {
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto j : mRows[i])
                {
                    if (mCols[j].find(i) == mCols[j].end())
                        throw RTE_LOC;
                }
            }

            for (u64 i = 0; i < cols(); ++i)
            {
                for (auto j : mCols[i])
                {
                    if(mRows[j].find(i) == mRows[j].end())
                        throw RTE_LOC;
                }
            }
        }
        DynSparseMtx selectColumns(span<u64> perm)const
        {
            DynSparseMtx r;
            r.mRows.resize(rows());
            for (u64 i = 0; i < (u64)perm.size(); ++i)
            {
                r.pushBackCol(col(perm[i]));
            }
            return r;
        }


        SparseMtx sparse() const
        {
            std::vector<Point> points;
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto j : row(i))
                    points.push_back({ i,j });
            }

            SparseMtx s;
            s.init(rows(), cols(), points);

            return s;
        }
    };


    inline std::ostream& operator<<(std::ostream& o, const DynSparseMtx& H)
    {
        for (u64 i = 0; i < H.rows(); ++i)
        {
            auto row = H.row(i);
            for (u64 j = 0, jj = 0; j < H.cols(); ++j)
            {
                if (jj != row.size() && j == row[jj])
                {
                    if (&o == &std::cout)
                        o << oc::Color::Green << "1 " << oc::Color::Default;
                    else
                        o << "1 ";
                    ++jj;
                }
                else
                    o << "0 ";
            }
            o << "\n";
        }
        return o;
    }





    namespace tests
    {
        void Mtx_make_test();
        void Mtx_add_test();
        void Mtx_mult_test();
        void Mtx_invert_test();
        void Mtx_block_test();
    }






}
