#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).

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

    // A sparse matrix represented as an unordered list of points.
    struct PointList
    {
        using iterator = std::vector<Point>::iterator;

        PointList(const PointList&) = default;
        PointList(PointList&&) = default;

        PointList(u64 r, u64 c)
            : mRows(r), mCols(c)
        {}

        PointList(u64 r, u64 c, span<const Point> pp);

        u64 mRows, mCols;
        std::vector<Point> mPoints;
#ifndef NDEBUG
        std::set<std::pair<u64, u64>> ss;
#endif

        // add the given point. SHould not have previously been added.
        void push_back(const Point& p);
        void push_back(u64 x, u64 y);

        operator span<Point>() { return mPoints; }

        iterator begin() { return mPoints.begin(); }
        iterator end() { return mPoints.end(); }

    };


    class DenseMtx;


    // A class representing a sparse binary matrix.
    // The points are represented in both column and row major.
    class SparseMtx
    {
    public:

        // reference class to a sparse row.
        class Row : public span<u64>
        {
        public:
            Row() = default;
            Row(const Row& r) = default;
            Row& operator=(const Row& r) = default;
            explicit Row(const span<u64>& r) { (span<u64>&)* this = r; }
        };

        // reference class to a sparse column.
        class Col : public span<u64>
        {
        public:
            Col() = default;
            Col(const Col& r) = default;
            Col& operator=(const Col& r) = default;
            explicit Col(const span<u64>& r) { (span<u64>&)* this = r; }
        };

        // const reference class to a sparse row.
        class ConstRow : public span<const u64>
        {
        public:
            ConstRow() = default;
            ConstRow(const ConstRow&) = default;
            ConstRow(const Row& r) : span<const u64>(r) { };
            ConstRow& operator=(const ConstRow&) = default;
            ConstRow& operator=(const Row& r) { (span<const u64>&)* this = r; return *this; };
        };
        // const reference class to a sparse column.
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

        // The row/column data is represented in a flat vector. 
        std::vector<u64> mDataRow, mDataCol;

        // Each row is a reference into the flat vectors.
        std::vector<Row> mRows;

        // Each column is a reference into the flat vectors.
        std::vector<Col> mCols;

        // the number of rows.
        u64 rows() const { return mRows.size(); }
        // the number of column.
        u64 cols() const { return mCols.size(); }

        // get the ith row by reference
        Row& row(u64 i) { return mRows[i]; }

        // get the ith column by reference
        Col& col(u64 i) { return mCols[i]; }

        // get the ith row by reference
        ConstRow row(u64 i) const { return mRows[i]; }

        // get the ith column by reference
        ConstCol col(u64 i) const { return mCols[i]; }

        bool operator()(u64 i, u64 j) const
        {
            if (i >= mRows.size() || j >= mCols.size())
                throw RTE_LOC;
            auto iter = std::find(mRows[i].begin(), mRows[i].end(), j);
            return iter != mRows[i].end();
        }

        // hash the matrix. will return the same value 
        // as hash for DenseMtx if they are equal.
        block hash() const;


        void init(PointList& list)
        {
            init(list.mRows, list.mCols, list.mPoints);
        }

        // constuct the matrix with the given points/size.
        void init(u64 rows, u64 cols, span<Point> points);

        // return the submatrix that are specified by the given columns.
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

        // return true if the coordinate is set.
        bool isSet(u64 row, u64 col);

        // check that the sparse matrix is well formed.
        bool validate();

        // vertically concatinate this matrix and the parameter.
        // this matrix will come first. The result is returned.
        SparseMtx vConcat(const SparseMtx& o) const;
        
        // returns the submatrix starting at (row, col) and of 
        // the given size.
        SparseMtx subMatrix(u64 row, u64 col, u64 rowCount, u64 colCount) const;

        // return the dense representation of this matix.
        DenseMtx dense() const;

        // multiply this matrix with the given vector.
        std::vector<u8> mult(span<const u8> x) const;

        // multiply this matrix by x and add (xor) the result to y.
        template<typename ConstVec, typename Vec>
        void multAdd(const ConstVec& x, Vec& y) const
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


        // compute y = x * this.
        template<typename ConstVec, typename Vec>
        void leftMultAdd(const ConstVec& x, Vec& y) const
        {
            assert(rows() == x.size());
            assert(y.size() == cols());
            for (u64 i = 0; i < cols(); ++i)
            {
                for (auto c : col(i))
                {
                    assert(c < rows());
                    y[i] = y[i] ^ x[c];
                }
            }
        }

        std::vector<u8> operator*(span<const u8> x) const { return mult(x); }

        // multiply this sparse matrix with X.
        SparseMtx mult(const SparseMtx& X) const;

        // multiply this sparse matrix with X.
        SparseMtx operator*(const SparseMtx& X) const { return mult(X); }

        // add this sparse matrix with X.
        SparseMtx operator+(const SparseMtx& X) const { return add(X); }

        // add this sparse matrix with X.
        SparseMtx add(const SparseMtx& X) const;

        // add X to this matrix
        SparseMtx& operator+=(const SparseMtx& X)
        {
            *this = add(X);
            return *this;
        }

        // invert this matrix. if not invertable then
        // the resturned value will have zero size.
        SparseMtx invert() const;

        // convert this sparse matrix into a vector of points.
        std::vector<Point> points() const;

        // converts this matrix into a point list.
        operator PointList() const
        {
            return PointList(mRows.size(), mCols.size(), points());
        }

        bool operator==(const SparseMtx& X) const;
        bool operator!=(const SparseMtx& X) const;
    };

    std::ostream& operator<<(std::ostream& o, const SparseMtx& H);



    // a class that represents a dense binary matrix.
    // The data is stored in column major format.
    class DenseMtx
    {
    public:
        // column major, which means we call mData.row(i) 
        // to get column i and vise versa.
        Matrix<block> mData;

        // the number of rows. This will be 
        // mData.cols() * 128 or a bit less.
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

        // resize the given matrix. If the number of rows
        // changed then the data is invalidated.
        void resize(u64 rows, u64 cols);

        // the number of rows.
        u64 rows() const { return mRows; }

        // the number of columns.
        u64 cols() const { return mData.rows(); }

        // returns a refernce to the given bit.
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

        // A referenced to the given row.
        struct Row
        {
            u64 mIdx;
            DenseMtx& mMtx;

            // swap the data of the underlying rows.
            void swap(const Row& r);

            // returns true if the row is zero.
            bool isZero() const;

            // xor the given row into this one.
            void operator^=(const Row& r);
        };

        // returns a refernce to the given row.
        Row row(u64 i) const
        {
            return Row{ i, (DenseMtx&)*this };
        }

        // returns a refernce to the given column.
        span<block> col(u64 i)
        {
            return mData[i];
        }

        // returns a refernce to the given column.
        span<const block> col(u64 i) const
        {
            return mData[i];
        }

        // return the "sparse vector" of the given column  c. 
        // The result is written to set.
        void colIndexSet(u64 c, std::vector<u64>& set)const;

        // returns a new matrix consisting of the given columns.
        DenseMtx selectColumns(span<u64> perm);

        // clears the given matrix.
        void setZero();

        // swap the given rows.
        void rowSwap(u64 i, u64 j);

        // return the sparse representation of this matrix.
        SparseMtx sparse() const;

        // multiply this matrix by m and return the result.
        DenseMtx mult(const DenseMtx& m);

        // multiply this matrix by m and return the result.
        DenseMtx operator*(const DenseMtx& m) { return mult(m); }

        // add this matrix with m and return the result.
        DenseMtx add(DenseMtx& m);

        // add this matrix with m and return the result.
        DenseMtx operator+(DenseMtx& m) { return add(m); }

        // returns the identity matrix of the given size.
        static DenseMtx Identity(u64 n);

        // Perform elementary row operations to this matrix
        // to obtain a upper triangular matrix.
        DenseMtx upperTriangular() const;

        // Perform gausian elimination and return the result.
        DenseMtx gausianElimination() const;

        // return the inverse of this matrix.
        DenseMtx invert() const;

        // return the transpose of this matrix.
        DenseMtx transpose() const;

        // return the submatrix starting at (row,col) with the given size.
        DenseMtx subMatrix(u64 row, u64 col, u64 rowCount, u64 colCount);
    };

    std::ostream& operator<<(std::ostream& o, const DenseMtx& H);

    // a small set class which stores the data sorted inside a vector.
    struct VecSortSet
    {
        std::vector<u64> mData;
        using iterator = std::vector<u64>::iterator;
        using constIerator = std::vector<u64>::const_iterator;

        iterator begin();
        iterator end();
        constIerator begin() const;
        constIerator end()const;

        iterator find(u64 i);
        constIerator find(u64 i)const;

        iterator lowerBound(u64 i);
        constIerator lowerBound(u64 i)const;

        void clear();

        // insert the items [b,e). iterators should
        // derefence to u64's.
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

        // insert i.
        void insert(u64 i);

        // insert i at the given hint. iter should lowerbound i.
        void insertHint(u64 i, iterator iter);

        // private function.
        void implInsert(u64 i, iterator iter);

        // erate i from the set. Assumes it is in the set.
        void erase(u64 i);

        // erase the given iterator.
        void erase(iterator iter);

        // the size of the set.
        u64 size() const { return mData.size(); }

        // returns the i'th sorted item in the set.
        u64& operator[](u64 i) { return mData[i]; }

        // compute the symetric set differnce and assign the result
        // to this set.
        void operator^=(const VecSortSet& o);
    };


    // A sparse matrix class thats design to have 
    // effecient manipulation operations.
    struct DynSparseMtx
    {
        // each row is stored as a set.
        std::vector<VecSortSet> mRows;

        // each column is stored as a set.
        std::vector<VecSortSet> mCols;

        DynSparseMtx() = default;
        DynSparseMtx(const DynSparseMtx&) = default;
        DynSparseMtx(DynSparseMtx&&) = default;

        DynSparseMtx(const SparseMtx& m);

        DynSparseMtx& operator=(const SparseMtx& m);
        DynSparseMtx& operator=(const DenseMtx& m);
        DynSparseMtx& operator=(const DynSparseMtx&) = default;
        DynSparseMtx& operator=(DynSparseMtx&&) = default;

        // returns the ith row.
        VecSortSet& row(u64 i) { return mRows[i]; }

        // returns the ith column.
        VecSortSet& col(u64 i) { return mCols[i]; }

        // returns the ith row.
        const VecSortSet& row(u64 i)const { return mRows[i]; }
        
        // returns the ith column.
        const VecSortSet& col(u64 i)const { return mCols[i]; }

        // returns the number of rows.
        u64 rows()const { return mRows.size(); }

        // returns the number of columns.
        u64 cols()const { return mCols.size(); }

        // resizes the matrix and maintain the invariances.
        void resize(u64 rows, u64 cols);

        // reserve space for the given matrix size.
        void reserve(u64 rows, u64 cols);

        // clears the given row and maintains the invariances.
        void clearRow(u64 i);

        // clears the given column and maintains the invariances.
        void clearCol(u64 i);

        // add the given column to the end of the matrix.
        void pushBackCol(const VecSortSet& col) { pushBackCol(span<const u64>(col.mData)); }
        
        // add the given column to the end of the matrix.
        void pushBackCol(span<const u64> col);

        // add the given row to the end of the matrix.
        void pushBackRow(const VecSortSet& row) { pushBackRow(row.mData); }

        // add the given row to the end of the matrix.
        void pushBackRow(span<const u64> row);

        // add the row indexed by r1 to r0.
        void rowAdd(u64 r0, u64 r1);

        // swap the rows indexed by r1, r0.
        void rowSwap(u64 r0, u64 r1);

        bool operator()(u64 r, u64 c) const
        {
            return mRows[r].find(c) != mRows[r].end();
        }

        // check that the row/column invariances are maintained.
        void validate();

        // construct a new matrix which is formed by the given
        // columns, as indexed by perm.
        DynSparseMtx selectColumns(span<u64> perm) const;

        // return the "sparse" representation of this matirx.
        SparseMtx sparse() const;
    };


    std::ostream& operator<<(std::ostream& o, const DynSparseMtx& H);





    namespace tests
    {
        void Mtx_block_test();
        void Mtx_make_test();
        void Mtx_add_test();
        void Mtx_mult_test();
        void Mtx_invert_test();
    }






}
