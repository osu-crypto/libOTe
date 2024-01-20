#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Util.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{


    // add the given point. SHould not have previously been added.
    PointList::PointList(u64 r, u64 c, span<const Point> pp)
        : mRows(r), mCols(c)
    {
        for (auto p : pp)
            push_back(p);
    }
    void PointList::push_back(u64 x, u64 y)
    {
        push_back({ x,y });
    }
    void PointList::push_back(const Point& p)
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

    // hash the matrix. will return the same value 
    // as hash for DenseMtx if they are equal.
    block SparseMtx::hash() const
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

    void SparseMtx::init(u64 rows, u64 cols, span<Point> points)
    {
        std::vector<u64> rowSizes(rows);
        std::vector<u64> colSizes(cols);

#define OC_INSERT_DEBUG
#ifdef OC_INSERT_DEBUG
        std::set<std::pair<u64, u64>> set;
#endif // !NDEBUG

        for (u64 i = 0; i < u64(points.size()); ++i)
        {
#ifdef OC_INSERT_DEBUG
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

    // return true if the coordinate is set.

    bool SparseMtx::isSet(u64 row, u64 col)
    {
        assert(row < rows());
        assert(col < cols());

        auto iter = std::lower_bound(
            mCols[col].begin(),
            mCols[col].end(),
            row);
        return iter != mCols[col].end() && *iter == row;
    }

    // check that the sparse matrix is well formed.

    bool SparseMtx::validate()
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

    // vertically concatinate this matrix and the parameter.
    // this matrix will come first. The result is returned.

    SparseMtx SparseMtx::vConcat(const SparseMtx& o) const
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

    SparseMtx SparseMtx::subMatrix(u64 row, u64 col, u64 rowCount, u64 colCount)const
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

    DenseMtx SparseMtx::dense() const
    {
        DenseMtx mtx(rows(), cols());

        for (u64 i = 0; i < rows(); ++i)
        {
            for (auto j : row(i))
                mtx(i, j) = 1;
        }

        return mtx;
    }

    // multiply this matrix with the given vector.

    std::vector<u8> SparseMtx::mult(span<const u8> x) const
    {
        std::vector<u8> y(rows());
        multAdd(x, y);
        return y;
    }

    // multiply this matrix by x and add (xor) the result to y.

    //void SparseMtx::multAdd(span<const u8> x, span<u8> y) const
    //{
    //    assert(cols() == x.size());
    //    assert(y.size() == rows());
    //    for (u64 i = 0; i < rows(); ++i)
    //    {
    //        for (auto c : row(i))
    //        {
    //            assert(c < cols());
    //            y[i] ^= x[c];
    //        }
    //    }
    //}

    // multiply this sparse matrix with y.

    SparseMtx SparseMtx::mult(const SparseMtx& X) const
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

    SparseMtx SparseMtx::add(const SparseMtx& p) const
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

            r.mCols[i] = (prev != r.mDataCol.size()) ?
                Col(span<u64>(r.mDataCol.begin() + prev, r.mDataCol.end())) :
                Col{};

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

            r.mRows[i] = (prev != r.mDataRow.size()) ?
                Row(span<u64>(r.mDataRow.begin() + prev, r.mDataRow.end())) :
                Row{};

            prev = r.mDataRow.size();
        }

        return r;
    }

    SparseMtx SparseMtx::invert() const
    {
        auto d = dense();
        d = d.invert();
        return d.sparse();
    }

    // convert this sparse matrix into a vector of points.

    std::vector<Point> SparseMtx::points() const
    {
        std::vector<Point> p; p.reserve(mDataCol.size());
        for (u64 i = 0; i < rows(); ++i)
        {
            for (auto c : row(i))
                p.push_back({ i,c });
        }

        return p;
    }


    bool SparseMtx::operator==(const SparseMtx& X) const
    {
        auto eq = rows() == X.rows() &&
            cols() == X.cols() &&
            mDataCol.size() == X.mDataCol.size() &&
            mDataCol == X.mDataCol;

        if (eq)
        {
            for (u64 i = 0; i < cols(); ++i)
                if (col(i).size() != X.col(i).size())
                    return false;

            return true;
        }
        else
            return false;
    }

    bool SparseMtx::operator!=(const SparseMtx& X) const
    {
        return !(*this == X);
    }



    std::ostream& operator<<(std::ostream& o, const SparseMtx& H)
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




    void DenseMtx::Row::swap(const Row& r)
    {
        assert(mMtx.cols() == r.mMtx.cols());

        for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
        {
            u8 bit = r.mMtx(r.mIdx, colIdx);
            r.mMtx(r.mIdx, colIdx) = mMtx(mIdx, colIdx);
            mMtx(mIdx, colIdx) = bit;
        }
    }

    // returns true if the row is zero.
    bool DenseMtx::Row::isZero() const
    {
        for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
        {
            u8 bit = mMtx(mIdx, colIdx);
            if (bit)
                return false;
        }
        return true;
    }

    void DenseMtx::Row::operator^=(const Row& r)
    {
        for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
        {
            mMtx(mIdx, colIdx) ^= r.mMtx(r.mIdx, colIdx);
        }
    }

    void DenseMtx::resize(u64 rows, u64 cols)
    {
        mRows = rows;
        mData.resize(cols, (rows + 127) / 128);
    }

    void DenseMtx::colIndexSet(u64 c, std::vector<u64>& set) const
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

    // returns a new matrix consisting of the given columns.

    DenseMtx DenseMtx::selectColumns(span<u64> perm)
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

    // clears the given matrix.

    void DenseMtx::setZero()
    {
        memset(mData.data(), 0, mData.size() * sizeof(oc::block));
    }

    // swap the given rows.

    void DenseMtx::rowSwap(u64 i, u64 j)
    {
        if (i != j)
        {
            row(i).swap(row(j));
        }
    }

    // return the sparse representation of this matrix.

    SparseMtx DenseMtx::sparse() const
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

    // multiply this matrix by m.

    DenseMtx DenseMtx::mult(const DenseMtx& m)
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

    // add this matrix with m and return the result.

    DenseMtx DenseMtx::add(DenseMtx& m)
    {
        assert(rows() == m.rows() && cols() == m.cols());

        auto ret = *this;
        for (u64 i = 0; i < mData.size(); ++i)
            ret.mData(i) = ret.mData(i) ^ m.mData(i);

        return  ret;
    }

    // returns the identity matrix of the given size.

    DenseMtx DenseMtx::Identity(u64 n)
    {
        DenseMtx I(n, n);

        for (u64 i = 0; i < n; ++i)
            I(i, i) = 1;

        return I;
    }

    // Perform elementary row operations to this matrix
    // to obtain a upper triangular matrix.

    DenseMtx DenseMtx::upperTriangular() const
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

    // Perform gausian elimination and return the result.
    DenseMtx DenseMtx::gausianElimination() const
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

    DenseMtx DenseMtx::invert() const
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

    // return the transpose of this matrix.

    DenseMtx DenseMtx::transpose() const
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

    // return the submatrix starting at (row,col) with the given size.

    DenseMtx DenseMtx::subMatrix(u64 row, u64 col, u64 rowCount, u64 colCount)
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

    std::ostream& operator<<(std::ostream& o, const DenseMtx& H)
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


    VecSortSet::iterator VecSortSet::begin()
    {
        return mData.begin();
    }

    VecSortSet::iterator VecSortSet::end()
    {
        return mData.end();
    }

    VecSortSet::iterator VecSortSet::find(u64 i)
    {
        auto iter = lowerBound(i);
        if (iter != end() && *iter != i)
            iter = end();
        return iter;
    }

    VecSortSet::iterator VecSortSet::lowerBound(u64 i)
    {
        return std::lower_bound(begin(), end(), i);
    }

    VecSortSet::constIerator VecSortSet::begin() const
    {
        return mData.begin();
    }

    VecSortSet::constIerator VecSortSet::end() const
    {
        return mData.end();
    }

    VecSortSet::constIerator VecSortSet::find(u64 i) const
    {
        auto iter = lowerBound(i);
        if (iter != end() && *iter != i)
            iter = end();
        return iter;
    }

    VecSortSet::constIerator VecSortSet::lowerBound(u64 i) const
    {
        return std::lower_bound(begin(), end(), i);
    }

    void VecSortSet::clear()
    {
        mData.clear();
    }

    void VecSortSet::insert(u64 i)
    {
        auto iter = lowerBound(i);
        implInsert(i, iter);
    }

    // insert i at the given hint. iter should lowerbound i.

    void VecSortSet::insertHint(u64 i, iterator iter)
    {
        assert(lowerBound(i) == iter);
        implInsert(i, iter);
    }

    void VecSortSet::implInsert(u64 i, iterator iter)
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

    void VecSortSet::erase(u64 i)
    {
        auto iter = lowerBound(i);
        assert(iter != end());
        erase(iter);
    }

    void VecSortSet::erase(iterator iter)
    {
        auto e = end() - 1;
        while (iter < e)
        {
            *iter = *(iter + 1);
            ++iter;
        }
        mData.pop_back();
    }

    void VecSortSet::operator^=(const VecSortSet& o)
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

    DynSparseMtx::DynSparseMtx(const SparseMtx& m)
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


    DynSparseMtx& DynSparseMtx::operator=(const SparseMtx& m)
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
        return *this;
    }


    DynSparseMtx& DynSparseMtx::operator=(const DenseMtx& m)
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

        return *this;
    }

    void DynSparseMtx::resize(u64 rows, u64 cols)
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

    void DynSparseMtx::reserve(u64 rows, u64 cols)
    {
        mRows.reserve(rows);
        mCols.reserve(cols);
    }

    // clears the given row and maintains the invariances.

    void DynSparseMtx::clearRow(u64 i)
    {
        assert(i < mRows.size());
        for (auto c : mRows[i])
        {
            mCols[c].erase(i);
        }
    }

    // clears the given column and maintains the invariances.

    void DynSparseMtx::clearCol(u64 i)
    {
        assert(i < mCols.size());
        for (auto r : mCols[i])
        {
            mRows[r].erase(i);
        }
    }

    void DynSparseMtx::pushBackCol(span<const u64> col)
    {
        auto c = mCols.size();
        mCols.emplace_back();
        mCols.back().insert(col.begin(), col.end());

        for (u64 i = 0; i < (u64)col.size(); ++i)
        {
            mRows[col[i]].insert(c);
        }
    }

    // add the given row to the end of the matrix.

    void DynSparseMtx::pushBackRow(span<const u64> row)
    {
        auto r = mRows.size();
        mRows.emplace_back();
        mRows.back().insert(row.begin(), row.end());

        for (u64 i = 0; i < (u64)row.size(); ++i)
        {
            mCols[row[i]].insert(r);
        }
    }

    // add the row indexed by r1 to r0.

    void DynSparseMtx::rowAdd(u64 r0, u64 r1)
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
        //validate();
    }

    // swap the rows indexed by r1, r0.

    void DynSparseMtx::rowSwap(u64 r0, u64 r1)
    {
        //validate();

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

        //validate();
    }

    // check that the row/column invariances are maintained.

    void DynSparseMtx::validate()
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
                if (mRows[j].find(i) == mRows[j].end())
                    throw RTE_LOC;
            }
        }
    }

    // construct a new matrix which is formed by the given
    // columns, as indexed by perm.

    DynSparseMtx DynSparseMtx::selectColumns(span<u64> perm) const
    {
        DynSparseMtx r;
        r.mRows.resize(rows());
        for (u64 i = 0; i < (u64)perm.size(); ++i)
        {
            r.pushBackCol(col(perm[i]));
        }
        return r;
    }

    // return the "sparse" representation of this matirx.

    SparseMtx DynSparseMtx::sparse() const
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

    std::ostream& operator<<(std::ostream& o, const DynSparseMtx& H)
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



    void tests::Mtx_make_test()
    {

        u64 n1 = 221,
            n2 = 31;

        oc::PRNG prng(block(0, 0));

        //Eigen::SparseMatrix<u8> eigen;
        //eigen.resize(n1, n2);

        oc::Matrix<u8> base(n1, n2);

        DenseMtx dense(n1, n2);
        DynSparseMtx sparse1, sparse2;
        sparse1.reserve(n1, n2); sparse1.resize(0, n2);
        sparse2.reserve(n1, n2); sparse2.resize(n1, 0);
        std::vector<Point> points;

        for (u64 i = 0; i < n1; ++i)
        {
            std::vector<u64> row;
            for (u64 j = 0; j < n2; ++j)
            {
                base(i, j) = prng.getBit();
                dense(i, j) = base(i, j);


                if (base(i, j))
                {
                    row.push_back(j);
                    points.push_back({ i,j });
                    //eigen.insert(i, j);
                }
            }
            sparse1.pushBackRow(row);
        }

        SparseMtx sparse3;
        sparse3.init(n1, n2, points);


        for (u64 j = 0; j < n2; ++j)
        {
            std::vector<u64> col;
            for (u64 i = 0; i < n1; ++i)
            {
                if (base(i, j))
                {
                    col.push_back(i);
                }
            }
            sparse2.pushBackCol(col);
        }

        for (u64 i = 0; i < n1; ++i)
        {
            for (u64 j = 0; j < n2; ++j)
            {
                if (base(i, j) != dense(i, j))
                {
                    std::cout << i << " " << j << " " << LOCATION << std::endl;
                    abort();
                }
            }
        }


        if (!(sparse1.sparse() == sparse2.sparse()))
        {
            std::cout << LOCATION << std::endl;
            abort();
        }
        if (!(sparse1.sparse() == dense.sparse()))
        {
            std::cout << LOCATION << std::endl;
            abort();
        }

    }

    void tests::Mtx_add_test()
    {

        u64 n1 = 20,
            n2 = 30;

        oc::PRNG prng(block(0, 0));

        DenseMtx d1(n1, n2);
        DenseMtx d2(n1, n2);

        for (u64 i = 0; i < n1; ++i)
            for (u64 j = 0; j < n2; ++j)
            {
                d1(i, j) = prng.getBit();
                d2(i, j) = prng.getBit();
            }

        auto s1 = d1.sparse();
        auto s2 = d2.sparse();



        auto d3 = d1 + d2;
        auto s3 = s1 + s2;

        assert(s3 == d3.sparse());
        assert(d3 == s3.dense());
    }
    void tests::Mtx_mult_test()
    {
        u64 n1 = 20,
            n2 = 30,
            n3 = 40;

        oc::PRNG prng(block(0, 0));

        DenseMtx d1(n1, n2);
        DenseMtx d2(n2, n3);

        for (u64 i = 0; i < n1; ++i)
            for (u64 j = 0; j < n2; ++j)
                d1(i, j) = prng.getBit();

        for (u64 i = 0; i < n2; ++i)
            for (u64 j = 0; j < n3; ++j)
                d2(i, j) = prng.getBit();

        auto s1 = d1.sparse();
        auto s2 = d2.sparse();



        auto d3 = d1 * d2;
        auto s3 = s1 * s2;

        assert(s3 == d3.sparse());
        assert(d3 == s3.dense());
    }

    void tests::Mtx_invert_test()
    {

        u64 n1 = 40;

        oc::PRNG prng(block(0, 0));

        DenseMtx d1(n1, n1);

        for (u64 i = 0; i < n1; ++i)
        {
            for (u64 j = 0; j < n1; ++j)
            {
                auto b = prng.getBit();
                //std::cout << int(b) << " ";
                d1(i, j) = b;
            }
            //std::cout << "\n";

        }
        //std::cout << "\nin \n" << d1 << std::endl;

        auto inv = d1.invert();

        auto I = d1 * inv;

        assert(I == DenseMtx::Identity(n1));

    }

    void tests::Mtx_block_test()
    {
#ifdef ENABLE_DLPC
        oc::PRNG prng(block(0, 0));

        u64 n = 10, w = 4;
        auto n2 = n / 2;
        auto M = sampleFixedColWeight(n, n, w, prng, false);


        auto M00 = M.subMatrix(0, 0, n2, n2);
        auto M01 = M.subMatrix(0, n2, n2, n2);
        auto M10 = M.subMatrix(n2, 0, n2, n2);
        auto M11 = M.subMatrix(n2, n2, n2, n2);


        //std::cout << M << std::endl;
        //std::cout << M00 << std::endl;
        //std::cout << M01 << std::endl;
        //std::cout << M10 << std::endl;
        //std::cout << M11 << std::endl;

#ifndef NDEBUG
        u64 cc =
            M00.mDataCol.size() +
            M01.mDataCol.size() +
            M10.mDataCol.size() +
            M11.mDataCol.size(),
            rr =
            M00.mDataRow.size() +
            M01.mDataRow.size() +
            M10.mDataRow.size() +
            M11.mDataRow.size();
#endif


        assert(cc == M.mDataCol.size());
        assert(rr == M.mDataRow.size());

        assert(M.validate());
        assert(M00.validate());
        assert(M01.validate());
        assert(M10.validate());
        assert(M11.validate());

        for (u64 i = 0; i < n2; ++i)
        {
            for (u64 j = 0; j < n2; ++j)
            {
                assert(M.isSet(i, j) == M00.isSet(i, j));
                assert(M.isSet(i, j + n2) == M01.isSet(i, j));
                assert(M.isSet(i + n2, j) == M10.isSet(i, j));
                assert(M.isSet(i + n2, j + n2) == M11.isSet(i, j));
            }
        }
#endif

    }


}


