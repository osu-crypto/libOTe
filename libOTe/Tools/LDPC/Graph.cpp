#include "Graph.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/TestCollection.h>
#include <random>
#include <numeric>
//#include "sparsehash/dense_hash_set"
//#include "sparsehash/sparse_hash_set"

//#include "../flat_hash_map/bytell_hash_map.hpp"
//#include "../hopscotch-map/include/tsl/bhopscotch_set.h"
//#include "../hopscotch-map/include/tsl/hopscotch_set.h"
//#include "../ordered-map/include/tsl/ordered_set.h"
//#include "../sparse-map/include/tsl/sparse_set.h"
//#include "../robin-map/include/tsl/robin_set.h"
//#include "../cpp-btree/btree/set.h"
//#include "absl/container/btree_set.h"
//#include "absl/container/flat_hash_set.h"
//#include "absl/container/node_hash_set.h"

#define LDPC_DEBUG

namespace osuCrypto
{


    void print(std::ostream& o, const Matrix<u64>& rows, u64 cols)
    {

        for (u64 i = 0; i < rows.rows(); ++i)
        {
            std::unordered_set<u64> c;
            for (u64 j = 0; j < rows.cols(); j++)
                c.insert(rows(i, j));

            for (u64 j = 0; j < cols; ++j)
            {
                if (c.find(j) != c.end())
                {
                    o << "1 ";
                }
                else
                {
                    o << "0 ";
                }
            }
            o << "\n";
        }

        o << "\n";
    }

    std::ostream& operator<<(std::ostream& o, const LDPC& s)
    {
        print(o, s.mRows, s.cols());
        return o;
    }

    //std::ostream& operator<<(std::ostream& o, const LDPC2& s)
    //{
    //    print(o, s.mRows, s.cols());
    //    return o;
    //}

    template<typename T>
    std::ostream& operator<<(std::ostream& o, const diff<T>& s)
    {
        std::array<oc::Color, 2> colors{ oc::Color::Blue, oc::Color::Green };
        u8 rowColorIdx = 0;
        for (u64 i = 0; i < s.mL.mRows.rows(); ++i)
        {

            std::unordered_set<u64> lc, rc;
            for (u64 j = 0; j < s.mL.mRows.cols(); j++)
                lc.insert(s.mL.mRows(i, j));
            for (u64 j = 0; j < s.mR.mRows.cols(); j++)
                rc.insert(s.mR.mRows(i, j));

            auto diffCols = lc;
            for (auto c : rc)
            {
                auto iter = diffCols.find(c);
                if (iter == diffCols.end())
                    diffCols.insert(c);
                else
                    diffCols.erase(iter);
            }

            if (std::find(s.mRIdx.begin(), s.mRIdx.end(), i) != s.mRIdx.end())
            {
                rowColorIdx ^= 1;
            }

            auto colorIdx = rowColorIdx;
            for (u64 j = 0; j < s.mL.cols(); ++j)
            {

                if (std::find(s.mCIdx.begin(), s.mCIdx.end(), j) != s.mCIdx.end())
                {
                    colorIdx ^= 1;
                }


                if (diffCols.find(j) != diffCols.end())
                    o << oc::Color::Red;
                else
                    o << colors[colorIdx];

                if (lc.find(j) != lc.end())
                {
                    o << "1 ";
                }
                else
                {
                    o << "0 ";
                }
                o << oc::Color::Default;
            }

            if (s.mWeights)
                o << "   " << (*s.mWeights)[i];
            o << "\n";
        }

        return o;
    }

    bool isBlockTriangular(LDPC& H, std::vector<u64>& R, std::vector<u64>& C)
    {
        u64 curRowIdx = 0;
        for (u64 i = 0; i < H.cols(); ++i)
        {
            auto& col = H.col(i);
            auto iter = H.colMinRowIdx(i);
            u64 m = iter == nullptr ? ~0ull : *iter;
            if (m < curRowIdx)
            {
                std::cout << H << std::endl;
                return false;
            }

            curRowIdx = m;
        }

        for (u64 i = 0; i < C.size() - 1; ++i)
        {
            auto cBegin = C[i];
            auto cEnd = C[i + 1];
            auto minRowIdx = R[i];

            for (u64 j = cBegin; j < cEnd; ++j)
            {
                auto& col = H.col(j);
                auto iter = H.colMinRowIdx(j);
                if (iter != nullptr && *iter < minRowIdx)
                {
                    return false;
                }
            }
        }

        return true;
    }


    //bool isBlockTriangular(LDPC2& H, std::vector<u64>& R, std::vector<u64>& C)
    //{
    //    u64 curRowIdx = 0;
    //    for (u64 i = 0; i < H.cols(); ++i)
    //    {
    //        auto col = H.col(i);
    //        auto iter = std::min_element(col.begin(), col.end());
    //        u64 m = iter == col.end() ? ~0ull : *iter;
    //        if (m < curRowIdx)
    //        {
    //            std::cout << H << std::endl;
    //            return false;
    //        }

    //        curRowIdx = m;
    //    }

    //    for (u64 i = 0; i < C.size() - 1; ++i)
    //    {
    //        auto cBegin = C[i];
    //        auto cEnd = C[i + 1];
    //        auto minRowIdx = R[i];

    //        for (u64 j = cBegin; j < cEnd; ++j)
    //        {
    //            auto& col = H.col(j);
    //            auto iter = std::min_element(col.begin(), col.end());
    //            if (iter != col.end() && *iter < minRowIdx)
    //            {
    //                return false;
    //            }
    //        }
    //    }

    //    return true;
    //}


    void LDPC::Columns::init(u64 cols, span<std::array<u64, 2>> points, double scaling)
    {
        if (scaling < 1)
            scaling = 5;
        mWidth = std::max<u64>(points.size() * scaling / cols, 1);
        mCore.resize(cols, mWidth + 2);

        std::vector<std::array<u64, 2>> extras;
        std::unordered_map<u64, u64> extraSizes;
        //std::vector<std::vector<u64>> cc(cols);
        for (auto& p : points)
        {
            //cc[p[1]].push_back(p[0]);
            auto col = mCore[p[1]];
            auto& s = col[0];
            if (s < mWidth)
                col[2 + s] = p[0];
            else
            {
                ++extraSizes[p[1]];
                extras.push_back(p);
            }
            ++s;
        }
        //std::vector<u64> dist(10);
        //for (u64 i = 0; i < mCore.rows(); ++i)
        //{
        //    auto ss = mCore(i, 0);
        //    if (dist.size() + 1 < ss)
        //    {
        //        dist.resize(ss + 1);
        //    }
        //    ++dist[ss];
        //}
        //
        //std::cout << points.size() << std::endl;
        //
        //for (u64 i = 0; i < dist.size(); ++i)
        //{
        //    std::cout << "d " << i << "  " << dist[i] <<  " " << (double(dist[i]) / points.size()) << std::endl;
        //}

        if (extras.size())
        {

            mExtra.resize(extras.size());
            auto iter = mExtra.data();

            for (auto ee : extraSizes)
            {
                auto colIdx = ee.first;
                auto extraSize = ee.second;

                auto& c = col(colIdx);
                c.mExtra = iter;
                c.mSize -= extraSize;
                iter += extraSize;

            }

            //#ifdef LDPC_DEBUG
            if (iter != mExtra.data() + mExtra.size())
                throw RTE_LOC;

            for (std::array<u64, 2> p : extras)
            {
                auto& c = col(p[1]);
                auto d = c.mSize++;
                c.mExtra[d - mWidth] = p[0];
            }
            //#endif
        }
    }

    void LDPC::insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points)
    {
        if (rows * rowWeight != points.size())
            throw RTE_LOC;

        mNumCols = cols;
        mRows.resize(0, 0);
        mRows.resize(rows, rowWeight);
        mColumns.init(cols, points);

        std::vector<u64> rowPos(rows);
        for (auto& p : points)
        {
            auto r = p[0];
            auto c = p[1];

            if (rowPos[r] >= mRows.cols())
            {
                std::stringstream ss; ss << "only " << mRows.cols() << "items can be added to a row";
                throw std::runtime_error(ss.str());
            }
            mRows(r, rowPos[r]++) = c;
        }
    }

    void LDPC::moveRows(u64 destIter, std::unordered_set<u64> srcRows)
    {
        while (srcRows.size())
        {
            auto sIter = srcRows.find(destIter);
            if (sIter == srcRows.end())
            {
                swapRow(destIter, *srcRows.begin());
                srcRows.erase(srcRows.begin());
            }
            else
                srcRows.erase(sIter);
            ++destIter;
        }
    }
    void LDPC::swapRow(u64 r0, u64 r1)
    {
        if (r0 == r1)
            return;
        validate();

        auto rr0 = mRows[r0];
        auto rr1 = mRows[r1];

        for (u64 i = 0; i < rr0.size(); ++i)
        {
            auto c0 = col(rr0[i]).find(r0, mColumns.mWidth);
            assert(c0);
            *c0 = r1;

            auto c1 = col(rr1[i]).find(r1, mColumns.mWidth);
            assert(c1);
            *c1 = r0;

            //auto col0 = colMain(rr0[i]);
            //auto col1 = colMain(rr1[i]);

            //auto m = col0.second;
            //auto iter = std::find(m.begin(), m.end(), r0);
            //if (iter == m.end())
            //{
            //    m = colExtra(rr0[i]);
            //    iter = std::find(m.begin(), m.end(), r0);
            //}
            //*iter = r1;


            //m = col1.second;
            //iter = std::find(m.begin(), m.end(), r0);
            //if (iter == m.end())
            //{
            //    m = colExtra(rr1[i]);
            //    iter = std::find(m.begin(), m.end(), r0);
            //}
            //*iter = r0;
        }

        std::swap_ranges(rr0.begin(), rr0.end(), rr1.begin());

        validate();
    }
    //void LDPC::moveCols(u64 destIter, std::unordered_set<u64> srcCols)
    //{
    //    while (srcCols.size())
    //    {
    //        auto sIter = srcCols.find(destIter);
    //        if (sIter == srcCols.end())
    //        {
    //            swapCol(destIter, *srcCols.begin());
    //            srcCols.erase(srcCols.begin());
    //        }
    //        else
    //            srcCols.erase(sIter);

    //        ++destIter;
    //    }
    //}
    void LDPC::swapCol(u64 c0, u64 c1)
    {
        if (c0 == c1)
            return;

        //auto debugC0 = 


        auto update = [this](span<u64>m, u64 c0, u64 c1)
        {
            for (auto rIdx : m)
            {
                auto row = mRows[rIdx];
                *std::find(row.begin(), row.end(), c0) = c1;
            }
        };

        auto cc0 = colMain(c0);
        update(cc0.second, c0, c1);
        if (cc0.first)
            update(colExtra(c0), c0, c1);

        auto cc1 = colMain(c1);
        update(cc1.second, c1, c0);
        if (cc1.first)
            update(colExtra(c1), c1, c0);

        auto core0 = mColumns.mCore[c0];
        auto core1 = mColumns.mCore[c1];
        std::swap_ranges(core0.begin(), core0.end(), core1.begin());

        //auto& col0 = col(c0);
        //auto& col1 = col(c1);
        //std::swap(col0.mSize, col1.mSize);
        //std::swap(col0.mExtra, col1.mExtra);
        validate();

    }
    void LDPC::validate()
    {
        //#ifdef LDPC_DEBUG
        //        for (u64 i = 0; i < rows(); ++i)
        //        {
        //            for (u64 j = 0; j < rowWeight(); ++j)
        //            {
        //                auto cIdx = mRows(i, j);
        //                auto& c = col(cIdx);
        //
        //                if (c.mSize != 0)
        //                {
        //                    auto m = c.find(i, mColumns.mWidth);
        //                    if (!m)
        //                        throw RTE_LOC;
        //                }
        //            }
        //        }
        //#endif
    }

    void LDPC::blockTriangulate(std::vector<u64>& R, std::vector<u64>& C, bool verbose)
    {
        u64 n = cols();
        u64 m = rows();
        u64 k = 0;
        u64 i = 0;
        u64 v = n;

        R.resize(0);
        C.resize(0);

        std::vector<u64> colSwaps;

        std::unique_ptr<LDPC> HH;
        if (verbose)
        {
            HH.reset(new LDPC(*this));
        }

        std::vector<u64> rowWeights(m, rowWeight());
        std::array<std::vector<u64>, 2> smallWeightSets;
        std::vector<std::unordered_set<u64>> bigWeightSets;
        // a mapping from a given weight to all rows that have that weight.
        bigWeightSets.resize(rowWeight() + 1 - smallWeightSets.size());
        smallWeightSets[0].reserve(10);
        smallWeightSets[1].reserve(40);
        for (u64 i = 0; i < rows(); ++i)
            bigWeightSets.back().insert(i);

        auto popMinWeightRow = [&]() {
            for (u64 i = 1; i < smallWeightSets.size(); ++i)
            {
                if (smallWeightSets[i].size())
                {
                    auto idx = smallWeightSets[i].back();
                    smallWeightSets[i].pop_back();
                    rowWeights[idx] = 0;
                    return std::pair<u64, u64>{ idx, i };
                }
            }

            for (u64 i = 0; i < bigWeightSets.size(); i++)
            {
                if (bigWeightSets[i].size())
                {
                    auto iter = bigWeightSets[i].begin();
                    auto idx = *iter;
                    bigWeightSets[i].erase(iter);
                    rowWeights[idx] = 0;
                    return std::pair<u64, u64>{ idx, i + smallWeightSets.size() };
                }
            }

            throw RTE_LOC;
        };

        auto decRowWeight = [&](u64 idx) {
            auto w = rowWeights[idx]--;
            assert(w);

            if (w > smallWeightSets.size() - 1)
            {
                auto i = w - smallWeightSets.size();

                auto iter = bigWeightSets[i].find(idx);
                assert(iter != bigWeightSets[i].end());
                bigWeightSets[i].erase(iter);

                if (i)
                    bigWeightSets[i - 1].insert(idx);
                else
                    smallWeightSets.back().push_back(idx);
            }
            else
            {
                assert(w);
                auto iter = std::find(smallWeightSets[w].begin(), smallWeightSets[w].end(), idx);
                assert(iter != smallWeightSets[w].end());
                std::swap(smallWeightSets[w].back(), *iter);
                smallWeightSets[w].pop_back();
                smallWeightSets[w - 1].push_back(idx);
            }
        };

        auto moveRowWeight = [&](u64 srcRow, u64 destRow)
        {
            if (srcRow == destRow)
                return;

            auto w = rowWeights[srcRow];
            std::swap(rowWeights[srcRow], rowWeights[destRow]);
            assert(w > 0);

            if (w > smallWeightSets.size() - 1)
            {
                auto i = w - smallWeightSets.size();

                auto iter = bigWeightSets[i].find(srcRow);
                assert(iter != bigWeightSets[i].end());
                bigWeightSets[i].erase(iter);
                bigWeightSets[i].insert(destRow);
            }
            else
            {
                assert(w);
                auto iter = std::find(smallWeightSets[w].begin(), smallWeightSets[w].end(), srcRow);
                assert(iter != smallWeightSets[w].end());
                *iter = destRow;
            }
        };


        //auto swapRowWeight = [&](u64 r0, u64 r1)
        //{
        //    assert(r0 != r1);

        //    auto w0 = rowWeights[r0];
        //    auto w1 = rowWeights[r1];

        //    assert(w0 == 0 && w1 != 0);

        //    std::swap(rowWeights[r0], rowWeights[r1]);


        //    if (w > smallWeightSets.size() - 1)
        //    {
        //        auto i = w - smallWeightSets.size();

        //        auto iter = bigWeightSets[i].find(srcRow);
        //        assert(iter != bigWeightSets[i].end());
        //        bigWeightSets[i].erase(iter);
        //        bigWeightSets[i].insert(destRow);
        //    }
        //    else
        //    {
        //        assert(w);
        //        auto iter = std::find(smallWeightSets[w].begin(), smallWeightSets[w].end(), srcRow);
        //        assert(iter != smallWeightSets[w].end());
        //        *iter = destRow;
        //    }
        //};



        while (i < m && v)
        {
            if (smallWeightSets[0].size() == 0)
            {
                // If we don't have any rows with hamming
                // weight 0 then we will pick the row with 
                // minimim hamming weight and move it to the
                // top of the view.
                auto uu = popMinWeightRow();
                auto u = uu.first;
                auto wi = uu.second;

                // move the min weight row u to row i.
                auto ii = (i);
                assert(u >= i);
                swapRow(u, ii);
                moveRowWeight(ii, u);

                if (verbose) {
                    std::cout << "wi " << wi << std::endl;
                    std::cout << "swapRow(" << i << ", " << u << ")" << std::endl;
                }

                // For this newly moved row i, we need to move all the 
                // columns where this row has a non-zero value to the
                // left side of the view. 

                // c1 is the column defining the left side of the view
                auto c1 = (n - v);

                // rIter iterates the columns which have non-zero values for row ii.
                auto row = mRows[ii];

                // this set will collect all of the columns in the view. 
                colSwaps.clear();


                for (u64 j = 0; j < rowWeight(); ++j)
                {
                    //auto c0 = colIdx[j];
                    auto c0 = row[j];

                    // check if this column is inside the view.
                    if (c0 >= c1)
                    {
                        // add this column to the set of columns that we will move.
                        colSwaps.push_back(c0);

                        if (verbose)
                            std::cout << "swapCol(" << c0 << ")" << std::endl;

                        // iterator over the rows for this column and decrement their row weight.
                        // we do this since we are about to move this column outside of the view.
                        //auto cIter = H.colIterator(c0);
                        //auto& cc = col(c0);
                        auto cc = colMain(c0);
                        for (auto c : cc.second)
                        {
                            // these a special case that this row is the u row which
                            // has already been decremented
                            if (c != i)
                                decRowWeight(c);
                        }

                        if (cc.first)
                        {
                            auto ee = colExtra(c0);
                            for (auto c : ee)
                                if (c != i)
                                    decRowWeight(c);
                        }
                    }
                }

                // now update the mappings so that these columns are
                // right before the view.
                while (colSwaps.size())
                {
                    auto sIter = std::find(colSwaps.begin(), colSwaps.end(), c1);
                    if (sIter != colSwaps.end())
                    {
                        std::swap(*sIter, colSwaps.back());
                    }
                    else
                    {
                        swapCol(c1, colSwaps.back());
                    }
                    ++c1;
                    colSwaps.pop_back();
                }

                if (verbose)
                {
                    std::cout << "v " << (v - wi) << " = " << v << " - " << wi << std::endl;
                    std::cout << "i " << (i + 1) << " = " << i << " + 1" << std::endl;
                }

                // move the view right by wi.
                v = v - wi;

                // move the view down by 1
                ++i;
            }
            else
            {
                // in the case that we have some rows with
                // hamming weight 0, we will move all these
                // rows to the top of the view and remove them.


                auto& rows = smallWeightSets[0];
                auto dk = rows.size();

                // the top of the view.
                auto c1 = i;

                while (rows.size())
                {
                    // check that there isn't already a row
                    // that we want at the top.
                    auto sIter = std::find(rows.begin(), rows.end(), c1);

                    if (sIter == rows.end())
                    {
                        // if not then pick an arbitrary row
                        // that we will move to the top.
                        sIter = rows.begin();

                        swapRow(c1, *sIter);
                        moveRowWeight(c1, *sIter);
                    }

                    // decrement the row weight to -1 to 
                    // denote that its outside the view.
                    assert(rowWeights[c1] == 0ull);

                    if (verbose)
                        std::cout << "rowSwap*(" << c1 << ", " << c1 << ")" << std::endl;

                    rows.erase(sIter);
                    ++c1;
                }

                // recode that this the end of the block.
                R.push_back(i + dk);
                C.push_back(n - v);

                if (verbose)
                {
                    std::cout << "RC " << R.back() << " " << C.back() << std::endl;
                    std::cout << "i " << (i + dk) << " = " << i << " + " << dk << std::endl;
                    std::cout << "k " << (k + 1) << " = " << k << " + 1" << std::endl;
                }

                i += dk;
                ++k;
            }

            if (verbose)
            {

                auto RR = R; RR.push_back(i);
                auto CC = C; CC.push_back(n - v);

                //std::vector<u64> 

                std::cout << "\n" << LDPC::Diff(*this, *HH, RR, CC, &rowWeights) << std::endl
                    << "=========================================\n"
                    << std::endl;

                *HH = *this;
            }
        }

        R.push_back(m);
        C.push_back(n);
    }



    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////








    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////

//
//    struct View
//    {
//        struct Idx
//        {
//            u64 mIdx, mSrcIdx;
//
//            bool operator==(Idx const& y) const
//            {
//                if (mIdx == y.mIdx)
//                {
//                    assert(mSrcIdx == y.mSrcIdx);
//                }
//                else
//                    assert(mSrcIdx != y.mSrcIdx);
//
//
//                return mIdx == y.mIdx;
//            }
//        };
//
//        struct RowIter
//        {
//            View& mH;
//            span<u64> mRow;
//            u64 mPos;
//
//            RowIter(View& H, const Idx& i, u64 p)
//                : mH(H)
//                , mRow(H.mH.mRows[i.mSrcIdx])
//                , mPos(p)
//            { }
//
//            void operator++()
//            {
//                ++mPos;
//            }
//
//            Idx operator*()
//            {
//                Idx idx;
//                idx.mSrcIdx = mRow[mPos];
//                idx.mIdx = mH.mColONMap[idx.mSrcIdx];
//                return idx;
//            }
//        };
//
//        struct ColIter
//        {
//            View& mH;
//            span<u64> mCol;
//            u64 mPos;
//
//            ColIter(View& H, const Idx& i, u64 p)
//                : mH(H)
//                , mCol(H.mH.col(i.mSrcIdx))
//                , mPos(p)
//            { }
//
//            void operator++()
//            {
//                ++mPos;
//            }
//
//            Idx operator*()
//            {
//                Idx idx;
//                idx.mSrcIdx = mCol[mPos];
//                idx.mIdx = mH.mRowONMap[idx.mSrcIdx];
//                return idx;
//            }
//
//            u64 srcIdx()
//            {
//                return mCol[mPos];
//            }
//
//            operator bool()
//            {
//                return mPos < mCol.size();
//            }
//        };
//        std::vector<u64> mRowNOMap, mRowONMap, mColNOMap, mColONMap;
//        LDPC2& mH;
//
//        // a mapping from rIter IDX to current weight
//        std::vector<u64> mRowWeights;// (m, mRows.cols());
//
//        std::array<std::vector<u64>, 2> mSmallWeightSets;
//        std::vector<btree::set<u64>> mBigWeightSets;
//
//        View(LDPC2& b)
//            : mH(b)
//            , mRowNOMap(b.rows())
//            , mRowONMap(b.rows())
//            , mColNOMap(b.cols())
//            , mColONMap(b.cols())
//            , mRowWeights(b.rows(), b.rowWeight())
//        {
//            // a mapping from a given weight to all rows that have that weight.
//            mBigWeightSets.resize(b.rowWeight() + 1 - mSmallWeightSets.size());
//            mSmallWeightSets[0].reserve(10);
//            mSmallWeightSets[1].reserve(40);
//            for (u64 i = 0; i < b.rows(); ++i)
//                mBigWeightSets.back().insert(i);
//
//            for (u64 i = 0; i < mRowNOMap.size(); ++i)
//                mRowNOMap[i] = mRowONMap[i] = i;
//
//            for (u64 i = 0; i < mColNOMap.size(); ++i)
//                mColNOMap[i] = mColONMap[i] = i;
//        }
//
//        void swapRows(Idx& r0, Idx& r1)
//        {
//            assert(r0.mSrcIdx == rowIdx(r0.mIdx).mSrcIdx);
//            assert(r1.mSrcIdx == rowIdx(r1.mIdx).mSrcIdx);
//
//            std::swap(mRowNOMap[r0.mIdx], mRowNOMap[r1.mIdx]);
//            std::swap(mRowONMap[r0.mSrcIdx], mRowONMap[r1.mSrcIdx]);
//            std::swap(r0.mSrcIdx, r1.mSrcIdx);
//        }
//
//        void swapCol(Idx& c0, Idx& c1)
//        {
//            assert(c0.mSrcIdx == colIdx(c0.mIdx).mSrcIdx);
//            assert(c1.mSrcIdx == colIdx(c1.mIdx).mSrcIdx);
//
//            std::swap(mColNOMap[c0.mIdx], mColNOMap[c1.mIdx]);
//            std::swap(mColONMap[c0.mSrcIdx], mColONMap[c1.mSrcIdx]);
//            std::swap(c0.mSrcIdx, c1.mSrcIdx);
//        };
//
//        u64 rowWeight(u64 r)
//        {
//            return mRowWeights[mRowNOMap[r]];
//        }
//
//        Idx rowIdx(u64 viewIdx)
//        {
//            return { viewIdx, mRowNOMap[viewIdx] };
//        }
//        Idx rowSrcIdx(u64 viewIdx)
//        {
//            return { mRowONMap[viewIdx], viewIdx };
//        }
//        Idx colIdx(u64 viewIdx)
//        {
//            return { viewIdx, mColNOMap[viewIdx] };
//        }
//
//        RowIter rowIterator(const Idx& row)
//        {
//            assert(row.mSrcIdx == rowIdx(row.mIdx).mSrcIdx);
//
//            return RowIter(*this, row, 0);
//        }
//
//        ColIter colIterator(const Idx& col)
//        {
//            assert(col.mSrcIdx == colIdx(col.mIdx).mSrcIdx);
//            return ColIter(*this, col, 0);
//        }
//
//        std::pair<Idx, u64> popMinWeightRow()
//        {
//            Idx idx;
//            for (u64 i = 1; i < mSmallWeightSets.size(); ++i)
//            {
//                if (mSmallWeightSets[i].size())
//                {
//                    idx.mSrcIdx = mSmallWeightSets[i].back();
//                    mSmallWeightSets[i].pop_back();
//                    idx.mIdx = mRowONMap[idx.mSrcIdx];
//                    mRowWeights[idx.mSrcIdx] = -1;
//                    return { idx, i };
//                }
//            }
//
//            for (u64 i = 0; i < mBigWeightSets.size(); i++)
//            {
//                if (mBigWeightSets[i].size())
//                {
//                    auto iter = mBigWeightSets[i].begin();
//                    idx.mSrcIdx = *iter;
//                    idx.mIdx = mRowONMap[idx.mSrcIdx];
//                    mBigWeightSets[i].erase(iter);
//                    mRowWeights[idx.mSrcIdx] = -1;
//                    return { idx, i + mSmallWeightSets.size() };
//                }
//            }
//
//            throw RTE_LOC;
//        }
//
//        void decRowWeight(const Idx& idx)
//        {
//            //assert(idx.mSrcIdx == rowIdx(idx.mIdx).mSrcIdx);
//            auto w = mRowWeights[idx.mSrcIdx]--;
//            if (w > 1)
//            {
//                auto i = w - mSmallWeightSets.size();
//
//                auto iter = mBigWeightSets[i].find(idx.mSrcIdx);
//                assert(iter != mBigWeightSets[i].end());
//                mBigWeightSets[i].erase(iter);
//
//                if (i)
//                    mBigWeightSets[i - 1].insert(idx.mSrcIdx);
//                else
//                    mSmallWeightSets.back().push_back(idx.mSrcIdx);
//            }
//            else
//            {
//                assert(w);
//                auto iter = std::find(mSmallWeightSets[w].begin(), mSmallWeightSets[w].end(), idx.mSrcIdx);
//                assert(iter != mSmallWeightSets[w].end());
//                std::swap(mSmallWeightSets[w].back(), *iter);
//                mSmallWeightSets[w].pop_back();
//                mSmallWeightSets[w - 1].push_back(idx.mSrcIdx);
//            }
//        }
//
//        void applyPerm(LDPC2& H)
//        {
//            Matrix<u64> newRows(H.rows(), H.rowWeight());
//            for (u64 i = 0; i < H.mRows.rows(); i++)
//            {
//                for (u64 j = 0; j < H.mRows.cols(); ++j)
//                {
//                    newRows(mRowONMap[i], j) = mColONMap[H.mRows(i, j)];
//                }
//            }
//            H.mRows = std::move(newRows);
//
//            std::vector<u64> newCols(H.mColData.size());
//            std::vector<u64> colStartIdxs(H.cols() + 1);
//            for (u64 i = 0, c = 0; i < H.cols(); ++i)
//            {
//                auto oIdx = mColNOMap[i];
//                auto b = H.mColStartIdxs[oIdx];
//                auto e = H.mColStartIdxs[oIdx + 1];
//                colStartIdxs[i + 1] = colStartIdxs[i] + (e - b);
//
//                while (b < e)
//                {
//                    newCols[c++] = mRowONMap[H.mColData[b++]];
//                }
//            }
//            H.mColStartIdxs = std::move(colStartIdxs);
//            H.mColData = std::move(newCols);
//        }
//
//    };
//
//}
//
//namespace std
//{
//    template<> struct hash<oc::View::Idx>
//    {
//        std::size_t operator()(oc::View::Idx const& i) const noexcept
//        {
//            return i.mIdx;
//        }
//    };
//}
//
//namespace ldpc
//{
//
//    void LDPC2::insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points)
//    {
//        if (rows * rowWeight != points.size())
//            throw RTE_LOC;
//
//        mNumCols = cols;
//        mRows.resize(0, 0);
//        mRows.resize(rows, rowWeight);
//        memset(mRows.data(), -1, mRows.size() * sizeof(u64));
//
//        mColData.clear();
//        mColData.resize(rows * rowWeight);
//        memset(mColData.data(), -1, mColData.size() * sizeof(u64));
//        mColStartIdxs.resize(cols + 1);
//
//        for (auto& p : points)
//            ++mColStartIdxs[p[1] + 1];
//
//        for (u64 i = 1; i < mColStartIdxs.size(); ++i)
//            mColStartIdxs[i] += mColStartIdxs[i - 1];
//        std::vector<u64> colPos(mColStartIdxs.begin(), mColStartIdxs.end()), rowPos(rows);
//
//        for (auto& p : points)
//        {
//            auto r = p[0];
//            auto c = p[1];
//
//            if (rowPos[r] >= mRows.cols())
//            {
//                std::stringstream ss; ss << "only " << mRows.cols() << "items can be added to a row";
//                throw std::runtime_error(ss.str());
//            }
//            mRows(r, rowPos[r]++) = c;
//            //col(c)[colPos[c]++] = r;
//            mColData[colPos[c]++] = r;
//        }
//    }
//
//    void LDPC2::blockTriangulate(std::vector<u64>& R, std::vector<u64>& C, bool verbose, bool stats)
//    {
//
//        u64 n = cols();
//        u64 m = rows();
//        u64 k = 0;
//        u64 i = 0;
//        u64 v = n;
//
//        R.resize(0);
//        C.resize(0);
//
//        // temps
//        std::vector<View::Idx> colSwaps;
//
//
//        // We are going to create a 'view' over the matrix.
//        // At each iterations we will move some of the rows 
//        // and columns in the view to the top/left. These 
//        // moved rows will then be excluded from the view.
//        // 
//        View H(*this);
//        std::unique_ptr<LDPC2> HH;
//        if (verbose)
//        {
//            HH.reset(new LDPC2(*this));
//        }
//
//        //std::vector<View::Idx> colIdx(rowWeight());
//        std::vector<u64> dks;
//        std::vector<double> avgs(rowWeight() + 1);
//        std::vector<u64> max(rowWeight() + 1);
//        u64 numSamples(0);
//
//        while (i < m && v)
//        {
//            numSamples++;
//            for (u64 j = 0; j < H.mSmallWeightSets.size(); ++j)
//            {
//                avgs[j] += H.mSmallWeightSets[j].size();
//                max[j] = std::max(max[j], H.mSmallWeightSets[j].size());
//            }
//
//            for (u64 j = 0; j < H.mBigWeightSets.size(); ++j)
//            {
//                auto jj = j + H.mSmallWeightSets.size();
//                avgs[jj] += H.mBigWeightSets[j].size();
//                max[jj] = std::max(max[jj], H.mBigWeightSets[j].size());
//            }
//
//            if (H.mSmallWeightSets[0].size() == 0)
//            {
//                // If we don't have any rows with hamming
//                // weight 0 then we will pick the row with 
//                // minimim hamming weight and move it to the
//                // top of the view.
//                auto uu = H.popMinWeightRow();
//                auto u = uu.first;
//                auto wi = uu.second;
//
//                // move the min weight row u to row i.
//                auto ii = H.rowIdx(i);
//                H.swapRows(u, ii);
//
//                if (verbose) {
//                    std::cout << "wi " << wi << std::endl;
//                    std::cout << "swapRow(" << i << ", " << u.mIdx << ")" << std::endl;
//                }
//
//                // For this newly moved row i, we need to move all the 
//                // columns where this row has a non-zero value to the
//                // left side of the view. 
//
//                // c1 is the column defining the left side of the view
//                auto c1 = (n - v);
//
//                // rIter iterates the columns which have non-zero values for row ii.
//                auto rIter = H.rowIterator(ii);
//
//                // this set will collect all of the columns in the view. 
//                colSwaps.clear();
//                for (u64 j = 0; j < rowWeight(); ++j)
//                {
//                    //auto c0 = colIdx[j];
//                    auto c0 = *rIter; ++rIter;
//
//                    // check if this column is inside the view.
//                    if (c0.mIdx >= c1)
//                    {
//                        // add this column to the set of columns that we will move.
//                        colSwaps.push_back(c0);
//
//                        if (verbose)
//                            std::cout << "swapCol(" << c0.mIdx << ")" << std::endl;
//
//                        // iterator over the rows for this column and decrement their row weight.
//                        // we do this since we are about to move this column outside of the view.
//                        auto cIter = H.colIterator(c0);
//                        while (cIter)
//                        {
//                            // these a special case that this row is the u row which
//                            // has already been decremented
//                            if (cIter.srcIdx() != ii.mSrcIdx)
//                            {
//                                H.decRowWeight(*cIter);
//                            }
//
//                            ++cIter;
//                        }
//                    }
//                }
//
//                // now update the mappings so that these columns are
//                // right before the view.
//                while (colSwaps.size())
//                {
//                    auto cc = H.colIdx(c1++);
//                    auto sIter = std::find(colSwaps.begin(), colSwaps.end(), cc);
//                    if (sIter != colSwaps.end())
//                    {
//                        std::swap(*sIter, colSwaps.back());
//                    }
//                    else
//                    {
//                        H.swapCol(cc, colSwaps.back());
//                    }
//
//                    colSwaps.pop_back();
//                }
//
//                if (verbose)
//                {
//                    std::cout << "v " << (v - wi) << " = " << v << " - " << wi << std::endl;
//                    std::cout << "i " << (i + 1) << " = " << i << " + 1" << std::endl;
//                }
//
//                // move the view right by wi.
//                v = v - wi;
//
//                // move the view down by 1
//                ++i;
//            }
//            else
//            {
//                // in the case that we have some rows with
//                // hamming weight 0, we will move all these
//                // rows to the top of the view and remove them.
//
//
//                auto& rows = H.mSmallWeightSets[0];
//                auto dk = rows.size();
//
//                // the top of the view.
//                auto c1 = i;
//
//                while (rows.size())
//                {
//                    // check that there isn't already a row
//                    // that we want at the top.
//                    auto sIter = std::find(rows.begin(), rows.end(), c1);
//                    auto srcIdx = c1;
//
//                    if (sIter == rows.end())
//                    {
//                        // if not then pick an arbitrary row
//                        // that we will move to the top.
//                        sIter = rows.begin();
//
//                        auto dest = H.rowIdx(c1);
//                        auto src = H.rowSrcIdx(*sIter);
//                        srcIdx = src.mIdx;
//
//                        H.swapRows(dest, src);
//                    }
//
//                    // decrement the row weight to -1 to 
//                    // denote that its outside the view.
//                    --H.mRowWeights[*sIter];
//                    if (H.mRowWeights[*sIter] != ~0ull)
//                        throw RTE_LOC;
//
//                    if (verbose)
//                        std::cout << "rowSwap*(" << c1 << ", " << srcIdx << ")" << std::endl;
//
//                    rows.erase(sIter);
//                    ++c1;
//                }
//
//                // recode that this the end of the block.
//                R.push_back(i + dk);
//                C.push_back(n - v);
//                dks.push_back(dk);
//
//                if (verbose)
//                {
//                    std::cout << "RC " << R.back() << " " << C.back() << std::endl;
//                    std::cout << "i " << (i + dk) << " = " << i << " + " << dk << std::endl;
//                    std::cout << "k " << (k + 1) << " = " << k << " + 1" << std::endl;
//                }
//
//                i += dk;
//                ++k;
//            }
//
//            if (verbose)
//            {
//                auto RR = R; RR.push_back(i);
//                auto CC = C; CC.push_back(n - v);
//                auto W = *this;
//                H.applyPerm(W);
//
//                std::cout << "\n" << LDPC2::diff(W, *HH, RR, CC) << std::endl
//                    << "=========================================\n"
//                    << std::endl;
//
//                *HH = std::move(W);
//            }
//        }
//
//        R.push_back(m);
//        C.push_back(n);
//
//
//        H.applyPerm(*this);
//
//        if (stats)
//        {
//
//            for (u64 j = 0; j < avgs.size(); ++j)
//            {
//                std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
//            }
//            u64 rPrev = 0;
//            u64 cPrev = 0;
//            for (u64 i = 0; i < R.size(); ++i)
//            {
//                std::string dk;
//                if (i < dks.size())
//                    dk = std::to_string(dks[i]);
//
//                std::cout << "RC[" << i << "] " << (R[i] - rPrev) << " " << (C[i] - cPrev) << "  ~   " << dk << std::endl;
//                rPrev = R[i];
//                cPrev = C[i];
//            }
//        }
//
//        //*this = applyPerm(H.mRowONMap, H.mColONMap);
//    }
//
//    void LDPC2::validate()
//    {
//        for (u64 i = 0; i < rows(); ++i)
//        {
//            for (u64 j = 0; j < rowWeight(); ++j)
//            {
//                auto cIdx = mRows(i, j);
//                auto c = col(cIdx);
//
//                if (c.size() != 0 && std::find(c.begin(), c.end(), i) == c.end())
//                    throw RTE_LOC;
//            }
//        }
//    }
//





     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////








     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////
     //////////////////////////////////////////////////////////////////////////////////////////////












    void blockTriangulateTest(const oc::CLP& cmd)
    {
        bool v = cmd.isSet("v");
        u64 m = cmd.getOr("m", 40ull);

        u64 n = m * cmd.getOr<double>("e", 2.4);
        u64 h = cmd.getOr("h", 2);

        u64 trials = cmd.getOr("t", 100);
        u64 tt = cmd.getOr("tt", 0);


        std::vector<std::array<u64, 2>> points; points.reserve(m * h);
        auto seed = cmd.getOr("s", 0);
        for (; tt < trials; ++tt)
        {
            oc::PRNG prng(block(0, seed + tt));

            points.clear();
            std::set<u64> c;
            for (u64 i = 0; i < m; ++i)
            {

                while (c.size() != h)
                    c.insert(prng.get<u64>() % n);
                for (auto cc : c)
                    points.push_back({ i, cc });

                c.clear();
            }

            LDPC H(m, n, h, points);


            auto HH = H;
            std::vector<u64> R, C;

            if (v)
                std::cout << H << std::endl
                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

            H.blockTriangulate(R, C, v);
            if (isBlockTriangular(H, R, C) == false)
                throw oc::UnitTestFail(LOCATION);
        }
    }

    //void blockTriangulateTest2(const CLP& cmd)
    //{
    //    bool v = cmd.isSet("v");
    //    u64 m = cmd.getOr("m", 40ull);

    //    u64 n = m * cmd.getOr<double>("e", 2.4);
    //    u64 h = cmd.getOr("h", 2);

    //    u64 trials = cmd.getOr("t", 100);
    //    u64 tt = cmd.getOr("tt", 0);


    //    std::vector<std::array<u64, 2>> points; points.reserve(m * h);
    //    for (; tt < trials; ++tt)
    //    {
    //        PRNG prng(block(0, cmd.getOr("s", tt)));

    //        points.clear();
    //        std::set<u64> c;
    //        for (u64 i = 0; i < m; ++i)
    //        {

    //            while (c.size() != h)
    //                c.insert(prng.get<u64>() % n);
    //            for (auto cc : c)
    //                points.push_back({ i, cc });

    //            c.clear();
    //        }

    //        LDPC2 H(m, n, h, points);


    //        auto HH = H;
    //        std::vector<u64> R, C;

    //        if (v)
    //            std::cout << H << std::endl
    //            << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

    //        H.blockTriangulate(R, C, v, false);
    //        if (isBlockTriangular(H, R, C) == false)
    //            throw UnitTestFail(LOCATION);
    //    }
    //}


    void unitTest(oc::CLP& cmd)
    {

        oc::TestCollection tests;
        tests.add("blockTriangulateTest    ", blockTriangulateTest);
        //tests.add("blockTriangulateTest2   ", blockTriangulateTest2);



        tests.runIf(cmd);
    }

    template<typename Set>
    void doBench(u64 n, oc::Timer& timer, std::string tag, Set& set)
    {
        timer.setTimePoint(tag + ".setup");

        for (u64 i = 0; i < n; ++i)
        {
            set.insert(i);
        }
        timer.setTimePoint(tag + ".insert");

        for (u64 i = 1; i < n; i += 2)
        {
            auto iter = set.find(i);
            if (iter == set.end())
                throw RTE_LOC;
        }
        timer.setTimePoint(tag + ".find");

        for (u64 i = 0; i < n; i += 2)
        {
            auto iter = set.find(i);
            set.erase(iter);
        }
        timer.setTimePoint(tag + ".find_erase");

        while (set.size())
        {
            set.erase(set.begin());

            //if (set.load_factor() < shink)
            //    set.resize(set.size());
        }

        timer.setTimePoint(tag + ".begin_erase");

    }


    //         n
    //    xxxxxxxxxxxx   x    y
    // m  xxxx H xxxxx * x =  y
    //    xxxxxxxxxxxx   x    y
    //                   x
    //                   x
    //                   x
    //
    void ldpc(oc::CLP& cmd)
    {
        if (cmd.isSet("u"))
            return unitTest(cmd);

        u64 v = cmd.isSet("v") ? cmd.getOr("v", 1) : 0;
        bool stats = cmd.isSet("stats");

        // The number of constaints
        u64 m = cmd.getOr("m", 30ull);
        // The 
        u64 n = m * cmd.getOr<double>("e", 2.4);
        u64 h = cmd.getOr("h", 2);
        u64 t = cmd.getOr("t", 1);
        oc::PRNG prng(block(0, cmd.getOr("s", 0)));

        u64 d = cmd.getOr("d", 0);
        double exp = cmd.getOr("exp", 0.0);

        std::vector<std::array<u64, 2>> points; points.reserve(m * h);
        oc::Timer timer;

        double dur1(0);
        std::set<u64> c;
        for (u64 i = 0; i < t; ++i)
        {
            points.clear();
            for (u64 i = 0; i < m; ++i)
            {

                {
                    while (c.size() != h)
                        c.insert(prng.get<u64>() % n);
                }

                for (auto cc : c)
                    points.push_back({ i, cc });

                c.clear();
            }

            {

                LDPC H1(m, n, h, points);

                //u64 maxCol = 0;
                //for (u64 i = 0; i < n; ++i)
                //    maxCol = std::max<u64>(maxCol, H.mCols[i].mRowIdxs.size());
                //

                if (v)
                {
                    std::cout << "--------------------------------" << std::endl;
                    std::cout << H1 << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }

                std::vector<u64> R, C;

                auto start = timer.setTimePoint("");
                auto vv = v > 1;

                H1.blockTriangulate(R, C, vv);
                auto end = timer.setTimePoint("");
                dur1 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


                timer.setTimePoint("triangulate");

                if (v)
                {
                    std::cout << LDPC::Diff(H1, H1, R, C) << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }


                bool ss = true;
                u64 gap = 0;
                for (u64 i = 0; i < n-1; ++i)
                {
                    auto r0 = H1.colMinRowIdx(i);
                    auto r1 = H1.colMinRowIdx(i + 1);
                    if (!r0 || !r1)
                    {
                        if(ss)
                            std::cout << "i " << i << std::endl;
                        ss = 0;
                        continue;
                    }

                    if (*r0 == *r1)
                        ++gap;
                }

                std::cout << "gap " << gap << " / " << n << " = " << double(gap) / n << std::endl;
            }

        }
        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
        std::cout << dur1 / t << std::endl;
        //H.partition(R, C, v);
        //std::cout << "--------------------------------" << std::endl;
        //std::cout << H << std::endl;

        return;
    }

}