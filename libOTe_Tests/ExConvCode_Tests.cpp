#include "ExConvCode_Tests.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode2.h"
#include <iomanip>
#include "libOTe/Tools/Subfield/Subfield.h"

namespace osuCrypto
{

    std::ostream& operator<<(std::ostream& o, const std::array<u8, 3>&a)
    {
        o << "{" << a[0] << " " << a[1] << " " << a[2] << "}";
        return o;
    }

    struct mtxPrint
    {
        mtxPrint(AlignedUnVector<u8>& d, u64 r, u64 c)
            :mData(d)
            , mRows(r)
            , mCols(c)
        {}

        AlignedUnVector<u8>& mData;
        u64 mRows, mCols;
    };

    std::ostream& operator<<(std::ostream& o, const mtxPrint& m)
    {
        for (u64 i = 0; i < m.mRows; ++i)
        {
            for (u64 j = 0; j < m.mCols; ++j)
            {
                bool color = (int)m.mData[i * m.mCols + j] && &o == &std::cout;
                if (color)
                    o << Color::Green;

                o << (int)m.mData[i * m.mCols + j] << " ";

                if (color)
                    o << Color::Default;
            }
            o << std::endl;
        }
        return o;
    }

    template<typename F, typename CoeffCtx>
    void exConvTest(u64 k, u64 n, u64 bw, u64 aw, bool sys)
    {

        ExConvCode2 code;
        code.config(k, n, bw, aw, sys);

        auto accOffset = sys * k;
        std::vector<F> x1(n), x2(n), x3(n), x4(n);
        PRNG prng(CCBlock);

        for (u64 i = 0; i < x1.size(); ++i)
        {
            x1[i] = x2[i] = x3[i] = prng.get();
        }

        std::vector<u8> rand(divCeil(aw, 8));
        for (i64 i = 0; i < x1.size() - aw - 1; ++i)
        {
            prng.get(rand.data(), rand.size());
            code.accOne<F, CoeffCtx, true>(x1.begin() + i, x1.end(), rand.data(), std::integral_constant<u64, 0>{});

            if (aw == 16)
                code.accOne<F, CoeffCtx, true>(x2.begin() + i, x2.end(), rand.data(), std::integral_constant<u64, 16>{});


            CoeffCtx::plus(x3[i + 1], x3[i + 1], x3[i]);
            for (u64 j = 0; j < aw && (i + j + 2) < x3.size(); ++j)
            {
                if (*BitIterator(rand.data(), j))
                {
                    CoeffCtx::plus(x3[i + j + 2], x3[i + j + 2], x3[i]);
                }
            }

            for (u64 j = i; j < x1.size() && j < i + aw + 2; ++j)
            {
                if (aw == 16 && x1[j] != x2[j])
                {
                    std::cout << j << " " << (x1[j]) << " " << (x2[j]) << std::endl;
                    throw RTE_LOC;
                }

                if (x1[j] != x3[j])
                {
                    std::cout << j << " " << (x1[j]) << " " << (x3[j]) << std::endl;
                    throw RTE_LOC;
                }
            }
        }


        x4 = x1;
        //std::cout << std::endl;

        code.accumulateFixed<F, CoeffCtx, 0>(x1.begin() + accOffset);

        if (aw == 16)
        {
            code.accumulateFixed<F, CoeffCtx, 16>(x2.begin() + accOffset);

            if (x1 != x2)
            {
                for (u64 i = 0; i < x1.size(); ++i)
                {
                    std::cout << i << " " << (x1[i]) << " " << (x2[i]) << std::endl;
                }
                throw RTE_LOC;
            }
        }

        {
            PRNG coeffGen(code.mSeed ^ OneBlock);
            u8* mtxCoeffIter = (u8*)coeffGen.mBuffer.data();
            auto mtxCoeffEnd = mtxCoeffIter + coeffGen.mBuffer.size() * sizeof(block) - divCeil(aw, 8);

            auto xi = x3.begin() + accOffset;
            auto end = x3.end();
            while (xi < end)
            {
                if (mtxCoeffIter > mtxCoeffEnd)
                {
                    // generate more mtx coefficients
                    ExConvCode2::refill(coeffGen);
                    mtxCoeffIter = (u8*)coeffGen.mBuffer.data();
                }
                
                // add xi to the next positions
                auto xj = xi + 1;
                if (xj != end)
                {
                    CoeffCtx::plus(*xj, *xj, *xi);
                    ++xj;
                }
                for (u64 j = 0; j < aw && xj != end; ++j, ++xj)
                {
                    if (*BitIterator(mtxCoeffIter, j))
                    {
                        CoeffCtx::plus(*xj, *xj, *xi);
                    }
                }
                ++mtxCoeffIter;

                ++xi;
            }
        }

        if (x1 != x3)
        {
            for (u64 i = 0; i < x1.size(); ++i)
            {
                std::cout << i << " " << (x1[i]) << " " << (x3[i]) << std::endl;
            }
            throw RTE_LOC;
        }


        detail::ExpanderModd expanderCoeff(code.mExpander.mSeed, code.mExpander.mCodeSize);
        std::vector<F> y1(k), y2(k);

        if (sys)
        {
            std::copy(x1.begin(), x1.begin() + k, y1.begin());
            y2 = y1;
            code.mExpander.expand<F, CoeffCtx, true>(x1.cbegin() + accOffset, y1.begin());
            //using P = std::pair<typename std::vector<F>::const_iterator, typename std::vector<F>::iterator>;
            //auto p = P{ x1.cbegin() + accOffset, y1.begin() };
            //code.mExpander.expandMany<true, CoeffCtx, F>(
            //    std::tuple<P>{ p }
            //);
        }
        else
        {
            code.mExpander.expand<F, CoeffCtx, false>(x1.cbegin() + accOffset, y1.begin());
        }

        u64 i = 0;
        auto main = k / 8 * 8;
        for (; i < main; i += 8)
        {
            for (u64 j = 0; j < code.mExpander.mExpanderWeight; ++j)
            {
                for (u64 p = 0; p < 8; ++p)
                {
                    auto idx = expanderCoeff.get();
                    CoeffCtx::plus(y2[i + p], y2[i + p], x1[idx + accOffset]);
                }
            }
        }

        for (; i < k; ++i)
        {
            for (u64 j = 0; j < code.mExpander.mExpanderWeight; ++j)
            {
                auto idx = expanderCoeff.get();
                CoeffCtx::plus(y2[i], y2[i], x1[idx + accOffset]);
            }
        }

        if (y1 != y2)
            throw RTE_LOC;

        code.dualEncode<F, CoeffCtx>(x4.begin());

        x4.resize(k);
        if (x4 != y1)
            throw RTE_LOC;
    }




    void ExConvCode_encode_basic_test(const oc::CLP& cmd)
    {

        //std::vector<int> i0, o0;
        //std::vector<u16> i1, o1;
        //std::vector<i32> i2, o2;

        //ExpanderCode2 ex;
        //ex.expandMany<true, CoeffCtxInteger, int, u16, i32>(
        //    std::tuple{
        //        std::pair{i0.begin(), o0.begin()},
        //        std::pair{i1.begin(), o1.begin()},
        //        std::pair{i2.begin(), o2.begin()}
        //    }, {});


        auto K = cmd.getManyOr<u64>("k", { 16ul, 64, 4353 });
        auto R = cmd.getManyOr<double>("R", { 2.0, 3.0 });
        auto Bw = cmd.getManyOr<u64>("bw", { 7, 21 });
        auto Aw = cmd.getManyOr<u64>("aw", { 16, 24, 29 });

        bool v = cmd.isSet("v");
        for (auto k : K) for (auto r : R) for (auto bw : Bw) for (auto aw : Aw) for (auto sys : { false, true })
        {
            auto n = k * r;
            exConvTest<u32, CoeffCtxInteger>(k, n, bw, aw, sys);
            exConvTest<u8, CoeffCtxInteger>(k, n, bw, aw, sys);
            exConvTest<block, CoeffCtxGFBlock>(k, n, bw, aw, sys);
            exConvTest<std::array<u8, 3>, CoeffCtxArray<u8, 3>>(k, n, bw, aw, sys);
        }

    }
}