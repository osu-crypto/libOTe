#include "ExConvCode_Tests.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <iomanip>
#include "libOTe/Tools/CoeffCtx.h"

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

        ExConvCode code;
        code.config(k, n, bw, aw, sys);

        auto accOffset = sys * k;
        std::vector<F> x1(n), x2(n), x3(n), x4(n);
        PRNG prng(CCBlock);

        for (u64 i = 0; i < x1.size(); ++i)
        {
            x1[i] = x2[i] = x3[i] = prng.get();
        }
        CoeffCtx ctx;
        std::vector<u8> rand(divCeil(aw, 8));
        for (i64 i = 0; i < i64(x1.size() - aw - 1); ++i)
        {
            prng.get(rand.data(), rand.size());
            code.accOneGen<F, CoeffCtx, true>(x1.data() + i, x1.data()+n, rand.data(), ctx);

            if (aw == 16)
                code.accOne<F, CoeffCtx, true, 16>(x2.data() + i, x2.data()+n, rand.data(), ctx);


            ctx.plus(x3[i + 1], x3[i + 1], x3[i]);
            //std::cout << "x" << i + 1 << " " << x3[i + 1] << " -> ";
            ctx.mulConst(x3[i + 1], x3[i + 1]);
            //std::cout << x3[i + 1] << std::endl;;
            assert(aw <= 64);
            u64 bits = 0;
            memcpy(&bits, rand.data(), std::min<u64>(rand.size(), 8));
            for (u64 j = 0; j < aw && (i + j + 2) < x3.size(); ++j)
            {
                if (bits & 1)
                {
                    ctx.plus(x3[i + j + 2], x3[i + j + 2], x3[i]);
                }
                bits >>= 1;
            }

            for (u64 j = i; j < x1.size() && j < i + aw + 2; ++j)
            {
                if (aw == 16 && x1[j] != x2[j])
                {
                    std::cout << j << " " << ctx.str(x1[j]) << " " << ctx.str(x2[j]) << std::endl;
                    throw RTE_LOC;
                }

                if (x1[j] != x3[j])
                {
                    std::cout << j << " " << ctx.str(x1[j]) << " " << ctx.str(x3[j]) << std::endl;
                    throw RTE_LOC;
                }
            }
        }


        x4 = x1;
        //std::cout << std::endl;

        code.accumulateFixed<F, CoeffCtx, 0>(x1.data() + accOffset, ctx);

        if (aw == 16)
        {
            code.accumulateFixed<F, CoeffCtx, 16>(x2.data() + accOffset, ctx);

            if (x1 != x2)
            {
                for (u64 i = 0; i < x1.size(); ++i)
                {
                    std::cout << i << " " << ctx.str(x1[i]) << " " << ctx.str(x2[i]) << std::endl;
                }
                throw RTE_LOC;
            }
        }

        {
            PRNG coeffGen(code.mSeed ^ OneBlock);
            u8* mtxCoeffIter = (u8*)coeffGen.mBuffer.data();
            auto mtxCoeffEnd = mtxCoeffIter + coeffGen.mBuffer.size() * sizeof(block) - divCeil(aw, 8);

            auto xi = x3.data() + accOffset;
            auto end = x3.data() + n;
            while (xi < end)
            {
                if (mtxCoeffIter > mtxCoeffEnd)
                {
                    // generate more mtx coefficients
                    ExConvCode::refill(coeffGen);
                    mtxCoeffIter = (u8*)coeffGen.mBuffer.data();
                }
                
                // add xi to the next positions
                auto xj = xi + 1;
                if (xj != end)
                {
                    ctx.plus(*xj, *xj, *xi);
                    ctx.mulConst(*xj, *xj);
                    ++xj;
                }
                //assert((mtxCoeffEnd - mtxCoeffIter) * 8 >= aw);
                u64 bits = 0;
                memcpy(&bits, mtxCoeffIter, divCeil(aw,8));
                for (u64 j = 0; j < aw && xj != end; ++j, ++xj)
                {
                    if (bits &1)
                    {
                        ctx.plus(*xj, *xj, *xi);
                    }
                    bits >>= 1;
                }
                ++mtxCoeffIter;

                ++xi;
            }
        }

        if (x1 != x3)
        {
            for (u64 i = 0; i < x1.size(); ++i)
            {
                std::cout << i << " " << ctx.str(x1[i]) << " " << ctx.str(x3[i]) << std::endl;
            }
            throw RTE_LOC;
        }


        detail::ExpanderModd expanderCoeff(code.mExpander.mSeed, code.mExpander.mCodeSize);
        std::vector<F> y1(k), y2(k);

        if (sys)
        {
            std::copy(x1.data(), x1.data() + k, y1.data());
            y2 = y1;
            code.mExpander.expand<F, CoeffCtx, true>(x1.data() + accOffset, y1.data());
            //using P = std::pair<typename std::vector<F>::const_iterator, typename std::vector<F>::iterator>;
            //auto p = P{ x1.cbegin() + accOffset, y1.begin() };
            //code.mExpander.expandMany<true, CoeffCtx, F>(
            //    std::tuple<P>{ p }
            //);
        }
        else
        {
            code.mExpander.expand<F, CoeffCtx, false>(x1.data() + accOffset, y1.data());
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
                    ctx.plus(y2[i + p], y2[i + p], x1[idx + accOffset]);
                }
            }
        }

        for (; i < k; ++i)
        {
            for (u64 j = 0; j < code.mExpander.mExpanderWeight; ++j)
            {
                auto idx = expanderCoeff.get();
                ctx.plus(y2[i], y2[i], x1[idx + accOffset]);
            }
        }

        if (y1 != y2)
            throw RTE_LOC;

        code.dualEncode<F, CoeffCtx>(x4.begin(), {});

        x4.resize(k);
        if (x4 != y1)
            throw RTE_LOC;
    }

    //block mult2(block x, int imm8)
    //{
    //    assert(imm8 < 2);
    //    if (imm8)
    //    {
    //        // mult x[1] * 2

    //    }
    //    else
    //    {
    //        // x[0] * 2
    //        __m128i carry = _mm_slli_si128(x, 8); 
    //        carry = _mm_srli_epi64(carry, 63);  
    //        x = _mm_slli_epi64(x, 1);
    //        return _mm_or_si128(x, carry);

    //        //return _mm_slli_si128(x, 8);
    //    }
    //    //TEMP[i] : = (TEMP1[0] and TEMP2[i])
    //    //    FOR j : = 1 to i
    //    //    TEMP[i] : = TEMP[i] XOR(TEMP1[j] AND TEMP2[i - j])
    //    //    ENDFOR
    //    //dst[i] : = TEMP[i]
    //}


    void ExConvCode_encode_basic_test(const oc::CLP& cmd)
    {
        auto K = cmd.getManyOr<u64>("k", { 32ul, 333 });
        auto R = cmd.getManyOr<double>("R", { 2.0, 3.0 });
        auto Bw = cmd.getManyOr<u64>("bw", { 7, 21 });
        auto Aw = cmd.getManyOr<u64>("aw", { 16, 24, 29 });

        //bool v = cmd.isSet("v");
        for (auto k : K) for (auto r : R) for (auto bw : Bw) for (auto aw : Aw) for (auto sys : { false, true })
        {
            auto n = k * r;
            exConvTest<u32, CoeffCtxInteger>(k, n, bw, aw, sys);
            exConvTest<u8, CoeffCtxInteger>(k, n, bw, aw, sys);
            exConvTest<block, CoeffCtxGF128>(k, n, bw, aw, sys);
            exConvTest<std::array<u8, 4>, CoeffCtxArray<u8, 4>>(k, n, bw, aw, sys);
        }

    }
}