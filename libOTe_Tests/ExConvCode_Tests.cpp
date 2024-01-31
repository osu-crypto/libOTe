#include "ExConvCode_Tests.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <iomanip>
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/ExConvCode/ExConvChecker.h"

namespace osuCrypto
{

    std::ostream& operator<<(std::ostream& o, const std::array<u8, 3>& a)
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
        for (u64 i = 0; i < n; ++i)
        {
            prng.get(rand.data(), rand.size());
            code.accOneGen<F, CoeffCtx, true>(x1.data(), i, n, rand.data(), ctx);

            if (aw == 24)
                code.accOne<F, CoeffCtx, true, 24>(x2.data(), i, n, rand.data(), ctx);

            u64 j = i + 1;

            assert(aw <= 64);
            u64 bits = 0;
            memcpy(&bits, rand.data(), std::min<u64>(rand.size(), 8));
            for (u64 a = 0; a < aw; ++a, ++j)
            {
                if (bits & 1)
                {
                    ctx.plus(x3[j % n], x3[j % n], x3[i]);
                }
                bits >>= 1;
            }
            ctx.plus(x3[j % n], x3[j % n], x3[i]);
            ctx.mulConst(x3[j % n], x3[j % n]);

            j = i + 1;
            for (u64 a = 0; a <= aw; ++a, ++j)
            {
                //auto j = (i + a + 2) % n;

                if (aw == 24 && x1[j%n] != x2[j % n])
                {
                    std::cout << j % n << " " << ctx.str(x1[j % n]) << " " << ctx.str(x2[j % n]) << std::endl;
                    throw RTE_LOC;
                }

                if (x1[j % n] != x3[j % n])
                {
                    std::cout << j % n << " " << ctx.str(x1[j % n]) << " " << ctx.str(x3[j % n]) << std::endl;
                    throw RTE_LOC;
                }
            }
        }

        x4 = x1;
        u64 size = n - accOffset;

        code.accumulateFixed<F, CoeffCtx, 0>(x1.data() + accOffset, size, ctx, code.mSeed);
        if (code.mAccTwice)
            code.accumulateFixed<F, CoeffCtx, 0>(x1.data() + accOffset, size, ctx, ~code.mSeed);
        if (aw == 24)
        {
            code.accumulateFixed<F, CoeffCtx, 24>(x2.data() + accOffset, size, ctx, code.mSeed);

            if (code.mAccTwice)
                code.accumulateFixed<F, CoeffCtx, 24>(x2.data() + accOffset, size, ctx, ~code.mSeed);

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
            for (auto r = 0; r < 1 + code.mAccTwice; ++r)
            {
                PRNG coeffGen(r ? ~code.mSeed : code.mSeed);
                u8* mtxCoeffIter = (u8*)coeffGen.mBuffer.data();
                auto mtxCoeffEnd = mtxCoeffIter + coeffGen.mBuffer.size() * sizeof(block) - divCeil(aw, 8);

                auto x = x3.data() + accOffset;
                u64 i = 0;
                while (i < size)
                {
                    auto xi = x + i;

                    if (mtxCoeffIter > mtxCoeffEnd)
                    {
                        // generate more mtx coefficients
                        ExConvCode::refill(coeffGen);
                        mtxCoeffIter = (u8*)coeffGen.mBuffer.data();
                    }

                    // add xi to the next positions
                    auto j = (i + 1) % size;

                    u64 bits = 0;
                    memcpy(&bits, mtxCoeffIter, divCeil(aw, 8));
                    for (u64 a = 0; a < aw; ++a)
                    {

                        if (bits & 1)
                        {
                            auto xj = x + j;
                            ctx.plus(*xj, *xj, *xi);
                        }
                        bits >>= 1;
                        j = (j + 1) % size;
                    }

                    {
                        auto xj = x + j;
                        ctx.plus(*xj, *xj, *xi);
                        ctx.mulConst(*xj, *xj);
                    }
 
                    ++mtxCoeffIter;

                    ++i;
                }
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

        u64 step, exSize, regCount = 0;;
        if (code.mExpander.mRegular)
        {
            regCount = divCeil(code.mExpander.mExpanderWeight, 2);
            exSize = step = code.mExpander.mCodeSize / regCount;
        }
        else
        {
            step = 0;
            exSize = n;
        }
        detail::ExpanderModd regExp(code.mExpander.mSeed^ block(342342134, 23421341), exSize);
        detail::ExpanderModd fullExp(code.mExpander.mSeed, code.mExpander.mCodeSize);

        u64 i = 0;
        auto main = k / 8 * 8;
        for (; i < main; i += 8)
        {
            
            for (u64 j = 0; j < regCount; ++j)
            {
                for (u64 p = 0; p < 8; ++p)
                {
                    auto idx = regExp.get() + step * j;
                    ctx.plus(y2[i + p], y2[i + p], x1[idx + accOffset]);
                }
            }
            for (u64 j = 0; j < code.mExpander.mExpanderWeight - regCount; ++j)
            {
                for (u64 p = 0; p < 8; ++p)
                {
                    auto idx = fullExp.get();
                    ctx.plus(y2[i + p], y2[i + p], x1[idx + accOffset]);
                }
            }
        }

        for (; i < k; ++i)
        {
            for (u64 j = 0; j < regCount; ++j)
            {
                auto idx = regExp.get() + step * j;
                ctx.plus(y2[i], y2[i], x1[idx + accOffset]);
            }
            for (u64 j = 0; j < code.mExpander.mExpanderWeight - regCount; ++j)
            {
                auto idx = fullExp.get();
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
    //    //    FOR a : = 1 to i
    //    //    TEMP[i] : = TEMP[i] XOR(TEMP1[a] AND TEMP2[i - a])
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


    Matrix<u8> getAccumulator(ExConvCode& encoder)
    {
        auto k = encoder.mMessageSize;;
        auto n = encoder.mCodeSize;;
        if (encoder.mSystematic == false)
            throw RTE_LOC;//not impl

        auto d = n - k;
        Matrix<u8> g(d, d);
        for (u64 i = 0; i < d; ++i)
        {
            std::vector<u8> x(d);
            x[i] = 1;
            CoeffCtxGF2 ctx;
            encoder.accumulate<u8, CoeffCtxGF2>(x.data(), ctx);

            for (u64 j = 0; j < d; ++j)
            {
                g(j, i) = x[j];
            }
        }
        return g;
    }


    u64 getGeneratorWeight_(ExConvCode& encoder, bool verbose)
    {
        auto k = encoder.mMessageSize;
        auto n = encoder.mCodeSize;
        auto g = getGenerator(encoder);
        //bool failed = false;
        u64 min = n;
        u64 iMin = 0;;
        for (u64 i = 0; i < k; ++i)
        {
            u64 weight = 0;
            for (u64 j = 0; j < n; ++j)
            {
                //if (verbose)
                //{
                //    if (g(i, j))
                //        std::cout << Color::Green << "1" << Color::Default;
                //    else
                //        std::cout << "0";
                //}
                assert(g(i, j) < 2);
                weight += g(i, j);
            }
            //if (verbose)
            //    std::cout << std::endl;

            if (weight < min)
                iMin = i;
            min = std::min<u64>(min, weight);
        }

        if (verbose)
        {
            auto Ex = encoder.mExpander.getMatrix();
            //for (u64 i = 0; i < Ex.cols(); ++i)
            //{
            //    std::cout << Ex(985, i) << " ";

            //}
            //std::cout << " ~ " << k << std::endl;

            std::cout << "i " << iMin << " " << min << " / " << n << " = " << double(min) / n << std::endl;
            for (u64 j = 0; j < n; ++j)
            {
                auto ei = Ex[iMin];
                bool found = std::find(ei.begin(), ei.end(), j - k) != ei.end();
                if (j == iMin + k)
                {
                    std::cout << Color::Blue << int(g(iMin, j)) << Color::Default;

                }
                else if (found)
                {
                    std::cout << Color::Red << int(g(iMin, j)) << Color::Default;

                }
                else if (g(iMin, j))
                    std::cout << Color::Green << "1" << Color::Default;
                else
                    std::cout << "0";

                if (j == k - 1)
                {
                    std::cout << "\n";
                }
            }
            std::cout << std::endl << "--------------------------------\n";

            auto a = getAccumulator(encoder);

            auto ei = Ex[iMin];
            for (auto i : ei)
            {
                for (u64 j = 0; j < k; ++j)
                {
                    if (a(i, j))
                        std::cout << Color::Green << "1" << Color::Default;
                    else
                        std::cout << "0";
                }
                std::cout << std::endl;
            }
        }

        return min;
    }


    void ExConvCode_weight_test(const oc::CLP& cmd)
    {
        u64  k = cmd.getOr("k", 1ull << cmd.getOr("kk", 6));
        u64 n = k * 2;
        //u64 aw = cmd.getOr("aw", 24);
        //u64 bw = cmd.getOr("bw", 7);
        bool verbose = cmd.isSet("v");
        bool accTwice = cmd.getOr("accTwice", 1);
        for (u64 aw = 4; aw < 16; aw += 2)
        {
            for (u64 bw = 3; bw < 11; bw += 2)
            {

                ExConvCode encoder;
                encoder.config(k, n, bw, aw);
                encoder.mAccTwice = accTwice;

                auto threshold = n / 6 - 2 * std::sqrt(n);
                u64 min = 0;
                //if (cmd.isSet("x2"))
                //    min = getGeneratorWeightx2(encoder, verbose);
                //else
                min = getGeneratorWeight_(encoder, verbose);

                if (cmd.isSet("acc"))
                {
                    auto g = getAccumulator(encoder);

                    for (u64 i = 0; i < k; ++i)
                    {
                        u64 w = 0;
                        for (u64 j = 0; j < k; ++j)
                        {
                            w += g(i, j);
                        }
                        //if (w < k / 2.2)
                        {
                            //std::cout << i << " " << w << std::endl;
                            for (u64 j = 0; j < k; ++j)
                            {
                                if (g(i, j))
                                    std::cout << Color::Green << "1" << Color::Default;
                                else
                                    std::cout << "0";
                            }
                            std::cout << std::endl;
                        }
                    }
                    std::cout << std::endl;
                }

                if (verbose)
                    std::cout << "aw " << aw << " bw " << bw << ": " << min << " / " << n << " = " << double(min) / n << " < threshold " << double(threshold) / n << std::endl;

                if (min < threshold)
                {
                    throw RTE_LOC;
                }

            }
        }

    }

}