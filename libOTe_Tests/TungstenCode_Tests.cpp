#include "cryptoTools/Common/CLP.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "TungstenCode_Tests.h"
#include "ExConvCode_Tests.h"
#include "cryptoTools/Common/Log.h"
#include "libOTe/Tools/ExConvCode/ExConvChecker.h"
using namespace oc;
using namespace oc::experimental;
namespace tests_libOTe
{


    template<
        typename Table,
        typename T,
        typename Ctx
    >
    void accumulateBlock(
        span<T> x,
        u64 i,
        Ctx ctx)
    {
        auto table = Table::data;
        for (u64 j = 0; j < Table::data.size(); ++j, ++i)
        {
            if (i == x.size())
                return;

            auto idx = (i + Table::max + 1) % x.size();
            ctx.plus(x[idx], x[idx], x[i]);
            ctx.mulConst(x[idx], x[idx]);

            for (u64 k = 0; k < table[j].size(); ++k)
            {
                auto d = (i + table[j][k]) % x.size();
                if (d != i)
                    ctx.plus(x[d], x[d], x[i]);

            }
        }
    }

    template<typename F, typename Ctx>
    void TungstenCode_encode_impl(u64 k, double r)
    {
        Ctx ctx;
        u64 n = k * r;
        TungstenCode encoder;

        encoder.config(k, n);

        PRNG prng(CCBlock);

        std::vector<F> x(n);
        prng.get<F>(x);




        auto z = x;
        {

            std::vector<F> in(roundUpTo(n - k, encoder.ChunkSize));
            std::vector<F> out(roundUpTo(n - k, encoder.ChunkSize));
            auto i = n - in.size();
            std::copy(x.begin() + i, x.end(), in.begin());

            u64 tableSize = TableTungsten1024x4::data.size();

            for (u64 j = 0; j <= encoder.mNumIter; ++j)
            {
                auto in2 = in;
                auto in3 = in;
                for (u64 i = 0; i < in.size(); i += tableSize)
                {
                    accumulateBlock<TableTungsten1024x4, F>(in, i, ctx);
                }

                TungstenNoop noop;
                encoder.accumulate<F, TungstenNoop, Ctx, F*>(in2.data(), nullptr, in.size(), noop, ctx);

                if (in2 != in)
                    throw RTE_LOC;

                if (j < encoder.mNumIter)
                {
                    auto perm = encoder.mPerm.mPerm;
                    std::vector<u8> flags(perm.size());
                    for (u64 p = 0; p < perm.size(); ++p)
                    {
                        if (std::exchange(flags[perm[p]], 1))
                            throw RTE_LOC;

                        for (u64 k = 0; k < encoder.ChunkSize; ++k)
                            out[perm[p] * encoder.ChunkSize + k] = in[p * encoder.ChunkSize + k];
                    }


                    //for (u64 p = 0; p < std::min<u64>(10, z.size()); ++p)
                    //{
                    //    std::cout << p << " ti " << j << ": " << in3[p] << std::endl;
                    //}
                    //std::cout << "\n";
                    encoder.mPerm.reset();
                    std::vector<F> out2(out.size());
                    encoder.accumulate<F, TungstenPerm<TungstenCode::ChunkSize>, Ctx, F*>(in3.data(), out2.data(), in.size(), encoder.mPerm, ctx);


                    if (in3 != in)
                        throw RTE_LOC;

                    //for (u64 p = 0; p < std::min<u64>(10, z.size()); ++p)
                    //{
                    //    std::cout << p << " to " <<j <<": " << out2[p] << "  in  " << in3[p] << std::endl;
                    //}
                    //std::cout << "\n\n";

                    if (out2 != out)
                    {
                        //for (u64 p = 0; p < out.size(); ++p)
                        //{
                        //    std::cout << p << " " << (p / encoder.ChunkSize) << " " << out[p] << " " << out2[p] << (out[p] != out2[p] ? " <<<<<" : "") << std::endl;
                        //}

                        throw RTE_LOC;
                    }

                    std::swap(in, out);

                }
                else
                {
                    for (u64 i = 0; i < k; ++i)
                        ctx.plus(z[i], z[i], in[i]);

                    z.resize(k);

                    auto w = x;
                    //for (u64 j = 0; j < std::min<u64>(20, z.size()); ++j)
                    //{
                    //    std::cout << j << " ft : " << in3[j] << " " << w[j] << std::endl;
                    //}
                    //std::cout << "\n\n";

                    TungstenAdder<TungstenCode::ChunkSize> adder;
                    encoder.accumulate<F>(in3.data(), w.data(), in.size(), adder, ctx);
                    w.resize(k);
                    if (w != z)
                        throw RTE_LOC;

                }
            }
        }

        auto y = x;
        encoder.dualEncode<F>(y.data(), ctx);
        y.resize(k);

        if (z != y)
        {
            //auto m = std::min<u64>(40, z.size());
            //for (u64 p = 0; p < m; ++p)
            //{
            //    std::cout << p << " " << (p / encoder.ChunkSize) << " " << z[p] << " " << y[p] << (z[p] != y[p] ? " <<<<<" : "") << std::endl;
            //}
            //for (u64 p = m; p < z.size(); ++p)
            //{
            //    if (z[p] != y[p])
            //        std::cout << p << " " << (p / encoder.ChunkSize) << " " << z[p] << " " << y[p] << (z[p] != y[p] ? " <<<<<" : "") << std::endl;
            //}
            throw RTE_LOC;
        }
    }

    void TungstenCode_encode_test(const oc::CLP& cmd)
    {

        auto K = cmd.getManyOr<u64>("k", { 256, 3328, 15232 });
        auto R = cmd.getManyOr<double>("R", { 2.0 });

        for (auto k : K) for (auto r : R)
        {
            TungstenCode_encode_impl<u32, CoeffCtxInteger>(k, r);
            TungstenCode_encode_impl<u8, CoeffCtxInteger>(k, r);
            TungstenCode_encode_impl<block, CoeffCtxGF128>(k, r);
            TungstenCode_encode_impl<std::array<u8, 4>, CoeffCtxArray<u8, 4>>(k, r);
        }

    }
    void TungstenCode_weight_test(const oc::CLP& cmd)
    {
        u64  k = cmd.getOr("k", 1ull << cmd.getOr("kk", 6));
        u64 n = k * 2;
        bool verbose = cmd.isSet("v");
        TungstenCode encoder;
        encoder.config(k, n);
        encoder.mNumIter = cmd.getOr("iter", 2);
        auto threshold = n / 4 - 2 * std::sqrt(n);
        u64 min = 0;
        //if(cmd.isSet("x2"))
        //    min = getGeneratorWeightx2(encoder, verbose);
        //else
        min = getGeneratorWeight(encoder, verbose);

        if (verbose)
        {
            std::cout << min << " / " << n << " = " << double(min) / n << " < threshold " << double(threshold) / n << std::endl;
        }

        if (min < threshold)
        {
            throw RTE_LOC;
        }
    }
}