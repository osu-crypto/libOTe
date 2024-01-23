#include "cryptoTools/Common/CLP.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/CoeffCtx.h"

using namespace oc;
using namespace oc::experimental;
namespace tests_libOTe
{


    template<
        typename Table,
        typename T>
    void accumulateBlock(
        span<T> x,
        u64 i)
    {
        auto table = Table::data;
        for (u64 j = 0; j < Table::data.size(); ++j, ++i)
        {
            if (i == x.size())
                return;

            x[(i + 1) % x.size()] ^= x[i];

            for (u64 k = 0; k < table[j].size(); ++k)
            {
                auto d = (i + table[j][k]) % x.size();
                if (d != i)
                    x[d] ^= x[i];

            }
        }
    }

    void TungstenCode_encode_test(const oc::CLP& cmd)
    {

        auto K = cmd.getManyOr<u64>("k", { 256, 3328, 152336 });
        auto R = cmd.getManyOr<double>("R", { 2.0 });

        for (auto k : K) for (auto r : R)
        {

            using F = block;
            using Ctx = CoeffCtxGF128;

            Ctx ctx;
            u64 n = k * r;
            TungstenCode encoder;

            encoder.config(k, n);
            
            //std::iota(encoder.mPerm.mPerm.begin(), encoder.mPerm.mPerm.end(), 0);
            //std::swap(encoder.mPerm.mPerm[0], encoder.mPerm.mPerm[1]);

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
                        accumulateBlock<TableTungsten1024x4, block>(in, i);
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
                        std::vector<block> out2(out.size());
                        encoder.accumulate<F>(in3.data(), out2.data(), in.size(), encoder.mPerm, ctx);


                        if (in3 != in)
                            throw RTE_LOC;

                        //for (u64 p = 0; p < std::min<u64>(10, z.size()); ++p)
                        //{
                        //    std::cout << p << " to " <<j <<": " << out2[p] << "  in  " << in3[p] << std::endl;
                        //}
                        //std::cout << "\n\n";

                        if (out2 != out)
                        {
                            for (u64 p = 0; p < out.size(); ++p)
                            {
                                std::cout << p << " " << (p/encoder.ChunkSize) << " " << out[p] << " " << out2[p] << (out[p] != out2[p] ? " <<<<<" : "") << std::endl;
                            }

                            throw RTE_LOC;
                        }

                        std::swap(in, out);

                    }
                    else
                    {
                        for (u64 i = 0; i < k; ++i)
                            z[i] ^= in[i];
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
                auto m = std::min<u64>(40, z.size());
                for (u64 p = 0; p < m; ++p)
                {
                    std::cout << p << " " << (p / encoder.ChunkSize) << " " << z[p] << " " << y[p] << (z[p] != y[p] ? " <<<<<" : "") << std::endl;
                }
                for (u64 p = m; p < z.size(); ++p)
                {
                    if(z[p] != y[p])
                        std::cout << p << " " << (p / encoder.ChunkSize) << " " << z[p] << " " << y[p] << (z[p] != y[p] ? " <<<<<" : "") << std::endl;
                }
                throw RTE_LOC;
            }
        }

    }
}