// © 2024 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#pragma once
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{

    // the (psuedo) minimum distance finder for expand convolute codes.
    void ExConvChecker(const CLP& cmd);
    namespace detail
    {
        struct GetGeneratorBatch
        {
            std::array<block, 8> mVal;

            GetGeneratorBatch operator^(const GetGeneratorBatch& b) const
            {
                GetGeneratorBatch ret;
                for (u64 i = 0; i < mVal.size(); ++i)
                    ret.mVal[i] = mVal[i] ^ b.mVal[i];
                return ret;
            }
        };
    }


    template<typename Code>
    Matrix<u8> getGenerator(Code& encoder)
    {
        auto k = encoder.mMessageSize;
        auto n = encoder.mCodeSize;;
        Matrix<u8> g(k, n);
        for (u64 i = 0; i < n; ++i)
        {
            std::vector<u8> x(n);
            x[i] = 1;
            encoder.template dualEncode<u8, CoeffCtxGF2>(x.data(), {});


            for (u64 j = 0; j < k; ++j)
            {
                g.data(j)[i] = x[j];
            }
        }
        return g;
    }

    template<typename Code>
    Matrix<block> getCompressedGenerator(Code& encoder)
    {
        auto k = encoder.mMessageSize;
        auto n = encoder.mCodeSize;;
        Matrix<block> g(k, divCeil(n, 128));

        u64 batchSize = sizeof(detail::GetGeneratorBatch) * 8;
        std::vector<detail::GetGeneratorBatch> x(n);
        for (u64 i = 0; i < n; i += batchSize)
        {
            memset(x.data(), 0, sizeof(x[0]) * x.size());

            for (u64 p = 0; p < batchSize; ++p)
            {
                *oc::BitIterator((u8*)&x[i + p], p) = 1;
            }

            // encode a batch of batchSize=1024 unit vectors...
            encoder.template dualEncode<detail::GetGeneratorBatch, CoeffCtxGF2>(x.data(), {});

            u64 mk = divCeil(std::min<u64>(batchSize, n - i), 8);
            auto i128 = i / 128;

            // x[j,p] is the (i+p)-th bit of the j-th codeword.
            // We want g[j, i+p] = x[j,p]
            for (u64 j = 0; j < k; ++j)
            {
                memcpy(g.data(j) + i128, &x[j], mk);
            }
        }
        return g;
    }
    inline Matrix<block> compress(Matrix<u8> g)
    {
        Matrix <block> G(g.rows(), divCeil(g.cols(), 128));
        for (u64 i = 0; i < g.rows(); ++i)
        {
            for (u64 j = 0; j < g.cols(); )
            {
                if (j + 8 < g.cols())
                {
                    auto gij = &g(i, j);
                    u8 b = gij[0] << 0
                        | gij[1] << 1
                        | gij[2] << 2
                        | gij[3] << 3
                        | gij[4] << 4
                        | gij[5] << 5
                        | gij[6] << 6
                        | gij[7] << 7;

                    ((u8*)G.data(i))[j / 8] = b;

                    j += 8;
                }
                else
                {
                    *BitIterator((u8*)G.data(i), j) = g(i, j);
                    ++j;
                }
            }
        }
        return G;
    }

    template<typename Code, typename Count = u64>
    u64 getGeneratorWeightx2(Code& encoder, bool verbose, Count c = {})
    {
        auto k = encoder.mMessageSize;
        auto n = encoder.mCodeSize;
        auto G = getCompressedGenerator(encoder);
        //auto G = compress(g);

        u64 min = n;
        auto N = G.cols();
        for (u64 i = 0; i < k; ++i)
        {
            for (u64 i2 = 0; i2 < k; ++i2)
            { 
                ++c;
                auto gg = G.data(i);
                u64 weight = 0;
                if (i == i2)
                {
                    for (u64 j = 0; j < N; ++j)
                    {
                        weight +=
                            popcount(gg[j].template get<u64>(0)) +
                            popcount(gg[j].template get<u64>(1));
                    }

                }
                else
                {
                    auto gg2 = G.data(i2);
                    for (u64 j = 0; j < N; ++j)
                    {
                        auto gj = gg[j] ^ gg2[j];
                        weight +=
                            popcount(gj.template get<u64>(0)) +
                            popcount(gj.template get<u64>(1));
                    }
                }

                //if (verbose)
                //{
                //    std::cout << i << " \n";
                //    for (u64 j = 0; j < n; ++j)
                //    {
                //        if (g(i, j))
                //            std::cout << Color::Green << "1" << Color::Default;
                //        else
                //            std::cout << "0";
                //    }
                //    std::cout << "\n";

                //    if (i != i2)
                //    {

                //        std::cout << i2 << " \n";
                //        for (u64 j = 0; j < n; ++j)
                //        {
                //            if (g(i2, j))
                //                std::cout << Color::Green << "1" << Color::Default;
                //            else
                //                std::cout << "0";
                //        }
                //        std::cout << "\n";
                //    }

                //}
                min = std::min<u64>(min, weight);
            }
        }
        return min;
    }

    template<typename Code, typename Count = u64>
    u64 getGeneratorWeight(Code& encoder, bool verbose, Count c = {})
    {
        auto k = encoder.mMessageSize;
        auto n = encoder.mCodeSize;
        //auto g = getGenerator(encoder);
        
        std::vector<u64> weights(k);
        for (u64 i = 0; i < n; ++i)
        {
            std::vector<u8> x(n);
            x[i] = 1;
            encoder.template dualEncode<u8, CoeffCtxGF2>(x.data(), {});

            for (u64 j = 0; j < k; ++j)
            {
                weights[j] += x[j];
            }
            ++c;
        }
        return *std::min_element(weights.begin(), weights.end());
    }


    template<typename Code, typename Count = u64>
    u64 getGeneratorWeight2(Code& encoder, bool verbose, Count c = {})
    {
        auto k = encoder.mMessageSize;
        auto n = encoder.mCodeSize;
        //auto g = getGenerator(encoder);

        std::vector<u64> weights(k);
        //for (u64 i = 0; i < n; ++i)
        //{
        //    std::vector<u8> x(n);
        //    x[i] = 1;
        //    encoder.template dualEncode<u8, CoeffCtxGF2>(x.data(), {});

        //    for (u64 j = 0; j < k; ++j)
        //    {
        //        weights[j] += x[j];
        //    }
        //    ++c;
        //}
        //Matrix<block> g(k, divCeil(n, 128));

        u64 batchSize = sizeof(detail::GetGeneratorBatch) * 8;
        std::vector<detail::GetGeneratorBatch> x(n);
        for (u64 i = 0; i < n; i += batchSize)
        {
            memset(x.data(), 0, sizeof(x[0]) * x.size());
            u64 min = std::min<u64>(batchSize, n - 1);

            for (u64 p = 0; p < min; ++p)
            {
                *oc::BitIterator((u8*)&x[i + p], p) = 1;
            }

            // encode a batch of batchSize=1024 unit vectors...
            encoder.template dualEncode<detail::GetGeneratorBatch, CoeffCtxGF2>(x.data(), {});

            //u64 mk = divCeil(min, 8);
            //auto i128 = i / 128;

            // x[j,p] is the (i+p)-th bit of the j-th codeword.
            // We want g[j, i+p] = x[j,p]
            for (u64 j = 0; j < k; ++j)
            {
                for (u64 b = 0; b < x[j].mVal.size(); ++b)
                {
                    weights[j] += 
                        popcount(x[j].mVal[b].get<u64>(0)) +
                        popcount(x[j].mVal[b].get<u64>(1));
                }
            }

            c += min;
        }

        return *std::min_element(weights.begin(), weights.end());
    }

}