#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).
#include "libOTe/config.h"

#ifdef ENABLE_LDPC

#include <vector>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/CLP.h"
#include "Mtx.h"
#include <cmath>
namespace osuCrypto
{

    class LdpcDecoder
    {
    public:
        u64 mK = 0;

        bool mAllowZero = true;
        double mP = 0.9;
        Matrix<double> mM, mR;

        std::vector<span<double>> mMM, mRR;
        std::vector<double> mMData, mRData;
        std::vector<double> mW, mL;

        SparseMtx mH;

        LdpcDecoder() = default;
        LdpcDecoder(const LdpcDecoder&) = default;
        LdpcDecoder(LdpcDecoder&&) = default;


        LdpcDecoder(SparseMtx& H)
        {
            init(H);
        }

        void init(SparseMtx& H);

        std::vector<u8> bpDecode(span<u8> codeword, u64 maxIter = 1000);
        std::vector<u8> logbpDecode2(span<u8> codeword, u64 maxIter = 1000);
        std::vector<u8> altDecode(span<u8> codeword, bool minSum, u64 maxIter = 1000);
        std::vector<u8> minSumDecode(span<u8> codeword, u64 maxIter = 1000);

        std::vector<u8> bpDecode(span<double> codeword, u64 maxIter = 1000);
        std::vector<u8> logbpDecode2(span<double> codeword, u64 maxIter = 1000);
        std::vector<u8> altDecode(span<double> codeword, bool minSum, u64 maxIter = 1000);

        std::vector<u8> decode(span<u8> codeword, u64 maxIter = 1000)
        {
            return logbpDecode2(codeword, maxIter);
        }

        bool check(const span<u8>& data);
        static bool isZero(span<u8> data)
        {
            for (auto d : data)
                if (d) return false;
            return true;
        }


        inline static double LLR(double d)
        {
            assert(d > -1 && d < 1);
            return std::log(d / (1 - d));
        }
        inline static double LR(double d)
        {
            assert(d > -1 && d < 1);
            return (d / (1 - d));
        }


        inline static double encodeLLR(double p, bool bit)
        {
            assert(p >= 0.5);
            assert(p < 1);

            p = bit ? (1 - p) : p;

            return LLR(p);
        }

        inline static double encodeLR(double p, bool bit)
        {
            assert(p > 0.5);
            assert(p < 1);

            p = bit ? (1 - p) : p;

            return LR(p);
        }

        inline static u32 decodeLLR(double l)
        {
            return (l >= 0 ? 0 : 1);
        }

    };



    namespace tests
    {
        void LdpcDecode_pb_test(const oc::CLP& cmd);

    }

}
#endif