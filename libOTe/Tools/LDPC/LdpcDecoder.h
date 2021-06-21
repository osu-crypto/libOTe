#pragma once
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