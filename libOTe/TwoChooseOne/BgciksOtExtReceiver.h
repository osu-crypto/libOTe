#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/DPF/BgiEvaluator.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Tools.h>
#include <libOTe/DPF/BgicksPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
namespace osuCrypto
{

    extern bool gUseBgicksPprf;

    enum class MultType
    {
        Naive,
        QuasiCyclic
    };

    class BgciksOtExtReceiver : public TimerAdapter
    {
    public:

		void genBase(u64 n, Channel& chl, PRNG& prng,
			u64 scaler = 4, u64 secParam = 80,
			BgciksBaseType base = BgciksBaseType::None,
			u64 threads = 1);

        void configure(const osuCrypto::u64 &n, const osuCrypto::u64 &scaler, const osuCrypto::u64 &secParam);
        u64 baseOtCount();

        void receive(
            span<block> messages,
            BitVector& choices,
            PRNG & prng,
            Channel & chl);


		void receive(
			span<block> messages,
			BitVector& choices,
			PRNG& prng,
			span<Channel> chls);

        void randMulNaive(Matrix<block> &rT, span<block> &messages);
        void randMulQuasiCyclic(Matrix<block> &rT, span<block> &messages, BitVector& choices, u64 threads);
        
        u64 mP, mN, mN2, mScaler, mSizePer;
        std::vector<u64> mS;
        block mDelta;

        BgiEvaluator::MultiKey mGenBgi;
        BgicksMultiPprfReceiver mGen;


    };

    Matrix<block> expandTranspose(BgiEvaluator::MultiKey & gen, u64 n);


    inline u8 parity(block b)
    {
        b = b ^ (b >> 1);
        b = b ^ (b >> 2);
        b = b ^ (b >> 4);
        b = b ^ (b >> 8);
        b = b ^ (b >> 16);
        b = b ^ (b >> 32);
        return (((u64*)&b)[0] ^ ((u64*)&b)[1]) & 1;
    }

    inline void mulRand(PRNG &pubPrng, span<block> mtxColumn, Matrix<block> &rT, BitIterator iter)
    {
        pubPrng.get(mtxColumn.data(), mtxColumn.size());

        //convertCol(mtx, i, mtxColumn);
        std::array<block, 8> sum, t;
        auto end = (rT.cols() / 8) * 8;

        for (u64 j = 0; j < 128; ++j)
        {
            auto row = rT[j];

            sum[0] = sum[0] ^ sum[0];
            sum[1] = sum[1] ^ sum[1];
            sum[2] = sum[2] ^ sum[2];
            sum[3] = sum[3] ^ sum[3];
            sum[4] = sum[4] ^ sum[4];
            sum[5] = sum[5] ^ sum[5];
            sum[6] = sum[6] ^ sum[6];
            sum[7] = sum[7] ^ sum[7];

            if (true)
            {

                for (u64 k = 0; k < end; k += 8)
                {
                    t[0] = row[k + 0] & mtxColumn[k + 0];
                    t[1] = row[k + 1] & mtxColumn[k + 1];
                    t[2] = row[k + 2] & mtxColumn[k + 2];
                    t[3] = row[k + 3] & mtxColumn[k + 3];
                    t[4] = row[k + 4] & mtxColumn[k + 4];
                    t[5] = row[k + 5] & mtxColumn[k + 5];
                    t[6] = row[k + 6] & mtxColumn[k + 6];
                    t[7] = row[k + 7] & mtxColumn[k + 7];


                    sum[0] = sum[0] ^ t[0];
                    sum[1] = sum[1] ^ t[1];
                    sum[2] = sum[2] ^ t[2];
                    sum[3] = sum[3] ^ t[3];
                    sum[4] = sum[4] ^ t[4];
                    sum[5] = sum[5] ^ t[5];
                    sum[6] = sum[6] ^ t[6];
                    sum[7] = sum[7] ^ t[7];

                }

                for (u64 k = end; k < row.size(); ++k)
                    sum[0] = sum[0] ^ (row[k] & mtxColumn[k]);

                sum[0] = sum[0] ^ sum[1];
                sum[2] = sum[2] ^ sum[3];
                sum[4] = sum[4] ^ sum[5];
                sum[6] = sum[6] ^ sum[7];

                sum[0] = sum[0] ^ sum[2];
                sum[4] = sum[4] ^ sum[6];

                sum[0] = sum[0] ^ sum[4];
            }
            else
            {
                for (u64 k = 0; k < row.size(); ++k)
                    sum[0] = sum[0] ^ (row[k] & mtxColumn[k]);
            }

            *iter = parity(sum[0]);
            ++iter;
        }
    }

    inline     void sse_transpose(span<block> s, Matrix<block>& r)
    {
        MatrixView<u8> ss((u8*)s.data(), s.size(), sizeof(block));
        MatrixView<u8> rr((u8*)r.data(), r.rows(), r.cols() * sizeof(block));

        sse_transpose(ss, rr);
    }

}
