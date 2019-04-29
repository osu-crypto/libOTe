#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/DPF/BgiEvaluator.h>
#include <cryptoTools/Common/Timer.h>

namespace osuCrypto
{
    void bitShiftXor(span<block> dest, span<block> in, u8 bitShift);
    void modp(span<block> dest, span<block> in, u64 p);

    class BgciksOtExtSender : public TimerAdapter
    {
    public:

        BgiEvaluator::MultiKey mGen;
        block mDelta;
        u64 mP, mN2, mN, mNumPartitions, mScaler, mSizePer;
        BitVector mS, mC;
        void genBase(u64 n, Channel& chl, u64 scaler = 4, u64 secParam = 80);

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl);


        void randMulNaive(Matrix<block>& rT, span<std::array<block, 2>>& messages);
        void randMulQuasiCyclic(Matrix<block>& rT, span<std::array<block, 2>>& messages);
    };

}
