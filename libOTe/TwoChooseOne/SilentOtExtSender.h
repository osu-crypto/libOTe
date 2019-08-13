#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENTOT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>

namespace osuCrypto
{
    void bitShiftXor(span<block> dest, span<block> in, u8 bitShift);
    void modp(span<block> dest, span<block> in, u64 p);

    class SilentOtExtSender : public TimerAdapter
    {
    public:

        //BgiEvaluator::MultiKey mGenBgi;
        SilentMultiPprfSender mGen;
        block mDelta;
        u64 mP, mN2, mN, mNumPartitions, mScaler, mSizePer;
		bool mMal;

        bool mDebug = false;
        void checkRT(span<Channel> chls, Matrix<block>& rT);



        //BitVector mS, mC;
		void genBase(u64 n, Channel& chl, PRNG& prng, u64 scaler = 4, u64 secParam = 80, bool mal = false, SilentBaseType base = SilentBaseType::BaseExtend,
			u64 threads = 1);
		//void genBase(u64 n, span<Channel> chls, PRNG& prng, u64 scaler = 4, u64 secParam = 80, SilentBaseType base = SilentBaseType::None);

		void configure(const u64& n, const u64& scaler, const u64& secParam, bool mal);

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl);

		void send(
			span<std::array<block, 2>> messages,
			PRNG& prng,
			span<Channel> chls);

        void randMulNaive(Matrix<block>& rT, span<std::array<block, 2>>& messages);
        void randMulQuasiCyclic(Matrix<block>& rT, span<std::array<block, 2>>& messages, u64 threads);
    };

}

#endif