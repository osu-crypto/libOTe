#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include "libOTe/config.h"

#ifdef ENABLE_AKN
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>

namespace osuCrypto
{

    class AknOtSender : public TimerAdapter
    {
    public:
        AknOtSender();
        ~AknOtSender();


        //void computeBounds(u64 n, u64 k, u64 statSecPara);


        void init(u64 totalOTCount, u64 cutAndChooseThreshold, double p,
            OtExtSender& ots, Channel& chl, PRNG& prng)
        {
            std::vector<Channel> chls{ chl };
            init(totalOTCount, cutAndChooseThreshold, p, ots, chls, prng);
        }

        void init(u64 totalOTCount, u64 cutAndChooseThreshold, double p,
            OtExtSender& ots, span<Channel> chls, PRNG& prng);

        //std::vector<BitVector> mTheirPermutes;

        std::vector<std::array<block, 2>> mMessages;

        BitVector mSampled;
        //u64 mTotalOTCount, mCutAndChooseThreshold;
        //double mCutAndChooseProb;
    };

}
#endif