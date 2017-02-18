#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>

namespace osuCrypto
{

    class AknOtSender
    {
    public:
        AknOtSender();
        ~AknOtSender();


        //void computeBounds(u64 n, u64 k, u64 statSecPara);


        void init(u64 totalOTCount, u64 cutAndChooseThreshold, double p,
            OtExtSender& ots, Channel& chl, PRNG& prng)
        {
            std::vector<Channel*> chls{ &chl };
            init(totalOTCount, cutAndChooseThreshold, p, ots, chls, prng);
        }

        void init(u64 totalOTCount, u64 cutAndChooseThreshold, double p,
            OtExtSender& ots, std::vector<Channel*>& chls, PRNG& prng);

        //std::vector<BitVector> mTheirPermutes;

        std::vector<std::array<block, 2>> mMessages;

        BitVector mSampled;
        //u64 mTotalOTCount, mCutAndChooseThreshold;
        //double mCutAndChooseProb;
    };

}
