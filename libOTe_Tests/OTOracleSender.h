#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#ifdef GetMessage
#undef GetMessage
#endif

#include <cryptoTools/Common/Defines.h>
#include <unordered_map> 
#include <cryptoTools/Crypto/PRNG.h>

using namespace osuCrypto;

namespace tests_libOTe
{

    class OTOracleSender :
        public OtExtSender
    {
    public:
        OTOracleSender(const block& seed);
        ~OTOracleSender();
        PRNG mPrng;
        bool hasBaseOts() const override { return true; }

        void setBaseOts(
            gsl::span<block> baseRecvOts,
            const BitVector& choices) override {};

        std::unique_ptr<OtExtSender> split() override
        {
            std::unique_ptr<OtExtSender> ret(new OTOracleSender(mPrng.get<block>()));
            return std::move(ret);
        }

        void send(
            gsl::span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;
    };
}