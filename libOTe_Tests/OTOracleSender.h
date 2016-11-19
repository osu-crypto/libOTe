#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "TwoChooseOne/OTExtInterface.h"
#ifdef GetMessage
#undef GetMessage
#endif

#include "Common/Defines.h"
#include <unordered_map> 
#include "Crypto/PRNG.h"

using namespace osuCrypto;


class OTOracleSender :
    public OtExtSender
{
public:
    OTOracleSender(const block& seed);
    ~OTOracleSender();
    PRNG mPrng;
    bool hasBaseOts() const override { return true; }

    void setBaseOts(
        ArrayView<block> baseRecvOts,
        const BitVector& choices) override {};

    std::unique_ptr<OtExtSender> split() override
    {
        std::unique_ptr<OtExtSender> ret(new OTOracleSender(mPrng.get<block>()));
        return std::move(ret);
    }

    void send(
        ArrayView<std::array<block,2>> messages,
        PRNG& prng,
        Channel& chl) override;
};
