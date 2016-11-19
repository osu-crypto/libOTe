#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "TwoChooseOne/OTExtInterface.h"
#include <unordered_set>
#include "OTOracleSender.h"
#include "Crypto/PRNG.h"

using namespace osuCrypto;

class OTOracleReceiver :
    public OtExtReceiver
{
public:
    OTOracleReceiver(const block& seed);
    ~OTOracleReceiver();
    PRNG mPrng;

    bool hasBaseOts() const override { return true; }

    void setBaseOts(
        ArrayView<std::array<block, 2>> baseSendOts) override {};
    void receive(
        const BitVector& choices,
        ArrayView<block> messages,
        PRNG& prng,
        Channel& chl) override;

    std::unique_ptr<OtExtReceiver> split() override
    {
        std::unique_ptr<OtExtReceiver> ret(new OTOracleReceiver(mPrng.get<block>()));
        return std::move(ret);
    }

};
