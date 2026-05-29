#include "libOTe/Vole/LogVole2/LogVole2Encoding.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstdint>
#include <vector>

using namespace osuCrypto::LogVole2;

namespace
{
    KeyDeriveRequest make_keyderive_request()
    {
        KeyDeriveRequest message{};
        message.mPolyModulusDegree = 1024;
        message.mCoeffModulusCount = 2;
        message.mTau = 3;
        message.mDCoeffs = { 1, 2, 3, 4, 5 };
        return message;
    }

    KeyDeriveResponse make_keyderive_response()
    {
        KeyDeriveResponse message{};
        message.mPolyModulusDegree = 2048;
        message.mCoeffModulusCount = 3;
        message.mTau = 4;
        message.mMNttCoeffs = { 9, 8, 7, 6 };
        return message;
    }
}

void LogVole2_Encoding_KeyDeriveRequestRoundTrip(const oc::CLP&)
{
    const auto message = make_keyderive_request();
    const auto encoded = encode(message);

    KeyDeriveRequest decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_TRUE(decoded.mDCoeffs == message.mDCoeffs);
}

void LogVole2_Encoding_KeyDeriveResponseRoundTrip(const oc::CLP&)
{
    const auto message = make_keyderive_response();
    const auto encoded = encode(message);

    KeyDeriveResponse decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_TRUE(decoded.mMNttCoeffs == message.mMNttCoeffs);
}
