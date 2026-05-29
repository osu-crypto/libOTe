#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe_Tests/LogVole_TestUtil.h"

#include <span>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    template<typename Message>
    bool decodeMessage(const Buffer& payload, Message& message)
    {
        return decode(std::span<const osuCrypto::u8>(payload.data(), payload.size()), message);
    }

    KeyDeriveRequest makeKeyDeriveRequest()
    {
        KeyDeriveRequest message{};
        message.mPolyModulusDegree = 16384;
        message.mCoeffModulusCount = 7;
        message.mTau = 3;
        message.mDCoeffs = { 0, 1, 0x0102030405060708ull, 0xFFFFFFFFFFFFFFFFull };
        return message;
    }

    KeyDeriveResponse makeKeyDeriveResponse()
    {
        KeyDeriveResponse message{};
        message.mPolyModulusDegree = 8192;
        message.mCoeffModulusCount = 4;
        message.mTau = 2;
        message.mMNttCoeffs = { 17, 23, 42, 99, 0x8877665544332211ull };
        return message;
    }

    ShrinkExpandOfflineMessage makeShrinkExpandOfflineMessage()
    {
        ShrinkExpandOfflineMessage message{};
        message.mPolyModulusDegree = 16384;
        message.mCoeffModulusBits = { 54, 54, 50 };
        message.mPlaintextModulusBits = 20;
        message.mAlpha = 2;
        message.mMu = 3;
        message.mTau = 4;
        message.mGadgetLogBase = 126;
        message.mMode = 1;
        message.mMetadataFingerprint = 0x1020304050607080ull;
        message.mCt1Rows = 2;
        message.mCt1Cols = 3;
        message.mCt1Coeffs = { 3, 1, 4, 1, 5, 9 };
        message.mLacctWidthPadded = 4;
        message.mLacctLevels = 2;
        message.mLacctCtRows = 8;
        message.mLacctCtCols = 6;
        message.mLacctCtCoeffs = { 2, 7, 1, 8, 2, 8, 1, 8 };
        return message;
    }

    PolyMessage makePolyMessage()
    {
        PolyMessage message{};
        message.mPolyModulusDegree = 1024;
        message.mCoeffModulusCount = 2;
        message.mCoeffs = { 0, 1, 0x0102030405060708ull, 0x8877665544332211ull };
        return message;
    }
}

void LogVole_Encoding_KeyDeriveRequestRoundTrip(const oc::CLP&)
{
    const auto message = makeKeyDeriveRequest();
    const auto encoded = encode(message);

    KeyDeriveRequest decoded{};
    LOGVOLE_REQUIRE_TRUE(decodeMessage(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_EQ(decoded.mDCoeffs, message.mDCoeffs);
}

void LogVole_Encoding_KeyDeriveResponseRoundTrip(const oc::CLP&)
{
    const auto message = makeKeyDeriveResponse();
    const auto encoded = encode(message);

    KeyDeriveResponse decoded{};
    LOGVOLE_REQUIRE_TRUE(decodeMessage(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_EQ(decoded.mMNttCoeffs, message.mMNttCoeffs);
}

void LogVole_Encoding_ShrinkExpandOfflineRoundTrip(const oc::CLP&)
{
    const auto message = makeShrinkExpandOfflineMessage();
    const auto encoded = encode(message);

    ShrinkExpandOfflineMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decodeMessage(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusBits, message.mCoeffModulusBits);
    LOGVOLE_EXPECT_EQ(decoded.mPlaintextModulusBits, message.mPlaintextModulusBits);
    LOGVOLE_EXPECT_EQ(decoded.mAlpha, message.mAlpha);
    LOGVOLE_EXPECT_EQ(decoded.mMu, message.mMu);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_EQ(decoded.mGadgetLogBase, message.mGadgetLogBase);
    LOGVOLE_EXPECT_EQ(decoded.mMode, message.mMode);
    LOGVOLE_EXPECT_EQ(decoded.mMetadataFingerprint, message.mMetadataFingerprint);
    LOGVOLE_EXPECT_EQ(decoded.mCt1Rows, message.mCt1Rows);
    LOGVOLE_EXPECT_EQ(decoded.mCt1Cols, message.mCt1Cols);
    LOGVOLE_EXPECT_EQ(decoded.mCt1Coeffs, message.mCt1Coeffs);
    LOGVOLE_EXPECT_EQ(decoded.mLacctWidthPadded, message.mLacctWidthPadded);
    LOGVOLE_EXPECT_EQ(decoded.mLacctLevels, message.mLacctLevels);
    LOGVOLE_EXPECT_EQ(decoded.mLacctCtRows, message.mLacctCtRows);
    LOGVOLE_EXPECT_EQ(decoded.mLacctCtCols, message.mLacctCtCols);
    LOGVOLE_EXPECT_EQ(decoded.mLacctCtCoeffs, message.mLacctCtCoeffs);
}

void LogVole_Encoding_PolyMessageRoundTrip(const oc::CLP&)
{
    const auto message = makePolyMessage();
    const auto encoded = encode(message);

    PolyMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decodeMessage(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffs, message.mCoeffs);
}

void LogVole_Encoding_MalformedPayloadRejected(const oc::CLP&)
{
    auto encoded = encode(makeKeyDeriveRequest());
    LOGVOLE_REQUIRE_FALSE(encoded.empty());

    auto truncated = encoded;
    truncated.pop_back();
    KeyDeriveRequest decoded_request{};
    LOGVOLE_EXPECT_FALSE(decodeMessage(truncated, decoded_request));

    auto with_trailing = encoded;
    with_trailing.push_back(0x42);
    LOGVOLE_EXPECT_FALSE(decodeMessage(with_trailing, decoded_request));

    auto offline = encode(makeShrinkExpandOfflineMessage());
    LOGVOLE_REQUIRE_FALSE(offline.empty());
    offline.resize(offline.size() - 1);
    ShrinkExpandOfflineMessage decoded_offline{};
    LOGVOLE_EXPECT_FALSE(decodeMessage(offline, decoded_offline));
}
