#include "libOTe/Vole/LogVole/LogVoleEncoding.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    KeyDeriveRequest make_keyderive_request()
    {
        KeyDeriveRequest message{};
        message.mPolyModulusDegree = 1024;
        message.mCoeffModulusCount = 2;
        message.mTau = 3;
        assignValues<std::uint64_t>(message.mDCoeffs, { 1, 2, 3, 4, 5 });
        return message;
    }

    KeyDeriveResponse make_keyderive_response()
    {
        KeyDeriveResponse message{};
        message.mPolyModulusDegree = 2048;
        message.mCoeffModulusCount = 3;
        message.mTau = 4;
        assignValues<std::uint64_t>(message.mMNttCoeffs, { 9, 8, 7, 6 });
        return message;
    }

    RingParams make_ring()
    {
        RingParams ring{};
        ring.mPolyModulusDegree = 8;
        assignValues<int>(ring.mCoeffModulusBits, { 30, 31 });
        return ring;
    }

    RnsPoly make_poly(const RingParams& ring, std::uint64_t seed)
    {
        RnsPoly poly{};
        poly.mCoeffs.resize(ringPolyCoeffCount(ring));
        for (std::size_t idx = 0; idx < poly.mCoeffs.size(); ++idx)
        {
            poly.mCoeffs[idx] = seed + static_cast<std::uint64_t>(idx * 17);
        }
        return poly;
    }

    RingTensor make_tensor(const RingParams& ring, std::uint32_t rows, std::uint32_t cols, std::uint64_t seed)
    {
        RingTensor tensor{};
        tensor.mRows = rows;
        tensor.mCols = cols;
        tensor.mPolys.reserve(static_cast<std::size_t>(rows) * cols);
        for (std::uint32_t idx = 0; idx < rows * cols; ++idx)
        {
            tensor.mPolys.push_back(make_poly(ring, seed + idx * 101));
        }
        return tensor;
    }

    void expect_poly_equal(const RnsPoly& lhs, const RnsPoly& rhs)
    {
        LOGVOLE_REQUIRE_EQ(lhs.mCoeffs.size(), rhs.mCoeffs.size());
        for (std::size_t idx = 0; idx < lhs.mCoeffs.size(); ++idx)
        {
            LOGVOLE_EXPECT_EQ(lhs.mCoeffs[idx], rhs.mCoeffs[idx]);
        }
    }

    void expect_tensor_equal(const RingTensor& lhs, const RingTensor& rhs)
    {
        LOGVOLE_EXPECT_EQ(lhs.mRows, rhs.mRows);
        LOGVOLE_EXPECT_EQ(lhs.mCols, rhs.mCols);
        LOGVOLE_REQUIRE_EQ(lhs.mPolys.size(), rhs.mPolys.size());
        for (std::size_t idx = 0; idx < lhs.mPolys.size(); ++idx)
        {
            expect_poly_equal(lhs.mPolys[idx], rhs.mPolys[idx]);
        }
    }
}

void LogVole_Encoding_KeyDeriveRequestRoundTrip(const oc::CLP&)
{
    const auto message = make_keyderive_request();
    const auto encoded = encode(message);

    KeyDeriveRequest decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_TRUE(rangesEqual(decoded.mDCoeffs, message.mDCoeffs));
}

void LogVole_Encoding_KeyDeriveResponseRoundTrip(const oc::CLP&)
{
    const auto message = make_keyderive_response();
    const auto encoded = encode(message);

    KeyDeriveResponse decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_TRUE(rangesEqual(decoded.mMNttCoeffs, message.mMNttCoeffs));
}

void LogVole_Encoding_SeedMessageRoundTrip(const oc::CLP&)
{
    SeedMessage message{};
    assignValues<std::uint8_t>(message.mSeed, { 1, 3, 5, 7, 9, 11 });

    const auto encoded = encode(message);
    SeedMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decoded.mSeed, message.mSeed));

    SeedMessage empty{};
    LOGVOLE_EXPECT_FALSE(decode(std::span<const std::uint8_t>{}, empty));
}

void LogVole_Encoding_RootOfflineMessageRoundTrip(const oc::CLP&)
{
    const RingParams ring = make_ring();

    RootOfflineMessage message{};
    message.mRing = ring;
    message.mTauHi = 2;
    message.mGadgetLogBase = 7;
    message.mPlaintextModulusBits = 18;
    message.mLeftWidth = 4;
    message.mRandomizerWidth = 3;
    message.mCtR = make_tensor(ring, 4, 2, 1000);
    message.mLacctLeft.mWidthPadded = 8;
    message.mLacctLeft.mLevels = 3;
    message.mLacctLeft.mCt = make_tensor(ring, 3, 4, 2000);
    message.mTopCt = make_tensor(ring, 4, 5, 3000);
    message.mPublicBStarNtt = {
        make_poly(ring, 4000),
        make_poly(ring, 5000),
        make_poly(ring, 6000),
    };

    const auto encoded = encode(message);
    RootOfflineMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));

    LOGVOLE_EXPECT_TRUE(decoded.mRing == message.mRing);
    LOGVOLE_EXPECT_EQ(decoded.mTauHi, message.mTauHi);
    LOGVOLE_EXPECT_EQ(decoded.mGadgetLogBase, message.mGadgetLogBase);
    LOGVOLE_EXPECT_EQ(decoded.mPlaintextModulusBits, message.mPlaintextModulusBits);
    LOGVOLE_EXPECT_EQ(decoded.mLeftWidth, message.mLeftWidth);
    LOGVOLE_EXPECT_EQ(decoded.mRandomizerWidth, message.mRandomizerWidth);
    expect_tensor_equal(decoded.mCtR, message.mCtR);
    LOGVOLE_EXPECT_EQ(decoded.mLacctLeft.mWidthPadded, message.mLacctLeft.mWidthPadded);
    LOGVOLE_EXPECT_EQ(decoded.mLacctLeft.mLevels, message.mLacctLeft.mLevels);
    expect_tensor_equal(decoded.mLacctLeft.mCt, message.mLacctLeft.mCt);
    expect_tensor_equal(decoded.mTopCt, message.mTopCt);
    LOGVOLE_REQUIRE_EQ(decoded.mPublicBStarNtt.size(), message.mPublicBStarNtt.size());
    for (std::size_t idx = 0; idx < decoded.mPublicBStarNtt.size(); ++idx)
    {
        expect_poly_equal(decoded.mPublicBStarNtt[idx], message.mPublicBStarNtt[idx]);
    }
}

void LogVole_Encoding_ShrinkExpandOfflineMessageDoesNotLeakNoiseRoot(const oc::CLP&)
{
    const RingParams ring = make_ring();

    ShrinkExpandOfflineMessage message{};
    message.mParams.mRing = ring;
    message.mParams.mPlaintextModulusBits = 18;
    message.mParams.mAlpha = 2;
    message.mParams.mMu = 3;
    message.mParams.mGadgetLogBase = 7;
    message.mParams.mTau = 2;
    message.mParams.mTruncateOneGadgetDigit = true;
    message.mParams.mLeafInputsAreGadget = true;
    message.mParams.mMode = ShrinkExpandMode::FullNoise;
    message.mParams.mNoiseBound = 5;
    message.mCt1 = make_tensor(ring, message.mParams.mMu, message.mParams.mTau, 7000);
    message.mLacct.mWidthPadded = 4;
    message.mLacct.mLevels = 2;
    message.mLacct.mCt = make_tensor(ring, 8, 4, 8000);

    const auto encoded = encode(message);
    ShrinkExpandOfflineMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));

    LOGVOLE_EXPECT_TRUE(decoded.mParams.mRing == message.mParams.mRing);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mPlaintextModulusBits, message.mParams.mPlaintextModulusBits);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mAlpha, message.mParams.mAlpha);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mMu, message.mParams.mMu);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mGadgetLogBase, message.mParams.mGadgetLogBase);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mTau, message.mParams.mTau);
    LOGVOLE_EXPECT_TRUE(decoded.mParams.mTruncateOneGadgetDigit);
    LOGVOLE_EXPECT_TRUE(decoded.mParams.mLeafInputsAreGadget);
    LOGVOLE_EXPECT_EQ(static_cast<std::uint8_t>(decoded.mParams.mMode), static_cast<std::uint8_t>(message.mParams.mMode));
    LOGVOLE_EXPECT_EQ(decoded.mParams.mNoiseBound, message.mParams.mNoiseBound);
    expect_tensor_equal(decoded.mCt1, message.mCt1);
    LOGVOLE_EXPECT_EQ(decoded.mLacct.mWidthPadded, message.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(decoded.mLacct.mLevels, message.mLacct.mLevels);
    expect_tensor_equal(decoded.mLacct.mCt, message.mLacct.mCt);
}

void LogVole_Encoding_ShrinkExpandOfflineMessageRejectsInvalidMode(const oc::CLP&)
{
    const RingParams ring = make_ring();

    ShrinkExpandOfflineMessage message{};
    message.mParams.mRing = ring;
    message.mParams.mPlaintextModulusBits = 18;
    message.mParams.mAlpha = 2;
    message.mParams.mMu = 3;
    message.mParams.mGadgetLogBase = 7;
    message.mParams.mTau = 2;
    message.mParams.mTruncateOneGadgetDigit = true;
    message.mParams.mLeafInputsAreGadget = true;
    message.mParams.mMode = ShrinkExpandMode::FullNoise;
    message.mParams.mNoiseBound = 5;
    message.mCt1 = make_tensor(ring, message.mParams.mMu, message.mParams.mTau, 7000);
    message.mLacct.mWidthPadded = 4;
    message.mLacct.mLevels = 2;
    message.mLacct.mCt = make_tensor(ring, 8, 4, 8000);

    auto encoded = encode(message);
    const std::size_t ringParamsSize =
        sizeof(std::uint32_t) +
        sizeof(std::uint32_t) +
        ring.mCoeffModulusBits.size() * sizeof(std::uint16_t);
    const std::size_t modeOffset =
        ringParamsSize +
        5u * sizeof(std::uint32_t) +
        2u * sizeof(std::uint8_t);
    LOGVOLE_REQUIRE_LT(modeOffset, encoded.size());
    encoded[modeOffset] = 0xFF;

    ShrinkExpandOfflineMessage decoded{};
    LOGVOLE_EXPECT_FALSE(decode(encoded, decoded));
}

void LogVole_Encoding_RootDigestAndResponseRoundTrip(const oc::CLP&)
{
    RootDigestMessage digest{};
    assignValues<std::uint64_t>(digest.mDPrimeCoeffs, { 1, 4, 9, 16, 25 });

    const auto encodedDigest = encode(digest);
    RootDigestMessage decodedDigest{};
    LOGVOLE_REQUIRE_TRUE(decode(encodedDigest, decodedDigest));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decodedDigest.mDPrimeCoeffs, digest.mDPrimeCoeffs));

    RootResponseMessage response{};
    assignValues<std::uint8_t>(response.mSeed, { 2, 4, 6, 8 });
    assignValues<std::uint64_t>(response.mSkPrimeCoeffs, { 10, 20, 30, 40 });

    const auto encodedResponse = encode(response);
    RootResponseMessage decodedResponse{};
    LOGVOLE_REQUIRE_TRUE(decode(encodedResponse, decodedResponse));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decodedResponse.mSeed, response.mSeed));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decodedResponse.mSkPrimeCoeffs, response.mSkPrimeCoeffs));

    RootDigestMessage emptyDigest{};
    LOGVOLE_EXPECT_FALSE(decode(encode(emptyDigest), emptyDigest));
}

void LogVole_Encoding_AllMessageRoundTrips(const oc::CLP& cmd)
{
    LogVole_Encoding_KeyDeriveRequestRoundTrip(cmd);
    LogVole_Encoding_KeyDeriveResponseRoundTrip(cmd);
    LogVole_Encoding_SeedMessageRoundTrip(cmd);
    LogVole_Encoding_ShrinkExpandOfflineMessageDoesNotLeakNoiseRoot(cmd);
    LogVole_Encoding_ShrinkExpandOfflineMessageRejectsInvalidMode(cmd);
    LogVole_Encoding_RootOfflineMessageRoundTrip(cmd);
    LogVole_Encoding_RootDigestAndResponseRoundTrip(cmd);
}
