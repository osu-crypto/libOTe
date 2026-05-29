#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    ShrinkExpandParams make_params()
    {
        ShrinkExpandParams params{};
        params.mRing.mPolyModulusDegree = 1024;
        params.mRing.mCoeffModulusBits = { 30, 30 };
        params.mPlaintextModulusBits = 20;
        params.mAlpha = 2;
        params.mMu = 3;
        params.mTau = 3;
        params.mGadgetLogBase = 20;
        params.mMode = ShrinkExpandMode::Deterministic;
        params.mNoiseSeed = 0xBAD5EEDu;
        params.mNoiseBound = 2;
        return params;
    }

    ShrinkExpandParams make_full_noise_params()
    {
        auto params = make_params();
        params.mRing.mCoeffModulusBits = { 54, 54, 54, 54, 54, 54, 54 };
        params.mPlaintextModulusBits = 54;
        params.mGadgetLogBase = 126;
        params.mMode = ShrinkExpandMode::FullNoise;
        params.mNoiseBound = 2;
        return params;
    }

    std::vector<RnsPoly> sample_batch(
        const RingNttContext& ctx,
        std::uint32_t count,
        std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0xABCDu, i));
        }
        return out;
    }

    RnsPoly sample_poly(const RingNttContext& ctx, std::uint64_t seed)
    {
        return deriveUniformPolyFromNonce(ctx, seed, 0xABCDu, 0);
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }

    std::vector<RnsPoly> multiply_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b)
    {
        std::vector<RnsPoly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(a[i], b[i], ctx, product));
            out.push_back(std::move(product));
        }
        return out;
    }

    std::vector<RnsPoly> subtract_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b)
    {
        std::vector<RnsPoly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly diff{};
            LOGVOLE_REQUIRE_TRUE(ringSub(a[i], b[i], ctx, diff));
            out.push_back(std::move(diff));
        }
        return out;
    }

    std::uint32_t log_q_bits(const ShrinkExpandParams& params)
    {
        std::uint32_t out = 0;
        for (const auto bits : params.mRing.mCoeffModulusBits)
        {
            out += static_cast<std::uint32_t>(bits);
        }
        return out;
    }

    long double max_centered_log2(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& polys)
    {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t coeffModCount = ctx.mParams.mCoeffModulusBits.size();
        auto contextData = ctx.mContext->key_context_data();
        seal::util::RNSBase fullBase(contextData->parms().coeff_modulus(), seal::MemoryManager::GetPool());

        auto composedPoly = seal::util::allocate_poly(n, coeffModCount, seal::MemoryManager::GetPool());
        auto coeffMpi = seal::util::allocate_uint(coeffModCount, seal::MemoryManager::GetPool());

        long double maxLog2 = 0.0L;
        for (const auto& poly : polys)
        {
            std::copy(poly.mCoeffs.begin(), poly.mCoeffs.end(), composedPoly.get());
            fullBase.compose_array(composedPoly.get(), n, seal::MemoryManager::GetPool());

            for (std::size_t i = 0; i < n; ++i)
            {
                const std::uint64_t* valPtr = composedPoly.get() + i * coeffModCount;
                const int bitCountPos = seal::util::get_significant_bit_count_uint(valPtr, coeffModCount);

                seal::util::sub_uint(fullBase.base_prod(), valPtr, coeffModCount, coeffMpi.get());
                const int bitCountNeg = seal::util::get_significant_bit_count_uint(coeffMpi.get(), coeffModCount);

                const int bitCount = std::min(bitCountPos, bitCountNeg);
                if (bitCount > maxLog2)
                {
                    maxLog2 = bitCount;
                }
            }
        }
        return maxLog2;
    }
}

void LogVole_ShrinkExpandCore_DenoiseCombExactness(const oc::CLP&)
{
    constexpr std::uint64_t seed_x = 0x8888;
    constexpr std::uint64_t seed_noise = 0x9999;

    const auto params = make_full_noise_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    const std::size_t n = params.mRing.mPolyModulusDegree;
    const std::size_t rho = params.mRing.mCoeffModulusBits.size();
    const std::size_t wPrime = 2;

    const auto xBatch = sample_batch(ctx, static_cast<std::uint32_t>(wPrime), seed_x);

    std::vector<RnsPoly> tbaPrime;
    tbaPrime.reserve(wPrime * rho);

    auto keyContextData = ctx.mContext->key_context_data();
    seal::util::RNSBase fullBase(keyContextData->parms().coeff_modulus(), seal::MemoryManager::GetPool());
    auto pool = seal::MemoryManager::GetPool();

    auto pJMpi = seal::util::allocate_uint(rho, pool);
    auto pJHalfMpi = seal::util::allocate_uint(rho, pool);
    auto modJMpi = seal::util::allocate_uint(rho, pool);
    auto remainderMpi = seal::util::allocate_uint(rho, pool);
    auto valMpi = seal::util::allocate_uint(rho, pool);
    auto noiseMpi = seal::util::allocate_uint(rho, pool);

    std::mt19937_64 prng(seed_noise);

    for (std::size_t i = 0; i < wPrime; ++i)
    {
        for (std::size_t j = 0; j < rho; ++j)
        {
            RnsPoly polyJ{};
            polyJ.mCoeffs.resize(n * rho, 0);

            const auto modulusJ = fullBase.base()[j];
            seal::util::set_uint(modulusJ.value(), rho, modJMpi.get());
            seal::util::divide_uint(fullBase.base_prod(), modJMpi.get(), rho, pJMpi.get(), remainderMpi.get(), pool);
            seal::util::right_shift_uint(pJMpi.get(), 1, rho, pJHalfMpi.get());

            for (std::size_t k = 0; k < n; ++k)
            {
                const std::uint64_t xKJ = xBatch[i].mCoeffs[j * n + k];
                seal::util::set_uint(xKJ, rho, valMpi.get());
                seal::util::multiply_uint(valMpi.get(), pJMpi.get(), rho, valMpi.get());

                const std::uint64_t noiseVal = (prng() % 1000) + 1;
                const bool negative = (prng() % 2) == 1;
                seal::util::set_uint(noiseVal, rho, noiseMpi.get());
                if (negative)
                {
                    seal::util::sub_uint(valMpi.get(), noiseMpi.get(), rho, valMpi.get());
                }
                else
                {
                    seal::util::add_uint(valMpi.get(), noiseMpi.get(), rho, valMpi.get());
                }

                seal::util::divide_uint(valMpi.get(), fullBase.base_prod(), rho, pJHalfMpi.get(), remainderMpi.get(), pool);
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    polyJ.mCoeffs[modIdx * n + k] =
                        seal::util::modulo_uint(remainderMpi.get(), rho, fullBase.base()[modIdx]);
                }
            }
            tbaPrime.push_back(std::move(polyJ));
        }
    }

    std::vector<RnsPoly> outBatch;
    LOGVOLE_REQUIRE_TRUE(denoiseComb(ctx, tbaPrime, outBatch));
    expect_batch_equal(outBatch, xBatch);
}

void LogVole_ShrinkExpandCore_DeterministicRelationExact(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput sender_input{};
    sender_input.mParams = params;
    sender_input.mS = sample_batch(ctx, params.mMu, 0x2001u);

    ShrinkExpandOfflineMessage offline_message{};
    ShrinkExpandSenderState sender_state{};
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(sender_input, offline_message, sender_state));

    ShrinkExpandReceiverOfflineInput receiver_input{};
    receiver_input.mParams = params;
    ShrinkExpandReceiverState receiver_state{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiver_input, offline_message, receiver_state));

    auto x = sample_batch(ctx, params.mMu, 0x3001u);
    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(shrink(receiver_state, x, digest));

    const auto tbk_prime = sample_poly(ctx, 0x4001u);
    RnsPoly sk_x{};
    LOGVOLE_REQUIRE_TRUE(deriveSkX(sender_state, digest, tbk_prime, sk_x));

    ShrinkExpandSenderExpandInput sender_expand_input{};
    sender_expand_input.mNonce = 0x999u;
    sender_expand_input.mTbkPrime = tbk_prime;

    ShrinkExpandSenderExpandOutput sender_expand{};
    LOGVOLE_REQUIRE_TRUE(expandSender(sender_state, sender_expand_input, sender_expand));

    ShrinkExpandReceiverExpandInput receiver_expand_input{};
    receiver_expand_input.mNonce = sender_expand_input.mNonce;
    receiver_expand_input.mX = x;
    receiver_expand_input.mDigest = digest;
    receiver_expand_input.mSkX = sk_x;

    ShrinkExpandReceiverExpandOutput receiver_expand{};
    LOGVOLE_REQUIRE_TRUE(expandReceiver(receiver_state, receiver_expand_input, receiver_expand));

    const auto tbm_minus_tbk = subtract_batches(ctx, receiver_expand.mTbm, sender_expand.mTbk);
    const auto expected = multiply_batches(ctx, sender_input.mS, x);
    expect_batch_equal(tbm_minus_tbk, expected);
}

void LogVole_ShrinkExpandCore_OfflineMetadataMismatchRejected(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput sender_input{};
    sender_input.mParams = params;
    sender_input.mS = sample_batch(ctx, params.mMu, 0x5001u);

    ShrinkExpandOfflineMessage offline_message{};
    ShrinkExpandSenderState sender_state{};
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(sender_input, offline_message, sender_state));

    offline_message.mMetadataFingerprint ^= 1u;

    ShrinkExpandReceiverOfflineInput receiver_input{};
    receiver_input.mParams = params;
    ShrinkExpandReceiverState receiver_state{};
    LOGVOLE_REQUIRE_FALSE(finalizeReceiverOffline(receiver_input, offline_message, receiver_state));
}

void LogVole_ShrinkExpandCore_FullNoiseTolerance(const oc::CLP&)
{
    auto params = make_full_noise_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    std::int64_t effectiveNoiseBound = 0;
    LOGVOLE_REQUIRE_TRUE(resolveEffectiveNoiseBound(params, effectiveNoiseBound));
    LOGVOLE_REQUIRE_GT(effectiveNoiseBound, params.mNoiseBound);

    ShrinkExpandSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mS = sample_batch(ctx, params.mMu, 0x5001u);

    ShrinkExpandOfflineMessage offlineMessage{};
    ShrinkExpandSenderState senderState{};
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(senderInput, offlineMessage, senderState));

    ShrinkExpandReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;
    ShrinkExpandReceiverState receiverState{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput, offlineMessage, receiverState));
    LOGVOLE_REQUIRE_EQ(senderState.mEffectiveNoiseBound, effectiveNoiseBound);
    LOGVOLE_REQUIRE_EQ(receiverState.mEffectiveNoiseBound, effectiveNoiseBound);

    auto x = sample_batch(ctx, params.mMu, 0x6001u);
    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(shrink(receiverState, x, digest));

    const auto tbkPrime = sample_poly(ctx, 0x7001u);
    RnsPoly skX{};
    LOGVOLE_REQUIRE_TRUE(deriveSkX(senderState, digest, tbkPrime, skX));

    ShrinkExpandSenderExpandInput senderExpandInput{};
    senderExpandInput.mNonce = 0xAAA1u;
    senderExpandInput.mTbkPrime = tbkPrime;

    ShrinkExpandSenderExpandOutput senderExpand{};
    LOGVOLE_REQUIRE_TRUE(expandSender(senderState, senderExpandInput, senderExpand));

    ShrinkExpandReceiverExpandInput receiverExpandInput{};
    receiverExpandInput.mNonce = senderExpandInput.mNonce;
    receiverExpandInput.mX = x;
    receiverExpandInput.mDigest = digest;
    receiverExpandInput.mSkX = skX;

    ShrinkExpandReceiverExpandOutput receiverExpand{};
    LOGVOLE_REQUIRE_TRUE(expandReceiver(receiverState, receiverExpandInput, receiverExpand));

    const auto tbmMinusTbk = subtract_batches(ctx, receiverExpand.mTbm, senderExpand.mTbk);
    const auto expected = multiply_batches(ctx, senderInput.mS, x);
    const auto residual = subtract_batches(ctx, tbmMinusTbk, expected);

    const auto maxLog2 = max_centered_log2(ctx, residual);
    const double maxNoiseAllowed = static_cast<double>(log_q_bits(params) - params.mRing.mCoeffModulusBits.back());
    LOGVOLE_EXPECT_GT(maxLog2, 0);
    LOGVOLE_EXPECT_LT(maxLog2, maxNoiseAllowed);
}
