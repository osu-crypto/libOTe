#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    RingParams make_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30 });
        return params;
    }

    bool prepare_sender_offline_for_test(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandSenderState& state)
    {
        oc::PRNG prng(oc::block(0x5100, 0x5101));
        return osuCrypto::LogVole::prepareShrinkExpandSenderOffline(input, prng, state);
    }

    bool prepare_sender_offline_for_test(
        const SenderOfflineInput& input,
        SenderOfflineOutput& out)
    {
        oc::PRNG prng(oc::block(0x5200, 0x5201));
        return osuCrypto::LogVole::prepareSenderOffline(input, prng, out);
    }

    bool prepare_root_offline_sender_for_test(SenderState& state, RootOfflineMessage& message)
    {
        oc::PRNG prng(oc::block(0x5300, 0x5301));
        return osuCrypto::LogVole::prepareRootOfflineSender(state, prng, message);
    }

    bool prepare_root_digest_receiver_for_test(
        const ReceiverState& state,
        const std::vector<RnsPoly>& x,
        RootDigestState& digestState,
        RootDigestMessage& message)
    {
        oc::PRNG prng(oc::block(0x5400, 0x5401));
        return osuCrypto::LogVole::prepareRootDigestReceiver(state, x, prng, digestState, message);
    }

    bool prepare_root_response_sender_for_test(
        const SenderState& state,
        const RootDigestMessage& request,
        RootResponseMessage& response)
    {
        oc::PRNG prng(oc::block(0x5500, 0x5501));
        return osuCrypto::LogVole::prepareRootResponseSender(state, request, prng, response);
    }

    bool run_local_online_for_test(
        SenderState& sender,
        ReceiverState& receiver,
        const ReceiverOnlineInput& input,
        SenderOnlineOutput& senderOut,
        ReceiverOnlineOutput& receiverOut)
    {
        oc::PRNG senderPrng(oc::block(0x5600, 0x5601));
        oc::PRNG receiverPrng(oc::block(0x5700, 0x5701));
        return osuCrypto::LogVole::runLocalOnline(sender, receiver, input, senderPrng, receiverPrng, senderOut, receiverOut);
    }

    Params make_golden_params()
    {
        Params params{};
        params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
        assignValues<int>(params.mShrinkExpand.mRing.mCoeffModulusBits, { 54, 54, 54, 54, 54, 54, 54 });
        params.mShrinkExpand.mPlaintextModulusBits = 54;
        params.mShrinkExpand.mAlpha = 2;
        params.mShrinkExpand.mTau = 3;
        params.mShrinkExpand.mMu =
            params.mShrinkExpand.mAlpha *
            params.mShrinkExpand.mTau *
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mShrinkExpand.mGadgetLogBase = 126;
        params.mShrinkExpand.mMode = ShrinkExpandMode::FullNoise;
        params.mShrinkExpand.mNoiseBound = 2;
        params.mW = params.mShrinkExpand.mMu;
        params.mGamma = 1;
        return params;
    }

    Params make_recursive_params(std::uint32_t numLevels)
    {
        Params params{};
        params.mShrinkExpand.mRing.mPolyModulusDegree = 8192;
        assignValues<int>(params.mShrinkExpand.mRing.mCoeffModulusBits, { 55, 55, 55, 55 });
        params.mShrinkExpand.mPlaintextModulusBits = 55;
        params.mShrinkExpand.mMode = ShrinkExpandMode::FullNoise;
        params.mShrinkExpand.mNoiseBound = 2;
        params.mShrinkExpand.mAlpha = 2;
        params.mShrinkExpand.mGadgetLogBase = 110;
        std::uint32_t logQ = 0;
        for (const auto bits : params.mShrinkExpand.mRing.mCoeffModulusBits)
        {
            logQ += static_cast<std::uint32_t>(bits);
        }
        params.mShrinkExpand.mTau =
            (logQ + params.mShrinkExpand.mGadgetLogBase - 1u) /
            params.mShrinkExpand.mGadgetLogBase;
        params.mShrinkExpand.mMu =
            params.mShrinkExpand.mAlpha *
            params.mShrinkExpand.mTau *
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());

        const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
        const std::uint32_t rho =
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
        std::uint32_t wPrime = 1;
        for (std::uint32_t i = 1; i < numLevels; ++i)
        {
            wPrime *= params.mShrinkExpand.mAlpha;
        }
        params.mW = wPrime * muHi;
        params.mGamma = 1;
        return params;
    }

    Params make_rejected_root_width_params()
    {
        Params params = make_golden_params();
        params.mW = 6;
        return params;
    }

    Params make_root_params()
    {
        Params params{};
        params.mShrinkExpand.mRing = make_params();
        params.mShrinkExpand.mPlaintextModulusBits = 18;
        params.mShrinkExpand.mAlpha = 2;
        params.mShrinkExpand.mTau = 3;
        params.mShrinkExpand.mMu =
            params.mShrinkExpand.mAlpha *
            params.mShrinkExpand.mTau *
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mShrinkExpand.mGadgetLogBase = 10;
        params.mShrinkExpand.mMode = ShrinkExpandMode::FullNoise;
        params.mShrinkExpand.mNoiseBound = 2;
        params.mW =
            params.mShrinkExpand.mAlpha *
            (params.mShrinkExpand.mTau - 1) *
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mGamma = 1;
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
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0007u, i));
        }
        return out;
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

    std::vector<std::uint64_t> delta_per_limb(const RingNttContext& ctx)
    {
        std::vector<std::uint64_t> out(ctx.mModuli.size(), 1);
        for (std::size_t j = 0; j < ctx.mModuli.size(); ++j)
        {
            std::uint64_t delta = 1;
            for (std::size_t k = 0; k < ctx.mModuli.size(); ++k)
            {
                if (k != j)
                {
                    delta = seal::util::multiply_uint_mod(delta, ctx.mModuli[k].value(), ctx.mModuli[j]);
                }
            }
            out[j] = delta;
        }
        return out;
    }

    RnsPoly zero_poly(const RingNttContext& ctx)
    {
        RnsPoly out{};
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        return out;
    }

    std::uint64_t pow2_mod(std::uint64_t exp, std::uint64_t mod)
    {
        const seal::Modulus modulus(mod);
        std::uint64_t result = 1;
        std::uint64_t base = 2 % mod;
        while (exp > 0)
        {
            if ((exp & 1) != 0)
            {
                result = mulMod(result, base, modulus);
            }
            base = mulMod(base, base, modulus);
            exp >>= 1;
        }
        return result;
    }

    bool scale_by_pow2(
        const RnsPoly& input,
        std::uint32_t gadgetLogBase,
        std::uint32_t power,
        const RingNttContext& ctx,
        RnsPoly& out)
    {
        if (!validateRingPolyShape(input, ctx.mParams))
        {
            return false;
        }

        out = input;
        const std::uint64_t shift = static_cast<std::uint64_t>(gadgetLogBase) * power;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const std::uint64_t factor = pow2_mod(shift, modulus.value());
            const std::size_t offset = modIdx * n;
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                const std::size_t idx = offset + coeffIdx;
                out.mCoeffs[idx] = seal::util::multiply_uint_mod(out.mCoeffs[idx], factor, modulus);
            }
        }
        return true;
    }

    std::uint64_t mix_public_seed(std::uint64_t value)
    {
        value += 0x9E3779B97F4A7C15ull;
        value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ull;
        value = (value ^ (value >> 27u)) * 0x94D049BB133111EBull;
        return value ^ (value >> 31u);
    }

    RnsPoly sample_small_plain_poly(
        const RingNttContext& ctx,
        std::uint64_t seed,
        std::uint32_t polyIdx,
        std::uint32_t bitCount)
    {
        RnsPoly out{};
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t rho = ctx.mModuli.size();
        resizeZero(out.mCoeffs, n * rho);

        const std::uint64_t mask =
            (bitCount >= 63u)
                ? std::numeric_limits<std::uint64_t>::max()
                : ((std::uint64_t{ 1 } << bitCount) - 1u);
        std::uint64_t state = mix_public_seed(seed ^ static_cast<std::uint64_t>(polyIdx));
        for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
        {
            state = mix_public_seed(state + static_cast<std::uint64_t>(coeffIdx));
            const std::uint64_t value = state & mask;
            for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
            {
                out.mCoeffs[modIdx * n + coeffIdx] = value % ctx.mModuli[modIdx].value();
            }
        }

        return out;
    }

    std::vector<RnsPoly> sample_small_plain_batch(
        const RingNttContext& ctx,
        std::uint32_t count,
        std::uint64_t seed,
        std::uint32_t bitCount)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(sample_small_plain_poly(ctx, seed, i, bitCount));
        }
        return out;
    }

    bool compute_expected_s_mul_x(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        const std::vector<RnsPoly>& x,
        std::vector<RnsPoly>& out)
    {
        if (s.size() != x.size())
        {
            return false;
        }

        out.clear();
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i)
        {
            RnsPoly prod{};
            if (!ringMultiply(s[i], x[i], ctx, prod))
            {
                return false;
            }
            out.push_back(std::move(prod));
        }
        return true;
    }

    bool subtract_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b,
        std::vector<RnsPoly>& out)
    {
        if (a.size() != b.size())
        {
            return false;
        }

        out.clear();
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly diff{};
            if (!ringSub(a[i], b[i], ctx, diff))
            {
                return false;
            }
            out.push_back(std::move(diff));
        }
        return true;
    }

    bool negate_batch(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& in,
        std::vector<RnsPoly>& out)
    {
        out.clear();
        out.reserve(in.size());
        const RnsPoly zero = zero_poly(ctx);
        for (const auto& poly : in)
        {
            RnsPoly neg{};
            if (!ringSub(zero, poly, ctx, neg))
            {
                return false;
            }
            out.push_back(std::move(neg));
        }
        return true;
    }

    long double max_centered_log2(const RingNttContext& ctx, const std::vector<RnsPoly>& polys)
    {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t rho = ctx.mParams.mCoeffModulusBits.size();
        auto contextData = ctx.mContext->key_context_data();
        seal::util::RNSBase fullBase(contextData->parms().coeff_modulus(), seal::MemoryManager::GetPool());

        auto composedPoly = seal::util::allocate_poly(n, rho, seal::MemoryManager::GetPool());
        auto coeffMpi = seal::util::allocate_uint(rho, seal::MemoryManager::GetPool());

        long double maxLog2 = 0.0L;
        for (const auto& poly : polys)
        {
            std::copy(poly.mCoeffs.begin(), poly.mCoeffs.end(), composedPoly.get());
            fullBase.compose_array(composedPoly.get(), n, seal::MemoryManager::GetPool());

            for (std::size_t i = 0; i < n; ++i)
            {
                const std::uint64_t* valPtr = composedPoly.get() + i * rho;
                const int bitCountPos = seal::util::get_significant_bit_count_uint(valPtr, rho);

                seal::util::sub_uint(fullBase.base_prod(), valPtr, rho, coeffMpi.get());
                const int bitCountNeg = seal::util::get_significant_bit_count_uint(coeffMpi.get(), rho);

                const int bitCount = std::min(bitCountPos, bitCountNeg);
                maxLog2 = std::max<long double>(maxLog2, bitCount);
            }
        }
        return maxLog2;
    }

    std::uint32_t log_q_bits(const RingParams& params)
    {
        std::uint32_t out = 0;
        for (const auto bits : params.mCoeffModulusBits)
        {
            out += static_cast<std::uint32_t>(bits);
        }
        return out;
    }

    bool check_logvole_noise_tolerance(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& actual,
        const std::vector<RnsPoly>& expected,
        const Params& params,
        long double& maxLog2)
    {
        std::vector<RnsPoly> residual;
        if (!subtract_batches(ctx, actual, expected, residual))
        {
            return false;
        }
        const long double maxLog2Pos = max_centered_log2(ctx, residual);

        std::vector<RnsPoly> expectedNeg;
        std::vector<RnsPoly> residualNeg;
        if (!negate_batch(ctx, expected, expectedNeg) ||
            !subtract_batches(ctx, actual, expectedNeg, residualNeg))
        {
            return false;
        }
        const long double maxLog2Neg = max_centered_log2(ctx, residualNeg);
        maxLog2 = std::min(maxLog2Pos, maxLog2Neg);

        const std::uint32_t logQ = log_q_bits(params.mShrinkExpand.mRing);
        if (params.mShrinkExpand.mPlaintextModulusBits >= logQ)
        {
            return false;
        }

        if (params.mShrinkExpand.mMode == ShrinkExpandMode::FullNoise)
        {
            const std::uint32_t tauHi =
                (params.mShrinkExpand.mTau > 0u) ? (params.mShrinkExpand.mTau - 1u) : 0u;
            const std::uint32_t rho =
                static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
            const long double pathLen =
                1.0L + std::log2((muHi > 1u) ? static_cast<long double>(muHi) : 1.0L);
            const long double truncationBoundLog2 =
                static_cast<long double>(params.mShrinkExpand.mGadgetLogBase) +
                std::log2(static_cast<long double>(params.mShrinkExpand.mRing.mPolyModulusDegree)) +
                std::log2(pathLen);
            return maxLog2 < truncationBoundLog2 + 1.0L;
        }

        return maxLog2 > 0.0L &&
               maxLog2 < static_cast<long double>(logQ - params.mShrinkExpand.mPlaintextModulusBits);
    }

}

void LogVole_Core_WideU64OneShiftBounds(const oc::CLP&)
{
    LOGVOLE_EXPECT_TRUE(wideU64Equal(wideU64OneShift(0), makeWideU64(1, 0)));
    LOGVOLE_EXPECT_TRUE(wideU64Equal(wideU64OneShift(63), makeWideU64(std::uint64_t{ 1 } << 63, 0)));
    LOGVOLE_EXPECT_TRUE(wideU64Equal(wideU64OneShift(64), makeWideU64(0, 1)));
    LOGVOLE_EXPECT_TRUE(wideU64Equal(wideU64OneShift(127), makeWideU64(0, std::uint64_t{ 1 } << 63)));
    LOGVOLE_EXPECT_TRUE(wideU64Equal(wideU64OneShift(128), makeWideU64(0, 0)));
    LOGVOLE_EXPECT_TRUE(wideU64Equal(wideU64OneShift(255), makeWideU64(0, 0)));
}

void LogVole_Core_ZpRingLabelCountCeilNoOverflow(const oc::CLP&)
{
    ZpCrtContext ctx{};
    ctx.mRing.mParams.mPolyModulusDegree = 1024;

    LOGVOLE_EXPECT_EQ(zpRingLabelCount(ctx, 0), 0ull);
    LOGVOLE_EXPECT_EQ(zpRingLabelCount(ctx, 1), 1ull);
    LOGVOLE_EXPECT_EQ(zpRingLabelCount(ctx, 1024), 1ull);
    LOGVOLE_EXPECT_EQ(zpRingLabelCount(ctx, 1025), 2ull);

    constexpr std::uint64_t maxLabels = std::numeric_limits<std::uint64_t>::max();
    constexpr std::uint64_t slots = 1024;
    LOGVOLE_EXPECT_EQ(
        zpRingLabelCount(ctx, maxLabels),
        maxLabels / slots + static_cast<std::uint64_t>((maxLabels % slots) != 0));
}

void LogVole_Core_ModeSelection(const oc::CLP&)
{
    LOGVOLE_EXPECT_TRUE(evalSeedLabelMode(4, 2, 2, 2) == SeedLabelMode::Leaf);
    LOGVOLE_EXPECT_TRUE(evalSeedLabelMode(5, 2, 2, 2) == SeedLabelMode::Internal);

    LOGVOLE_EXPECT_TRUE(evalRecursiveMode(8, 2, 2, 2) == RecursiveMode::Root);
    LOGVOLE_EXPECT_TRUE(evalRecursiveMode(9, 2, 2, 2) == RecursiveMode::Internal);
}

void LogVole_Core_RuntimeCacheScopePropagatesToParallelWorkers(const oc::CLP&)
{
    const ProtocolCacheScope outerScope = currentProtocolCacheScope();
    const std::uint64_t runId = allocateProtocolCacheRunId();
    std::atomic<std::uint32_t> observed{ 0 };

    {
        ScopedProtocolCacheScope scoped(ProtocolCacheRole::Sender, runId);
        LOGVOLE_REQUIRE_TRUE(detail::runParallelTasks(
            16,
            4,
            [&](std::size_t) {
                const auto scope = currentProtocolCacheScope();
                if (scope.mRole == ProtocolCacheRole::Sender && scope.mRunId == runId)
                {
                    observed.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
                return false;
            }));
    }

    LOGVOLE_EXPECT_EQ(observed.load(std::memory_order_relaxed), 16u);

    const ProtocolCacheScope restoredScope = currentProtocolCacheScope();
    LOGVOLE_EXPECT_EQ(restoredScope.mRunId, outerScope.mRunId);
    LOGVOLE_EXPECT_TRUE(restoredScope.mRole == outerScope.mRole);
}

void LogVole_Core_SeedLabelAggSumsTauBlocks(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t outCount = 3;
    const std::uint32_t tau = 2;
    const auto input = sample_batch(ctx, outCount * tau, 0x1001u);

    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelAgg(input, outCount, tau, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), outCount);

    for (std::uint32_t i = 0; i < outCount; ++i)
    {
        RnsPoly expected = input[static_cast<std::size_t>(i) * tau];
        LOGVOLE_REQUIRE_TRUE(ringAddInplace(expected, input[static_cast<std::size_t>(i) * tau + 1], ctx));
        expect_poly_equal(actual[i], expected);
    }
}

void LogVole_Core_GdecompHiUnbundleLiftsOneLimbPerOutput(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const auto digest = deriveUniformPolyFromNonce(ctx, 0x2002u, 0x1E2C0008u, 0);
    const std::uint32_t tauHi = 2;
    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(digest, 20, 1, tauHi, ctx, digits));

    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelGadgetDecomposeHiAndUnbundle(digest, 20, tauHi, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(tauHi) * ctx.mModuli.size());

    const auto delta = delta_per_limb(ctx);
    const std::size_t n = params.mPolyModulusDegree;
    const std::size_t rho = ctx.mModuli.size();
    for (std::size_t digitIdx = 0; digitIdx < tauHi; ++digitIdx)
    {
        for (std::size_t limb = 0; limb < rho; ++limb)
        {
            const auto& poly = actual[digitIdx * rho + limb];
            for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
            {
                const std::size_t offset = modIdx * n;
                for (std::size_t c = 0; c < n; ++c)
                {
                    const auto expected =
                        (modIdx == limb)
                            ? seal::util::multiply_uint_mod(
                                  digits[digitIdx].mCoeffs[offset + c],
                                  delta[limb],
                                  ctx.mModuli[limb])
                            : 0u;
                    LOGVOLE_EXPECT_EQ(poly.mCoeffs[offset + c], expected);
                }
            }
        }
    }
}

void LogVole_Core_RepOfflineSenderInputGammaOneRepeats(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const auto s = sample_batch(ctx, 1, 0x3003u);
    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(s, 1, 2, 3, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(2 * 3 * params.mCoeffModulusBits.size()));
    for (const auto& poly : actual)
    {
        expect_poly_equal(poly, s[0]);
    }
}

void LogVole_Core_RepOfflineSenderInputGammaTauUnbundlesResidues(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t alpha = 2;
    const std::uint32_t tau = 3;
    const auto s = sample_batch(ctx, tau, 0x4004u);

    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(s, tau, alpha, tau, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(alpha * tau * params.mCoeffModulusBits.size()));

    const std::size_t n = params.mPolyModulusDegree;
    const std::size_t rho = ctx.mModuli.size();
    for (std::size_t alphaIdx = 0; alphaIdx < alpha; ++alphaIdx)
    {
        for (std::size_t digit = 0; digit < tau; ++digit)
        {
            for (std::size_t limb = 0; limb < rho; ++limb)
            {
                const auto& poly = actual[(alphaIdx * tau + digit) * rho + limb];
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    const std::size_t offset = modIdx * n;
                    for (std::size_t c = 0; c < n; ++c)
                    {
                        const auto expected =
                            (modIdx == limb) ? s[digit].mCoeffs[offset + c] : 0u;
                        LOGVOLE_EXPECT_EQ(poly.mCoeffs[offset + c], expected);
                    }
                }
            }
        }
    }
}

void LogVole_Core_RecursiveLiftOracleKeepsSenderResiduesUnscaled(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t alpha = 2;
    const std::uint32_t tauHi = 2;
    const std::size_t n = params.mPolyModulusDegree;
    const std::size_t rho = ctx.mModuli.size();
    LOGVOLE_REQUIRE_TRUE(rho >= 2);

    std::vector<RnsPoly> s(tauHi);
    for (std::uint32_t digit = 0; digit < tauHi; ++digit)
    {
        resizeZero(s[digit].mCoeffs, ringPolyCoeffCount(params));
        for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const std::size_t offset = modIdx * n;
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                s[digit].mCoeffs[offset + coeffIdx] =
                    (13u + 17u * digit + 19u * modIdx + coeffIdx) % modulus.value();
            }
        }
    }

    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(s, tauHi, alpha, tauHi, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(alpha) * tauHi * rho);

    const auto delta = delta_per_limb(ctx);
    bool wouldCatchDoubleLift = false;
    for (std::size_t alphaIdx = 0; alphaIdx < alpha; ++alphaIdx)
    {
        for (std::size_t digit = 0; digit < tauHi; ++digit)
        {
            for (std::size_t limb = 0; limb < rho; ++limb)
            {
                const auto& poly = actual[(alphaIdx * tauHi + digit) * rho + limb];
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    const std::size_t offset = modIdx * n;
                    for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
                    {
                        const auto expected =
                            (modIdx == limb) ? s[digit].mCoeffs[offset + coeffIdx] : 0u;
                        LOGVOLE_EXPECT_EQ(poly.mCoeffs[offset + coeffIdx], expected);

                        if (modIdx == limb)
                        {
                            const auto oldDoubleLift =
                                seal::util::multiply_uint_mod(expected, delta[limb], ctx.mModuli[limb]);
                            wouldCatchDoubleLift |= oldDoubleLift != expected;
                        }
                    }
                }
            }
        }
    }
    LOGVOLE_EXPECT_TRUE(wouldCatchDoubleLift);
}

void LogVole_Core_SeedLabelSampleCt2FromSeedDeterministic(const oc::CLP&)
{
    const auto params = make_params();
    const std::vector<std::uint8_t> seed = { 1, 3, 5, 7, 9, 11, 13, 15 };
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
    const auto digest = deriveUniformPolyFromNonce(ctx, 0xD1CEu, 0xC720u, 0);

    std::vector<RnsPoly> a;
    std::vector<RnsPoly> b;
    LOGVOLE_REQUIRE_TRUE(seedLabelSampleCt2FromSeed(seed, 2, digest, 3, 3, params, a));
    LOGVOLE_REQUIRE_TRUE(seedLabelSampleCt2FromSeed(seed, 2, digest, 3, 3, params, b));
    expect_batch_equal(a, b);

    std::vector<RnsPoly> c;
    LOGVOLE_REQUIRE_TRUE(seedLabelSampleCt2FromSeed(seed, 3, digest, 3, 3, params, c));
    LOGVOLE_EXPECT_FALSE(rangesEqual(a[0].mCoeffs, c[0].mCoeffs));
}

void LogVole_Core_SeedLabelDenoiseMatchesShrinkExpandComb(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t tau = static_cast<std::uint32_t>(params.mCoeffModulusBits.size());
    const std::uint32_t outCount = 2;
    const auto input = sample_batch(ctx, outCount * tau, 0x5005u);

    std::vector<RnsPoly> expected;
    LOGVOLE_REQUIRE_TRUE(shrinkExpandDenoiseComb(ctx, input, expected));

    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelDenoiseTbm(input, outCount, tau, params, actual));
    expect_batch_equal(actual, expected);
}

void LogVole_Core_RootTruncParamsAndKeyReplication(const oc::CLP&)
{
    Params params{};
    params.mShrinkExpand.mRing = make_params();
    params.mShrinkExpand.mAlpha = 2;
    params.mShrinkExpand.mTau = 4;
    params.mShrinkExpand.mMu = 123;

    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, true, trunc));
    LOGVOLE_EXPECT_EQ(trunc.mTau, std::uint32_t{ 3 });
    LOGVOLE_EXPECT_EQ(trunc.mMu, std::uint32_t{ 2 * 3 * 2 });
    LOGVOLE_EXPECT_TRUE(trunc.mTruncateOneGadgetDigit);
    LOGVOLE_EXPECT_TRUE(trunc.mLeafInputsAreGadget);

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));
    const auto skHi = sample_batch(ctx, trunc.mTau, 0x7101u);

    std::vector<RnsPoly> replicated;
    LOGVOLE_REQUIRE_TRUE(replicateRootHiKeyByLimb(skHi, trunc.mTau, params.mShrinkExpand.mRing, replicated));
    LOGVOLE_REQUIRE_EQ(replicated.size(), static_cast<std::size_t>(trunc.mTau) * ctx.mModuli.size());

    for (std::size_t digit = 0; digit < trunc.mTau; ++digit)
    {
        for (std::size_t limb = 0; limb < ctx.mModuli.size(); ++limb)
        {
            expect_poly_equal(replicated[digit * ctx.mModuli.size() + limb], skHi[digit]);
        }
    }
}

void LogVole_Core_RootScaledNttAddMatchesCoeffDomain(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly accCoeff = deriveUniformPolyFromNonce(ctx, 0x7201u, 0x1E2C0020u, 0);
    RnsPoly polyCoeff = deriveUniformPolyFromNonce(ctx, 0x7202u, 0x1E2C0021u, 0);
    RnsPoly accNtt = accCoeff;
    RnsPoly polyNtt = polyCoeff;
    LOGVOLE_REQUIRE_TRUE(forwardNtt(accNtt, ctx));
    LOGVOLE_REQUIRE_TRUE(forwardNtt(polyNtt, ctx));

    const std::uint32_t gadgetLogBase = 7;
    const std::uint32_t power = 2;
    LOGVOLE_REQUIRE_TRUE(addScaledNttInplace(accNtt, polyNtt, gadgetLogBase, power, ctx, false));
    LOGVOLE_REQUIRE_TRUE(inverseNtt(accNtt, ctx));

    RnsPoly scaled{};
    LOGVOLE_REQUIRE_TRUE(scale_by_pow2(polyCoeff, gadgetLogBase, power, ctx, scaled));
    RnsPoly expected{};
    LOGVOLE_REQUIRE_TRUE(ringAdd(accCoeff, scaled, ctx, expected));
    expect_poly_equal(accNtt, expected);
}

void LogVole_Core_RootTopCtNoiselessRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t tauHi = 2;
    const std::uint32_t randomizer = 3;
    const std::uint32_t leftWidth = 2;
    const std::uint32_t gadgetLogBase = 7;
    const std::uint32_t gadgetPowerOffset = 1;

    const auto r1 = sample_batch(ctx, leftWidth, 0x7301u);
    auto r2Ntt = sample_batch(ctx, leftWidth, 0x7302u);
    for (auto& poly : r2Ntt)
    {
        LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
    }

    auto publicBRootNtt = sample_batch(ctx, tauHi, 0x7303u);
    auto publicBStarNtt = sample_batch(ctx, randomizer, 0x7304u);
    for (auto& poly : publicBRootNtt)
    {
        LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
    }
    for (auto& poly : publicBStarNtt)
    {
        LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
    }

    RingTensor topCt{};
    oc::PRNG prng(oc::block(0x7305u, 0));
    LOGVOLE_REQUIRE_TRUE(buildRootTopCt(
        ctx,
        r1,
        r2Ntt,
        publicBRootNtt,
        publicBStarNtt,
        gadgetLogBase,
        gadgetPowerOffset,
        prng,
        0.0,
        0.0,
        topCt));
    LOGVOLE_EXPECT_EQ(topCt.mRows, leftWidth);
    LOGVOLE_EXPECT_EQ(topCt.mCols, tauHi + randomizer);
    LOGVOLE_REQUIRE_EQ(topCt.mPolys.size(), static_cast<std::size_t>(leftWidth) * (tauHi + randomizer));

    for (std::uint32_t row = 0; row < leftWidth; ++row)
    {
        for (std::uint32_t col = 0; col < topCt.mCols; ++col)
        {
            const auto& bNtt = (col < tauHi) ? publicBRootNtt[col] : publicBStarNtt[col - tauHi];
            RnsPoly bCoeff = bNtt;
            LOGVOLE_REQUIRE_TRUE(inverseNtt(bCoeff, ctx));

            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(r1[row], bCoeff, ctx, product));
            RnsPoly expected{};
            RnsPoly zero = zero_poly(ctx);
            LOGVOLE_REQUIRE_TRUE(ringSub(zero, product, ctx, expected));

            if (col < tauHi)
            {
                RnsPoly r2Coeff = r2Ntt[row];
                LOGVOLE_REQUIRE_TRUE(inverseNtt(r2Coeff, ctx));
                RnsPoly scaled{};
                LOGVOLE_REQUIRE_TRUE(
                    scale_by_pow2(r2Coeff, gadgetLogBase, gadgetPowerOffset + col, ctx, scaled));
                LOGVOLE_REQUIRE_TRUE(ringSubInplace(expected, scaled, ctx));
            }

            RnsPoly actual = topCt.mPolys[ringTensorIndex(topCt, row, col)];
            LOGVOLE_REQUIRE_TRUE(inverseNtt(actual, ctx));
            expect_poly_equal(actual, expected);
        }
    }
}

void LogVole_Core_RootZetaShapeAndBounds(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t randomizer = 4;
    const std::uint32_t gadgetLogBase = 8;
    std::vector<RnsPoly> zeta;
    oc::PRNG prng(oc::block(0x8401u, 0));
    LOGVOLE_REQUIRE_TRUE(sampleRootZeta(ctx, randomizer, gadgetLogBase, prng, zeta));
    LOGVOLE_REQUIRE_EQ(zeta.size(), randomizer);

    const std::uint64_t eta = (std::uint64_t{ 1 } << gadgetLogBase) - 1;
    const std::size_t n = params.mPolyModulusDegree;
    for (const auto& poly : zeta)
    {
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(poly, params));
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const std::uint64_t mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                const std::uint64_t value = poly.mCoeffs[offset + coeffIdx];
                LOGVOLE_EXPECT_TRUE(value <= eta || value >= mod - eta);
            }
        }
    }
}

void LogVole_Core_RootInnerProductMatchesCoeffDomain(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::uint32_t count = 4;
    const auto leftCoeff = sample_batch(ctx, count, 0x7401u);
    const auto rightCoeff = sample_batch(ctx, count, 0x7402u);

    auto leftNtt = leftCoeff;
    for (auto& poly : leftNtt)
    {
        LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
    }

    RnsPoly actual{};
    LOGVOLE_REQUIRE_TRUE(rootInnerProductNtt(ctx, leftNtt, rightCoeff, actual));

    RnsPoly expected = zero_poly(ctx);
    for (std::uint32_t idx = 0; idx < count; ++idx)
    {
        RnsPoly product{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(leftCoeff[idx], rightCoeff[idx], ctx, product));
        LOGVOLE_REQUIRE_TRUE(ringAddInplace(expected, product, ctx));
    }

    expect_poly_equal(actual, expected);
}

void LogVole_Core_RootOfflineSetupFinalizeShapes(const oc::CLP&)
{
    const Params params = make_root_params();
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, false, trunc));

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx));

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput.mS = sample_batch(ctx, trunc.mMu, 0x7501u);

    ShrinkExpandSenderState seSender{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(seInput, seSender));

    SenderState sender{};
    sender.mParams = params;
    sender.mShrinkExpandState = seSender;

    RootOfflineMessage message{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_offline_sender_for_test(sender, message));

    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1;
    const std::uint32_t rho = static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const std::uint32_t leftWidth = tauHi * rho;
    const std::uint32_t randomizer = rootRandomizerWidth(params.mShrinkExpand);

    LOGVOLE_EXPECT_TRUE(message.mRing == params.mShrinkExpand.mRing);
    LOGVOLE_EXPECT_EQ(message.mTauHi, tauHi);
    LOGVOLE_EXPECT_EQ(message.mLeftWidth, leftWidth);
    LOGVOLE_EXPECT_EQ(message.mRandomizerWidth, randomizer);
    LOGVOLE_EXPECT_EQ(message.mCtR.mRows, leftWidth);
    LOGVOLE_EXPECT_EQ(message.mCtR.mCols, tauHi);
    LOGVOLE_EXPECT_EQ(message.mTopCt.mRows, leftWidth);
    LOGVOLE_EXPECT_EQ(message.mTopCt.mCols, tauHi + randomizer);
    LOGVOLE_REQUIRE_EQ(message.mPublicBStarNtt.size(), randomizer);
    LOGVOLE_REQUIRE_EQ(sender.mRootSkRRt.size(), tauHi);
    LOGVOLE_REQUIRE_EQ(sender.mRootR1Rt.size(), leftWidth);

    ReceiverState receiver{};
    receiver.mParams = params;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(receiver, message));
    LOGVOLE_EXPECT_EQ(receiver.mRootRandomizerWidth, randomizer);
    LOGVOLE_EXPECT_EQ(receiver.mRootCtRRt.mRows, leftWidth);
    LOGVOLE_EXPECT_EQ(receiver.mRootCtRRt.mCols, tauHi);
    LOGVOLE_EXPECT_EQ(receiver.mRootLacctLeft.mWidthPadded, message.mLacctLeft.mWidthPadded);
    LOGVOLE_EXPECT_EQ(receiver.mRootTopCt.mRows, message.mTopCt.mRows);
    LOGVOLE_EXPECT_EQ(receiver.mRootPublicBStarNtt.size(), message.mPublicBStarNtt.size());

    RnsPoly roundTrip = receiver.mRootCtRRt.mPolys[0];
    LOGVOLE_REQUIRE_TRUE(inverseNtt(roundTrip, ctx));
    expect_poly_equal(roundTrip, message.mCtR.mPolys[0]);
}

void LogVole_Core_RootRandomizerWidthTracksGadgetBase(const oc::CLP&)
{
    Params params = make_root_params();
    params.mShrinkExpand.mRing.mPolyModulusDegree = 8192;
    params.mShrinkExpand.mTau = 2;
    params.mShrinkExpand.mGadgetLogBase = 110;
    LOGVOLE_EXPECT_EQ(rootRandomizerWidth(params.mShrinkExpand), 3);

    params.mShrinkExpand.mGadgetLogBase = 30;
    LOGVOLE_EXPECT_TRUE(rootRandomizerWidth(params.mShrinkExpand) >= 6);
}

void LogVole_Core_RootOfflineRejectsMetadataMismatch(const oc::CLP&)
{
    const Params params = make_root_params();
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, false, trunc));

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx));

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput.mS = sample_batch(ctx, trunc.mMu, 0x7502u);

    ShrinkExpandSenderState seSender{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(seInput, seSender));

    SenderState sender{};
    sender.mParams = params;
    sender.mShrinkExpandState = seSender;

    RootOfflineMessage message{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_offline_sender_for_test(sender, message));
    message.mTauHi += 1;

    ReceiverState receiver{};
    receiver.mParams = params;
    LOGVOLE_EXPECT_FALSE(finalizeRootOfflineReceiver(receiver, message));
}

void LogVole_Core_RootOnlineLocalFlow(const oc::CLP&)
{
    Params params = make_golden_params();
    params.mW =
        params.mShrinkExpand.mAlpha *
        (params.mShrinkExpand.mTau - 1) *
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, true, trunc));

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx));

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput.mS = sample_batch(ctx, trunc.mMu, 0x7601u);

    ShrinkExpandSenderState seSender{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(seInput, seSender));

    SenderState sender{};
    sender.mParams = params;
    sender.mShrinkExpandState = seSender;
    assignValues<std::uint8_t>(
        sender.mGoldenSeed,
        { 0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225 });

    RootOfflineMessage offlineMessage{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_offline_sender_for_test(sender, offlineMessage));

    ShrinkExpandReceiverOfflineInput seReceiverInput{};
    seReceiverInput.mParams = trunc;

    ShrinkExpandReceiverState seReceiver{};
    LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(seReceiverInput, seSender, seReceiver));

    ReceiverState receiver{};
    receiver.mParams = params;
    receiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(receiver, offlineMessage));

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(12u, params.mShrinkExpand.mPlaintextModulusBits);
    const auto x = sample_small_plain_batch(ctx, params.mW, 0x7602u, plainSampleBits);

    RootDigestState digestState{};
    RootDigestMessage digestMessage{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_digest_receiver_for_test(receiver, x, digestState, digestMessage));
    LOGVOLE_REQUIRE_EQ(digestMessage.mDPrimeCoeffs.size(), ringPolyCoeffCount(params.mShrinkExpand.mRing));

    RootResponseMessage response{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_response_sender_for_test(sender, digestMessage, response));
    LOGVOLE_EXPECT_TRUE(rangesEqual(response.mSeed, sender.mGoldenSeed));
    LOGVOLE_REQUIRE_EQ(response.mSkPrimeCoeffs.size(), ringPolyCoeffCount(params.mShrinkExpand.mRing));

    RnsPoly senderKey{};
    RnsPoly receiverKey{};
    LOGVOLE_REQUIRE_TRUE(computeRootSenderKey(sender, response.mSeed, senderKey));
    LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(receiver, digestState, response, receiverKey));
    LOGVOLE_EXPECT_TRUE(rangesEqual(receiver.mGoldenSeed, response.mSeed));

    ShrinkExpandExpandSenderInput senderExpandInput{};
    senderExpandInput.mSid = params.mSessionId;
    senderExpandInput.mSeed = response.mSeed;
    senderExpandInput.mDigest = digestState.mDRt;
    senderExpandInput.mMaskDigest = digestState.mDPrime;
    senderExpandInput.mNonce = 0;
    senderExpandInput.mTbkPrime = senderKey;

    ShrinkExpandSenderExpandOutput senderExpand{};
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandSender(sender.mShrinkExpandState, senderExpandInput, senderExpand));

    ShrinkExpandExpandReceiverInput receiverExpandInput{};
    receiverExpandInput.mSid = params.mSessionId;
    receiverExpandInput.mSeed = response.mSeed;
    receiverExpandInput.mNonce = senderExpandInput.mNonce;
    receiverExpandInput.mX = x;
    receiverExpandInput.mDigest = digestState.mDRt;
    receiverExpandInput.mMaskDigest = digestState.mDPrime;
    receiverExpandInput.mSkX = receiverKey;
    receiverExpandInput.mTree = digestState.mRootTree;

    ShrinkExpandReceiverExpandOutput receiverExpand{};
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandReceiver(receiver.mShrinkExpandState, receiverExpandInput, receiverExpand));
    LOGVOLE_REQUIRE_EQ(senderExpand.mTbk.size(), x.size());
    LOGVOLE_REQUIRE_EQ(receiverExpand.mTbm.size(), x.size());

    for (std::size_t idx = 0; idx < x.size(); ++idx)
    {
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(senderExpand.mTbk[idx], params.mShrinkExpand.mRing));
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(receiverExpand.mTbm[idx], params.mShrinkExpand.mRing));
    }
}

void LogVole_Core_RootOnlineLocalRelation(const oc::CLP&)
{
    Params params = make_golden_params();
    params.mW =
        params.mShrinkExpand.mAlpha *
        (params.mShrinkExpand.mTau - 1) *
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, false, trunc));

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx));

    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
    const auto sk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7611u);

    std::vector<RnsPoly> sRep;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
        sk1,
        params.mGamma,
        params.mShrinkExpand.mAlpha,
        tauHi,
        params.mShrinkExpand.mRing,
        sRep));
    LOGVOLE_REQUIRE_EQ(sRep.size(), params.mW);

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput.mS = sRep;

    ShrinkExpandSenderState seSender{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(seInput, seSender));

    SenderState sender{};
    sender.mParams = params;
    sender.mSk1 = sk1;
    sender.mShrinkExpandState = seSender;

    RootOfflineMessage offlineMessage{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_offline_sender_for_test(sender, offlineMessage));
    ShrinkExpandReceiverOfflineInput seReceiverInput{};
    seReceiverInput.mParams = trunc;

    ShrinkExpandReceiverState seReceiver{};
    LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(seReceiverInput, seSender, seReceiver));

    ReceiverState receiver{};
    receiver.mParams = params;
    receiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(receiver, offlineMessage));

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits);
    const auto x = sample_small_plain_batch(ctx, params.mW, 0x7622u, plainSampleBits);

    RootDigestState digestState{};
    RootDigestMessage digestMessage{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_digest_receiver_for_test(receiver, x, digestState, digestMessage));

    RootResponseMessage response{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_response_sender_for_test(sender, digestMessage, response));

    RnsPoly senderKey{};
    RnsPoly receiverKey{};
    LOGVOLE_REQUIRE_TRUE(computeRootSenderKey(sender, response.mSeed, senderKey));
    LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(receiver, digestState, response, receiverKey));

    RnsPoly directReceiverKey{};
    LOGVOLE_REQUIRE_TRUE(deriveSkxTrunc(
        ctx,
        sender.mShrinkExpandState.mSk1,
        digestState.mDRt,
        senderKey,
        params.mShrinkExpand.mGadgetLogBase,
        tauHi,
        directReceiverKey));
    std::vector<RnsPoly> receiverKeyDiff;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(
        ctx,
        std::vector<RnsPoly>{ receiverKey },
        std::vector<RnsPoly>{ directReceiverKey },
        receiverKeyDiff));
    const auto receiverKeyResidual = max_centered_log2(ctx, receiverKeyDiff);

    ShrinkExpandExpandSenderInput senderExpandInput{};
    senderExpandInput.mSid = params.mSessionId;
    senderExpandInput.mSeed = response.mSeed;
    senderExpandInput.mDigest = digestState.mDRt;
    senderExpandInput.mMaskDigest = digestState.mDPrime;
    senderExpandInput.mNonce = 0;
    senderExpandInput.mTbkPrime = senderKey;

    ShrinkExpandSenderExpandOutput senderExpand{};
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandSender(sender.mShrinkExpandState, senderExpandInput, senderExpand));

    ShrinkExpandExpandReceiverInput receiverExpandInput{};
    receiverExpandInput.mSid = params.mSessionId;
    receiverExpandInput.mSeed = response.mSeed;
    receiverExpandInput.mNonce = senderExpandInput.mNonce;
    receiverExpandInput.mX = x;
    receiverExpandInput.mDigest = digestState.mDRt;
    receiverExpandInput.mMaskDigest = digestState.mDPrime;
    receiverExpandInput.mSkX = receiverKey;
    receiverExpandInput.mTree = digestState.mRootTree;

    ShrinkExpandReceiverExpandOutput receiverExpand{};
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandReceiver(receiver.mShrinkExpandState, receiverExpandInput, receiverExpand));

    std::vector<RnsPoly> actual;
    std::vector<RnsPoly> expected;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(ctx, receiverExpand.mTbm, senderExpand.mTbk, actual));
    LOGVOLE_REQUIRE_TRUE(compute_expected_s_mul_x(ctx, sRep, x, expected));

    long double maxLog2 = 0.0L;
    LOGVOLE_EXPECT_TRUE(check_logvole_noise_tolerance(ctx, actual, expected, params, maxLog2))
        << "max centered log2 residual " << static_cast<double>(maxLog2)
        << ", root sk_x residual " << static_cast<double>(receiverKeyResidual);
}

void LogVole_Core_TwoLevelLocalApiRelation(const oc::CLP&)
{
    Params params = make_recursive_params(2);
    params.mShrinkExpand.mMode = ShrinkExpandMode::FullNoise;
    params.mShrinkExpand.mNoiseBound = 2;
    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
    const std::uint32_t rho =
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7751u);

    SenderOfflineOutput senderOffline{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(senderInput, senderOffline));

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    ReceiverOfflineOutput receiverOffline{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput, senderOffline.mMessage, receiverOffline));

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits);
    ReceiverOnlineInput receiverInputOnline{};
    receiverInputOnline.mX = sample_small_plain_batch(ctx, params.mW, 0x7762u, plainSampleBits);

    SenderOnlineOutput senderOnline{};
    ReceiverOnlineOutput receiverOnline{};
    LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(
        senderOffline.mState,
        receiverOffline.mState,
        receiverInputOnline,
        senderOnline,
        receiverOnline));
    LOGVOLE_REQUIRE_EQ(senderOnline.mTbk.size(), params.mW);
    LOGVOLE_REQUIRE_EQ(receiverOnline.mTbm.size(), params.mW);
    LOGVOLE_REQUIRE_FALSE(senderOnline.mSeed.empty());
    LOGVOLE_EXPECT_TRUE(rangesEqual(senderOnline.mSeed, receiverOnline.mSeed));
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mPrecomputedTbk != nullptr);
    LOGVOLE_REQUIRE_EQ(senderOffline.mState.mPrecomputedTbk->size(), params.mW);

    std::vector<RnsPoly> sRep;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
        senderInput.mSk1,
        params.mGamma,
        params.mShrinkExpand.mAlpha,
        tauHi,
        params.mShrinkExpand.mRing,
        sRep));

    const std::uint32_t wDoublePrime = (params.mW + muHi - 1u) / muHi;
    std::vector<RnsPoly> sW;
    sW.reserve(params.mW);
    for (std::uint32_t chunkIdx = 0; chunkIdx < wDoublePrime; ++chunkIdx)
    {
        for (const auto& poly : sRep)
        {
            if (sW.size() < params.mW)
            {
                sW.push_back(poly);
            }
        }
    }

    std::vector<RnsPoly> actual;
    std::vector<RnsPoly> expected;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(ctx, receiverOnline.mTbm, senderOnline.mTbk, actual));
    LOGVOLE_REQUIRE_TRUE(compute_expected_s_mul_x(ctx, sW, receiverInputOnline.mX, expected));

    long double maxLog2 = 0.0L;
    LOGVOLE_EXPECT_TRUE(check_logvole_noise_tolerance(ctx, actual, expected, params, maxLog2))
        << "max centered log2 residual " << static_cast<double>(maxLog2);
}

void LogVole_Core_ThreeLevelOfflineReuseAndInvalidWidth(const oc::CLP&)
{
    Params params = make_recursive_params(3);

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7851u);

    SenderOfflineOutput senderOffline{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(senderInput, senderOffline));
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mNextLevelState != nullptr);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mNextLevelState->mNextLevelState != nullptr);
    LOGVOLE_EXPECT_TRUE(senderOffline.mMessage.mHasShrinkExpandMessage);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mMessage.mNextLevel != nullptr);
    LOGVOLE_EXPECT_TRUE(senderOffline.mMessage.mNextLevel->mHasShrinkExpandMessage);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mMessage.mNextLevel->mNextLevel != nullptr);
    LOGVOLE_EXPECT_FALSE(senderOffline.mMessage.mNextLevel->mNextLevel->mHasShrinkExpandMessage);

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    ReceiverOfflineOutput receiverOffline{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput, senderOffline.mMessage, receiverOffline));
    LOGVOLE_REQUIRE_TRUE(receiverOffline.mState.mNextLevelState != nullptr);
    LOGVOLE_REQUIRE_TRUE(receiverOffline.mState.mNextLevelState->mNextLevelState != nullptr);

    LOGVOLE_EXPECT_TRUE(senderOffline.mState.mGoldenSeed.empty());
    LOGVOLE_EXPECT_TRUE(senderOffline.mState.mPrecomputedTbk == nullptr);

    ReceiverOnlineInput receiverInputOnline{};
    receiverInputOnline.mX = sample_small_plain_batch(
        ctx,
        params.mW,
        0x7862u,
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits));

    SenderOnlineOutput senderOnline{};
    ReceiverOnlineOutput receiverOnline{};
    LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(
        senderOffline.mState,
        receiverOffline.mState,
        receiverInputOnline,
        senderOnline,
        receiverOnline));
    LOGVOLE_REQUIRE_EQ(senderOnline.mTbk.size(), params.mW);
    LOGVOLE_REQUIRE_EQ(receiverOnline.mTbm.size(), params.mW);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mPrecomputedTbk != nullptr);
    LOGVOLE_REQUIRE_EQ(senderOffline.mState.mPrecomputedTbk->size(), params.mW);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mNextLevelState->mPrecomputedTbk != nullptr);
    LOGVOLE_REQUIRE_EQ(
        senderOffline.mState.mNextLevelState->mPrecomputedTbk->size(),
        senderOffline.mState.mNextLevelState->mParams.mW);

    const auto& topPackage = senderOffline.mState.mShrinkExpandState;
    const auto& firstInternal = senderOffline.mState.mNextLevelState->mShrinkExpandState;
    const auto& reusedRootPackage =
        senderOffline.mState.mNextLevelState->mNextLevelState->mShrinkExpandState;

    expect_batch_equal(topPackage.mSk1, firstInternal.mSk1);
    expect_batch_equal(firstInternal.mSk1, reusedRootPackage.mSk1);

    const Params rejectedParams = make_rejected_root_width_params();
    const std::uint32_t tauHi = rejectedParams.mShrinkExpand.mTau - 1u;
    const std::uint32_t rho =
        static_cast<std::uint32_t>(rejectedParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const std::uint32_t muHi = rejectedParams.mShrinkExpand.mAlpha * tauHi * rho;
    LOGVOLE_REQUIRE_LT(rejectedParams.mW, muHi);

    RingNttContext rejectedCtx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(rejectedParams.mShrinkExpand.mRing, rejectedCtx));

    SenderOfflineInput rejectedSenderInput{};
    rejectedSenderInput.mParams = rejectedParams;
    rejectedSenderInput.mSk1 = sample_batch(rejectedCtx, 1, 0x7D01u);

    SenderOfflineOutput rejectedSenderOutput{};
    LOGVOLE_EXPECT_FALSE(prepare_sender_offline_for_test(rejectedSenderInput, rejectedSenderOutput));

    ReceiverOfflineInput rejectedReceiverInput{};
    rejectedReceiverInput.mParams = rejectedParams;

    OfflineMessage emptyMessage{};
    ReceiverOfflineOutput rejectedReceiverOutput{};
    LOGVOLE_EXPECT_FALSE(finalizeReceiverOffline(rejectedReceiverInput, emptyMessage, rejectedReceiverOutput));
}

void run_recursive_gadget_subproblem_test(bool deterministic)
{
    Params params = make_recursive_params(2);
    params.mShrinkExpand.mMode =
        deterministic ? ShrinkExpandMode::FullNoise : ShrinkExpandMode::FullNoise;
    params.mShrinkExpand.mNoiseBound = deterministic ? 0 : 2;

    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
    const std::uint32_t rho =
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
    const std::uint32_t wDoublePrime = (params.mW + muHi - 1u) / muHi;

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7C51u);

    SenderOfflineOutput senderOffline{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(senderInput, senderOffline));
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mNextLevelState != nullptr);

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    ReceiverOfflineOutput receiverOffline{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput, senderOffline.mMessage, receiverOffline));
    LOGVOLE_REQUIRE_TRUE(receiverOffline.mState.mNextLevelState != nullptr);

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits);
    const auto x = sample_small_plain_batch(ctx, params.mW, 0x7C62u, plainSampleBits);

    std::vector<RnsPoly> dHat;
    dHat.reserve(static_cast<std::size_t>(wDoublePrime) * tauHi * rho);
    for (std::uint32_t chunkIdx = 0; chunkIdx < wDoublePrime; ++chunkIdx)
    {
        const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
        const std::size_t end = std::min(start + static_cast<std::size_t>(muHi), x.size());

        std::vector<RnsPoly> chunk(x.begin() + start, x.begin() + end);
        while (chunk.size() < muHi)
        {
            chunk.push_back(zero_poly(ctx));
        }

        ShrinkExpandShrinkOutput shrink{};
        std::vector<RnsPoly> decomposed;
        LOGVOLE_REQUIRE_TRUE(shrinkExpandShrink(receiverOffline.mState.mShrinkExpandState, chunk, shrink));
        LOGVOLE_REQUIRE_TRUE(seedLabelGadgetDecomposeHiAndUnbundle(
            shrink.mDigest,
            params.mShrinkExpand.mGadgetLogBase,
            tauHi,
            params.mShrinkExpand.mRing,
            decomposed));
        LOGVOLE_REQUIRE_EQ(decomposed.size(), static_cast<std::size_t>(tauHi) * rho);

        for (auto& poly : decomposed)
        {
            dHat.push_back(std::move(poly));
        }
    }

    ReceiverOnlineInput childInput{};
    childInput.mX = dHat;

    SenderOnlineOutput childSenderOnline{};
    ReceiverOnlineOutput childReceiverOnline{};
    LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(
        *senderOffline.mState.mNextLevelState,
        *receiverOffline.mState.mNextLevelState,
        childInput,
        childSenderOnline,
        childReceiverOnline));

    const auto& nextParams = senderOffline.mState.mNextLevelState->mParams;
    std::vector<RnsPoly> nextRep;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
        senderOffline.mState.mNextLevelState->mSk1,
        nextParams.mGamma,
        nextParams.mShrinkExpand.mAlpha,
        tauHi,
        nextParams.mShrinkExpand.mRing,
        nextRep));

    const std::uint32_t nextWDoublePrime = (nextParams.mW + muHi - 1u) / muHi;
    std::vector<RnsPoly> sk1W;
    sk1W.reserve(nextParams.mW);
    for (std::uint32_t i = 0; i < nextWDoublePrime; ++i)
    {
        for (const auto& poly : nextRep)
        {
            if (sk1W.size() < nextParams.mW)
            {
                sk1W.push_back(poly);
            }
        }
    }

    std::vector<RnsPoly> actual;
    std::vector<RnsPoly> expected;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(ctx, childReceiverOnline.mTbm, childSenderOnline.mTbk, actual));
    LOGVOLE_REQUIRE_TRUE(compute_expected_s_mul_x(ctx, sk1W, dHat, expected));

    long double maxLog2 = 0.0L;
    LOGVOLE_EXPECT_TRUE(check_logvole_noise_tolerance(ctx, actual, expected, nextParams, maxLog2))
        << "max centered log2 residual " << static_cast<double>(maxLog2);
}

void LogVole_Core_RecursiveGadgetInputSubproblem(const oc::CLP&)
{
    run_recursive_gadget_subproblem_test(true);
}

void LogVole_Core_RejectsWidthsBelowRandomizedRootBlock(const oc::CLP&)
{
    const Params params = make_rejected_root_width_params();
    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
    const std::uint32_t rho =
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
    LOGVOLE_REQUIRE_LT(params.mW, muHi);

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, 1, 0x7D01u);

    SenderOfflineOutput senderOutput{};
    LOGVOLE_EXPECT_FALSE(prepare_sender_offline_for_test(senderInput, senderOutput));

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    OfflineMessage emptyMessage{};
    ReceiverOfflineOutput receiverOutput{};
    LOGVOLE_EXPECT_FALSE(finalizeReceiverOffline(receiverInput, emptyMessage, receiverOutput));
}

void LogVole_Core_TwoLevelCoprotoRelation(const oc::CLP&)
{
    Params params = make_recursive_params(2);
    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
    const std::uint32_t rho =
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7D51u);

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    LogVoleRingSender sender{};
    LogVoleRingReceiver receiver{};
    SenderState senderState{};
    ReceiverState receiverState{};

    auto offlineSockets = coproto::LocalAsyncSocket::makePair();
    oc::PRNG senderOfflinePrng(oc::block(0x7D53u, 0));
    auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.offline(senderInput, senderState, senderOfflinePrng, offlineSockets[0]),
        receiver.offline(receiverInput, receiverState, offlineSockets[1])));
    std::get<0>(offlineResult).result();
    std::get<1>(offlineResult).result();

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits);
    ReceiverOnlineInput receiverOnlineInput{};
    receiverOnlineInput.mSid = 0x7D60u;
    receiverOnlineInput.mX = sample_small_plain_batch(ctx, params.mW, 0x7D62u, plainSampleBits);

    SenderOnlineOutput senderOnline{};
    ReceiverOnlineOutput receiverOnline{};
    SenderOnlineOptions senderOptions{};
    senderOptions.mSid = receiverOnlineInput.mSid;

    auto onlineSockets = coproto::LocalAsyncSocket::makePair();
    const auto senderSentBefore = onlineSockets[0].bytesSent();
    const auto senderReceivedBefore = onlineSockets[0].bytesReceived();
    const auto receiverSentBefore = onlineSockets[1].bytesSent();
    const auto receiverReceivedBefore = onlineSockets[1].bytesReceived();
    oc::PRNG senderOnlinePrng(oc::block(0x7D54u, 0));
    oc::PRNG receiverOnlinePrng(oc::block(0x7D55u, 0));
    auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.online(senderState, senderOptions, senderOnline, senderOnlinePrng, onlineSockets[0]),
        receiver.online(receiverState, receiverOnlineInput, receiverOnline, receiverOnlinePrng, onlineSockets[1])));
    std::get<0>(onlineResult).result();
    std::get<1>(onlineResult).result();
    const auto senderBytesSent = onlineSockets[0].bytesSent() - senderSentBefore;
    const auto senderBytesReceived = onlineSockets[0].bytesReceived() - senderReceivedBefore;
    const auto receiverBytesSent = onlineSockets[1].bytesSent() - receiverSentBefore;
    const auto receiverBytesReceived = onlineSockets[1].bytesReceived() - receiverReceivedBefore;

    LOGVOLE_REQUIRE_EQ(senderOnline.mTbk.size(), params.mW);
    LOGVOLE_REQUIRE_EQ(receiverOnline.mTbm.size(), params.mW);
    LOGVOLE_REQUIRE_FALSE(senderOnline.mSeed.empty());
    LOGVOLE_EXPECT_TRUE(rangesEqual(senderOnline.mSeed, receiverOnline.mSeed));
    LOGVOLE_EXPECT_EQ(senderOnline.mComm.mBytesSent, receiverOnline.mComm.mBytesReceived);
    LOGVOLE_EXPECT_EQ(senderOnline.mComm.mBytesReceived, receiverOnline.mComm.mBytesSent);
    LOGVOLE_EXPECT_GT(senderOnline.mComm.mBytesSent, 0ull);
    LOGVOLE_EXPECT_GT(senderOnline.mComm.mBytesReceived, 0ull);
    LOGVOLE_EXPECT_GT(senderBytesSent, senderOnline.mComm.mBytesSent);
    LOGVOLE_EXPECT_GT(senderBytesReceived, senderOnline.mComm.mBytesReceived);
    LOGVOLE_EXPECT_GT(receiverBytesSent, receiverOnline.mComm.mBytesSent);
    LOGVOLE_EXPECT_GT(receiverBytesReceived, receiverOnline.mComm.mBytesReceived);
    LOGVOLE_EXPECT_LT(senderBytesSent - senderOnline.mComm.mBytesSent, 128ull);
    LOGVOLE_EXPECT_LT(senderBytesReceived - senderOnline.mComm.mBytesReceived, 128ull);
    LOGVOLE_EXPECT_LT(receiverBytesSent - receiverOnline.mComm.mBytesSent, 128ull);
    LOGVOLE_EXPECT_LT(receiverBytesReceived - receiverOnline.mComm.mBytesReceived, 128ull);

    const auto rootPolyBytes =
        static_cast<std::uint64_t>(params.mShrinkExpand.mRing.mPolyModulusDegree) *
        static_cast<std::uint64_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size()) *
        static_cast<std::uint64_t>(sizeof(std::uint64_t));
    const auto onlineBytesBound = rootPolyBytes * 3 + 4096;
    LOGVOLE_EXPECT_LT(senderOnline.mComm.mBytesSent, onlineBytesBound);
    LOGVOLE_EXPECT_LT(receiverOnline.mComm.mBytesSent, onlineBytesBound);

    std::vector<RnsPoly> sRep;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
        senderInput.mSk1,
        params.mGamma,
        params.mShrinkExpand.mAlpha,
        tauHi,
        params.mShrinkExpand.mRing,
        sRep));

    const std::uint32_t wDoublePrime = (params.mW + muHi - 1u) / muHi;
    std::vector<RnsPoly> sW;
    sW.reserve(params.mW);
    for (std::uint32_t chunkIdx = 0; chunkIdx < wDoublePrime; ++chunkIdx)
    {
        for (const auto& poly : sRep)
        {
            if (sW.size() < params.mW)
            {
                sW.push_back(poly);
            }
        }
    }

    std::vector<RnsPoly> actual;
    std::vector<RnsPoly> expected;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(ctx, receiverOnline.mTbm, senderOnline.mTbk, actual));
    LOGVOLE_REQUIRE_TRUE(compute_expected_s_mul_x(ctx, sW, receiverOnlineInput.mX, expected));

    long double maxLog2 = 0.0L;
    LOGVOLE_EXPECT_TRUE(check_logvole_noise_tolerance(ctx, actual, expected, params, maxLog2))
        << "max centered log2 residual " << static_cast<double>(maxLog2);
}

void LogVole_Core_TwoLevelCoprotoMultiThreadSkipTbkOutput(const oc::CLP&)
{
    Params params = make_recursive_params(2);
    params.mShrinkExpand.mNumWorkerThreads = 4;

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7D71u);

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    LogVoleRingSender sender{};
    LogVoleRingReceiver receiver{};
    SenderState senderState{};
    ReceiverState receiverState{};

    auto offlineSockets = coproto::LocalAsyncSocket::makePair();
    oc::PRNG senderOfflinePrng(oc::block(0x7D73u, 0));
    auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.offline(senderInput, senderState, senderOfflinePrng, offlineSockets[0]),
        receiver.offline(receiverInput, receiverState, offlineSockets[1])));
    std::get<0>(offlineResult).result();
    std::get<1>(offlineResult).result();

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits);
    ReceiverOnlineInput receiverOnlineInput{};
    receiverOnlineInput.mSid = 0x7D80u;
    receiverOnlineInput.mX = sample_small_plain_batch(ctx, params.mW, 0x7D82u, plainSampleBits);

    SenderOnlineOutput senderOnline{};
    ReceiverOnlineOutput receiverOnline{};
    SenderOnlineOptions options{};
    options.mSid = receiverOnlineInput.mSid;
    options.mSkipTbkOutput = true;

    auto onlineSockets = coproto::LocalAsyncSocket::makePair();
    oc::PRNG senderOnlinePrng(oc::block(0x7D74u, 0));
    oc::PRNG receiverOnlinePrng(oc::block(0x7D75u, 0));
    auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.online(senderState, options, senderOnline, senderOnlinePrng, onlineSockets[0]),
        receiver.online(receiverState, receiverOnlineInput, receiverOnline, receiverOnlinePrng, onlineSockets[1])));
    std::get<0>(onlineResult).result();
    std::get<1>(onlineResult).result();

    LOGVOLE_EXPECT_TRUE(senderOnline.mTbk.empty());
    LOGVOLE_REQUIRE_EQ(receiverOnline.mTbm.size(), params.mW);
    LOGVOLE_REQUIRE_FALSE(senderOnline.mSeed.empty());
    LOGVOLE_EXPECT_TRUE(rangesEqual(senderOnline.mSeed, receiverOnline.mSeed));
    LOGVOLE_REQUIRE_TRUE(senderState.mPrecomputedTbk != nullptr);
    LOGVOLE_REQUIRE_EQ(senderState.mPrecomputedTbk->size(), params.mW);
}

void LogVole_Core_GoldenSeedSearchAcceptsFeasibleParams(const oc::CLP&)
{
    auto params = make_golden_params();
    LOGVOLE_REQUIRE_TRUE(validateGoldenSeedSearch(params));

    params.mShrinkExpand.mMu += 1;
    LOGVOLE_REQUIRE_FALSE(validateGoldenSeedSearch(params));
}

void LogVole_Core_GoldenSeedRejectsMalformedCandidate(const oc::CLP&)
{
    const Params params = make_golden_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));
    LOGVOLE_REQUIRE_TRUE(validateGoldenSeedSearch(params));

    const std::size_t expectedCount =
        static_cast<std::size_t>((params.mW + params.mShrinkExpand.mMu - 1u) / params.mShrinkExpand.mMu) *
        static_cast<std::size_t>(params.mShrinkExpand.mMu);
    LOGVOLE_REQUIRE_TRUE(expectedCount > 0);

    std::vector<RnsPoly> wrongCount(expectedCount - 1);
    for (auto& poly : wrongCount)
    {
        resizeZero(poly.mCoeffs, ringPolyCoeffCount(params.mShrinkExpand.mRing));
    }
    bool candidateOk = true;
    LOGVOLE_EXPECT_FALSE(validateGoldenSeedCandidate(params, wrongCount, candidateOk));

    std::vector<RnsPoly> wrongShape(expectedCount);
    for (auto& poly : wrongShape)
    {
        resizeZero(poly.mCoeffs, ringPolyCoeffCount(params.mShrinkExpand.mRing));
    }
    wrongShape[0].mCoeffs.resize(wrongShape[0].mCoeffs.size() - 1);

    candidateOk = true;
    LOGVOLE_EXPECT_FALSE(validateGoldenSeedCandidate(params, wrongShape, candidateOk));
}

void LogVole_Core_GoldenSeedFindAndValidateCandidate(const oc::CLP&)
{
    const auto params = make_golden_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

    const auto sk2 = sample_batch(ctx, 1, 0x6006u);
    const auto digest = deriveUniformPolyFromNonce(ctx, 0x6007u, 0xD1CEu, 0);

    GoldenSeedSearchOutput found{};
    oc::PRNG prng(oc::block(0x6008u, 0));
    LOGVOLE_REQUIRE_TRUE(findGoldenSeed(params, sk2, digest, prng, found));
    LOGVOLE_EXPECT_EQ(found.mSeed.size(), std::size_t{ 16 });
    LOGVOLE_REQUIRE_EQ(found.mTbkPerSampledPoly.size(), params.mShrinkExpand.mMu);

    bool candidateOk = false;
    LOGVOLE_REQUIRE_TRUE(validateGoldenSeedCandidate(params, found.mTbkPerSampledPoly, candidateOk));
    LOGVOLE_EXPECT_TRUE(candidateOk);

    std::vector<RnsPoly> repeatCt2;
    LOGVOLE_REQUIRE_TRUE(seedLabelSampleCt2FromSeed(
        found.mSeed,
        params.mSessionId,
        digest,
        0,
        params.mShrinkExpand.mMu,
        params.mShrinkExpand.mRing,
        repeatCt2));
    LOGVOLE_REQUIRE_EQ(repeatCt2.size(), params.mShrinkExpand.mMu);

    std::vector<RnsPoly> publicANtt;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mShrinkExpand.mMu, publicANtt));
    RnsPoly sk2Ntt = sk2[0];
    LOGVOLE_REQUIRE_TRUE(forwardNtt(sk2Ntt, ctx));

    for (std::uint32_t row = 0; row < params.mShrinkExpand.mMu; ++row)
    {
        RnsPoly ask{};
        resizeZero(ask.mCoeffs, ringPolyCoeffCount(params.mShrinkExpand.mRing));
        LOGVOLE_REQUIRE_TRUE(dyadicMultiplyAddNttInplace(publicANtt[row], sk2Ntt, ask, ctx));
        LOGVOLE_REQUIRE_TRUE(inverseNtt(ask, ctx));

        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringSub(repeatCt2[row], ask, ctx, expected));
        expect_poly_equal(found.mTbkPerSampledPoly[row], expected);
    }
}
