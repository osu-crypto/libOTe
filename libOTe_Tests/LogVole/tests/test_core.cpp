#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe_Tests/LogVole_TestOptions.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "coproto/Socket/BufferingSocket.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "macoro/when_all.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{


    RingNttContext cpuReferenceContext(const RingNttContext& source)
    {
        auto options = source.mExecutionOptions;
        options.mUseGpu = false;
        RingNttContext result;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(source.mParams, result,
            std::make_shared<RingContextFactory>(options)));
        return result;
    }


#if defined(ENABLE_LOGVOLE_CUDA)
    // Observe only explicitly supplied resource owners. Weak baselines do not
    // keep a factory record warm or alter the lifetime being tested.
    class RetentionBaseline
    {
        using Stats = gpu::PublicUniformRetentionStats;
        struct Entry
        {
            std::weak_ptr<PublicPolynomialCache> mOwner;
            Stats mBefore;
        };
        std::vector<Entry> mEntries;
    public:
        void capture(const RingNttContext& ctx)
        {
            if (!ctx.mPublicCache) return;
            for (const auto& entry : mEntries)
                if (entry.mOwner.lock() == ctx.mPublicCache) return;
            mEntries.push_back({ctx.mPublicCache, gpu::publicUniformRetentionStats(ctx)});
        }
        template<typename State>
        void captureTree(const State& state)
        {
            for (auto* node = &state; node; node = node->mNextLevelState.get())
                if (const auto& owner = node->mShrinkExpandState.mRingFactoryOwner)
                    capture(*owner);
        }
        Stats delta(const RingNttContext& ctx) const
        {
            if (!ctx.mPublicCache) return {};
            auto result = gpu::publicUniformRetentionStats(ctx);
            for (const auto& entry : mEntries)
            {
                if (entry.mOwner.lock() != ctx.mPublicCache) continue;
                result.mCaptures -= entry.mBefore.mCaptures;
                result.mCopies -= entry.mBefore.mCopies;
                result.mCopiedBytes -= entry.mBefore.mCopiedBytes;
                result.mMisses -= entry.mBefore.mMisses;
                result.mHostMaterializations -= entry.mBefore.mHostMaterializations;
                result.mHostMaterializedBytes -= entry.mBefore.mHostMaterializedBytes;
                break;
            }
            return result;
        }
        template<typename State>
        Stats deltaTree(const State& state) const
        {
            Stats result{};
            std::vector<const PublicPolynomialCache*> seen;
            for (auto* node = &state; node; node = node->mNextLevelState.get())
            {
                const auto& owner = node->mShrinkExpandState.mRingFactoryOwner;
                if (!owner || !owner->mPublicCache) continue;
                const auto* cache = owner->mPublicCache.get();
                if (std::find(seen.begin(), seen.end(), cache) != seen.end()) continue;
                seen.push_back(cache);
                const auto change = delta(*owner);
                result.mCaptures += change.mCaptures;
                result.mCopies += change.mCopies;
                result.mCopiedBytes += change.mCopiedBytes;
                result.mMisses += change.mMisses;
                result.mHostMaterializations += change.mHostMaterializations;
                result.mHostMaterializedBytes += change.mHostMaterializedBytes;
            }
            return result;
        }
    };
#endif

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

    bool finalize_receiver_from_sender_wire(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandSenderState& sender,
        ShrinkExpandReceiverState& receiver)
    {
        const auto workers = input.mParams.mNumWorkerThreads;
        auto bytes = encodeShrinkExpandOfflineState(sender, workers);
        ShrinkExpandOfflineMessage message;
        return decode(bytes, message, workers) &&
            finalizeShrinkExpandReceiverOffline(input, std::move(message), receiver);
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
        RootDigestMessage& message,
        bool deferDPrimeHash = false)
    {
        oc::PRNG prng(oc::block(0x5400, 0x5401));
        return osuCrypto::LogVole::prepareRootDigestReceiver(
            state, x, prng, digestState, message, {}, 0, deferDPrimeHash);
    }

    bool prepare_root_response_sender_for_test(
        const SenderState& state,
        const RootDigestMessage& request,
        RootResponseMessage& response,
        bool deferPrecompute = false)
    {
        oc::PRNG prng(oc::block(0x5500, 0x5501));
        return tests_libOTe::logvole_test::prepareRootResponse(
            state, request, prng, response, nullptr, nullptr,
            deferPrecompute);
    }

    bool prepare_root_response_sender_owned_for_test(
        const SenderState& state,
        RootDigestMessage&& request,
        RootResponseMessage& response,
        bool deferPrecompute = false)
    {
        oc::PRNG prng(oc::block(0x5500, 0x5501));
        return tests_libOTe::logvole_test::prepareRootResponse(
            state, std::move(request), prng, response, nullptr, nullptr,
            deferPrecompute);
    }

    bool run_socket_online_for_test(
        SenderState& sender,
        ReceiverState& receiver,
        const ReceiverOnlineInput& input,
        oc::PRNG& senderPrng,
        oc::PRNG& receiverPrng,
        SenderOnlineOutput& senderOut,
        ReceiverOnlineOutput& receiverOut)
    {
        LogVoleRingSender senderProtocol;
        LogVoleRingReceiver receiverProtocol;
        SenderOnlineOptions senderOptions{};
        senderOptions.mSid = input.mSid;
        // Application-owned resources reused through all recursive levels.
        auto* root = &receiver;
        while (root->mNextLevelState) root = root->mNextLevelState.get();
        const auto& rootState = root->mShrinkExpandState;
        macoro::thread_pool executor;
        auto work = executor.make_work();
        std::array<LheDecryptBuffer, 3> lheBuffers, senderBuffers;
        std::array<LencEvalBuffer, 3> lencBuffers;
        if (!rootState.mRingFactoryOwner || !rootState.mRingFactoryOwner->mExecutionOptions.mUseGpu)
        {
            executor.create_threads(1);
            for (auto& buffer : lheBuffers)
                buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(rootState.mParams.mRing));
            for (auto& buffer : senderBuffers)
                buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(rootState.mParams.mRing));
            auto terms = std::size_t{2} * root->mRootLacctLeft.mLevels * (rootState.mParams.mTau + 1);
            for (auto* level = &receiver; level; level = level->mNextLevelState.get())
                terms = std::max(terms, std::size_t{2} * level->mShrinkExpandState.hostLacct().mLevels *
                    (level->mShrinkExpandState.mParams.mTau + 1));
            for (auto& buffer : lencBuffers)
            {
                buffer.mCiphertexts.reserve(terms);
                buffer.mNodes.reserve(terms);
            }
        }
        auto sockets = coproto::LocalAsyncSocket::makePair();
        try
        {
            auto result = macoro::sync_wait(macoro::when_all_ready(
                senderProtocol.online(executor, senderBuffers, sender, senderOptions, senderOut, senderPrng, sockets[0]),
                receiverProtocol.online(executor, lheBuffers, lencBuffers, receiver, input, receiverOut, receiverPrng, sockets[1])));
            std::get<0>(result).result();
            std::get<1>(result).result();
            {
                const auto cache = sender.mPrecomputedTbk;
                const auto seed = sender.mGoldenSeed;
                oc::PRNG cachedPrng(oc::block(0x9911, 0x9922));
                oc::PRNG untouchedPrng(oc::block(0x9911, 0x9922));
                auto cached = senderPrecompute(executor, senderBuffers, sender, cachedPrng);
                LOGVOLE_REQUIRE_TRUE(sender.mPrecomputedTbk == cache);
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(std::move(cached)));
                LOGVOLE_REQUIRE_TRUE(sender.mPrecomputedTbk == cache);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(sender.mGoldenSeed, seed));
                LOGVOLE_REQUIRE_TRUE(cachedPrng.get<oc::block>() == untouchedPrng.get<oc::block>());

                // A malformed root key must fail without publishing a new cache
                // or changing the supplied seed. The lazy operation owns no work
                // until it is awaited and can be moved before starting.
                auto* terminal = &sender;
                while (terminal->mNextLevelState) terminal = terminal->mNextLevelState.get();
                SenderState invalid;
                invalid.mParams = terminal->mParams;
                invalid.mShrinkExpandState.mParams = terminal->mShrinkExpandState.mParams;
                invalid.mShrinkExpandState.mRingFactoryOwner = terminal->mShrinkExpandState.mRingFactoryOwner;
                invalid.mGoldenSeed = terminal->mGoldenSeed;
                invalid.mRootDPrimeRt = terminal->mRootDPrimeRt;
                invalid.mRootDPrimeHash = terminal->mRootDPrimeHash;
                invalid.mRootDPrimeHashValid = terminal->mRootDPrimeHashValid;
                invalid.mRootKPrimeRt = std::make_shared<RnsPoly>();
                const auto oldSeed = invalid.mGoldenSeed;
                auto failed = senderPrecompute(executor, senderBuffers, invalid, cachedPrng);
                LOGVOLE_REQUIRE_TRUE(!invalid.mPrecomputedTbk);
                auto moved = std::move(failed);
                LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(std::move(moved)));
                LOGVOLE_REQUIRE_TRUE(!invalid.mPrecomputedTbk && rangesEqual(invalid.mGoldenSeed, oldSeed));
            }
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    template<class State>
    void useCpuReference(State& state, ProtocolCacheRole role)
    {
        auto options = state.mShrinkExpandState.mRingFactoryOwner
            ? state.mShrinkExpandState.mRingFactoryOwner->mExecutionOptions : osuCrypto::LogVoleExecutionOptions{};
        options.mUseGpu = false;
        for (auto* level = &state; level; level = level->mNextLevelState.get())
            *level = tests_libOTe::logvole_test::withAdvancedOptions(std::move(*level), options, role);
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
        return run_socket_online_for_test(
            sender, receiver, input, senderPrng, receiverPrng, senderOut, receiverOut);
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

    Params make_alpha4_root_params(std::uint32_t width)
    {
        Params params = make_recursive_params(1u);
        params.mShrinkExpand.mAlpha = 4u;
        params.mShrinkExpand.mMu =
            params.mShrinkExpand.mAlpha *
            params.mShrinkExpand.mTau *
            static_cast<std::uint32_t>(
                params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mW = width;
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

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b,
        const char* stage = "unspecified", std::size_t batchIndex = 0)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i])
                << stage << " batch idx " << batchIndex
                << " coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b,
        const char* stage = "unspecified")
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i], stage, i);
        }
    }

    std::vector<std::uint64_t> delta_per_limb(const RingNttContext& ctx)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.size() != ringModulusCount(ctx)) return {};
        std::vector<std::uint64_t> out(moduli.size(), 1);
        for (std::size_t j = 0; j < moduli.size(); ++j)
        {
            std::uint64_t delta = 1;
            for (std::size_t k = 0; k < moduli.size(); ++k)
            {
                if (k != j)
                {
                    delta = seal::util::multiply_uint_mod(delta, moduli[k].value(), moduli[j]);
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

        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.size() != ringModulusCount(ctx)) return false;
        out = input;
        const std::uint64_t shift = static_cast<std::uint64_t>(gadgetLogBase) * power;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
        {
            const auto& modulus = moduli[modIdx];
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
        const std::size_t rho = ringModulusCount(ctx);
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
                out.mCoeffs[modIdx * n + coeffIdx] = value % ringModulusValue(ctx, modIdx);
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
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        auto contextData = hostContext->key_context_data();
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

void LogVole_Core_GpuSetupDeltaChain(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0)) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!cmd.getOr("gpu", 0)) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    tests_libOTe::logvole_test::ScopedOptionValue chain(setupOptions.mDeltaChainDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue deviceDelta(setupOptions.mDeltaDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue deviceLenc(setupOptions.mLencDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue devicePadding(setupOptions.mLencDevicePadding, true);

    for (auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
    {
        CivoleParams civole{};
        LOGVOLE_REQUIRE_TRUE(makeCivoleParams(setting, civole, 2u));
        auto params = civole.mLogVole;
        LOGVOLE_REQUIRE_TRUE(params.mShrinkExpand.mTau >= 2u);
        const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
        const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi *
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mW = muHi;
        params.mTotalLabelCount = (oc::u64{1} << 18) + 3u;
        const std::size_t expectedRootBytes =
            setting == CivoleSetting::GoldenSeed ? 10'223'704u : 95'420'512u;
        LOGVOLE_REQUIRE_EQ(forecastRootOfflineWireSize(params, false),
            expectedRootBytes);
        auto recursiveForecastParams = params;
        recursiveForecastParams.mW = 4u * muHi;
        LOGVOLE_REQUIRE_EQ(forecastRootOfflineWireSize(
            recursiveForecastParams, false), expectedRootBytes);
        auto productionForecastParams = params;
        productionForecastParams.mW = 1u << 25;
        LOGVOLE_REQUIRE_EQ(forecastRootOfflineWireSize(
            productionForecastParams, false), expectedRootBytes);
        const oc::u64 runId = allocateProtocolCacheRunId();
        ScopedProtocolCacheScope ownerScope(ProtocolCacheRole::Sender, runId);
        ZpCrtContext zp{};
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mShrinkExpand.mRing,
            params.mShrinkExpand.mPlaintextModulusBits, zp,
            std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(advanced))));
        LOGVOLE_REQUIRE_TRUE(zp.mGpuLightweight);
        const oc::u64 scalar = zp.mPlaintextModulus - 1u;
        auto delta = gpu::wrapSetupDeltaResident(zp, scalar, {}, nullptr);
        LOGVOLE_REQUIRE_TRUE(delta != nullptr);
        LOGVOLE_REQUIRE_EQ(delta->count(), 1u);
        LOGVOLE_REQUIRE_TRUE(gpu::setupDeltaBatchMatches(
            zp.mRing, *delta, 1u, runId));
        RnsPoly hostDelta{};
        {
            ZpCrtContext cpuZp;
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mShrinkExpand.mRing,
                params.mShrinkExpand.mPlaintextModulusBits, cpuZp));
            LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(cpuZp, scalar, true, 2u, hostDelta));
        }
        std::vector<RnsPoly> exactDelta;
        LOGVOLE_REQUIRE_TRUE(gpu::download(*delta, exactDelta, readbackExecution.readbackStream(), 1u));
        LOGVOLE_REQUIRE_EQ(exactDelta.size(), 1u);
        expect_poly_equal(exactDelta[0], hostDelta);

        auto rep = gpu::seedLabelRepResident(zp.mRing, *delta, 1u,
            params.mShrinkExpand.mAlpha, tauHi);
        LOGVOLE_REQUIRE_TRUE(rep != nullptr);
        const std::size_t repCount = static_cast<std::size_t>(
            params.mShrinkExpand.mAlpha) * tauHi * ringModulusCount(zp.mRing);
        LOGVOLE_REQUIRE_TRUE(gpu::setupSeedLabelRepBatchMatches(
            zp.mRing, *rep, repCount, runId));
        std::vector<RnsPoly> expectedRep, actualRep;
        LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
            std::vector<RnsPoly>{hostDelta}, 1u,
            params.mShrinkExpand.mAlpha, tauHi,
            params.mShrinkExpand.mRing, expectedRep));
        LOGVOLE_REQUIRE_TRUE(gpu::download(*rep, actualRep, readbackExecution.readbackStream(), repCount));
        expect_batch_equal(expectedRep, actualRep, "CI delta device repetition");

        {
            ScopedProtocolCacheScope wrongRole(ProtocolCacheRole::Receiver, runId);
            LOGVOLE_REQUIRE_FALSE(gpu::setupDeltaBatchMatches(
                zp.mRing, *delta, 1u, runId));
            LOGVOLE_REQUIRE_FALSE(gpu::setupSeedLabelRepBatchMatches(
                zp.mRing, *rep, repCount, runId));
            LOGVOLE_REQUIRE_TRUE(gpu::seedLabelRepResident(zp.mRing,
                *delta, 1u, params.mShrinkExpand.mAlpha, tauHi) == nullptr);
        }
        {
            ScopedProtocolCacheScope wrongRun(ProtocolCacheRole::Sender, runId + 1u);
            LOGVOLE_REQUIRE_FALSE(gpu::setupDeltaBatchMatches(
                zp.mRing, *delta, 1u, runId));
            LOGVOLE_REQUIRE_FALSE(gpu::setupSeedLabelRepBatchMatches(
                zp.mRing, *rep, repCount, runId));
        }
        RingNttContext reordered = zp.mRing;
        LOGVOLE_REQUIRE_TRUE(reordered.mRawModuli != nullptr);
        auto reorderedModuli =
            std::make_shared<RingModulusMetadata>(*reordered.mRawModuli);
        LOGVOLE_REQUIRE_TRUE(reorderedModuli->mValues.size() >= 2u);
        std::swap(reorderedModuli->mValues[0], reorderedModuli->mValues[1]);
        reordered.mRawModuli = std::move(reorderedModuli);
        LOGVOLE_REQUIRE_FALSE(gpu::setupDeltaBatchMatches(
            reordered, *delta, 1u, runId));
        LOGVOLE_REQUIRE_FALSE(gpu::setupSeedLabelRepBatchMatches(
            reordered, *rep, repCount, runId));
        LOGVOLE_REQUIRE_FALSE(gpu::setupDeltaBatchMatches(
            zp.mRing, *delta, 2u, runId));
        {
            tests_libOTe::logvole_test::ScopedOptionValue forced(zp.mRing.mExecutionOptions.mAdvanced.mProtocol.mFailures.mDeltaDevice, true);
            LOGVOLE_REQUIRE_TRUE(gpu::wrapSetupDeltaResident(
                zp, scalar, {}, nullptr) == nullptr);
        }

        SenderOfflineInput hostInput{};
        hostInput.mParams = params;
        hostInput.mSk1 = {hostDelta};
        SenderOfflineInput selectedInput{};
        selectedInput.mParams = params;
        selectedInput.mUseGpuResidentInternalState = true;
        selectedInput.mWrappedDeltaDevice = delta;
        selectedInput.mWrappedDeltaHostFallback =
            [zp, scalar](RnsPoly& out) {
                return wrapZpConstantCrt(zp, scalar, true, 2u, out);
            };
        const oc::block seed(0x534554555044454cULL,
            setting == CivoleSetting::GoldenSeed ? 1u : 2u);
        struct Snapshot
        {
            SenderState mState;
            RootWirePinOverlapEvidence mRootWirePin;
            std::vector<oc::u8> mWire;
            std::array<oc::u64, 16> mNextRandom{};
            RootWireCudaAllocEvidence mRootCudaWire;
        };
        const auto runOffline = [&](const SenderOfflineInput& in,
            oc::u64 scopeRun, bool useGpu) {
            ScopedProtocolCacheScope scope(ProtocolCacheRole::Sender, scopeRun);
            auto selectedOptions = advanced;
            selectedOptions.mUseGpu = useGpu;
            oc::PRNG prng(seed, 3);
            coproto::BufferingSocket socket;
            LogVoleRingSender sender;
            Snapshot out;
            auto configured = tests_libOTe::logvole_test::withAdvancedOptions(
                in, selectedOptions, ProtocolCacheRole::Sender);
            macoro::sync_wait(sender.offline(configured, out.mState, prng, socket, out.mRootWirePin));
            out.mRootCudaWire = rootWireCudaAllocEvidenceSnapshot();
            macoro::sync_wait(socket.flush());
            auto bytes = socket.getOutbound();
            LOGVOLE_REQUIRE_TRUE(bytes && !bytes->empty());
            out.mWire.assign(bytes->begin(), bytes->end());
            prng.get(out.mNextRandom.data(), out.mNextRandom.size());
            return out;
        };
        const auto baselineRunId = allocateProtocolCacheRunId();
        const auto baseline = runOffline(tests_libOTe::logvole_test::withSetupOptions(hostInput, setupOptions),
            baselineRunId, false);
        auto selected = [&] {
            auto pinInput = selectedInput;
            pinInput.mParams.mShrinkExpand.mTransport.mEncoding.mRootWirePinOverlap = true;
            return runOffline(tests_libOTe::logvole_test::withSetupOptions(pinInput, setupOptions), runId, true);
        }();
        LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.mWire, selected.mWire));
        LOGVOLE_REQUIRE_TRUE(baseline.mNextRandom == selected.mNextRandom);
        LOGVOLE_REQUIRE_TRUE(selected.mRootWirePin.mRequested);
        LOGVOLE_REQUIRE_EQ(selected.mRootWirePin.mSenderRunId, runId);
        LOGVOLE_REQUIRE_TRUE(selected.mRootWirePin.mWireBytes >=
            (std::size_t{1} << 20));
        if (selected.mRootWirePin.mLaunched)
            LOGVOLE_REQUIRE_TRUE(selected.mRootWirePin.mPinEndNs >=
                selected.mRootWirePin.mPinBeginNs);
        // A later sender cannot overwrite the earlier sender's diagnostics.
        LOGVOLE_REQUIRE_FALSE(baseline.mRootWirePin.mRequested);
        LOGVOLE_REQUIRE_FALSE(baseline.mRootWirePin.mSelected);
        LOGVOLE_REQUIRE_EQ(baseline.mRootWirePin.mSenderRunId, baselineRunId);
        if (cmd.getOr("pin_result_only", 0) != 0)
        {
            // A failed new attempt must clear the previous attempt's diagnostics.
            SenderOfflineInput invalid;
            invalid.mSenderOwnerRunId = allocateProtocolCacheRunId();
            oc::PRNG retryPrng(seed, 3);
            coproto::BufferingSocket retrySocket;
            LogVoleRingSender sender;
            bool rejected = false;
            try { macoro::sync_wait(sender.offline(invalid, selected.mState, retryPrng, retrySocket, selected.mRootWirePin)); }
            catch (const std::runtime_error&) { rejected = true; }
            LOGVOLE_REQUIRE_TRUE(rejected);
            LOGVOLE_REQUIRE_EQ(selected.mRootWirePin.mSenderRunId, invalid.mSenderOwnerRunId);
            LOGVOLE_REQUIRE_FALSE(selected.mRootWirePin.mRequested);
            LOGVOLE_REQUIRE_FALSE(selected.mRootWirePin.mSelected);
            LOGVOLE_REQUIRE_EQ(selected.mRootWirePin.mPinBeginNs, 0u);
            LOGVOLE_REQUIRE_EQ(selected.mRootWirePin.mWireBytes, 0u);
            LOGVOLE_REQUIRE_FALSE(baseline.mRootWirePin.mSelected);
            return;
        }
        LOGVOLE_REQUIRE_TRUE(selected.mRootWirePin.mEligible);
        LOGVOLE_REQUIRE_TRUE(selected.mRootWirePin.mPinSucceeded);
        LOGVOLE_REQUIRE_TRUE(selected.mRootWirePin.mSelected);
        const bool earlyCudaWire = cmd.getOr("root_cuda_wire_early", 0) != 0;
        if (cmd.getOr("root_cuda_wire", 0) != 0 || earlyCudaWire)
        {
            const oc::u64 cudaRunId = allocateProtocolCacheRunId();
            auto cudaInput = selectedInput;
            {
                ScopedProtocolCacheScope freshScope(
                    ProtocolCacheRole::Sender, cudaRunId);
                cudaInput.mWrappedDeltaDevice =
                    gpu::wrapSetupDeltaResident(zp, scalar, {}, nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(cudaInput.mWrappedDeltaDevice != nullptr);
            cudaInput.mSenderOwnerRunId = cudaRunId;
            auto cudaActual = [&] {
                auto& encoding = cudaInput.mParams.mShrinkExpand.mTransport.mEncoding;
                encoding.mRootWireCudaAlloc = true;
                encoding.mRootWirePinOverlap = false;
                encoding.mRootWireCudaAllocEarly = earlyCudaWire;
                return runOffline(tests_libOTe::logvole_test::withSetupOptions(cudaInput, setupOptions), cudaRunId, true);
            }();
            LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.mWire,
                cudaActual.mWire));
            LOGVOLE_REQUIRE_TRUE(baseline.mNextRandom ==
                cudaActual.mNextRandom);
            LOGVOLE_REQUIRE_EQ(cudaActual.mRootCudaWire.mSenderRunId,
                cudaRunId);
            LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mRequested);
            LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mEligible);
            LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mSelected);
            LOGVOLE_REQUIRE_FALSE(cudaActual.mRootCudaWire.mDeclined);
            LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mDirectDownloadCalls > 0);
            LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mDirectDownloadBytes > 0);
            LOGVOLE_REQUIRE_EQ(cudaActual.mRootCudaWire.mDirectDownloadCalls,
                cudaActual.mRootCudaWire.mExpectedDirectDownloadCalls);
            LOGVOLE_REQUIRE_EQ(cudaActual.mRootCudaWire.mDirectDownloadBytes,
                cudaActual.mRootCudaWire.mExpectedDirectDownloadBytes);
            LOGVOLE_REQUIRE_FALSE(cudaActual.mRootWirePin.mSelected);
            LOGVOLE_REQUIRE_EQ(cudaActual.mRootCudaWire.mWireBytes,
                expectedRootBytes);
            LOGVOLE_REQUIRE_EQ(cudaActual.mRootCudaWire.mEarlyRequested,
                earlyCudaWire);
            if (earlyCudaWire)
            {
                LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mEarlyEligible);
                LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mEarlyLaunched);
                LOGVOLE_REQUIRE_TRUE(cudaActual.mRootCudaWire.mEarlyAdopted);
                LOGVOLE_REQUIRE_EQ(
                    cudaActual.mRootCudaWire.mEarlyForecastBytes,
                    expectedRootBytes);
                LOGVOLE_REQUIRE_TRUE(
                    cudaActual.mRootCudaWire.mAllocationEndNs >=
                    cudaActual.mRootCudaWire.mAllocationBeginNs);
            }
        }
        expect_batch_equal(baseline.mState.mSk1, selected.mState.mSk1, "CI delta public snapshot");
        // The top HE secret is distinct from mSk1's wrapped CI delta. It was
        // sampled once from the same parent SEAL row draws and stayed private
        // on the sender device until Ct1/Root completed.
        const auto& topSecret = selected.mState.mShrinkExpandState;
        LOGVOLE_REQUIRE_TRUE(topSecret.mTopSk1Device != nullptr);
        LOGVOLE_REQUIRE_TRUE(topSecret.mLazyTopSk1 != nullptr);
        LOGVOLE_REQUIRE_EQ(topSecret.mTopSk1OwnerRunId, runId);
        LOGVOLE_REQUIRE_TRUE(topSecret.mSk1.empty());
        expect_batch_equal(baseline.mState.mShrinkExpandState.mSk1,
            topSecret.hostSk1(), "top HE secret seed replay");
        LOGVOLE_REQUIRE_TRUE(gpu::topSecretUniformBatchMatches(zp.mRing,
            *topSecret.mTopSk1Device, tauHi, runId));
        LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(zp.mRing,
            *topSecret.mTopSk1Device, tauHi, runId));
        auto ordinaryUpload = gpu::upload(zp.mRing,
            baseline.mState.mShrinkExpandState.mSk1);
        LOGVOLE_REQUIRE_TRUE(ordinaryUpload != nullptr);
        LOGVOLE_REQUIRE_FALSE(gpu::topSecretUniformBatchMatches(zp.mRing,
            *ordinaryUpload, tauHi, runId));
        // Gamma one repeats the complete polynomial across all limbs;
        // gamma=tau>1 selects one limb per row. Both are protocol shapes.
        for (const std::uint32_t width : {1u, 2u})
        {
            std::shared_ptr<const gpu::DeviceBatch> privateKey;
            std::shared_ptr<const LazyRootSecretHostState> privateHost;
            if (width == tauHi)
            {
                privateKey = topSecret.mTopSk1Device;
                privateHost = topSecret.mLazyTopSk1;
            }
            else
            {
                oc::PRNG privatePrng(oc::block(0xA57A11u, width), 3);
                std::vector<RnsPoly> declined{};
                std::shared_ptr<gpu::DeviceBatch> sampledKey;
                LOGVOLE_REQUIRE_TRUE(sampleTopSecretUniformBatch(zp.mRing,
                    width, privatePrng, declined, sampledKey, privateHost));
                privateKey = std::move(sampledKey);
                LOGVOLE_REQUIRE_TRUE(declined.empty() && privateKey && privateHost);
            }
            auto privateRep = gpu::topSecretSeedLabelRepResident(zp.mRing,
                *privateKey, params.mShrinkExpand.mAlpha, width);
            LOGVOLE_REQUIRE_TRUE(privateRep != nullptr);
            const std::size_t privateRows = static_cast<std::size_t>(
                params.mShrinkExpand.mAlpha) * width * ringModulusCount(zp.mRing);
            LOGVOLE_REQUIRE_TRUE(gpu::setupSeedLabelRepBatchMatches(zp.mRing,
                *privateRep, privateRows, runId));
            std::vector<RnsPoly> hostRep, deviceRep;
            {
                LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
                    privateHost->hostCoefficients(), width,
                    params.mShrinkExpand.mAlpha, width,
                    params.mShrinkExpand.mRing, hostRep));
            }
            LOGVOLE_REQUIRE_TRUE(gpu::download(*privateRep,
                deviceRep, readbackExecution.readbackStream(), privateRows));
            expect_batch_equal(hostRep, deviceRep, width == 1u
                ? "top HE gamma-one full-poly repetition"
                : "top HE multi-digit selected-limb repetition");
        }
        auto rootReplica = gpu::rootHiReplicateResident(zp.mRing,
            *topSecret.mTopSk1Device, tauHi);
        LOGVOLE_REQUIRE_TRUE(rootReplica != nullptr);
        const std::size_t rootRows = static_cast<std::size_t>(tauHi) *
            ringModulusCount(zp.mRing);
        LOGVOLE_REQUIRE_TRUE(gpu::rootHiRepBatchMatches(zp.mRing,
            *rootReplica, rootRows, runId));
        LOGVOLE_REQUIRE_FALSE(gpu::setupSeedLabelRepBatchMatches(zp.mRing,
            *rootReplica, rootRows, runId));
        std::vector<RnsPoly> expectedRoot, actualRoot;
        LOGVOLE_REQUIRE_TRUE(replicateRootHiKeyByLimb(topSecret.hostSk1(),
            tauHi, params.mShrinkExpand.mRing, expectedRoot));
        LOGVOLE_REQUIRE_TRUE(gpu::download(*rootReplica, actualRoot, readbackExecution.readbackStream(), rootRows));
        expect_batch_equal(expectedRoot, actualRoot, "Root high-key whole-poly D2D replication");
        {
            ScopedProtocolCacheScope wrongRole(ProtocolCacheRole::Receiver, runId);
            LOGVOLE_REQUIRE_FALSE(gpu::topSecretUniformBatchMatches(zp.mRing,
                *topSecret.mTopSk1Device, tauHi, runId));
            LOGVOLE_REQUIRE_FALSE(gpu::rootHiRepBatchMatches(zp.mRing,
                *rootReplica, rootRows, runId));
        }
        {
            ScopedProtocolCacheScope wrongRun(ProtocolCacheRole::Sender, runId + 1u);
            LOGVOLE_REQUIRE_FALSE(gpu::topSecretUniformBatchMatches(zp.mRing,
                *topSecret.mTopSk1Device, tauHi, runId));
            LOGVOLE_REQUIRE_FALSE(gpu::rootHiRepBatchMatches(zp.mRing,
                *rootReplica, rootRows, runId));
        }
        LOGVOLE_REQUIRE_FALSE(gpu::topSecretUniformBatchMatches(reordered,
            *topSecret.mTopSk1Device, tauHi, runId));
        LOGVOLE_REQUIRE_FALSE(gpu::rootHiRepBatchMatches(reordered,
            *rootReplica, rootRows, runId));
        LOGVOLE_REQUIRE_FALSE(gpu::topSecretUniformBatchMatches(zp.mRing,
            *topSecret.mTopSk1Device, tauHi + 1u, runId));
        auto detachedTop = topSecret;
        materializeShrinkExpandHostState(detachedTop);
        LOGVOLE_REQUIRE_TRUE(detachedTop.mTopSk1Device == nullptr);
        expect_batch_equal(topSecret.hostSk1(), detachedTop.mSk1);
        detachedTop.mSk1[0].mCoeffs[0] ^= 1u;
        expect_batch_equal(baseline.mState.mShrinkExpandState.mSk1,
            topSecret.hostSk1());
        LOGVOLE_REQUIRE_TRUE(selected.mState.mShrinkExpandState.mSk1.empty());
        LOGVOLE_REQUIRE_TRUE(selected.mState.mShrinkExpandState.mLazyS != nullptr);
        LOGVOLE_REQUIRE_TRUE(selected.mState.mShrinkExpandState.mS.empty());
        expect_batch_equal(expectedRep,
            selected.mState.mShrinkExpandState.hostS(), "CI delta selected seed-label host view");
        auto detached = selected.mState.mShrinkExpandState;
        materializeShrinkExpandHostState(detached);
        expect_batch_equal(expectedRep, detached.mS);
        detached.mS[0].mCoeffs[0] ^= 1u;
        expect_batch_equal(expectedRep,
            selected.mState.mShrinkExpandState.hostS());

        {
            tests_libOTe::logvole_test::ScopedOptionValue forced(advanced.mAdvanced.mProtocol.mFailures.mLencDevice, true);
            auto declined = runOffline(tests_libOTe::logvole_test::withSetupOptions(selectedInput, setupOptions), runId, true);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.mWire, declined.mWire));
            LOGVOLE_REQUIRE_TRUE(baseline.mNextRandom == declined.mNextRandom);
        }
        {
            tests_libOTe::logvole_test::ScopedOptionValue forced(advanced.mAdvanced.mProtocol.mFailures.mDeltaChain, true);
            auto declined = runOffline(tests_libOTe::logvole_test::withSetupOptions(selectedInput, setupOptions), runId, true);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.mWire, declined.mWire));
            LOGVOLE_REQUIRE_TRUE(baseline.mNextRandom == declined.mNextRandom);
            LOGVOLE_REQUIRE_TRUE(declined.mState.mShrinkExpandState.mLazyS == nullptr);
        }
        {
            auto eagerInput = selectedInput;
            eagerInput.mParams.mShrinkExpand.mGpuSetup.mDirectWire = false;
            eagerInput.mParams.mShrinkExpand.mTransport.mEncoding.mRootWireCudaAlloc = true;
            eagerInput.mParams.mShrinkExpand.mTransport.mEncoding.mRootWireCudaAllocEarly = true;
            auto eager = runOffline(tests_libOTe::logvole_test::withSetupOptions(eagerInput, setupOptions), runId, true);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.mWire, eager.mWire));
            LOGVOLE_REQUIRE_TRUE(baseline.mNextRandom == eager.mNextRandom);
            LOGVOLE_REQUIRE_TRUE(eager.mState.mShrinkExpandState.mLazyS == nullptr);
            LOGVOLE_REQUIRE_TRUE(!eager.mState.mShrinkExpandState.mS.empty());
            LOGVOLE_REQUIRE_TRUE(eager.mRootCudaWire.mEarlyRequested);
            LOGVOLE_REQUIRE_FALSE(eager.mRootCudaWire.mEarlyEligible);
            LOGVOLE_REQUIRE_FALSE(eager.mRootCudaWire.mEarlyLaunched);
            LOGVOLE_REQUIRE_FALSE(eager.mRootCudaWire.mEarlyAdopted);
            LOGVOLE_REQUIRE_FALSE(eager.mRootCudaWire.mSelected);
        }
        {
            oc::PRNG publicPrng(seed, 3);
            SenderOfflineOutput publicOutput{};
            LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(
                tests_libOTe::logvole_test::withSetupOptions(hostInput, setupOptions), publicPrng, publicOutput));
            LOGVOLE_REQUIRE_TRUE(publicOutput.mState.mShrinkExpandState.mLazyS == nullptr);
            LOGVOLE_REQUIRE_TRUE(!publicOutput.mState.mShrinkExpandState.mS.empty());
            LOGVOLE_REQUIRE_TRUE(publicOutput.mState.mShrinkExpandState.mTopSk1Device == nullptr);
            LOGVOLE_REQUIRE_TRUE(!publicOutput.mState.mShrinkExpandState.mSk1.empty());
        }

        // Three Core levels make the top key traverse two recursive child
        // fixed-key Ct1 and seed-label LENC operations before terminal Root.
        SenderOfflineInput recursiveHost = hostInput;
        recursiveHost.mParams.mW = 4u * muHi;
        SenderOfflineInput recursiveSelected = selectedInput;
        recursiveSelected.mParams.mW = recursiveHost.mParams.mW;
        const auto runRecursiveSelected = [&](bool topSecretDevice = true) {
            const oc::u64 freshRun = allocateProtocolCacheRunId();
            std::shared_ptr<gpu::DeviceBatch> freshDelta;
            {
                ScopedProtocolCacheScope capture(
                    ProtocolCacheRole::Sender, freshRun);
                freshDelta = gpu::wrapSetupDeltaResident(zp, scalar, {}, nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(freshDelta != nullptr);
            auto inputForRun = recursiveSelected;
            inputForRun.mWrappedDeltaDevice = freshDelta;
            inputForRun.mSenderOwnerRunId = freshRun;
            tests_libOTe::logvole_test::ScopedOptionValue topDevice(
                advanced.mAdvanced.mProtocol.mTopSecretDevice, topSecretDevice);
            return runOffline(tests_libOTe::logvole_test::withSetupOptions(inputForRun, setupOptions), freshRun, true);
        };
        const auto recursiveBaseline = runOffline(tests_libOTe::logvole_test::withSetupOptions(recursiveHost, setupOptions),
            allocateProtocolCacheRunId(), false);
        // This three-level tree follows the production recursive transport
        // shape: the terminal Root reuses its parent's shrink state, so the
        // pin worker must launch during an ancestor frame instead of Root's
        // own (absent) shrink frame.
        auto recursiveActual = [&] {
            recursiveSelected.mParams.mShrinkExpand.mTransport.mEncoding.mRootWirePinOverlap = true;
            return runRecursiveSelected();
        }();
        LOGVOLE_REQUIRE_TRUE(rangesEqual(recursiveBaseline.mWire,
            recursiveActual.mWire));
        LOGVOLE_REQUIRE_TRUE(recursiveBaseline.mNextRandom ==
            recursiveActual.mNextRandom);
        LOGVOLE_REQUIRE_TRUE(recursiveActual.mRootWirePin.mRequested);
        LOGVOLE_REQUIRE_TRUE(recursiveActual.mRootWirePin.mWireBytes >=
            (std::size_t{1} << 20));
        LOGVOLE_REQUIRE_TRUE(recursiveActual.mRootWirePin.mEligible);
        LOGVOLE_REQUIRE_TRUE(recursiveActual.mRootWirePin.mPinSucceeded);
        LOGVOLE_REQUIRE_TRUE(recursiveActual.mRootWirePin.mSelected);
        LOGVOLE_REQUIRE_TRUE(recursiveActual.mRootWirePin.mLaunched ||
            recursiveActual.mRootWirePin.mAlreadyPinned);
        const bool earlyCudaWireN25 =
            cmd.getOr("root_cuda_wire_early_n25", 0) != 0;
        const bool cudaWireN25 = cmd.getOr("root_cuda_wire_n25", 0) != 0 ||
            earlyCudaWireN25;
        if (cmd.getOr("root_pin_n25", 0) != 0 || cudaWireN25)
        {
            // Optional production-size sender-only check. It exercises the
            // same reused terminal Root with W and label budget both at 2^25,
            // and compares the complete framed offline bytes and PRNG state.
            SenderOfflineInput n25Host = hostInput;
            n25Host.mParams.mW = 1u << 25;
            n25Host.mParams.mTotalLabelCount = oc::u64{1} << 25;
            SenderOfflineInput n25Selected = selectedInput;
            n25Selected.mParams = n25Host.mParams;
            const auto n25Baseline = runOffline(tests_libOTe::logvole_test::withSetupOptions(n25Host, setupOptions),
                allocateProtocolCacheRunId(), false);
            const oc::u64 n25RunId = allocateProtocolCacheRunId();
            {
                ScopedProtocolCacheScope freshScope(
                    ProtocolCacheRole::Sender, n25RunId);
                n25Selected.mWrappedDeltaDevice =
                    gpu::wrapSetupDeltaResident(zp, scalar, {}, nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(n25Selected.mWrappedDeltaDevice != nullptr);
            n25Selected.mSenderOwnerRunId = n25RunId;
            auto n25Actual = [&] {
                auto& encoding = n25Selected.mParams.mShrinkExpand.mTransport.mEncoding;
                encoding.mRootWirePinOverlap = !cudaWireN25;
                encoding.mRootWireCudaAlloc = cudaWireN25;
                encoding.mRootWireCudaAllocEarly = earlyCudaWireN25;
                return runOffline(tests_libOTe::logvole_test::withSetupOptions(n25Selected, setupOptions), n25RunId, true);
            }();
            LOGVOLE_REQUIRE_TRUE(rangesEqual(n25Baseline.mWire,
                n25Actual.mWire));
            LOGVOLE_REQUIRE_TRUE(n25Baseline.mNextRandom ==
                n25Actual.mNextRandom);
            if (cudaWireN25)
            {
                LOGVOLE_REQUIRE_EQ(n25Actual.mRootCudaWire.mSenderRunId,
                    n25RunId);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootCudaWire.mRequested);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootCudaWire.mEligible);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootCudaWire.mSelected);
                LOGVOLE_REQUIRE_FALSE(n25Actual.mRootCudaWire.mDeclined);
                LOGVOLE_REQUIRE_TRUE(
                    n25Actual.mRootCudaWire.mDirectDownloadCalls > 0);
                LOGVOLE_REQUIRE_TRUE(
                    n25Actual.mRootCudaWire.mDirectDownloadBytes > 0);
                LOGVOLE_REQUIRE_EQ(
                    n25Actual.mRootCudaWire.mDirectDownloadCalls,
                    n25Actual.mRootCudaWire.mExpectedDirectDownloadCalls);
                LOGVOLE_REQUIRE_EQ(
                    n25Actual.mRootCudaWire.mDirectDownloadBytes,
                    n25Actual.mRootCudaWire.mExpectedDirectDownloadBytes);
                LOGVOLE_REQUIRE_FALSE(n25Actual.mRootWirePin.mSelected);
                LOGVOLE_REQUIRE_EQ(n25Actual.mRootCudaWire.mWireBytes,
                    expectedRootBytes);
                LOGVOLE_REQUIRE_EQ(n25Actual.mRootCudaWire.mEarlyRequested,
                    earlyCudaWireN25);
                if (earlyCudaWireN25)
                {
                    LOGVOLE_REQUIRE_TRUE(
                        n25Actual.mRootCudaWire.mEarlyEligible);
                    LOGVOLE_REQUIRE_TRUE(
                        n25Actual.mRootCudaWire.mEarlyLaunched);
                    LOGVOLE_REQUIRE_TRUE(
                        n25Actual.mRootCudaWire.mEarlyAdopted);
                    LOGVOLE_REQUIRE_EQ(
                        n25Actual.mRootCudaWire.mEarlyForecastBytes,
                        expectedRootBytes);
                }
            }
            else
            {
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootWirePin.mRequested);
                LOGVOLE_REQUIRE_EQ(n25Actual.mRootWirePin.mSenderRunId,
                    n25RunId);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootWirePin.mWireBytes >=
                    (std::size_t{1} << 20));
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootWirePin.mEligible);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootWirePin.mPinSucceeded);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootWirePin.mSelected);
                LOGVOLE_REQUIRE_TRUE(n25Actual.mRootWirePin.mLaunched ||
                    n25Actual.mRootWirePin.mAlreadyPinned);
            }
        }
        const SenderState* referenceLevel = &recursiveBaseline.mState;
        SenderState* actualLevel = &recursiveActual.mState;
        const auto privateOwner =
            actualLevel->mShrinkExpandState.mTopSk1Device.get();
        LOGVOLE_REQUIRE_TRUE(privateOwner != nullptr);
        unsigned levels = 0;
        while (referenceLevel && actualLevel)
        {
            const auto& seReference = referenceLevel->mShrinkExpandState;
            const auto& seActual = actualLevel->mShrinkExpandState;
            LOGVOLE_REQUIRE_TRUE(seActual.mTopSk1Device.get() == privateOwner);
            LOGVOLE_REQUIRE_TRUE(seActual.mSk1.empty());
            expect_batch_equal(seReference.mSk1, seActual.hostSk1(), "recursive top fixed-key seed replay");
            if (levels)
            {
                LOGVOLE_REQUIRE_TRUE(actualLevel->mSk1.empty());
                expect_batch_equal(referenceLevel->mSk1,
                    actualLevel->hostSk1(), "recursive child fixed-key host view");
                LOGVOLE_REQUIRE_TRUE(seActual.mLazyS != nullptr);
                LOGVOLE_REQUIRE_TRUE(seActual.mS.empty());
                expect_batch_equal(seReference.mS, seActual.hostS(), "recursive child device seed-label repetition");
            }
            expect_batch_equal(seReference.mCt1.mPolys,
                seActual.hostCt1().mPolys, "recursive top/child Ct1");
            referenceLevel = referenceLevel->mNextLevelState.get();
            actualLevel = actualLevel->mNextLevelState.get();
            ++levels;
        }
        LOGVOLE_REQUIRE_TRUE(!referenceLevel && !actualLevel);
        LOGVOLE_REQUIRE_EQ(levels, 3u);
        // A copied public sender input cannot turn a receiver or another
        // offline run into the owner of this private, fixed child key.
        ShrinkExpandSenderOfflineInput fixedKeyInput{};
        fixedKeyInput.mParams =
            recursiveActual.mState.mNextLevelState->mShrinkExpandState.mParams;
        fixedKeyInput.mS =
            recursiveBaseline.mState.mNextLevelState->mShrinkExpandState.mS;
        fixedKeyInput.mFixedSk1Device =
            recursiveActual.mState.mShrinkExpandState.mTopSk1Device;
        fixedKeyInput.mLazyFixedSk1 =
            recursiveActual.mState.mShrinkExpandState.mLazyTopSk1;
        fixedKeyInput.mFixedSk1OwnerRunId =
            recursiveActual.mState.mShrinkExpandState.mTopSk1OwnerRunId;
        fixedKeyInput.mDeferTopSk1Host = true;
        fixedKeyInput.mDeferHostCiphertexts = true;
        {
            ScopedProtocolCacheScope receiverImpostor(
                ProtocolCacheRole::Receiver,
                fixedKeyInput.mFixedSk1OwnerRunId);
            oc::PRNG impostorPrng(seed, 3);
            ShrinkExpandSenderState rejected{};
            LOGVOLE_REQUIRE_FALSE(prepareShrinkExpandSenderOffline(
                tests_libOTe::logvole_test::withSetupOptions(fixedKeyInput, setupOptions), impostorPrng, rejected));
        }
        {
            ScopedProtocolCacheScope wrongOfflineRun(
                ProtocolCacheRole::Sender,
                fixedKeyInput.mFixedSk1OwnerRunId + 1u);
            oc::PRNG impostorPrng(seed, 3);
            ShrinkExpandSenderState rejected{};
            LOGVOLE_REQUIRE_FALSE(prepareShrinkExpandSenderOffline(
                tests_libOTe::logvole_test::withSetupOptions(fixedKeyInput, setupOptions), impostorPrng, rejected));
        }
        {
            ScopedProtocolCacheScope wrongRole(
                ProtocolCacheRole::Receiver,
                recursiveActual.mState.mShrinkExpandState.mTopSk1OwnerRunId);
            LOGVOLE_REQUIRE_FALSE(materializeSenderTopSk1HostViews(
                recursiveActual.mState));
        }
        LOGVOLE_REQUIRE_TRUE(materializeSenderTopSk1HostViews(
            recursiveActual.mState));
        LOGVOLE_REQUIRE_TRUE(!recursiveActual.mState.mShrinkExpandState.mSk1.empty());
        auto* firstChild = recursiveActual.mState.mNextLevelState.get();
        LOGVOLE_REQUIRE_TRUE(firstChild != nullptr);
        LOGVOLE_REQUIRE_TRUE(!firstChild->mSk1.empty());
        const auto unmodifiedChild = firstChild->mSk1[0].mCoeffs[0];
        recursiveActual.mState.mShrinkExpandState.mSk1[0].mCoeffs[0] ^= 1u;
        LOGVOLE_REQUIRE_EQ(firstChild->mSk1[0].mCoeffs[0], unmodifiedChild);
        for (auto stage : {
                 &osuCrypto::LogVoleFailureOptions::mTopSk1Device,
                 &osuCrypto::LogVoleFailureOptions::mTopSk1Rep,
                 &osuCrypto::LogVoleFailureOptions::mTopSk1Lhe,
                 &osuCrypto::LogVoleFailureOptions::mTopSk1Root,
                 &osuCrypto::LogVoleFailureOptions::mTopSk1Lenc })
        {
            tests_libOTe::logvole_test::ScopedOptionValue forced(
                advanced.mAdvanced.mProtocol.mFailures.*stage, true);
            auto declined = runRecursiveSelected();
            LOGVOLE_REQUIRE_TRUE(rangesEqual(recursiveBaseline.mWire,
                declined.mWire));
            LOGVOLE_REQUIRE_TRUE(recursiveBaseline.mNextRandom ==
                declined.mNextRandom);
            if (stage == &osuCrypto::LogVoleFailureOptions::mTopSk1Device)
                LOGVOLE_REQUIRE_TRUE(declined.mState.mShrinkExpandState.mTopSk1Device == nullptr);
        }
        {
            tests_libOTe::logvole_test::ScopedOptionValue strict(setupOptions.mTopSecretConsumerStrict, true);
            tests_libOTe::logvole_test::ScopedOptionValue decline(advanced.mAdvanced.mProtocol.mFailures.mTopSk1Rep, true);
            bool rejected = false;
            try { (void)runRecursiveSelected(); }
            catch (const std::runtime_error&) { rejected = true; }
            LOGVOLE_REQUIRE_TRUE(rejected);
        }
        {
            auto eager = runRecursiveSelected(false);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(recursiveBaseline.mWire, eager.mWire));
            LOGVOLE_REQUIRE_TRUE(recursiveBaseline.mNextRandom == eager.mNextRandom);
            LOGVOLE_REQUIRE_TRUE(eager.mState.mShrinkExpandState.mTopSk1Device == nullptr);
            LOGVOLE_REQUIRE_TRUE(!eager.mState.mShrinkExpandState.mSk1.empty());
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
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
        for (bool dynamic : { false, true })
        {
            std::array<std::atomic<unsigned>, 16> seen{};
            LOGVOLE_REQUIRE_TRUE(detail::runParallelTasks(
                16,
                4,
                [&](std::size_t index) {
                    const auto scope = currentProtocolCacheScope();
                    if (scope.mRole == ProtocolCacheRole::Sender && scope.mRunId == runId &&
                        seen[index].fetch_add(1, std::memory_order_relaxed) == 0)
                    {
                        observed.fetch_add(1, std::memory_order_relaxed);
                        return true;
                    }
                    return false;
                }, dynamic));
        }
        LOGVOLE_REQUIRE_TRUE(!detail::runParallelTasks(100, 4,
            [](std::size_t index) { return index != 0; }, true));
    }

    LOGVOLE_EXPECT_EQ(observed.load(std::memory_order_relaxed), 32u);

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
    const auto& moduli = getRingHostModuli(ctx);
    const std::size_t rho = ringModulusCount(ctx);
    LOGVOLE_REQUIRE_EQ(moduli.size(), rho);
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(tauHi) * rho);

    const auto delta = delta_per_limb(ctx);
    const std::size_t n = params.mPolyModulusDegree;
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
                                  moduli[limb])
                            : 0u;
                    LOGVOLE_EXPECT_EQ(poly.mCoeffs[offset + c], expected);
                }
            }
        }
    }

}

void LogVole_Core_RepOfflineSenderInputGammaOneRepeats(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) != 0) LOGVOLE_REQUIRE_TRUE(gpu::enabled(advanced));
#else
    (void)cmd;
#endif
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx, std::make_shared<RingContextFactory>(advanced)));

    const auto s = sample_batch(ctx, 1, 0x3003u);
    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(s, 1, 2, 3, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(2 * 3 * params.mCoeffModulusBits.size()));
    for (const auto& poly : actual)
    {
        expect_poly_equal(poly, s[0]);
    }
#if defined(ENABLE_LOGVOLE_CUDA)
    if (gpu::enabled(advanced))
    {
        // Exercise the device entry point directly so fallback cannot conceal
        // a declined launch. Repetition must preserve even unreduced words.
        auto alias = s;
        alias[0].mCoeffs[0] = std::numeric_limits<std::uint64_t>::max();
        const auto expected = alias[0];
        LOGVOLE_REQUIRE_TRUE(gpu::seedLabelRepDevice(ctx, alias, 1, 2, 3, alias));
        LOGVOLE_REQUIRE_EQ(alias.size(), actual.size());
        for (const auto& poly : alias) expect_poly_equal(poly, expected);
        const auto preserved = alias;
        LOGVOLE_REQUIRE_FALSE(gpu::seedLabelRepDevice(ctx, alias, 2, 2, 3, alias));
        LOGVOLE_REQUIRE_FALSE(gpu::seedLabelRepDevice(ctx, alias, 1,
            std::numeric_limits<std::uint32_t>::max(), std::numeric_limits<std::uint32_t>::max(), alias));
        expect_batch_equal(alias, preserved);
    }
#endif
}

void LogVole_Core_RepOfflineSenderInputGammaTauUnbundlesResidues(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) != 0) LOGVOLE_REQUIRE_TRUE(gpu::enabled(advanced));
#else
    (void)cmd;
#endif
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx, std::make_shared<RingContextFactory>(advanced)));

    const std::uint32_t alpha = 2;
    const std::uint32_t tau = 3;
    const auto s = sample_batch(ctx, tau, 0x4004u);

    std::vector<RnsPoly> actual;
    LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(s, tau, alpha, tau, params, actual));
    LOGVOLE_REQUIRE_EQ(actual.size(), static_cast<std::size_t>(alpha * tau * params.mCoeffModulusBits.size()));

    const std::size_t n = params.mPolyModulusDegree;
    const std::size_t rho = ringModulusCount(ctx);
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

void LogVole_Core_RecursiveLiftOracleKeepsSenderResiduesUnscaled(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) != 0) LOGVOLE_REQUIRE_TRUE(gpu::enabled(advanced));
#else
    (void)cmd;
#endif
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx, std::make_shared<RingContextFactory>(advanced)));

    const std::uint32_t alpha = 2;
    const std::uint32_t tauHi = 2;
    const std::size_t n = params.mPolyModulusDegree;
    const auto& moduli = getRingHostModuli(ctx);
    const std::size_t rho = ringModulusCount(ctx);
    LOGVOLE_REQUIRE_EQ(moduli.size(), rho);
    LOGVOLE_REQUIRE_TRUE(rho >= 2);

    std::vector<RnsPoly> s(tauHi);
    for (std::uint32_t digit = 0; digit < tauHi; ++digit)
    {
        resizeZero(s[digit].mCoeffs, ringPolyCoeffCount(params));
        for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
        {
            const auto& modulus = moduli[modIdx];
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
                                seal::util::multiply_uint_mod(expected, delta[limb], moduli[limb]);
                            wouldCatchDoubleLift |= oldDoubleLift != expected;
                        }
                    }
                }
            }
        }
    }
    LOGVOLE_EXPECT_TRUE(wouldCatchDoubleLift);
#if defined(ENABLE_LOGVOLE_CUDA)
    if (gpu::enabled(advanced))
    {
        std::vector<RnsPoly> device;
        LOGVOLE_REQUIRE_TRUE(gpu::seedLabelRepDevice(ctx, s, tauHi, alpha, tauHi, device));
        expect_batch_equal(device, actual);
        auto alias = s;
        LOGVOLE_REQUIRE_TRUE(gpu::seedLabelRepDevice(ctx, alias, tauHi, alpha, tauHi, alias));
        expect_batch_equal(alias, actual);
    }
#endif
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
    const std::size_t rho = ringModulusCount(ctx);
    LOGVOLE_REQUIRE_EQ(replicated.size(), static_cast<std::size_t>(trunc.mTau) * rho);

    for (std::size_t digit = 0; digit < trunc.mTau; ++digit)
    {
        for (std::size_t limb = 0; limb < rho; ++limb)
        {
            expect_poly_equal(replicated[digit * rho + limb], skHi[digit]);
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

void LogVole_Core_RootTopCtNoiselessRelation(const oc::CLP& cmd)
{
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
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
        topCt, 1,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions));
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

    // Keep device activation inside this direct-ciphertext fixture. Other toy
    // recursive tests retain their established CPU/GPU scope.
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool haveGpu = cmd.getOr("gpu", 0) != 0 && gpu::available();
    if (const char* strict = (setupOptions.mRootDeviceStrict ? "1" : "0"))
        if (strict[0] == '1') LOGVOLE_REQUIRE_TRUE(haveGpu);
#else
    const bool haveGpu = false;
#endif

    auto checkDeviceParity = [&](const RingParams& ring, std::uint32_t gadgetBits) {
        osuCrypto::LogVoleExecutionOptions advanced;
        advanced.mUseGpu = haveGpu;
        RingNttContext parityContext{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, parityContext, std::make_shared<RingContextFactory>(advanced)));
        const auto left = sample_batch(parityContext, 5, 0x7351u);
        auto rightNtt = sample_batch(parityContext, 5, 0x7352u);
        auto rootB = sample_batch(parityContext, 2, 0x7353u);
        auto starB = sample_batch(parityContext, 3, 0x7354u);
        for (auto* batch : { &rightNtt, &rootB, &starB })
            for (auto& poly : *batch) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, parityContext));
        const auto originalRight = rightNtt, originalRoot = rootB, originalStar = starB;
        for (double sigma : { 0.0, 3.2 })
        {
            oc::PRNG referencePrng(oc::block(0x7355u, 0), 3);
            RingTensor expected{};
            {
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mRootDevice, false);
                tests_libOTe::logvole_test::ScopedOptionValue batchOption(setupOptions.mBatchNtt, false);
                auto cpuContext = cpuReferenceContext(parityContext);
                LOGVOLE_REQUIRE_TRUE(buildRootTopCt(cpuContext, left, rightNtt, rootB, starB,
                    gadgetBits, 1, referencePrng, sigma, 6 * sigma, expected, 1,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions));
            }
            const auto nextReference = referencePrng.get<oc::block>();
#if defined(ENABLE_LOGVOLE_CUDA)
            if (haveGpu && sigma == 0.0)
            {
                // The full-noise host input may also be the destination. No
                // publication may invalidate it before all GPU reads finish.
                std::vector<RnsPoly> aliasedNoise(expected.mPolys.size(), zero_poly(parityContext));
                const auto originalNoise = aliasedNoise;
                {
                    tests_libOTe::logvole_test::ScopedOptionValue forced(parityContext.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootDevice, true);
                    const auto* storage = aliasedNoise.data();
                    LOGVOLE_REQUIRE_FALSE(gpu::assembleRootTopCtDevice(parityContext,
                        left, rightNtt, rootB, starB, gadgetBits, 1u, aliasedNoise, aliasedNoise));
                    LOGVOLE_REQUIRE_TRUE(aliasedNoise.data() == storage);
                    expect_batch_equal(aliasedNoise, originalNoise);
                }
                LOGVOLE_REQUIRE_TRUE(gpu::assembleRootTopCtDevice(parityContext,
                    left, rightNtt, rootB, starB, gadgetBits, 1u, aliasedNoise, aliasedNoise));
                expect_batch_equal(aliasedNoise, expected.mPolys);
            }
#endif
            for (const char* batch : { "0", "1" })
            for (const char* compact : { "0", "1" })
            for (std::uint32_t workers : { 1u, 4u })
            {
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mRootDevice, (haveGpu ? "1" : "0")[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mRootDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue batchOption(setupOptions.mBatchNtt, (batch)[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mRootCompactNoise, (compact)[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mRootCompactNoiseStrict, true);
#if defined(ENABLE_LOGVOLE_CUDA)
                if (haveGpu) LOGVOLE_REQUIRE_TRUE(gpu::enabled(parityContext));
#endif
                oc::PRNG actualPrng(oc::block(0x7355u, 0), 3);
                RingTensor actual{};
                LOGVOLE_REQUIRE_TRUE(buildRootTopCt(parityContext, left, rightNtt, rootB, starB,
                    gadgetBits, 1, actualPrng, sigma, 6 * sigma, actual, workers,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions));
                LOGVOLE_REQUIRE_EQ(actual.mRows, expected.mRows);
                LOGVOLE_REQUIRE_EQ(actual.mCols, expected.mCols);
                LOGVOLE_REQUIRE_EQ(actual.mPolys.size(), expected.mPolys.size());
                for (std::size_t i = 0; i < actual.mPolys.size(); ++i)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mPolys[i].mCoeffs, expected.mPolys[i].mCoeffs))
                        << " root ciphertext polynomial " << i;
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                for (const auto& batches : {
                        std::pair{ &rightNtt, &originalRight }, std::pair{ &rootB, &originalRoot },
                        std::pair{ &starB, &originalStar } })
                    for (std::size_t i = 0; i < batches.first->size(); ++i)
                        LOGVOLE_REQUIRE_TRUE(rangesEqual((*batches.first)[i].mCoeffs, (*batches.second)[i].mCoeffs));
            }
            if (haveGpu)
            {
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mRootDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mRootDeviceStrict, false);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mRootCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mRootCompactNoiseStrict, false);
                tests_libOTe::logvole_test::ScopedOptionValue decline(parityContext.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootCompactNoise, true);
                oc::PRNG replayPrng(oc::block(0x7355u, 0), 3);
                RingTensor replay{};
                LOGVOLE_REQUIRE_TRUE(buildRootTopCt(parityContext, left, rightNtt, rootB, starB,
                    gadgetBits, 1, replayPrng, sigma, 6 * sigma, replay, 4,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions));
                expect_batch_equal(replay.mPolys, expected.mPolys);
                LOGVOLE_EXPECT_EQ(replayPrng.get<oc::block>(), nextReference);
                tests_libOTe::logvole_test::ScopedOptionValue requireCompact(setupOptions.mRootCompactNoiseStrict, true);
                oc::PRNG rejectedPrng(oc::block(0x7355u, 0), 3);
                RingTensor rejected = expected;
                const auto* storage = rejected.mPolys.data();
                LOGVOLE_REQUIRE_TRUE(!buildRootTopCt(parityContext, left, rightNtt, rootB, starB,
                    gadgetBits, 1, rejectedPrng, sigma, 6 * sigma, rejected, 4,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions));
                LOGVOLE_REQUIRE_TRUE(rejected.mPolys.data() == storage);
                expect_batch_equal(rejected.mPolys, expected.mPolys);
                LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), nextReference);
            }
        }
    };
    checkDeviceParity(params, 7);
    RingParams production{};
    production.mPolyModulusDegree = 8192;
    assignValues<int>(production.mCoeffModulusBits, { 55, 55, 55, 55 });
    checkDeviceParity(production, 110);
    production.mPolyModulusDegree = 16384;
    assignValues<int>(production.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    checkDeviceParity(production, 208);
}

void LogVole_Core_RootErrorCompactGpuParity(const oc::CLP& cmd)
{
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    const bool haveGaussian = gpu::gaussianTransformHostCompatible();
    tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mRootCompactNoise, true);
    tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mRootCompactNoiseStrict, true);

    const auto checkRing = [&](const RingParams& params) {
        osuCrypto::LogVoleExecutionOptions advanced;
        advanced.mUseGpu = true;
        advanced.mAdvanced.mProtocol.mGaussianResident = false;
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx, std::make_shared<RingContextFactory>(advanced)));
        for (const std::uint32_t count : { 1u, 5u })
        for (const double sigma : { 0.0, 3.2 })
        for (const bool outputNtt : { false, true })
        {
            const auto seed = oc::block(0x7391u + count, outputNtt);
            oc::PRNG referencePrng(seed, 3);
            std::vector<RnsPoly> expected;
            {
                auto cpuContext = cpuReferenceContext(ctx);
                // Exercise the original seven-argument public API as well.
                LOGVOLE_REQUIRE_TRUE(sampleRootErrorBatch(cpuContext, count, referencePrng,
                    sigma, 6 * sigma, outputNtt, expected, 1, setupOptions));
            }
            const auto nextReference = referencePrng.get<oc::block>();
            for (const std::uint32_t workers : { 1u, 4u })
            {
                oc::PRNG actualPrng(seed, 3);
                std::vector<RnsPoly> actual;
                LOGVOLE_REQUIRE_TRUE(sampleRootErrorBatch(ctx, count, actualPrng,
                    sigma, 6 * sigma, outputNtt, actual, workers, setupOptions));
                expect_batch_equal(actual, expected);
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
            }
            {
                tests_libOTe::logvole_test::ScopedOptionValue resident(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResident, true);
                tests_libOTe::logvole_test::ScopedOptionValue residentStrict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, (haveGaussian));
                tests_libOTe::logvole_test::ScopedOptionValue residentDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, false);
                tests_libOTe::logvole_test::ScopedOptionValue transform(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransform, true);
                tests_libOTe::logvole_test::ScopedOptionValue transformStrict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformStrict, (haveGaussian));
                tests_libOTe::logvole_test::ScopedOptionValue transformDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianTransform, false);
                for (const char* blocks : {"0", "1"})
                {
                    tests_libOTe::logvole_test::ScopedOptionValue prefix(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, static_cast<std::uint64_t>(std::strtoull(blocks, nullptr, 10)));
                    oc::PRNG actualPrng(seed, 3);
                    std::vector<RnsPoly> actual;
                    LOGVOLE_REQUIRE_TRUE(sampleRootErrorBatch(ctx, count, actualPrng,
                        sigma, 6 * sigma, outputNtt, actual, 4, setupOptions));
                    expect_batch_equal(actual, expected);
                    LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                }
                if (sigma > 0.0)
                {
                    tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, true);
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue replay(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, false);
                        oc::PRNG replayPrng(seed, 3);
                        std::vector<RnsPoly> replayOutput;
                        LOGVOLE_REQUIRE_TRUE(sampleRootErrorBatch(ctx, count, replayPrng,
                            sigma, 6 * sigma, outputNtt, replayOutput, 4, setupOptions));
                        expect_batch_equal(replayOutput, expected);
                        LOGVOLE_EXPECT_EQ(replayPrng.get<oc::block>(), nextReference);
                    }
                    tests_libOTe::logvole_test::ScopedOptionValue requireResident(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, true);
                    oc::PRNG rejectedPrng(seed, 3);
                    auto rejected = expected;
                    const auto* storage = rejected.data();
                    LOGVOLE_REQUIRE_FALSE(sampleRootErrorBatch(ctx, count, rejectedPrng,
                        sigma, 6 * sigma, outputNtt, rejected, 4, setupOptions));
                    LOGVOLE_REQUIRE_TRUE(rejected.data() == storage);
                    expect_batch_equal(rejected, expected);
                    LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), nextReference);
                }
            }
            tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootCompactNoise, true);
            {
                tests_libOTe::logvole_test::ScopedOptionValue fallback(setupOptions.mRootCompactNoiseStrict, false);
                oc::PRNG replayPrng(seed, 3);
                std::vector<RnsPoly> replay;
                LOGVOLE_REQUIRE_TRUE(sampleRootErrorBatch(ctx, count, replayPrng,
                    sigma, 6 * sigma, outputNtt, replay, 4, setupOptions));
                expect_batch_equal(replay, expected);
                LOGVOLE_EXPECT_EQ(replayPrng.get<oc::block>(), nextReference);
            }
            oc::PRNG rejectedPrng(seed, 3);
            auto rejected = expected;
            const auto* storage = rejected.data();
            LOGVOLE_REQUIRE_TRUE(!sampleRootErrorBatch(ctx, count, rejectedPrng,
                sigma, 6 * sigma, outputNtt, rejected, 4, setupOptions));
            LOGVOLE_REQUIRE_TRUE(rejected.data() == storage);
            expect_batch_equal(rejected, expected);
            LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), nextReference);
        }
        std::vector<std::uint64_t> invalid(params.mPolyModulusDegree - 1, 0);
        auto marker = sample_batch(ctx, 1, 0x7392u);
        const auto snapshot = marker;
        const auto* storage = marker.data();
        LOGVOLE_REQUIRE_TRUE(!gpu::expandRootErrorCompactDevice(ctx, invalid, true, marker));
        LOGVOLE_REQUIRE_TRUE(marker.data() == storage);
        expect_batch_equal(marker, snapshot);
    };
    checkRing(make_params());
    RingParams production{};
    production.mPolyModulusDegree = 8192;
    assignValues<int>(production.mCoeffModulusBits, { 55, 55, 55, 55 });
    checkRing(production);
    production.mPolyModulusDegree = 16384;
    assignValues<int>(production.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    checkRing(production);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_Core_GaussianResidentPublicWireParity(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    const bool haveGaussian = gpu::gaussianTransformHostCompatible();
    tests_libOTe::logvole_test::ScopedOptionValue resident(advanced.mAdvanced.mProtocol.mGaussianResident, true);
    tests_libOTe::logvole_test::ScopedOptionValue residentStrict(advanced.mAdvanced.mProtocol.mGaussianResidentStrict, (haveGaussian));

    tests_libOTe::logvole_test::ScopedOptionValue transform(advanced.mAdvanced.mProtocol.mGaussianTransform, true);
    tests_libOTe::logvole_test::ScopedOptionValue transformStrict(advanced.mAdvanced.mProtocol.mGaussianTransformStrict, (haveGaussian));

    tests_libOTe::logvole_test::ScopedOptionValue prefix(advanced.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, std::uint64_t{0});
    tests_libOTe::logvole_test::ScopedOptionValue compact(setupOptions.mCompactNoise, true);
    tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, true);
    tests_libOTe::logvole_test::ScopedOptionValue rootCompact(setupOptions.mRootCompactNoise, true);
    tests_libOTe::logvole_test::ScopedOptionValue rootCompactStrict(setupOptions.mRootCompactNoiseStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue lencDevice(setupOptions.mLencDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue lencStrict(setupOptions.mLencDeviceStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue lheDevice(setupOptions.mLheDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue lheStrict(setupOptions.mLheDeviceStrict, true);

    tests_libOTe::logvole_test::ScopedOptionValue rootDevice(setupOptions.mRootDevice, true);
    tests_libOTe::logvole_test::ScopedOptionValue rootStrict(setupOptions.mRootDeviceStrict, true);
    tests_libOTe::logvole_test::ScopedOptionValue publicUniformStrict(advanced.mAdvanced.mProtocol.mUniformSamplingStrict, true);

    for (bool noGolden : {false, true})
    {
        Params params = make_recursive_params(2);
        if (noGolden)
        {
            params.mShrinkExpand.mRing.mPolyModulusDegree = 16384;
            assignValues<int>(params.mShrinkExpand.mRing.mCoeffModulusBits,
                {52, 52, 52, 52, 52, 52, 52, 52});
            params.mShrinkExpand.mPlaintextModulusBits = 52;
            params.mShrinkExpand.mGadgetLogBase = 208;
            params.mShrinkExpand.mMu = 32;
            params.mW = 32;
            params.mCt2SeedMode = Ct2SeedMode::PublicSeed;
        }
        params.mShrinkExpand.mNumWorkerThreads = 4;
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx, std::make_shared<RingContextFactory>(advanced)));
        SenderOfflineInput input;
        input.mParams = params;
        input.mSk1 = sample_batch(ctx, params.mGamma, 0x475257495245u);
        ReceiverOfflineInput receiverInput;
        receiverInput.mParams = params;
        const oc::block seed(0x475245534944454eULL, noGolden);
        oc::PRNG referencePrng(seed, 3);
        SenderOfflineOutput expected;
        {
            tests_libOTe::logvole_test::ScopedOptionValue cpuReference(advanced.mUseGpu, false);
            LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Sender), referencePrng, expected));
        }
        std::array<std::uint64_t, 16> nextReference;
        referencePrng.get(nextReference.data(), nextReference.size());
        for (bool forcedReplay : {false, true})
        {
            tests_libOTe::logvole_test::ScopedOptionValue decline(advanced.mAdvanced.mProtocol.mFailures.mGaussianResident, (forcedReplay ? "1" : "0")[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue strict(advanced.mAdvanced.mProtocol.mGaussianResidentStrict, !(forcedReplay || !haveGaussian));
            tests_libOTe::logvole_test::ScopedOptionValue publicDecline(advanced.mAdvanced.mProtocol.mFailures.mPublicRetain, (forcedReplay ? "1" : "0")[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue extraDownload(advanced.mAdvanced.mProtocol.mExtraPipelinedDownload, !forcedReplay);
            const auto run = allocateProtocolCacheRunId();
            ScopedProtocolCacheScope senderScope(ProtocolCacheRole::Sender, run);
            oc::PRNG actualPrng(seed, 3);
            SenderOfflineOutput actual;
            RetentionBaseline retentionBefore;
            retentionBefore.capture(ctx);
            retentionBefore.captureTree(expected.mState);
            LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Sender), actualPrng, actual));
            const auto retentionAfter = retentionBefore.deltaTree(actual.mState);
            if (forcedReplay)
                LOGVOLE_REQUIRE_EQ(retentionAfter.mCopies, 0u);
            else
            {
                LOGVOLE_REQUIRE_TRUE(retentionAfter.mCaptures > 0u);
                LOGVOLE_REQUIRE_TRUE(retentionAfter.mCopies > 0u);
                LOGVOLE_REQUIRE_TRUE(retentionAfter.mCopiedBytes > 0u);
            }
            std::array<std::uint64_t, 16> nextActual;
            actualPrng.get(nextActual.data(), nextActual.size());
            LOGVOLE_REQUIRE_TRUE(nextActual == nextReference);
            const OfflineMessage* a = &actual.mMessage;
            const OfflineMessage* e = &expected.mMessage;
            while (a && e)
            {
                LOGVOLE_REQUIRE_EQ(a->mHasShrinkExpandMessage, e->mHasShrinkExpandMessage);
                if (e->mHasShrinkExpandMessage)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(encode(a->mShrinkExpandMessage), encode(e->mShrinkExpandMessage)));
                if (!e->mNextLevel)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(encode(a->mRootMessage), encode(e->mRootMessage)));
                a = a->mNextLevel.get();
                e = e->mNextLevel.get();
            }
            LOGVOLE_REQUIRE_TRUE(!a && !e);
            ReceiverOfflineOutput receiver;
            ScopedProtocolCacheScope receiverScope(ProtocolCacheRole::Receiver, run);
            LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), actual.mMessage, receiver));
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
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
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            const std::uint64_t mod = ringModulusValue(ctx, modIdx);
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

void LogVole_Core_RootOfflineSetupFinalizeShapes(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

    const Params params = make_root_params();
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, false, trunc));

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx));

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput.mS = sample_batch(ctx, trunc.mMu, 0x7501u);

    ShrinkExpandSenderState seSender{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withSetupOptions(seInput, setupOptions), seSender));

    SenderState sender{};
    sender.mParams = params;
    sender.mShrinkExpandState = seSender;

    RootOfflineMessage message{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_offline_sender_for_test(tests_libOTe::logvole_test::withSetupOptions(sender, setupOptions), message));

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

    // Exercise setup batching on a device when available, and retain the same
    // exact-replay check for the CPU fallback. This includes the noisy root
    // ciphertext and the receiver's root and shrink/expand transforms.
#if defined(ENABLE_LOGVOLE_CUDA)
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
    if (advanced.mUseGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
#endif
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx, std::make_shared<RingContextFactory>(advanced)));
    Buffer serialMessage;
    std::vector<RnsPoly> serialRootCt;
    std::vector<RnsPoly> serialShrinkCt;
    std::uint64_t serialNextRandom = 0;
    for (const char* option : { "0", "1" })
    {
        tests_libOTe::logvole_test::ScopedOptionValue batchOption(setupOptions.mBatchNtt, (option)[0] != '0');
        SenderState replaySender{};
        replaySender.mParams = params;
        replaySender.mShrinkExpandState = seSender;
        replaySender.mShrinkExpandState.mParams.mNumWorkerThreads = 4;
        replaySender = tests_libOTe::logvole_test::withAdvancedOptions(std::move(replaySender), advanced, ProtocolCacheRole::Sender);
        oc::PRNG replayPrng(oc::block(0x7502u, 0x7503u));
        RootOfflineMessage replayMessage{};
        LOGVOLE_REQUIRE_TRUE(prepareRootOfflineSender(tests_libOTe::logvole_test::withSetupOptions(replaySender, setupOptions), replayPrng, replayMessage));
        const auto nextRandom = replayPrng.get<std::uint64_t>();
        const auto encoded = encode(replayMessage);

        ReceiverState replayReceiver{};
        replayReceiver.mParams = params;
        replayReceiver = tests_libOTe::logvole_test::withAdvancedOptions(std::move(replayReceiver), advanced, ProtocolCacheRole::Receiver);
        LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(replayReceiver, replayMessage));
        ShrinkExpandReceiverOfflineInput seReceiverInput{};
        seReceiverInput.mParams = trunc;
        seReceiverInput = tests_libOTe::logvole_test::withAdvancedOptions(std::move(seReceiverInput), advanced, ProtocolCacheRole::Receiver);
        ShrinkExpandReceiverState seReceiver{};
        LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(
            tests_libOTe::logvole_test::withSetupOptions(seReceiverInput, setupOptions), seSender, seReceiver));

        RootOfflineMessage ownedRoot = replayMessage;
        const auto* rootStorage = ownedRoot.mTopCt.mPolys.data();
        ReceiverState movedRoot{};
        movedRoot.mParams = params;
        movedRoot = tests_libOTe::logvole_test::withAdvancedOptions(std::move(movedRoot), advanced, ProtocolCacheRole::Receiver);
        LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(movedRoot, std::move(ownedRoot)));
        LOGVOLE_EXPECT_TRUE(movedRoot.mRootTopCt.mPolys.data() == rootStorage);
        expect_batch_equal(movedRoot.mRootCtRRt.mPolys, replayReceiver.mRootCtRRt.mPolys);
        expect_batch_equal(movedRoot.mRootLacctLeft.mCt.mPolys, replayReceiver.mRootLacctLeft.mCt.mPolys);
        expect_batch_equal(movedRoot.mRootTopCt.mPolys, replayReceiver.mRootTopCt.mPolys);
        expect_batch_equal(movedRoot.mRootPublicBStarNtt, replayReceiver.mRootPublicBStarNtt);
        LOGVOLE_EXPECT_TRUE(rangesEqual(encoded, encode(replayMessage)));

        ShrinkExpandOfflineMessage ownedShrink{};
        ownedShrink.mParams = seSender.mParams;
        ownedShrink.mCt1 = seSender.mCt1;
        ownedShrink.mLacct = seSender.mLacct;
        const auto* shrinkStorage = ownedShrink.mLacct.mCt.mPolys.data();
        ShrinkExpandReceiverState movedShrink{};
        LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(
            tests_libOTe::logvole_test::withSetupOptions(seReceiverInput, setupOptions), std::move(ownedShrink), movedShrink));
        LOGVOLE_EXPECT_TRUE(movedShrink.mLacct.mCt.mPolys.data() == shrinkStorage);
        expect_batch_equal(movedShrink.mCt1.mPolys, seReceiver.mCt1.mPolys);
        expect_batch_equal(movedShrink.mLacct.mCt.mPolys, seReceiver.mLacct.mCt.mPolys);
        expect_batch_equal(*movedShrink.mPublicANtt, *seReceiver.mPublicANtt);
        expect_batch_equal(*movedShrink.mPublicBNtt, *seReceiver.mPublicBNtt);

        ShrinkExpandOfflineMessage malformedShrink{};
        malformedShrink.mParams = seSender.mParams;
        malformedShrink.mCt1 = seSender.mCt1;
        malformedShrink.mLacct = seSender.mLacct;
        malformedShrink.mLacct.mLevels = 0;
        const auto* malformedStorage = malformedShrink.mCt1.mPolys.data();
        const auto* previousStorage = movedShrink.mCt1.mPolys.data();
        LOGVOLE_EXPECT_FALSE(finalizeShrinkExpandReceiverOffline(
            tests_libOTe::logvole_test::withSetupOptions(seReceiverInput, setupOptions), std::move(malformedShrink), movedShrink));
        LOGVOLE_EXPECT_TRUE(malformedShrink.mCt1.mPolys.data() == malformedStorage);
        LOGVOLE_EXPECT_TRUE(movedShrink.mCt1.mPolys.data() == previousStorage);

        if (option[0] == '0')
        {
            serialMessage = encoded;
            serialRootCt = replayReceiver.mRootCtRRt.mPolys;
            serialShrinkCt = seReceiver.mCt1.mPolys;
            serialNextRandom = nextRandom;
        }
        else
        {
            LOGVOLE_REQUIRE_TRUE(rangesEqual(serialMessage, encoded));
            LOGVOLE_EXPECT_EQ(serialNextRandom, nextRandom);
            LOGVOLE_REQUIRE_EQ(serialRootCt.size(), replayReceiver.mRootCtRRt.mPolys.size());
            for (std::size_t i = 0; i < serialRootCt.size(); ++i)
                expect_poly_equal(serialRootCt[i], replayReceiver.mRootCtRRt.mPolys[i]);
            LOGVOLE_REQUIRE_EQ(serialShrinkCt.size(), seReceiver.mCt1.mPolys.size());
            for (std::size_t i = 0; i < serialShrinkCt.size(); ++i)
                expect_poly_equal(serialShrinkCt[i], seReceiver.mCt1.mPolys[i]);
        }
    }

    // The internal transport Root path borrows the same deterministic B as
    // the eager API. A declined device consumer replays every sampled value
    // without advancing the parent PRNG a second time.
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool replayGpuEnabled = gpu::enabled(advanced);
#else
        constexpr bool replayGpuEnabled = false;
#endif

        tests_libOTe::logvole_test::ScopedOptionValue lencDevice(setupOptions.mLencDevice, true);
        tests_libOTe::logvole_test::ScopedOptionValue rootDevice(setupOptions.mRootDevice, true);
        tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, false);
        tests_libOTe::logvole_test::ScopedOptionValue rootCompactStrict(setupOptions.mRootCompactNoiseStrict, false);
        struct Replay
        {
            Buffer mWire;
            oc::block mNext;
            std::vector<RnsPoly> mR1;
            std::vector<RnsPoly> mSkR;
            std::vector<RnsPoly> mBStar;
            bool mLazyTop = false;
            bool mLazyCtR = false;
            bool mR1InitiallyDeviceOnly = false;
            bool mR1DeviceOwned = false;
            bool mSkInitiallyDeviceOnly = false;
            bool mSkDeviceOwned = false;
            oc::block mNextAfterHost;
            oc::block mNextAfterSkHost;
            Buffer mResponseWire;
            oc::block mResponseNext;
        };
        const auto replay = [&](bool deferHost, const char* rootDecline,
                                const char* lencDecline, const char* tokenOption,
                                std::uint64_t runId, const char* r1Decline = "0",
                                const char* lheDecline = "0",
                                const char* r1Option = "1",
                                const char* skDecline = "0",
                                const char* skOption = "1",
                                const char* skxDecline = "0",
                                const char* bStarOption = "1",
                                const char* bStarCaptureDecline = "0") {
            ScopedProtocolCacheScope senderScope(ProtocolCacheRole::Sender, runId);
            tests_libOTe::logvole_test::ScopedOptionValue forceRoot(advanced.mAdvanced.mProtocol.mFailures.mRootDevice, (rootDecline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue forceLenc(advanced.mAdvanced.mProtocol.mFailures.mLencDevice, (lencDecline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue forceR1(advanced.mAdvanced.mProtocol.mFailures.mRootR1Device, (r1Decline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue forceLhe(advanced.mAdvanced.mProtocol.mFailures.mLheDevice, (lheDecline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue forceSk(advanced.mAdvanced.mProtocol.mFailures.mRootSkRRDevice, (skDecline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue forceSkx(advanced.mAdvanced.mProtocol.mFailures.mRootSkX, (skxDecline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue forceBStar(advanced.mAdvanced.mProtocol.mFailures.mRootBStarDevice, (bStarCaptureDecline)[0] == '1');
            tests_libOTe::logvole_test::ScopedOptionValue strictRoot(setupOptions.mRootDeviceStrict, (replayGpuEnabled && rootDecline[0] == '0' ? "1" : "0")[0] != '0');
            tests_libOTe::logvole_test::ScopedOptionValue strictLenc(setupOptions.mLencDeviceStrict, (replayGpuEnabled && lencDecline[0] == '0' ? "1" : "0")[0] != '0');
            tests_libOTe::logvole_test::ScopedOptionValue strictLhe(setupOptions.mLheDeviceStrict, (replayGpuEnabled && lheDecline[0] == '0' ? "1" : "0")[0] != '0');
            SenderState nextSender{};
            nextSender.mParams = params;
            nextSender.mParams.mShrinkExpand.mGpuSetup.mRootR1Device = r1Option[0] != '0';
            nextSender.mParams.mShrinkExpand.mGpuSetup.mRootSecretDevice = skOption[0] != '0';
            nextSender.mParams.mShrinkExpand.mGpuSetup.mRootPublicBToken = tokenOption[0] != '0';
            nextSender.mParams.mShrinkExpand.mGpuSetup.mRootBStarDevice = bStarOption[0] != '0';
            nextSender.mShrinkExpandState = seSender;
            nextSender = tests_libOTe::logvole_test::withAdvancedOptions(
                std::move(nextSender), advanced, ProtocolCacheRole::Sender);
            oc::PRNG nextPrng(oc::block(0x76B0u, 0x76B1u));
            RootOfflineMessage nextMessage{};
            LOGVOLE_REQUIRE_TRUE(prepareRootOfflineSender(
                tests_libOTe::logvole_test::withSetupOptions(nextSender, setupOptions), nextPrng, nextMessage, deferHost));
#if defined(ENABLE_LOGVOLE_CUDA)
            if (replayGpuEnabled && runId == 0x76B002u)
            {
                const auto rootOwner = std::static_pointer_cast<gpu::DeviceBatch>(
                    nextSender.mRootR1RtDevice);
                LOGVOLE_REQUIRE_TRUE(rootOwner != nullptr);
                LOGVOLE_REQUIRE_TRUE(nextSender.mLazyRootR1Rt != nullptr);
                LOGVOLE_REQUIRE_TRUE(gpu::rootErrorBatchMatches(ctx,
                    *rootOwner, leftWidth));
                RingNttContext reordered = ctx;
                if (reordered.mRawModuli)
                {
                    auto moduli = std::make_shared<RingModulusMetadata>(*reordered.mRawModuli);
                    std::swap(moduli->mValues[0], moduli->mValues[1]);
                    reordered.mRawModuli = std::move(moduli);
                }
                else
                    std::swap(reordered.mModuli[0], reordered.mModuli[1]);
                LOGVOLE_REQUIRE_FALSE(gpu::rootErrorBatchMatches(reordered,
                    *rootOwner, leftWidth));
                RingParams widerParams = trunc.mRing;
                widerParams.mPolyModulusDegree *= 2;
                RingNttContext widerCtx{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(widerParams, widerCtx, std::make_shared<RingContextFactory>(advanced)));
                LOGVOLE_REQUIRE_FALSE(gpu::rootErrorBatchMatches(widerCtx,
                    *rootOwner, leftWidth));
                const auto secretOwner = std::static_pointer_cast<gpu::DeviceBatch>(
                    nextSender.mRootSkRRtDevice);
                LOGVOLE_REQUIRE_TRUE(secretOwner != nullptr);
                LOGVOLE_REQUIRE_TRUE(nextSender.mLazyRootSkRRt != nullptr);
                LOGVOLE_REQUIRE_TRUE(gpu::rootSecretUniformBatchMatches(ctx,
                    *secretOwner, tauHi, runId));
                LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(ctx,
                    *secretOwner, tauHi, runId + 1u));
                LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(reordered,
                    *secretOwner, tauHi, runId));
                LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(widerCtx,
                    *secretOwner, tauHi, runId));
                {
                    tests_libOTe::logvole_test::ScopedOptionValue forcedSkx(advanced.mAdvanced.mProtocol.mFailures.mRootSkX, true);
                    LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(reordered,
                        *secretOwner, tauHi, runId));
                    LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(widerCtx,
                        *secretOwner, tauHi, runId));
                    SenderState wrongRun{};
                    wrongRun.mParams = nextSender.mParams;
                    wrongRun.mRootSkRRtDevice = nextSender.mRootSkRRtDevice;
                    wrongRun.mLazyRootSkRRt = nextSender.mLazyRootSkRRt;
                    wrongRun.mRootSkRRtOwnerRunId =
                        nextSender.mRootSkRRtOwnerRunId + 1u;
                    wrongRun = tests_libOTe::logvole_test::withAdvancedOptions(
                        std::move(wrongRun), advanced, ProtocolCacheRole::Sender);
                    RootDigestMessage badRequest{};
                    badRequest.mDPrimeCoeffs =
                        sample_batch(ctx, 1u, 0x76B0D1u)[0].mCoeffs;
                    oc::PRNG badPrng(oc::block(0x76B0E1u, 0x76B0E2u));
                    oc::PRNG referencePrng(oc::block(0x76B0E1u, 0x76B0E2u));
                    RootResponseMessage unchangedResponse{};
                    LOGVOLE_REQUIRE_FALSE(tests_libOTe::logvole_test::prepareRootResponse(
                        wrongRun, badRequest, badPrng, unchangedResponse,
                        nullptr, nullptr, true));
                    LOGVOLE_EXPECT_TRUE(unchangedResponse.mSkPrimeCoeffs.empty());
                    LOGVOLE_EXPECT_EQ(badPrng.get<oc::block>(),
                        referencePrng.get<oc::block>());
                }
                gpu::DeviceBatchPtr preparedKPrime;
                if (gpu::prepareRootSenderOperandsDevice(
                        nextSender, RnsPoly{}, preparedKPrime))
                {
                    const auto preparedSk =
                        std::static_pointer_cast<gpu::DeviceBatch>(
                            nextSender.mRootSkRRtNttDevice);
                    LOGVOLE_REQUIRE_TRUE(preparedSk != nullptr);
                    LOGVOLE_REQUIRE_TRUE(gpu::rootSecretUniformBatchMatches(ctx,
                        *preparedSk, tauHi, runId, true));
                }
                auto otherR = sample_batch(ctx, leftWidth, 0x76B0C1u);
                auto otherB = sample_batch(ctx, tauHi, 0x76B0C2u);
                for (auto& poly : otherR) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
                for (auto& poly : otherB) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
                oc::PRNG rejectedPrng(oc::block(0x76B0u, 0x76B0C3u));
                oc::PRNG referencePrng(oc::block(0x76B0u, 0x76B0C3u));
                RingTensor unchanged{};
                {
                    ScopedProtocolCacheScope wrongRole(ProtocolCacheRole::Receiver, runId);
                    LOGVOLE_REQUIRE_FALSE(gpu::rootErrorBatchMatches(ctx,
                        *rootOwner, leftWidth));
                    LOGVOLE_REQUIRE_FALSE(gpu::rootSecretUniformBatchMatches(ctx,
                        *secretOwner, tauHi, runId));
                    LOGVOLE_REQUIRE_FALSE(buildRootTopCt(ctx, {}, otherR,
                        otherB, nextMessage.mPublicBStarNtt,
                        seSender.mParams.mGadgetLogBase, 1, rejectedPrng,
                        0.0, 0.0, unchanged, 4, {}, nullptr, nullptr,
                        rootOwner.get(), nextSender.mLazyRootR1Rt.get(), nullptr, setupOptions));
                }
                LOGVOLE_EXPECT_TRUE(unchanged.mPolys.empty());
                LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(),
                    referencePrng.get<oc::block>());
            }
#endif
            Replay result{};
            result.mLazyTop = nextMessage.mLazyTopCt != nullptr;
            result.mLazyCtR = nextMessage.mLazyCtR != nullptr;
            result.mR1InitiallyDeviceOnly = nextSender.mRootR1Rt.empty() &&
                nextSender.mLazyRootR1Rt != nullptr;
            result.mR1DeviceOwned = nextSender.mRootR1RtDevice != nullptr;
            result.mSkInitiallyDeviceOnly = nextSender.mRootSkRRt.empty() &&
                nextSender.mLazyRootSkRRt != nullptr;
            result.mSkDeviceOwned = nextSender.mRootSkRRtDevice != nullptr;
            result.mBStar = nextMessage.mPublicBStarNtt;
            result.mWire = encode(nextMessage, 4);
            result.mNext = nextPrng.get<oc::block>();
            result.mR1 = nextSender.mLazyRootR1Rt
                ? nextSender.mLazyRootR1Rt->hostCoefficients()
                : std::move(nextSender.mRootR1Rt);
            result.mNextAfterHost = nextPrng.get<oc::block>();
            nextSender.mParams.mCt2SeedMode = Ct2SeedMode::PublicSeed;
            RootDigestMessage onlineRequest{};
            onlineRequest.mDPrimeCoeffs =
                sample_batch(ctx, 1u, 0x76B0D1u)[0].mCoeffs;
            oc::PRNG responsePrng(oc::block(0x76B0D2u, 0x76B0D3u));
            RootResponseMessage onlineResponse{};
            LOGVOLE_REQUIRE_TRUE(tests_libOTe::logvole_test::prepareRootResponse(
                nextSender, onlineRequest, responsePrng, onlineResponse,
                nullptr, nullptr, true));
            result.mResponseWire = encode(onlineResponse);
            result.mResponseNext = responsePrng.get<oc::block>();
            result.mSkR = nextSender.mLazyRootSkRRt
                ? nextSender.mLazyRootSkRRt->hostCoefficients()
                : std::move(nextSender.mRootSkRRt);
            result.mNextAfterSkHost = nextPrng.get<oc::block>();
            return result;
        };
        const auto eager = replay(false, "0", "0", "1", 0x76B001u);
        const auto retained = replay(true, "0", "0", "1", 0x76B002u);
        const auto rootFallback = replay(true, "1", "0", "1", 0x76B003u);
        const auto lencFallback = replay(true, "0", "1", "1", 0x76B004u);
        const auto hostOptOut = replay(true, "0", "0", "0", 0x76B005u);
        const auto r1Fallback = replay(true, "0", "0", "1", 0x76B007u, "1");
        const auto lheFallback = replay(true, "0", "0", "1", 0x76B008u, "0", "1");
        const auto r1OptOut = replay(true, "0", "0", "1", 0x76B009u, "0", "0", "0");
        const auto skFallback = replay(true, "0", "0", "1", 0x76B00Au,
            "0", "0", "1", "1");
        const auto skOptOut = replay(true, "0", "0", "1", 0x76B00Bu,
            "0", "0", "1", "0", "0");
        const auto skxFallback = replay(true, "0", "0", "1", 0x76B00Cu,
            "0", "0", "1", "0", "1", "1");
        const auto bStarOptOut = replay(true, "0", "0", "1", 0x76B00Du,
            "0", "0", "1", "0", "1", "0", "0");
        const auto bStarCaptureDecline = replay(true, "0", "0", "1",
            0x76B00Eu, "0", "0", "1", "0", "1", "0", "1", "1");
        if (replayGpuEnabled)
        {
            LOGVOLE_REQUIRE_TRUE(retained.mLazyTop);
            LOGVOLE_REQUIRE_TRUE(retained.mLazyCtR);
        }
        if (replayGpuEnabled)
        {
            LOGVOLE_REQUIRE_TRUE(retained.mR1InitiallyDeviceOnly);
            LOGVOLE_REQUIRE_TRUE(retained.mR1DeviceOwned);
            LOGVOLE_REQUIRE_FALSE(r1Fallback.mR1DeviceOwned);
            LOGVOLE_REQUIRE_FALSE(r1OptOut.mR1DeviceOwned);
            LOGVOLE_REQUIRE_TRUE(retained.mSkInitiallyDeviceOnly);
            LOGVOLE_REQUIRE_TRUE(retained.mSkDeviceOwned);
            LOGVOLE_REQUIRE_FALSE(skFallback.mSkDeviceOwned);
            LOGVOLE_REQUIRE_FALSE(skOptOut.mSkDeviceOwned);
            LOGVOLE_REQUIRE_TRUE(skxFallback.mSkDeviceOwned);
        }
        for (const auto* candidate : { &retained, &rootFallback, &lencFallback,
                                     &hostOptOut, &r1Fallback, &lheFallback,
                                     &r1OptOut, &skFallback, &skOptOut,
                                     &skxFallback, &bStarOptOut,
                                     &bStarCaptureDecline })
        {
            LOGVOLE_REQUIRE_TRUE(rangesEqual(candidate->mWire, eager.mWire));
            LOGVOLE_EXPECT_EQ(candidate->mNext, eager.mNext);
            LOGVOLE_EXPECT_EQ(candidate->mNextAfterHost, eager.mNextAfterHost);
            LOGVOLE_EXPECT_EQ(candidate->mNextAfterSkHost, eager.mNextAfterSkHost);
            expect_batch_equal(candidate->mR1, eager.mR1);
            expect_batch_equal(candidate->mSkR, eager.mSkR);
            expect_batch_equal(candidate->mBStar, eager.mBStar);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(candidate->mResponseWire,
                eager.mResponseWire));
            LOGVOLE_EXPECT_EQ(candidate->mResponseNext, eager.mResponseNext);
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (replayGpuEnabled)
        {
            // A matching ring/count/NTT token from a different nonce cannot
            // use the fixed LENC-B host fallback if the Root device declines.
            ScopedProtocolCacheScope senderScope(ProtocolCacheRole::Sender, 0x76B006u);
            std::shared_ptr<const gpu::RetainedPublicUniform> otherB;
            LOGVOLE_REQUIRE_TRUE(retainUniformPolyBatchFromNonce(ctx,
                0x76B0BADu, 0x1EEC0DEu, 2u * (tauHi + 1u), true, otherB));
            auto otherR = sample_batch(ctx, leftWidth, 0x76B0A1u);
            for (auto& poly : otherR) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
            oc::PRNG rejectedPrng(oc::block(0x76B0u, 0x76B2u));
            oc::PRNG referencePrng(oc::block(0x76B0u, 0x76B2u));
            RingTensor unchanged = message.mTopCt;
            LOGVOLE_REQUIRE_FALSE(buildRootTopCt(ctx, sender.mRootR1Rt,
                otherR, {}, message.mPublicBStarNtt, seSender.mParams.mGadgetLogBase,
                1, rejectedPrng, 0.0, 0.0, unchanged, 4, {}, nullptr, otherB.get(), nullptr, nullptr, nullptr, setupOptions));
            expect_batch_equal(unchanged.mPolys, message.mTopCt.mPolys);
            LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), referencePrng.get<oc::block>());
        }
        if (replayGpuEnabled)
        {
            // These are the two production Root geometries. BStar has two NTT
            // rows in each, and its owner is consumed before any host wire view.
            for (const bool noGoldenSeed : { false, true })
            {
                RingParams ring{};
                ring.mPolyModulusDegree = noGoldenSeed ? 16384u : 8192u;
                const std::uint32_t rho = noGoldenSeed ? 8u : 4u;
                resizeFill<int>(ring.mCoeffModulusBits, rho,
                    noGoldenSeed ? 52 : 55);
                RingNttContext productionCtx{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, productionCtx, std::make_shared<RingContextFactory>(advanced)));
                const std::uint64_t runId = noGoldenSeed ? 0xB57A5202u : 0xB57A5201u;
                ScopedProtocolCacheScope senderScope(
                    ProtocolCacheRole::Sender, runId);

                auto owner = gpu::retainRootBStarNttDevice(
                    productionCtx, 2u);
                LOGVOLE_REQUIRE_TRUE(owner != nullptr);
                LOGVOLE_REQUIRE_TRUE(gpu::retainedRootBStarNttMatches(
                    productionCtx, *owner, 2u));
                LOGVOLE_REQUIRE_FALSE(gpu::retainedRootBStarNttMatches(
                    productionCtx, *owner, 3u));
                RingNttContext reordered = productionCtx;
                LOGVOLE_REQUIRE_TRUE(reordered.mRawModuli != nullptr);
                auto reorderedModuli =
                    std::make_shared<RingModulusMetadata>(*reordered.mRawModuli);
                LOGVOLE_REQUIRE_TRUE(reorderedModuli->mValues.size() >= 2u);
                std::swap(reorderedModuli->mValues[0],
                    reorderedModuli->mValues[1]);
                reordered.mRawModuli = std::move(reorderedModuli);
                LOGVOLE_REQUIRE_FALSE(gpu::retainedRootBStarNttMatches(
                    reordered, *owner, 2u));
                {
                    ScopedProtocolCacheScope receiverScope(
                        ProtocolCacheRole::Receiver, runId);
                    LOGVOLE_REQUIRE_FALSE(gpu::retainedRootBStarNttMatches(
                        productionCtx, *owner, 2u));
                }
                {
                    ScopedProtocolCacheScope nextRun(
                        ProtocolCacheRole::Sender, runId + 1u);
                    LOGVOLE_REQUIRE_FALSE(gpu::retainedRootBStarNttMatches(
                        productionCtx, *owner, 2u));
                }
                std::shared_ptr<const gpu::RetainedPublicUniform> wrongNonce;
                LOGVOLE_REQUIRE_TRUE(retainUniformPolyBatchFromNonce(
                    productionCtx, 0xB57A52BADu, 0xB57A52BADu,
                    2u, true, wrongNonce));
                LOGVOLE_REQUIRE_FALSE(gpu::retainedRootBStarNttMatches(
                    productionCtx, *wrongNonce, 2u));

                const auto eagerBStar = deriveUniformPolyBatchFromNonce(
                    productionCtx, gpu::kRootBStarNonce,
                    gpu::kRootBStarDomain, 2u, true);
                auto r1 = sample_batch(productionCtx, rho,
                    noGoldenSeed ? 0xB57A5302u : 0xB57A5301u);
                auto r2Ntt = sample_batch(productionCtx, rho,
                    noGoldenSeed ? 0xB57A5402u : 0xB57A5401u);
                for (auto& poly : r2Ntt)
                    LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, productionCtx));
                auto publicBRootNtt = deriveUniformPolyBatchFromNonce(
                    productionCtx, 0xB57A5500u, 0xB57A5501u, 1u, true);
                const std::uint32_t gadgetLogBase = noGoldenSeed ? 208u : 110u;
                tests_libOTe::logvole_test::ScopedOptionValue rootDevice(setupOptions.mRootDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue rootStrict(setupOptions.mRootDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mRootCompactNoise, true);
                oc::PRNG eagerPrng(oc::block(0xB57A5600u, 0xB57A5601u));
                oc::PRNG retainedPrng(oc::block(0xB57A5600u, 0xB57A5601u));
                RingTensor eagerTop{}, retainedTop{};
                LOGVOLE_REQUIRE_TRUE(buildRootTopCt(productionCtx,
                    r1, r2Ntt, publicBRootNtt, eagerBStar,
                    gadgetLogBase, 1, eagerPrng, 0.0, 0.0,
                    eagerTop, 4,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions));
                const auto before = gpu::publicUniformRetentionStats(productionCtx);
                LOGVOLE_REQUIRE_TRUE(buildRootTopCt(productionCtx,
                    r1, r2Ntt, publicBRootNtt, {}, gadgetLogBase, 1,
                    retainedPrng, 0.0, 0.0, retainedTop, 4,
                    {}, nullptr, nullptr, nullptr, nullptr, owner.get(), setupOptions));
                const auto after = gpu::publicUniformRetentionStats(productionCtx);
                LOGVOLE_EXPECT_EQ(after.mHostMaterializations,
                    before.mHostMaterializations);
                expect_batch_equal(retainedTop.mPolys, eagerTop.mPolys);
                LOGVOLE_EXPECT_EQ(retainedPrng.get<oc::block>(),
                    eagerPrng.get<oc::block>());
                std::vector<RnsPoly> wireBStar;
                LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(
                    *owner, wireBStar, readbackExecution.readbackStream()));
                expect_batch_equal(wireBStar, eagerBStar);

                oc::PRNG rejectedPrng(oc::block(0xB57A5602u, 0xB57A5603u));
                oc::PRNG referencePrng(oc::block(0xB57A5602u, 0xB57A5603u));
                RingTensor unchanged = retainedTop;
                LOGVOLE_REQUIRE_FALSE(buildRootTopCt(productionCtx,
                    r1, r2Ntt, publicBRootNtt, {}, gadgetLogBase, 1,
                    rejectedPrng, 0.0, 0.0, unchanged, 4,
                    {}, nullptr, nullptr, nullptr, nullptr,
                    wrongNonce.get(), setupOptions));
                expect_batch_equal(unchanged.mPolys, retainedTop.mPolys);
                LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(),
                    referencePrng.get<oc::block>());
            }
        }
#endif
    }
}

void LogVole_Core_RootRandomizerWidthTracksGadgetBase(const oc::CLP&)
{
    Params params = make_root_params();
    params.mShrinkExpand.mRing.mPolyModulusDegree = 8192;
    params.mShrinkExpand.mTau = 2;
    params.mShrinkExpand.mGadgetLogBase = 110;
    LOGVOLE_EXPECT_EQ(rootRandomizerWidth(params.mShrinkExpand), 3u);
    const auto standaloneRootBytes = forecastRootOfflineWireSize(
        params, false);
    LOGVOLE_REQUIRE_TRUE(standaloneRootBytes > 0u);
    auto recursive = params;
    recursive.mW *= 4u;
    LOGVOLE_EXPECT_EQ(forecastRootOfflineWireSize(recursive, false),
        standaloneRootBytes);

    params.mShrinkExpand.mGadgetLogBase = 30;
    LOGVOLE_EXPECT_TRUE(rootRandomizerWidth(params.mShrinkExpand) >= 6);
    LOGVOLE_EXPECT_TRUE(forecastRootOfflineWireSize(params, false) >
        standaloneRootBytes);
    params.mShrinkExpand.mGadgetLogBase = 0u;
    LOGVOLE_EXPECT_EQ(forecastRootOfflineWireSize(params, false), 0u);
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
    const auto encoded = encode(message);
    receiver.mRootRandomizerWidth = 12345;
    LOGVOLE_EXPECT_FALSE(finalizeRootOfflineReceiver(receiver, std::move(message)));
    LOGVOLE_EXPECT_TRUE(rangesEqual(encoded, encode(message)));
    LOGVOLE_EXPECT_EQ(receiver.mRootRandomizerWidth, 12345u);
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
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(seReceiverInput, seSender, seReceiver));

    ReceiverState receiver{};
    receiver.mParams = params;
    receiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(receiver, offlineMessage));

    const std::uint32_t plainSampleBits =
        std::min<std::uint32_t>(12u, params.mShrinkExpand.mPlaintextModulusBits);
    const auto x = sample_small_plain_batch(ctx, params.mW, 0x7602u, plainSampleBits);

    RootDigestState digestState{};
    RootDigestMessage digestMessage{};
    LOGVOLE_REQUIRE_TRUE(
        prepare_root_digest_receiver_for_test(receiver, x, digestState, digestMessage, true));
    LOGVOLE_REQUIRE_EQ(digestMessage.mDPrimeCoeffs.size(), ringPolyCoeffCount(params.mShrinkExpand.mRing));
    LOGVOLE_EXPECT_FALSE(digestState.mDPrimeHashValid);
    const oc::block expectedDigestHash = hashSeedDigest(digestState.mDPrime);
    LOGVOLE_REQUIRE_TRUE(finishRootDigestHash(digestState));
    LOGVOLE_EXPECT_TRUE(digestState.mDPrimeHashValid);
    LOGVOLE_EXPECT_TRUE(digestState.mDPrimeHash == expectedDigestHash);
    // Completion is explicitly idempotent so retry/error cleanup cannot change
    // transcript state after the hash has become authoritative.
    LOGVOLE_REQUIRE_TRUE(finishRootDigestHash(digestState));
    LOGVOLE_EXPECT_TRUE(digestState.mDPrimeHash == expectedDigestHash);

    RootResponseMessage response{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_response_sender_for_test(sender, digestMessage, response));
    LOGVOLE_EXPECT_TRUE(rangesEqual(response.mSeed, sender.mGoldenSeed));
    LOGVOLE_REQUIRE_EQ(response.mSkPrimeCoeffs.size(), ringPolyCoeffCount(params.mShrinkExpand.mRing));

    // The owned sender overload consumes the decoded polynomial only after its
    // full shape has been validated, and produces the exact legacy wire bytes.
    RootDigestMessage ownedDigest = digestMessage;
    RootResponseMessage ownedResponse{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_response_sender_owned_for_test(
        sender, std::move(ownedDigest), ownedResponse));
    LOGVOLE_EXPECT_TRUE(ownedDigest.mDPrimeCoeffs.empty());
    LOGVOLE_EXPECT_FALSE(digestMessage.mDPrimeCoeffs.empty());
    const Buffer responseWire = encode(response);
    const Buffer ownedResponseWire = encode(ownedResponse);
    LOGVOLE_EXPECT_TRUE(rangesEqual(responseWire, ownedResponseWire));

    RootDigestMessage malformedDigest = digestMessage;
    malformedDigest.mDPrimeCoeffs.resize(
        malformedDigest.mDPrimeCoeffs.size() - 1u);
    const std::size_t malformedDigestSize = malformedDigest.mDPrimeCoeffs.size();
    RootResponseMessage rejectedResponse{};
    LOGVOLE_EXPECT_FALSE(prepare_root_response_sender_owned_for_test(
        sender, std::move(malformedDigest), rejectedResponse));
    LOGVOLE_EXPECT_EQ(malformedDigest.mDPrimeCoeffs.size(), malformedDigestSize);

    RnsPoly senderKey{};
    RnsPoly receiverKey{};
    LOGVOLE_REQUIRE_TRUE(computeRootSenderKey(sender, response.mSeed, senderKey));
    LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(receiver, digestState, response, receiverKey));
    LOGVOLE_EXPECT_TRUE(rangesEqual(receiver.mGoldenSeed, response.mSeed));
    LOGVOLE_EXPECT_FALSE(response.mSkPrimeCoeffs.empty());

#if defined(ENABLE_LOGVOLE_CUDA)
    // With an available GPU, retain CtR, Lacct, TopCt and BStar from an independently
    // owned Root frame. Without one, the decoder publishes eager host polys.
    // Force a real host decline after setup and compare the NTT-domain CtR and
    // complete receiver key against the direct-message reference.
    RootOfflineMessage wireRoot{};
    bool expectOwnedRootWire = false;
    {
        ScopedProtocolCacheScope receiverRole(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        expectOwnedRootWire = gpu::available() &&
            std::endian::native == std::endian::little;
        auto receivedRoot = encode(offlineMessage, 4, {}, gpu::available());
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(
            std::move(receivedRoot), wireRoot, 4, {}, gpu::available()));
    }
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireRoot.mOwnedCtRWire) == expectOwnedRootWire);
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireRoot.mOwnedLacctLeftWire) == expectOwnedRootWire);
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireRoot.mOwnedTopCtWire) == expectOwnedRootWire);
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireRoot.mOwnedPublicBStarWire) == expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireRoot.mCtR.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireRoot.mLacctLeft.mCt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireRoot.mTopCt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireRoot.mPublicBStarNtt.empty(), expectOwnedRootWire);
    if (expectOwnedRootWire)
    {
        RootOfflineMessage badBStarCount = wireRoot;
        ++badBStarCount.mPublicBStarCount;
        ReceiverState rejected{};
        rejected.mParams = params;
        rejected.mRootRandomizerWidth = 12345u;
        LOGVOLE_EXPECT_FALSE(finalizeRootOfflineReceiver(
            rejected, std::move(badBStarCount)));
        LOGVOLE_EXPECT_EQ(rejected.mRootRandomizerWidth, 12345u);
    }
    ReceiverState wireReceiver{};
    wireReceiver.mParams = params;
    wireReceiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(wireReceiver, std::move(wireRoot)));
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireReceiver.mRootCtRWire) == expectOwnedRootWire);
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireReceiver.mRootLacctLeftWire) == expectOwnedRootWire);
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireReceiver.mRootTopCtWire) == expectOwnedRootWire);
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(wireReceiver.mRootPublicBStarWire) == expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootCtRRt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootLacctLeft.mCt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootTopCt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootPublicBStarNtt.empty(), expectOwnedRootWire);
    if (expectOwnedRootWire)
    {
        // A declined GPU path must replay the same NTT-domain public BStar
        // through its once-only host view, not an eager wire decode.
        RootDigestState declinedDigest{};
        RootDigestMessage declinedMessage{};
        LOGVOLE_REQUIRE_TRUE(prepare_root_digest_receiver_for_test(
            wireReceiver, x, declinedDigest, declinedMessage, true));
        LOGVOLE_EXPECT_TRUE(rangesEqual(
            digestMessage.mDPrimeCoeffs, declinedMessage.mDPrimeCoeffs));
        LOGVOLE_EXPECT_TRUE(wireReceiver.mRootPublicBStarNtt.empty());
    }
    RnsPoly declinedKey{};
    {
        LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(
            wireReceiver, digestState, response, declinedKey));
    }
    LOGVOLE_EXPECT_TRUE(rangesEqual(receiverKey.mCoeffs, declinedKey.mCoeffs));
    if (expectOwnedRootWire)
    {
        expect_batch_equal(wireReceiver.mRootCtRWire->get().mPolys,
            receiver.mRootCtRRt.mPolys);
        expect_batch_equal(wireReceiver.mRootPublicBStarWire->get().mPolys,
            receiver.mRootPublicBStarNtt);
    }
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootCtRRt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootLacctLeft.mCt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootTopCt.mPolys.empty(), expectOwnedRootWire);
    LOGVOLE_EXPECT_EQ(wireReceiver.mRootPublicBStarNtt.empty(), expectOwnedRootWire);

    RootOfflineMessage eagerLacctRoot{};
    {
        oc::LogVoleEncodingOptions options;
        options.mRootCtREncodedReceive = false;
        options.mRootLacctEncodedReceive = false;
        ScopedProtocolCacheScope receiverRole(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        auto receivedRoot = encode(offlineMessage, 4, {}, gpu::available());
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(
            std::move(receivedRoot), eagerLacctRoot, 4, options, gpu::available()));
    }
    LOGVOLE_EXPECT_TRUE(!eagerLacctRoot.mOwnedCtRWire &&
        !eagerLacctRoot.mCtR.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(!eagerLacctRoot.mOwnedLacctLeftWire &&
        !eagerLacctRoot.mLacctLeft.mCt.mPolys.empty());
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(eagerLacctRoot.mOwnedTopCtWire) == expectOwnedRootWire);
    ReceiverState eagerLacctReceiver{};
    eagerLacctReceiver.mParams = params;
    eagerLacctReceiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(eagerLacctReceiver,
        std::move(eagerLacctRoot)));
    LOGVOLE_EXPECT_TRUE(!eagerLacctReceiver.mRootCtRWire &&
        !eagerLacctReceiver.mRootCtRRt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(!eagerLacctReceiver.mRootLacctLeftWire &&
        !eagerLacctReceiver.mRootLacctLeft.mCt.mPolys.empty());
    RnsPoly eagerLacctKey{};
    {
        LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(
            eagerLacctReceiver, digestState, response, eagerLacctKey));
    }
    LOGVOLE_EXPECT_TRUE(rangesEqual(receiverKey.mCoeffs, eagerLacctKey.mCoeffs));

    RootOfflineMessage eagerBStarRoot{};
    {
        oc::LogVoleEncodingOptions options;
        options.mRootBStarEncodedReceive = false;
        ScopedProtocolCacheScope receiverRole(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        auto receivedRoot = encode(offlineMessage, 4, {}, gpu::available());
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(
            std::move(receivedRoot), eagerBStarRoot, 4, options, gpu::available()));
    }
    LOGVOLE_EXPECT_TRUE(!eagerBStarRoot.mOwnedPublicBStarWire &&
        !eagerBStarRoot.mPublicBStarNtt.empty());
    LOGVOLE_REQUIRE_TRUE(static_cast<bool>(eagerBStarRoot.mOwnedTopCtWire) ==
        expectOwnedRootWire);
    ReceiverState eagerBStarReceiver{};
    eagerBStarReceiver.mParams = params;
    eagerBStarReceiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(
        eagerBStarReceiver, std::move(eagerBStarRoot)));
    LOGVOLE_EXPECT_TRUE(!eagerBStarReceiver.mRootPublicBStarWire &&
        !eagerBStarReceiver.mRootPublicBStarNtt.empty());
    RnsPoly eagerBStarKey{};
    {
        LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(
            eagerBStarReceiver, digestState, response, eagerBStarKey));
    }
    LOGVOLE_EXPECT_TRUE(rangesEqual(receiverKey.mCoeffs, eagerBStarKey.mCoeffs));
#endif

    // Passing no device-output slot deliberately exercises the owned overload's
    // host fallback. Its local keeps the moved sk' alive across any device-path
    // decline, while the const result remains bit-identical and unconsumed.
    RootResponseMessage consumedResponse = ownedResponse;
    RnsPoly ownedReceiverKey{};
    LOGVOLE_REQUIRE_TRUE(finalizeRootResponseReceiver(
        receiver, digestState, std::move(consumedResponse), ownedReceiverKey));
    LOGVOLE_EXPECT_TRUE(consumedResponse.mSeed.empty());
    LOGVOLE_EXPECT_TRUE(consumedResponse.mSkPrimeCoeffs.empty());
    LOGVOLE_EXPECT_TRUE(rangesEqual(receiverKey.mCoeffs, ownedReceiverKey.mCoeffs));

    RootResponseMessage malformedResponse = ownedResponse;
    malformedResponse.mSkPrimeCoeffs.resize(
        malformedResponse.mSkPrimeCoeffs.size() - 1u);
    const std::size_t malformedResponseSeedSize = malformedResponse.mSeed.size();
    const std::size_t malformedResponsePolySize =
        malformedResponse.mSkPrimeCoeffs.size();
    RnsPoly rejectedReceiverKey{};
    LOGVOLE_EXPECT_FALSE(finalizeRootResponseReceiver(
        receiver, digestState, std::move(malformedResponse), rejectedReceiverKey));
    LOGVOLE_EXPECT_EQ(malformedResponse.mSeed.size(), malformedResponseSeedSize);
    LOGVOLE_EXPECT_EQ(
        malformedResponse.mSkPrimeCoeffs.size(), malformedResponsePolySize);

    ShrinkExpandExpandSenderInput senderExpandInput{};
    senderExpandInput.mSid = params.mSessionId;
    senderExpandInput.mSeed = response.mSeed;
    senderExpandInput.mDigest = digestState.mDRt;
    senderExpandInput.mMaskDigest = digestState.mDPrime;
    senderExpandInput.mNonce = 0;
    senderExpandInput.mTbkPrime = senderKey;

    ShrinkExpandSenderExpandOutput senderExpand{};
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandSender(sender.mShrinkExpandState, senderExpandInput, senderExpand,
        sender.mShrinkExpandState.mParams.mNumWorkerThreads));

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
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandReceiver(receiver.mShrinkExpandState, receiverExpandInput, receiverExpand,
        receiver.mShrinkExpandState.mParams.mNumWorkerThreads));
    LOGVOLE_REQUIRE_EQ(senderExpand.mTbk.size(), x.size());
    LOGVOLE_REQUIRE_EQ(receiverExpand.mTbm.size(), x.size());

    for (std::size_t idx = 0; idx < x.size(); ++idx)
    {
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(senderExpand.mTbk[idx], params.mShrinkExpand.mRing));
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(receiverExpand.mTbm[idx], params.mShrinkExpand.mRing));
    }

}

void LogVole_Core_RootFinalizePrefetchExactAndCleanup(const oc::CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)

    if (!gpu::available()) return;

    const std::uint64_t runId = allocateProtocolCacheRunId();
    ScopedProtocolCacheScope receiverScope(
        ProtocolCacheRole::Receiver, runId);

    Params params = make_recursive_params(1u);
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, true, trunc));
    const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
    const std::uint32_t rho = static_cast<std::uint32_t>(
        params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    LOGVOLE_REQUIRE_EQ(params.mShrinkExpand.mRing.mPolyModulusDegree, 8192u);
    LOGVOLE_REQUIRE_EQ(rho, 4u);
    LOGVOLE_REQUIRE_EQ(tauHi, 1u);
    LOGVOLE_REQUIRE_EQ(rootLeftWidth(tauHi, rho), 4u);

    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx, std::make_shared<RingContextFactory>(advanced)));

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput = tests_libOTe::logvole_test::withAdvancedOptions(std::move(seInput), advanced, ProtocolCacheRole::Sender);
    seInput.mS = sample_batch(ctx, trunc.mMu, 0x7D8101u);
    ShrinkExpandSenderState seSender{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(seInput, seSender));

    SenderState sender{};
    sender.mParams = params;
    sender.mShrinkExpandState = seSender;
    RootOfflineMessage offlineMessage{};
    {
        ScopedProtocolCacheScope senderScope(
            ProtocolCacheRole::Sender, runId);
        LOGVOLE_REQUIRE_TRUE(
            prepare_root_offline_sender_for_test(sender, offlineMessage));
    }

    ShrinkExpandReceiverOfflineInput seReceiverInput{};
    seReceiverInput.mParams = trunc;
    seReceiverInput = tests_libOTe::logvole_test::withAdvancedOptions(std::move(seReceiverInput), advanced, ProtocolCacheRole::Receiver);
    ShrinkExpandReceiverState seReceiver{};
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(
        seReceiverInput, seSender, seReceiver));

    ReceiverState receiver{};
    receiver.mParams = params;
    receiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(receiver, offlineMessage));

    // Observe a real setup's counters through a graph that shares its context.
    // Graph traversal must count that resource domain once and weak baselines
    // must report only subsequent work. No extra GPU work is needed here.
    {
        const auto& owner = receiver.mShrinkExpandState.mRingFactoryOwner;
        LOGVOLE_REQUIRE_TRUE(owner);
        ReceiverState sharedGraph;
        sharedGraph.mShrinkExpandState.mRingFactoryOwner = owner;
        sharedGraph.mNextLevelState = std::make_unique<ReceiverState>();
        sharedGraph.mNextLevelState->mShrinkExpandState.mRingFactoryOwner = owner;
        const auto equalStats = [](const auto& a, const auto& b) {
            LOGVOLE_REQUIRE_EQ(a.mCaptures, b.mCaptures);
            LOGVOLE_REQUIRE_EQ(a.mCopies, b.mCopies);
            LOGVOLE_REQUIRE_EQ(a.mCopiedBytes, b.mCopiedBytes);
            LOGVOLE_REQUIRE_EQ(a.mMisses, b.mMisses);
            LOGVOLE_REQUIRE_EQ(a.mHostMaterializations, b.mHostMaterializations);
            LOGVOLE_REQUIRE_EQ(a.mHostMaterializedBytes, b.mHostMaterializedBytes);
        };
        RetentionBaseline observation;
        equalStats(observation.deltaTree(sharedGraph), gpu::publicUniformRetentionStats(*owner));
        observation.captureTree(sharedGraph);
        equalStats(observation.deltaTree(sharedGraph), gpu::PublicUniformRetentionStats{});
        equalStats(observation.delta(RingNttContext{}), gpu::PublicUniformRetentionStats{});
    }

    // This production tuple exercises the actual receiver Root device chain.
    // Feed the exact independent Root frame through the transport decoder so
    // CtR begins in coefficient domain on the wire, with no host scatter/NTT.
    RootOfflineMessage wireRoot{};
    {
        auto rootPayload = encode(offlineMessage, 4, {}, true);
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(
            std::move(rootPayload), wireRoot, 4, {}, true));
    }
    LOGVOLE_REQUIRE_TRUE(wireRoot.mOwnedCtRWire != nullptr);
    LOGVOLE_REQUIRE_TRUE(wireRoot.mOwnedPublicBStarWire != nullptr);
    LOGVOLE_EXPECT_TRUE(wireRoot.mCtR.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(wireRoot.mPublicBStarNtt.empty());
    ReceiverState wireReceiver{};
    wireReceiver.mParams = params;
    wireReceiver.mShrinkExpandState = seReceiver;
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(
        wireReceiver, std::move(wireRoot)));
    LOGVOLE_REQUIRE_TRUE(wireReceiver.mRootCtRWire != nullptr);
    LOGVOLE_REQUIRE_TRUE(wireReceiver.mRootPublicBStarWire != nullptr);
    LOGVOLE_EXPECT_TRUE(wireReceiver.mRootCtRRt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(wireReceiver.mRootPublicBStarNtt.empty());

    const auto x = sample_small_plain_batch(
        ctx, params.mW, 0x7D8102u,
        std::min<std::uint32_t>(
            20u, params.mShrinkExpand.mPlaintextModulusBits));
    RootDigestState digestState{};
    RootDigestMessage digestMessage{};
    LOGVOLE_REQUIRE_TRUE(prepare_root_digest_receiver_for_test(
        receiver, x, digestState, digestMessage, true));
    LOGVOLE_REQUIRE_TRUE(!digestState.mDPrimeHashValid);
    LOGVOLE_REQUIRE_TRUE(digestState.mLeftTreeGpu != nullptr);
    LOGVOLE_REQUIRE_TRUE(digestState.mTopInputsNttGpu != nullptr);

    const auto topInputs = std::static_pointer_cast<gpu::DeviceBatch>(
        digestState.mTopInputsNttGpu);
    const auto dPrimeDevice = std::static_pointer_cast<gpu::DeviceBatch>(
        digestState.mDPrimeGpu);
    LOGVOLE_REQUIRE_TRUE(dPrimeDevice != nullptr);

    // Match the production v2 ordering: the prefix is queued while the digest
    // hash is deliberately still invalid, then the authoritative hash and peer
    // response are produced before consuming it.
    gpu::PreparedRootFinalizePtr prepared;
    LOGVOLE_REQUIRE_TRUE(gpu::prefetchRootFinalizeReceiverDevice(
        receiver,
        ctx,
        digestState.mDPrime,
        topInputs,
        digestState.mLeftTreeGpu,
        tauHi,
        rootLeftWidth(tauHi, rho),
        prepared,
        dPrimeDevice));
    LOGVOLE_REQUIRE_TRUE(prepared != nullptr);
    if (gpu::rootDigestHashEnabled(ctx.mExecutionOptions))
    {
        // Require the device entry point itself to succeed; a CPU fallback in
        // finishRootDigestHash must not hide a missing or incorrect reader.
        LOGVOLE_REQUIRE_TRUE(digestState.mGpuExecution ==
            receiver.mShrinkExpandState.mRingFactoryOwner->mGpuExecution);
        oc::block actual;
        LOGVOLE_REQUIRE_TRUE(gpu::hashRootDigestDevice(*dPrimeDevice, actual,
            readbackExecution.readbackStream()));
        LOGVOLE_REQUIRE_TRUE(actual == hashSeedDigest(digestState.mDPrime));
    }
    LOGVOLE_REQUIRE_TRUE(finishRootDigestHash(digestState));
    LOGVOLE_REQUIRE_TRUE(digestState.mDPrimeHashValid);

    RootResponseMessage response{};
    {
        ScopedProtocolCacheScope senderScope(
            ProtocolCacheRole::Sender, runId);
        LOGVOLE_REQUIRE_TRUE(prepare_root_response_sender_for_test(
            sender, digestMessage, response));
    }
    RnsPoly skPrime{};
    skPrime.mCoeffs = response.mSkPrimeCoeffs;

    const auto runFinalizeFor = [&](ReceiverState& target,
                                    oc::block digestHash,
                                    gpu::PreparedRootFinalize* prepared,
                                    gpu::DeviceBatchPtr& out) {
        return gpu::rootFinalizeReceiverDevice(
            target,
            ctx,
            digestState.mDPrime,
            digestHash,
            skPrime,
            digestState.mTopInputsNtt,
            topInputs.get(),
            digestState.mLeftTreeGpu,
            std::span<const std::uint8_t>(
                response.mSeed.data(), response.mSeed.size()),
            params.mSessionId,
            tauHi,
            rootLeftWidth(tauHi, rho),
            out,
            prepared,
            dPrimeDevice.get());
    };
    const auto runFinalize = [&](oc::block digestHash,
                                 gpu::PreparedRootFinalize* prepared,
                                 gpu::DeviceBatchPtr& out) {
        return runFinalizeFor(receiver, digestHash, prepared, out);
    };

    gpu::DeviceBatchPtr splitKey;
    gpu::DeviceBatchPtr monolithicKey;
    LOGVOLE_REQUIRE_TRUE(runFinalize(
        digestState.mDPrimeHash, prepared.get(), splitKey));
    LOGVOLE_REQUIRE_TRUE(runFinalize(
        digestState.mDPrimeHash, nullptr, monolithicKey));
    std::vector<RnsPoly> splitHost;
    std::vector<RnsPoly> monolithicHost;
    LOGVOLE_REQUIRE_TRUE(gpu::download(*splitKey, splitHost, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(gpu::download(*monolithicKey, monolithicHost, readbackExecution.readbackStream()));
    expect_batch_equal(splitHost, monolithicHost);
    gpu::DeviceBatchPtr wireKey;
    LOGVOLE_REQUIRE_TRUE(runFinalizeFor(
        wireReceiver, digestState.mDPrimeHash, nullptr, wireKey));
    LOGVOLE_REQUIRE_TRUE(wireKey != nullptr);
    LOGVOLE_REQUIRE_TRUE(wireReceiver.mRootGpuCache != nullptr);
    std::vector<RnsPoly> wireHost;
    LOGVOLE_REQUIRE_TRUE(gpu::download(*wireKey, wireHost, readbackExecution.readbackStream()));
    expect_batch_equal(wireHost, monolithicHost);
    LOGVOLE_EXPECT_TRUE(wireReceiver.mRootCtRRt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(wireReceiver.mRootPublicBStarNtt.empty());

    // Model a socket exception: destroying an unconsumed successful handle must
    // wait for its event before releasing acc/phi and every retained input owner.
    gpu::PreparedRootFinalizePtr abandoned;
    LOGVOLE_REQUIRE_TRUE(gpu::prefetchRootFinalizeReceiverDevice(
        receiver,
        ctx,
        digestState.mDPrime,
        topInputs,
        digestState.mLeftTreeGpu,
        tauHi,
        rootLeftWidth(tauHi, rho),
        abandoned,
        dPrimeDevice));
    LOGVOLE_REQUIRE_TRUE(abandoned != nullptr);
    abandoned.reset();

    // The prefix is deliberately hash-independent. Bind a different
    // authoritative hash only in the response suffix and prove that the split
    // and monolithic paths feed those identical bytes into CT2.
    gpu::PreparedRootFinalizePtr alternateHash;
    LOGVOLE_REQUIRE_TRUE(gpu::prefetchRootFinalizeReceiverDevice(
        receiver,
        ctx,
        digestState.mDPrime,
        topInputs,
        digestState.mLeftTreeGpu,
        tauHi,
        rootLeftWidth(tauHi, rho),
        alternateHash,
        dPrimeDevice));
    const oc::block mismatchedHash =
        digestState.mDPrimeHash ^ oc::block(1u, 0u);
    gpu::DeviceBatchPtr mismatchFallbackKey;
    gpu::DeviceBatchPtr mismatchReferenceKey;
    LOGVOLE_REQUIRE_TRUE(runFinalize(
        mismatchedHash, alternateHash.get(), mismatchFallbackKey));
    LOGVOLE_REQUIRE_TRUE(runFinalize(
        mismatchedHash, nullptr, mismatchReferenceKey));
    std::vector<RnsPoly> mismatchFallbackHost;
    std::vector<RnsPoly> mismatchReferenceHost;
    LOGVOLE_REQUIRE_TRUE(gpu::download(
        *mismatchFallbackKey, mismatchFallbackHost, readbackExecution.readbackStream()));
    LOGVOLE_REQUIRE_TRUE(gpu::download(
        *mismatchReferenceKey, mismatchReferenceHost, readbackExecution.readbackStream()));
    expect_batch_equal(mismatchFallbackHost, mismatchReferenceHost);
    alternateHash.reset();
#endif
}

void LogVole_Core_NoGoldenSeedRootFinalizePrefetchTwoQueryExact(const oc::CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) return;

    const auto runId = allocateProtocolCacheRunId();
    ScopedProtocolCacheScope receiverScope(ProtocolCacheRole::Receiver, runId);

    CivoleParams civole{};
    LOGVOLE_REQUIRE_TRUE(makeCivoleParams(
        CivoleSetting::NoGoldenSeed, civole, 4u));
    Params params = civole.mLogVole;
    const auto rho = static_cast<std::uint32_t>(
        params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    const auto tauHi = params.mShrinkExpand.mTau - 1u;
    params.mW = params.mShrinkExpand.mAlpha * tauHi * rho;
    params.mTotalLabelCount = oc::u64{1} << 25;
    LOGVOLE_REQUIRE_EQ(params.mShrinkExpand.mRing.mPolyModulusDegree, 16384u);
    LOGVOLE_REQUIRE_EQ(rho, 8u);
    LOGVOLE_REQUIRE_EQ(tauHi, 1u);
    LOGVOLE_REQUIRE_EQ(rootLeftWidth(tauHi, rho), 8u);
    LOGVOLE_REQUIRE_EQ(params.mCt2SeedMode, Ct2SeedMode::PublicSeed);

    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, true, trunc));
    LOGVOLE_REQUIRE_EQ(trunc.mMu, 16u);
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(trunc.mRing, ctx, std::make_shared<RingContextFactory>(advanced)));

    ShrinkExpandSenderOfflineInput seInput{};
    seInput.mParams = trunc;
    seInput = tests_libOTe::logvole_test::withAdvancedOptions(std::move(seInput), advanced, ProtocolCacheRole::Sender);
    seInput.mS = sample_batch(ctx, trunc.mMu, 0x7D8201u);
    ShrinkExpandSenderState seSender{};
    SenderState sender{};
    sender.mParams = params;
    RootOfflineMessage offlineMessage{};
    {
        ScopedProtocolCacheScope senderScope(ProtocolCacheRole::Sender, runId);
        LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(seInput, seSender));
        sender.mShrinkExpandState = seSender;
        LOGVOLE_REQUIRE_TRUE(prepare_root_offline_sender_for_test(
            sender, offlineMessage));
    }

    ShrinkExpandReceiverOfflineInput seReceiverInput{};
    seReceiverInput.mParams = trunc;
    seReceiverInput = tests_libOTe::logvole_test::withAdvancedOptions(std::move(seReceiverInput), advanced, ProtocolCacheRole::Receiver);
    ShrinkExpandReceiverState seReceiver{};
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(
        seReceiverInput, seSender, seReceiver));

    // Decode an independently owned Root frame as the copied TCP receiver does.
    // Its coefficient tensors remain encoded until the receiver device chain
    // consumes them; no sender cache or host polynomial is shared with it.
    RootOfflineMessage wireRoot{};
    {
        auto rootPayload = encode(offlineMessage, 4, {}, true);
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(
            std::move(rootPayload), wireRoot, 4, {}, true));
    }
    LOGVOLE_REQUIRE_TRUE(wireRoot.mOwnedCtRWire != nullptr);
    LOGVOLE_REQUIRE_TRUE(wireRoot.mOwnedPublicBStarWire != nullptr);
    LOGVOLE_REQUIRE_TRUE(wireRoot.mCtR.mPolys.empty());
    LOGVOLE_REQUIRE_TRUE(wireRoot.mPublicBStarNtt.empty());
    ReceiverState receiver{};
    receiver.mParams = params;
    receiver.mShrinkExpandState = std::move(seReceiver);
    LOGVOLE_REQUIRE_TRUE(finalizeRootOfflineReceiver(
        receiver, std::move(wireRoot)));
    LOGVOLE_REQUIRE_TRUE(receiver.mRootCtRWire != nullptr);
    LOGVOLE_REQUIRE_TRUE(receiver.mRootPublicBStarWire != nullptr);
    LOGVOLE_REQUIRE_TRUE(receiver.mRootCtRRt.mPolys.empty());
    LOGVOLE_REQUIRE_TRUE(receiver.mRootPublicBStarNtt.empty());

    for (std::uint64_t query = 0; query != 2; ++query)
    {
        sender.mParams.mSessionId = query;
        receiver.mParams.mSessionId = query;
        const auto x = sample_small_plain_batch(
            ctx, params.mW, 0x7D8202u + query, 20u);
        RootDigestState digestState{};
        RootDigestMessage digestMessage{};
        oc::PRNG receiverPrng(oc::block(0x7D8203u, query));
        LOGVOLE_REQUIRE_TRUE(prepareRootDigestReceiver(
            receiver, x, receiverPrng, digestState, digestMessage,
            {}, 0, true));
        LOGVOLE_REQUIRE_TRUE(!digestState.mDPrimeHashValid);
        LOGVOLE_REQUIRE_TRUE(digestState.mLeftTreeGpu != nullptr);
        LOGVOLE_REQUIRE_TRUE(digestState.mTopInputsNttGpu != nullptr);
        const auto topInputs = std::static_pointer_cast<gpu::DeviceBatch>(
            digestState.mTopInputsNttGpu);
        const auto dPrimeDevice = std::static_pointer_cast<gpu::DeviceBatch>(
            digestState.mDPrimeGpu);
        LOGVOLE_REQUIRE_TRUE(topInputs != nullptr);
        LOGVOLE_REQUIRE_TRUE(dPrimeDevice != nullptr);

        gpu::PreparedRootFinalizePtr prepared;
        LOGVOLE_REQUIRE_TRUE(gpu::prefetchRootFinalizeReceiverDevice(
            receiver, ctx, digestState.mDPrime, topInputs,
            digestState.mLeftTreeGpu, tauHi, rootLeftWidth(tauHi, rho),
            prepared, dPrimeDevice));
        LOGVOLE_REQUIRE_TRUE(prepared != nullptr);
        LOGVOLE_REQUIRE_TRUE(finishRootDigestHash(digestState));
        LOGVOLE_REQUIRE_TRUE(digestState.mDPrimeHashValid);

        RootResponseMessage response{};
        {
            ScopedProtocolCacheScope senderScope(
                ProtocolCacheRole::Sender, runId);
            oc::PRNG senderPrng(oc::block(0x7D8204u, query));
            LOGVOLE_REQUIRE_TRUE(tests_libOTe::logvole_test::prepareRootResponse(
                sender, digestMessage, senderPrng, response));
        }
        LOGVOLE_REQUIRE_TRUE(response.mSeed.empty());
        RnsPoly skPrime{};
        skPrime.mCoeffs = response.mSkPrimeCoeffs;
        std::array<std::uint8_t, 16> publicSeed{};
        derivePublicCt2Seed(
            query, digestState.mDPrimeHash,
            std::span<std::uint8_t>(publicSeed), params.mOnlineMode);

        const auto finalize = [&](gpu::PreparedRootFinalize* prefix,
                                  gpu::DeviceBatchPtr& out) {
            return gpu::rootFinalizeReceiverDevice(
                receiver, ctx, digestState.mDPrime,
                digestState.mDPrimeHash, skPrime,
                digestState.mTopInputsNtt, topInputs.get(),
                digestState.mLeftTreeGpu,
                std::span<const std::uint8_t>(publicSeed), query,
                tauHi, rootLeftWidth(tauHi, rho), out,
                prefix, dPrimeDevice.get());
        };
        gpu::DeviceBatchPtr splitKey;
        LOGVOLE_REQUIRE_TRUE(finalize(prepared.get(), splitKey));
        LOGVOLE_REQUIRE_TRUE(splitKey != nullptr);
        std::vector<RnsPoly> splitHost;
        LOGVOLE_REQUIRE_TRUE(gpu::download(*splitKey, splitHost, readbackExecution.readbackStream()));
        prepared.reset();

        gpu::DeviceBatchPtr monolithicKey;
        LOGVOLE_REQUIRE_TRUE(finalize(nullptr, monolithicKey));
        LOGVOLE_REQUIRE_TRUE(monolithicKey != nullptr);
        std::vector<RnsPoly> monolithicHost;
        LOGVOLE_REQUIRE_TRUE(gpu::download(*monolithicKey, monolithicHost, readbackExecution.readbackStream()));
        expect_batch_equal(splitHost, monolithicHost);
        LOGVOLE_REQUIRE_TRUE(receiver.mRootCtRRt.mPolys.empty());
        LOGVOLE_REQUIRE_TRUE(receiver.mRootPublicBStarNtt.empty());
    }
#endif
}

void LogVole_Core_RootOnlineStateReuseAcrossQueries(const oc::CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    // Check the public host outputs directly, including their final Z_p relation.
#endif
    Params params = make_golden_params();
    params.mW = params.mShrinkExpand.mAlpha * (params.mShrinkExpand.mTau - 1u) *
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    params.mTotalLabelCount = static_cast<std::uint64_t>(params.mW) *
        params.mShrinkExpand.mRing.mPolyModulusDegree;
    constexpr std::uint64_t delta = 19;
    oc::PRNG senderPrng(oc::block(1, 2)), receiverPrng(oc::block(3, 4));
    ZpCrtContext ctx;
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mShrinkExpand.mRing,
        params.mShrinkExpand.mPlaintextModulusBits, ctx));
    SenderOfflineInput senderInput;
    senderInput.mParams = params;
    senderInput.mSk1.resize(1);
    LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(ctx, delta, true, 1, senderInput.mSk1[0]));
    SenderOfflineOutput senderOffline;
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(senderInput, senderPrng, senderOffline));
    ReceiverOfflineInput receiverInput;
    receiverInput.mParams = params;
    ReceiverOfflineOutput receiverOffline;
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput,
        senderOffline.mMessage, receiverOffline));
    auto& sender = senderOffline.mState;
    auto& receiver = receiverOffline.mState;
    ReceiverOfflineOutput referenceOffline;
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput, senderOffline.mMessage, referenceOffline));
    auto& referenceState = referenceOffline.mState;

    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    std::array<LheDecryptBuffer, 3> lheBuffers;
    std::array<LencEvalBuffer, 3> lencBuffers;
    for (auto& buffer : lheBuffers)
        buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(receiver.mShrinkExpandState.mParams.mRing));
    const auto terms = std::size_t{2} * std::max(receiver.mRootLacctLeft.mLevels,
        receiver.mShrinkExpandState.hostLacct().mLevels) *
        (receiver.mShrinkExpandState.mParams.mTau + 1);
    for (auto& buffer : lencBuffers)
    {
        buffer.mCiphertexts.reserve(terms);
        buffer.mNodes.reserve(terms);
    }
    std::array<const std::uint64_t*, 3> productAllocations;
    std::array<const RnsPoly* const*, 3> ciphertextAllocations, nodeAllocations;
    for (std::size_t i = 0; i < lheBuffers.size(); ++i)
    {
        productAllocations[i] = lheBuffers[i].mProduct.mCoeffs.data();
        ciphertextAllocations[i] = lencBuffers[i].mCiphertexts.data();
        nodeAllocations[i] = lencBuffers[i].mNodes.data();
    }
    auto onWorker = [](macoro::thread_pool& pool, macoro::task<bool> operation) -> macoro::task<bool> {
        co_await pool.schedule();
        co_return co_await std::move(operation);
    };
    for (std::uint64_t query = 0; query < 2; ++query)
    {
        sender.mParams.mSessionId = receiver.mParams.mSessionId = query;
        std::vector<std::uint64_t> x(params.mTotalLabelCount, 7 + query);
        ReceiverOnlineInput input;
        input.mSid = query;
        LOGVOLE_REQUIRE_TRUE(wrapZpLabelsCrt(ctx, x, false, 0, 1, input.mX));
        RootDigestState digest;
        RootDigestMessage request;
        LOGVOLE_REQUIRE_TRUE(prepareRootDigestReceiver(receiver, input.mX,
            receiverPrng, digest, request));
        RootResponseMessage response;
        SenderOnlineOutput senderOutput;
        ReceiverOnlineOutput receiverOutput;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onWorker(executor, prepareRootOnlineSender(executor, lheBuffers, sender, request,
            senderPrng, response, senderOutput))));
        const auto cachedKeys = sender.mPrecomputedTbk;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(senderPrecompute(executor, lheBuffers, sender, senderPrng)));
        LOGVOLE_EXPECT_TRUE(sender.mPrecomputedTbk == cachedKeys);
        referenceState.mParams.mSessionId = query;
        ReceiverOnlineOutput reference;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(finalizeRootOnlineReceiver(executor, lheBuffers, lencBuffers, referenceState, input, digest, response, reference)));
        if (query == 1) digest.mLeftTree.reset(); // Exercise exact tree reconstruction.
        const auto oldRoot = receiver.mRootDPrimeRt;
        const auto oldSeed = receiver.mGoldenSeed;
        // Own the response before starting: its original object is destroyed here.
        auto operation = [&] {
            auto owned = response;
            return finalizeRootOnlineReceiver(executor, lheBuffers, lencBuffers,
                receiver, input, digest, std::move(owned), receiverOutput);
        }();
        LOGVOLE_REQUIRE_TRUE(receiver.mRootDPrimeRt == oldRoot);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(receiver.mGoldenSeed, oldSeed));
        auto moved = std::move(operation);
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onWorker(executor, std::move(moved))));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(receiverOutput.mSeed, reference.mSeed));
        LOGVOLE_REQUIRE_EQ(receiverOutput.mTbm.size(), reference.mTbm.size());
        for (std::size_t i = 0; i < reference.mTbm.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(receiverOutput.mTbm[i].mCoeffs, reference.mTbm[i].mCoeffs));
        for (std::size_t i = 0; i < lheBuffers.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(lheBuffers[i].mProduct.mCoeffs.data() == productAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mCiphertexts.data() == ciphertextAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mNodes.data() == nodeAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mCiphertexts.empty() && lencBuffers[i].mNodes.empty());
        }
        // Neither a failed key evaluation nor a failed final expansion publishes output.
        const auto publishedRoot = receiver.mRootDPrimeRt;
        auto failedOutput = receiverOutput;
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(finalizeRootOnlineReceiver(executor, lheBuffers, {},
            receiver, input, digest, response, failedOutput)));
        LOGVOLE_REQUIRE_TRUE(receiver.mRootDPrimeRt == publishedRoot);
        LencEvalBuffer prefixOnly;
        const auto prefixTerms = std::size_t{2} * receiver.mRootLacctLeft.mLevels *
            (params.mShrinkExpand.mTau - 1);
        prefixOnly.mCiphertexts.reserve(prefixTerms);
        prefixOnly.mNodes.reserve(prefixTerms);
        receiver.mGoldenSeed.clear();
        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(finalizeRootOnlineReceiver(executor, lheBuffers,
            std::span(&prefixOnly, 1), receiver, input, digest, response, failedOutput)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(receiver.mGoldenSeed, response.mSeed));
        LOGVOLE_REQUIRE_TRUE(receiver.mRootDPrimeRt == publishedRoot);
        for (std::size_t i = 0; i < reference.mTbm.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(failedOutput.mTbm[i].mCoeffs, reference.mTbm[i].mCoeffs));
        AlignedUnVec<std::uint64_t> keys, macs;
        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(ctx, senderOutput.mTbk,
            x.size(), true, 1, keys));
        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(ctx, receiverOutput.mTbm,
            x.size(), true, 1, macs));
        LOGVOLE_REQUIRE_EQ(keys.size(), x.size());
        LOGVOLE_REQUIRE_EQ(macs.size(), x.size());
        for (std::size_t i = 0; i < x.size(); ++i)
            LOGVOLE_EXPECT_EQ(macs[i], mulAddMod(x[i], delta, keys[i],
                seal::Modulus(ctx.mPlaintextModulus))) << "query " << query << " slot " << i;
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
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(seReceiverInput, seSender, seReceiver));

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
    LOGVOLE_EXPECT_TRUE(digestState.mDPrimeHashValid);

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
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandSender(sender.mShrinkExpandState, senderExpandInput, senderExpand,
        sender.mShrinkExpandState.mParams.mNumWorkerThreads));

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
    LOGVOLE_REQUIRE_TRUE(shrinkExpandExpandReceiver(receiver.mShrinkExpandState, receiverExpandInput, receiverExpand,
        receiver.mShrinkExpandState.mParams.mNumWorkerThreads));

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

void LogVole_Core_GpuSetupOptions(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0)) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!cmd.getOr("gpu", 0)) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    Params params = make_recursive_params(2);
    params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));
    SenderOfflineInput input{};
    input.mParams = params;
    input.mSk1 = sample_batch(ctx, params.mGamma, 0x5091u);
    input.mUseGpuResidentInternalState = true;
    const auto run = [&](oc::LogVoleGpuSetupOptions options, oc::LogVoleExecutionOptions advanced = {}) {
        advanced.mUseGpu = true;
        ScopedProtocolCacheScope scope(ProtocolCacheRole::Sender, allocateProtocolCacheRunId());
        auto selected = input;
        selected.mParams.mShrinkExpand.mGpuSetup = options;
        RingNttContext configured;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, configured,
            std::make_shared<RingContextFactory>(advanced)));
        selected.mRingFactoryOwner = configured.mFactoryOwner;
        oc::PRNG prng(oc::block(0x5092u, 0));
        coproto::BufferingSocket socket;
        LogVoleRingSender sender;
        SenderState state;
        RootWirePinOverlapEvidence rootWirePin;
        macoro::sync_wait(sender.offline(selected, state, prng, socket, rootWirePin));
        macoro::sync_wait(socket.flush());
        auto bytes = socket.getOutbound();
        LOGVOLE_REQUIRE_TRUE(bytes && !bytes->empty());
        for (auto* level = &state; level; level = level->mNextLevelState.get())
        {
            LOGVOLE_REQUIRE_TRUE(level->mShrinkExpandState.mRingFactoryOwner);
            LOGVOLE_REQUIRE_TRUE(level->mShrinkExpandState.mRingFactoryOwner->mExecutionOptions == advanced);
            LOGVOLE_REQUIRE_EQ(level->mParams.mShrinkExpand.mGpuSetup.mDirectWire, options.mDirectWire);
            LOGVOLE_REQUIRE_EQ(level->mParams.mShrinkExpand.mGpuSetup.mLazyCiphertexts, options.mLazyCiphertexts);
        }
        return std::make_pair(Buffer(bytes->begin(), bytes->end()), prng.get<oc::block>());
    };
    const auto baseline = run({});
    oc::LogVoleExecutionOptions advanced;
    advanced.mAdvanced.mStreams.mLazyIndexScratch = oc::LogVoleChoice::Enabled;
    advanced.mAdvanced.mStreams.mIndexScratchKiB = 256;
    advanced.mAdvanced.mStreams.mPipelinedUpload = true;
    advanced.mAdvanced.mStreams.mDownloadSlotMiB = 1;
    advanced.mAdvanced.mStreams.mPolyStageMiB = 1;
    advanced.mAdvanced.mStreams.mReuseDownloadStaging = false;
    advanced.mAdvanced.mStreams.mDownloadReuseWorkers = false;
    advanced.mAdvanced.mProtocol.mLencRandomizerResidency = false;
    advanced.mAdvanced.mProtocol.mPublicUniformRetention = false;
    advanced.mAdvanced.mProtocol.mUniformSampling = false;
    advanced.mAdvanced.mProtocol.mUniformSamplingStrict = true;
    advanced.mAdvanced.mProtocol.mShareCache = false;
    advanced.mAdvanced.mProtocol.mShareSenderCache = false;
    advanced.mAdvanced.mProtocol.mLeafBDevice = false;
    advanced.mAdvanced.mProtocol.mSenderPublicAOnly = false;
    advanced.mAdvanced.mProtocol.mExtraPipelinedDownload = false;
    advanced.mAdvanced.mProtocol.mPipelinedDownload = false;
    advanced.mAdvanced.mProtocol.mDirectDownload = false;
    const auto configured = run({}, advanced);
    LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.first, configured.first));
    LOGVOLE_REQUIRE_TRUE(baseline.second == configured.second);
    // Each rollback must preserve wire bytes and parent PRNG consumption.
    for (auto member : { &oc::LogVoleGpuSetupOptions::mDirectWire,
            &oc::LogVoleGpuSetupOptions::mLazyCiphertexts,
            &oc::LogVoleGpuSetupOptions::mRootPublicBToken,
            &oc::LogVoleGpuSetupOptions::mRootBStarDevice,
            &oc::LogVoleGpuSetupOptions::mRootR1Device,
            &oc::LogVoleGpuSetupOptions::mRootSecretDevice,
            &oc::LogVoleGpuSetupOptions::mBatchNtt,
            &oc::LogVoleGpuSetupOptions::mParallelCopy,
            &oc::LogVoleGpuSetupOptions::mParallelMessageCopy,
            &oc::LogVoleGpuSetupOptions::mSharedState,
            &oc::LogVoleGpuSetupOptions::mRootDevice,
            &oc::LogVoleGpuSetupOptions::mRootCompactNoise,
            &oc::LogVoleGpuSetupOptions::mLencDevice,
            &oc::LogVoleGpuSetupOptions::mLheDevice,
            &oc::LogVoleGpuSetupOptions::mLencDevicePadding,
            &oc::LogVoleGpuSetupOptions::mCompactNoise,
            &oc::LogVoleGpuSetupOptions::mLencRandomizerOutput })
    {
        oc::LogVoleGpuSetupOptions options;
        options.*member = false;
        const auto actual = run(options);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.first, actual.first));
        LOGVOLE_REQUIRE_TRUE(baseline.second == actual.second);
    }
    oc::LogVoleGpuSetupOptions strict;
    strict.mRootDeviceStrict = true;
    strict.mRootCompactNoiseStrict = true;
    strict.mLencDeviceStrict = true;
    strict.mLheDeviceStrict = true;
    strict.mCompactNoiseStrict = true;
    strict.mLencRandomizerOutputStrict = true;
    strict.mRootBStarDeviceStrict = true;
    strict.mRootR1DeviceStrict = true;
    strict.mRootSecretDeviceStrict = true;
    const auto actual = run(strict);
    LOGVOLE_REQUIRE_TRUE(rangesEqual(baseline.first, actual.first));
    LOGVOLE_REQUIRE_TRUE(baseline.second == actual.second);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA";
#endif
}

void LogVole_Core_GpuResidentSetupState(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
    // Force the transfer pipeline even for small fixtures, which the
    // production default deliberately keeps on the simpler download path.
    tests_libOTe::logvole_test::ScopedOptionValue receiverPipeline(advanced.mAdvanced.mProtocol.mReceiverPipelinedDownload, osuCrypto::LogVoleChoice::Enabled);
    tests_libOTe::logvole_test::ScopedOptionValue residentNttDefault(setupOptions.mReceiverResidentNtt, false);
    tests_libOTe::logvole_test::ScopedOptionValue residentNttStrictDefault(setupOptions.mReceiverResidentNttStrict, false);

#if defined(ENABLE_LOGVOLE_CUDA)
    if (advanced.mUseGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
#else
    (void)cmd;
#endif
    tests_libOTe::logvole_test::ScopedOptionValue sharedState(setupOptions.mSharedState, true);
    bool senderDevice = false, receiverDevice = false;
#if defined(ENABLE_LOGVOLE_CUDA)
    {
        ScopedProtocolCacheScope scope(ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
        senderDevice = gpu::enabled(advanced);
    }
    {
        ScopedProtocolCacheScope scope(ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        receiverDevice = gpu::enabled(advanced);
    }
    if (senderDevice || receiverDevice)
    {
        ScopedProtocolCacheScope scope(senderDevice ? ProtocolCacheRole::Sender : ProtocolCacheRole::Receiver,
            currentProtocolCacheScope().mRunId);

        gpu::GpuStream uploadStream, downloadStream;

        constexpr std::size_t bytes = (std::size_t{1} << 20) + 19u;
        const auto pattern = [](std::size_t i) {
            return static_cast<oc::u8>((i * 29u + (i >> 10u)) & 255u);
        };
        for (bool registerFirst : { false, true })
        {
            // The full fixture deliberately provokes an already-registered API error.
            // The bounded settings check keeps CUDA API-error reporting strict.
            if (cmd.getOr("lvFactoryFast", 0) && registerFirst) continue;
            // Offsets also exercise wire headers that do not align ciphertext
            // spans to either machine words or pages. Guards remain outside it.
            std::vector<oc::u8> source(bytes + 8u, 0xa5u), destination(bytes + 10u, 0x5au);
            auto* sourceSpan = source.data() + 3u;
            auto* destinationSpan = destination.data() + 5u;
            struct WireCleanup
            {
                gpu::GpuStream& upload;
                gpu::GpuStream& download;
                gpu::OwnedGpuBuffer device;
                void* registeredSource = nullptr;
                void* registeredDestination = nullptr;
                ~WireCleanup()
                {
                    // Assertions can throw after either enqueue or registration.
                    // Drain before unregistering or allowing host vectors to die.
                    if (!upload.sync() || !download.sync()) std::terminate();
                    if (registeredSource) (void)gpu::gpuUnregisterHost(registeredSource);
                    if (registeredDestination) (void)gpu::gpuUnregisterHost(registeredDestination);
                }
            } cleanup{ uploadStream, downloadStream };
            cleanup.device = gpu::OwnedGpuBuffer(uploadStream.allocationOwner(), bytes);
            LOGVOLE_REQUIRE_TRUE(cleanup.device);
            for (std::size_t i = 0; i < bytes; ++i) sourceSpan[i] = pattern(i);
            if (registerFirst)
            {
                bool registered = false;
                const bool sourceOk = gpu::gpuTryRegisterHost(sourceSpan, bytes, registered);
                if (registered) cleanup.registeredSource = sourceSpan;
                LOGVOLE_REQUIRE_TRUE(sourceOk);
                registered = false;
                const bool destinationOk = gpu::gpuTryRegisterHost(destinationSpan, bytes, registered);
                if (registered) cleanup.registeredDestination = destinationSpan;
                LOGVOLE_REQUIRE_TRUE(destinationOk);
                // Unsupported registration still exercises the ordinary copy
                // fallback. Supported devices now force an already-registered
                // decline when each helper attempts its own registration.
            }
            LOGVOLE_REQUIRE_TRUE(gpu::uploadSetupWire(cleanup.device.data(), {sourceSpan, bytes}, uploadStream));
            // A synchronous upload permits immediate source reuse. Transfer
            // allocation ownership before the consumer uses another stream.
            std::fill(sourceSpan, sourceSpan + bytes, 0u);
            cleanup.device.handoff(downloadStream.allocationOwner());
            LOGVOLE_REQUIRE_TRUE(gpu::downloadSetupWire({destinationSpan, bytes}, cleanup.device.data(), downloadStream));
            std::size_t firstMismatch = 0;
            while (firstMismatch < bytes && destinationSpan[firstMismatch] == pattern(firstMismatch))
                ++firstMismatch;
            LOGVOLE_EXPECT_EQ(firstMismatch, bytes);
            LOGVOLE_EXPECT_EQ(source.front(), 0xa5u);
            LOGVOLE_EXPECT_EQ(source.back(), 0xa5u);
            LOGVOLE_EXPECT_EQ(destination.front(), 0x5au);
            LOGVOLE_EXPECT_EQ(destination.back(), 0x5au);
            const char* error = nullptr;
            const bool noError = gpu::gpuLastErrorOk(&error);
            LOGVOLE_REQUIRE_TRUE(noError) << (error ? error : "");
            if (cleanup.registeredSource)
            {
                LOGVOLE_REQUIRE_TRUE(gpu::gpuUnregisterHost(cleanup.registeredSource));
                cleanup.registeredSource = nullptr;
            }
            if (cleanup.registeredDestination)
            {
                LOGVOLE_REQUIRE_TRUE(gpu::gpuUnregisterHost(cleanup.registeredDestination));
                cleanup.registeredDestination = nullptr;
            }
        }
    }
#endif
    Params params = make_recursive_params(3);
    if (cmd.getOr("lvFactoryFast", 0)) params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
    params.mShrinkExpand.mNumWorkerThreads = 4;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx, std::make_shared<RingContextFactory>(advanced)));
    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mSk1 = sample_batch(ctx, params.mGamma, 0x781234u);
    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    const oc::block seed(0x5245534944454E54ull, 0x123456789ull);
    oc::PRNG baselinePrng(seed, 3), residentPrng(seed, 3), wirePrng(seed, 3), legacyWirePrng(seed, 3);
    SenderOfflineOutput baselineSender{}, residentSender{};
    ReceiverOfflineOutput baselineReceiver{}, residentReceiver{};
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), baselinePrng, baselineSender));
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), baselineSender.mMessage, baselineReceiver));
    senderInput.mUseGpuResidentInternalState = true;
    receiverInput.mUseGpuResidentInternalState = true;
    LOGVOLE_REQUIRE_TRUE(prepareSenderOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), residentPrng, residentSender));
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), residentSender.mMessage, residentReceiver));
    SenderOfflineOutput wireSender{}, legacyWireSender{};
    {
        senderInput.mParams.mShrinkExpand.mGpuSetup.mDirectWire = true;
        LOGVOLE_REQUIRE_TRUE(detail::prepareSenderOfflineForTransport(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), wirePrng, wireSender));
    }
    {
        senderInput.mParams.mShrinkExpand.mGpuSetup.mDirectWire = false;
        LOGVOLE_REQUIRE_TRUE(detail::prepareSenderOfflineForTransport(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), legacyWirePrng, legacyWireSender));
    }
    senderInput.mParams.mShrinkExpand.mGpuSetup.mDirectWire = true;
    for (unsigned i = 0; i < 16; ++i)
    {
        const auto expected = baselinePrng.get<std::uint64_t>();
        LOGVOLE_EXPECT_EQ(expected, residentPrng.get<std::uint64_t>());
        LOGVOLE_EXPECT_EQ(expected, wirePrng.get<std::uint64_t>());
        LOGVOLE_EXPECT_EQ(expected, legacyWirePrng.get<std::uint64_t>());
    }

    // Only socket preparation substitutes independently owned wire bytes for
    // the message tensor clone. Public preparation retains mutable messages,
    // including when its recursive state explicitly opts into GPU residency.
    auto* wireMessage = &wireSender.mMessage;
    const auto* legacyWireMessage = &legacyWireSender.mMessage;
    const auto* wireState = &wireSender.mState;
    const auto* expectedWireMessage = &baselineSender.mMessage;
    while (wireMessage && legacyWireMessage && wireState && expectedWireMessage)
    {
        LOGVOLE_EXPECT_TRUE(legacyWireMessage->mEncodedShrinkExpandMessage.empty());
        LOGVOLE_EXPECT_EQ(wireMessage->mHasShrinkExpandMessage, expectedWireMessage->mHasShrinkExpandMessage);
        if (wireMessage->mHasShrinkExpandMessage)
        {
            const auto expected = encode(expectedWireMessage->mShrinkExpandMessage);
            LOGVOLE_EXPECT_TRUE(rangesEqual(expected, encode(legacyWireMessage->mShrinkExpandMessage)));
            LOGVOLE_EXPECT_EQ(!wireMessage->mEncodedShrinkExpandMessage.empty(), senderDevice);
            if (senderDevice)
            {
                const auto& lazySender = wireState->mShrinkExpandState;
                LOGVOLE_REQUIRE_TRUE(lazySender.mLazyCt1 != nullptr);
                LOGVOLE_REQUIRE_TRUE(lazySender.mLazyLacct != nullptr);
                LOGVOLE_EXPECT_TRUE(lazySender.mCt1.mPolys.empty());
                LOGVOLE_EXPECT_TRUE(lazySender.mLacct.mCt.mPolys.empty());
                LOGVOLE_EXPECT_TRUE(wireMessage->mShrinkExpandMessage.mCt1.mPolys.empty());
                LOGVOLE_EXPECT_TRUE(wireMessage->mShrinkExpandMessage.mLacct.mCt.mPolys.empty());
                LOGVOLE_EXPECT_TRUE(rangesEqual(expected, wireMessage->mEncodedShrinkExpandMessage));
                // Altering owned transport bytes cannot modify the sender's
                // retained host fallback, including immutable recursive views.
                wireMessage->mEncodedShrinkExpandMessage.back() ^= 1u;
                LOGVOLE_EXPECT_TRUE(rangesEqual(expected,
                    encodeShrinkExpandOfflineState(wireState->mShrinkExpandState, 4)));
                wireMessage->mEncodedShrinkExpandMessage.back() ^= 1u;
                LOGVOLE_REQUIRE_TRUE(decodeShrinkExpandOfflineForTransport(
                    std::move(wireMessage->mEncodedShrinkExpandMessage),
                    wireMessage->mShrinkExpandMessage, 4, {}, receiverDevice));
                wireMessage->mEncodedShrinkExpandMessage.clear();
                const auto& received = wireMessage->mShrinkExpandMessage;
                LOGVOLE_EXPECT_EQ(static_cast<bool>(received.mLazyCt1), receiverDevice);
                LOGVOLE_EXPECT_EQ(static_cast<bool>(received.mLazyLacct), receiverDevice);
                if (receiverDevice)
                {
                    LOGVOLE_EXPECT_TRUE(received.mCt1.mPolys.empty());
                    LOGVOLE_EXPECT_TRUE(received.mLacct.mCt.mPolys.empty());
                    LOGVOLE_EXPECT_EQ(received.mLazyCt1->encodedCoefficients().size(),
                        ringTensorSize(received.mCt1) * ringPolyCoeffCount(params.mShrinkExpand.mRing) * sizeof(oc::u64));
                }
            }
            if (!wireMessage->mShrinkExpandMessage.mLazyCt1)
                LOGVOLE_EXPECT_TRUE(rangesEqual(expected, encode(wireMessage->mShrinkExpandMessage)));
            else
            {
                // Public serialization resolves lazy storage exactly. Use a
                // separate owner so this read cannot prepopulate the receiver
                // path whose first lazy materialization is checked below.
                auto roundTripBytes = expected;
                ShrinkExpandOfflineMessage roundTrip{};
                LOGVOLE_REQUIRE_TRUE(decodeShrinkExpandOfflineForTransport(std::move(roundTripBytes), roundTrip, 4, {}, gpu::enabled(advanced)));
                LOGVOLE_REQUIRE_TRUE(roundTrip.mLazyCt1 && roundTrip.mLazyLacct);
                LOGVOLE_EXPECT_TRUE(rangesEqual(expected, encode(roundTrip, 4)));
            }
        }
        else
            LOGVOLE_EXPECT_TRUE(wireMessage->mEncodedShrinkExpandMessage.empty());
        if (!wireMessage->mNextLevel)
            LOGVOLE_EXPECT_TRUE(rangesEqual(encode(expectedWireMessage->mRootMessage), encode(wireMessage->mRootMessage)));
        wireMessage = wireMessage->mNextLevel.get();
        legacyWireMessage = legacyWireMessage->mNextLevel.get();
        wireState = wireState->mNextLevelState.get();
        expectedWireMessage = expectedWireMessage->mNextLevel.get();
    }
    LOGVOLE_EXPECT_TRUE(!wireMessage && !legacyWireMessage && !wireState && !expectedWireMessage);
    ReceiverOfflineOutput wireReceiver{};
    {
        tests_libOTe::logvole_test::ScopedOptionValue residentNtt(setupOptions.mReceiverResidentNtt, true);
        tests_libOTe::logvole_test::ScopedOptionValue strictNtt(setupOptions.mReceiverResidentNttStrict, true);
        LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), std::move(wireSender.mMessage), wireReceiver));
    }
    for (const ReceiverState* level = &wireReceiver.mState; level; level = level->mNextLevelState.get())
    {
        const auto& lazy = level->mShrinkExpandState;
        LOGVOLE_EXPECT_EQ(static_cast<bool>(lazy.mLazyCt1Ntt), receiverDevice);
        if (receiverDevice)
        {
            LOGVOLE_REQUIRE_TRUE(lazy.mGpuCache != nullptr);
            LOGVOLE_EXPECT_TRUE(lazy.mCt1.mPolys.empty());
            if (senderDevice)
            {
                LOGVOLE_REQUIRE_TRUE(lazy.mLazyLacct != nullptr);
                LOGVOLE_EXPECT_TRUE(lazy.mLacct.mCt.mPolys.empty());
            }
        }
    }

    // Race the first explicit fallback read: all readers must observe one
    // completed immutable publication, without changing the compact views.
    const auto concurrentHostReads = [](const auto& state) {
        std::array<const RingTensor*, 4> tensors{};
        std::array<const ShrinkExpandLacct*, 4> laccts{};
        std::array<std::exception_ptr, 4> errors{};
        std::array<std::thread, 4> readers;
        std::atomic<unsigned> ready{0};
        std::atomic<bool> start{false};
        for (unsigned i = 0; i < readers.size(); ++i)
            readers[i] = std::thread([&, i] {
                ++ready;
                while (!start.load()) std::this_thread::yield();
                try
                {
                    tensors[i] = &state.hostCt1();
                    laccts[i] = &state.hostLacct();
                }
                catch (...) { errors[i] = std::current_exception(); }
            });
        while (ready.load() != readers.size()) std::this_thread::yield();
        start = true;
        for (auto& reader : readers) reader.join();
        for (unsigned i = 0; i < readers.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(errors[i] == nullptr);
            LOGVOLE_REQUIRE_TRUE(tensors[i] != nullptr && laccts[i] != nullptr);
            LOGVOLE_EXPECT_TRUE(tensors[i] == tensors[0]);
            LOGVOLE_EXPECT_TRUE(laccts[i] == laccts[0]);
        }
    };
    concurrentHostReads(wireSender.mState.mShrinkExpandState);
    concurrentHostReads(wireReceiver.mState.mShrinkExpandState);
    if (senderDevice)
    {
        // Changed metadata must not let an export fallback write a larger
        // tensor into the buffer reserved for the advertised dimensions.
        auto malformed = wireSender.mState.mShrinkExpandState;
        ++malformed.mCt1.mRows;
        bool rejected = false;
        try { (void)encodeShrinkExpandOfflineState(malformed, 2); }
        catch (const std::invalid_argument&) { rejected = true; }
        LOGVOLE_EXPECT_TRUE(rejected);
        malformed = wireSender.mState.mShrinkExpandState;
        malformed.mLazyLacct.reset();
        rejected = false;
        try { (void)encodeShrinkExpandOfflineState(malformed, 2); }
        catch (const std::invalid_argument&) { rejected = true; }
        LOGVOLE_EXPECT_TRUE(rejected);
    }
    for (const SenderState* actual = &wireSender.mState, *expected = &baselineSender.mState;
        actual && expected; actual = actual->mNextLevelState.get(), expected = expected->mNextLevelState.get())
    {
        expect_batch_equal(expected->mShrinkExpandState.mCt1.mPolys, actual->mShrinkExpandState.hostCt1().mPolys);
        expect_batch_equal(expected->mShrinkExpandState.mLacct.mCt.mPolys, actual->mShrinkExpandState.hostLacct().mCt.mPolys);
        if (senderDevice) LOGVOLE_EXPECT_TRUE(actual->mShrinkExpandState.mCt1.mPolys.empty());
    }
    for (const ReceiverState* actual = &wireReceiver.mState, *expected = &baselineReceiver.mState;
        actual && expected; actual = actual->mNextLevelState.get(), expected = expected->mNextLevelState.get())
    {
        expect_batch_equal(expected->mShrinkExpandState.mCt1.mPolys, actual->mShrinkExpandState.hostCt1().mPolys);
        expect_batch_equal(expected->mShrinkExpandState.mLacct.mCt.mPolys, actual->mShrinkExpandState.hostLacct().mCt.mPolys);
        if (receiverDevice) LOGVOLE_EXPECT_TRUE(actual->mShrinkExpandState.mCt1.mPolys.empty());
    }

    const OfflineMessage* referenceMessage = &baselineSender.mMessage;
    const OfflineMessage* actualMessage = &residentSender.mMessage;
    while (referenceMessage && actualMessage)
    {
        LOGVOLE_EXPECT_EQ(referenceMessage->mHasShrinkExpandMessage, actualMessage->mHasShrinkExpandMessage);
        if (referenceMessage->mHasShrinkExpandMessage)
            LOGVOLE_EXPECT_TRUE(rangesEqual(encode(referenceMessage->mShrinkExpandMessage), encode(actualMessage->mShrinkExpandMessage)));
        if (!referenceMessage->mNextLevel)
            LOGVOLE_EXPECT_TRUE(rangesEqual(encode(referenceMessage->mRootMessage), encode(actualMessage->mRootMessage)));
        referenceMessage = referenceMessage->mNextLevel.get();
        actualMessage = actualMessage->mNextLevel.get();
    }
    LOGVOLE_EXPECT_TRUE(!referenceMessage && !actualMessage);

    auto expectStorage = [](const auto& reference, const auto& actual, bool isView) {
        LOGVOLE_EXPECT_TRUE(reference.mSharedHostState == nullptr);
        LOGVOLE_EXPECT_EQ(static_cast<bool>(actual.mSharedHostState), isView);
        expect_batch_equal(reference.mCt1.mPolys, actual.hostCt1().mPolys);
        expect_batch_equal(reference.mLacct.mCt.mPolys, actual.hostLacct().mCt.mPolys);
        LOGVOLE_EXPECT_EQ(reference.mCt1.mRows, actual.mCt1.mRows);
        LOGVOLE_EXPECT_EQ(reference.mCt1.mCols, actual.mCt1.mCols);
        LOGVOLE_EXPECT_EQ(reference.mLacct.mWidthPadded, actual.mLacct.mWidthPadded);
        LOGVOLE_EXPECT_EQ(reference.mLacct.mLevels, actual.mLacct.mLevels);
        if (isView)
        {
            LOGVOLE_EXPECT_TRUE(actual.mCt1.mPolys.empty());
            LOGVOLE_EXPECT_TRUE(actual.mLacct.mCt.mPolys.empty());
            LOGVOLE_EXPECT_TRUE(actual.mSharedHostState->mSharedHostState == nullptr);
            LOGVOLE_EXPECT_TRUE(actual.mGpuCache != nullptr);
        }
    };
    const SenderState* referenceSender = &baselineSender.mState;
    const SenderState* actualSender = &residentSender.mState;
    const ReceiverState* referenceReceiver = &baselineReceiver.mState;
    const ReceiverState* actualReceiver = &residentReceiver.mState;
    bool top = true;
    while (referenceSender && actualSender && referenceReceiver && actualReceiver)
    {
        const auto& s = actualSender->mShrinkExpandState;
        const auto& r = actualReceiver->mShrinkExpandState;
        expectStorage(referenceSender->mShrinkExpandState, s, !top && senderDevice);
        expectStorage(referenceReceiver->mShrinkExpandState, r, !top && receiverDevice);
        expect_batch_equal(referenceSender->mShrinkExpandState.mS, s.hostS());
        expect_batch_equal(referenceSender->mShrinkExpandState.mR, s.hostR());
        expect_batch_equal(referenceSender->mShrinkExpandState.mSk1, s.hostSk1());
        if (s.mSharedHostState)
        {
            LOGVOLE_EXPECT_TRUE(s.mS.empty() && s.mR.empty());
            LOGVOLE_EXPECT_TRUE(s.mSharedHostState == residentSender.mState.mNextLevelState->mShrinkExpandState.mSharedHostState);
        }
        if (r.mSharedHostState)
            LOGVOLE_EXPECT_TRUE(r.mSharedHostState == residentReceiver.mState.mNextLevelState->mShrinkExpandState.mSharedHostState);
        referenceSender = referenceSender->mNextLevelState.get();
        actualSender = actualSender->mNextLevelState.get();
        referenceReceiver = referenceReceiver->mNextLevelState.get();
        actualReceiver = actualReceiver->mNextLevelState.get();
        top = false;
    }
    LOGVOLE_EXPECT_TRUE(!referenceSender && !actualSender && !referenceReceiver && !actualReceiver);

    // A public conversion from the sender package must resolve the original
    // coefficient-domain Ct1, even though an internal view holds no vectors.
    ShrinkExpandReceiverOfflineInput seInput{};
    seInput.mParams = residentSender.mState.mNextLevelState->mShrinkExpandState.mParams;
    ShrinkExpandReceiverState converted{};
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(
        tests_libOTe::logvole_test::withSetupOptions(seInput, setupOptions), residentSender.mState.mNextLevelState->mShrinkExpandState, converted));
    expect_batch_equal(converted.mCt1.mPolys, baselineReceiver.mState.mNextLevelState->mShrinkExpandState.mCt1.mPolys);

#if defined(ENABLE_LOGVOLE_CUDA)
    if (receiverDevice)
    {
        // A dropped device mirror can be rebuilt from the immutable backup;
        // the opt-in view itself remains compact.
        auto rebuild = residentReceiver.mState.mNextLevelState->mShrinkExpandState;
        const auto oldCache = rebuild.mGpuCache;
        rebuild.mGpuCache.reset();
        LOGVOLE_REQUIRE_TRUE(gpu::prepareReusableReceiverCache(rebuild));
        LOGVOLE_EXPECT_TRUE(rebuild.mGpuCache != oldCache);
        LOGVOLE_EXPECT_TRUE(rebuild.mCt1.mPolys.empty());
    }
#endif

    // CPU fallback consumes the very same tensors after GPU setup, with no
    // materialization or resampling. This also tests CPU-only builds/requests.
    ReceiverOnlineInput onlineInput{};
    onlineInput.mX = sample_small_plain_batch(ctx, params.mW, 0x7862u, 20u);
    SenderOnlineOutput referenceK{}, actualK{}, wireK{};
    ReceiverOnlineOutput referenceM{}, actualM{}, wireM{};
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        for (auto* state : {&baselineSender.mState, &residentSender.mState, &wireSender.mState})
            useCpuReference(*state, ProtocolCacheRole::Sender);
        for (auto* state : {&baselineReceiver.mState, &residentReceiver.mState, &wireReceiver.mState})
            useCpuReference(*state, ProtocolCacheRole::Receiver);
#endif
        LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(baselineSender.mState, baselineReceiver.mState, onlineInput, referenceK, referenceM));
        LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(residentSender.mState, residentReceiver.mState, onlineInput, actualK, actualM));
        LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(wireSender.mState, wireReceiver.mState, onlineInput, wireK, wireM));
    }
    expect_batch_equal(referenceK.mTbk, wireK.mTbk);
    expect_batch_equal(referenceM.mTbm, wireM.mTbm);
    LOGVOLE_EXPECT_TRUE(rangesEqual(referenceK.mSeed, wireK.mSeed));
    LOGVOLE_EXPECT_TRUE(rangesEqual(referenceM.mSeed, wireM.mSeed));
    LOGVOLE_EXPECT_EQ(referenceK.mComm.mBytesSent, wireK.mComm.mBytesSent);
    LOGVOLE_EXPECT_EQ(referenceK.mComm.mBytesReceived, wireK.mComm.mBytesReceived);
    LOGVOLE_EXPECT_EQ(referenceM.mComm.mBytesSent, wireM.mComm.mBytesSent);
    LOGVOLE_EXPECT_EQ(referenceM.mComm.mBytesReceived, wireM.mComm.mBytesReceived);
    expect_batch_equal(referenceK.mTbk, actualK.mTbk);
    expect_batch_equal(referenceM.mTbm, actualM.mTbm);
    LOGVOLE_EXPECT_TRUE(rangesEqual(referenceK.mSeed, actualK.mSeed));
    LOGVOLE_EXPECT_TRUE(rangesEqual(referenceM.mSeed, actualM.mSeed));
    LOGVOLE_EXPECT_EQ(referenceK.mComm.mBytesSent, actualK.mComm.mBytesSent);
    LOGVOLE_EXPECT_EQ(referenceK.mComm.mBytesReceived, actualK.mComm.mBytesReceived);
    LOGVOLE_EXPECT_EQ(referenceM.mComm.mBytesSent, actualM.mComm.mBytesSent);
    LOGVOLE_EXPECT_EQ(referenceM.mComm.mBytesReceived, actualM.mComm.mBytesReceived);

    // Materialization must sever lazy ownership as well as the device cache.
    // A sibling retains its original bytes after the producer package dies.
    auto detachedSender = wireSender.mState.mShrinkExpandState;
    auto detachedReceiver = wireReceiver.mState.mShrinkExpandState;
    std::weak_ptr<const LazyRingTensorHostState> lazySenderOwner = detachedSender.mLazyCt1;
    std::weak_ptr<const LazyRingTensorHostState> lazyReceiverOwner = detachedReceiver.mLazyCt1Ntt;
    wireSender = {};
    wireReceiver = {};
    if (senderDevice) LOGVOLE_EXPECT_FALSE(lazySenderOwner.expired());
    if (receiverDevice) LOGVOLE_EXPECT_FALSE(lazyReceiverOwner.expired());
    auto lazySenderSibling = detachedSender;
    auto lazyReceiverSibling = detachedReceiver;
    materializeShrinkExpandHostState(detachedSender);
    materializeShrinkExpandHostState(detachedReceiver);
    LOGVOLE_EXPECT_TRUE(!detachedSender.mSharedHostState && !detachedSender.mLazyCt1 &&
        !detachedSender.mLazyLacct && !detachedSender.mGpuCache);
    LOGVOLE_EXPECT_TRUE(!detachedReceiver.mSharedHostState && !detachedReceiver.mLazyCt1Ntt &&
        !detachedReceiver.mLazyLacct && !detachedReceiver.mGpuCache);
    const auto checkIndependentCopies = [](auto& detached, const auto& sibling) {
        expect_batch_equal(detached.mCt1.mPolys, sibling.hostCt1().mPolys);
        expect_batch_equal(detached.mLacct.mCt.mPolys, sibling.hostLacct().mCt.mPolys);
        const auto ct1 = sibling.hostCt1().mPolys[0].mCoeffs[0];
        const auto lacct = sibling.hostLacct().mCt.mPolys[0].mCoeffs[0];
        detached.mCt1.mPolys[0].mCoeffs[0] ^= 1u;
        detached.mLacct.mCt.mPolys[0].mCoeffs[0] ^= 1u;
        LOGVOLE_EXPECT_EQ(sibling.hostCt1().mPolys[0].mCoeffs[0], ct1);
        LOGVOLE_EXPECT_EQ(sibling.hostLacct().mCt.mPolys[0].mCoeffs[0], lacct);
    };
    checkIndependentCopies(detachedSender, lazySenderSibling);
    checkIndependentCopies(detachedReceiver, lazyReceiverSibling);
    lazySenderSibling = {};
    lazyReceiverSibling = {};
    LOGVOLE_EXPECT_TRUE(lazySenderOwner.expired() && lazyReceiverOwner.expired());

    auto keptSender = residentSender.mState.mNextLevelState->mShrinkExpandState;
    auto keptReceiver = residentReceiver.mState.mNextLevelState->mShrinkExpandState;
    std::weak_ptr<const ShrinkExpandSenderState> senderOwner = keptSender.mSharedHostState;
    std::weak_ptr<const ShrinkExpandReceiverState> receiverOwner = keptReceiver.mSharedHostState;
    residentSender = {};
    residentReceiver = {};
    if (senderDevice) LOGVOLE_EXPECT_FALSE(senderOwner.expired());
    if (receiverDevice) LOGVOLE_EXPECT_FALSE(receiverOwner.expired());
    auto siblingSender = keptSender;
    auto siblingReceiver = keptReceiver;
    materializeShrinkExpandHostState(keptSender);
    materializeShrinkExpandHostState(keptReceiver);
    LOGVOLE_EXPECT_TRUE(!keptSender.mSharedHostState && !keptSender.mGpuCache);
    LOGVOLE_EXPECT_TRUE(!keptReceiver.mSharedHostState && !keptReceiver.mGpuCache);
    expect_batch_equal(keptSender.mS, siblingSender.hostS());
    expect_batch_equal(keptSender.mR, siblingSender.hostR());
    expect_batch_equal(keptSender.mCt1.mPolys, siblingSender.hostCt1().mPolys);
    expect_batch_equal(keptReceiver.mCt1.mPolys, siblingReceiver.hostCt1().mPolys);
    const auto originalS = siblingSender.hostS()[0].mCoeffs[0];
    const auto originalCt = siblingReceiver.hostLacct().mCt.mPolys[0].mCoeffs[0];
    keptSender.mS[0].mCoeffs[0] ^= 1u;
    keptReceiver.mLacct.mCt.mPolys[0].mCoeffs[0] ^= 1u;
    LOGVOLE_EXPECT_EQ(siblingSender.hostS()[0].mCoeffs[0], originalS);
    LOGVOLE_EXPECT_EQ(siblingReceiver.hostLacct().mCt.mPolys[0].mCoeffs[0], originalCt);
    siblingSender = {};
    siblingReceiver = {};
    LOGVOLE_EXPECT_TRUE(senderOwner.expired() && receiverOwner.expired());

    // Explicit rollback and unavailable eager caches retain the full public
    // host representation instead of publishing an unusable compact view.
    for (bool sharedState : {false, true})
    {
        tests_libOTe::logvole_test::ScopedOptionValue stateOption(setupOptions.mSharedState, sharedState);
        tests_libOTe::logvole_test::ScopedOptionValue disabled(advanced.mAdvanced.mProtocol.mShareCache, !sharedState);
        SenderOfflineOutput fallbackSender{};
        ReceiverOfflineOutput fallbackReceiver{};
        LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), fallbackSender));
        LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), fallbackSender.mMessage, fallbackReceiver));
        for (const SenderState* level = &fallbackSender.mState; level; level = level->mNextLevelState.get())
        {
            LOGVOLE_EXPECT_TRUE(level->mShrinkExpandState.mSharedHostState == nullptr);
            LOGVOLE_EXPECT_FALSE(level->mShrinkExpandState.mCt1.mPolys.empty());
        }
        for (const ReceiverState* level = &fallbackReceiver.mState; level; level = level->mNextLevelState.get())
        {
            LOGVOLE_EXPECT_TRUE(level->mShrinkExpandState.mSharedHostState == nullptr);
            LOGVOLE_EXPECT_FALSE(level->mShrinkExpandState.mCt1.mPolys.empty());
        }
    }
#if defined(ENABLE_LOGVOLE_CUDA)
    if (receiverDevice)
    {
        // Retain the receiver's own transformed Ct1; the sender's message and
        // full public host snapshots must remain byte-for-byte identical.
        for (unsigned shape = 0; shape < 3; ++shape)
        {
            if (cmd.getOr("lvFactoryFast", 0) && shape != 0) continue;
            RingParams ring = params.mShrinkExpand.mRing;
            if (shape)
            {
                ring.mPolyModulusDegree = shape == 1 ? 8192 : 16384;
                ring.mCoeffModulusBits.resize(shape == 1 ? 4 : 8);
                std::fill(ring.mCoeffModulusBits.begin(), ring.mCoeffModulusBits.end(), shape == 1 ? 55 : 52);
            }
            RingNttContext ringCtx{};
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, ringCtx, std::make_shared<RingContextFactory>(advanced)));
            for (bool truncated : {false, true})
            {
                ShrinkExpandReceiverOfflineInput input{};
                input.mParams = params.mShrinkExpand;
                input.mParams.mRing = ring;
                input.mParams.mMu = 3;
                input.mParams.mTau = 2;
                input.mParams.mPlaintextModulusBits = 20;
                input.mParams.mGadgetLogBase = 20;
                input.mParams.mTruncateOneGadgetDigit = truncated;
                input.mParams.mLeafInputsAreGadget = false;
                ShrinkExpandOfflineMessage wire{};
                wire.mParams = input.mParams;
                wire.mCt1.mRows = 3;
                wire.mCt1.mCols = 2;
                wire.mCt1.mPolys = sample_batch(ringCtx, 6, 0x725300u + shape);
                wire.mLacct.mWidthPadded = 4;
                wire.mLacct.mLevels = 2;
                wire.mLacct.mCt.mRows = 8;
                wire.mLacct.mCt.mCols = 4;
                wire.mLacct.mCt.mPolys = sample_batch(ringCtx, 32, 0x725400u + shape);
                for (auto& poly : wire.mCt1.mPolys)
                {
                    poly.mCoeffs[0] = std::numeric_limits<std::uint64_t>::max();
                    poly.mCoeffs[1] = ringModulusValue(ringCtx, 0);
                }
                const auto encodedWire = encode(wire);
                ShrinkExpandReceiverState cpuReference{};
                {
                    tests_libOTe::logvole_test::ScopedOptionValue cpuOnly(advanced.mUseGpu, false);
                    LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Receiver), wire, cpuReference));
                }
                const auto checkHost = [&](const ShrinkExpandReceiverState& actual) {
                    expect_batch_equal(cpuReference.mCt1.mPolys, actual.mCt1.mPolys);
                    expect_batch_equal(cpuReference.mLacct.mCt.mPolys, actual.mLacct.mCt.mPolys);
                    LOGVOLE_EXPECT_EQ(actual.mCt1.mRows, cpuReference.mCt1.mRows);
                    LOGVOLE_EXPECT_EQ(actual.mCt1.mCols, cpuReference.mCt1.mCols);
                    LOGVOLE_EXPECT_EQ(actual.mLacct.mWidthPadded, cpuReference.mLacct.mWidthPadded);
                    LOGVOLE_EXPECT_EQ(actual.mLacct.mLevels, cpuReference.mLacct.mLevels);
                };
                tests_libOTe::logvole_test::ScopedOptionValue residentNtt(setupOptions.mReceiverResidentNtt, true);
                tests_libOTe::logvole_test::ScopedOptionValue strictNtt(setupOptions.mReceiverResidentNttStrict, true);
                for (std::uint32_t workers : {1u, 4u})
                {
                    input.mParams.mNumWorkerThreads = workers;
                    wire.mParams = input.mParams;
                    for (const char* batchMode : {"0", "1"})
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue batch(setupOptions.mBatchNtt, (batchMode)[0] != '0');
                        ShrinkExpandReceiverState actual{};
                        LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Receiver), wire, actual));
                        checkHost(actual);
                        LOGVOLE_REQUIRE_TRUE(actual.mGpuCache != nullptr);
                        const auto retained = actual.mGpuCache;
                        LOGVOLE_REQUIRE_TRUE(gpu::prepareReusableReceiverCache(actual));
                        LOGVOLE_EXPECT_TRUE(actual.mGpuCache == retained);
                        // Reinitializing a state replaces its completed mirror.
                        auto movedWire = wire;
                        LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Receiver), std::move(movedWire), actual));
                        checkHost(actual);
                        LOGVOLE_EXPECT_TRUE(actual.mGpuCache && actual.mGpuCache != retained);
                    }
                }
                wire.mParams.mNumWorkerThreads = cpuReference.mParams.mNumWorkerThreads;
                LOGVOLE_EXPECT_TRUE(rangesEqual(encodedWire, encode(wire)));
                input.mParams = wire.mParams;

                // The transport decoder owns the original coefficient bytes;
                // GPU finalization retains NTT Ct1 and encoded Lacct without
                // publishing either large host tensor. Destroy the message
                // before first host access to exercise receiver ownership.
                auto payload = encode(wire);
                ShrinkExpandOfflineMessage encoded{};
                LOGVOLE_REQUIRE_TRUE(decodeShrinkExpandOfflineForTransport(std::move(payload), encoded, 4, {}, gpu::enabled(advanced)));
                LOGVOLE_REQUIRE_TRUE(encoded.mLazyCt1 && encoded.mLazyLacct);
                LOGVOLE_EXPECT_TRUE(encoded.mCt1.mPolys.empty() && encoded.mLacct.mCt.mPolys.empty());
                auto lazyInput = input;
                lazyInput.mDeferHostSnapshot = true;
                ShrinkExpandReceiverState lazyState{};
                RetentionBaseline beforeRetainedReceiver;
                beforeRetainedReceiver.capture(ringCtx);
                if (cpuReference.mRingFactoryOwner)
                    beforeRetainedReceiver.capture(*cpuReference.mRingFactoryOwner);
                LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(lazyInput, setupOptions), advanced, ProtocolCacheRole::Receiver), std::move(encoded), lazyState));
                LOGVOLE_REQUIRE_TRUE(lazyState.mRingFactoryOwner);
                const auto afterRetainedReceiver = beforeRetainedReceiver.delta(*lazyState.mRingFactoryOwner);
                LOGVOLE_REQUIRE_TRUE(lazyState.mLazyCt1Ntt && lazyState.mLazyLacct && lazyState.mGpuCache);
                LOGVOLE_EXPECT_TRUE(lazyState.mCt1.mPolys.empty() && lazyState.mLacct.mCt.mPolys.empty());
                LOGVOLE_EXPECT_TRUE(!lazyState.mPublicANtt && !lazyState.mPublicBNtt);
                LOGVOLE_REQUIRE_TRUE(lazyState.mPublicANttDevice && lazyState.mPublicBNttDevice);
                LOGVOLE_EXPECT_EQ(afterRetainedReceiver.mHostMaterializations, 0u);
                encoded = {};
                payload.clear();
                {
                    // The host getter replays the retained wire independently.
                    concurrentHostReads(lazyState);
                    expect_batch_equal(cpuReference.mCt1.mPolys, lazyState.hostCt1().mPolys);
                    expect_batch_equal(cpuReference.mLacct.mCt.mPolys, lazyState.hostLacct().mCt.mPolys);
                }
                LOGVOLE_EXPECT_TRUE(lazyState.mCt1.mPolys.empty() && lazyState.mLacct.mCt.mPolys.empty());
                materializeShrinkExpandHostState(lazyState);
                checkHost(lazyState);
                LOGVOLE_REQUIRE_TRUE(lazyState.mPublicANtt && lazyState.mPublicBNtt);
                expect_batch_equal(*cpuReference.mPublicANtt, *lazyState.mPublicANtt);
                expect_batch_equal(*cpuReference.mPublicBNtt, *lazyState.mPublicBNtt);
                LOGVOLE_EXPECT_TRUE(!lazyState.mPublicANttDevice && !lazyState.mPublicBNttDevice);
                LOGVOLE_EXPECT_TRUE(!lazyState.mLazyCt1Ntt && !lazyState.mLazyLacct && !lazyState.mGpuCache);

                if (shape == 0 && !truncated)
                {
                    std::vector<Buffer> malformed;
                    auto invalidShape = wire;
                    ++invalidShape.mCt1.mRows;
                    malformed.push_back(encode(invalidShape));
                    invalidShape = wire;
                    ++invalidShape.mLacct.mLevels;
                    malformed.push_back(encode(invalidShape));
                    malformed.push_back(encode(wire));
                    malformed.back().resize(malformed.back().size() - 1);
                    malformed.push_back(encode(wire));
                    malformed.back().resize(malformed.back().size() / 2);
                    malformed.push_back(encode(wire));
                    const auto originalSize = malformed.back().size();
                    malformed.back().resize(originalSize + 1);
                    malformed.back()[originalSize] = 0;
                    for (auto& bad : malformed)
                    {
                        auto untouched = wire;
                        untouched.mCt1.mPolys[0].mCoeffs[0] ^= 1u;
                        const auto before = encode(untouched);
                        LOGVOLE_EXPECT_FALSE(decodeShrinkExpandOfflineForTransport(std::move(bad), untouched, 4, {}, gpu::enabled(advanced)));
                        LOGVOLE_EXPECT_TRUE(rangesEqual(before, encode(untouched)));
                        LOGVOLE_EXPECT_TRUE(!untouched.mLazyCt1 && !untouched.mLazyLacct);
                    }
                    auto validBytes = encode(wire);
                    ShrinkExpandOfflineMessage invalidLazy{};
                    LOGVOLE_REQUIRE_TRUE(decodeShrinkExpandOfflineForTransport(std::move(validBytes), invalidLazy, 4, {}, gpu::enabled(advanced)));
                    ++invalidLazy.mCt1.mCols;
                    auto unchanged = cpuReference;
                    unchanged.mCt1.mPolys[0].mCoeffs[0] ^= 1u;
                    const auto markerValue = unchanged.mCt1.mPolys[0].mCoeffs[0];
                    LOGVOLE_EXPECT_FALSE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withSetupOptions(lazyInput, setupOptions), std::move(invalidLazy), unchanged));
                    LOGVOLE_EXPECT_EQ(unchanged.mCt1.mPolys[0].mCoeffs[0], markerValue);
                    LOGVOLE_EXPECT_TRUE(!unchanged.mGpuCache && !unchanged.mLazyCt1Ntt);

                    // CPU-only transport retains the public eager contract.
                    auto cpuBytes = encode(wire);
                    ShrinkExpandOfflineMessage cpuDecoded{};
                    LOGVOLE_REQUIRE_TRUE(decodeShrinkExpandOfflineForTransport(std::move(cpuBytes), cpuDecoded, 4));
                    LOGVOLE_EXPECT_TRUE(!cpuDecoded.mLazyCt1 && !cpuDecoded.mLazyLacct);
                    LOGVOLE_EXPECT_TRUE(rangesEqual(encode(wire), encode(cpuDecoded)));
                }

                for (const char* failurePoint : {"1", "2"})
                {
                    tests_libOTe::logvole_test::ScopedOptionValue decline(advanced.mAdvanced.mProtocol.mFailures.mReceiverResidentNtt, (failurePoint)[0] == '1' ? osuCrypto::LogVoleFailureStage::BeforeWork : osuCrypto::LogVoleFailureStage::AfterWork);
                    tests_libOTe::logvole_test::ScopedOptionValue rawDecline(
                        ringCtx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mReceiverResidentNtt,
                        advanced.mAdvanced.mProtocol.mFailures.mReceiverResidentNtt);
                    // Direct helper failure before or after the actual device
                    // NTT must retain the same coefficient-domain fallback.
                    auto raw = cpuReference;
                    raw.mCt1 = wire.mCt1;
                    LOGVOLE_EXPECT_FALSE(gpu::finalizeReceiverSetupDevice(ringCtx, raw));
                    LOGVOLE_EXPECT_TRUE(raw.mGpuCache == nullptr);
                    expect_batch_equal(raw.mCt1.mPolys, wire.mCt1.mPolys);
                    expect_batch_equal(raw.mLacct.mCt.mPolys, wire.mLacct.mCt.mPolys);
                    auto marker = cpuReference;
                    marker.mCt1.mPolys[0].mCoeffs[0] ^= 1u;
                    const auto markerValue = marker.mCt1.mPolys[0].mCoeffs[0];
                    LOGVOLE_EXPECT_FALSE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Receiver), wire, marker));
                    LOGVOLE_EXPECT_EQ(marker.mCt1.mPolys[0].mCoeffs[0], markerValue);
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue fallback(setupOptions.mReceiverResidentNttStrict, false);
                        LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(input, setupOptions), advanced, ProtocolCacheRole::Receiver), wire, marker));
                    }
                    checkHost(marker);
                    LOGVOLE_EXPECT_TRUE(marker.mGpuCache == nullptr);
                    LOGVOLE_EXPECT_TRUE(marker.mPublicANtt && marker.mPublicBNtt);
                    LOGVOLE_EXPECT_TRUE(!marker.mPublicANttDevice && !marker.mPublicBNttDevice);

                    auto encodedBytes = encode(wire);
                    ShrinkExpandOfflineMessage encodedFailure{};
                    LOGVOLE_REQUIRE_TRUE(decodeShrinkExpandOfflineForTransport(std::move(encodedBytes), encodedFailure, 4, {}, gpu::enabled(advanced)));
                    marker.mCt1.mPolys[0].mCoeffs[0] ^= 1u;
                    const auto encodedMarkerValue = marker.mCt1.mPolys[0].mCoeffs[0];
                    LOGVOLE_EXPECT_FALSE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(lazyInput, setupOptions), advanced, ProtocolCacheRole::Receiver), std::move(encodedFailure), marker));
                    LOGVOLE_EXPECT_EQ(marker.mCt1.mPolys[0].mCoeffs[0], encodedMarkerValue);
                    LOGVOLE_EXPECT_TRUE(!marker.mGpuCache && !marker.mLazyCt1Ntt && !marker.mLazyLacct);
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue fallback(setupOptions.mReceiverResidentNttStrict, false);
                        LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(lazyInput, setupOptions), advanced, ProtocolCacheRole::Receiver), std::move(encodedFailure), marker));
                    }
                    checkHost(marker);
                    LOGVOLE_EXPECT_TRUE(!marker.mGpuCache && !marker.mLazyCt1Ntt && !marker.mLazyLacct);
                }
                auto invalid = cpuReference;
                invalid.mCt1 = wire.mCt1;
                invalid.mCt1.mCols += 1;
                LOGVOLE_EXPECT_FALSE(gpu::finalizeReceiverSetupDevice(ringCtx, invalid));
                expect_batch_equal(invalid.mCt1.mPolys, wire.mCt1.mPolys);
            }
        }
    }
#endif
}

void LogVole_Core_ThreeLevelOfflineReuseAndInvalidWidth(const oc::CLP& cmd)
{
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext operationExecution;
#endif

#if defined(ENABLE_LOGVOLE_CUDA)
    osuCrypto::LogVole::gpu::GpuExecutionContext readbackExecution;
#endif

    // This fixture isolates recursive eager-cache sharing. The separate
    // resident-state fixture covers optional top-level NTT cache retention.
    tests_libOTe::logvole_test::ScopedOptionValue residentNtt(setupOptions.mReceiverResidentNtt, false);
#if defined(ENABLE_LOGVOLE_CUDA)
    if (gpu::enabled(advanced))
    {
        const auto seed = oc::block(0x414553435452ull, 0x123456789ull);
        for (std::size_t count : { 1u, 2u, 3u, 257u, 1025u, 8193u })
        for (std::uint64_t modulus : { std::uint64_t{1}, std::uint64_t{3},
                (std::uint64_t{1} << 61u) - 1u, std::numeric_limits<std::uint64_t>::max() })
        {
            // Odd counts and several AES buffer boundaries must match the
            // exact scalar stream, including a deliberately short CPU buffer.
            oc::PRNG reference(seed, 3);
            auto generated = gpu::sampleScalarsFromSeed(seed, count, modulus, operationExecution.mainStream());
            LOGVOLE_REQUIRE_TRUE(generated != nullptr);
            LOGVOLE_REQUIRE_EQ(generated->count(), count);
            LOGVOLE_EXPECT_TRUE(generated->producerStream() == nullptr);
            std::vector<std::uint64_t> values(count);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*generated, values, readbackExecution.readbackStream()));
            for (auto value : values)
                LOGVOLE_REQUIRE_EQ(value, reference.get<std::uint64_t>() % modulus);
        }
        LOGVOLE_EXPECT_TRUE(gpu::sampleScalarsFromSeed(seed, 0u, 3u, operationExecution.mainStream()) == nullptr);
        LOGVOLE_EXPECT_TRUE(gpu::sampleScalarsFromSeed(seed, 3u, 0u, operationExecution.mainStream()) == nullptr);
    }
#endif
    tests_libOTe::logvole_test::ScopedOptionValue serialCopy(setupOptions.mParallelCopy, false);
    tests_libOTe::logvole_test::ScopedOptionValue serialMessageCopy(setupOptions.mParallelMessageCopy, false);
    tests_libOTe::logvole_test::ScopedOptionValue stagedDownload(advanced.mAdvanced.mProtocol.mDirectDownload, false);
    Params params = make_recursive_params(3);
    if (cmd.getOr("lvFactoryFast", 0)) params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
    params.mShrinkExpand.mNumWorkerThreads = 4;

    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx, std::make_shared<RingContextFactory>(advanced)));

    SenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mCpuScratch = std::make_shared<detail::ShrinkExpandScratch>();
    senderInput.mSk1 = sample_batch(ctx, std::max<std::uint32_t>(1u, params.mGamma), 0x7851u);

    SenderOfflineOutput senderOffline{};
    LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), senderOffline));
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mNextLevelState != nullptr);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mState.mNextLevelState->mNextLevelState != nullptr);
    LOGVOLE_EXPECT_TRUE(senderOffline.mMessage.mHasShrinkExpandMessage);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mMessage.mNextLevel != nullptr);
    LOGVOLE_EXPECT_TRUE(senderOffline.mMessage.mNextLevel->mHasShrinkExpandMessage);
    LOGVOLE_REQUIRE_TRUE(senderOffline.mMessage.mNextLevel->mNextLevel != nullptr);
    LOGVOLE_EXPECT_FALSE(senderOffline.mMessage.mNextLevel->mNextLevel->mHasShrinkExpandMessage);

#if defined(ENABLE_LOGVOLE_CUDA)
    bool senderDeviceEnabled = false;
    {
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
        senderDeviceEnabled = gpu::enabled(advanced);
    }
    auto expectSharedSenderCache = [&](const SenderOfflineOutput& output) {
        if (!senderDeviceEnabled) return;
        const auto& top = output.mState.mShrinkExpandState;
        const auto& internal = output.mState.mNextLevelState->mShrinkExpandState;
        const auto& root = output.mState.mNextLevelState->mNextLevelState->mShrinkExpandState;
        LOGVOLE_EXPECT_TRUE(top.mGpuCache == nullptr);
        LOGVOLE_REQUIRE_TRUE(internal.mGpuCache != nullptr);
        LOGVOLE_EXPECT_TRUE(root.mGpuCache == internal.mGpuCache);
    };
    expectSharedSenderCache(senderOffline);
    if (senderDeviceEnabled)
    {
        SenderOfflineOutput lazySender;
        {
            tests_libOTe::logvole_test::ScopedOptionValue disabledSenderCache(advanced.mAdvanced.mProtocol.mShareSenderCache, false);
            LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), lazySender));
        }
        for (const SenderState* level = &lazySender.mState; level; level = level->mNextLevelState.get())
            LOGVOLE_EXPECT_TRUE(level->mShrinkExpandState.mGpuCache == nullptr);

        const auto oldCache = senderOffline.mState.mNextLevelState->mShrinkExpandState.mGpuCache;
        LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), senderOffline));
        expectSharedSenderCache(senderOffline);
        LOGVOLE_EXPECT_TRUE(senderOffline.mState.mNextLevelState->mShrinkExpandState.mGpuCache != oldCache);
    }
#endif

    ReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;
    receiverInput.mCpuScratch = std::make_shared<detail::ShrinkExpandScratch>();

    ReceiverOfflineOutput receiverOffline{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), senderOffline.mMessage, receiverOffline));
    LOGVOLE_REQUIRE_TRUE(receiverOffline.mState.mNextLevelState != nullptr);
    LOGVOLE_REQUIRE_TRUE(receiverOffline.mState.mNextLevelState->mNextLevelState != nullptr);
    LOGVOLE_REQUIRE_TRUE(senderInput.mCpuScratch != receiverInput.mCpuScratch);
    for (const SenderState* level = &senderOffline.mState; level; level = level->mNextLevelState.get())
        if (level->mShrinkExpandState.mParams.mMu)
            LOGVOLE_REQUIRE_TRUE(level->mShrinkExpandState.mCpuScratch == senderInput.mCpuScratch);
    for (const ReceiverState* level = &receiverOffline.mState; level; level = level->mNextLevelState.get())
        if (level->mShrinkExpandState.mParams.mMu)
            LOGVOLE_REQUIRE_TRUE(level->mShrinkExpandState.mCpuScratch == receiverInput.mCpuScratch);

#if defined(ENABLE_LOGVOLE_CUDA)
    bool receiverDeviceEnabled = false;
    {
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        receiverDeviceEnabled = gpu::enabled(advanced);
    }
    auto expectSharedReceiverCache = [&](const ReceiverOfflineOutput& output) {
        if (!receiverDeviceEnabled) return;
        const auto& top = output.mState.mShrinkExpandState;
        const auto& internal = output.mState.mNextLevelState->mShrinkExpandState;
        const auto& root = output.mState.mNextLevelState->mNextLevelState->mShrinkExpandState;
        // The top package is different and remains lazy. Only exact receiver
        // package copies share the eagerly uploaded, immutable device mirror.
        LOGVOLE_EXPECT_TRUE(top.mGpuCache == nullptr);
        LOGVOLE_REQUIRE_TRUE(internal.mGpuCache != nullptr);
        LOGVOLE_EXPECT_TRUE(root.mGpuCache == internal.mGpuCache);
        LOGVOLE_EXPECT_TRUE(internal.mGpuCache !=
            senderOffline.mState.mNextLevelState->mShrinkExpandState.mGpuCache);
    };
    expectSharedReceiverCache(receiverOffline);
    if (receiverDeviceEnabled)
    {
        ReceiverOfflineOutput lazyReceiver{};
        {
            tests_libOTe::logvole_test::ScopedOptionValue disabledCache(advanced.mAdvanced.mProtocol.mShareCache, false);
            tests_libOTe::logvole_test::ScopedOptionValue hostLeafB(advanced.mAdvanced.mProtocol.mLeafBDevice, false);
            LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), senderOffline.mMessage, lazyReceiver));
        }
        for (const ReceiverState* level = &lazyReceiver.mState; level; level = level->mNextLevelState.get())
            LOGVOLE_EXPECT_TRUE(level->mShrinkExpandState.mGpuCache == nullptr);

        // Both paths must consume identical recursive public-B coefficients.
        // Compare actual shrink digests and all unbundled child inputs using a
        // fresh CPU-scaled cache versus the directly device-scaled cache.
        {
            ScopedProtocolCacheScope roleScope(
                ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
            const auto& reference = lazyReceiver.mState.mNextLevelState->mShrinkExpandState;
            const auto& candidate = receiverOffline.mState.mNextLevelState->mShrinkExpandState;
            const std::uint32_t muHi = reference.mParams.mMu;
            const std::uint32_t tauHi = reference.mParams.mTau;
            auto x = sample_small_plain_batch(ctx, muHi, 0x7863u, 4u);
            gpu::LevelSession referenceSession, candidateSession;
            std::vector<RnsPoly> referenceDigests, candidateDigests;
            std::vector<std::vector<RnsPoly>> referenceChildren, candidateChildren;
            {
                LOGVOLE_REQUIRE_TRUE(gpu::shrinkChunks(reference, x, muHi, tauHi,
                    referenceSession, referenceDigests, referenceChildren));
            }
            LOGVOLE_REQUIRE_TRUE(gpu::shrinkChunks(candidate, x, muHi, tauHi,
                candidateSession, candidateDigests, candidateChildren));
            expect_batch_equal(referenceDigests, candidateDigests);
            LOGVOLE_REQUIRE_EQ(referenceChildren.size(), candidateChildren.size());
            for (std::size_t i = 0; i < referenceChildren.size(); ++i)
                expect_batch_equal(referenceChildren[i], candidateChildren[i]);
        }

        // Reinitializing an existing output must discard its previous device
        // mirror. Keep that mirror alive so pointer inequality is meaningful.
        const auto oldCache = receiverOffline.mState.mNextLevelState->mShrinkExpandState.mGpuCache;
        LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), senderOffline.mMessage, receiverOffline));
        expectSharedReceiverCache(receiverOffline);
        LOGVOLE_EXPECT_TRUE(receiverOffline.mState.mNextLevelState->mShrinkExpandState.mGpuCache != oldCache);
    }
#endif

    {
        tests_libOTe::logvole_test::ScopedOptionValue parallelCopy(setupOptions.mParallelCopy, true);
        tests_libOTe::logvole_test::ScopedOptionValue parallelMessageCopy(setupOptions.mParallelMessageCopy, true);
        tests_libOTe::logvole_test::ScopedOptionValue directDownload(advanced.mAdvanced.mProtocol.mDirectDownload, true);
        SenderOfflineOutput parallelSender{};
        LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(senderInput, setupOptions), advanced, ProtocolCacheRole::Sender), parallelSender));
#if defined(ENABLE_LOGVOLE_CUDA)
        expectSharedSenderCache(parallelSender);
#endif
        ReceiverOfflineOutput parallelReceiver{};
        LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(
            tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), parallelSender.mMessage, parallelReceiver));
#if defined(ENABLE_LOGVOLE_CUDA)
        expectSharedReceiverCache(parallelReceiver);
#endif

        auto expectCommon = [](const auto& reference, const auto& actual) {
            LOGVOLE_EXPECT_TRUE(reference.mParams.mRing == actual.mParams.mRing);
            LOGVOLE_EXPECT_EQ(reference.mCt1.mRows, actual.mCt1.mRows);
            LOGVOLE_EXPECT_EQ(reference.mCt1.mCols, actual.mCt1.mCols);
            LOGVOLE_EXPECT_EQ(reference.mLacct.mWidthPadded, actual.mLacct.mWidthPadded);
            LOGVOLE_EXPECT_EQ(reference.mLacct.mLevels, actual.mLacct.mLevels);
            LOGVOLE_EXPECT_EQ(reference.mLacct.mCt.mRows, actual.mLacct.mCt.mRows);
            LOGVOLE_EXPECT_EQ(reference.mLacct.mCt.mCols, actual.mLacct.mCt.mCols);
            expect_batch_equal(reference.mCt1.mPolys, actual.mCt1.mPolys);
            expect_batch_equal(reference.mLacct.mCt.mPolys, actual.mLacct.mCt.mPolys);
            expect_batch_equal(*reference.mPublicANtt, *actual.mPublicANtt);
            expect_batch_equal(*reference.mPublicBNtt, *actual.mPublicBNtt);
        };
        const SenderState* serialSenderState = &senderOffline.mState;
        const SenderState* parallelSenderState = &parallelSender.mState;
        const ReceiverState* serialReceiverState = &receiverOffline.mState;
        const ReceiverState* parallelReceiverState = &parallelReceiver.mState;
        while (serialSenderState && parallelSenderState && serialReceiverState && parallelReceiverState)
        {
            const auto& reference = serialSenderState->mShrinkExpandState;
            const auto& actual = parallelSenderState->mShrinkExpandState;
            expectCommon(reference, actual);
            expect_batch_equal(reference.mS, actual.mS);
            expect_batch_equal(reference.mR, actual.mR);
            expect_batch_equal(reference.mSk1, actual.mSk1);
            expectCommon(serialReceiverState->mShrinkExpandState, parallelReceiverState->mShrinkExpandState);
            expect_batch_equal(serialSenderState->mRootSkRRt, parallelSenderState->mRootSkRRt);
            const auto& serialR1 = serialSenderState->mLazyRootR1Rt
                ? serialSenderState->mLazyRootR1Rt->hostCoefficients()
                : serialSenderState->mRootR1Rt;
            const auto& parallelR1 = parallelSenderState->mLazyRootR1Rt
                ? parallelSenderState->mLazyRootR1Rt->hostCoefficients()
                : parallelSenderState->mRootR1Rt;
            expect_batch_equal(serialR1, parallelR1);
            expect_batch_equal(serialReceiverState->mRootCtRRt.mPolys, parallelReceiverState->mRootCtRRt.mPolys);
            expect_batch_equal(serialReceiverState->mRootLacctLeft.mCt.mPolys, parallelReceiverState->mRootLacctLeft.mCt.mPolys);
            expect_batch_equal(serialReceiverState->mRootTopCt.mPolys, parallelReceiverState->mRootTopCt.mPolys);
            expect_batch_equal(serialReceiverState->mRootPublicBStarNtt, parallelReceiverState->mRootPublicBStarNtt);
            serialSenderState = serialSenderState->mNextLevelState.get();
            parallelSenderState = parallelSenderState->mNextLevelState.get();
            serialReceiverState = serialReceiverState->mNextLevelState.get();
            parallelReceiverState = parallelReceiverState->mNextLevelState.get();
        }
        LOGVOLE_EXPECT_TRUE(!serialSenderState && !parallelSenderState && !serialReceiverState && !parallelReceiverState);

        // Serial and parallel message construction both retain full, separate
        // ciphertext storage. Mutating any transmitted polynomial must leave
        // the corresponding sender state unchanged.
        for (auto* output : { &senderOffline, &parallelSender })
        {
            auto* message = &output->mMessage;
            const auto* state = &output->mState;
            while (message && state)
            {
                if (message->mHasShrinkExpandMessage)
                {
                    auto& sent = message->mShrinkExpandMessage;
                    const auto& kept = state->mShrinkExpandState;
                    LOGVOLE_EXPECT_EQ(sent.mCt1.mRows, kept.mCt1.mRows);
                    LOGVOLE_EXPECT_EQ(sent.mCt1.mCols, kept.mCt1.mCols);
                    LOGVOLE_EXPECT_EQ(sent.mLacct.mWidthPadded, kept.mLacct.mWidthPadded);
                    LOGVOLE_EXPECT_EQ(sent.mLacct.mLevels, kept.mLacct.mLevels);
                    LOGVOLE_EXPECT_EQ(sent.mLacct.mCt.mRows, kept.mLacct.mCt.mRows);
                    LOGVOLE_EXPECT_EQ(sent.mLacct.mCt.mCols, kept.mLacct.mCt.mCols);
                    auto expectMessagePolys = [](auto& transmitted, const auto& retained) {
                        expect_batch_equal(transmitted, retained);
                        for (std::size_t i = 0; i < transmitted.size(); ++i)
                        {
                            LOGVOLE_REQUIRE_FALSE(transmitted[i].mCoeffs.empty());
                            LOGVOLE_EXPECT_TRUE(transmitted[i].mCoeffs.data() != retained[i].mCoeffs.data());
                            const auto original = retained[i].mCoeffs[0];
                            transmitted[i].mCoeffs[0] ^= 1u;
                            LOGVOLE_EXPECT_EQ(retained[i].mCoeffs[0], original);
                            transmitted[i].mCoeffs[0] ^= 1u;
                        }
                    };
                    expectMessagePolys(sent.mCt1.mPolys, kept.mCt1.mPolys);
                    expectMessagePolys(sent.mLacct.mCt.mPolys, kept.mLacct.mCt.mPolys);
                }
                message = message->mNextLevel.get();
                state = state->mNextLevelState.get();
            }
            LOGVOLE_EXPECT_TRUE(!message && !state);
        }

        auto expectIndependent = [](const auto& source, const auto& cloned) {
            LOGVOLE_REQUIRE_FALSE(source.mCt1.mPolys.empty());
            LOGVOLE_REQUIRE_FALSE(source.mLacct.mCt.mPolys.empty());
            LOGVOLE_EXPECT_TRUE(source.mCt1.mPolys.data() != cloned.mCt1.mPolys.data());
            LOGVOLE_EXPECT_TRUE(source.mLacct.mCt.mPolys.data() != cloned.mLacct.mCt.mPolys.data());
            LOGVOLE_EXPECT_TRUE(source.mCt1.mPolys[0].mCoeffs.data() != cloned.mCt1.mPolys[0].mCoeffs.data());
            LOGVOLE_EXPECT_TRUE(source.mLacct.mCt.mPolys[0].mCoeffs.data() != cloned.mLacct.mCt.mPolys[0].mCoeffs.data());
            LOGVOLE_EXPECT_TRUE(source.mPublicANtt == cloned.mPublicANtt);
            LOGVOLE_EXPECT_TRUE(source.mPublicBNtt == cloned.mPublicBNtt);
            LOGVOLE_EXPECT_TRUE(source.mGpuCache == cloned.mGpuCache);
        };
        for (const auto* output : { &senderOffline, &parallelSender })
        {
            const auto& source = output->mState.mNextLevelState->mShrinkExpandState;
            const auto& cloned = output->mState.mNextLevelState->mNextLevelState->mShrinkExpandState;
            expectIndependent(source, cloned);
            for (const auto& pair : { std::pair{ &source.mS, &cloned.mS },
                    std::pair{ &source.mR, &cloned.mR }, std::pair{ &source.mSk1, &cloned.mSk1 } })
            {
                LOGVOLE_REQUIRE_FALSE(pair.first->empty());
                LOGVOLE_EXPECT_TRUE(pair.first->data() != pair.second->data());
                LOGVOLE_EXPECT_TRUE((*pair.first)[0].mCoeffs.data() != (*pair.second)[0].mCoeffs.data());
            }
        }
        for (const auto* output : { &receiverOffline, &parallelReceiver })
        {
            expectIndependent(output->mState.mNextLevelState->mShrinkExpandState,
                output->mState.mNextLevelState->mNextLevelState->mShrinkExpandState);
        }
        senderOffline = std::move(parallelSender);
        receiverOffline = std::move(parallelReceiver);
    }

    // The const API preserves the wire message; the owned API transfers it and
    // must retain the same reusable internal package at every recursive level.
    const auto* ownedTopStorage = senderOffline.mMessage.mShrinkExpandMessage.mLacct.mCt.mPolys.data();
    ReceiverOfflineOutput movedOffline{};
    LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(
        tests_libOTe::logvole_test::withAdvancedOptions(tests_libOTe::logvole_test::withSetupOptions(receiverInput, setupOptions), advanced, ProtocolCacheRole::Receiver), std::move(senderOffline.mMessage), movedOffline));
#if defined(ENABLE_LOGVOLE_CUDA)
    expectSharedReceiverCache(movedOffline);
#endif
    LOGVOLE_EXPECT_TRUE(movedOffline.mState.mShrinkExpandState.mLacct.mCt.mPolys.data() == ownedTopStorage);
    const ReceiverState* copied = &receiverOffline.mState;
    const ReceiverState* moved = &movedOffline.mState;
    while (copied && moved)
    {
        expect_batch_equal(copied->mShrinkExpandState.mCt1.mPolys, moved->mShrinkExpandState.mCt1.mPolys);
        expect_batch_equal(copied->mShrinkExpandState.mLacct.mCt.mPolys, moved->mShrinkExpandState.mLacct.mCt.mPolys);
        expect_batch_equal(*copied->mShrinkExpandState.mPublicANtt, *moved->mShrinkExpandState.mPublicANtt);
        expect_batch_equal(*copied->mShrinkExpandState.mPublicBNtt, *moved->mShrinkExpandState.mPublicBNtt);
        expect_batch_equal(copied->mRootCtRRt.mPolys, moved->mRootCtRRt.mPolys);
        expect_batch_equal(copied->mRootLacctLeft.mCt.mPolys, moved->mRootLacctLeft.mCt.mPolys);
        expect_batch_equal(copied->mRootTopCt.mPolys, moved->mRootTopCt.mPolys);
        expect_batch_equal(copied->mRootPublicBStarNtt, moved->mRootPublicBStarNtt);
        LOGVOLE_EXPECT_EQ(copied->mRootRandomizerWidth, moved->mRootRandomizerWidth);
        copied = copied->mNextLevelState.get();
        moved = moved->mNextLevelState.get();
    }
    LOGVOLE_EXPECT_TRUE(copied == nullptr && moved == nullptr);
    receiverOffline = std::move(movedOffline);

    LOGVOLE_EXPECT_TRUE(senderOffline.mState.mGoldenSeed.empty());
    LOGVOLE_EXPECT_TRUE(senderOffline.mState.mPrecomputedTbk == nullptr);

    ReceiverOnlineInput receiverInputOnline{};
    receiverInputOnline.mX = sample_small_plain_batch(
        ctx,
        params.mW,
        0x7862u,
        std::min<std::uint32_t>(20u, params.mShrinkExpand.mPlaintextModulusBits));

#if defined(ENABLE_LOGVOLE_CUDA)
    // Setup parity above exercises the GPU. Retain this test's original online
    // backend: forcing GPU on the serial baseline also fails its local flow.
    useCpuReference(senderOffline.mState, ProtocolCacheRole::Sender);
    useCpuReference(receiverOffline.mState, ProtocolCacheRole::Receiver);
#endif
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
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(rejectedParams.mShrinkExpand.mRing, rejectedCtx, std::make_shared<RingContextFactory>(advanced)));

    SenderOfflineInput rejectedSenderInput{};
    rejectedSenderInput.mParams = rejectedParams;
    rejectedSenderInput.mSk1 = sample_batch(rejectedCtx, 1, 0x7D01u);

    SenderOfflineOutput rejectedSenderOutput{};
    LOGVOLE_EXPECT_FALSE(prepare_sender_offline_for_test(tests_libOTe::logvole_test::withSetupOptions(rejectedSenderInput, setupOptions), rejectedSenderOutput));

    ReceiverOfflineInput rejectedReceiverInput{};
    rejectedReceiverInput.mParams = rejectedParams;

    OfflineMessage emptyMessage{};
    ReceiverOfflineOutput rejectedReceiverOutput{};
    LOGVOLE_EXPECT_FALSE(finalizeReceiverOffline(tests_libOTe::logvole_test::withSetupOptions(rejectedReceiverInput, setupOptions), emptyMessage, rejectedReceiverOutput));
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

void LogVole_Core_PartialRootWidthExperimental(const oc::CLP&)
{

    Params paddedSeedParams{};
    std::vector<RnsPoly> paddedRejectedCandidate;
    RingNttContext paddedCtx{};

    for (const std::uint32_t width : { 8u, 16u })
    {
        Params params = make_alpha4_root_params(width);
        params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
        const std::uint32_t tauHi = params.mShrinkExpand.mTau - 1u;
        const std::uint32_t rho = static_cast<std::uint32_t>(
            params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const std::uint32_t muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
        LOGVOLE_REQUIRE_EQ(muHi, 16u);
        LOGVOLE_REQUIRE_TRUE(width <= muHi);
        LOGVOLE_REQUIRE_FALSE(params.mAllowPartialRootWidth);
        params.mAllowPartialRootWidth = width < muHi;

        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));

        SenderOfflineInput senderInput{};
        senderInput.mParams = params;
        senderInput.mSk1 = sample_batch(ctx, 1u, 0x7DA100u + width);
        SenderOfflineOutput senderOffline{};
        LOGVOLE_REQUIRE_TRUE(
            prepare_sender_offline_for_test(senderInput, senderOffline));

        ReceiverOfflineInput receiverInput{};
        receiverInput.mParams = params;
        ReceiverOfflineOutput receiverOffline{};
        LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(
            receiverInput, senderOffline.mMessage, receiverOffline));

        ReceiverOnlineInput onlineInput{};
        onlineInput.mX = sample_small_plain_batch(
            ctx, width, 0x7DA200u + width,
            std::min<std::uint32_t>(
                20u, params.mShrinkExpand.mPlaintextModulusBits));
        SenderOnlineOutput senderOnline{};
        ReceiverOnlineOutput receiverOnline{};
        LOGVOLE_REQUIRE_TRUE(run_local_online_for_test(
            senderOffline.mState,
            receiverOffline.mState,
            onlineInput,
            senderOnline,
            receiverOnline));
        LOGVOLE_REQUIRE_EQ(senderOnline.mTbk.size(), width);
        LOGVOLE_REQUIRE_EQ(receiverOnline.mTbm.size(), width);

        std::vector<RnsPoly> sRep;
        LOGVOLE_REQUIRE_TRUE(seedLabelRepOfflineSenderInput(
            senderInput.mSk1,
            params.mGamma,
            params.mShrinkExpand.mAlpha,
            tauHi,
            params.mShrinkExpand.mRing,
            sRep));
        LOGVOLE_REQUIRE_TRUE(sRep.size() >= width);
        sRep.resize(width);

        std::vector<RnsPoly> actual;
        std::vector<RnsPoly> expected;
        LOGVOLE_REQUIRE_TRUE(subtract_batches(
            ctx, receiverOnline.mTbm, senderOnline.mTbk, actual));
        LOGVOLE_REQUIRE_TRUE(compute_expected_s_mul_x(
            ctx, sRep, onlineInput.mX, expected));
        long double maxLog2 = 0.0L;
        LOGVOLE_EXPECT_TRUE(check_logvole_noise_tolerance(
            ctx, actual, expected, params, maxLog2))
            << "width=" << width
            << " max centered log2 residual " << static_cast<double>(maxLog2);

        if (width == 8u)
        {
            // An independent instance still rejects this same partial width.
            // Its policy cannot be changed by the opted-in instance above.
            auto strictSender = senderInput;
            strictSender.mParams.mAllowPartialRootWidth = false;
            SenderOfflineOutput strictSenderOutput;
            LOGVOLE_REQUIRE_FALSE(prepare_sender_offline_for_test(strictSender, strictSenderOutput));
            auto strictReceiver = receiverInput;
            strictReceiver.mParams.mAllowPartialRootWidth = false;
            ReceiverOfflineOutput strictReceiverOutput;
            LOGVOLE_REQUIRE_FALSE(finalizeReceiverOffline(
                strictReceiver, senderOffline.mMessage, strictReceiverOutput));

            // The option permits one incomplete Root block, not an oversized
            // logical input and not arbitrary Root widths.
            std::vector<RnsPoly> overwideInput = onlineInput.mX;
            overwideInput.push_back(zero_poly(ctx));
            RootDigestState rejectedDigestState{};
            RootDigestMessage rejectedDigest{};
            LOGVOLE_EXPECT_FALSE(prepare_root_digest_receiver_for_test(
                receiverOffline.mState,
                overwideInput,
                rejectedDigestState,
                rejectedDigest));

            receiverOffline.mState.mParams.mW = 0u;
            LOGVOLE_EXPECT_FALSE(prepare_root_digest_receiver_for_test(
                receiverOffline.mState,
                {},
                rejectedDigestState,
                rejectedDigest));
            receiverOffline.mState.mParams.mW = 17u;
            LOGVOLE_EXPECT_FALSE(prepare_root_digest_receiver_for_test(
                receiverOffline.mState,
                onlineInput.mX,
                rejectedDigestState,
                rejectedDigest));
            receiverOffline.mState.mParams.mW = width;

            // Intermediate Root candidates remain physically muHi-wide. A
            // failure in the padded half must still reject that Q/q_j check.
            LOGVOLE_REQUIRE_TRUE(makeEffectiveTruncParams(
                params, paddedSeedParams));
            LOGVOLE_REQUIRE_TRUE(paddedSeedParams.mAllowPartialRootWidth);
            LOGVOLE_REQUIRE_EQ(paddedSeedParams.mW, 8u);
            LOGVOLE_REQUIRE_EQ(paddedSeedParams.mShrinkExpand.mMu, 16u);
            paddedRejectedCandidate.assign(muHi, zero_poly(ctx));
            bool candidateOk = false;
            LOGVOLE_REQUIRE_TRUE(validateGoldenSeedCandidate(
                paddedSeedParams, paddedRejectedCandidate, candidateOk));
            LOGVOLE_REQUIRE_TRUE(candidateOk);

            // Force the target-0 rounding fraction to the top boundary in tail
            // row 8.  For source limb 1, v=(q1/2)*(q2*q3 mod q1) makes the
            // validator's v*inv(q2*q3) equal floor(q1/2); multiplying by
            // floor(2^128/q1) lands within <q1/2 of 2^127.  Adding the validator's
            // 2^127 rounding term therefore wraps within the rejection margin.
            const std::size_t n = params.mShrinkExpand.mRing.mPolyModulusDegree;
            const std::size_t sourceLimb = 1u;
            const auto& moduli = getRingHostModuli(ctx);
            LOGVOLE_REQUIRE_EQ(moduli.size(), rho);
            const seal::Modulus& sourceMod = moduli[sourceLimb];
            std::uint64_t puncturedModSource = 1u;
            for (std::size_t limb = 1u; limb < rho; ++limb)
            {
                if (limb == sourceLimb) continue;
                puncturedModSource = seal::util::multiply_uint_mod(
                    puncturedModSource,
                    moduli[limb].value(),
                    sourceMod);
            }
            paddedRejectedCandidate[8].mCoeffs[sourceLimb * n] =
                seal::util::multiply_uint_mod(
                    sourceMod.value() / 2u,
                    puncturedModSource,
                    sourceMod);
            LOGVOLE_REQUIRE_TRUE(validateGoldenSeedCandidate(
                paddedSeedParams, paddedRejectedCandidate, candidateOk));
            LOGVOLE_REQUIRE_FALSE(candidateOk);
            paddedCtx = ctx;
        }
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    if (gpu::available())
    {
        auto advanced = paddedCtx.mExecutionOptions;
        advanced.mUseGpu = true;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(paddedCtx.mParams, paddedCtx,
            std::make_shared<RingContextFactory>(advanced)));
        auto candidateDev = gpu::upload(
            paddedCtx,
            std::span<const RnsPoly>(
                paddedRejectedCandidate.data(), paddedRejectedCandidate.size()));
        LOGVOLE_REQUIRE_TRUE(candidateDev != nullptr);
        LOGVOLE_REQUIRE_EQ(candidateDev->count(), 16u);
        gpu::GoldenValidationAttempt attempt;
        LOGVOLE_REQUIRE_TRUE(attempt.begin(paddedCtx));

        gpu::DeviceBatchPtr prefix;
        LOGVOLE_REQUIRE_TRUE(gpu::denoiseAndAggValidateDevice(
            attempt,
            paddedCtx,
            *candidateDev,
            1u,
            paddedSeedParams,
            prefix,
            8u));
        LOGVOLE_REQUIRE_TRUE(prefix != nullptr);
        LOGVOLE_REQUIRE_EQ(prefix->count(), 2u);

        bool accepted = true;
        LOGVOLE_REQUIRE_TRUE(attempt.finish(accepted));
        LOGVOLE_EXPECT_FALSE(accepted);
    }
#endif
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

    const Params alpha4Partial = make_alpha4_root_params(8u);
    SenderOfflineInput alpha4SenderInput{};
    alpha4SenderInput.mParams = alpha4Partial;
    alpha4SenderInput.mSk1 = sample_batch(ctx, 1u, 0x7D02u);
    SenderOfflineOutput alpha4SenderOutput{};
    LOGVOLE_EXPECT_FALSE(prepare_sender_offline_for_test(
        alpha4SenderInput, alpha4SenderOutput));
}

void LogVole_Core_TwoLevelCoprotoRelation(const oc::CLP& cmd)
{
    RootWirePinOverlapEvidence rootWirePin;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0)) LOGVOLE_REQUIRE_TRUE(gpu::available());
#endif
    Params params = make_recursive_params(2);
    const bool transport = cmd.getOr("legacy_transport", 0) == 0;
    params.mShrinkExpand.mTransport = {transport, transport, transport, transport};
    if (cmd.getOr("scalar_wire", 0) != 0)
    {
        auto& encoding = params.mShrinkExpand.mTransport.mEncoding;
        encoding.mWire = {false, false, false};
        encoding.mRootU64Memcpy = false;
        encoding.mSetupMemcpy = false;
        encoding.mParallel = false;
        encoding.mEncodedReceive = false;
        encoding.mRootEncodedReceive = false;
    }
    params.mShrinkExpand.mNumWorkerThreads = 4;
    params.mAllowPartialRootWidth = true;
    params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
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
    oc::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = cmd.getOr("gpu", 0) != 0;
    if (cmd.getOr("cpu_options", 0) != 0)
        advanced.mAdvanced.mCpu = {false, false, false};
    if (cmd.getOr("protocol_options", 0) != 0)
    {
        auto& policy = advanced.mAdvanced.mProtocol;
        policy.mRootDirectUpload = true;
        policy.mRootKPrimeResident = true;
        policy.mRootSkNttResident = false;
        policy.mRootKPrimePreupload = true;
        policy.mRootDPrimeResident = false;
        policy.mRootFinalizePriorityPrefetch = false;
        policy.mIdentityLeaf = false;
        policy.mPlainBroadcastSingleLimb = false;
        policy.mReuseHiDigits = false;
        policy.mDirectRecursiveLeaf = false;
        policy.mRecursiveDiagonal = false;
        policy.mRecursiveLeafSelfZero = false;
        policy.mRecursiveLeafSparseInverse = false;
        policy.mFusedUnwrap = false;
        policy.mFusedScaleUnwrap = false;
        policy.mFusedWrap = false;
        policy.mRootZeta = false;
        policy.mNoGoldRootZeta = false;
        policy.mNoGoldRootPinnedSeeds = false;
        policy.mSenderInplaceKey = false;
        policy.mCt2PrefixCache = true;
        policy.mTopSenderCt2Prefetch = false;
        policy.mReceiverCt2Prefetch = oc::LogVoleChoice::Disabled;
        policy.mReceiverShrinkTilePipeline = true;
        policy.mReceiverShrinkTileCount = 2;
        policy.mDeferredGoldenValidation = false;
        policy.mInplaceHiDigit = false;
        policy.mLencRandomizerResidency = false;
        policy.mRootDigestHash = true;
        policy.mRootKPrimeSampling = false;
        policy.mNoGoldRootPriorityPrefetch = false;
    }
    const auto makeOwner = [&](ProtocolCacheRole role) {
        ScopedProtocolCacheScope scope(role, allocateProtocolCacheRunId());
        RingNttContext selected;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, selected,
            std::make_shared<RingContextFactory>(advanced)));
        return selected.mFactoryOwner;
    };
    senderInput.mRingFactoryOwner = makeOwner(ProtocolCacheRole::Sender);
    receiverInput.mRingFactoryOwner = makeOwner(ProtocolCacheRole::Receiver);

    LogVoleRingSender sender{};
    LogVoleRingReceiver receiver{};
    SenderState senderState{};
    ReceiverState receiverState{};

    auto offlineSockets = coproto::LocalAsyncSocket::makePair();
    oc::PRNG senderOfflinePrng(oc::block(0x7D53u, 0));
    auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.offline(senderInput, senderState, senderOfflinePrng, offlineSockets[0], rootWirePin),
        receiver.offline(receiverInput, receiverState, offlineSockets[1])));
    std::get<0>(offlineResult).result();
    std::get<1>(offlineResult).result();

    // Evidence belongs to its caller and is reset only when a new attempt starts.
    // An unrelated failed sender must not change this completed sender's result.
    const auto completedRun = rootWirePin.mSenderRunId;
    const auto completedBytes = rootWirePin.mWireBytes;
    RootWirePinOverlapEvidence failedPin;
    failedPin.mSelected = failedPin.mRequested = true;
    failedPin.mPinBeginNs = failedPin.mWireBytes = 99;
    SenderOfflineInput invalid;
    invalid.mSenderOwnerRunId = 0x7D54;
    SenderState unchanged;
    unchanged.mParams.mW = 777;
    oc::PRNG invalidPrng(oc::block(0x7D54u, 0));
    coproto::BufferingSocket invalidSocket;
    auto failedAttempt = sender.offline(invalid, unchanged, invalidPrng, invalidSocket, failedPin);
    LOGVOLE_REQUIRE_TRUE(failedPin.mSelected); // The returned task is still lazy.
    bool rejected = false;
    try { macoro::sync_wait(std::move(failedAttempt)); }
    catch (const std::runtime_error&) { rejected = true; }
    LOGVOLE_REQUIRE_TRUE(rejected);
    LOGVOLE_REQUIRE_EQ(unchanged.mParams.mW, 777u);
    LOGVOLE_REQUIRE_EQ(failedPin.mSenderRunId, invalid.mSenderOwnerRunId);
    LOGVOLE_REQUIRE_FALSE(failedPin.mRequested || failedPin.mSelected);
    LOGVOLE_REQUIRE_EQ(failedPin.mPinBeginNs, 0u);
    LOGVOLE_REQUIRE_EQ(failedPin.mWireBytes, 0u);
    LOGVOLE_REQUIRE_EQ(rootWirePin.mSenderRunId, completedRun);
    LOGVOLE_REQUIRE_EQ(rootWirePin.mWireBytes, completedBytes);

    LOGVOLE_REQUIRE_TRUE(senderState.mNextLevelState != nullptr);
    LOGVOLE_REQUIRE_TRUE(receiverState.mNextLevelState != nullptr);
    for (auto* level = &senderState; level; level = level->mNextLevelState.get())
    {
        LOGVOLE_REQUIRE_TRUE(level->mParams.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_TRUE(level->mShrinkExpandState.mRingFactoryOwner->mExecutionOptions == advanced);
    }
    for (auto* level = &receiverState; level; level = level->mNextLevelState.get())
    {
        LOGVOLE_REQUIRE_TRUE(level->mParams.mAllowPartialRootWidth);
        LOGVOLE_REQUIRE_TRUE(level->mShrinkExpandState.mRingFactoryOwner->mExecutionOptions == advanced);
    }

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
    macoro::thread_pool executor;
    auto work = executor.make_work();
    std::array<LheDecryptBuffer, 3> lheBuffers, senderBuffers;
    std::array<const std::uint64_t*, 3> senderAllocations{};
    std::array<LencEvalBuffer, 3> lencBuffers;
    std::array<const std::uint64_t*, 3> productAllocations{};
    std::array<const RnsPoly* const*, 3> ciphertextAllocations{}, nodeAllocations{};
    if (!advanced.mUseGpu)
    {
        // More partitions than executor threads exercises suspension without
        // nested blocking. Every level reuses the same exclusive buffers.
        executor.create_threads(cmd.getOr("executor_threads", 1));
        std::size_t terms = 0;
        for (auto* level = &receiverState; level; level = level->mNextLevelState.get())
            terms = std::max(terms, std::size_t{2} *
                std::max(level->mRootLacctLeft.mLevels, level->mShrinkExpandState.hostLacct().mLevels) *
                (level->mShrinkExpandState.mParams.mTau + 1));
        for (std::size_t i = 0; i < lheBuffers.size(); ++i)
        {
            lheBuffers[i].mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mShrinkExpand.mRing));
            senderBuffers[i].mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mShrinkExpand.mRing));
            senderAllocations[i] = senderBuffers[i].mProduct.mCoeffs.data();
            lencBuffers[i].mCiphertexts.reserve(terms);
            lencBuffers[i].mNodes.reserve(terms);
            productAllocations[i] = lheBuffers[i].mProduct.mCoeffs.data();
            ciphertextAllocations[i] = lencBuffers[i].mCiphertexts.data();
            nodeAllocations[i] = lencBuffers[i].mNodes.data();
        }
    }
    auto receiverOperation = receiver.online(executor, lheBuffers, lencBuffers, receiverState,
        receiverOnlineInput, receiverOnline, receiverOnlinePrng, onlineSockets[1]);
    // The controller and its queued workers share the sole thread by default.
    // Own the lazy operation in this frame before scheduling it.
    auto onPool = [](macoro::thread_pool& pool, oc::task<> operation, bool cpu) -> oc::task<> {
        if (cpu) co_await pool.schedule();
        co_await std::move(operation);
    };
    auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
        onPool(executor, sender.online(executor, senderBuffers, senderState, senderOptions,
            senderOnline, senderOnlinePrng, onlineSockets[0]), !advanced.mUseGpu),
        onPool(executor, std::move(receiverOperation), !advanced.mUseGpu)));
    std::get<0>(onlineResult).result();
    std::get<1>(onlineResult).result();
    if (!advanced.mUseGpu)
        for (std::size_t i = 0; i < lheBuffers.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(lheBuffers[i].mProduct.mCoeffs.data() == productAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(senderBuffers[i].mProduct.mCoeffs.data() == senderAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mCiphertexts.data() == ciphertextAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mNodes.data() == nodeAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mCiphertexts.empty() && lencBuffers[i].mNodes.empty());
        }
    const auto senderBytesSent = onlineSockets[0].bytesSent() - senderSentBefore;
    const auto senderBytesReceived = onlineSockets[0].bytesReceived() - senderReceivedBefore;
    const auto receiverBytesSent = onlineSockets[1].bytesSent() - receiverSentBefore;
    const auto receiverBytesReceived = onlineSockets[1].bytesReceived() - receiverReceivedBefore;

#if defined(ENABLE_LOGVOLE_CUDA)
    gpu::GpuExecutionContext readbackExecution;
    if (senderOnline.mTbkDevice)
        LOGVOLE_REQUIRE_TRUE(gpu::download(
            *std::static_pointer_cast<gpu::DeviceBatch>(senderOnline.mTbkDevice),
            senderOnline.mTbk, readbackExecution.readbackStream()));
    if (receiverOnline.mTbmDevice)
        LOGVOLE_REQUIRE_TRUE(gpu::download(
            *std::static_pointer_cast<gpu::DeviceBatch>(receiverOnline.mTbmDevice),
            receiverOnline.mTbm, readbackExecution.readbackStream()));
#endif
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
    RootWirePinOverlapEvidence rootWirePin;
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
        sender.offline(senderInput, senderState, senderOfflinePrng, offlineSockets[0], rootWirePin),
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
    tests_libOTe::logvole_test::SenderResources senderResources(params.mShrinkExpand.mRing);
    tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(params.mShrinkExpand);
    oc::PRNG senderOnlinePrng(oc::block(0x7D74u, 0));
    oc::PRNG receiverOnlinePrng(oc::block(0x7D75u, 0));
    auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.online(senderResources.executor, senderResources.buffers, senderState, options, senderOnline, senderOnlinePrng, onlineSockets[0]),
        receiver.online(senderResources.executor, receiverBuffers.lhe, receiverBuffers.lenc, receiverState, receiverOnlineInput, receiverOnline, receiverOnlinePrng, onlineSockets[1])));
    std::get<0>(onlineResult).result();
    std::get<1>(onlineResult).result();

    LOGVOLE_EXPECT_TRUE(senderOnline.mTbk.empty());
    LOGVOLE_REQUIRE_EQ(receiverOnline.mTbm.size(), params.mW);
    LOGVOLE_REQUIRE_FALSE(senderOnline.mSeed.empty());
    LOGVOLE_EXPECT_TRUE(rangesEqual(senderOnline.mSeed, receiverOnline.mSeed));
    LOGVOLE_REQUIRE_TRUE(senderState.mPrecomputedTbk != nullptr);
    LOGVOLE_REQUIRE_EQ(senderState.mPrecomputedTbk->size(), params.mW);
}

void LogVole_Core_EarlyGoldenMatchesFullEvaluation(const oc::CLP&)
{
    for (std::uint32_t workers : {1u, 2u, 4u})
    {
        Params params = make_recursive_params(3);
        params.mShrinkExpand.mRing.mPolyModulusDegree = 1024;
        LOGVOLE_REQUIRE_TRUE(params.mEarlyGoldenCheck);
        params.mShrinkExpand.mNumWorkerThreads = workers;
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));
        SenderOnlineOutput referenceSender;
        ReceiverOnlineOutput referenceReceiver;
        std::array<oc::block, 2> referenceNext{};
        for (const bool early : {false, true})
        {
            params.mEarlyGoldenCheck = early;
            SenderOfflineInput input{};
            input.mParams = params;
            input.mSk1 = sample_batch(ctx, 1, 0x7E101u);
            SenderOfflineOutput sender;
            LOGVOLE_REQUIRE_TRUE(prepare_sender_offline_for_test(input, sender));
            ReceiverOfflineInput receiverInput{};
            receiverInput.mParams = params;
            ReceiverOfflineOutput receiver;
            LOGVOLE_REQUIRE_TRUE(finalizeReceiverOffline(receiverInput, sender.mMessage, receiver));
            for (auto* level = &sender.mState; level; level = level->mNextLevelState.get())
                LOGVOLE_REQUIRE_EQ(level->mParams.mEarlyGoldenCheck, early);
            for (auto* level = &receiver.mState; level; level = level->mNextLevelState.get())
                LOGVOLE_REQUIRE_EQ(level->mParams.mEarlyGoldenCheck, early);
            ReceiverOnlineInput onlineInput{};
            onlineInput.mSid = 19;
            onlineInput.mX = sample_small_plain_batch(ctx, params.mW, 0x7E102u, 20);
            oc::PRNG senderPrng(oc::block(0x7E103, 0x123));
            oc::PRNG receiverPrng(oc::block(0x7E104, 0x456));
            SenderOnlineOutput actualSender;
            ReceiverOnlineOutput actualReceiver;
            LOGVOLE_REQUIRE_TRUE(run_socket_online_for_test(
                sender.mState, receiver.mState, onlineInput,
                senderPrng, receiverPrng, actualSender, actualReceiver));
            const std::array<oc::block, 2> next{senderPrng.get<oc::block>(), receiverPrng.get<oc::block>()};
            if (!early)
            {
                referenceSender = std::move(actualSender);
                referenceReceiver = std::move(actualReceiver);
                referenceNext = next;
            }
            else
            {
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actualSender.mSeed, referenceSender.mSeed));
                LOGVOLE_REQUIRE_EQ(actualSender.mTbk.size(), referenceSender.mTbk.size());
                LOGVOLE_REQUIRE_EQ(actualReceiver.mTbm.size(), referenceReceiver.mTbm.size());
                for (std::size_t j = 0; j < actualSender.mTbk.size(); ++j)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actualSender.mTbk[j].mCoeffs, referenceSender.mTbk[j].mCoeffs));
                for (std::size_t j = 0; j < actualReceiver.mTbm.size(); ++j)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actualReceiver.mTbm[j].mCoeffs, referenceReceiver.mTbm[j].mCoeffs));
                LOGVOLE_REQUIRE_TRUE(next == referenceNext);
            }
        }
    }
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

void LogVole_Core_LeafGoldenSeedChecksOutputRounding(const oc::CLP&)
{
    // Five limbs put p*B/q near 2^-68, above the fixed-point undershoot (below 2^-71), and keep the
    // per-limb margin B*q_j/q near 2^-67, far below the per-limb distance (about 1/p) of the
    // coefficient built below.
    Params params = make_golden_params();
    assignValues<int>(params.mShrinkExpand.mRing.mCoeffModulusBits, { 54, 54, 54, 54, 54 });
    params.mShrinkExpand.mMu =
        params.mShrinkExpand.mAlpha *
        params.mShrinkExpand.mTau *
        static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
    params.mW = params.mShrinkExpand.mMu;
    ZpCrtContext zp{};
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(
        params.mShrinkExpand.mRing,
        params.mShrinkExpand.mPlaintextModulusBits,
        zp));
    const std::uint64_t p = zp.mPlaintextModulus;
    const std::size_t n = params.mShrinkExpand.mRing.mPolyModulusDegree;
    const std::size_t rho = zp.mRing.mModuli.size();

    auto makeZeroBatch = [&](std::size_t count) {
        std::vector<RnsPoly> polys(count);
        for (auto& poly : polys)
        {
            resizeZero(poly.mCoeffs, ringPolyCoeffCount(params.mShrinkExpand.mRing));
        }
        return polys;
    };

    // V = 0 gives frac(p*V/q) = 0, as far from the rounding boundary as possible.
    const std::vector<RnsPoly> safe = makeZeroBatch(params.mW);
    bool candidateOk = false;
    LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, safe, candidateOk));
    LOGVOLE_EXPECT_TRUE(candidateOk);

    candidateOk = true;
    LOGVOLE_EXPECT_FALSE(validateLeafGoldenSeedCandidate(params, makeZeroBatch(params.mW - 1), candidateOk));
    LOGVOLE_EXPECT_FALSE(validateLeafGoldenSeedCandidate(params, {}, candidateOk));

    // V = (2p)^-1 mod q gives frac(p*V/q) = 1/2 + 1/(2q), so a noise term of -1 already flips the
    // rounding to Z_p. Modulo each q/q_j, V stays about 1/p or more from the boundary, so the
    // per-limb check used for intermediate levels accepts it; only the leaf check protects the
    // output rounding.
    std::vector<RnsPoly> boundary = safe;
    for (std::size_t i = 0; i < rho; ++i)
    {
        const auto& modulus = zp.mRing.mModuli[i];
        std::uint64_t inv2p = 0;
        LOGVOLE_REQUIRE_TRUE(seal::util::try_invert_uint_mod(
            seal::util::multiply_uint_mod(2, p, modulus),
            modulus,
            inv2p));
        boundary.back().mCoeffs[i * n + (n - 1)] = inv2p;
    }

    candidateOk = true;
    LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, boundary, candidateOk));
    LOGVOLE_EXPECT_FALSE(candidateOk);

    candidateOk = false;
    LOGVOLE_REQUIRE_TRUE(validateGoldenSeedCandidate(params, boundary, candidateOk));
    LOGVOLE_EXPECT_TRUE(candidateOk);
}
namespace
{
    // Non-negative multiprecision integers as little-endian 64-bit words.
    using Words = std::vector<std::uint64_t>;

    // 2^log2X rounded down to a 53-bit mantissa, so it never exceeds 2^log2X.
    Words wordsBelowPow2(double log2X, std::size_t wordCount)
    {
        Words out(wordCount, 0);
        const int exponent = static_cast<int>(std::floor(log2X));
        out[0] = static_cast<std::uint64_t>(std::ldexp(std::exp2(log2X - exponent), 52));
        if (exponent >= 52)
        {
            seal::util::left_shift_uint(out.data(), exponent - 52, wordCount, out.data());
        }
        else
        {
            out[0] >>= 52 - exponent;
        }
        return out;
    }

    // An accepted s in (lo, hi] whose predecessor is rejected, given that lo is rejected and hi accepted.
    template<typename Accepts>
    Words bisectAcceptThreshold(Words lo, Words hi, Accepts&& accepts)
    {
        const std::size_t wordCount = lo.size();
        LOGVOLE_REQUIRE_FALSE(accepts(lo));
        LOGVOLE_REQUIRE_TRUE(accepts(hi));
        for (;;)
        {
            Words gap(wordCount);
            seal::util::sub_uint(hi.data(), lo.data(), wordCount, gap.data());
            if (gap[0] <= 1 && std::all_of(gap.begin() + 1, gap.end(), [](std::uint64_t w) { return w == 0; }))
            {
                return hi;
            }
            Words mid(wordCount);
            seal::util::add_uint(lo.data(), hi.data(), wordCount, mid.data());
            seal::util::right_shift_uint(mid.data(), 1, wordCount, mid.data());
            (accepts(mid) ? hi : lo) = mid;
        }
    }

    // value +/- s mod q_i, with s reduced into the limb.
    std::uint64_t addOffset(std::uint64_t value, const Words& s, bool add, const seal::Modulus& modulus)
    {
        const std::uint64_t sModQi = seal::util::modulo_uint(s.data(), s.size(), modulus);
        return add ?
            seal::util::add_uint_mod(value, sModQi, modulus) :
            seal::util::sub_uint_mod(value, sModQi, modulus);
    }

    // Five limbs put the margins near 2^-68, close enough to the fixed-point undershoot (about 2^-72)
    // that a margin without it is visibly too small.
    Params make_five_limb_golden_params()
    {
        Params params = make_golden_params();
        assignValues<int>(params.mShrinkExpand.mRing.mCoeffModulusBits, { 54, 54, 54, 54, 54 });
        params.mShrinkExpand.mMu =
            params.mShrinkExpand.mAlpha *
            params.mShrinkExpand.mTau *
            static_cast<std::uint32_t>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mW = params.mShrinkExpand.mMu;
        return params;
    }

    std::vector<RnsPoly> makeZeroPolys(const Params& params, std::size_t count)
    {
        std::vector<RnsPoly> polys(count);
        for (auto& poly : polys)
        {
            resizeZero(poly.mCoeffs, ringPolyCoeffCount(params.mShrinkExpand.mRing));
        }
        return polys;
    }
}

void LogVole_Core_LeafGoldenSeedMatchesDecoder(const oc::CLP&)
{
    // Every leaf value the check accepts must decode consistently: for |e| <= B and any m in Z_p,
    // decode(K + floor(q/p)*m + e) = decode(K) + m. The worst accepted K are the ones closest to the
    // rounding boundary, so the test finds them by bisecting on the check itself instead of assuming
    // where its threshold lies, then runs both through unwrapRingLabelsCrt.
    const Params params = make_five_limb_golden_params();
    ZpCrtContext zp{};
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(
        params.mShrinkExpand.mRing,
        params.mShrinkExpand.mPlaintextModulusBits,
        zp));
    const std::uint64_t p = zp.mPlaintextModulus;
    const std::size_t n = params.mShrinkExpand.mRing.mPolyModulusDegree;
    const std::size_t rho = zp.mRing.mModuli.size();
    const std::size_t coeff = n - 1;
    const double log2B = noiseBoundLog2(params);
    LOGVOLE_REQUIRE_TRUE(std::isfinite(log2B));
    LOGVOLE_REQUIRE_LT(log2B + 2.0, 64.0 * static_cast<double>(rho) - 1.0);
    const Words noise = wordsBelowPow2(log2B, rho);

    // K0 = (2p)^-1 mod q has frac(p*K0/q) = 1/2 + 1/(2q): exactly on the rounding boundary. K0 + s
    // sits about p*s/q above it, K0 - s about p*s/q below it.
    std::vector<std::uint64_t> boundary(rho);
    for (std::size_t i = 0; i < rho; ++i)
    {
        const auto& modulus = zp.mRing.mModuli[i];
        LOGVOLE_REQUIRE_TRUE(seal::util::try_invert_uint_mod(
            seal::util::multiply_uint_mod(2, p, modulus),
            modulus,
            boundary[i]));
    }
    auto setOffset = [&](RnsPoly& poly, const Words& s, bool above) {
        for (std::size_t i = 0; i < rho; ++i)
        {
            poly.mCoeffs[i * n + coeff] = addOffset(boundary[i], s, above, zp.mRing.mModuli[i]);
        }
    };
    auto leafAccepts = [&](const Words& s, bool above) {
        std::vector<RnsPoly> batch = makeZeroPolys(params, params.mW);
        setOffset(batch.back(), s, above);
        bool candidateOk = false;
        LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, batch, candidateOk));
        return candidateOk;
    };

    // decode(K + floor(q/p)*m +/- e) - decode(K) must equal the slot decoding of m*X^coeff.
    seal::BatchEncoder encoder(*zp.mBatchingContext);
    auto decodesConsistently = [&](const Words& s, bool above, std::uint64_t m, bool addNoise) {
        RnsPoly key = makeZeroPolys(params, 1).front();
        setOffset(key, s, above);
        RnsPoly mac = key;
        for (std::size_t i = 0; i < rho; ++i)
        {
            const auto& modulus = zp.mRing.mModuli[i];
            std::uint64_t& value = mac.mCoeffs[i * n + coeff];
            value = seal::util::add_uint_mod(
                value,
                seal::util::multiply_uint_mod(m, zp.mPlaintextLiftModQj[i], modulus),
                modulus);
            value = addOffset(value, noise, addNoise, modulus);
        }

        AlignedUnVec<std::uint64_t> keySlots;
        AlignedUnVec<std::uint64_t> macSlots;
        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(zp, { key }, zpSlotCount(zp), true, 1, keySlots));
        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(zp, { mac }, zpSlotCount(zp), true, 1, macSlots));

        seal::Plaintext plain(n);
        plain.set_zero();
        plain[coeff] = m;
        std::vector<std::uint64_t> expected;
        encoder.decode(plain, expected);

        LOGVOLE_REQUIRE_EQ(keySlots.size(), expected.size());
        LOGVOLE_REQUIRE_EQ(macSlots.size(), expected.size());
        for (std::size_t slot = 0; slot < expected.size(); ++slot)
        {
            if (macSlots[slot] != (keySlots[slot] + expected[slot]) % p)
            {
                return false;
            }
        }
        return true;
    };

    for (const bool above : { true, false })
    {
        Words one(rho, 0);
        one[0] = 1;
        Words fourB(rho);
        seal::util::left_shift_uint(noise.data(), 2, rho, fourB.data());
        const Words tightest = bisectAcceptThreshold(
            one,
            fourB,
            [&](const Words& s) { return leafAccepts(s, above); });

        // The tightest accepted offset must survive every noise sign and plaintext, including
        // m = p - 1, where floor(q/p)*m falls furthest short of (q/p)*m.
        for (const std::uint64_t m : { std::uint64_t{ 0 }, std::uint64_t{ 1 }, p - 1 })
        {
            for (const bool addNoise : { true, false })
            {
                LOGVOLE_EXPECT_TRUE(decodesConsistently(tightest, above, m, addNoise));
            }
        }

        // Negative control: half the threshold, with noise towards the boundary, must break decoding.
        Words half(rho);
        seal::util::right_shift_uint(tightest.data(), 1, rho, half.data());
        LOGVOLE_EXPECT_FALSE(decodesConsistently(half, above, 0, !above));
    }
}

void LogVole_Core_LeafGoldenSeedChecksPlaintextProduct(const oc::CLP& cmd)
{
    Params params = make_golden_params();
    auto& se = params.mShrinkExpand;
    se.mRing.mPolyModulusDegree = 8192;
    resizeFill<int>(se.mRing.mCoeffModulusBits, 4, 55);
    se.mPlaintextModulusBits = 55;
    se.mGadgetLogBase = 20;
    se.mTau = 11;
    se.mMu = se.mAlpha * se.mTau * 4;
    params.mW = se.mMu;
    LOGVOLE_REQUIRE_TRUE(validateShrinkExpandParams(se));
    LOGVOLE_REQUIRE_TRUE(validateGoldenSeedSearch(params));

    ZpCrtContext zp;
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(se.mRing, se.mPlaintextModulusBits, zp));
    const auto p = zp.mPlaintextModulus;
    const auto n = se.mRing.mPolyModulusDegree;
    const auto rho = zp.mRing.mModuli.size();
    const auto log2B = noiseBoundLog2(params);
    // A small gadget keeps the noise allowance below p, exposing the lift
    // error of the unreduced product Delta*x, which can approach p^2.
    LOGVOLE_REQUIRE_LT(log2B, std::log2(static_cast<double>(p)));

    seal::Plaintext plain(n);
    plain.set_zero();
    plain[n - 1] = p - 1;
    std::vector<std::uint64_t> inputs;
    seal::BatchEncoder encoder(*zp.mBatchingContext);
    encoder.decode(plain, inputs);
    RnsPoly delta, x, product;
    LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(zp, p - 1, true, 1, delta));
    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(zp, inputs, false, 0, 1, x));
    LOGVOLE_REQUIRE_TRUE(ringMultiply(delta, x, zp.mRing, product));

    auto makeCandidate = [&](wideU64 offset, bool above) {
        auto batch = makeZeroPolys(params, params.mW);
        for (std::size_t i = 0; i < rho; ++i)
        {
            const auto& qi = zp.mRing.mModuli[i];
            std::uint64_t boundary = 0;
            LOGVOLE_REQUIRE_TRUE(seal::util::try_invert_uint_mod(
                seal::util::multiply_uint_mod(2, p, qi), qi, boundary));
            const auto shift = wideU64Mod(offset, qi);
            batch.back().mCoeffs[i * n + n - 1] = above
                ? seal::util::add_uint_mod(boundary, shift, qi)
                : seal::util::sub_uint_mod(boundary, shift, qi);
        }
        return batch;
    };
    const auto noise = wordsBelowPow2(log2B, rho);
    auto mismatchedSlots = [&](const RnsPoly& key, int noiseSign) {
        RnsPoly mac;
        LOGVOLE_REQUIRE_TRUE(ringAdd(key, product, zp.mRing, mac));
        if (noiseSign)
            for (std::size_t i = 0; i < rho; ++i)
                mac.mCoeffs[i * n + n - 1] = addOffset(
                    mac.mCoeffs[i * n + n - 1], noise, noiseSign > 0,
                    zp.mRing.mModuli[i]);
        AlignedUnVec<std::uint64_t> keys, macs;
        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(zp, {key}, n, true, 1, keys));
        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(zp, {mac}, n, true, 1, macs));
        LOGVOLE_REQUIRE_EQ(keys.size(), inputs.size());
        LOGVOLE_REQUIRE_EQ(macs.size(), inputs.size());
        const seal::Modulus modulus(p);
        std::size_t mismatches = 0;
        for (std::size_t i = 0; i < inputs.size(); ++i)
            mismatches += macs[i] != mulAddMod(inputs[i], p - 1, keys[i], modulus);
        return mismatches;
    };

    // K=(2p)^-1+2^100 passes the old single-message lift margin, but the
    // actual wrapped product crosses the rounding boundary even with e=0.
    auto unsafe = makeCandidate(wideU64OneShift(100), true);
    LOGVOLE_REQUIRE_GT(mismatchedSlots(unsafe.back(), 0), std::size_t{0});
    bool accepted = true;
    LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, unsafe, accepted));
    LOGVOLE_EXPECT_FALSE(accepted);

    // Offsets beyond the full product allowance must remain usable on both
    // sides of the boundary, including either extremal noise sign.
    const auto pSquared = wideU64Mul(p, p);
    const auto safeOffset = wideU64Add(pSquared, pSquared);
    for (const bool above : {false, true})
    {
        auto safe = makeCandidate(safeOffset, above);
        accepted = false;
        LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, safe, accepted));
        LOGVOLE_EXPECT_TRUE(accepted);
        for (const int sign : {-1, 0, 1})
            LOGVOLE_EXPECT_EQ(mismatchedSlots(safe.back(), sign), std::size_t{0});

#if defined(ENABLE_LOGVOLE_CUDA)
        if (cmd.getOr("gpu", 0) != 0)
        {
            LOGVOLE_REQUIRE_TRUE(gpu::available());
            osuCrypto::LogVoleExecutionOptions advanced;
            advanced.mUseGpu = true;
            RingNttContext deviceContext;
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(se.mRing, deviceContext, std::make_shared<RingContextFactory>(advanced)));
            for (std::size_t i = 0; i < rho; ++i)
                LOGVOLE_REQUIRE_EQ(ringModulusValue(deviceContext, i), zp.mRing.mModuli[i].value());
            auto safeDevice = gpu::upload(deviceContext, safe);
            auto unsafeDevice = gpu::upload(deviceContext, unsafe);
            LOGVOLE_REQUIRE_TRUE(safeDevice && unsafeDevice);
            for (const bool bad : {false, true})
            {
                const auto& device = bad ? unsafeDevice : safeDevice;
                bool deviceOk = false;
                LOGVOLE_REQUIRE_TRUE(gpu::validateLeafGoldenSeedDevice(params, deviceContext, *device, deviceOk));
                LOGVOLE_EXPECT_EQ(deviceOk, !bad);
                if (gpu::deferredGoldenValidationEnabled(deviceContext.mExecutionOptions.mAdvanced.mProtocol))
                {
                    gpu::GoldenValidationAttempt attempt;
                    LOGVOLE_REQUIRE_TRUE(attempt.begin(deviceContext));
                    LOGVOLE_REQUIRE_TRUE(gpu::queueLeafGoldenSeedValidation(attempt, params, deviceContext, *device));
                    LOGVOLE_REQUIRE_TRUE(attempt.finish(deviceOk));
                    LOGVOLE_EXPECT_EQ(deviceOk, !bad);
                }
            }
        }
#endif
    }
#if !defined(ENABLE_LOGVOLE_CUDA)
    (void)cmd;
#endif
}

void LogVole_Core_LeafGoldenSeedGpuParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::available());
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    osuCrypto::LogVoleExecutionOptions advanced;
    advanced.mUseGpu = true;
    for (const std::uint32_t rho : {4u, 5u, 8u})
    {
        Params params = make_golden_params();
        resizeFill<int>(params.mShrinkExpand.mRing.mCoeffModulusBits, rho, 55);
        params.mShrinkExpand.mMu = params.mShrinkExpand.mAlpha * params.mShrinkExpand.mTau * rho;
        params.mW = params.mShrinkExpand.mMu - 1;
        ZpCrtContext zp;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mShrinkExpand.mRing,
            params.mShrinkExpand.mPlaintextModulusBits, zp,
            std::make_shared<ZpContextFactory>(std::make_shared<RingContextFactory>(advanced))));
        const auto n = params.mShrinkExpand.mRing.mPolyModulusDegree;
        auto boundary = makeZeroPolys(params, 1).front();
        for (std::size_t i = 0; i < rho; ++i)
        {
            const seal::Modulus q(ringModulusValue(zp.mRing, i));
            LOGVOLE_REQUIRE_TRUE(seal::util::try_invert_uint_mod(
                seal::util::multiply_uint_mod(2, zp.mPlaintextModulus, q), q,
                boundary.mCoeffs[i * n + n - 1]));
        }
        auto safe = makeZeroPolys(params, params.mShrinkExpand.mMu);
        // A bad value in the padded suffix must not reject the final output.
        safe.back() = boundary;
        auto unsafe = safe;
        unsafe[params.mW - 1] = boundary;
        auto safeDevice = gpu::upload(zp.mRing, safe);
        auto unsafeDevice = gpu::upload(zp.mRing, unsafe);
        LOGVOLE_REQUIRE_TRUE(safeDevice && unsafeDevice);
        if (rho == 4u && gpu::deferredGoldenValidationEnabled(advanced.mAdvanced.mProtocol))
        {
            auto isolated = zp.mRing;
            isolated.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(advanced);
            gpu::GoldenValidationAttempt rejected, accepted;
            LOGVOLE_REQUIRE_TRUE(rejected.begin(zp.mRing));
            LOGVOLE_REQUIRE_TRUE(accepted.begin(isolated));
            // Both consume the same immutable math context and device batches,
            // but their explicitly owned flags must remain independent.
            LOGVOLE_REQUIRE_TRUE(gpu::queueLeafGoldenSeedValidation(rejected, params, zp.mRing, *unsafeDevice));
            LOGVOLE_REQUIRE_TRUE(gpu::queueLeafGoldenSeedValidation(accepted, params, zp.mRing, *safeDevice));
            bool ok = false;
            LOGVOLE_REQUIRE_TRUE(accepted.finish(ok));
            LOGVOLE_REQUIRE_TRUE(ok);
            LOGVOLE_REQUIRE_TRUE(rejected.finish(ok));
            LOGVOLE_REQUIRE_FALSE(ok);
            LOGVOLE_REQUIRE_FALSE(rejected.finish(ok));
            // A completed attempt can reuse its flag without retaining failure.
            LOGVOLE_REQUIRE_TRUE(rejected.begin(zp.mRing));
            LOGVOLE_REQUIRE_TRUE(gpu::queueLeafGoldenSeedValidation(rejected, params, zp.mRing, *safeDevice));
            LOGVOLE_REQUIRE_TRUE(rejected.finish(ok));
            LOGVOLE_REQUIRE_TRUE(ok);
        }
        for (const bool bad : {false, true})
        {
            const auto& batch = bad ? unsafe : safe;
            const auto& device = bad ? unsafeDevice : safeDevice;
            auto logical = batch;
            logical.resize(params.mW);
            bool hostOk = false, deviceOk = false;
            LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, logical, hostOk));
            LOGVOLE_REQUIRE_EQ(hostOk, !bad);
            LOGVOLE_REQUIRE_TRUE(gpu::validateLeafGoldenSeedDevice(params, zp.mRing, *device, deviceOk));
            LOGVOLE_REQUIRE_EQ(hostOk, deviceOk);
            if (gpu::deferredGoldenValidationEnabled(advanced.mAdvanced.mProtocol))
            {
                gpu::GoldenValidationAttempt attempt;
                LOGVOLE_REQUIRE_TRUE(attempt.begin(zp.mRing));
                LOGVOLE_REQUIRE_TRUE(gpu::queueLeafGoldenSeedValidation(attempt, params, zp.mRing, *device));
                // A subsequent successful check must not erase a prior failure.
                LOGVOLE_REQUIRE_TRUE(gpu::queueLeafGoldenSeedValidation(attempt, params, zp.mRing, *safeDevice));
                LOGVOLE_REQUIRE_TRUE(attempt.finish(deviceOk));
                LOGVOLE_REQUIRE_EQ(hostOk, deviceOk);
            }
        }
        auto random = sample_batch(zp.mRing, params.mW, 0x193000u + rho);
        bool hostOk = false, deviceOk = false;
        LOGVOLE_REQUIRE_TRUE(validateLeafGoldenSeedCandidate(params, random, hostOk));
        auto randomDevice = gpu::upload(zp.mRing, random);
        LOGVOLE_REQUIRE_TRUE(randomDevice != nullptr);
        LOGVOLE_REQUIRE_TRUE(gpu::validateLeafGoldenSeedDevice(params, zp.mRing, *randomDevice, deviceOk));
        LOGVOLE_REQUIRE_EQ(hostOk, deviceOk);
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA";
#endif
}
