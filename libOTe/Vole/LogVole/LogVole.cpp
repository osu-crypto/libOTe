#include "libOTe/Vole/LogVole/LogVole.h"

#include "libOTe/config.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include "cryptoTools/Crypto/PRNG.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

namespace osuCrypto::LogVole
{
    struct ZpHostContextCache
    {
        std::mutex mMutex;
        std::shared_ptr<const ZpCrtContext> mContext;
        RingParams mRingParams;
        std::vector<u64> mRingModuli;
        std::shared_ptr<RingHostContextCache> mRingOwner;
        AlignedUnVec<u64> mPlaintextLiftModQj;
        u32 mRequestedPlaintextBits = 0;
        u32 mSelectedPlaintextBits = 0;
        u64 mPlaintextModulus = 0;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
    };

    namespace
    {
        struct CivoleOfflineMeta
        {
            u64 mLabelCount = 0;
            OnlineMode mMode = OnlineMode::Interactive;
        };

        bool validateZpValue(const ZpCrtContext& ctx, u64 value)
        {
            return ctx.mPlaintextModulus != 0 && value < ctx.mPlaintextModulus;
        }

        bool validateZpValues(const ZpCrtContext& ctx, std::span<const u64> values)
        {
            for (u64 value : values)
            {
                if (!validateZpValue(ctx, value))
                {
                    return false;
                }
            }
            return true;
        }

        bool validateZpContext(const ZpCrtContext& ctx)
        {
            const bool common = ctx.mPlaintextModulus != 0 &&
                validateRingContextMetadata(ctx.mRing) && ringModulusCount(ctx.mRing) != 0 &&
                ctx.mPlaintextLiftModQj.size() == ringModulusCount(ctx.mRing);
            if (!common) return false;
            if (ctx.mGpuLightweight)
            {
                if (!ctx.mRing.mGpuLightweight || !ctx.mHostContextCache ||
                    ctx.mBatchingContext || ctx.mBatchEncoder) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
                if (ctx.mNativeSealBundleCommitted)
                {
                    const auto& plain = ctx.mNativePlainNtt;
                    return plain && ctx.mRing.mRawModuli &&
                        ctx.mRing.mRawModuli->mDynamicGpuCertificate &&
                        plain->nativeBundleOwnerRole() ==
                            ctx.mRing.mRawModuli->mDynamicGpuCertificate->rawOwnerRole() &&
                        plain->n() == ctx.mRing.mParams.mPolyModulusDegree &&
                        plain->view().mMinModulus == ctx.mPlaintextModulus &&
                        plain->view().mMaxModulus == ctx.mPlaintextModulus;
                }
#endif
                return !ctx.mNativePlainNtt;
            }
            return !ctx.mRing.mGpuLightweight && ctx.mBatchingContext &&
                ctx.mBatchingContext->first_context_data() && ctx.mBatchEncoder &&
                !ctx.mNativePlainNtt && !ctx.mNativeSealBundleCommitted;
        }

        bool encodeSlotsToRingCrt(
            const ZpCrtContext& ctx,
            const std::vector<u64>& slots,
            seal::BatchEncoder& encoder,
            bool multiplyByDelta,
            RnsPoly& out)
        {
            const u64 slotCount = zpSlotCount(ctx);
            if (slots.size() != slotCount)
            {
                return false;
            }

            seal::Plaintext plain;
            try
            {
                encoder.encode(slots, plain);
            }
            catch (const std::exception&)
            {
                return false;
            }

            const std::size_t n = ctx.mRing.mParams.mPolyModulusDegree;
            const std::size_t rho = ctx.mRing.mModuli.size();
            out.mCoeffs.resize(n * rho);

            const u64* plainCoeffs = plain.data();
            const std::size_t plainCoeffCount = std::min<std::size_t>(n, plain.coeff_count());

            // The encoded coefficients overwrite the prefix in every limb.
            // Only an absent plaintext tail requires explicit zero padding.
            for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                std::fill(out.mCoeffs.data() + modIdx*n + plainCoeffCount,
                    out.mCoeffs.data() + (modIdx+1)*n, u64{0});

            if (!multiplyByDelta)
            {
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    std::copy_n(plainCoeffs, plainCoeffCount, out.mCoeffs.data() + modIdx * n);
                }
                return true;
            }

            for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
            {
                u64* limbCoeffs = out.mCoeffs.data() + modIdx * n;
                const u64 plaintextLiftModQj = ctx.mPlaintextLiftModQj[modIdx];
                const auto& modulus = ctx.mRing.mModuli[modIdx];
                for (std::size_t coeffIdx = 0; coeffIdx < plainCoeffCount; ++coeffIdx)
                {
                    limbCoeffs[coeffIdx] =
                        seal::util::multiply_uint_mod(plainCoeffs[coeffIdx], plaintextLiftModQj, modulus);
                }
            }
            return true;
        }

        RnsPoly makeZeroPoly(const RingParams& ring)
        {
            RnsPoly zero{};
            resizeZero(zero.mCoeffs, ringPolyCoeffCount(ring));
            return zero;
        }

        bool computeMuHi(const Params& params, u32& out)
        {
            if (params.mShrinkExpand.mTau < 2)
            {
                return false;
            }
            const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (rho == 0)
            {
                return false;
            }
            out = params.mShrinkExpand.mAlpha * (params.mShrinkExpand.mTau - 1) * rho;
            return out != 0;
        }

        bool computeInternalRingWidth(
            const Params& params,
            const ZpCrtContext& ctx,
            u64 labelCount,
            u32& out)
        {
            if (labelCount == 0)
            {
                return false;
            }

            const u64 packedWidth = zpRingLabelCount(ctx, labelCount);
            u32 muHi = 0;
            if (packedWidth == 0 || !computeMuHi(params, muHi))
            {
                return false;
            }

            const u64 paddedWidth = std::max<u64>(packedWidth, muHi);
            if (paddedWidth > std::numeric_limits<u32>::max())
            {
                return false;
            }
            out = static_cast<u32>(paddedWidth);
            return true;
        }

        void applySessionId(SenderState& state, CivoleSid sid)
        {
            state.mParams.mSessionId = sid;
            if (state.mNextLevelState)
            {
                applySessionId(*state.mNextLevelState, sid);
            }
        }

        void applySessionId(ReceiverState& state, CivoleSid sid)
        {
            state.mParams.mSessionId = sid;
            if (state.mNextLevelState)
            {
                applySessionId(*state.mNextLevelState, sid);
            }
        }

        void clearSenderCachedOutputs(SenderState& state)
        {
            state.mGoldenSeed.clear();
            state.mRootKPrimeRt.reset();
            state.mRootKPrimeRtDevice.reset();
            state.mRootDPrimeRt.reset();
            state.mRootDPrimeHashValid = false;
            state.mPrecomputedTbk.reset();
            state.mPrecomputedTbkDevice.reset();
            state.mPrecomputedTbkCount = 0;
            if (state.mNextLevelState)
            {
                clearSenderCachedOutputs(*state.mNextLevelState);
            }
        }

        void clearReceiverCachedOutputs(ReceiverState& state)
        {
            state.mGoldenSeed.clear();
            state.mRootDPrimeRt.reset();
            state.mRootDPrimeHashValid = false;
            if (state.mNextLevelState)
            {
                clearReceiverCachedOutputs(*state.mNextLevelState);
            }
        }

        bool containsSid(const AlignedUnVec<CivoleSid>& sids, CivoleSid sid)
        {
            return std::find(sids.begin(), sids.end(), sid) != sids.end();
        }

        bool prepareSenderSidForReleaseK(CivoleSenderState& state, CivoleSid sid)
        {
            if (containsSid(state.mUsedSids, sid))
            {
                return false;
            }
            if (state.mHasActiveSid &&
                state.mActiveSid != sid &&
                state.mKeyReleased &&
                !state.mReleaseIntUsed)
            {
                return false;
            }
            if (state.mHasActiveSid && state.mActiveSid == sid)
            {
                return true;
            }

            clearSenderCachedOutputs(state.mLogVoleState);
            applySessionId(state.mLogVoleState, sid);
            state.mHasActiveSid = true;
            state.mActiveSid = sid;
            state.mKeyReleased = false;
            state.mReleaseIntUsed = false;
            state.mReleasedKeys.clear();
            return true;
        }

        bool prepareReceiverSidForSetX(CivoleReceiverState& state, CivoleSid sid)
        {
            if (containsSid(state.mUsedSids, sid))
            {
                return false;
            }

            const auto usedSidCount = state.mUsedSids.size();
            state.mUsedSids.resize(usedSidCount + 1);
            state.mUsedSids[usedSidCount] = sid;
            clearReceiverCachedOutputs(state.mLogVoleState);
            applySessionId(state.mLogVoleState, sid);
            return true;
        }

        void writeU64(std::span<u8> out, u64 value)
        {
            if (out.size() != 8)
            {
                throw std::runtime_error("LogVole CI-VOLE metadata field has invalid size");
            }
            for (u32 i = 0; i < 8; ++i)
            {
                out[i] = static_cast<u8>((value >> (8 * i)) & 0xFF);
            }
        }

        u64 readU64(std::span<const u8> in)
        {
            if (in.size() != 8)
            {
                throw std::runtime_error("LogVole CI-VOLE metadata field has invalid size");
            }

            u64 value = 0;
            for (u32 i = 0; i < 8; ++i)
            {
                value |= static_cast<u64>(in[i]) << (8 * i);
            }
            return value;
        }

        task<> sendCivoleOfflineMeta(Socket& sock, const CivoleOfflineMeta& meta)
        {
            std::array<u8, 16> payload{};
            writeU64(std::span<u8>(payload).subspan(0, 8), meta.mLabelCount);
            writeU64(std::span<u8>(payload).subspan(8, 8), static_cast<u64>(meta.mMode));
            co_await sock.send(coproto::copy(payload));
        }

        task<CivoleOfflineMeta> recvCivoleOfflineMeta(Socket& sock)
        {
            std::array<u8, 16> payload{};
            co_await sock.recv(payload);

            CivoleOfflineMeta meta{};
            meta.mLabelCount = readU64(std::span<const u8>(payload).subspan(0, 8));
            const u64 mode = readU64(std::span<const u8>(payload).subspan(8, 8));
            if (mode > static_cast<u64>(OnlineMode::NonInteractive))
                throw std::runtime_error("LogVole CI-VOLE offline mode is invalid");
            meta.mMode = static_cast<OnlineMode>(mode);
            co_return meta;
        }
    }

    bool makeDefaultCivoleParams(CivoleParams& out, u32 workerThreads)
    {
        CivoleParams params{};
        params.mLogVole.mShrinkExpand.mRing.mPolyModulusDegree = 8192;
        resizeFill<int>(params.mLogVole.mShrinkExpand.mRing.mCoeffModulusBits, 4, 55);
        params.mLogVole.mShrinkExpand.mPlaintextModulusBits = 55;
        params.mLogVole.mShrinkExpand.mMode = ShrinkExpandMode::FullNoise;
        params.mLogVole.mShrinkExpand.mNoiseBound = 2;
        params.mLogVole.mShrinkExpand.mAlpha = 2;
        params.mLogVole.mShrinkExpand.mGadgetLogBase = 110;
        params.mLogVole.mShrinkExpand.mNumWorkerThreads = workerThreads;

        u32 logQ = 0;
        for (int bits : params.mLogVole.mShrinkExpand.mRing.mCoeffModulusBits)
        {
            logQ += static_cast<u32>(bits);
        }
        params.mLogVole.mShrinkExpand.mTau =
            (logQ + params.mLogVole.mShrinkExpand.mGadgetLogBase - 1) /
            params.mLogVole.mShrinkExpand.mGadgetLogBase;
        const u32 rho = static_cast<u32>(params.mLogVole.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mLogVole.mShrinkExpand.mMu =
            params.mLogVole.mShrinkExpand.mAlpha * params.mLogVole.mShrinkExpand.mTau * rho;
        params.mLogVole.mGamma = 1;
        out = std::move(params);
        return true;
    }

    bool makeNoGoldenSeedCivoleParams(CivoleParams& out, u32 workerThreads)
    {
        // Fixed NoGoldenSeed parameter set:
        // n=16384 log_q=416 log_p=52 log_g=208 m=2, i.e. rho = 416/52 = 8 limbs,
        // tau = ceil(416/208) = 2 so tauHi = 1 and muHi = alpha*tauHi*rho = 16.
        // log_q = 416 is inside the 128-bit HE guidance for n = 16384 (438).
        //
        // Delta_j = prod_{w != j} q_w is 7 x 52 = 364 bits against a noise bound
        // of log2 B = 234.2 at 2^21 labels, so a sampled ct2 coefficient is bad
        // with probability at most 2^-128.8 and no golden seed is needed.
        CivoleParams params{};
        params.mLogVole.mShrinkExpand.mRing.mPolyModulusDegree = 16384;
        resizeFill<int>(params.mLogVole.mShrinkExpand.mRing.mCoeffModulusBits, 8, 52);
        params.mLogVole.mShrinkExpand.mPlaintextModulusBits = 52;
        params.mLogVole.mShrinkExpand.mMode = ShrinkExpandMode::FullNoise;
        params.mLogVole.mShrinkExpand.mNoiseBound = 2;
        params.mLogVole.mShrinkExpand.mAlpha = 2;
        params.mLogVole.mShrinkExpand.mGadgetLogBase = 208;
        params.mLogVole.mShrinkExpand.mNumWorkerThreads = workerThreads;
        params.mLogVole.mCt2SeedMode = Ct2SeedMode::PublicSeed;

        // The tuple carries 1.79 bits of margin against the optimizer's
        // log2(B) + 128 <= log2(Delta) line at 2^21 labels, which is a
        // per-coefficient failure bound of 2^-128.8 there but shrinks with the
        // request size (B grows with the reuse count T): 2^-128.2 at 2^23,
        // 2^-127.8 at 2^24, 2^-127.1 at 2^26. Requiring a full 128 bits would
        // therefore cap the setting at 2^23 labels, so the accepted bound is
        // stated as 127 - the value the optimizer's feasible frontier actually
        // implies - rather than silently failing above it.
        params.mLogVole.mCt2StatBits = 127;

        u32 logQ = 0;
        for (int bits : params.mLogVole.mShrinkExpand.mRing.mCoeffModulusBits)
        {
            logQ += static_cast<u32>(bits);
        }
        params.mLogVole.mShrinkExpand.mTau =
            (logQ + params.mLogVole.mShrinkExpand.mGadgetLogBase - 1) /
            params.mLogVole.mShrinkExpand.mGadgetLogBase;
        const u32 rho = static_cast<u32>(params.mLogVole.mShrinkExpand.mRing.mCoeffModulusBits.size());
        params.mLogVole.mShrinkExpand.mMu =
            params.mLogVole.mShrinkExpand.mAlpha * params.mLogVole.mShrinkExpand.mTau * rho;
        params.mLogVole.mGamma = 1;
        out = std::move(params);
        return true;
    }

    bool makeCivoleParams(CivoleSetting setting, CivoleParams& out, u32 workerThreads)
    {
        switch (setting)
        {
        case CivoleSetting::GoldenSeed:
            return makeDefaultCivoleParams(out, workerThreads);
        case CivoleSetting::NoGoldenSeed:
            return makeNoGoldenSeedCivoleParams(out, workerThreads);
        }
        return false;
    }

    u32 civoleSettingPlaintextModulusBits(CivoleSetting setting)
    {
        return setting == CivoleSetting::NoGoldenSeed ? 52u : 0u;
    }

    static bool resolveCivoleModulusWithEvidence(
        const CivoleParams& params, u64& out, bool* nativeBundleCommitted)
    {
        ZpCrtContext ctx{};
        if (!makeZpCrtContext(
                params.mLogVole.mShrinkExpand.mRing,
                params.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx))
        {
            return false;
        }
        out = ctx.mPlaintextModulus;
        if (nativeBundleCommitted)
            *nativeBundleCommitted = ctx.mNativeSealBundleCommitted;
        return true;
    }

    bool resolveCivoleModulus(const CivoleParams& params, u64& out)
    {
        return resolveCivoleModulusWithEvidence(params, out, nullptr);
    }

}

namespace osuCrypto
{
    using namespace LogVole;

    LogVoleSender::LogVoleSender(LogVoleSender&& other)
    {
        *this = std::move(other);
    }

    LogVoleSender& LogVoleSender::operator=(LogVoleSender&& other)
    {
        if (this != &other)
        {
            mTimer = other.mTimer;
            mRequestSize = other.mRequestSize;
            mPlaintextModulusBits = other.mPlaintextModulusBits;
            mModulus = other.mModulus;
            mDelta = other.mDelta;
            mNumThreads = other.mNumThreads;
            mNextSid = other.mNextSid;
            mLastOnlineComm = other.mLastOnlineComm;
            mState = other.mState;
            mSetting = other.mSetting;
            mConfigureCacheRunId = other.mConfigureCacheRunId;
            mNativeSealBundleAtConfigure = other.mNativeSealBundleAtConfigure;
            mKeepOutputOnDevice = other.mKeepOutputOnDevice;
            mOutputDevice = std::move(other.mOutputDevice);
            mOutputDeviceCount = other.mOutputDeviceCount;
            mParams = std::move(other.mParams);
            mOfflineState = std::move(other.mOfflineState);

            other.mTimer = nullptr;
            other.clear();
        }
        return *this;
    }

    LogVoleReceiver::LogVoleReceiver(LogVoleReceiver&& other)
    {
        *this = std::move(other);
    }

    LogVoleReceiver& LogVoleReceiver::operator=(LogVoleReceiver&& other)
    {
        if (this != &other)
        {
            mTimer = other.mTimer;
            mRequestSize = other.mRequestSize;
            mPlaintextModulusBits = other.mPlaintextModulusBits;
            mModulus = other.mModulus;
            mNumThreads = other.mNumThreads;
            mNextSid = other.mNextSid;
            mLastOnlineComm = other.mLastOnlineComm;
            mState = other.mState;
            mInputDevice = std::move(other.mInputDevice);
            mSetting = other.mSetting;
            mConfigureCacheRunId = other.mConfigureCacheRunId;
            mNativeSealBundleAtConfigure = other.mNativeSealBundleAtConfigure;
            mKeepOutputOnDevice = other.mKeepOutputOnDevice;
            mOutputDevice = std::move(other.mOutputDevice);
            mOutputDeviceCount = other.mOutputDeviceCount;
            mParams = std::move(other.mParams);
            mOfflineState = std::move(other.mOfflineState);

            other.mTimer = nullptr;
            other.clear();
        }
        return *this;
    }

    void LogVoleSender::configure(
        u64 n,
        u32 plaintextModulusBits,
        u32 numThreads,
        LogVole::CivoleSetting setting,
        LogVole::OnlineMode mode)
    {
        const auto inheritedRun = LogVole::currentProtocolCacheScope().mRunId;
        const auto configureRun = inheritedRun ? inheritedRun :
            LogVole::allocateProtocolCacheRunId();
        LogVole::ScopedProtocolCacheScope roleScope(
            LogVole::ProtocolCacheRole::Sender, configureRun);
        if ((mode != OnlineMode::Interactive && mode != OnlineMode::NonInteractive) ||
            (mode == OnlineMode::NonInteractive && setting != CivoleSetting::NoGoldenSeed))
            throw std::runtime_error("LogVole non-interactive mode requires NoGoldenSeed");
        if (n == 0)
        {
            throw std::runtime_error("LogVole CI-VOLE sender requires a nonzero request size");
        }
        if (const u32 fixed = civoleSettingPlaintextModulusBits(setting))
        {
            // The setting's parameter tuple pins log p to the RNS limb size, so a
            // different request cannot be honoured.
            plaintextModulusBits = fixed;
        }
        if (plaintextModulusBits < 2 || plaintextModulusBits > 61)
        {
            throw std::runtime_error("LogVole CI-VOLE plaintext modulus bit count is invalid");
        }
        if (numThreads == 0)
        {
            numThreads = 1;
        }

        CivoleParams params{};
        u64 modulus = 0;
        bool nativeBundleCommitted = false;
        if (!makeCivoleParams(setting, params, numThreads))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not create default parameters");
        }
        params.mLogVole.mShrinkExpand.mPlaintextModulusBits = plaintextModulusBits;
        params.mLogVole.mOnlineMode = mode;
        if (!resolveCivoleModulusWithEvidence(
                params, modulus, &nativeBundleCommitted))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not resolve plaintext modulus");
        }

        mRequestSize = n;
        mPlaintextModulusBits = plaintextModulusBits;
        mModulus = modulus;
        mConfigureCacheRunId = configureRun;
        mNativeSealBundleAtConfigure = nativeBundleCommitted;
        mDelta = 0;
        mNumThreads = numThreads;
        mNextSid = 0;
        mLastOnlineComm = {};
        mSetting = setting;
        mParams = std::move(params);
        mOfflineState = {};
        mState = State::Configured;
    }

    task<> LogVoleSender::offline(u64 delta, PRNG& prng, Socket& sock)
    {
        if (!isConfigured())
        {
            throw std::runtime_error("LogVole CI-VOLE sender must be configured before offline");
        }

        CivoleSenderOfflineInput input{};
        input.mParams = mParams;
        input.mDelta = delta;
        input.mW = mRequestSize;

        CivoleSenderState state{};
        co_await civoleSenderOffline(input, state, prng, sock);

        mOfflineState = std::move(state);
        mModulus = mOfflineState.mModulus;
        mDelta = delta;
        mNextSid = 0;
        mLastOnlineComm = {};
        mState = State::Offline;
    }

    task<> LogVoleSender::send(span<u64> b, PRNG& prng, Socket& sock)
    {
        if (!hasOffline())
        {
            throw std::runtime_error("LogVole CI-VOLE sender requires offline state before send");
        }
        if (b.size() != mRequestSize && !(mKeepOutputOnDevice && b.empty()))
        {
            throw std::runtime_error("LogVole CI-VOLE sender output size does not match configured size");
        }

        const CivoleSid sid = mNextSid++;
        CivoleSenderReleaseOutput release{};
        LogVole::CivoleSenderReleaseOptions options{};
        options.mKeepKeysOnDevice = mKeepOutputOnDevice;
        if (!mKeepOutputOnDevice)
        {
            // Hand the destination down so the keys are written once rather than
            // allocated, copied into mReleasedKeys, and copied again into b.
            options.mKeysOut = std::span<u64>(b.data(), b.size());
        }
        co_await civoleSenderRelease(mOfflineState, sid, release, prng, sock, options);

        mOutputDevice = release.mKeysDevice;
        mOutputDeviceCount = release.mKeysDeviceCount;
        if (b.empty() && (!release.mKeysDevice || release.mKeysDeviceCount != mRequestSize))
        {
            throw std::runtime_error("LogVole CI-VOLE sender declined its requested device-only output");
        }
        if (!release.mKeysDevice && !mOfflineState.mReleasedKeys.empty())
        {
            if (mOfflineState.mReleasedKeys.size() != b.size())
            {
                throw std::runtime_error("LogVole CI-VOLE sender key output size is invalid");
            }
            std::copy(mOfflineState.mReleasedKeys.begin(), mOfflineState.mReleasedKeys.end(), b.begin());
        }
        mLastOnlineComm = release.mComm;
    }

    task<> LogVoleSender::send(u64 delta, span<u64> b, PRNG& prng, Socket& sock)
    {
        if (!isConfigured())
        {
            if (b.empty() && mKeepOutputOnDevice)
                throw std::runtime_error("LogVole CI-VOLE device-only sender requires configured size");
            configure(b.size(), mPlaintextModulusBits, mNumThreads, mSetting);
        }
        if (b.size() != mRequestSize && !(mKeepOutputOnDevice && b.empty()))
        {
            throw std::runtime_error("LogVole CI-VOLE sender output size does not match configured size");
        }
        if (!hasOffline())
        {
            co_await offline(delta, prng, sock);
        }
        else if (delta != mDelta)
        {
            throw std::runtime_error("LogVole CI-VOLE sender offline delta does not match requested delta");
        }

        co_await send(b, prng, sock);
    }

    void LogVoleSender::clear()
    {
        mRequestSize = 0;
        mPlaintextModulusBits = 55;
        mModulus = 0;
        mDelta = 0;
        mNumThreads = 1;
        mNextSid = 0;
        mLastOnlineComm = {};
        mSetting = LogVole::CivoleSetting::GoldenSeed;
        mParams = {};
        mOfflineState = {};
        mState = State::Default;
        mKeepOutputOnDevice = false;
        mOutputDevice.reset();
        mOutputDeviceCount = 0;
        mConfigureCacheRunId = 0;
        mNativeSealBundleAtConfigure = false;
    }

    void LogVoleReceiver::configure(
        u64 n,
        u32 plaintextModulusBits,
        u32 numThreads,
        LogVole::CivoleSetting setting,
        LogVole::OnlineMode mode)
    {
        const auto inheritedRun = LogVole::currentProtocolCacheScope().mRunId;
        const auto configureRun = inheritedRun ? inheritedRun :
            LogVole::allocateProtocolCacheRunId();
        LogVole::ScopedProtocolCacheScope roleScope(
            LogVole::ProtocolCacheRole::Receiver, configureRun);
        if ((mode != OnlineMode::Interactive && mode != OnlineMode::NonInteractive) ||
            (mode == OnlineMode::NonInteractive && setting != CivoleSetting::NoGoldenSeed))
            throw std::runtime_error("LogVole non-interactive mode requires NoGoldenSeed");
        if (n == 0)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver requires a nonzero request size");
        }
        if (const u32 fixed = civoleSettingPlaintextModulusBits(setting))
        {
            plaintextModulusBits = fixed;
        }
        if (plaintextModulusBits < 2 || plaintextModulusBits > 61)
        {
            throw std::runtime_error("LogVole CI-VOLE plaintext modulus bit count is invalid");
        }
        if (numThreads == 0)
        {
            numThreads = 1;
        }

        CivoleParams params{};
        u64 modulus = 0;
        bool nativeBundleCommitted = false;
        if (!makeCivoleParams(setting, params, numThreads))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not create default parameters");
        }
        params.mLogVole.mShrinkExpand.mPlaintextModulusBits = plaintextModulusBits;
        params.mLogVole.mOnlineMode = mode;
        if (!resolveCivoleModulusWithEvidence(
                params, modulus, &nativeBundleCommitted))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not resolve plaintext modulus");
        }

        mRequestSize = n;
        mPlaintextModulusBits = plaintextModulusBits;
        mModulus = modulus;
        mConfigureCacheRunId = configureRun;
        mNativeSealBundleAtConfigure = nativeBundleCommitted;
        mNumThreads = numThreads;
        mNextSid = 0;
        mLastOnlineComm = {};
        mSetting = setting;
        mParams = std::move(params);
        mOfflineState = {};
        mState = State::Configured;
    }

    task<> LogVoleReceiver::offline(Socket& sock)
    {
        if (!isConfigured())
        {
            throw std::runtime_error("LogVole CI-VOLE receiver must be configured before offline");
        }

        CivoleReceiverOfflineInput input{};
        input.mParams = mParams;
        input.mW = mRequestSize;

        CivoleReceiverState state{};
        co_await civoleReceiverOffline(input, state, sock);
        if (state.mW != mRequestSize)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver offline size does not match configured size");
        }

        mOfflineState = std::move(state);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mOfflineState.mFirstQueryGpuAllocations)
        {
            ScopedProtocolCacheScope receiverRole(
                ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
            auto plan = std::static_pointer_cast<gpu::ReceiverFirstQueryAllocations>(
                mOfflineState.mFirstQueryGpuAllocations);
            // The offline helper's temporary state has been moved into this
            // receiver's final storage. Seal that address before any query can
            // bind the reservation; a copied handle in another state declines.
            if (!gpu::sealReceiverFirstQueryAllocationOwner(
                    plan, &mOfflineState))
                mOfflineState.mFirstQueryGpuAllocations.reset();
        }
#endif
        mModulus = mOfflineState.mModulus;
        mNextSid = 0;
        mLastOnlineComm = {};
        mState = State::Offline;
    }

    task<> LogVoleReceiver::receive(span<const u64> x, span<u64> a, PRNG& prng, Socket& sock)
    {
        const bool emptyDeviceInput = x.empty() && mInputDevice != nullptr;
        const bool emptyDeviceOutput = a.empty() && mKeepOutputOnDevice;
        if (!isConfigured() && (emptyDeviceInput || emptyDeviceOutput))
        {
            throw std::runtime_error("LogVole CI-VOLE device-only receiver requires configured size");
        }
        const u64 inputSize = emptyDeviceInput ? mRequestSize : x.size();
        const u64 outputSize = emptyDeviceOutput ? mRequestSize : a.size();
        if (inputSize != outputSize)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver input and output sizes do not match");
        }
        if (!isConfigured())
        {
            configure(inputSize, mPlaintextModulusBits, mNumThreads, mSetting);
        }
        if (inputSize != mRequestSize)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver input size does not match configured size");
        }
        if (!hasOffline())
        {
            co_await offline(sock);
        }

        const CivoleSid sid = mNextSid;

        CivoleReceiverSetXOutput setX{};
        LogVole::CivoleReceiverSetXOptions options{};
        options.mKeepMacsOnDevice = mKeepOutputOnDevice;
        options.mXDevice = mInputDevice;
        options.mXDeviceCount = mInputDevice ? mRequestSize : 0;
        if (!mKeepOutputOnDevice)
        {
            // Hand the destination down so the MACs land in the caller's buffer
            // directly instead of being allocated and then copied.
            options.mMacsOut = std::span<u64>(a.data(), a.size());
        }
        try
        {
            co_await civoleReceiverSetX(mOfflineState, sid, x, setX, prng, sock, options);
        }
        catch (...)
        {
            // setX records a SID only after validating local input. Preserve
            // the counter on a local rejection, but never reuse a SID after
            // a later failure that may have exposed query material to the peer.
            if (std::find(mOfflineState.mUsedSids.begin(), mOfflineState.mUsedSids.end(), sid) !=
                mOfflineState.mUsedSids.end())
                ++mNextSid;
            throw;
        }
        ++mNextSid;

        mOutputDevice = setX.mMacsDevice;
        mOutputDeviceCount = setX.mMacsDeviceCount;
        if (a.empty() && (!setX.mMacsDevice || setX.mMacsDeviceCount != mRequestSize))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver declined its requested device-only output");
        }
        if (!setX.mMacsDevice)
        {
            if (!setX.mMacs.empty())
            {
                if (setX.mMacs.size() != a.size())
                {
                    throw std::runtime_error("LogVole CI-VOLE receiver MAC output size is invalid");
                }
                std::copy(setX.mMacs.begin(), setX.mMacs.end(), a.begin());
            }
            // else: civoleReceiverSetX already wrote into `a`.
        }
        mLastOnlineComm = setX.mComm;
    }

    void LogVoleReceiver::clear()
    {
        mRequestSize = 0;
        mPlaintextModulusBits = 55;
        mModulus = 0;
        mNumThreads = 1;
        mNextSid = 0;
        mLastOnlineComm = {};
        mSetting = LogVole::CivoleSetting::GoldenSeed;
        mParams = {};
        mOfflineState = {};
        mState = State::Default;
        mInputDevice.reset();
        mKeepOutputOnDevice = false;
        mOutputDevice.reset();
        mOutputDeviceCount = 0;
        mConfigureCacheRunId = 0;
        mNativeSealBundleAtConfigure = false;
    }
}

namespace osuCrypto::LogVole
{

    u64 zpSlotCount(const ZpCrtContext& ctx)
    {
        return ctx.mRing.mParams.mPolyModulusDegree;
    }

    u64 zpRingLabelCount(const ZpCrtContext& ctx, u64 zpLabelCount)
    {
        const u64 slots = zpSlotCount(ctx);
        if (slots == 0)
        {
            return 0;
        }
        return zpLabelCount / slots + static_cast<u64>((zpLabelCount % slots) != 0);
    }

    namespace
    {
        // makeZpCrtContext builds a second SEALContext plus a BatchEncoder, both
        // of which are expensive and depend only on (ring, plaintext bits). The
        // online phase asks for one per query, so they are memoised.
        struct ZpCacheKey
        {
            u32 mDegree = 0;
            u32 mPlaintextBits = 0;
            std::vector<int> mBits;
            bool mExpandModChain = true;
            bool mSingleBatchLimb = false;
            bool mGpuLightweight = false;
            bool mNativeSealBundleRequested = false;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;

            bool operator==(const ZpCacheKey& o) const
            {
                return mDegree == o.mDegree && mPlaintextBits == o.mPlaintextBits && mBits == o.mBits &&
                    mExpandModChain == o.mExpandModChain && mSingleBatchLimb == o.mSingleBatchLimb &&
                    mGpuLightweight == o.mGpuLightweight &&
                    mNativeSealBundleRequested == o.mNativeSealBundleRequested &&
                    mRole == o.mRole;
            }
        };

        struct ZpCacheKeyHash
        {
            std::size_t operator()(const ZpCacheKey& k) const
            {
                std::size_t h = std::hash<u32>{}(k.mDegree) ^ (std::hash<u32>{}(k.mPlaintextBits) << 1);
                for (int b : k.mBits)
                {
                    h ^= std::hash<int>{}(b) + 0x9e3779b9u + (h << 6) + (h >> 2);
                }
                h ^= std::hash<bool>{}(k.mExpandModChain) + 0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<bool>{}(k.mSingleBatchLimb) + 0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<bool>{}(k.mGpuLightweight) + 0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<bool>{}(k.mNativeSealBundleRequested) +
                    0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<u8>{}(static_cast<u8>(k.mRole)) + 0x9e3779b9u + (h << 6) + (h >> 2);
                return h;
            }
        };

        using ZpCache =
            std::unordered_map<ZpCacheKey, std::shared_ptr<const ZpCrtContext>, ZpCacheKeyHash>;

        // Deliberately never destroyed. The cached ZpCrtContext keeps
        // seal::SEALContext and seal::BatchEncoder alive, and those hold
        // allocations from SEAL's global MemoryPoolMT. At process exit there is
        // no ordering guarantee between this cache and that pool, and tearing
        // the pool down first makes the shared_ptr release corrupt the heap
        // (aborts in MemoryPoolHeadMT::~MemoryPoolHeadMT). A process-lifetime
        // cache has nothing to gain from being freed at exit.
        ZpCache& zpContextCache()
        {
            static ZpCache* cache = new ZpCache();
            return *cache;
        }
        std::mutex zpContextCacheMutex;

        bool makeZpCrtContextUncached(
            const RingParams& ring, u32 plaintextModulusBits, bool expandModChain,
            bool singleBatchLimb, ZpCrtContext& out);

        bool makeGpuZpCrtContextUncached(
            const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out);

        bool productionGpuZpTuple(const RingParams& ring, u32 plaintextModulusBits)
        {
            const auto allBits = [&](int expected, std::size_t count) {
                return ring.mCoeffModulusBits.size() == count &&
                    std::all_of(ring.mCoeffModulusBits.begin(), ring.mCoeffModulusBits.end(),
                        [&](int bits) { return bits == expected; });
            };
            return (ring.mPolyModulusDegree == 8192u && plaintextModulusBits == 55u && allBits(55, 4)) ||
                (ring.mPolyModulusDegree == 16384u && plaintextModulusBits == 52u && allBits(52, 8));
        }

        bool gpuZpTupleSupported(const RingParams& ring, u32 plaintextModulusBits)
        {
            if (productionGpuZpTuple(ring, plaintextModulusBits)) return true;
#if defined(ENABLE_LOGVOLE_CUDA)
            return plaintextModulusBits && gpu::dynamicSealSetupSupported(ring) &&
                gpu::currentDeviceOrdinal() == 0;
#else
            return false;
#endif
        }
    }

    bool makeZpCrtContext(const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out)
    {
        if (plaintextModulusBits == 0)
        {
            return false;
        }

        ZpCacheKey key{};
        key.mDegree = ring.mPolyModulusDegree;
        key.mPlaintextBits = plaintextModulusBits;
        key.mBits.assign(ring.mCoeffModulusBits.begin(), ring.mCoeffModulusBits.end());
        const auto ownerScope = currentProtocolCacheScope();
        key.mRole = ownerScope.mRole;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* fullChain = std::getenv("LV_GPU_SETUP_FULL_MOD_CHAIN");
        key.mExpandModChain = !gpu::enabled() || (fullChain && fullChain[0] == '1');
        const char* singleLimb = std::getenv("LV_GPU_SETUP_BATCHING_SINGLE_LIMB");
        key.mSingleBatchLimb = gpu::enabled() && (!singleLimb || singleLimb[0] != '0');
        const char* lightweight = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_CRT");
        const char* lightweightRing = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_RING");
        key.mGpuLightweight = gpu::enabled() && (!lightweight || lightweight[0] != '0') &&
            (!lightweightRing || lightweightRing[0] != '0') &&
            !key.mExpandModChain && key.mSingleBatchLimb &&
            gpuZpTupleSupported(ring, plaintextModulusBits);
        const char* bundleControl = std::getenv("LV_GPU_NATIVE_SEAL_BUNDLE");
        key.mNativeSealBundleRequested = key.mGpuLightweight &&
            (ownerScope.mRole == ProtocolCacheRole::Sender ||
                ownerScope.mRole == ProtocolCacheRole::Receiver) &&
            bundleControl && std::strcmp(bundleControl, "1") == 0;
#endif

        {
            std::lock_guard<std::mutex> lock(zpContextCacheMutex);
            auto it = zpContextCache().find(key);
            if (it != zpContextCache().end())
            {
                out = *it->second;
                return true;
            }
        }

        ZpCrtContext built{};
        const bool builtOk = key.mGpuLightweight
            ? makeGpuZpCrtContextUncached(ring, plaintextModulusBits, built)
            : makeZpCrtContextUncached(
                  ring, plaintextModulusBits, key.mExpandModChain, key.mSingleBatchLimb, built);
        if (!builtOk)
        {
            return false;
        }

        // A configure call can run before its protocol run ID is assigned,
        // and a device factory can decline cleanly. Keep that sequential
        // result under the opt-out key so a later scoped setup can still
        // create the native owner instead of inheriting this fallback.
        if (key.mNativeSealBundleRequested &&
            !built.mNativeSealBundleCommitted)
            key.mNativeSealBundleRequested = false;

        auto shared = std::make_shared<const ZpCrtContext>(std::move(built));
        {
            std::lock_guard<std::mutex> lock(zpContextCacheMutex);
            auto [it, inserted] = zpContextCache().emplace(std::move(key), shared);
            (void)inserted;
            out = *it->second;
        }
        return true;
    }

    bool makeNativeSealSetupContexts(const RingParams& ring,
        u32 plaintextModulusBits, RingNttContext& ringOut,
        ZpCrtContext& zpOut)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* optIn = std::getenv("LV_GPU_NATIVE_SEAL_BUNDLE");
        const char* lightweightRing = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_RING");
        const char* lightweightCrt = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_CRT");
        const char* fullChain = std::getenv("LV_GPU_SETUP_FULL_MOD_CHAIN");
        const char* singleLimb = std::getenv("LV_GPU_SETUP_BATCHING_SINGLE_LIMB");
        const auto ownerScope = currentProtocolCacheScope();
        const bool requested = gpu::enabled() &&
            gpu::dynamicSealSetupSupported(ring) &&
            (ownerScope.mRole == ProtocolCacheRole::Sender ||
                ownerScope.mRole == ProtocolCacheRole::Receiver) &&
            ownerScope.mRunId != 0u &&
            optIn && std::strcmp(optIn, "1") == 0 &&
            (!lightweightRing || lightweightRing[0] != '0') &&
            (!lightweightCrt || lightweightCrt[0] != '0') &&
            (!fullChain || fullChain[0] != '1') &&
            (!singleLimb || singleLimb[0] != '0');
        if (requested)
        {
            // The CRT factory creates or reuses the ring internally. A prior
            // standalone Ring call would force an early q download and defeat
            // the private one-record producer.
            ZpCrtContext next{};
            if (!makeZpCrtContext(ring, plaintextModulusBits, next))
                return false;
            RingNttContext nextRing = next.mRing;
            ringOut = std::move(nextRing);
            zpOut = std::move(next);
            return true;
        }
#endif
        RingNttContext nextRing{};
        ZpCrtContext nextZp{};
        if (!makeRingNttContext(ring, nextRing) ||
            !makeZpCrtContext(ring, plaintextModulusBits, nextZp))
            return false;
        ringOut = std::move(nextRing);
        zpOut = std::move(nextZp);
        return true;
    }

    namespace
    {
    bool makeGpuZpCrtContextUncached(
        const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out)
    {
        HostStep contextStep("setup: GPU CRT context build");
        if (!gpuZpTupleSupported(ring, plaintextModulusBits)) return false;

#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::NativeSealSetupBundle prepared{};
        if (gpu::buildNativeSealSetupBundleDevice(
                ring, plaintextModulusBits, prepared))
        {
            if (prepared.mOwnerRole != currentProtocolCacheScope().mRole ||
                prepared.mOwnerRunId != currentProtocolCacheScope().mRunId ||
                !prepared.mRing || !prepared.mPlainNtt)
                return false;
            RingNttContext ringCtx{};
            if (!makeNativeGpuRingNttContextFromCertificate(
                    ring, prepared.mOrderedPrimes, prepared.mRing, ringCtx))
                return false;
            ZpCrtContext next{};
            next.mRing = std::move(ringCtx);
            next.mPlaintextModulusBits = prepared.mSelectedPlaintextBits;
            next.mPlaintextModulus = prepared.mPlaintextPrime;
            next.mPlaintextLiftModQj = std::move(prepared.mPlaintextLift);
            next.mNativePlainNtt = std::move(prepared.mPlainNtt);
            next.mNativeSealBundleCommitted = true;
            next.mGpuLightweight = true;
            next.mHostContextCache = std::make_shared<ZpHostContextCache>();
            auto& cache = *next.mHostContextCache;
            cache.mRingParams = next.mRing.mParams;
            cache.mRingModuli = next.mRing.mRawModuli->mValues;
            cache.mRingOwner = next.mRing.mHostContextCache;
            cache.mPlaintextLiftModQj = next.mPlaintextLiftModQj;
            cache.mRequestedPlaintextBits = plaintextModulusBits;
            cache.mSelectedPlaintextBits = next.mPlaintextModulusBits;
            cache.mPlaintextModulus = next.mPlaintextModulus;
            cache.mRole = currentProtocolCacheScope().mRole;
            if (!validateZpContext(next) ||
                !gpu::GpuPlainNtt::publishRaw(
                    ring.mPolyModulusDegree, next.mPlaintextModulus,
                    next.mNativePlainNtt))
                return false;
            out = std::move(next);
            // The combined CRT result is committed now. Publish its immutable
            // native ring into the standalone raw/context lanes in that order:
            // a reader between publications can still use a valid static
            // context but will already find this same-role native GPU table.
            // Cache allocation failure only loses reuse, never the factory
            // result or the caller's output.
            if (gpu::GpuRing::publishRaw(ring,
                    out.mRing.mRawModuli->mValues,
                    out.mRing.mRawModuli->mDynamicGpuCertificate))
                (void)publishNativeGpuRingNttContext(out.mRing);
            return true;
        }
        if (!productionGpuZpTuple(ring, plaintextModulusBits))
        {
            // Explicit opt-out, unsupported owner scope, and a clean native
            // decline retain the previously accepted sequential GPU path.
            RingNttContext ringCtx{};
            if (!makeRingNttContext(ring, ringCtx) || !ringCtx.mGpuLightweight) return false;
            const auto deviceRing = gpu::GpuRing::get(ringCtx);
            if (!deviceRing || !ringCtx.mRawModuli ||
                (ringCtx.mRawModuli->mDynamicGpuCertificate &&
                    deviceRing != ringCtx.mRawModuli->mDynamicGpuCertificate)) return false;

            u64 plaintextPrime = 0;
            u32 selectedBits = 0;
            if (!gpu::selectSealPlainModulusDevice(ring.mPolyModulusDegree,
                    plaintextModulusBits, deviceRing->view().mMinModulus,
                    plaintextPrime, selectedBits) ||
                !gpu::GpuPlainNtt::getRaw(ring.mPolyModulusDegree, plaintextPrime))
                return false;

            ZpCrtContext next{};
            next.mRing = std::move(ringCtx);
            next.mPlaintextModulusBits = selectedBits;
            next.mPlaintextModulus = plaintextPrime;
            if (!gpu::preparePlaintextLiftDevice(*deviceRing, plaintextPrime,
                    next.mPlaintextLiftModQj)) return false;
            next.mGpuLightweight = true;
            next.mHostContextCache = std::make_shared<ZpHostContextCache>();
            auto& cache = *next.mHostContextCache;
            cache.mRingParams = next.mRing.mParams;
            cache.mRingModuli = next.mRing.mRawModuli->mValues;
            cache.mRingOwner = next.mRing.mHostContextCache;
            cache.mPlaintextLiftModQj = next.mPlaintextLiftModQj;
            cache.mRequestedPlaintextBits = plaintextModulusBits;
            cache.mSelectedPlaintextBits = selectedBits;
            cache.mPlaintextModulus = plaintextPrime;
            cache.mRole = currentProtocolCacheScope().mRole;
            out = std::move(next);
            return true;
        }
#else
        if (!productionGpuZpTuple(ring, plaintextModulusBits)) return false;
#endif

        // These are exact SEAL 4.1.1 production results, independently checked
        // against every coefficient/plaintext NTT table and the CRT derivation.
        // Runtime prime search, multiprecision division, SEALContext, and
        // BatchEncoder construction are replaced by device table generation.
        static constexpr std::array<u64, 4> goldenQ{
            36028797017276417ULL, 36028797017456641ULL,
            36028797017571329ULL, 36028797018652673ULL
        };
        static constexpr std::array<u64, 4> goldenLift{
            31167066492716324ULL, 21694619169948978ULL,
            65560066590007ULL, 11186266514113866ULL
        };
        static constexpr std::array<u64, 8> noGoldenQ{
            4503599623864321ULL, 4503599624716289ULL,
            4503599624847361ULL, 4503599625404417ULL,
            4503599625535489ULL, 4503599625830401ULL,
            4503599626321921ULL, 4503599626682369ULL
        };
        static constexpr std::array<u64, 8> noGoldenLift{
            4387753181945957ULL, 2958736519422233ULL,
            4311407244373363ULL, 2043635392656052ULL,
            3613420940470256ULL, 2606009313598ULL,
            2340510748877534ULL, 2511146381739566ULL
        };

        RingNttContext ringCtx{};
        if (!makeRingNttContext(ring, ringCtx) || !ringCtx.mGpuLightweight) return false;

        const bool golden = ring.mPolyModulusDegree == 8192u;
        const auto expectedQ = golden
            ? std::span<const u64>(goldenQ)
            : std::span<const u64>(noGoldenQ);
        if (ringModulusCount(ringCtx) != expectedQ.size()) return false;
        for (std::size_t i = 0; i < expectedQ.size(); ++i)
            if (ringModulusValue(ringCtx, i) != expectedQ[i]) return false;

        ZpCrtContext next{};
        next.mRing = std::move(ringCtx);
        next.mPlaintextModulusBits = golden ? 54u : 51u;
        next.mPlaintextModulus = golden ? 18014398508400641ULL : 2251799813554177ULL;
        const auto lift = golden
            ? std::span<const u64>(goldenLift)
            : std::span<const u64>(noGoldenLift);
        next.mPlaintextLiftModQj.resize(lift.size());
        std::copy(lift.begin(), lift.end(), next.mPlaintextLiftModQj.begin());
        next.mGpuLightweight = true;
        next.mHostContextCache = std::make_shared<ZpHostContextCache>();
        auto& cache = *next.mHostContextCache;
        cache.mRingParams = next.mRing.mParams;
        cache.mRingModuli.assign(expectedQ.begin(), expectedQ.end());
        cache.mRingOwner = next.mRing.mHostContextCache;
        cache.mPlaintextLiftModQj = next.mPlaintextLiftModQj;
        cache.mRequestedPlaintextBits = plaintextModulusBits;
        cache.mSelectedPlaintextBits = next.mPlaintextModulusBits;
        cache.mPlaintextModulus = next.mPlaintextModulus;
        cache.mRole = currentProtocolCacheScope().mRole;
        out = std::move(next);
        return true;
    }

    bool makeZpCrtContextUncached(
        const RingParams& ring, u32 plaintextModulusBits, bool expandModChain,
        bool singleBatchLimb, ZpCrtContext& out)
    {
        HostStep contextStep("setup: CRT context build");
        if (plaintextModulusBits == 0)
        {
            return false;
        }

        RingNttContext ringCtx{};
        if (!makeRingNttContext(ring, ringCtx))
        {
            return false;
        }
        if (ringCtx.mGpuLightweight)
        {
            ringCtx.mContext = getRingHostContext(ringCtx);
            if (!ringCtx.mContext) return false;
            ringCtx.mModuli = ringCtx.mContext->key_context_data()->parms().coeff_modulus();
            ringCtx.mGpuLightweight = false;
            ringCtx.mRawModuli.reset();
            ringCtx.mHostContextCache.reset();
        }

        const auto minModulusIt = std::min_element(
            ringCtx.mModuli.begin(),
            ringCtx.mModuli.end(),
            [](const seal::Modulus& lhs, const seal::Modulus& rhs) { return lhs.value() < rhs.value(); });
        if (minModulusIt == ringCtx.mModuli.end())
        {
            return false;
        }

        seal::Modulus batchingPlainModulus{};
        u32 selectedPlaintextBits = 0;
        HostStep primesStep("setup: plaintext modulus generation");
        for (u32 bits = plaintextModulusBits; bits >= 2; --bits)
        {
            try
            {
                auto candidate = seal::PlainModulus::Batching(ring.mPolyModulusDegree, bits);
                if (candidate.value() < minModulusIt->value())
                {
                    batchingPlainModulus = candidate;
                    selectedPlaintextBits = bits;
                    break;
                }
            }
            catch (const std::exception&)
            {
            }
        }

        if (selectedPlaintextBits == 0)
        {
            return false;
        }
        primesStep.stop();

        seal::EncryptionParameters batchingParams(seal::scheme_type::bgv);
        batchingParams.set_poly_modulus_degree(ring.mPolyModulusDegree);
        batchingParams.set_coeff_modulus(ringCtx.mModuli);
        batchingParams.set_plain_modulus(batchingPlainModulus);
        if (singleBatchLimb)
        {
            const auto compatible = std::find_if(ringCtx.mModuli.begin(), ringCtx.mModuli.end(),
                [&](const seal::Modulus& modulus) { return modulus.value() > batchingPlainModulus.value(); });
            if (compatible != ringCtx.mModuli.end())
            {
                // This BGV object supplies only BatchEncoder's plaintext NTT
                // tables and slot map; LogVole never encrypts with it. Its
                // helper parameter IDs may differ, while the complete protocol
                // ring, modulus product and plaintext lift remain in ringCtx.
                batchingParams.set_coeff_modulus(std::vector<seal::Modulus>{*compatible});
            }
        }

        HostStep sealStep("setup: batching SEAL context");
        // BatchEncoder and the GPU plaintext transform read only the first
        // data context. Keep that context unchanged and omit unused levels.
        auto batchingContext = std::make_shared<seal::SEALContext>(batchingParams, expandModChain, seal::sec_level_type::none);
        sealStep.stop();
        if (!batchingContext || !batchingContext->first_context_data())
        {
            return false;
        }

        auto ringContextData = ringCtx.mContext ? ringCtx.mContext->key_context_data() : nullptr;
        if (!ringContextData || !ringContextData->rns_tool() || !ringContextData->rns_tool()->base_q())
        {
            return false;
        }

        const std::size_t rho = ringCtx.mModuli.size();
        auto pool = seal::MemoryManager::GetPool();
        auto numerator = seal::util::allocate_uint(rho, pool);
        seal::util::set_uint(ringContextData->rns_tool()->base_q()->base_prod(), rho, numerator.get());
        auto denominator = seal::util::allocate_zero_uint(rho, pool);
        denominator[0] = batchingPlainModulus.value();
        auto plaintextLift = seal::util::allocate_zero_uint(rho, pool);
        seal::util::divide_uint_inplace(numerator.get(), denominator.get(), rho, plaintextLift.get(), pool);

        ZpCrtContext next{};
        next.mRing = std::move(ringCtx);
        next.mPlaintextModulusBits = selectedPlaintextBits;
        next.mPlaintextModulus = batchingPlainModulus.value();
        next.mBatchingContext = std::move(batchingContext);
        {
            HostStep encoderStep("setup: batch encoder tables");
            next.mBatchEncoder = std::make_shared<seal::BatchEncoder>(*next.mBatchingContext);
        }
        next.mPlaintextLiftModQj.resize(rho);
        for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
        {
            next.mPlaintextLiftModQj[modIdx] =
                seal::util::modulo_uint(plaintextLift.get(), rho, next.mRing.mModuli[modIdx]);
        }

        out = std::move(next);
        return true;
    }

    namespace
    {
        bool lightweightZpMetadataMatchesCache(const ZpCrtContext& ctx)
        {
            if (!ctx.mGpuLightweight || !ctx.mHostContextCache ||
                !ctx.mRing.mGpuLightweight ||
                !validateRingContextMetadata(ctx.mRing)) return false;
            const auto& cache = *ctx.mHostContextCache;
            const bool metadataMatches =
                !ctx.mBatchingContext && !ctx.mBatchEncoder &&
                ctx.mRing.mParams == cache.mRingParams &&
                ctx.mRing.mHostContextCache == cache.mRingOwner &&
                ctx.mPlaintextModulusBits == cache.mSelectedPlaintextBits &&
                ctx.mPlaintextModulus == cache.mPlaintextModulus &&
                ringModulusCount(ctx.mRing) == cache.mRingModuli.size() &&
                ctx.mPlaintextLiftModQj.size() == cache.mPlaintextLiftModQj.size() &&
                std::equal(ctx.mPlaintextLiftModQj.begin(), ctx.mPlaintextLiftModQj.end(),
                    cache.mPlaintextLiftModQj.begin());
            if (!metadataMatches) return false;
            for (std::size_t i = 0; i < cache.mRingModuli.size(); ++i)
                if (ringModulusValue(ctx.mRing, i) != cache.mRingModuli[i]) return false;
            return true;
        }
    }

    std::shared_ptr<const ZpCrtContext> getZpHostContext(const ZpCrtContext& ctx)
    {
        if (!ctx.mGpuLightweight)
            return std::make_shared<const ZpCrtContext>(ctx);
        if (!lightweightZpMetadataMatchesCache(ctx)) return nullptr;

        const auto& cache = *ctx.mHostContextCache;
        std::lock_guard<std::mutex> lock(ctx.mHostContextCache->mMutex);
        if (ctx.mHostContextCache->mContext) return ctx.mHostContextCache->mContext;

        HostStep fallbackStep("setup: CRT host fallback materialization");
        const auto runId = currentProtocolCacheScope().mRunId;
        ScopedProtocolCacheScope ownerScope(cache.mRole, runId);
        ZpCrtContext host{};
        if (!makeZpCrtContextUncached(
                cache.mRingParams,
                cache.mRequestedPlaintextBits,
                false, true, host) || host.mGpuLightweight ||
            host.mPlaintextModulusBits != cache.mSelectedPlaintextBits ||
            host.mPlaintextModulus != cache.mPlaintextModulus ||
            host.mPlaintextLiftModQj.size() != cache.mPlaintextLiftModQj.size() ||
            !std::equal(host.mPlaintextLiftModQj.begin(), host.mPlaintextLiftModQj.end(),
                cache.mPlaintextLiftModQj.begin()))
        {
            return nullptr;
        }
        ctx.mHostContextCache->mContext = std::make_shared<const ZpCrtContext>(std::move(host));
        return ctx.mHostContextCache->mContext;
    }
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    namespace
    {
        bool wrapLightweightZpLabelsOnGpu(
            const ZpCrtContext& ctx,
            std::span<const u64> labels,
            bool multiplyByDelta,
            u64 padValue,
            u64 expectedChunks,
            std::vector<RnsPoly>& out)
        {
            auto batch = gpu::wrapLabelsDevice(
                ctx, labels, multiplyByDelta, padValue, expectedChunks);
            if (!batch || batch->count() != expectedChunks)
                return false;
            std::vector<RnsPoly> completed;
            if (!gpu::download(*batch, completed, expectedChunks) ||
                completed.size() != expectedChunks)
                return false;
            out = std::move(completed);
            return true;
        }
    }
#endif

    bool wrapZpBatchCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32,
        RnsPoly& out)
    {
        if (ctx.mGpuLightweight)
        {
            if (!validateZpContext(ctx) ||
                !lightweightZpMetadataMatchesCache(ctx) ||
                labels.size() > zpSlotCount(ctx) ||
                !validateZpValues(ctx, labels) ||
                !validateZpValue(ctx, padValue))
                return false;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (gpu::enabled())
            {
                // The public API returns a host polynomial. Complete the
                // BatchEncoder inverse NTT and CRT lift on the device, then
                // download only that requested result.
                const std::array<u64, 1> emptyInput{padValue};
                const auto input = labels.empty()
                    ? std::span<const u64>(emptyInput) : labels;
                std::vector<RnsPoly> completed;
                if (!wrapLightweightZpLabelsOnGpu(
                        ctx, input, multiplyByDelta, padValue, 1u, completed))
                    return false;
                out = std::move(completed.front());
                return true;
            }
#endif
            const auto host = getZpHostContext(ctx);
            return host && wrapZpBatchCrt(
                *host, labels, multiplyByDelta, padValue, 1, out);
        }
        if (!validateZpContext(ctx) ||
            labels.size() > zpSlotCount(ctx) ||
            !validateZpValues(ctx, labels) ||
            !validateZpValue(ctx, padValue))
        {
            return false;
        }

        std::vector<u64> slots(zpSlotCount(ctx), padValue);
        std::copy(labels.begin(), labels.end(), slots.begin());

        seal::BatchEncoder& encoder = *ctx.mBatchEncoder;
        return encodeSlotsToRingCrt(ctx, slots, encoder, multiplyByDelta, out);
    }

    bool wrapZpConstantCrt(
        const ZpCrtContext& ctx,
        u64 value,
        bool multiplyByDelta,
        u32 requestedWorkers,
        RnsPoly& out)
    {
        if (ctx.mGpuLightweight)
        {
            if (!validateZpContext(ctx) ||
                !lightweightZpMetadataMatchesCache(ctx) ||
                !validateZpValue(ctx, value))
                return false;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (gpu::enabled())
            {
                // One scalar plus the device-side pad broadcast represents
                // the same all-slot constant as the host BatchEncoder path.
                const std::array<u64, 1> input{value};
                std::vector<RnsPoly> completed;
                if (!wrapLightweightZpLabelsOnGpu(
                        ctx, input, multiplyByDelta, value, 1u, completed))
                    return false;
                out = std::move(completed.front());
                return true;
            }
#endif
            const auto host = getZpHostContext(ctx);
            return host && wrapZpConstantCrt(
                *host, value, multiplyByDelta, requestedWorkers, out);
        }
        if (!validateZpContext(ctx) || !validateZpValue(ctx, value))
        {
            return false;
        }

        std::vector<u64> slots(zpSlotCount(ctx), value);
        seal::BatchEncoder& encoder = *ctx.mBatchEncoder;
        (void)requestedWorkers;
        return encodeSlotsToRingCrt(ctx, slots, encoder, multiplyByDelta, out);
    }

    bool wrapZpLabelsCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32 requestedWorkers,
        std::vector<RnsPoly>& out)
    {
        if (ctx.mGpuLightweight)
        {
            if (!validateZpContext(ctx) ||
                !lightweightZpMetadataMatchesCache(ctx) ||
                !validateZpValues(ctx, labels) ||
                !validateZpValue(ctx, padValue))
                return false;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (gpu::enabled())
            {
                AutoTimer wrapTimer(globalTimingStats.mWrapTimeUs);
                const u64 expectedChunks = zpRingLabelCount(ctx, labels.size());
                if (!expectedChunks)
                {
                    out.clear();
                    return true;
                }
                return wrapLightweightZpLabelsOnGpu(
                    ctx, labels, multiplyByDelta, padValue, expectedChunks, out);
            }
#endif
            const auto host = getZpHostContext(ctx);
            return host && wrapZpLabelsCrt(
                *host, labels, multiplyByDelta, padValue, requestedWorkers, out);
        }
        if (!validateZpContext(ctx) ||
            !validateZpValues(ctx, labels) ||
            !validateZpValue(ctx, padValue))
        {
            return false;
        }

        AutoTimer wrapTimer(globalTimingStats.mWrapTimeUs);
        const u64 slotCount = zpSlotCount(ctx);
        const u64 chunkCount = zpRingLabelCount(ctx, labels.size());
        out.resize(chunkCount);
        return detail::runParallelTasks(
            static_cast<std::size_t>(chunkCount),
            requestedWorkers,
            [&](std::size_t taskIdx) {
                const u64 chunkIdx = static_cast<u64>(taskIdx);
                const u64 offset = chunkIdx * slotCount;
                const u64 chunkSize = std::min<u64>(slotCount, labels.size() - offset);
                return wrapZpBatchCrt(
                    ctx,
                    labels.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(chunkSize)),
                    multiplyByDelta,
                    padValue,
                    requestedWorkers,
                    out[chunkIdx]);
            });
    }

    bool unwrapRingLabelsCrt(
        const ZpCrtContext& ctx,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        bool scaleAndRound,
        u32 requestedWorkers,
        AlignedUnVec<u64>& out)
    {
        if (!validateZpContext(ctx) || !validateRingBatchShape(labels, ctx.mRing.mParams))
        {
            return false;
        }

        const u64 slotCount = zpSlotCount(ctx);
        if (zpLabelCount > labels.size() * slotCount)
        {
            return false;
        }

        if (ctx.mGpuLightweight && !lightweightZpMetadataMatchesCache(ctx))
            return false;

        const u64 chunkCount = zpRingLabelCount(ctx, zpLabelCount);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (ctx.mGpuLightweight && !scaleAndRound && gpu::enabled())
        {
            // Public callers still request host scalars. Compose Q, reduce
            // modulo p and BatchEncoder-decode on the role's GPU; publish the
            // host output only after the complete device path succeeds.
            if (!zpLabelCount)
            {
                out.resize(0);
                return true;
            }
            AlignedUnVec<u64> completed;
            completed.resize(static_cast<std::size_t>(zpLabelCount));
            if (!gpu::unwrapLabelsBatchUnscaled(
                    ctx, labels, chunkCount, zpLabelCount, completed.data()))
                return false;
            out = std::move(completed);
            return true;
        }
        // Try the complete device pipeline before asking a lightweight context
        // to construct any host SEAL state. A decline remains replayable.
        if (scaleAndRound && gpu::enabled() && chunkCount == labels.size())
        {
            out.resize(static_cast<std::size_t>(zpLabelCount));
            if (gpu::unwrapLabelsBatch(ctx, labels, zpLabelCount, out.data()))
                return true;
            out.resize(0);
        }
#endif
        if (ctx.mGpuLightweight)
        {
            const auto host = getZpHostContext(ctx);
            return host && unwrapRingLabelsCrt(
                *host, labels, zpLabelCount, scaleAndRound, requestedWorkers, out);
        }

        auto batchingContextData = ctx.mBatchingContext->first_context_data();
        auto ringContextData = ctx.mRing.mContext ? ctx.mRing.mContext->key_context_data() : nullptr;
        if (!batchingContextData ||
            !batchingContextData->rns_tool() ||
            !ringContextData ||
            !ringContextData->rns_tool() ||
            !ringContextData->rns_tool()->base_q())
        {
            return false;
        }

        auto pool = seal::MemoryManager::GetPool();
        const auto& plainModulus = batchingContextData->parms().plain_modulus();
        const u64 plainModulusValue = plainModulus.value();
        const std::size_t n = ctx.mRing.mParams.mPolyModulusDegree;
        const std::size_t rho = ctx.mRing.mModuli.size();
        seal::util::RNSBase fullBase(ringContextData->parms().coeff_modulus(), pool);
        auto invPunctProd = fullBase.inv_punctured_prod_mod_base_array();
        std::vector<seal::util::MultiplyUIntModOperand> crtInvPunctured(rho);
        AlignedUnVec<u64> qI;
        AlignedUnVec<wideU64> fracInvModulus;
        resizeZero(qI, rho);
        resizeZero(fracInvModulus, rho);
        for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
        {
            qI[modIdx] = fullBase.base()[modIdx].value();
            crtInvPunctured[modIdx] = invPunctProd[modIdx];
            fracInvModulus[modIdx] = reciprocal2Pow128Wide(qI[modIdx]);
        }
        const wideU64 half = wideU64OneShift(127);

        AutoTimer unwrapTimer(globalTimingStats.mUnwrapTimeUs);

        out.resize(static_cast<std::size_t>(zpLabelCount));
        if (!detail::runParallelTasks(
                static_cast<std::size_t>(chunkCount),
                requestedWorkers,
                [&](std::size_t labelIdx) {
                    seal::Plaintext plain;
                    plain.resize(slotCount);

                    const bool vectorRounded = scaleAndRound && detail::cpuScaleAndRoundRns(
                        labels[labelIdx].mCoeffs.data(), plain.data(), n, fullBase, plainModulusValue);
                    RnsPoly canonical;
                    if (!vectorRounded)
                    {
                        canonical = labels[labelIdx];
                        if (!canonicalizePoly(canonical, ctx.mRing)) return false;
                    }

                    if (scaleAndRound && !vectorRounded)
                    {
                        for (std::size_t coeffIdx = 0; coeffIdx < slotCount; ++coeffIdx)
                        {
                            u64 scaledCoeff = 0;
                            wideU64 fracSum = half;
                            for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                            {
                                const u64 vI = canonical.mCoeffs[modIdx * n + coeffIdx];
                                const u64 xI = seal::util::multiply_uint_mod(
                                    vI,
                                    crtInvPunctured[modIdx],
                                    ctx.mRing.mModuli[modIdx]);

                                // floor(xI * p / q_i) and the matching remainder.
                                // divModWide128 is exact and replaces a software
                                // 128/64 division, which dominated this loop.
                                const wideU64 scaledNumerator = wideU64Mul(xI, plainModulusValue);
                                wideU64 quotient{};
                                u64 rem = 0;
                                divModWide128(
                                    scaledNumerator, qI[modIdx], fracInvModulus[modIdx], quotient, rem);

                                scaledCoeff += quotient.mLo;
                                if (scaledCoeff >= plainModulusValue)
                                {
                                    scaledCoeff -= plainModulusValue;
                                }

                                unsigned char carry = 0;
                                fracSum = wideU64Add(
                                    fracSum,
                                    wideU64MulLow(rem, fracInvModulus[modIdx]),
                                    &carry);
                                if (carry)
                                {
                                    ++scaledCoeff;
                                    if (scaledCoeff == plainModulusValue)
                                    {
                                        scaledCoeff = 0;
                                    }
                                }
                            }
                            plain[coeffIdx] = scaledCoeff;
                        }
                    }
                    else if (!scaleAndRound)
                    {
                        auto localPool = seal::MemoryManager::GetPool();
                        auto composedLocal = seal::util::allocate_poly(n, rho, localPool);
                        std::copy(canonical.mCoeffs.begin(), canonical.mCoeffs.end(), composedLocal.get());
                        ringContextData->rns_tool()->base_q()->compose_array(composedLocal.get(), n, localPool);

                        for (std::size_t coeffIdx = 0; coeffIdx < slotCount; ++coeffIdx)
                        {
                            plain[coeffIdx] =
                                seal::util::modulo_uint(composedLocal.get() + coeffIdx * rho, rho, plainModulus);
                        }
                    }

                    std::vector<u64> slots;
                    try
                    {
                        seal::BatchEncoder& encoder = *ctx.mBatchEncoder;
                        encoder.decode(plain, slots);
                    }
                    catch (const std::exception&)
                    {
                        return false;
                    }

                    const u64 offset = static_cast<u64>(labelIdx) * slotCount;
                    const u64 remaining = zpLabelCount - offset;
                    const u64 copyCount = std::min<u64>(remaining, slots.size());
                    std::copy_n(slots.begin(), copyCount, out.data() + offset);
                    return true;
                }))
        {
            return false;
        }

        return true;
    }

    task<> civoleSenderOffline(
        const CivoleSenderOfflineInput& input,
        CivoleSenderState& state,
        PRNG& prng,
        Socket& sock)
    {
        // The delta producer precedes LogVoleRingSender::offline. Give both
        // stages the same fresh sender run rather than publishing a run-zero
        // device owner that a later party could accidentally reuse.
        const u64 incomingRun = currentProtocolCacheScope().mRunId;
        const u64 offlineRunId = incomingRun
            ? incomingRun : allocateProtocolCacheRunId();
        std::optional<ScopedProtocolCacheScope> senderScope(std::in_place,
            ProtocolCacheRole::Sender, offlineRunId);
        CivoleParams sessionParams = input.mParams;

        ZpCrtContext ctx{};
        if (!makeZpCrtContext(
                sessionParams.mLogVole.mShrinkExpand.mRing,
                sessionParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx) ||
            (input.mGarbledDeltaPattern
                ? (input.mDelta != 0 || !input.mDeltaSlots.empty() || zpSlotCount(ctx) < 3 ||
                   std::any_of(input.mGarbledDeltaPattern->begin(), input.mGarbledDeltaPattern->end(),
                       [&](u64 value) { return value == 0 || value >= ctx.mPlaintextModulus; }))
                : input.mDeltaSlots.empty()
                ? (input.mDelta == 0 || input.mDelta >= ctx.mPlaintextModulus)
                : (input.mDelta != 0 || input.mDeltaSlots.size() != zpSlotCount(ctx) ||
                   !validateZpValues(ctx, input.mDeltaSlots) ||
                   std::all_of(input.mDeltaSlots.begin(), input.mDeltaSlots.end(),
                       [](u64 v) { return v == 0; }))))
        {
            throw std::runtime_error("LogVole CI-VOLE sender offline input is invalid");
        }

        u32 ringWidth = 0;
        if (!computeInternalRingWidth(sessionParams.mLogVole, ctx, input.mW, ringWidth))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not compute ring width");
        }

        Params params = sessionParams.mLogVole;
        params.mW = ringWidth;
        params.mTotalLabelCount = input.mW;

        // The correctness budget depends on the request size through the reuse
        // count, so it can only be checked once the label count is known. Failing
        // here is much better than producing keys that are wrong for a fraction
        // of coefficients.
        if (!validateCt2SeedMode(params))
        {
            throw std::runtime_error(
                "LogVole CI-VOLE parameters do not meet the correctness budget of the selected setting");
        }

        const auto workers = sessionParams.mLogVole.mShrinkExpand.mNumWorkerThreads;
        const auto slotsForFallback =
            std::vector<u64>(input.mDeltaSlots.begin(), input.mDeltaSlots.end());
        const auto patternForFallback = input.mGarbledDeltaPattern;
        auto wrapHost = [ctx, delta = input.mDelta, slotsForFallback,
            patternForFallback, workers](RnsPoly& out) -> bool {
            if (patternForFallback)
            {
                std::vector<u64> slots(zpSlotCount(ctx), 0);
                for (std::size_t i = 0; i < (slots.size() / 3) * 3; ++i)
                    slots[i] = (*patternForFallback)[i % 3];
                return wrapZpBatchCrt(ctx, slots, true, 0, workers, out);
            }
            return slotsForFallback.empty()
                ? wrapZpConstantCrt(ctx, delta, true, workers, out)
                : wrapZpBatchCrt(ctx, slotsForFallback, true, 0, workers, out);
        };

        RnsPoly wrappedDelta{};
        bool wrapped = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::DeviceBatchPtr residentDelta{};
#endif
        {
            HostStep deltaStep("setup: delta preparation");
            bool strictDevice = false;
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* deviceDelta = std::getenv("LV_GPU_SETUP_DELTA_DEVICE");
            if (gpu::enabled() && (!deviceDelta || deviceDelta[0] != '0'))
            {
                const char* strict = std::getenv("LV_GPU_SETUP_DELTA_DEVICE_STRICT");
                strictDevice = strict && strict[0] != '0';
                const char* chain = std::getenv("LV_GPU_SETUP_DELTA_CHAIN_DEVICE");
                const char* chainStrict = std::getenv("LV_GPU_SETUP_DELTA_CHAIN_STRICT");
                if ((!chain || chain[0] != '0') && params.mGamma == 1u &&
                    ctx.mGpuLightweight)
                {
                    residentDelta = gpu::wrapSetupDeltaResident(ctx, input.mDelta,
                        input.mDeltaSlots,
                        input.mGarbledDeltaPattern ? &*input.mGarbledDeltaPattern : nullptr);
                    if (residentDelta)
                        wrapped = true;
                    else if (chainStrict && chainStrict[0] == '1')
                        throw std::runtime_error(
                            "LogVole CI-VOLE sender resident delta capture declined");
                }
                if (!wrapped)
                    wrapped = gpu::wrapSetupDeltaDevice(ctx, input.mDelta,
                        input.mDeltaSlots,
                        input.mGarbledDeltaPattern ? &*input.mGarbledDeltaPattern : nullptr,
                        wrappedDelta);
            }
#endif
            if (!wrapped && !strictDevice)
            {
                HostStep cpuStep("setup: delta CPU preparation");
                wrapped = wrapHost(wrappedDelta);
            }
        }
        if (!wrapped)
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not wrap delta");
        }
        // Context/bootstrap and the delta producer are synchronous. Release
        // this thread-local scope before metadata transport can suspend; the
        // RingSender reinstates the same run for each synchronous consumer.
        senderScope.reset();

        auto metaSock = sock.fork();
        CivoleOfflineMeta meta{};
        meta.mLabelCount = input.mW;
        meta.mMode = sessionParams.mLogVole.mOnlineMode;
        co_await sendCivoleOfflineMeta(metaSock, meta);

        SenderOfflineInput offlineInput{};
        offlineInput.mParams = params;
        offlineInput.mSenderOwnerRunId = offlineRunId;
#if defined(ENABLE_LOGVOLE_CUDA)
        offlineInput.mUseGpuResidentInternalState = gpu::enabled();
        offlineInput.mWrappedDeltaDevice = std::move(residentDelta);
        if (offlineInput.mWrappedDeltaDevice)
            offlineInput.mWrappedDeltaHostFallback = std::move(wrapHost);
        else
            offlineInput.mSk1.resize(params.mGamma, std::move(wrappedDelta));
#else
        offlineInput.mSk1.resize(params.mGamma, std::move(wrappedDelta));
#endif

        LogVoleRingSender sender{};
        SenderState logVoleState{};
        auto logVoleSock = sock.fork();
        co_await sender.offline(offlineInput, logVoleState, prng, logVoleSock);

        CivoleSenderState next{};
        next.mParams = sessionParams;
        next.mModulus = ctx.mPlaintextModulus;
        next.mDelta = input.mDelta;
        next.mW = input.mW;
        next.mRingWidth = params.mW;
        next.mLogVoleState = std::move(logVoleState);
        state = std::move(next);
    }

    task<> civoleReceiverOffline(
        const CivoleReceiverOfflineInput& input,
        CivoleReceiverState& state,
        Socket& sock)
    {
        if (input.mW == 0)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver requires a nonzero output length");
        }

        auto metaSock = sock.fork();
        const CivoleOfflineMeta meta = co_await recvCivoleOfflineMeta(metaSock);
        if (meta.mLabelCount != input.mW)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver peer output length does not match expected length");
        }
        CivoleParams sessionParams = input.mParams;
        if (meta.mMode != sessionParams.mLogVole.mOnlineMode)
            throw std::runtime_error("LogVole CI-VOLE offline modes do not match");

        ZpCrtContext ctx{};
        if (!makeZpCrtContext(
                sessionParams.mLogVole.mShrinkExpand.mRing,
                sessionParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not build CRT context");
        }

        u32 ringWidth = 0;
        if (!computeInternalRingWidth(sessionParams.mLogVole, ctx, meta.mLabelCount, ringWidth))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not compute ring width");
        }

        Params params = sessionParams.mLogVole;
        params.mW = ringWidth;
        params.mTotalLabelCount = meta.mLabelCount;

        if (!validateCt2SeedMode(params))
        {
            throw std::runtime_error(
                "LogVole CI-VOLE parameters do not meet the correctness budget of the selected setting");
        }

        ReceiverOfflineInput offlineInput{};
        offlineInput.mParams = params;
#if defined(ENABLE_LOGVOLE_CUDA)
        offlineInput.mUseGpuResidentInternalState = gpu::enabled();
#endif

        LogVoleRingReceiver receiver{};
        ReceiverState logVoleState{};
        std::shared_ptr<void> firstQueryGpuAllocations;
        auto logVoleSock = sock.fork();
        co_await receiver.offline(
            offlineInput, logVoleState, logVoleSock, &firstQueryGpuAllocations);

        CivoleReceiverState next{};
        next.mParams = sessionParams;
        next.mModulus = ctx.mPlaintextModulus;
        next.mW = meta.mLabelCount;
        next.mRingWidth = params.mW;
        next.mLogVoleState = std::move(logVoleState);
        next.mFirstQueryGpuAllocations = std::move(firstQueryGpuAllocations);
        state = std::move(next);
    }

    bool civoleSenderReleaseK(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleReleaseKOutput& output)
    {
        // NI fixes k only after d' arrives; it cannot offer staged key release.
        if (state.mParams.mLogVole.mOnlineMode == OnlineMode::NonInteractive) return false;
        ScopedProtocolCacheScope scopedCache(ProtocolCacheRole::Sender, sid);

        if (!prepareSenderSidForReleaseK(state, sid) ||
            !ensureSenderPrecompute(state.mLogVoleState) ||
            !state.mLogVoleState.mPrecomputedTbk)
        {
            return false;
        }

        ZpCrtContext ctx{};
        AlignedUnVec<u64> keys;
        if (!makeZpCrtContext(
                state.mParams.mLogVole.mShrinkExpand.mRing,
                state.mParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx))
        {
            return false;
        }

        bool haveKeys = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        // Same as the receiver: unwrap the keys where they were produced.
        if (state.mLogVoleState.mPrecomputedTbk->empty() && state.mLogVoleState.mPrecomputedTbkDevice)
        {
            auto dev =
                std::static_pointer_cast<gpu::DeviceBatch>(state.mLogVoleState.mPrecomputedTbkDevice);
            keys.resize(static_cast<std::size_t>(state.mW));
            haveKeys = gpu::unwrapLabelsDevice(
                ctx, *dev, state.mLogVoleState.mPrecomputedTbkCount, state.mW, keys.data());
            if (!haveKeys) keys.resize(0);
        }
#endif
        if (!haveKeys &&
            !unwrapRingLabelsCrt(
                ctx,
                *state.mLogVoleState.mPrecomputedTbk,
                state.mW,
                true,
                state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                keys))
        {
            return false;
        }

        state.mKeyReleased = true;
        const auto usedSidCount = state.mUsedSids.size();
        state.mUsedSids.resize(usedSidCount + 1);
        state.mUsedSids[usedSidCount] = sid;
        state.mReleasedKeys = std::move(keys);

        CivoleReleaseKOutput next{};
        next.mSid = sid;
        next.mModulus = state.mModulus;
        next.mKeys = state.mReleasedKeys;
        output = std::move(next);
        return true;
    }

    task<> civoleSenderRelease(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleSenderReleaseOutput& output,
        PRNG& prng,
        Socket& sock,
        CivoleSenderReleaseOptions options)
    {
        if (!prepareSenderSidForReleaseK(state, sid) ||
            state.mReleaseIntUsed)
        {
            throw std::runtime_error("LogVole CI-VOLE release input is invalid");
        }
        state.mReleaseIntUsed = true;

        ScopedProtocolCacheScope scopedCache(ProtocolCacheRole::Sender, sid);

        LogVoleRingSender sender{};
        SenderOnlineOutput online{};
        SenderOnlineOptions onlineOptions{};
        onlineOptions.mSid = sid;
        // Unwrap directly from the retained online cache. Copying these ring
        // labels into a temporary output used gigabytes of extra memory traffic.
        onlineOptions.mSkipTbkOutput = true;
        onlineOptions.mUsePrecomputed = senderHasPrecompute(state.mLogVoleState);
        {
            HostStep step("send: logvole online");
            co_await sender.online(state.mLogVoleState, onlineOptions, online, prng, sock);
        }

        ZpCrtContext ctx{};
        AlignedUnVec<u64> keys;
        if (!makeZpCrtContext(
                state.mParams.mLogVole.mShrinkExpand.mRing,
                state.mParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not unwrap keys");
        }

        state.mKeyReleased = true;
        const auto usedSidCount = state.mUsedSids.size();
        state.mUsedSids.resize(usedSidCount + 1);
        state.mUsedSids[usedSidCount] = sid;

        CivoleSenderReleaseOutput next{};
        next.mSid = sid;
        next.mComm = online.mComm;

        const bool writeToCaller = options.mKeysOut.size() == static_cast<std::size_t>(state.mW);
        HostStep unwrapStep("cpu sender: unwrap keys and copy");
        bool haveKeys = false;
        const auto& ringKeys = *state.mLogVoleState.mPrecomputedTbk;
#if defined(ENABLE_LOGVOLE_CUDA)
        const auto& ringKeysDevice = state.mLogVoleState.mPrecomputedTbkDevice;
        const auto ringKeyCount = state.mLogVoleState.mPrecomputedTbkCount;
        if (ringKeys.empty() && ringKeysDevice)
        {
            auto dev = std::static_pointer_cast<gpu::DeviceBatch>(ringKeysDevice);
            if (options.mKeepKeysOnDevice)
            {
                HostStep step("send: unwrap keys -> device");
                // Nothing crosses PCIe for the sender either: the keys are
                // unwrapped in place and left for a device-side consumer.
                if (auto scalars = gpu::unwrapLabelsToDevice(ctx, *dev, ringKeyCount, state.mW))
                {
                    next.mKeysDevice = scalars;
                    next.mKeysDeviceCount = state.mW;
                    state.mReleasedKeys.resize(0);
                    output = std::move(next);
                    co_return;
                }
            }
            // Otherwise land straight in the caller's buffer when it gave us one.
            u64* dst = writeToCaller ? options.mKeysOut.data() : nullptr;
            if (!dst)
            {
                keys.resize(static_cast<std::size_t>(state.mW));
                dst = keys.data();
            }
            haveKeys = gpu::unwrapLabelsDevice(ctx, *dev, ringKeyCount, state.mW, dst);
            if (!haveKeys) keys.resize(0);
        }
#endif
        if (!haveKeys &&
            !unwrapRingLabelsCrt(
                ctx,
                ringKeys,
                state.mW,
                true,
                state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                keys))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not unwrap keys");
        }

        if (haveKeys && writeToCaller)
        {
            state.mReleasedKeys.resize(0);   // already written into the caller's span
        }
        else if (writeToCaller)
        {
            std::copy(keys.begin(), keys.end(), options.mKeysOut.begin());
            state.mReleasedKeys.resize(0);
        }
        else
        {
            state.mReleasedKeys = std::move(keys);
        }
        output = std::move(next);
    }

    task<> civoleReceiverSetX(
        CivoleReceiverState& state,
        CivoleSid sid,
        std::span<const u64> x,
        CivoleReceiverSetXOutput& output,
        PRNG& prng,
        Socket& sock,
        CivoleReceiverSetXOptions options)
    {
        // With a device-resident x the caller passes the size in `x` (or in
        // mXDeviceCount) and the values never touch host memory, so the host-side
        // range check cannot run here.
        const bool xOnDevice = options.mXDevice != nullptr;
        const u64 xCount = xOnDevice ? options.mXDeviceCount : static_cast<u64>(x.size());
        const u64 slots = state.mParams.mLogVole.mShrinkExpand.mRing.mPolyModulusDegree;
        const u64 perRing = slots / 3;
        const bool garbledSizeValid = perRing && xCount && state.mW % slots == 0 &&
            (xCount / perRing + (xCount % perRing != 0)) == state.mW / slots;
        if (options.mGarbledInput ? !garbledSizeValid : xCount != state.mW)
        {
            throw std::runtime_error("LogVole CI-VOLE setx size does not match offline width");
        }

        ZpCrtContext ctx{};
        {
            HostStep step("recv: crt ctx + validate + sid");
            if (!makeZpCrtContext(
                    state.mParams.mLogVole.mShrinkExpand.mRing,
                    state.mParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                    ctx) ||
                (!xOnDevice && !validateZpValues(ctx, x)) ||
                !prepareReceiverSidForSetX(state, sid))
            {
                throw std::runtime_error("LogVole CI-VOLE receiver setx input is invalid");
            }
        }

        const auto paddedSize = static_cast<std::size_t>(state.mLogVoleState.mParams.mW);

        ScopedProtocolCacheScope scopedCache(ProtocolCacheRole::Receiver, sid);

#if defined(ENABLE_LOGVOLE_CUDA)
        auto firstQueryGpuAllocations =
            std::static_pointer_cast<gpu::ReceiverFirstQueryAllocations>(
                state.mFirstQueryGpuAllocations);
        const bool firstQueryAllocationBound = firstQueryGpuAllocations &&
            gpu::bindReceiverFirstQueryAllocations(firstQueryGpuAllocations, &state, sid);
#endif

        ReceiverOnlineInput onlineInput{};
        onlineInput.mSid = sid;

#if defined(ENABLE_LOGVOLE_CUDA)
        // Wrap straight into device memory: only the scalars are uploaded and the
        // 256 KiB-per-chunk host representation is never built.
        if (gpu::enabled())
        {
            HostStep step("recv: wrap x -> device");
            gpu::DeviceBatchPtr dev{};
            if (xOnDevice)
            {
                // Nothing of input size crosses PCIe: the scalars are wrapped in
                // place, exactly as the MACs are unwrapped in place on the way out.
                auto scalars = std::static_pointer_cast<gpu::DeviceScalars>(options.mXDevice);
                if (scalars->count() < xCount || (options.mGarbledInput && scalars->count() != xCount))
                    throw std::runtime_error("LogVole device input size does not match its handle");
                dev = gpu::wrapDeviceLabels(ctx, *scalars, xCount, false, 0, paddedSize,
                    options.mGarbledInput,
                    firstQueryAllocationBound ? firstQueryGpuAllocations.get() : nullptr,
                    firstQueryAllocationBound ? &state : nullptr,
                    firstQueryAllocationBound ? sid : 0);
            }
            else
            {
                dev = gpu::wrapLabelsDevice(ctx, x, false, 0, paddedSize, options.mGarbledInput);
            }
            if (dev)
            {
                onlineInput.mXDevice = dev;
                onlineInput.mXCount = paddedSize;
            }
        }
        else if (xOnDevice)
        {
            throw std::runtime_error(
                "LogVole CI-VOLE receiver was given a device-resident x without the GPU backend");
        }
#endif
        if (!onlineInput.mXDevice)
        {
            HostStep wrapStep("cpu receiver: wrap inputs");
            if (xOnDevice)
            {
                throw std::runtime_error(
                    "LogVole CI-VOLE receiver could not wrap its device-resident input");
            }
            std::vector<RnsPoly> wrapped;
            AlignedUnVec<u64> repeated;
            std::span<const u64> packedX = x;
            if (options.mGarbledInput)
            {
                repeated.resize(state.mW);
                std::fill(repeated.begin(), repeated.end(), u64{0});
                for (u64 i = 0; i < xCount; ++i)
                {
                    const u64 base = (i / perRing) * slots + (i % perRing) * 3;
                    repeated[base] = repeated[base + 1] = repeated[base + 2] = x[i];
                }
                packedX = {repeated.data(), repeated.size()};
            }
            if (!wrapZpLabelsCrt(
                    ctx,
                    packedX,
                    false,
                    0,
                    state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                    wrapped))
            {
                throw std::runtime_error("LogVole CI-VOLE receiver could not wrap inputs");
            }

            const auto inputSize = wrapped.size();
            if (inputSize < paddedSize)
            {
                wrapped.resize(paddedSize);
                for (std::size_t idx = inputSize; idx < paddedSize; ++idx)
                {
                    wrapped[idx] = makeZeroPoly(state.mLogVoleState.mParams.mShrinkExpand.mRing);
                }
            }
            onlineInput.mX = std::move(wrapped);
        }

        LogVoleRingReceiver receiver{};
        ReceiverOnlineOutput online{};
        {
            HostStep step("recv: logvole online");
            co_await receiver.online(
                state.mLogVoleState, onlineInput, online, prng, sock,
                state.mFirstQueryGpuAllocations, &state);
        }

        CivoleReceiverSetXOutput next{};
        next.mSid = sid;
        next.mModulus = state.mModulus;
        next.mComm = online.mComm;

        const bool writeToCaller =
            options.mMacsOut.size() == static_cast<std::size_t>(state.mW);
        HostStep unwrapStep("cpu receiver: unwrap macs and copy");

        AlignedUnVec<u64> macs;
        bool haveMacs = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        // The MACs never touch host memory as polynomials: they are unwrapped in
        // place on the device. Every recursion level below kept its
        // intermediates on the device too.
        if (online.mTbm.empty() && online.mTbmDevice)
        {
            auto dev = std::static_pointer_cast<gpu::DeviceBatch>(online.mTbmDevice);
            if (options.mKeepMacsOnDevice)
            {
                HostStep step("recv: unwrap macs -> device");
                // Nothing crosses PCIe: the caller consumes the result on the GPU.
                if (auto scalars = gpu::unwrapLabelsToDevice(
                        ctx, *dev, static_cast<u64>(online.mTbmCount), state.mW))
                {
                    next.mMacsDevice = scalars;
                    next.mMacsDeviceCount = state.mW;
                    output = std::move(next);
                    co_return;
                }
            }
            // Download straight into the caller's buffer when it gave us one,
            // which avoids allocating and then copying a full-length array.
            u64* dst = writeToCaller ? options.mMacsOut.data() : nullptr;
            if (!dst)
            {
                macs.resize(static_cast<std::size_t>(state.mW));
                dst = macs.data();
            }
            haveMacs = gpu::unwrapLabelsDevice(
                ctx, *dev, static_cast<u64>(online.mTbmCount), state.mW, dst);
            if (!haveMacs)
            {
                macs.resize(0);
                if (!gpu::download(*dev, online.mTbm, static_cast<std::size_t>(online.mTbmCount)))
                {
                    throw std::runtime_error("LogVole CI-VOLE receiver could not fetch MACs");
                }
            }
        }
#endif
        if (!haveMacs && !unwrapRingLabelsCrt(
                ctx,
                online.mTbm,
                state.mW,
                true,
                state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                macs))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not unwrap MACs");
        }

        if (haveMacs && writeToCaller)
        {
            // Already written in place.
        }
        else if (writeToCaller)
        {
            std::copy(macs.begin(), macs.end(), options.mMacsOut.begin());
        }
        else
        {
            next.mMacs = std::move(macs);
        }
        output = std::move(next);
    }
}
