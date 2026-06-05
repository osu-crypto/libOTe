#include "libOTe/Vole/LogVole/LogVole.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include "cryptoTools/Crypto/PRNG.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string>

namespace osuCrypto::LogVole
{
    namespace
    {
        struct CivoleOfflineMeta
        {
            u64 mLabelCount = 0;
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
            return ctx.mPlaintextModulus != 0 &&
                   !ctx.mRing.mModuli.empty() &&
                   ctx.mPlaintextLiftModQj.size() == ctx.mRing.mModuli.size() &&
                   ctx.mBatchingContext &&
                   ctx.mBatchingContext->first_context_data();
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
            resizeZero(out.mCoeffs, n * rho);

            const u64* plainCoeffs = plain.data();
            const std::size_t plainCoeffCount = std::min<std::size_t>(n, plain.coeff_count());

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
            state.mRootDPrimeRt.reset();
            state.mPrecomputedTbk.reset();
            if (state.mNextLevelState)
            {
                clearSenderCachedOutputs(*state.mNextLevelState);
            }
        }

        void clearReceiverCachedOutputs(ReceiverState& state)
        {
            state.mGoldenSeed.clear();
            state.mRootDPrimeRt.reset();
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
            std::array<u8, 8> payload{};
            writeU64(std::span<u8>(payload).subspan(0, 8), meta.mLabelCount);
            co_await sock.send(coproto::copy(payload));
        }

        task<CivoleOfflineMeta> recvCivoleOfflineMeta(Socket& sock)
        {
            std::array<u8, 8> payload{};
            co_await sock.recv(payload);

            CivoleOfflineMeta meta{};
            meta.mLabelCount = readU64(std::span<const u8>(payload).subspan(0, 8));
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

    bool resolveCivoleModulus(const CivoleParams& params, u64& out)
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
        return true;
    }

}

namespace osuCrypto
{
    using namespace LogVole;

    void LogVoleSender::configure(u64 n, u32 plaintextModulusBits, u32 numThreads)
    {
        if (n == 0)
        {
            throw std::runtime_error("LogVole CI-VOLE sender requires a nonzero request size");
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
        if (!makeDefaultCivoleParams(params, numThreads))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not create default parameters");
        }
        params.mLogVole.mShrinkExpand.mPlaintextModulusBits = plaintextModulusBits;
        if (!resolveCivoleModulus(params, modulus))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not resolve plaintext modulus");
        }

        mRequestSize = n;
        mPlaintextModulusBits = plaintextModulusBits;
        mModulus = modulus;
        mDelta = 0;
        mNumThreads = numThreads;
        mNextSid = 0;
        mLastOnlineComm = {};
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
        if (b.size() != mRequestSize)
        {
            throw std::runtime_error("LogVole CI-VOLE sender output size does not match configured size");
        }

        const CivoleSid sid = mNextSid++;
        CivoleSenderReleaseOutput release{};
        co_await civoleSenderRelease(mOfflineState, sid, release, prng, sock);
        if (mOfflineState.mReleasedKeys.size() != b.size())
        {
            throw std::runtime_error("LogVole CI-VOLE sender key output size is invalid");
        }

        std::copy(mOfflineState.mReleasedKeys.begin(), mOfflineState.mReleasedKeys.end(), b.begin());
        mLastOnlineComm = release.mComm;
    }

    task<> LogVoleSender::send(u64 delta, span<u64> b, PRNG& prng, Socket& sock)
    {
        if (!isConfigured())
        {
            configure(b.size(), mPlaintextModulusBits, mNumThreads);
        }
        if (b.size() != mRequestSize)
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
        mParams = {};
        mOfflineState = {};
        mState = State::Default;
    }

    void LogVoleReceiver::configure(u64 n, u32 plaintextModulusBits, u32 numThreads)
    {
        if (n == 0)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver requires a nonzero request size");
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
        if (!makeDefaultCivoleParams(params, numThreads))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not create default parameters");
        }
        params.mLogVole.mShrinkExpand.mPlaintextModulusBits = plaintextModulusBits;
        if (!resolveCivoleModulus(params, modulus))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not resolve plaintext modulus");
        }

        mRequestSize = n;
        mPlaintextModulusBits = plaintextModulusBits;
        mModulus = modulus;
        mNumThreads = numThreads;
        mNextSid = 0;
        mLastOnlineComm = {};
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

        CivoleReceiverState state{};
        co_await civoleReceiverOffline(input, state, sock);
        if (state.mW != mRequestSize)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver offline size does not match configured size");
        }

        mOfflineState = std::move(state);
        mModulus = mOfflineState.mModulus;
        mNextSid = 0;
        mLastOnlineComm = {};
        mState = State::Offline;
    }

    task<> LogVoleReceiver::receive(span<const u64> x, span<u64> a, PRNG& prng, Socket& sock)
    {
        if (x.size() != a.size())
        {
            throw std::runtime_error("LogVole CI-VOLE receiver input and output sizes do not match");
        }
        if (!isConfigured())
        {
            configure(x.size(), mPlaintextModulusBits, mNumThreads);
        }
        if (x.size() != mRequestSize)
        {
            throw std::runtime_error("LogVole CI-VOLE receiver input size does not match configured size");
        }
        if (!hasOffline())
        {
            co_await offline(sock);
        }

        const CivoleSid sid = mNextSid++;

        CivoleReceiverSetXOutput setX{};
        co_await civoleReceiverSetX(mOfflineState, sid, x, setX, prng, sock);
        if (setX.mMacs.size() != a.size())
        {
            throw std::runtime_error("LogVole CI-VOLE receiver MAC output size is invalid");
        }

        std::copy(setX.mMacs.begin(), setX.mMacs.end(), a.begin());
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
        mParams = {};
        mOfflineState = {};
        mState = State::Default;
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

    bool makeZpCrtContext(const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out)
    {
        if (plaintextModulusBits == 0)
        {
            return false;
        }

        RingNttContext ringCtx{};
        if (!makeRingNttContext(ring, ringCtx))
        {
            return false;
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

        seal::EncryptionParameters batchingParams(seal::scheme_type::bgv);
        batchingParams.set_poly_modulus_degree(ring.mPolyModulusDegree);
        batchingParams.set_coeff_modulus(ringCtx.mModuli);
        batchingParams.set_plain_modulus(batchingPlainModulus);

        auto batchingContext = std::make_shared<seal::SEALContext>(batchingParams, true, seal::sec_level_type::none);
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
        next.mPlaintextLiftModQj.resize(rho);
        for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
        {
            next.mPlaintextLiftModQj[modIdx] =
                seal::util::modulo_uint(plaintextLift.get(), rho, next.mRing.mModuli[modIdx]);
        }

        out = std::move(next);
        return true;
    }

    bool wrapZpBatchCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32,
        RnsPoly& out)
    {
        if (!validateZpContext(ctx) ||
            labels.size() > zpSlotCount(ctx) ||
            !validateZpValues(ctx, labels) ||
            !validateZpValue(ctx, padValue))
        {
            return false;
        }

        std::vector<u64> slots(zpSlotCount(ctx), padValue);
        std::copy(labels.begin(), labels.end(), slots.begin());

        seal::BatchEncoder encoder(*ctx.mBatchingContext);
        return encodeSlotsToRingCrt(ctx, slots, encoder, multiplyByDelta, out);
    }

    bool wrapZpConstantCrt(
        const ZpCrtContext& ctx,
        u64 value,
        bool multiplyByDelta,
        u32 requestedWorkers,
        RnsPoly& out)
    {
        if (!validateZpContext(ctx) || !validateZpValue(ctx, value))
        {
            return false;
        }

        std::vector<u64> slots(zpSlotCount(ctx), value);
        seal::BatchEncoder encoder(*ctx.mBatchingContext);
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
        if (!validateZpContext(ctx) ||
            !validateZpValues(ctx, labels) ||
            !validateZpValue(ctx, padValue))
        {
            return false;
        }

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
        AlignedUnVec<u64> crtInvPunctured;
        AlignedUnVec<u64> qI;
        AlignedUnVec<wideU64> fracInvModulus;
        resizeZero(crtInvPunctured, rho);
        resizeZero(qI, rho);
        resizeZero(fracInvModulus, rho);
        for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
        {
            qI[modIdx] = fullBase.base()[modIdx].value();
            crtInvPunctured[modIdx] = invPunctProd[modIdx].operand;
            fracInvModulus[modIdx] = reciprocal2Pow128Wide(qI[modIdx]);
        }
        const wideU64 half = wideU64OneShift(127);

        const u64 chunkCount = zpRingLabelCount(ctx, zpLabelCount);
        std::vector<AlignedUnVec<u64>> decodedChunks(chunkCount);
        if (!detail::runParallelTasks(
                static_cast<std::size_t>(chunkCount),
                requestedWorkers,
                [&](std::size_t labelIdx) {
                    RnsPoly canonical = labels[labelIdx];
                    if (!canonicalizePoly(canonical, ctx.mRing))
                    {
                        return false;
                    }

                    seal::Plaintext plain;
                    plain.resize(slotCount);

                    if (scaleAndRound)
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

                                const wideU64 scaledNumerator = wideU64Mul(xI, plainModulusValue);
                                u64 scaledWords[2] = {
                                    scaledNumerator.mLo,
                                    scaledNumerator.mHi
                                };
                                u64 quotientWords[2] = { 0, 0 };
                                seal::util::divide_uint128_inplace(scaledWords, qI[modIdx], quotientWords);

                                scaledCoeff += quotientWords[0];
                                if (scaledCoeff >= plainModulusValue)
                                {
                                    scaledCoeff -= plainModulusValue;
                                }

                                unsigned char carry = 0;
                                fracSum = wideU64Add(
                                    fracSum,
                                    wideU64MulLow(scaledWords[0], fracInvModulus[modIdx]),
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
                    else
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
                        seal::BatchEncoder encoder(*ctx.mBatchingContext);
                        encoder.decode(plain, slots);
                    }
                    catch (const std::exception&)
                    {
                        return false;
                    }

                    const u64 offset = static_cast<u64>(labelIdx) * slotCount;
                    const u64 remaining = zpLabelCount - offset;
                    const u64 copyCount = std::min<u64>(remaining, slots.size());
                    assignRange(decodedChunks[labelIdx], slots.begin(), slots.begin() + copyCount);
                    return true;
                }))
        {
            return false;
        }

        out.resize(static_cast<std::size_t>(zpLabelCount));
        auto* outIter = out.data();
        for (const auto& chunk : decodedChunks)
        {
            outIter = std::copy(chunk.begin(), chunk.end(), outIter);
        }
        return true;
    }

    task<> civoleSenderOffline(
        const CivoleSenderOfflineInput& input,
        CivoleSenderState& state,
        PRNG& prng,
        Socket& sock)
    {
        CivoleParams sessionParams = input.mParams;

        ZpCrtContext ctx{};
        if (!makeZpCrtContext(
                sessionParams.mLogVole.mShrinkExpand.mRing,
                sessionParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx) ||
            input.mDelta == 0 ||
            input.mDelta >= ctx.mPlaintextModulus)
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

        RnsPoly wrappedDelta{};
        if (!wrapZpConstantCrt(
                ctx,
                input.mDelta,
                true,
                sessionParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                wrappedDelta))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not wrap delta");
        }

        auto metaSock = sock.fork();
        CivoleOfflineMeta meta{};
        meta.mLabelCount = input.mW;
        co_await sendCivoleOfflineMeta(metaSock, meta);

        SenderOfflineInput offlineInput{};
        offlineInput.mParams = params;
        offlineInput.mSk1.resize(params.mGamma, std::move(wrappedDelta));

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
        auto metaSock = sock.fork();
        const CivoleOfflineMeta meta = co_await recvCivoleOfflineMeta(metaSock);
        CivoleParams sessionParams = input.mParams;

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

        ReceiverOfflineInput offlineInput{};
        offlineInput.mParams = params;

        LogVoleRingReceiver receiver{};
        ReceiverState logVoleState{};
        auto logVoleSock = sock.fork();
        co_await receiver.offline(offlineInput, logVoleState, logVoleSock);

        CivoleReceiverState next{};
        next.mParams = sessionParams;
        next.mModulus = ctx.mPlaintextModulus;
        next.mW = meta.mLabelCount;
        next.mRingWidth = params.mW;
        next.mLogVoleState = std::move(logVoleState);
        state = std::move(next);
    }

    bool civoleSenderReleaseK(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleReleaseKOutput& output)
    {
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
                ctx) ||
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
        Socket& sock)
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
        SenderOnlineOptions options{};
        options.mSid = sid;
        options.mSkipTbkOutput = false;
        co_await sender.online(state.mLogVoleState, options, online, prng, sock);

        ZpCrtContext ctx{};
        AlignedUnVec<u64> keys;
        if (!makeZpCrtContext(
                state.mParams.mLogVole.mShrinkExpand.mRing,
                state.mParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx) ||
            !unwrapRingLabelsCrt(
                ctx,
                online.mTbk,
                state.mW,
                true,
                state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                keys))
        {
            throw std::runtime_error("LogVole CI-VOLE sender could not unwrap keys");
        }

        state.mKeyReleased = true;
        const auto usedSidCount = state.mUsedSids.size();
        state.mUsedSids.resize(usedSidCount + 1);
        state.mUsedSids[usedSidCount] = sid;
        state.mReleasedKeys = std::move(keys);

        CivoleSenderReleaseOutput next{};
        next.mSid = sid;
        next.mComm = online.mComm;
        output = next;
    }

    task<> civoleReceiverSetX(
        CivoleReceiverState& state,
        CivoleSid sid,
        std::span<const u64> x,
        CivoleReceiverSetXOutput& output,
        PRNG& prng,
        Socket& sock)
    {
        if (x.size() != state.mW)
        {
            throw std::runtime_error("LogVole CI-VOLE setx size does not match offline width");
        }

        ZpCrtContext ctx{};
        if (!makeZpCrtContext(
                state.mParams.mLogVole.mShrinkExpand.mRing,
                state.mParams.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                ctx) ||
            !validateZpValues(ctx, x) ||
            !prepareReceiverSidForSetX(state, sid))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver setx input is invalid");
        }

        std::vector<RnsPoly> wrapped;
        if (!wrapZpLabelsCrt(
                ctx,
                x,
                false,
                0,
                state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                wrapped))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not wrap inputs");
        }

        const auto paddedSize = static_cast<std::size_t>(state.mLogVoleState.mParams.mW);
        const auto inputSize = wrapped.size();
        if (inputSize < paddedSize)
        {
            wrapped.resize(paddedSize);
            for (std::size_t idx = inputSize; idx < paddedSize; ++idx)
            {
                wrapped[idx] = makeZeroPoly(state.mLogVoleState.mParams.mShrinkExpand.mRing);
            }
        }

        ScopedProtocolCacheScope scopedCache(ProtocolCacheRole::Receiver, sid);

        ReceiverOnlineInput onlineInput{};
        onlineInput.mSid = sid;
        onlineInput.mX = std::move(wrapped);

        LogVoleRingReceiver receiver{};
        ReceiverOnlineOutput online{};
        co_await receiver.online(state.mLogVoleState, onlineInput, online, prng, sock);

        AlignedUnVec<u64> macs;
        if (!unwrapRingLabelsCrt(
                ctx,
                online.mTbm,
                state.mW,
                true,
                state.mParams.mLogVole.mShrinkExpand.mNumWorkerThreads,
                macs))
        {
            throw std::runtime_error("LogVole CI-VOLE receiver could not unwrap MACs");
        }

        CivoleReceiverSetXOutput next{};
        next.mSid = sid;
        next.mModulus = state.mModulus;
        assignSpan(next.mValues, x);
        next.mMacs = std::move(macs);
        next.mComm = online.mComm;
        output = std::move(next);
    }
}
