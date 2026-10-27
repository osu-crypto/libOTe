#pragma once

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <functional>
#include <memory>
#include <vector>

namespace osuCrypto::LogVole
{
    enum class SeedLabelMode : u8
    {
        Leaf = 0,
        Internal = 1
    };

    enum class RecursiveMode : u8
    {
        Root = 0,
        Internal = 1
    };

    struct GoldenSeedSearchOutput
    {
        AlignedUnVec<u8> mSeed;
        std::vector<RnsPoly> mTbkPerSampledPoly;
    };

    struct RootDigestState
    {
        RnsPoly mDRt;
        RnsPoly mYLeft;
        RnsPoly mDPrime;
        // Normally computed alongside mDPrime and reused by both Root operations
        // and all recursive levels. This is local per-query state, not the wire.
        block mDPrimeHash{};
        // The production socket path may defer the receiver's hash until its
        // digest has been scheduled for sending, overlapping this local work
        // with the sender's response. Direct/Core callers retain the historical
        // eager hash by default. Never consume mDPrimeHash unless this is true.
        bool mDPrimeHashValid = false;
        std::vector<RnsPoly> mHatDRt;
        std::vector<RnsPoly> mZeta;
        // When zeta was sampled directly on the GPU, retain the exact task-key
        // plan rather than materializing its 3*rho*N host coefficients. A later
        // device-path decline can replay these without touching the parent PRNG.
        std::vector<block> mZetaTaskSeeds;
        u32 mZetaRangesPerPoly = 0;
        bool mZetaForceFirstReject = false;
        std::shared_ptr<DigestTree> mRootTree;

        // Two results the digest step computes and used to throw away, both of
        // which the response step then recomputed from scratch. Carrying them
        // across the wire exchange is free - the state object already lives that
        // long - and it deletes a third of the Root's host time.
        //
        // mLeftTree is the digest tree over hatD. prepareRootDigestReceiver needs
        // only its root (yLeft), so it called lencDigestTrunc and dropped the tree;
        // finalizeRootResponseReceiver then called the lencEvalTrunc overload that
        // rebuilds the identical tree from the identical input.
        //
        // mTopInputsNtt is NTT(gadget(yLeft) ++ zeta), tauHi + randomizerWidth
        // polynomials. prepareRootDigestReceiver transforms exactly these to form
        // its two inner products; evalRootTopCtNtt then re-derived and
        // re-transformed them. Both are optional: empty means recompute, which is
        // what the CPU-only and test paths do.
        std::shared_ptr<DigestTree> mLeftTree;
        std::vector<RnsPoly> mTopInputsNtt;

        // The same left tree, still in device memory (an opaque gpu::LevelSession),
        // so the device key derivation can evaluate against it without the nodes
        // making a round trip. mLeftTree stays populated as the host fallback.
        std::shared_ptr<void> mLeftTreeGpu;
        // mTopInputsNtt on the device (an opaque gpu::DeviceBatch). Set instead of
        // mTopInputsNtt when the digest step ran its arithmetic there, in which case
        // yLeft's gadget digits and all four transforms never reach the host.
        std::shared_ptr<void> mTopInputsNttGpu;
        // Coefficient-domain dPrime retained after its mandatory wire download.
        // The download synchronizes its producer before this opaque
        // gpu::DeviceBatch crosses the socket wait, so finalization can safely
        // reuse it from any resuming stream. Enabled by default; setting
        // LV_GPU_ROOT_DPRIME_RESIDENT=0 restores the host-backed path.
        std::shared_ptr<void> mDPrimeGpu;
        // Opaque gpu::LevelSession. When the Root's shrink ran on the device this
        // holds its digest tree in device memory across the wire exchange, so the
        // matching expand can run there too without the tree ever reaching the host.
        // When set, mDRt and mRootTree stay empty and the device path is used.
        std::shared_ptr<void> mGpuSession;

        // Optional opaque gpu::PreparedRootFinalize. It owns the exact
        // response-independent Root-finalize output and its completion event
        // across the socket wait. Declared last so it is destroyed first and
        // can synchronize abandoned work before any tree/top-input owner dies.
        std::shared_ptr<void> mRootFinalizePrefetch;
    };

    struct SenderOfflineInput
    {
        Params mParams;
        std::vector<RnsPoly> mSk1;
        // Internal CI-VOLE transport may keep its one wrapped delta in
        // coefficient domain on the sender GPU until seed-label repetition.
        // The callback is exact CPU replay for a declined device consumer;
        // direct/public SenderOfflineInput keeps using eager mSk1.
        std::shared_ptr<const gpu::DeviceBatch> mWrappedDeltaDevice;
        std::function<bool(RnsPoly&)> mWrappedDeltaHostFallback;
        // Selected recursive child borrows only the sender-owned top HE key.
        // A CPU decline uses its already-drawn SEAL seeds through the lazy owner.
        std::shared_ptr<const gpu::DeviceBatch> mTopSk1Device;
        std::shared_ptr<const LazyRootSecretHostState> mLazyTopSk1;
        // Internal CI-VOLE offline run for a retained delta. RingSender uses
        // this only around synchronous setup/encoding; zero keeps direct
        // callers' existing scope behavior.
        u64 mSenderOwnerRunId = 0;
        bool mLeafInputsAreGadget = false;
        // Opt in to immutable shared host backing for internal recursive GPU
        // states after their device cache is complete. The default preserves
        // full independent mutable host vectors at every level.
        bool mUseGpuResidentInternalState = false;
    };

    struct OfflineMessage
    {
        bool mHasShrinkExpandMessage = true;
        ShrinkExpandOfflineMessage mShrinkExpandMessage;
        // Internal socket preparation may encode directly from the sender
        // state. These independently owned bytes replace mShrinkExpandMessage
        // only in detail::prepareSenderOfflineForTransport's output.
        Buffer mEncodedShrinkExpandMessage;
        RootOfflineMessage mRootMessage;
        std::unique_ptr<OfflineMessage> mNextLevel;
    };

    struct SenderOfflineOutput
    {
        SenderState mState;
        OfflineMessage mMessage;
        // mMessage carries the top level's shrink/expand and Root messages already.
        // There used to be copies of both here; nothing read them, and at these
        // parameters filling them duplicated the whole offline tensor set - 397 MB
        // at N = 16384 with 8 limbs.
    };

    struct ReceiverOfflineInput
    {
        Params mParams;
        bool mLeafInputsAreGadget = false;
        bool mUseGpuResidentInternalState = false;
    };

    struct ReceiverOfflineOutput
    {
        ReceiverState mState;
    };

    struct CommunicationStats
    {
        u64 mBytesSent = 0;
        u64 mBytesReceived = 0;
    };

    struct SenderOnlineOutput
    {
        std::vector<RnsPoly> mTbk;
        // Set instead of mTbk when the GPU produced the keys and they were left
        // on the device (see ReceiverOnlineOutput::mTbmDevice). The concrete type
        // is gpu::DeviceBatch.
        std::shared_ptr<void> mTbkDevice;
        u64 mTbkCount = 0;
        AlignedUnVec<u8> mSeed;
        CommunicationStats mComm;
    };

    struct SenderOnlineOptions
    {
        u64 mSid = 0;
        bool mSkipTbkOutput = false;

        // Keep an existing senderPrecompute() result instead of clearing the
        // online cache. Only meaningful within a single SID; see
        // senderPrecompute for why this cannot hoist work before x arrives.
        bool mUsePrecomputed = false;
    };

    struct ReceiverOnlineInput
    {
        u64 mSid = 0;
        std::vector<RnsPoly> mX;

        // Optional device-resident copy of mX, used by the CUDA backend to keep
        // a recursion level's output from round-tripping through the host. When
        // set, mX may be empty and mXCount carries the length. Type-erased so
        // that this header stays free of CUDA types.
        std::shared_ptr<void> mXDevice;
        u64 mXCount = 0;
    };

    inline u64 receiverInputCount(const ReceiverOnlineInput& input)
    {
        return input.mXDevice ? input.mXCount : static_cast<u64>(input.mX.size());
    }

    struct ReceiverOnlineOutput
    {
        std::vector<RnsPoly> mTbm;
        AlignedUnVec<u8> mSeed;
        CommunicationStats mComm;

        // Optional device-resident copy of mTbm; see ReceiverOnlineInput.
        std::shared_ptr<void> mTbmDevice;
        u64 mTbmCount = 0;
    };

    u32 rootRandomizerWidth(const ShrinkExpandParams& params);
    u32 rootLeftWidth(u32 tauHi, u32 rho);
    double rootNoiseSigma(const ShrinkExpandParams& params, double factor);
    double rootNoiseMaxDeviation(double sigma);

    SeedLabelMode evalSeedLabelMode(u32 w, u32 alpha, u32 tau, u32 rho);
    RecursiveMode evalRecursiveMode(u32 w, u32 alpha, u32 tau, u32 rho);

    bool makeTruncShrinkExpandParams(
        const Params& params,
        bool leafInputsAreGadget,
        ShrinkExpandParams& out);

    bool replicateRootHiKeyByLimb(
        const std::vector<RnsPoly>& skHi,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool sampleRootErrorBatch(
        const RingNttContext& ctx,
        u32 count,
        PRNG& prng,
        double sigma,
        double maxDeviation,
        bool outputNtt,
        std::vector<RnsPoly>& out);
    bool sampleRootErrorBatch(
        const RingNttContext& ctx, u32 count, PRNG& prng, double sigma,
        double maxDeviation, bool outputNtt, std::vector<RnsPoly>& out, u32 requestedWorkers);

    bool addScaledNttInplace(
        RnsPoly& accNtt,
        const RnsPoly& polyNtt,
        u32 gadgetLogBase,
        u32 power,
        const RingNttContext& ctx,
        bool subtract);

    bool negateNttInplace(RnsPoly& polyNtt, const RingNttContext& ctx);

    bool buildRootTopCt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r1,
        const std::vector<RnsPoly>& r2Ntt,
        const std::vector<RnsPoly>& publicBRootNtt,
        const std::vector<RnsPoly>& publicBStarNtt,
        u32 gadgetLogBase,
        u32 gadgetPowerOffset,
        PRNG& prng,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        RingTensor& out,
        u32 requestedWorkers = 1,
        std::shared_ptr<const LazyLencRandomizerState> randomizers = {},
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext = nullptr,
        const gpu::RetainedPublicUniform* retainedPublicBFullNtt = nullptr,
        const gpu::DeviceBatch* rootR1Device = nullptr,
        const LazyRootErrorHostState* rootR1Host = nullptr,
        const gpu::RetainedPublicUniform* retainedBStarNtt = nullptr);

    // requestedWorkers > 1 splits the coefficients across the worker pool, each
    // range drawing from its own PRNG keyed from `prng`. zeta is the receiver's
    // local randomizer, so only its distribution matters; requestedWorkers = 1
    // keeps the original single-stream draw order.
    bool sampleRootZeta(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        PRNG& prng,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);

    // Exact replay of sampleRootZeta's parallel path. `taskSeeds` is ordered as
    // [poly][range], with one independent cryptoTools AES-CTR PRNG per range.
    // Keeping this boundary explicit lets the GPU consume the already-drawn
    // seeds while any allocation/launch fallback reconstructs the same zeta
    // without advancing the parent PRNG a second time. `forceFirstReject` is a
    // deterministic test hook: it treats task zero's first candidate as rejected
    // in both the CPU and GPU implementations.
    bool sampleRootZetaFromTaskSeeds(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        std::span<const block> taskSeeds,
        u32 rangesPerPoly,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1,
        bool forceFirstReject = false);

    // outputNtt leaves the accumulator in the evaluation domain so a caller that
    // sums several inner products pays one inverse transform for the sum instead
    // of one per term.
    bool rootInnerProductNtt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& leftNtt,
        const std::vector<RnsPoly>& rightCoeff,
        RnsPoly& out,
        bool outputNtt = false);

    bool prepareRootOfflineSender(
        SenderState& state,
        PRNG& prng,
        RootOfflineMessage& message,
        bool deferRandomizerHost = false);

    bool finalizeRootOfflineReceiver(
        ReceiverState& state,
        const RootOfflineMessage& message);

    // Consumes ciphertext storage after validation; state is unchanged on failure.
    bool finalizeRootOfflineReceiver(
        ReceiverState& state,
        RootOfflineMessage&& message);

    // `xDevice` is an optional opaque gpu::DeviceBatch holding the same input as
    // `x`. When present the device shrink reads it directly, so the Root's input
    // never makes a device -> host -> device round trip; `x` may then be empty.
    bool prepareRootDigestReceiver(
        const ReceiverState& state,
        const std::vector<RnsPoly>& x,
        PRNG& prng,
        RootDigestState& digestState,
        RootDigestMessage& message,
        const std::shared_ptr<void>& xDevice = {},
        u64 xDeviceCount = 0,
        bool deferDPrimeHash = false);

    // Completes a hash deferred by prepareRootDigestReceiver. Idempotent after
    // success. The state owns mDPrime for the whole Root exchange, so callers can
    // safely invoke this after scheduling the digest buffer and before waiting
    // for or consuming the sender's response.
    bool finishRootDigestHash(RootDigestState& digestState);

    // Public random-oracle response H((sid, non-interactive), d'). Uses the
    // full canonical randomized digest and ring parameters; no sender secret
    // or sender randomness is needed. CT2 uses a separate oracle domain.
    bool deriveNonInteractiveRootResponse(
        const Params& params,
        const RnsPoly& dPrime,
        RootResponseMessage& response);

    // `preSampledKPrime`, when non-null, is used instead of drawing k'_Rt here.
    // k'_Rt does not depend on the receiver's digest, so the caller can draw it
    // while it is waiting for that digest to arrive; the PRNG stream is unchanged
    // because nothing else draws from it in between.
    // `preSampledKPrimeDevice` is its optional synchronized coefficient-domain
    // mirror from prepareRootResponseDeviceOperands, or a device-generated key
    // from sampleRootResponseKPrime (whose matching host pre-sample is empty).
    // It is consumed only when the matching pre-sample is supplied; skRRt residency is
    // independent, and either missing operand takes its exact upload fallback.
    //
    // With `deferPrecompute` the recursive sender expansion is *not* run here, so
    // the reply can go on the wire before it starts. Only legal in
    // Ct2SeedMode::PublicSeed, where the reply carries no seed and therefore does
    // not depend on the expansion; the caller must then call
    // finishRootSenderPrecompute.
    bool prepareRootResponseSender(
        const SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot = nullptr,
        const RnsPoly* preSampledKPrime = nullptr,
        bool deferPrecompute = false,
        const std::shared_ptr<void>& preSampledKPrimeDevice = {});

    // Single-use production overload. After validating the wire shape, this
    // moves the decoded d' coefficients into the query state instead of copying
    // the full ring polynomial. The const overload above remains the public
    // retry/test path and never consumes its input.
    bool prepareRootResponseSender(
        const SenderState& state,
        RootDigestMessage&& request,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot = nullptr,
        const RnsPoly* preSampledKPrime = nullptr,
        bool deferPrecompute = false,
        const std::shared_ptr<void>& preSampledKPrimeDevice = {});

    // The half of prepareRootResponseSender that deferPrecompute skipped.
    bool finishRootSenderPrecompute(
        const SenderState& state,
        PRNG& prng,
        const SenderState* precomputeRoot = nullptr);

    // Draws the k'_Rt that prepareRootResponseSender would draw, so it can be
    // moved off the critical path.
    // When requested and supported, returns a synchronized device-generated
    // polynomial and leaves out empty. CPU consumers materialize it lazily.
    bool sampleRootResponseKPrime(const SenderState& state, PRNG& prng, RnsPoly& out,
        std::shared_ptr<void>* deviceOut = nullptr);

    // Device preparation for the digest-independent Root response operands.
    // Immutable offline skRRt caching is enabled by default and can be rolled
    // back with LV_GPU_ROOT_SK_NTT_RESIDENT=0; LV_GPU_ROOT_KPRIME_PREUPLOAD
    // independently enables a synchronized coefficient-domain fresh kPrime.
    // LV_GPU_ROOT_OPERAND_RESIDENCY enables all components as a compatibility
    // alias. False is a soft miss and preserves the established path.
    bool prepareRootResponseDeviceOperands(
        const SenderState& state,
        const RnsPoly& kPrime,
        std::shared_ptr<void>& preparedKPrimeDevice);

    // When `rootKeyDevice` is supplied and the GPU path is available, the whole key
    // derivation runs on the device and the key is returned there (an opaque
    // gpu::DeviceBatch of one polynomial), leaving `rootKey` untouched. The device
    // expand is the only consumer, so this saves a download and a re-upload as well
    // as the arithmetic.
    bool finalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice = nullptr);

    // Single-use production overload matching prepareRootResponseSender's owned
    // path. It validates before moving skPrime out of the decoded response.
    bool finalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        RootResponseMessage&& response,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice = nullptr);

    bool computeRootSenderKey(
        const SenderState& state,
        std::span<const u8> seed,
        RnsPoly& rootKey);

    bool prepareSenderOffline(
        const SenderOfflineInput& input,
        PRNG& prng,
        SenderOfflineOutput& out);
    // Explicit inspection of a selected internal top-key owner. This fills
    // independent mutable key vectors only after device setup/recursion ends.
    bool materializeSenderTopSk1HostViews(SenderState& state);

    namespace detail
    {
        // Socket-only preparation: explicit internal GPU inputs may return
        // encoded shrink/expand messages for ownership transfer to transport.
        // Public prepareSenderOffline always returns mutable message tensors.
        bool prepareSenderOfflineForTransport(
            const SenderOfflineInput& input,
            PRNG& prng,
            SenderOfflineOutput& out);
    }

    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        const OfflineMessage& message,
        ReceiverOfflineOutput& out);

    // Consumes message storage; recursive failure may leave message partly moved.
    // Output remains unchanged on failure, and reusable internal states are copied.
    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        OfflineMessage&& message,
        ReceiverOfflineOutput& out);

    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& shrinkExpandMessage,
        const RootOfflineMessage& rootMessage,
        ReceiverOfflineOutput& out);

    bool ensureSenderPrecompute(
        const SenderState& state);

    bool ensureRootSenderPrecompute(
        const SenderState& state);

    // Per-limb rounding margins used by validateGoldenSeedCandidate, as 128-bit
    // values split into low/high words. Exposed so that the CUDA backend can run
    // the same predicate on the device. Returns false if the parameters do not
    // admit a feasible golden-seed search.
    bool goldenSeedRoundingMargins(
        const Params& params,
        const RingNttContext& ctx,
        std::vector<u64>& marginLo,
        std::vector<u64>& marginHi);

    // Full-CRT constants for the final Q/p rounding, shared by CPU and CUDA.
    // The inverse includes p; the margin covers noise, floor(Q/p)'s lift error,
    // and the 128-bit reciprocal error in both the predicate and the decoder.
    struct LeafGoldenSeedRoundingConstants
    {
        std::vector<u64> mInverse;
        std::vector<u64> mReciprocalLo;
        std::vector<u64> mReciprocalHi;
        u64 mMarginLo = 0;
        u64 mMarginHi = 0;
    };

    bool leafGoldenSeedRoundingConstants(
        const Params& params,
        const RingNttContext& ctx,
        LeafGoldenSeedRoundingConstants& out);

    // Pick a golden seed and evaluate the sender expansion tbk into
    // SenderState::mPrecomputedTbk.
    //
    // Note that this is NOT usable as a "before x arrives" precomputation: the
    // sender expansion consumes the receiver's root digest d' as the ct2 mask,
    // so state.mRootDPrimeRt must already be populated (i.e. the root digest
    // message must have been received). It exists so that a cached result can
    // be reused across the response and the key release within one SID.
    bool senderPrecompute(
        SenderState& state,
        PRNG& prng);

    // True when a usable senderPrecompute() result is cached.
    bool senderHasPrecompute(const SenderState& state);

    bool prepareRootOnlineSender(
        SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        SenderOnlineOutput& out);

    bool finalizeRootOnlineReceiver(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        ReceiverOnlineOutput& out);

    bool finalizeRootOnlineReceiver(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        RootResponseMessage&& response,
        ReceiverOnlineOutput& out);

    bool seedLabelAgg(
        const std::vector<RnsPoly>& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    // Consumes a temporary batch, avoiding a full copy when tau == 1.
    bool seedLabelAgg(
        std::vector<RnsPoly>&& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelGadgetDecomposeAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelGadgetDecomposeHiAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelDenoiseTbm(
        const std::vector<RnsPoly>& tbmPrime,
        u32 wPrime,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);

    bool seedLabelRepOfflineSenderInput(
        const std::vector<RnsPoly>& s,
        u32 gamma,
        u32 alpha,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelSampleCt2FromSeed(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u32 instanceIdx,
        u32 coeffCount,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool validateGoldenSeedSearch(const Params& params);

    // log2 of the SEC6 noise bound B for these parameters. Exposed so that a
    // caller (or a benchmark) can report the correctness margin it is running
    // with rather than infer it.
    double noiseBoundLog2(const Params& params);

    // Feasibility of Ct2SeedMode::PublicSeed: for every limb j,
    //     log2(2B) + mCt2StatBits <= log2(Delta_j),  Delta_j = prod_{w != j} q_w,
    // i.e. a sampled ct2 coefficient is bad with probability at most
    // 2^-mCt2StatBits and no seed search is needed.
    bool validateNoGoldenSeedBudget(const Params& params);

    // What that check achieves: min_j (log2(Delta_j) - log2(2B)), the number of
    // bits of per-coefficient correctness margin these parameters actually give.
    double noGoldenSeedFailureBits(const Params& params);

    // The truncated parameter set the recursion runs (tauHi = tau - 1), which is
    // what both budget checks and the noise bound are stated over.
    bool makeEffectiveTruncParams(const Params& params, Params& out);

    // Whichever of the two budget checks matches params.mCt2SeedMode, evaluated
    // against the truncated parameter set the recursion actually runs.
    bool validateCt2SeedMode(const Params& params);

    bool validateGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbkPerSampledPoly,
        bool& out);

    // Leaf validation takes exactly mW logical output polynomials. Intermediate
    // levels continue to validate the entire padded sample with Q/q_j.
    bool validateLeafGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbk,
        bool& out);

    bool findGoldenSeed(
        const Params& params,
        const std::vector<RnsPoly>& sk2PerInstance,
        const RnsPoly& digest,
        PRNG& prng,
        GoldenSeedSearchOutput& out);
}
