#pragma once

// Host-visible declarations for the LogVole CUDA kernels. This header is
// deliberately free of both CUDA and SEAL types so that it can be included
// from ordinary C++ translation units. Streams are passed as void* and cast to
// cudaStream_t inside the .cu file.

#include <cstddef>
#include <cstdint>

namespace osuCrypto::LogVole::gpu
{
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;

    // Mirrors seal::util::MultiplyUIntModOperand.
    struct HostShoupOperand
    {
        u64 mOperand = 0;
        u64 mQuotient = 0;
    };

    // Mirrors seal::Modulus: value plus the two low words of
    // floor(2^128 / value) (seal::Modulus::const_ratio()).
    struct HostModulus
    {
        u64 mValue = 0;
        u64 mRatio0 = 0;
        u64 mRatio1 = 0;
    };

    struct LeafGoldenSeedLimb
    {
        u64 mQ = 0;
        HostShoupOperand mInverse;
        u64 mReciprocalLo = 0;
        u64 mReciprocalHi = 0;
    };

    // Minimal per-limb table for the fixed N=8192/rho=4 scale-and-round path.
    // It contains only constants read by that kernel and is uploaded once with
    // the plaintext-modulus-specific scale constants.
    struct ScaleRoundFastLimb
    {
        u64 mQ = 0;
        u64 mBarrettRatio1 = 0;
        u64 mInvOperand = 0;
        u64 mInvQuotient = 0;
        u64 mPShoup = 0;
        u64 mFracLo = 0;
        u64 mFracHi = 0;
    };
    static_assert(sizeof(ScaleRoundFastLimb) == 7 * sizeof(u64));

    struct ScaleRoundConstView
    {
        const u64* mCrtInvPunctured = nullptr;
        const u64* mQ = nullptr;
        const u64* mPShoup = nullptr;
        const u64* mFracLo = nullptr;
        const u64* mFracHi = nullptr;
        const ScaleRoundFastLimb* mFastLimbs = nullptr;
    };

    // Device-resident constants for one RingParams instance. All pointers are
    // device pointers owned by GpuRingContext.
    struct RingConstView
    {
        u32 mN = 0;
        u32 mLogN = 0;
        u32 mRho = 0;
        // Host-side dispatch metadata. The pointed-to modulus table is device
        // memory, so launchers cannot inspect it before selecting a kernel.
        u64 mMinModulus = 0;
        u64 mMaxModulus = 0;

        const void* mMods = nullptr;            // [rho]        GpuModulus
        const void* mRoots = nullptr;           // [rho][N]     ShoupOperand, bit-reversed
        const void* mInvRoots = nullptr;        // [rho][N]     ShoupOperand, scrambled
        const void* mInvDegree = nullptr;       // [rho]        ShoupOperand
        const void* mScaledInvRoot = nullptr;   // [rho]        ShoupOperand

        // Multi-precision CRT constants, rho words each, little-endian.
        const u64* mBaseProd = nullptr;         // [rho]
        const u64* mBaseProdHalf = nullptr;     // [rho]  floor(baseProd / 2)
        const u64* mPuncturedProd = nullptr;    // [rho][rho]
        const void* mInvPuncturedProd = nullptr;// [rho]  ShoupOperand

        // q_j^-1 mod q_i at [i*rho + j], j < i. Mixed-radix (Garner) composition
        // constants; see garnerCompose.
        const void* mGarnerInv = nullptr;       // [rho][rho] ShoupOperand

        // Optional exact integer-valued doubles for the H200 FP52 transforms.
        // Packed operands omit the unused Shoup quotient and boundary conversion.
        const double* mFp52Roots = nullptr;     // [rho][N]
        const double* mFp52InvRoots = nullptr;  // [rho][N]
        // Optional per-ring GPU-prepared q, RN(1/q), and Garner operands.
        const double* mFp52GadgetConstants = nullptr; // [8 + 8 + 64]
        const double* mFp52GadgetRatios = nullptr; // optional [64], RN(root/q)
        // Host metadata prepared in this ring's CUDA context. Zero leaves L2
        // policy untouched, including unsupported devices and synthetic views.
        std::size_t mH200RootL2MaxWindow = 0;
    };

    bool gpuDeviceAvailable();
    const char* gpuDeviceName();
    bool gpuLastErrorOk(const char** msg);

    // ---- memory -----------------------------------------------------------
    // Device allocations are recycled through a size-bucketed free list because
    // cudaMalloc/cudaFree synchronise and are far too slow to call per query.
    void* gpuMalloc(std::size_t bytes);
    void gpuFree(void* ptr);
    // Hands every cached block back to the driver.
    void gpuTrimMemory();
    void* gpuMallocHost(std::size_t bytes);
    void gpuFreeHost(void* ptr);
    // Setup-wire storage is ordinary page-aligned host memory so allocation
    // does not eagerly fault and pin a large payload. The process-local pool
    // registers a complete owned block lazily on its first GPU transfer and
    // retains successful registration across reuse. Allocation/registration
    // declines preserve the ordinary/staged fallback.
    void* gpuTryAllocateSetupWireHost(std::size_t bytes);
    // True only while the complete range belongs to a live setup-wire block.
    bool gpuIsSetupWireHostRange(const void* ptr, std::size_t bytes);
    // True only when the live range also has persistent CUDA registration.
    bool gpuIsSetupWirePinnedHostRange(const void* ptr, std::size_t bytes);
    // Try to register the complete page-aligned block containing this range.
    // pinned=false is a benign decline; fatal CUDA errors return false.
    bool gpuTryPinSetupWireHostRange(const void* ptr, std::size_t bytes, bool& pinned);
    // Release an exact setup-wire base pointer; false means it is not ours.
    bool gpuReleaseSetupWireHost(void* ptr) noexcept;
    // Optional registration of an exact caller-owned host span. A supported
    // decline returns true with registered=false; fatal CUDA errors return false.
    // Only a successful registration may be passed to gpuUnregisterHost.
    bool gpuTryRegisterHost(void* ptr, std::size_t bytes, bool& registered);
    bool gpuUnregisterHost(void* ptr);
    bool gpuMemcpyH2D(void* dst, const void* src, std::size_t bytes, void* stream);
    bool gpuMemcpyD2H(void* dst, const void* src, std::size_t bytes, void* stream);
    bool gpuMemcpyD2D(void* dst, const void* src, std::size_t bytes, void* stream);
    bool gpuMemsetZero(void* dst, std::size_t bytes, void* stream);

    // Drop the caching allocator's references to `stream`, so cached blocks are not
    // left tagged with a stream that is about to be destroyed. Must be called after
    // the stream is synchronised and its buffers freed, and before it is destroyed.
    void gpuForgetStream(void* stream);

    // ---- events ------------------------------------------------------------
    // Just enough to overlap two independent kernel chains on separate streams
    // and join them without a host round trip.
    bool gpuStreamWaitEvent(void* stream, void* event);
    // Declares which stream the calling scope is about to use. gpuMalloc tags
    // blocks with it and gpuFree records it, so the caching allocator can hand a
    // recycled block straight back to the same stream and synchronise only when a
    // block crosses streams. Without this, running two parties on two streams
    // would let one stream reuse a block the other is still writing.
    void gpuSetCurrentStream(void* stream);
    void* gpuCurrentStream();

    void* gpuStreamCreate();
    void gpuStreamDestroy(void* stream);
    bool gpuStreamSync(void* stream);
    bool gpuDeviceSync();

    // Events, used to pipeline a large device-to-host copy against the host-side
    // copy out of the pinned staging buffer.
    void* gpuEventCreate();
    void gpuEventDestroy(void* event);
    bool gpuEventRecord(void* event, void* stream);
    bool gpuEventSync(void* event);

    // ---- transforms -------------------------------------------------------
    // Setup-only optional context reservation; no device metadata is cached
    // process-wide. The caller must use the ring in its owning CUDA context.
    bool prepareH200RootPersistence(RingConstView& rc);
    // In-place batched forward/inverse negacyclic NTT, bit-identical to SEAL's
    // ntt_negacyclic_harvey / inverse_ntt_negacyclic_harvey. `data` holds
    // `polyCount` polynomials of rho*N u64 in limb-major order. When polyIdx is
    // non-null it selects which polynomials of `data` to transform.
    bool launchNttForward(
        const RingConstView& rc, u64* data, u32 polyCount, const u32* polyIdx, void* stream);
    // Plaintext forward NTT with BatchEncoder's final slot permutation fused
    // into the transform store. `inverseSlotMap[k]` gives the decoded slot for
    // transformed coefficient k; the final chunk is truncated by outCount.
    bool launchNttForwardGather(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* inverseSlotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        void* stream);
    // Out-of-place forward transform. `inIdx` and `outIdx` independently select
    // the source and destination polynomials. Used when the producer is an exact
    // identity materialization, so the transform can load the source directly
    // and avoid writing then rereading a full intermediate batch.
    bool launchNttForwardFrom(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        void* stream);

    // Out-of-place forward transform for an exact plaintext
    // broadcast whose canonical coefficient is materialized in source limb 0
    // only. Target limbs still use their own roots/moduli and full-RNS layout.
    bool canLaunchNttForwardFromPlainBroadcast(const RingConstView& rc);
    bool launchNttForwardFromPlainBroadcast(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        void* stream);

    // Fuses the exact recursive dHat round trip into an out-of-place NTT load.
    // For output i, inIdx[i] selects a full-RNS high digit and limbSel[i]
    // selects the residue whose centred representative is broadcast to every
    // target limb. limbSel >= rho denotes a zero-padding polynomial.
    bool launchNttForwardCenteredLimbFrom(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        const u32* limbSel,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        void* stream);

    // Same-binary Stage-88 exactness launchers. `fusedLastTwo == false`
    // directly names the accepted staged special-input symbol; true names its
    // S11/S12 sidecar. Unsupported geometry is a soft decline. Once launched,
    // CUDA failure is terminal and callers must not invoke a fallback.
    bool tryLaunchNttForwardFromPlainBroadcastTailForTest(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        bool fusedLastTwo,
        void* stream,
        bool& launched);

    bool tryLaunchNttForwardCenteredLimbFromTailForTest(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        const u32* limbSel,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        bool fusedLastTwo,
        void* stream,
        bool& launched);

    // Same-binary Stage-109 exactness launchers. `warpStages712 == false`
    // directly names the preceding S11/S12 rollback symbol; true names the
    // accepted S7--S12 warp-register path. Unsupported geometry, null pointers,
    // out-of-place aliases and overflowing launch counts decline without a
    // write. These hooks do not consult the production environment switch.
    bool tryLaunchNttForwardWarpStages712ForTest(
        const RingConstView& rc,
        u64* data,
        const u32* polyIdx,
        u32 polyCount,
        bool warpStages712,
        void* stream,
        bool& launched);

    bool tryLaunchNttForwardFromPlainBroadcastWarpStages712ForTest(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        bool warpStages712,
        void* stream,
        bool& launched);

    bool tryLaunchNttForwardCenteredLimbFromWarpStages712ForTest(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        const u32* limbSel,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        bool warpStages712,
        void* stream,
        bool& launched);

    bool launchNttInverse(
        const RingConstView& rc, u64* data, u32 polyCount, const u32* polyIdx, void* stream);

    // "no fused operation" for the two hooks below.
    constexpr u32 kElemOpNoneHost = 0xFFFFFFFFu;

    // The inner product that feeds the inverse transform, folded into the
    // transform's *load*, replacing a launchInnerProduct that would write a full
    // polynomial array only for the transform to read it straight back.
    //
    // With mTerms != 0 the transform computes, for its own (polynomial, limb),
    //     sum_k A[mAIdx[slot*mTerms+k]] * B[mBIdx[slot*mTerms+k]]   (mod q)
    // using the same mulAddMod accumulation in the same order as
    // innerProductKernel, so the value handed to the transform is bit-identical to
    // what the separate kernel would have stored. mMode mirrors
    // launchInnerProduct's flags: Replace ignores the destination, Accumulate gives
    // dst + sum, Subtract gives dst - sum.
    //
    // Traffic: the pair costs terms reads plus one write instead of terms reads, a
    // write, a read and a write - two polynomials less per output.
    //
    // Deliberately holds *one* inner product, not a chain. Folding the expand's
    // other two accumulator writes in as well was tried and measured slower,
    // 167.2 against 170.4 M/s: the transform is 1024 threads on 64 KiB of shared
    // memory, so one block per SM, and a scattered gather there has no second
    // block to hide its latency behind. innerProductKernel's 256-thread blocks run
    // at high occupancy and absorb it. Folding pays only when it also removes a
    // write and a read of a whole polynomial array, which is the case for the
    // transform's own operand and not for the others.
    struct NttFusedIp
    {
        enum Mode : u32
        {
            Replace = 0,
            Accumulate = 1,
            Subtract = 2
        };

        const u64* mA = nullptr;
        const u64* mB = nullptr;
        const u32* mAIdx = nullptr;
        const u32* mBIdx = nullptr;
        u32 mTerms = 0;
        u32 mMode = Replace;
    };

    // False when LOGVOLE_GPU_FUSED_IP=0 asks for the unfused two-kernel path.
    bool gpuFusedIpActive();

    // Inverse NTT with one elementwise operation folded into the shared-memory
    // load and one into the store:
    //     sh  = preOp(data, preB)      then transform then
    //     out = postOp(result, postB)
    // preOp/postOp take ElemOp values (Add/Sub, plus Negate for postOp) or
    // kElemOpNoneHost. preB/postB are full polynomial arrays indexed like `data`.
    //
    // The transform already streams every coefficient through shared memory, so a
    // folded operation costs one extra global read; the separate elementwise
    // kernel it replaces cost two reads and a write over the whole array. Results
    // are bit-identical to running the two kernels in sequence.
    bool launchNttInverseFused(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* polyIdx,
        u32 preOp,
        const u64* preB,
        u32 postOp,
        const u64* postB,
        void* stream,
        const NttFusedIp& ip = NttFusedIp{});

    // Backward-compatible alpha-aware overload. Only the three protocol paths
    // that carry a validated shrink/expand alpha pass `alphaIsTwo=true`; all
    // existing callers and the original ABI retain the accepted dispatch.
    bool launchNttInverseFused(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* polyIdx,
        u32 preOp,
        const u64* preB,
        u32 postOp,
        const u64* postB,
        void* stream,
        const NttFusedIp& ip,
        bool alphaIsTwo);

    // Same-binary Stage-110 oracle. `warpStages05=false` names the accepted
    // fused-last-three symbol; true names its S0--S5 warp-register sidecar and
    // additionally requires `alphaIsTwo`. Unsupported shapes, post operations,
    // pointers and launch counts are soft declines with no write.
    bool tryLaunchNttInversePostWarpStages05ForTest(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* polyIdx,
        u32 postOp,
        const u64* postB,
        bool warpStages05,
        bool alphaIsTwo,
        void* stream,
        bool& launched);

    // Exact fixed-N=8192/rho=4 IP -> inverse sidecars. Unsupported shapes are
    // not errors: they return true with `launched == false`, so callers retain
    // the existing indexed-IP and inverse launches as an exact fallback.
    bool tryLaunchNttInverseOuterMu4ReverseSub(
        const RingConstView& rc,
        u64* out,
        const u64* publicA,
        const u64* sk,
        u32 outCount,
        const u64* ct2,
        void* stream,
        bool& launched);

    bool tryLaunchNttInverseOuterMuReverseSub(
        const RingConstView& rc,
        u64* out,
        const u64* publicA,
        const u64* sk,
        u32 mu,
        u32 outCount,
        const u64* ct2,
        void* stream,
        bool& launched);

    // Exact fixed-N=8192/rho=4/mu=8-or-16 standalone sender outer product. The
    // implementation retains one chunk coefficient across all public-A rows;
    // unsupported/small shapes return with `launched == false`.
    bool tryLaunchInnerProductOuterMuRowReuse(
        const RingConstView& rc,
        const u64* publicA,
        const u64* skNtt,
        u64* out,
        u32 mu,
        u32 chunkCount,
        void* stream,
        bool& launched);

    // Default-on pseudo-55 row-reuse peer for mu=32/64/128. It is attempted
    // only for at least eight chunks; an explicit zero or any decline leaves the
    // existing indexed sender product as the exact fallback.
    bool tryLaunchInnerProductOuterWideMuRowReuse(
        const RingConstView& rc,
        const u64* publicA,
        const u64* skNtt,
        u64* out,
        u32 mu,
        u32 chunkCount,
        void* stream,
        bool& launched);

    bool tryLaunchNttInverseExpandAccumulatorTau1Add(
        const RingConstView& rc,
        u64* out,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 outCount,
        const u64* ct2,
        void* stream,
        bool& launched);

    bool tryLaunchNttInverseTreePairNegate(
        const RingConstView& rc,
        u64* out,
        const u64* publicB,
        const u64* nodes,
        u32 outCount,
        u32 depth,
        u32 nodeCount,
        u32 publicCol,
        void* stream,
        bool& launched);

    // Alpha-aware overload for the default-on Stage-112 product/S0 -> warp S1--S5
    // fusion. Only the protocol path with validated alpha=2 may pass true; the
    // original ABI above delegates false and retains the accepted Stage-104
    // dispatch exactly.
    bool tryLaunchNttInverseTreePairNegate(
        const RingConstView& rc,
        u64* out,
        const u64* publicB,
        const u64* nodes,
        u32 outCount,
        u32 depth,
        u32 nodeCount,
        u32 publicCol,
        void* stream,
        bool& launched,
        bool alphaIsTwo);

    // Fixed recursive-leaf diagonal -> inverse sidecar. One block owns one
    // logical leaf: it caches the selected NTT limb in `packed`, transforms the
    // selected left/right product with a zero-safe negate, and writes zero to
    // the complementary output limb. Unsupported/small shapes return with
    // `launched == false` so the indexed diagonal plus full inverse remains the
    // exact fallback.
    bool tryLaunchNttInverseRecursiveLeafSparseNegate(
        const RingConstView& rc,
        const u64* nodes,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* out,
        u32 logicalCount,
        void* stream,
        bool& launched);

    // Candidate producer for a mandatory sparse-pair gadget consumer. It is
    // identical to the accepted recursive-leaf sparse inverse for active limbs
    // and packed digits, but leaves each complementary zero limb unmaterialized.
    // A caller must not fall back to a dense four-limb consumer after launch.
    bool tryLaunchNttInverseRecursiveLeafSparseNegateNoZero(
        const RingConstView& rc,
        const u64* nodes,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* out,
        u32 logicalCount,
        void* stream,
        bool& launched);

    // ---- pointwise --------------------------------------------------------
    // out[i] = sum_{k<terms} A[aIdx[i*terms+k]] * B[bIdx[i*terms+k]] (mod q),
    // per RNS limb and coefficient. `accumulate` adds into the existing out,
    // `negate` stores the additive inverse (applied *after* accumulate, so the two
    // together give -(out + sum)). `subtract` overrides both and stores
    // out - sum, which is what lets a following elementwise subtraction be folded
    // in and its temporary dropped. Index arrays are device pointers; a null index
    // array means the identity mapping.
    bool launchInnerProduct(
        const RingConstView& rc,
        const u64* aBase,
        const u64* bBase,
        const u32* aIdx,
        const u32* bIdx,
        u32 terms,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        bool accumulate,
        bool negate,
        void* stream,
        bool subtract = false);

    // Test-only entry points for the accepted, default-on q=2^55-c pointwise reducer.
    // The production-shaped try launchers name either the untouched accepted
    // symbol or its candidate peer in the same binary. A structural decline is
    // reported as success with `launched == false`; once a kernel is committed,
    // a CUDA error is reported as failure with `launched == true` and callers
    // must never fall back.
    bool launchPointwisePseudo55ReduceWideForTest(
        const u64* lo,
        const u64* hi,
        u32 count,
        u64 q,
        u32 maxTerms,
        u64* residues,
        void* stream);

    bool tryLaunchInnerProductFixedIndexedPointwiseForTest(
        const RingConstView& rc,
        const u64* aBase,
        const u64* bBase,
        const u32* aIdx,
        const u32* bIdx,
        u32 terms,
        u64* out,
        u32 outCount,
        bool accumulate,
        bool subtract,
        bool usePseudo55,
        void* stream,
        bool& launched);

    // Forces either the untouched runtime kernel or the opt-in rolled
    // pseudo-55 candidate for an otherwise identical 8/10/12/14-term
    // Accumulate call. Unsupported shapes decline without launching.
    bool tryLaunchInnerProductPseudo55WideAccumulateForTest(
        const RingConstView& rc,
        const u64* aBase,
        const u64* bBase,
        const u32* aIdx,
        const u32* bIdx,
        u32 terms,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        bool accumulate,
        bool negate,
        bool subtract,
        bool useCandidate,
        void* stream,
        bool& launched);

    bool tryLaunchInnerProductOuterMuRowReusePointwiseForTest(
        const RingConstView& rc,
        const u64* publicA,
        const u64* skNtt,
        u64* out,
        u32 mu,
        u32 chunkCount,
        bool usePseudo55,
        void* stream,
        bool& launched);

    // Test-only default-switch bypass for the distinct mu=32/64/128 pseudo-55
    // row-reuse symbols. Invalid metadata is a pure decline.
    bool tryLaunchInnerProductOuterWideMuRowReusePseudo55ForTest(
        const RingConstView& rc,
        const u64* publicA,
        const u64* skNtt,
        u64* out,
        u32 mu,
        u32 chunkCount,
        void* stream,
        bool& launched);

    bool tryLaunchNttInverseTreePairNegatePointwiseForTest(
        const RingConstView& rc,
        u64* out,
        const u64* publicB,
        const u64* nodes,
        u32 outCount,
        u32 depth,
        u32 nodeCount,
        u32 publicCol,
        bool usePseudo55,
        bool useWarpStages,
        void* stream,
        bool& launched);

    // Same-binary Stage-112 oracle. `productWarpStages05=false` names the
    // Stage-104 rollback; true names the direct product/S0 -> S5 path (and its
    // default vector-pair successor) and additionally requires alphaIsTwo.
    // Invalid shape, metadata, pointers, aliases, or alpha provenance are pure
    // declines with no write.
    bool tryLaunchNttInverseTreePairNegateProductWarpStages05ForTest(
        const RingConstView& rc,
        u64* out,
        const u64* publicB,
        const u64* nodes,
        u32 outCount,
        u32 depth,
        u32 nodeCount,
        u32 publicCol,
        bool productWarpStages05,
        bool alphaIsTwo,
        void* stream,
        bool& launched);

    bool tryLaunchNttInverseRecursiveLeafSparseNoZeroPointwiseForTest(
        const RingConstView& rc,
        const u64* nodes,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* out,
        u32 logicalCount,
        bool usePseudo55,
        void* stream,
        bool& launched);

    // Reports whether the tauHi=1 receiver can skip its first two pointwise
    // passes and commit to launchExpandAccumulatorTau1. Six-term shapes retain
    // the established runtime fallback. Wider shapes require an exact supported
    // tuple and the default-on wide pseudo-55 switch (whose explicit zero is the
    // three-pass rollback).
    bool canLaunchExpandAccumulatorTau1(
        const RingConstView& rc,
        u32 mu,
        u32 treeTerms,
        u32 outCount);

    // Receiver-expand fast path for tauHi=1. In one 256-thread pass it computes,
    // per output polynomial,
    //
    //   ct1[row] * u[chunk] - publicA[row] * sk[chunk]
    //       + sum_{k<K} lacct[lacctAIdx[o*K+k]] * nodes[lacctBIdx[o*K+k]].
    //
    // K=6 retains the established runtime and accepted mu=8 specialization.
    // K=8/10/12/14 is accepted only for the matching benchmark alpha tuple.
    // This is exactly the three launchInnerProduct calls it replaces, but keeps
    // the accumulator in registers and removes two full read/write round trips.
    // `outCount` must equal chunkCount*mu.
    bool launchExpandAccumulatorTau1(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        void* stream);

    // Alpha-aware overload for the default-on Stage-111 fixed accumulator.
    // Only the receiver path with validated alpha=2 may pass true; the original
    // ABI above delegates false and therefore retains accepted dispatch.
    bool launchExpandAccumulatorTau1(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        void* stream,
        bool alphaIsTwo);

    // Same-binary Stage-111 oracle. `dual=false` names the unchanged accepted
    // fixed pseudo-55 symbol; true names the dual-carry sidecar and additionally
    // requires alphaIsTwo. Invalid metadata, counts, pointers and aliases are
    // soft declines (`launched == false`) with no write.
    bool tryLaunchExpandAccumulatorTau1GoldenPseudo55DualForTest(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        bool dual,
        bool alphaIsTwo,
        void* stream,
        bool& launched);

    // Bypasses the production wide switch and launches one of the exact
    // (mu,treeTerms)=(16,8),(32,10),(64,12),(128,14) pseudo-55 symbols. The
    // default-on LV_GPU_EXPAND_ACCUM_PSEUDO55_DUAL switch selects the dual-Wide
    // successor; with that path active, the default-on
    // LV_GPU_EXPAND_ACCUM_PSEUDO55_DUAL_PACKED_PAIRS switch selects its aligned
    // pointer-pair successor. Packed-pairs zero selects Stage 101, while dual
    // zero selects Stage 99 regardless of the packed setting. Invalid metadata
    // is a pure decline (`launched == false`).
    bool tryLaunchExpandAccumulatorTau1Pseudo55WideForTest(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        void* stream,
        bool& launched);

    // Focused exactness hook for the accepted production accumulator. This
    // bypasses all runtime experiment gates and always launches the adaptive
    // Q64 `<true,true>` symbol, allowing an opt-in test to compare it with the
    // production dispatch on an independent stream in the same process.
    bool launchExpandAccumulatorTau1GoldenAcceptedForTest(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u64* out,
        u32 outCount,
        void* stream);

    // out[i] = op(A[aIdx[i]], B[bIdx[i]]) with op in {add, sub}.
    enum class ElemOp : u32
    {
        Add = 0,
        Sub = 1,
        Negate = 2,
        Copy = 3,
        // Inverse-transform post-op only: postB - transformed value.
        ReverseSub = 4
    };

    bool launchElementwise(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        const u64* bBase,
        const u32* bIdx,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        ElemOp op,
        void* stream);

    // Multiply each selected polynomial by 2^(gadgetLogBase * power) mod q.
    bool launchScaleByPow2(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        const u64* factorsPerLimb, // device [rho], 2^shift mod q_j
        void* stream);

    // Reduce every coefficient modulo its limb modulus (mirrors
    // canonicalizePoly / modulo_poly_coeffs).
    bool launchCanonicalize(
        const RingConstView& rc, u64* data, const u32* polyIdx, u32 polyCount, void* stream);

    // ---- gadget decomposition --------------------------------------------
    // Shares the cached mode parser between ring setup and online dispatch.
    bool h200Fp52GadgetConstantsEnabled();
    bool h200Fp52GadgetPredivEnabled();
    // Setup-only; the caller owns 80 doubles and synchronizes before publishing
    // the ring. The online gadget only reads this immutable device allocation.
    bool launchPrepareH200Fp52GadgetConstants(
        const RingConstView& rc, double* out, void* stream, double* ratios = nullptr);

    // Mirrors gadgetDecomposeBitsRange (centered == false) and
    // gadgetDecomposeBitsRangeCentered (centered == true).
    // out layout: [inCount][levels] polynomials, i.e.
    // out[(i*levels + level)] holds digit `level` of input i.
    bool launchGadgetDecompose(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u32 inCount,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        bool centered,
        u64* out,
        const u32* outIdx,
        void* stream);

    // Opt-in fixed recursive-leaf sparse-parent decomposition. Input parent i
    // has active CRT limbs {0,1} when i is even and {2,3} when i is odd. Input
    // is contiguous (there is deliberately no inIdx); outIdx remains an
    // arbitrary unique scatter. The output is a complete dense rho4 polynomial.
    bool canLaunchGadgetDecomposeHi110RecursiveLeafSparsePair(
        const RingConstView& rc,
        const u64* in,
        u32 parentCount,
        const u64* out);

    // Explicit/direct launch after `canLaunch` has committed the protocol, or
    // for the focused oracle. It revalidates geometry and pointers but does not
    // re-read the candidate's own opt-in toggle.
    bool launchGadgetDecomposeHi110RecursiveLeafSparsePair(
        const RingConstView& rc,
        const u64* in,
        u32 parentCount,
        u64* out,
        const u32* outIdx,
        void* stream);

    // Same-binary Stage-89 arithmetic and production-shaped launchers. The raw
    // entry point returns false without writing for an unsupported q. The two
    // try-launch APIs soft-decline unsupported metadata before launch and set
    // `launched` as soon as either accepted or candidate work is committed.
    bool launchGadgetReduceMagnitude110Pseudo55ForTest(
        const u64* magLo,
        const u64* magHi,
        u32 count,
        u64 q,
        u64* residues,
        void* stream);

    bool tryLaunchGadgetDecomposeHi110Pseudo55ForTest(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u32 inCount,
        u64* out,
        const u32* outIdx,
        bool pseudo55SecondFold,
        void* stream,
        bool& launched);

    bool tryLaunchGadgetDecomposeHi110RecursiveLeafSparsePairPseudo55ForTest(
        const RingConstView& rc,
        const u64* in,
        u32 parentCount,
        u64* out,
        const u32* outIdx,
        bool pseudo55SecondFold,
        void* stream,
        bool& launched);

    // Exact seed-label repetition/projection, including noncanonical input
    // words. gammaOne repeats input[0]; otherwise outputs cycle through
    // (input digit, selected RNS limb). No modular arithmetic is applied.
    bool launchSeedLabelRep(const RingConstView& rc, const u64* input,
        u64* output, u32 tau, u32 count, bool gammaOne, void* stream);

    // ---- CRT helpers ------------------------------------------------------
    // Mirrors selectAndScaleLimbNtt: zero everything except limb `limbIdx`,
    // which is multiplied by scale[limbIdx]. limbSel is a device array of
    // per-output limb indices.
    bool launchSelectScaleLimb(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        const u32* limbSel,
        const u64* scalePerLimb,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        void* stream);

    // Mirrors decomposeRecursiveLeafSingleDigitNtt's pre-NTT part: take limb
    // `limbSel[i]` of the input, multiply by invScale[limb], centre it around
    // zero, then broadcast the centred value to every limb.
    bool launchLiftCenteredLimb(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        const u32* limbSel,
        const u64* invScalePerLimb,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        void* stream);

    // Dense q0 coefficients, centered and expanded into full RNS polynomials.
    // Source and destination must be disjoint; no selector or scale arrays.
    bool launchExpandCenteredCompact(
        const RingConstView& rc, const u64* compactQ0, u64* out,
        u32 outCount, void* stream);

    // Constant slots, or complete triples followed by zero-valued tail slots.
    // Small deltas travel as kernel parameters; no host slot array is needed.
    bool launchPrepareDeltaSlots(u64 delta0, u64 delta1, u64 delta2,
        u32 slotCount, bool garbled, u64* out, void* stream);

    // Equal plaintext slots encode as the constant polynomial delta. Write its
    // CRT lift directly, including every zero coefficient, without a slot NTT.
    bool launchPrepareConstantDelta(const RingConstView& rc, u64 delta,
        const u64* liftModQ, u64* out, void* stream);

    // Mirrors recursiveLeafPairInnerProductNttToStd (LogVoleLenc.cpp).
    bool launchLeafPairScaled(
        const RingConstView& rc,
        const u64* leftB,
        const u64* rightB,
        const u64* digits,
        const u32* leftIdx,
        const u32* rightIdx,
        const u32* leftLimb,
        const u32* rightLimb,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        void* stream);

    // Consumes the diagonal limbs of compact recursive leaf nodes once. It
    // caches NTT(hiDigits) back into `packed` and writes the only nonzero limb
    // of each leaf-pair product into `parent`. The fixed rho4 self-zero mode
    // also initializes the complementary limb owned by each sibling.
    bool launchRecursiveLeafDiagonal(
        const RingConstView& rc,
        const u64* nodes,
        const u32* nodeIdx,
        const u32* parentAndSide,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* parent,
        u32 logicalCount,
        bool selfZeroRho4,
        void* stream);

    // ---- denoise ----------------------------------------------------------
    // Mirrors shrinkExpandDenoiseComb: rho consecutive input polynomials
    // produce one output polynomial.
    struct DenoiseConstView
    {
        const u64* mQ = nullptr;                 // [rho] moduli values
        const void* mMods = nullptr;             // [rho] GpuModulus
        const u32* mSrcLimb = nullptr;           // [rho][rho-1]
        const u64* mCrtInvPunctured = nullptr;   // [rho][rho-1]
        const u64* mPuncturedProdModTarget = nullptr; // [rho][rho-1]
        const void* mCrtInvPuncturedShoup = nullptr; // [rho][rho-1] ShoupOperand
        const void* mScaledPuncturedShoup = nullptr; // [rho][rho-1] P*inv(lift), ShoupOperand
        const u64* mFracInvLo = nullptr;         // [rho][rho-1] low word of 2^128/q_w
        const u64* mFracInvHi = nullptr;         // [rho][rho-1] high word
        const u64* mCrtLiftModTarget = nullptr;  // [rho]
        const u64* mInvCrtLiftModTarget = nullptr;// [rho]
        const void* mInvCrtLiftShoup = nullptr;  // [rho] ShoupOperand
    };

    // Raw setup writes into newly allocated, unpublished constant views.
    // scratch has 3*rho u64 words; status is one u32, zeroed by this launcher.
    // A nonzero status after stream completion rejects a composite prime or a
    // failed primitive-root search. Callers must drain before publication/free.
    bool launchPrepareRawNttTables(const RingConstView& rc, const u64* primes,
        u64* scratch, u32* status, void* stream);
    bool launchPrepareRawCrtConstants(const RingConstView& rc,
        const DenoiseConstView& dc, u64* crtLift, u64* invCrtLift,
        u64* sampleMaxMultiple, const u32* status, void* stream);
    bool launchPrepareRawSlotMaps(u32 n, u32* slotMap, u32* inverseSlotMap, void* stream);
    // Match SEAL 4.1.1 CoeffModulus::Create's descending get_primes search and
    // reverse placement within each equal-bit group. A nonzero status declines
    // before any caller publishes the small host metadata copy.
    bool launchSelectSealCoeffModuli(u32 n, const int* bits, u32 rho,
        u64* orderedPrimes, u32* status, void* stream);
    // Match PlainModulus::Batching's first prime for each attempted bit width;
    // the caller's p < min(q) rule advances to the next smaller width.
    bool launchSelectSealPlainModulus(u32 n, u32 requestedBits, u64 minimumQ,
        u64* selectedPrime, u32* selectedBits, u32* status, void* stream);
    // Compute floor(prod(q)/p) mod every q_j from device CRT base-product state.
    bool launchPreparePlaintextLift(const RingConstView& rc, u64 plaintextPrime,
        u64* residues, u32* status, void* stream);
    // One ordered stream pipeline for a private native-SEAL bundle. All
    // producer/consumer operands and five independent stage statuses stay on
    // device until its caller copies one final metadata record. Views must
    // point into unpublished, role-owned storage; their host min/max fields
    // are filled only after successful publication.
    bool launchNativeSealSetupBundle(const RingConstView& ring,
        const DenoiseConstView& denoise, const RingConstView& plain,
        const int* coefficientBits, u32 coefficientCount,
        u32 requestedPlaintextBits,
        u64* orderedQ, u64* selectedP, u32* selectedBits, u64* plaintextLift,
        u32* fiveStatuses, u64* ringScratch, u64* plainScratch,
        u64* crtLift, u64* inverseCrtLift, u64* sampleMaxMultiple,
        u32* slotMap, u32* inverseSlotMap, void* stream);
    bool launchPreparePow2Factors(const RingConstView& rc, u32 shiftBits,
        u64* factors, void* stream);
    bool launchPrepareScaleRoundConstants(const RingConstView& rc, u64 plaintextModulus,
        const ScaleRoundConstView& out, void* stream);

    bool launchDenoiseComb(
        const RingConstView& rc,
        const DenoiseConstView& dc,
        const u64* in,
        u64* out,
        u32 outCount,
        void* stream);

    // The GoldenSeed predicate for input polynomial o*rho+j targets limb j
    // whenever mu is divisible by rho. Denoise already reconstructs the exact
    // wrapped 128-bit fraction used by that predicate, so this specialization
    // records failures while producing the ordinary denoised output. The flag is
    // accumulated (never cleared here), and a prior failure must not suppress the
    // denoise stores needed by the levels above.
    bool launchDenoiseCombValidate(
        const RingConstView& rc,
        const DenoiseConstView& dc,
        const u64* in,
        u64* out,
        u32 outCount,
        const u64* marginLo,     // [rho]
        const u64* marginHi,     // [rho]
        u32* failFlag,
        void* stream);

    // Mirrors validateGoldenSeedCandidate's rounding predicate. Reuses the
    // denoise CRT constants (they are the same punctured-product inverses and
    // 2^128/q_w reciprocals) and adds the per-limb margins. Writes 1 into
    // `failFlag` if any coefficient of any polynomial is too close to a
    // rounding boundary.
    bool launchValidateGoldenSeed(
        const RingConstView& rc,
        const DenoiseConstView& dc,
        const u64* tbk,
        u32 polyCount,
        u32 mu,
        const u64* marginLo,     // [rho]
        const u64* marginHi,     // [rho]
        u32* failFlag,
        void* stream);

    // Final Q/p predicate over the logical prefix, with p folded into each
    // full-CRT inverse. Accumulates into the same flag as intermediate checks.
    bool launchValidateLeafGoldenSeed(
        const RingConstView& rc,
        const LeafGoldenSeedLimb* constants,
        const u64* tbk,
        u32 logicalPolyCount,
        u64 marginLo,
        u64 marginHi,
        u32* failFlag,
        void* stream);

    // out[i] = sum_{j<tau} in[i*tau + j] mod q, mirroring seedLabelAgg.
    bool launchAggregate(
        const RingConstView& rc,
        const u64* in,
        u32 tau,
        u64* out,
        u32 outCount,
        void* stream);

    // Mirrors the unscaled unwrap branch: canonicalize each RNS residue,
    // compose its representative in [0,Q), then reduce that integer modulo
    // the plaintext prime. Both CRT and plaintext modulus tables stay on the
    // owning party's device; out holds inCount * N plaintext coefficients.
    bool launchComposeReducePlain(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64* out,
        void* stream);

    // Mirrors the scaleAndRound branch of unwrapRingLabelsCrt. Produces
    // inCount * N plaintext coefficients modulo plainModulus.
    bool launchScaleAndRound(
        const RingConstView& rc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const u64* crtInvPunctured,
        const u64* qValues,
        const u64* pShoup,
        const u64* fracInvLo,
        const u64* fracInvHi,
        const ScaleRoundFastLimb* fastLimbs,
        u64* out,
        void* stream);

    // Fixed hot unwrap: scale N=8192/rho=4 RNS coefficients into the
    // plaintext modulus, run its one-limb forward NTT in shared memory, and
    // publish BatchEncoder slots directly. The predicate and launcher share
    // the same structural/environment eligibility checks so callers can omit
    // the otherwise mandatory chunk*N coefficient scratch allocation.
    bool canLaunchScaleNttForwardGather(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        u32 slotCount,
        u64* out,
        u64 outCount);
    bool launchScaleNttForwardGather(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        const u32* slotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        void* stream);

    // Alpha-aware overload for the default-off Stage-113 S7--S12 warp
    // sidecar. Only state-aware protocol paths with validated alpha=2 pass
    // true. The original ABI above delegates false and therefore always keeps
    // the accepted slot-owned transform.
    bool launchScaleNttForwardGather(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        const u32* slotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        void* stream,
        bool alphaIsTwo);

    // Exactness hook for the fixed N=8192/rho=4 high-carry fusion. Launches
    // either ownership variant irrespective of its runtime experiment switch.
    bool launchScaleNttForwardGatherHiCarryForTest(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        const u32* slotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        bool slotOwned,
        void* stream);

    // Same-binary Stage-113 oracle launcher. `warpStages712=false` names the
    // accepted slot-owned symbol; true names the S7--S12 register sidecar and
    // additionally requires alphaIsTwo. Invalid metadata, pointers, aliases,
    // counts, or alpha provenance are pure declines with no write.
    bool tryLaunchScaleNttForwardGatherWarpStages712ForTest(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        const u32* slotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        bool warpStages712,
        bool alphaIsTwo,
        void* stream,
        bool& launched);

    // Mirrors the slot-permutation loop at the end of
    // seal::BatchEncoder::decode, applied to `chunkCount` transformed
    // plaintexts at once:
    //   out[c * slotCount + i] = plain[c * n + slotMap[i]]
    // Writes are clipped at `outCount` so the last chunk can be partial.
    bool launchGatherSlots(
        const u64* plain,
        u32 n,
        const u32* slotMap,
        u32 slotCount,
        u32 chunkCount,
        u64* out,
        u64 outCount,
        void* stream);

    // Inverse of launchGatherSlots, mirroring seal::BatchEncoder::encode's
    // scatter: plain[c * n + slotMap[i]] = labels[c * slotCount + i], with
    // padValue past labelCount.
    bool launchScatterSlots(
        const u64* labels,
        u64 labelCount,
        u64 padValue,
        const u32* slotMap,
        u32 slotCount,
        u32 chunkCount,
        u64* plain,
        u32 n,
        void* stream,
        bool garbledInput = false);

    // Materialized reference for the fused garbled-input load path.
    bool launchRepeatGarbledInputs(const u64* labels, u64 count, u32 n,
        u32 chunks, u64* out, void* stream);

    // True when the plaintext transform fits in one shared-memory tile and can
    // therefore consume scattered slots and publish the broadcast ring limbs
    // without materialising an intermediate plaintext polynomial batch.
    bool canLaunchNttInverseScatterBroadcast(
        const RingConstView& plainRc, const RingConstView& ringRc);

    // Fuses the common (unscaled) wrap chain
    //
    //   scatter slots -> plaintext inverse NTT -> broadcast to every RNS limb
    //
    // into one kernel. inverseSlotMap[k] is the slot whose value legacy scatter
    // would place at plaintext coefficient k. The final chunk is filled with
    // padValue past labelCount. Only one-tile plaintext transforms are accepted;
    // callers retain the materialised chain for larger degrees and Delta lifts.
    bool launchNttInverseScatterBroadcast(
        const RingConstView& plainRc,
        const RingConstView& ringRc,
        const u64* labels,
        u64 labelCount,
        u64 padValue,
        const u32* inverseSlotMap,
        u32 chunkCount,
        u64* out,
        void* stream,
        bool garbledInput = false);

    // Compact protocol representation. It preserves the plaintext inverse
    // exactly but writes each canonical coefficient only to ring limb 0. The
    // matching forward launcher above broadcasts that immutable source on load.
    bool canLaunchNttInverseScatterSingleLimb(
        const RingConstView& plainRc, const RingConstView& ringRc);
    bool launchNttInverseScatterSingleLimb(
        const RingConstView& plainRc,
        const RingConstView& ringRc,
        const u64* labels,
        u64 labelCount,
        u64 padValue,
        const u32* inverseSlotMap,
        u32 chunkCount,
        u64* out,
        void* stream,
        bool garbledInput = false);

    // Restore the ordinary full-RNS logical representation in place when a
    // single-limb plaintext broadcast reaches a consumer other than the exact
    // identity-forward path.
    bool launchMaterializePlainBroadcast(
        const RingConstView& rc, u64* data, u32 polyCount, void* stream);

    // Mirrors encodeSlotsToRingCrt: broadcast n plaintext coefficients to all
    // rho limbs of an RnsPoly. liftModQ == null copies; otherwise each limb is
    // multiplied by liftModQ[limb] (the Delta lift).
    bool launchLiftPlainToRing(
        const RingConstView& rc,
        const u64* plain,
        u32 chunkCount,
        const u64* liftModQ,
        u64* out,
        void* stream);

    // ---- pseudorandom sampling -------------------------------------------
    // Blake2xb-based uniform polynomial sampling that matches SEAL's
    // sample_poly_uniform driven by seal::Blake2xbPRNG.
    //
    // seeds:      device array of outCount * 8 u64 (the SEAL prng seed per poly)
    // scratch:    device array of outCount * streamWords u64, streamWords >=
    //             rho*N + kSampleSlackWords
    // maxMultiple: device array of rho u64, precomputed as in
    //             sample_poly_uniform
    constexpr u32 kSampleSlackWords = 4096;

    // True when the sampler will take a non-materialized path, which generates
    // the Blake2xb stream in registers/shared memory and so needs no `scratch` at
    // all: callers use this to skip the outCount * streamWords staging buffer
    // (540 MB at n = 2^24) and pass a null scratch pointer.
    bool gpuFusedSamplerActive(u32 n, u32 streamWords, u32 outCount);

    // True when the non-materialized path splits each polynomial across
    // independent 2,048-word CTAs. This route needs the persistent rejection
    // epochs even though it does not need the materialized stream.
    bool gpuTiledSamplerActive(u32 n, u32 streamWords, u32 outCount);

    // True when the selected non-materialized sampler publishes rare rejection
    // epochs and follows its common kernel with the exact cold replay. Callers use
    // this to reserve/advance the persistent per-polynomial epoch array without
    // allocating the otherwise-unused materialized stream.
    bool gpuFusedSamplerNeedsRejectEpoch(u32 n, u32 streamWords, u32 outCount);

    // True when the materialized sampler replaces its full-polynomial fixup
    // scan with reduce-time detection and an epoch-gated rare repair pass.
    bool gpuRejectReduceFusionActive();

    // Device replacement for the per-chunk ct2 seed derivation:
    //   ct2Seed_c = deriveSeedInstanceBlockFromDigestHash(
    //                   seed, sid, digestHash, instanceBase + c, mu)
    //   sealSeed  = sealSeedFromBlock(RO(label|ct2Seed|domainTag|row|N|rho))
    //
    // `prefix` is a device array of 9 u64 holding the random-oracle message with
    // slot 3 reserved for the per-chunk instance index:
    //   label, sid, fallbackNonce, -, seedSize, digestHash.lo, digestHash.hi,
    //   seed[0], seed[1]
    // and requires the golden seed to be 16 bytes. `ct2Scratch` needs
    // 2*chunkCount u64, `outSeeds` needs 8*chunkCount*mu u64.
    // Measurement hooks that settle "would an AES-CTR PRG beat Blake2xb here?".
    // Both fill `streamCount` independent streams of `wordsPerStream` u64 from a
    // 16-byte seed each. Only used by -lvgpu; the protocol's ct2 bytes are
    // defined by SEAL's sample_poly_uniform.
    bool launchAesCtrStreamForTest(
        const u64* seeds, u64* out, u32 wordsPerStream, u32 streamCount, void* stream);

    // Exact cryptoTools PRNG(seed).get<u64>() % modulus, starting at counter
    // zero. The seed is two device u64 words; odd scalar counts are supported.
    bool launchAesCtrScalars(
        const u64* seed, u64* out, u64 count, u64 modulus, void* stream);
    bool launchBlake2xbStreamForTest(
        const u64* seeds, u64* out, u32 wordsPerStream, u32 streamCount, void* stream);

    // Focused AES schedule equivalence hook. `keys` is count consecutive
    // little-endian 128-bit keys, `roundKeys` receives count*176 bytes, and
    // `outSeeds` receives AES_key(counter=0..3) as count*8 u64. The Boolean
    // selects the shared-S-box/vector-store schedule directly, bypassing its
    // production dispatch gate so tests can compare both implementations in
    // one process.
    bool launchAes128ExpandAndEncryptForTest(
        const u64* keys,
        u32 count,
        unsigned char* roundKeys,
        u64* outSeeds,
        bool sharedVectorExpand,
        void* stream);

    // Exact hashSeedDigest RandomOracle(16) over label, size and coefficients.
    bool launchRootDigestHash(
        const u64* words, u32 count, u64* out, void* stream);

    // Root randomizer sampler for N=8192, rho=4, g=110. `taskSeeds` contains
    // exactly 3*rangesPerPoly cryptoTools AES-CTR keys in [poly][range] order;
    // scratch sizes are (3*rangesPerPoly)*176 bytes / u32 flags respectively.
    // Output is three coefficient-domain RNS polynomials. The common path
    // consumes AES counter `coefficientWithinRange`; a first-reject marker
    // gates an exact ordered replay of the affected stream.
    bool launchRootZetaRho4(
        const RingConstView& rc,
        const u64* taskSeeds,
        unsigned char* roundKeys,
        u32* firstReject,
        u64* out,
        u32 rangesPerPoly,
        bool forceFirstReject,
        void* stream);

    // NoGoldenSeed N=16384, rho=8, g=208 counterpart. Three polynomials,
    // 2..32 independently keyed ranges each; two AES blocks per 209-bit draw.
    // Scratch sizes are (3*rangesPerPoly)*176 bytes / u32 flags respectively.
    bool launchRootZetaRho8(
        const RingConstView& rc,
        const u64* taskSeeds,
        unsigned char* roundKeys,
        u32* firstReject,
        u64* out,
        u32 rangesPerPoly,
        bool forceFirstReject,
        void* stream);

    // Raw-draw oracle hook: masks each four-word draw to 209 bits, writes a
    // rejection flag, and leaves rejected output coefficients untouched.
    bool launchRootZetaRho8RawForTest(
        const RingConstView& rc, const u64* rawWords, u32 count,
        u32* rejected, u64* out, void* stream);

    bool launchCt2Seeds(
        const u64* prefix,
        u64 instanceBase,
        u32 chunkCount,
        u32 mu,
        u64 domainTag,
        u32 polyModulusDegree,
        u64 modulusCount,
        u64* ct2Scratch,
        u64* outSeeds,
        unsigned char* roundKeyScratch,
        void* stream);

    // Second half of the above on its own: for each of `seedCount` 16-byte seeds
    // and each index in [0, perSeedCount), derive
    //   sealSeedFromBlock(RO(label | seed | domainTag | index | N | rho))
    // which is exactly deriveUniformPolyFromSeed's seed derivation. `outSeeds`
    // needs 8 * seedCount * perSeedCount u64.
    bool launchPolySeeds(
        const u64* seeds,
        u32 seedCount,
        u32 perSeedCount,
        u64 domainTag,
        u32 polyModulusDegree,
        u64 modulusCount,
        u64* outSeeds,
        unsigned char* roundKeyScratch,
        void* stream);

    // Direct arithmetic oracle for the candidate q=2^55-c sampler fold. Each
    // input word produces its canonical residue and one exact SEAL-default
    // rejection bit. The launcher accepts only 0<c<2^21.
    bool launchSampleUniformPseudo55ReduceWordForTest(
        const u64* words,
        u32 count,
        u64 q,
        u64* residues,
        u32* rejected,
        void* stream);

    // Isolated, opt-in launcher for the candidate pseudo-55 sampler symbols.
    // It is deliberately not part of production dispatch. `split64` selects
    // the accepted two-CTA ownership shape and therefore requires outCount=64.
    // A false default-threshold provenance bit soft-declines before any write.
    bool launchSampleUniformPolyBlake2xbPseudo55Candidate(
        const RingConstView& rc,
        const u64* seeds,
        u32 streamWords,
        const u64* maxMultiple,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        u32* rejectEpochs,
        u32 rejectEpoch,
        bool maxMultipleIsSealDefault,
        bool split64,
        void* stream);

    // Isolated launcher for the Stage-93 N=8192/rho=4 small-batch sidecar.
    // The production path accepts only the SEAL-default threshold provenance;
    // focused validation may explicitly opt into a custom threshold to force
    // rejection and exercise the same unbounded ordered-repair path. A false
    // result means either a preflight decline or a committed launch failure.
    bool launchSampleUniformPolyBlake2xbSmallDirectCandidate(
        const RingConstView& rc,
        const u64* seeds,
        u32 streamWords,
        const u64* maxMultiple,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        u32* rejectEpochs,
        u32 rejectEpoch,
        bool maxMultipleIsSealDefault,
        bool allowCustomThresholdForTest,
        void* stream);

    // `maxMultipleIsSealDefault` is provenance, not a value comparison. False
    // keeps custom/forced thresholds on the accepted sampler; true permits the
    // default-off pseudo55 preflight when every other production gate matches.
    bool launchSampleUniformPolyBlake2xb(
        const RingConstView& rc,
        const u64* seeds,
        u64* scratch,
        u32 streamWords,
        const u64* maxMultiple,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        u32* rejectEpochs,
        u32 rejectEpoch,
        bool maxMultipleIsSealDefault,
        void* stream);
}
