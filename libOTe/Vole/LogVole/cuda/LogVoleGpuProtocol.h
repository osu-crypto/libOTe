#pragma once

// GPU fast paths for the LogVole online phase.
//
// The digest tree is only 8 leaves wide and 3 levels deep, so a single chunk
// has nowhere near enough parallelism to fill a GPU. These entry points
// therefore work on *all* chunks of a recursion level at once and keep the node
// trees device resident between the shrink and the expand of that level.
//
// Every routine is a drop-in replacement for the corresponding CPU loop in
// LogVoleRingReceiver::online / evaluateSenderSeedCandidate
// and produces bit-identical results.

#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

#include <memory>
#include <array>
#include <span>
#include <string>
#include <vector>

namespace osuCrypto::LogVole
{
    // Defined in LogVole.h. Only referenced by reference here so that the CUDA
    // layer does not have to pull in the CI-VOLE API.
    struct ZpCrtContext;
}

namespace osuCrypto::LogVole::gpu
{
    class ReceiverFirstQueryAllocations;
    using ReceiverFirstQueryAllocationsPtr = std::shared_ptr<ReceiverFirstQueryAllocations>;

    // Opt-in receiver-only storage reserved while the same session's copied
    // offline TCP frames are received. The caller joins its worker before
    // publishing the finalized state. Every consumer checks this state's
    // identity, query SID, role, device, ordered ring primes and exact shape;
    // a miss takes the unchanged allocation path.
    ReceiverFirstQueryAllocationsPtr beginReceiverFirstQueryAllocations(const Params& params);
    void finishReceiverFirstQueryAllocations(const ReceiverFirstQueryAllocationsPtr& plan);
    bool sealReceiverFirstQueryAllocationOwner(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner);
    bool bindReceiverFirstQueryAllocations(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, u64 sid);
    void bindReceiverFirstQueryOnlineRun(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, u64 sid, u64 runId);
    // Narrow correctness-test observation only; never exposes owned pointers.
    bool receiverFirstQueryAllocationStatus(
        const ReceiverFirstQueryAllocationsPtr& plan,
        bool& ready, bool& wrapSelected, bool& nodesSelected);

    // Runtime switch. enabled() is false when no CUDA device is present.
    void setEnabled(bool on);
    bool enabled();
    std::string deviceDescription();

    // Prepare the immutable receiver offline mirror before making exact state
    // copies owned by one receiver. Success publishes a synchronized cache that
    // those receiver-local copies share; failure leaves the existing lazy
    // initialization path available. Only for finalized receiver setup states,
    // before concurrent online use.
    bool prepareReusableReceiverCache(ShrinkExpandReceiverState& state);
    // Finalize a fresh receiver package whose Ct1 is still in coefficient
    // domain. Public calls publish the same full host snapshot. Explicit
    // internal calls may retain immutable coefficient backing and materialize
    // host NTT only on demand. Encoded owners expose validated coefficient
    // payloads for direct upload into receiver-owned device buffers. On failure,
    // host coefficients, lazy owners and cache are unchanged.
    bool finalizeReceiverSetupDevice(
        const RingNttContext& ctx, ShrinkExpandReceiverState& state,
        bool deferHostSnapshot = false,
        std::shared_ptr<const LazyRingTensorHostState> encodedCt1 = {},
        std::shared_ptr<const LazyLacctHostState> encodedLacct = {});
    // Sender counterpart: share only within one sender's exact setup copies,
    // before concurrent online use.
    bool prepareReusableSenderCache(ShrinkExpandSenderState& state);
    bool lencRandomizerResidencyEnabled();

    // Device state that has to survive from a level's shrink to its expand.
    class LevelSession
    {
    public:
        LevelSession();
        ~LevelSession();
        LevelSession(const LevelSession&) = delete;
        LevelSession& operator=(const LevelSession&) = delete;

        bool valid() const;
        void reset();

        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    // A batch of polynomials that lives on the device. Passing these between
    // recursion levels is what keeps the tbk/dHat chains off the host; the
    // measured host round trip was the dominant cost of the online phase.
    class DeviceBatch
    {
    public:
        DeviceBatch();
        ~DeviceBatch();
        DeviceBatch(const DeviceBatch&) = delete;
        DeviceBatch& operator=(const DeviceBatch&) = delete;

        std::size_t count() const;
        bool empty() const;

        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    using DeviceBatchPtr = std::shared_ptr<DeviceBatch>;

    // Completed immutable public sampler output. Unlike DeviceBatch, this
    // handle is never accepted by a mutating device operation.
    class RetainedPublicUniform
    {
    public:
        RetainedPublicUniform();
        ~RetainedPublicUniform();
        RetainedPublicUniform(const RetainedPublicUniform&) = delete;
        RetainedPublicUniform& operator=(const RetainedPublicUniform&) = delete;
        std::size_t count() const;
        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };
    using RetainedPublicUniformPtr = std::shared_ptr<const RetainedPublicUniform>;

    bool publicUniformRetentionEnabled();
    // Register only the original captured host allocations moved directly into
    // a const owner. They must not have been modified after sampling. A copied
    // vector cannot register; lookup requires its live immutable owner, exact
    // full span, ring/moduli, device and protocol run. No borrowed host reads
    // occur after that owner expires. Missing entries use normal host uploads.
    bool registerPublicUniformRetention(const RingNttContext& ctx,
        const std::shared_ptr<const std::vector<RnsPoly>>& host,
        const RetainedPublicUniformPtr& captured);
    RetainedPublicUniformPtr findPublicUniformRetention(
        const RingNttContext& ctx, std::span<const RnsPoly> host);
    bool fetchRetainedPublicUniform(
        const RetainedPublicUniform& source, std::vector<RnsPoly>& out);
    // Validate a retained operand without touching host polynomial storage.
    // The token is scoped to its exact ring, protocol role/run and CUDA device;
    // outputNtt distinguishes legacy raw public A from transformed public B.
    bool retainedPublicUniformMatches(const RingNttContext& ctx,
        const RetainedPublicUniform& source, std::size_t expectedCount,
        bool outputNtt);
    // The sender's Root BStar is the nonce-derived, actual NTT batch sent on
    // the public Root wire. Its producer attaches the fixed nonce/domain before
    // publishing an immutable owner; consumers reject another public token.
    inline constexpr u64 kRootBStarNonce = 0x52544E43524F4F54ull;
    inline constexpr u64 kRootBStarDomain = 0xB57A52u;
    RetainedPublicUniformPtr retainRootBStarNttDevice(
        const RingNttContext& ctx, u32 count);
    bool retainedRootBStarNttMatches(const RingNttContext& ctx,
        const RetainedPublicUniform& source, std::size_t expectedCount);
    // Publish one immutable complete host snapshot. The first caller downloads
    // the synchronized device owner, or replays the already-consumed SEAL seeds
    // exactly if CUDA is unavailable. Failure leaves out unchanged.
    bool materializeRetainedPublicUniform(const RingNttContext& ctx,
        const RetainedPublicUniformPtr& source,
        std::shared_ptr<const std::vector<RnsPoly>>& out);
    struct PublicUniformRetentionStats
    {
        u64 mCaptures = 0;
        u64 mCopies = 0;
        u64 mCopiedBytes = 0;
        u64 mMisses = 0;
        u64 mHostMaterializations = 0;
        u64 mHostMaterializedBytes = 0;
    };
    PublicUniformRetentionStats publicUniformRetentionStats();

    // Repetition and RNS projection for sender setup. Publishes a complete
    // independent host snapshot only after the device work succeeds; input
    // and output may alias. Preserves every input bit (no canonicalization).
    bool seedLabelRepDevice(const RingNttContext& ctx, std::span<const RnsPoly> input,
        u32 gamma, u32 alpha, u32 tau, std::vector<RnsPoly>& out);
    // The private CI-VOLE delta stays in coefficient domain on this sender's
    // GPU while its exact seed-label replication is constructed. Only marked
    // producers may publish either owner; ordinary uploads cannot impersonate
    // them, and every consumer checks role/run/device/ordered ring/count.
    bool setupDeltaBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId);
    DeviceBatchPtr seedLabelRepResident(const RingNttContext& ctx,
        const DeviceBatch& delta, u32 gamma, u32 alpha, u32 tau);
    bool setupSeedLabelRepBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId);

    bool rootKPrimeSamplingEnabled();
    // Direct SEAL-seed replay. Publishes a coefficient-domain, synchronized
    // device polynomial; never consumes protocol PRNG state itself.
    bool sampleRootKPrimeDevice(const RingNttContext& ctx,
        const std::array<u64, 8>& seed, DeviceBatchPtr& out);

    bool rootDigestHashEnabled();
    bool hashRootDigestDevice(const DeviceBatch& digest, block& out);

    // A coefficient-domain ct2 batch sampled ahead of the sender's top
    // recursive expansion. The implementation owns both the device output and
    // the secondary-stream completion event. Keeping this opaque prevents a
    // caller from consuming the batch without the required cross-stream wait.
    class PreparedSenderCt2
    {
    public:
        PreparedSenderCt2();
        ~PreparedSenderCt2();
        PreparedSenderCt2(const PreparedSenderCt2&) = delete;
        PreparedSenderCt2& operator=(const PreparedSenderCt2&) = delete;

        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    using PreparedSenderCt2Ptr = std::unique_ptr<PreparedSenderCt2>;

    // A coefficient-domain ct2 batch sampled ahead of a receiver expansion.
    // This is separate from PreparedSenderCt2 because the state identity and
    // offline cache being validated belong to the opposite protocol role. The
    // owned event/output provide the same cross-stream lifetime guarantee.
    class PreparedReceiverCt2
    {
    public:
        PreparedReceiverCt2();
        ~PreparedReceiverCt2();
        PreparedReceiverCt2(const PreparedReceiverCt2&) = delete;
        PreparedReceiverCt2& operator=(const PreparedReceiverCt2&) = delete;

        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    using PreparedReceiverCt2Ptr = std::unique_ptr<PreparedReceiverCt2>;

    // Response-independent prefix of the receiver's Root finalization. The
    // implementation owns its device outputs and producer event so the Root
    // coroutine may suspend on the socket, resume on another thread/stream, or
    // unwind on a socket failure without leaving borrowed device work alive.
    class PreparedRootFinalize
    {
    public:
        PreparedRootFinalize();
        ~PreparedRootFinalize();
        PreparedRootFinalize(const PreparedRootFinalize&) = delete;
        PreparedRootFinalize& operator=(const PreparedRootFinalize&) = delete;

        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    using PreparedRootFinalizePtr = std::shared_ptr<PreparedRootFinalize>;

    // A flat device array of Z_p scalars, i.e. a VOLE output that was left on
    // the GPU for a downstream device-side consumer.
    class DeviceScalars
    {
    public:
        DeviceScalars() = default;
        ~DeviceScalars();
        DeviceScalars(const DeviceScalars&) = delete;
        DeviceScalars& operator=(const DeviceScalars&) = delete;

        bool resize(std::size_t count);
        u64* data() const { return mData; }
        std::size_t count() const { return mCount; }
        bool empty() const { return mCount == 0; }

        // Stream the contents were produced on. A consumer that may run on another
        // thread must order against this rather than assume stream ordering, since
        // threadStream() is thread-keyed. Lets the producer skip an eager drain.
        void* producerStream() const { return mProducerStream; }
        void setProducerStream(void* s) { mProducerStream = s; }

    private:
        u64* mData = nullptr;
        std::size_t mCount = 0;
        void* mProducerStream = nullptr;
    };

    using DeviceScalarsPtr = std::shared_ptr<DeviceScalars>;

    // Copies a device scalar array to the host. Provided so that callers who
    // asked to keep the output on the GPU can still read it when they need to.
    bool fetchScalars(const DeviceScalars& src, std::span<u64> dst);

    // Waits until a device scalar result is complete without copying it. This is
    // useful at a throughput boundary: returning a device handle is intentionally
    // asynchronous, but timing only command submission overstates sustained rate.
    bool waitScalars(DeviceScalars& src);

    // In-place forward/inverse negacyclic NTT of host-resident polynomials,
    // bit-identical to forwardNtt / inverseNtt.
    //
    // Used by the Root recursion level, which stays on the host because it is
    // only 8 polynomials wide. Even so a round trip beats SEAL: one 4-limb
    // polynomial is 256 KiB, so upload + kernel + download is roughly 55 us
    // against about 1.1 ms for the four ntt_negacyclic_harvey calls. Returns
    // false if the GPU is unavailable, in which case the caller runs on the CPU.
    // Drain the calling thread's stream. Needed when a device-resident result is
    // handed to a consumer that may not run on the same thread - after a coroutine
    // suspends on the socket it can resume elsewhere, and threadStream() is keyed on
    // the thread, so stream ordering alone no longer guarantees the data is ready.
    bool syncStream();

    bool nttHostBatch(const RingNttContext& ctx, std::span<RnsPoly> polys, bool inverse);
    // Optional full-u64 reduction before forward NTT, or canonical reduction
    // after inverse NTT, on the same device stream. Both overloads leave all
    // host inputs unchanged on failure; the three-argument API is unchanged.
    bool nttHostBatch(const RingNttContext& ctx, std::span<RnsPoly> polys,
        bool inverse, bool canonicalizeOnDevice);

    // Expand canonical compact Gaussian q0 samples on device. Centered
    // magnitudes must be smaller than every modulus (validated by the sampler).
    // Required host state is downloaded after optional NTT; out is atomic on failure.
    bool expandErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out);
    bool expandErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 requestedWorkers);
    bool expandErrorCompactDevice(const RingNttContext& ctx,
        const DeviceScalars& compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 polyCount = 0);
    bool expandErrorCompactDevice(const RingNttContext& ctx,
        const DeviceScalars& compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 polyCount, u32 requestedWorkers);
    // Root-specific wrapper retains the root debug-decline control.
    bool expandRootErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out);
    bool expandRootErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 requestedWorkers);
    // Internal sender Root path: retain completed coefficient-domain r1 rows
    // on the owning party's GPU. Consumers copy the immutable rows before NTT.
    // The owner is bound to ring, Sender role, protocol run and CUDA device.
    DeviceBatchPtr expandRootErrorCompactToBatch(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, const DeviceScalars* deviceCompact,
        u32 polyCount);
    bool rootErrorBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount);
    // Private sender Root uniform secret. This form never enters the public
    // uniform retention registry and is completed before it crosses streams.
    DeviceBatchPtr sampleRootSecretUniformToDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> rowSeeds);
    bool rootSecretUniformBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        u64 ownerRunId, bool outputNtt = false);
    // Separate private top HE key provenance; no public-uniform registry entry.
    DeviceBatchPtr sampleTopSecretUniformToDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> rowSeeds);
    bool topSecretUniformBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        u64 ownerRunId);
    DeviceBatchPtr topSecretSeedLabelRepResident(const RingNttContext& ctx,
        const DeviceBatch& topSecret, u32 alpha, u32 tau);
    DeviceBatchPtr rootHiReplicateResident(const RingNttContext& ctx,
        const DeviceBatch& topSecret, u32 tauHi);
    bool rootHiRepBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId);
    bool setupLencInputBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId);

    // Root top ciphertexts: NTT(noise) - NTT(r1[row])*B[col], with
    // -2^(gadgetLogBase*(gadgetPowerOffset+col))*r2[row] on root B columns.
    // Host inputs/output stay unchanged on failure; noise may alias output.
    bool assembleRootTopCtDevice(
        const RingNttContext& ctx,
        std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt,
        std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt,
        u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs,
        std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0 = {});
    // Device compact inputs are completed, borrowed, immutable q0 matrices.
    // A source must be supplied on either host or device, never both.
    bool assembleRootTopCtDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt, std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt, u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs, std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0, const DeviceScalars* compactNoiseDevice);
    bool assembleRootTopCtDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt, std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt, u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs, std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0, const DeviceScalars* compactNoiseDevice,
        u32 requestedWorkers,
        const LazyLencRandomizerState* randomizers = nullptr,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext = nullptr,
        const RetainedPublicUniform* retainedPublicBFullNtt = nullptr,
        const DeviceBatch* rootR1Device = nullptr,
        const RetainedPublicUniform* retainedBStarNtt = nullptr);

    // Assemble truncated LENC ciphertexts from exact host-sampled coefficient
    // noise and NTT operands. Host inputs/output are unchanged on failure, and
    // output is synchronized before publication. noiseCoeffs may alias outCtNtt.
    // With outFirstRNtt, randomizer layers and padded input are coefficient
    // batches: keep them on device through NTT and return only the first layer.
    // The two output vectors must be distinct.
    // Optional compactNoiseLimb0 replaces noiseCoeffs with count*N canonical
    // q0 values whose centered magnitudes are smaller than every RNS modulus.
    // compactRandomizerLimb0 similarly replaces the randomizer coefficient
    // storage (layer/width metadata remains); it requires outFirstRNtt.
    // devicePadding accepts the original nonempty coefficient input, at most
    // width polynomials, and zeros any device tail; it requires outFirstRNtt.
    bool assembleLencTruncDevice(
        const RingNttContext& ctx,
        const std::vector<std::vector<RnsPoly>>& rLayersNtt,
        std::span<const RnsPoly> sPadNtt,
        std::span<const RnsPoly> publicBNtt,
        u32 tauHi, u32 tauLeaf, u32 gadgetLogBase, bool gadgetLeaves,
        std::span<const u64> crtLiftModQj,
        std::span<const RnsPoly> noiseCoeffs,
        std::vector<RnsPoly>& outCtNtt,
        std::vector<RnsPoly>* outFirstRNtt = nullptr,
        std::span<const u64> compactNoiseLimb0 = {},
        std::span<const u64> compactRandomizerLimb0 = {},
        u32 requestedWorkers = 1,
        bool devicePadding = false);
    // The extended overload may publish a completed device owner instead of
    // host polynomials. On that success outCtNtt is empty; both outputs and the
    // optional owner remain unchanged on failure.
    // retainedRandomizers replaces the first-layer host output with exactly
    // retainedRandomizerCount immutable NTT polynomials. It requires
    // outFirstRNtt (cleared on success); gadget leaves must omit crtLiftModQj
    // in this internal mode because the ring supplies the exact GPU lift.
    // retainedPublicB replaces an empty host B span with the exact immutable
    // role/run/device-scoped public B owner.
    bool assembleLencTruncDevice(
        const RingNttContext& ctx, const std::vector<std::vector<RnsPoly>>& rLayersNtt,
        std::span<const RnsPoly> sPadNtt, std::span<const RnsPoly> publicBNtt,
        u32 tauHi, u32 tauLeaf, u32 gadgetLogBase, bool gadgetLeaves,
        std::span<const u64> crtLiftModQj, std::span<const RnsPoly> noiseCoeffs,
        std::vector<RnsPoly>& outCtNtt, std::vector<RnsPoly>* outFirstRNtt,
        std::span<const u64> compactNoiseLimb0, std::span<const u64> compactRandomizerLimb0,
        u32 requestedWorkers, bool devicePadding,
        const DeviceScalars* compactNoiseDevice, const DeviceScalars* compactRandomizerDevice,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext = nullptr,
        u32 retainedRandomizerCount = 0,
        std::shared_ptr<const LazyLencRandomizerState>* retainedRandomizers = nullptr,
        const RetainedPublicUniform* retainedPublicB = nullptr,
        const DeviceBatch* seedLabelDevice = nullptr);

    // LHE setup arithmetic, including canonicalization, required forward
    // transforms, gadget scaling and final inverse transforms. Optional compact
    // noise is count*N canonical q0 values, bounded for centered RNS broadcast;
    // it is lifted and added on device after the inverse transform. rPowerOffset is
    // zero for full LHE and one for the truncated variant. Host inputs/output
    // remain unchanged on failure; success publishes coefficient-domain output.
    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx,
        std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1,
        std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs,
        std::span<const u64> compactNoiseLimb0 = {});
    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1, std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs, std::span<const u64> compactNoiseLimb0,
        const DeviceScalars* compactNoiseDevice);
    // A requested deferred owner retains the completed coefficient tensor and
    // clears outCoeffs on success. All outputs remain unchanged on failure.
    // randomizers borrows a completed immutable NTT layer in place of an empty
    // r span. Its owner must survive the synchronized call.
    // retainedPublicA replaces an empty host A span with the exact immutable
    // role/run/device-scoped raw public A owner.
    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1, std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs, std::span<const u64> compactNoiseLimb0,
        const DeviceScalars* compactNoiseDevice, u32 requestedWorkers,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext = nullptr,
        const LazyLencRandomizerState* randomizers = nullptr,
        const RetainedPublicUniform* retainedPublicA = nullptr,
        const DeviceBatch* rootR1Device = nullptr,
        const DeviceBatch* rootSecretDevice = nullptr,
        u64 rootSecretOwnerRunId = 0,
        bool topSecretDomain = false);

    // GPU equivalent of gadgetDecomposeBitsRange{,Centered} for one host input
    // polynomial, producing `levels` host digit polynomials. Bit-identical: the
    // kernel is the one the chunk path already validates.
    //
    // Unlike an NTT, this is worth a round trip even for a single polynomial: the
    // work is 128/256-bit CRT compose per coefficient, so the arithmetic-to-bytes
    // ratio is high enough to cover the transfer. Measured in 5.2.11.
    bool gadgetDecomposeHost(
        const RingNttContext& ctx,
        const RnsPoly& in,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        bool centered,
        std::vector<RnsPoly>& out);

    // Exact setup sampling from already-consumed SEAL seeds. The opt-in gate
    // also checks that the configured SEAL factory uses Blake2xb. On failure,
    // out is unchanged and callers can replay the same seeds on the CPU.
    bool setupUniformSamplingEnabled();
    bool sampleUniformBatchFromSeedsDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> seeds,
        bool outputNtt,
        std::vector<RnsPoly>& out);
    bool sampleUniformBatchFromSeedsDevice(
        const RingNttContext& ctx, std::span<const std::array<u64, 8>> seeds,
        bool outputNtt, std::vector<RnsPoly>& out,
        RetainedPublicUniformPtr* captured);
    // Retained-only form: completes sampling/optional NTT and publishes a
    // device owner without a device-to-host copy. Seeds are copied into the
    // owner so an exact CPU fallback can be materialized later.
    bool retainUniformBatchFromSeedsDevice(
        const RingNttContext& ctx, std::span<const std::array<u64, 8>> seeds,
        bool outputNtt, RetainedPublicUniformPtr& out);

    // GPU equivalent of
    //   for i in [0, count): out[i] = deriveUniformPolyFromSeed(ctx, seed, tag, i)
    // i.e. deriveUniformPolyBatchFromSeed. Bit-identical: it reuses the same
    // random-oracle, AES seed expansion and SEAL-order rejection sampling that the
    // ct2 path already validates against buildHashedCt2.
    //
    // Worth the round trip because it is a batch: the host alternative is `count`
    // separate Blake2xb XOF streams through SEAL, about 0.26 ms each.
    bool deriveUniformPolyBatchDevice(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count,
        std::vector<RnsPoly>& out);

    // Copies a device batch back to host polynomials.
    bool download(const DeviceBatch& batch, std::vector<RnsPoly>& out, std::size_t count = 0);
    // Uploads host polynomials into a fresh device batch.
    DeviceBatchPtr upload(const RingNttContext& ctx, std::span<const RnsPoly> polys);

    // Batched equivalent of, for every chunk:
    //     shrinkExpandShrink(state, chunk, shrink)
    //     seedLabelGadgetDecomposeHiAndUnbundle(shrink.mDigest, ...)
    //
    // x is the level's full input (chunkCount * muHi polynomials, the tail is
    // zero padded internally). digests and dHatChunks are filled on the host;
    // the digest trees stay on the device inside `session`.
    bool shrinkChunks(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        u32 muHi,
        u32 tauHi,
        LevelSession& session,
        std::vector<RnsPoly>& digests,
        std::vector<std::vector<RnsPoly>>& dHatChunks);

    // Device-resident shrink. `xHost` or `xDev` supplies the level's input
    // (exactly one). The digests stay inside `session` and the child input is
    // returned as a device batch, so nothing crosses PCIe. `allowTilePipeline`
    // is supplied only by the outer recursive receiver frames; the backend still
    // enforces the opt-in switch and exact production geometry.
    // LV_GPU_RECEIVER_SHRINK_TILE_PIPELINE=1 enables the experiment;
    // LV_GPU_RECEIVER_SHRINK_TILES selects the bounded 2/4-way split (default 4).
    bool shrinkChunksDevice(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> xHost,
        const DeviceBatch* xDev,
        u32 xCount,
        u32 muHi,
        u32 tauHi,
        LevelSession& session,
        DeviceBatchPtr& dHat,
        bool allowTilePipeline = false,
        ReceiverFirstQueryAllocations* firstQueryAllocations = nullptr,
        const void* firstQueryOwner = nullptr, u64 firstQuerySid = 0);

    // Device equivalent of buildDigestTreeTrunc for a single chunk, with the tree
    // width supplied explicitly instead of taken from the level's accumulator.
    //
    // This exists for the Root's *left* digest tree, which is the same computation
    // a level's shrink performs but over `mRootLacctLeft`'s width and always with
    // gadget-digit leaves. On the host it was the largest single item in the Root:
    // 5.9 ms per query for a four-leaf tree, because it is a chain of transforms and
    // gadget decompositions on 256 KiB polynomials.
    //
    // `nodesFlat` receives the per-node NTT'd gadget digits in the layout
    // nodesFlat[node * maxTauOut + digit], node in [0, 2*widthPadded - 1), matching
    // DigestTree::mNodeDecompNtt. Bit-identical: these are the same kernels the
    // level ladder already validates against buildDigestTreeTrunc.
    // `sessionOut` keeps the tree in device memory (an opaque gpu::LevelSession) so
    // that rootFinalizeReceiverDevice can evaluate against it without the nodes
    // making a round trip.
    // `xDev`, when given, supplies the leaves from device memory and `x` is ignored.
    // `wantHostTree` false leaves `digest` and `nodesFlat` untouched and returns only
    // the device session, which is all the device key derivation needs.
    bool buildDigestTreeChunkDevice(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        const DeviceBatch* xDev,
        u32 widthPadded,
        u32 tauHi,
        bool leafInputsAreGadget,
        bool wantHostTree,
        u32& maxTauOut,
        RnsPoly& digest,
        std::vector<RnsPoly>& nodesFlat,
        std::shared_ptr<void>& sessionOut);

    // The arithmetic of finalizeRootResponseReceiver, entirely on the device.
    //
    // Runs lheApplyCt1Trunc, lheDec, evalRootTopCtNtt, lencEvalTrunc over the
    // device-resident left tree, buildHashedCt2, the row combine, the inverse
    // transform and denoise-plus-aggregate as one kernel sequence on one stream.
    // The Root's three offline tensors are uploaded once per ReceiverState and
    // cached in ReceiverState::mRootGpuCache; per query only dPrime, skPrime and
    // NTT(gadget(yLeft) ++ zeta) cross, and the key is returned device resident
    // because its only consumer is the device expand.
    //
    // Bit-identical to the host chain: every step is one of the kernels the level
    // path already validates, in the same order and with the same reductions.
    bool rootFinalizeReceiverDevice(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const RnsPoly& dPrime,
        block dPrimeHash,
        const RnsPoly& skPrime,
        const std::vector<RnsPoly>& topInputsNtt,
        const DeviceBatch* topInputsNttDev,
        const std::shared_ptr<void>& leftTreeSession,
        std::span<const u8> seed,
        u64 sid,
        u32 tauHi,
        u32 leftWidth,
        DeviceBatchPtr& rootKey,
        PreparedRootFinalize* prepared = nullptr,
        const DeviceBatch* dPrimeDevice = nullptr);

    // The default LV_GPU_ROOT_FINALIZE_PRIORITY_PREFETCH path uses a pre-created
    // Root cache stream at the device's greatest priority plus retained device
    // dPrime; set it to 0 for the monolithic rollback. It queues exactly the
    // response-independent prefix immediately after dPrime is sent and hands
    // readiness to the suffix through one event.
    // A false return may still leave `prepared` non-null: it owns partially
    // queued work for deferred, exception-safe cleanup while the caller runs
    // the unchanged monolithic fallback.
    bool rootFinalizeReceiverPrefetchEnabled();
    bool prefetchRootFinalizeReceiverDevice(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const RnsPoly& dPrime,
        const DeviceBatchPtr& topInputsNttDev,
        const std::shared_ptr<void>& leftTreeSession,
        u32 tauHi,
        u32 leftWidth,
        PreparedRootFinalizePtr& prepared,
        const DeviceBatchPtr& dPrimeDevice = {});

    // The digest step's arithmetic after the tree build, on the device:
    //   yDecomp   = centred gadget digits of the left tree's own digest
    //   inputsNtt = NTT(yDecomp ++ zeta)
    //   d'        = -INTT( publicB[1..tauHi] . inputsNtt + bStar . inputsNtt )
    //
    // yLeft never leaves the device - it is the tree's digest, which is already
    // there. Only zeta comes in (it is drawn from the host PRNG, whose stream has to
    // stay authoritative) and only d' goes out, because d' is what goes on the wire.
    // inputsNtt is handed back device resident for rootFinalizeReceiverDevice.
    bool rootDigestReceiverDevice(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const std::shared_ptr<void>& leftTreeSession,
        const std::vector<RnsPoly>& zeta,
        u32 tauHi,
        RnsPoly& negDPrime,
        DeviceBatchPtr& topInputsNtt,
        DeviceBatchPtr* negDPrimeDevice = nullptr);

    // Hot equivalent that never materializes zeta on the host. `taskSeeds` is
    // the exact [randomizer][rangesPerPoly] seed array already consumed from the
    // parent PRNG. On any failure the caller may replay those same seeds with
    // sampleRootZetaFromTaskSeeds and call rootDigestReceiverDevice above.
    bool rootDigestReceiverDeviceFromZetaSeeds(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const std::shared_ptr<void>& leftTreeSession,
        std::span<const block> taskSeeds,
        u32 rangesPerPoly,
        u32 tauHi,
        bool forceFirstReject,
        RnsPoly& negDPrime,
        DeviceBatchPtr& topInputsNtt,
        DeviceBatchPtr* negDPrimeDevice = nullptr);

    // Device-resident receiver expand. `skX` is one key per chunk on the device
    // and is consumed (transformed in place); the result is returned as a device
    // batch of `totalOut` polynomials.
    bool expandReceiverChunksDevice(
        const ShrinkExpandReceiverState& state,
        LevelSession& session,
        DeviceBatch& skX,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 outPerChunk,
        u32 totalOut,
        DeviceBatchPtr& tbm,
        PreparedReceiverCt2* preparedCt2 = nullptr);

    // Batched equivalent of, for every chunk:
    //     shrinkExpandExpandReceiver(state, expandInput, expandOutput)
    // reusing the digest trees held by `session`. Writes `totalOut`
    // polynomials, taking the first `outPerChunk` outputs of each chunk.
    bool expandReceiverChunks(
        const ShrinkExpandReceiverState& state,
        LevelSession& session,
        std::span<const RnsPoly> skX,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 outPerChunk,
        u32 totalOut,
        std::vector<RnsPoly>& tbm,
        PreparedReceiverCt2* preparedCt2 = nullptr);

    // Receiver counterpart to the sender prefetch scheduler. The measured
    // default selects three levels only for 2^24/2^25-label requests whose exact
    // tracked output-plus-scratch allocation is at most 2 GiB. Every other
    // request remains synchronous. LV_GPU_RECEIVER_CT2_PREFETCH=0 is the full
    // rollback, =1 forces the scheduler, and LEVELS selects 1..3 when enabled.
    // Request-dependent selection is evaluated per call, never cached.
    u32 receiverCt2PrefetchLevels(
        u64 totalLabelCount,
        std::span<const ShrinkExpandReceiverState* const> states,
        std::span<const u32> chunkCounts);
    bool prefetchReceiverCt2(
        const ShrinkExpandReceiverState& state,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 chunkCount,
        PreparedReceiverCt2Ptr& prepared);

    // Queue the top sender level's independent ct2 sampling on the role's
    // secondary stream before evaluating the recursive child. A dedicated
    // scratch lane and owned output/event keep it disjoint from every ordinary
    // sampleCt2Batch call. The caller supplies the request-size-dependent
    // default; LV_GPU_TOP_CT2_PREFETCH_LEVELS explicitly overrides it.
    // LV_GPU_TOP_CT2_PREFETCH=0 is the full scheduling rollback.
    bool topSenderCt2PrefetchEnabled();
    u32 topSenderCt2PrefetchLevels(u32 adaptiveDefault);
    bool prefetchSenderCt2(
        const ShrinkExpandSenderState& state,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 chunkCount,
        PreparedSenderCt2Ptr& prepared);

    // Batched equivalent of, for every chunk:
    //     shrinkExpandExpandSender(state, expandInput, expandOutput)
    //
    // tbkPrimeHost or tbkPrimeDev supplies one key polynomial per chunk (exactly
    // one of them must be non-null). The result stays on the device.
    bool expandSenderChunks(
        const ShrinkExpandSenderState& state,
        std::span<const RnsPoly> tbkPrimeHost,
        DeviceBatch* tbkPrimeDev,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        DeviceBatchPtr& tbkAll,
        PreparedSenderCt2* preparedCt2 = nullptr);

    // deriveSkxTrunc on the device:
    //   uHi     = centred gadget digits 1..tauHi of `digest`
    //   out     = tbkPrime + sum_i sk1[i] * uHi[i]
    //
    // The sum is formed in the evaluation domain and transformed once, which is
    // bit-identical to the host's per-term ringMultiply followed by ringAdd
    // because the inverse transform is linear over Z_q. This is the sender's
    // reply to the root digest, so it is on the critical path of both parties and
    // it does not scale with the label count.
    //
    // When residentKPrime is non-null and LV_GPU_ROOT_KPRIME_RESIDENT=1, a
    // one-polynomial coefficient-domain copy of tbkPrime is returned after the
    // function's mandatory output download has synchronized its producer
    // stream. The caller may therefore hand it to a later stream without an
    // event. A null returned handle is a soft miss and preserves the host path.
    // LV_GPU_ROOT_SK_NTT_RESIDENT caches the immutable transformed secret key by
    // default; LV_GPU_ROOT_KPRIME_PREUPLOAD independently enables the synchronized
    // fresh key upload before the Root request arrives. LV_GPU_ROOT_OPERAND_RESIDENCY
    // enables both. Each handle is validated and each missing operand independently
    // takes the established upload path.
    // recoverNonInteractiveMask changes the result to tbkPrime - <sk1,g^-1(d)>,
    // where tbkPrime is the public oracle response. residentKPrime then holds
    // that computed mask for the following expansion.
    bool rootSkxSenderDevice(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tauHi,
        RnsPoly& out,
        DeviceBatchPtr* residentKPrime = nullptr,
        const DeviceBatchPtr& preparedSkNtt = {},
        const DeviceBatchPtr& preparedKPrime = {},
        block* digestHash = nullptr,
        bool recoverNonInteractiveMask = false,
        const DeviceBatchPtr& rootSecretCoeffs = {},
        u64 rootSecretOwnerRunId = 0);

    // Root response preparation. Immutable skRRt caching is on by default; fresh
    // kPrime preupload remains independently opt-in. A false return is a soft miss.
    bool prepareRootSenderOperandsDevice(
        const SenderState& state,
        const RnsPoly& kPrime,
        DeviceBatchPtr& preparedKPrime);

    // The sender's whole Root level on the device: computeRootSenderKey followed
    // by the Root's own shrinkExpandExpandSender.
    //
    //   ctK     = buildHashedCt2(leftWidth rows, seed, sid, d'_Rt, instance 0)
    //   tbkRt   = lheDec(ctK, k'_Rt)              // publicA rows 0..leftWidth-1
    //   rootKey = seedLabelAgg(denoiseComb(tbkRt))
    //   tbk     = lheDec(buildHashedCt2(mu rows, ..., instance 0), rootKey)
    //
    // On the host this was ~85% of the sender's per-query cost and it is
    // independent of the label count, so it set the floor for every size: two
    // Blake2xb expansions of a megabyte each plus 24 SEAL transforms, and then the
    // 16 MiB result was uploaded by the level above. Nothing crosses PCIe here
    // except the two 16-byte seeds and the one-off k'_Rt upload.
    //
    // publicA row i does not depend on the batch size (see
    // deriveUniformPolyFromNonce), so the cached mu-row matrix serves the
    // leftWidth-row decryption as well - that is what lheDec's own
    // getOrCreateCachedPublicANtt does on the host.
    // `kPrimeRtDevice` is an optional reusable coefficient-domain copy. It is
    // never transformed in place because GoldenSeed can evaluate more than one
    // candidate; each call D2D-copies it into the ordinary destructive scratch.
    // Invalid or mismatched handles fall back to the unchanged host upload.
    bool rootSenderTbkDevice(
        const ShrinkExpandSenderState& state,
        const RingNttContext& ctx,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& dPrimeRt,
        block dPrimeHash,
        const RnsPoly& kPrimeRt,
        const DeviceBatch* kPrimeRtDevice,
        u32 leftWidth,
        u32 tauHi,
        DeviceBatchPtr& tbk);

    // shrinkExpandDenoiseComb followed by seedLabelAgg, both on the device.
    // `in` normally holds outCount * rho * tau polynomials.  A nonzero
    // logicalInputCount consumes only that complete prefix while retaining a
    // physically padded input batch (used by the experimental partial Root).
    bool denoiseAndAggDevice(
        const RingNttContext& ctx,
        const DeviceBatch& in,
        u32 tau,
        DeviceBatchPtr& out,
        u64 logicalInputCount = 0);

    // Default-on scheduling optimization for GoldenSeed. Each non-top sampled
    // batch is checked by the downstream denoise kernel, all levels OR into one
    // device flag, and the sender reads that flag once after queuing the top
    // check. LV_GPU_DEFER_GOLDEN_VALIDATION=0 restores the per-level checks.
    bool deferredGoldenValidationEnabled();
    bool beginGoldenValidationAttempt(const RingNttContext& ctx);
    bool denoiseAndAggValidateDevice(
        const RingNttContext& ctx,
        const DeviceBatch& in,
        u32 tau,
        const Params& validatedLevelParams,
        DeviceBatchPtr& out,
        u64 logicalInputCount = 0);
    bool finishGoldenValidationAttempt(bool& ok);
    bool abortGoldenValidationAttempt();

    // validateGoldenSeedCandidate against a device-resident tbk.
    bool validateGoldenSeedDevice(
        const Params& params,
        const DeviceBatch& tbk,
        bool& ok);

    // Leaf Q/p check over mW outputs; any physical padded suffix is ignored.
    bool validateLeafGoldenSeedDevice(
        const Params& params,
        const DeviceBatch& tbk,
        bool& ok);
    bool queueLeafGoldenSeedValidation(
        const Params& params,
        const DeviceBatch& tbk);

    // Batched shrinkExpandDenoiseComb: rho consecutive inputs give one output.
    bool denoiseCombBatch(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& in,
        std::vector<RnsPoly>& out);

    // Test/benchmark hook: GPU equivalent of calling
    // deriveUniformPolyFromSeed(ctx, seeds[i], domainTag, index) for every seed.
    //
    // `maxMultipleOverride`, when non-empty, replaces sample_poly_uniform's
    // per-limb rejection thresholds (rho entries). With the real 55-bit moduli
    // only ((2^64-1) mod q) + 2 of the 2^64 draws reject, about 2^-37 per
    // coefficient, so the rejection branch is unreachable in any feasible test.
    // A lowered threshold makes rejection common and is the only way to cover the
    // replacement ordering, which is the one order-dependent part of the sampler.
    bool sampleUniformFromSeedsForTest(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 index,
        std::vector<RnsPoly>& out,
        std::span<const u64> maxMultipleOverride = {});

    // Test hook for the device ct2 seed derivation. Produces, for chunk c in
    // [0, chunkCount) and row r in [0, mu), the same polynomial as
    //   buildHashedCt2(ctx, mu, seed, sid, digest, instanceBase + c, ct2)[r]
    // laid out as out[c * mu + r]. This is what pins the derivation to the host
    // implementation, including the field widths of the random-oracle input.
    bool ct2BatchForTest(
        const RingNttContext& ctx,
        u32 mu,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceBase,
        u32 chunkCount,
        std::vector<RnsPoly>& out);

    // Whole-pipeline device replacement for unwrapRingLabelsCrt's scaleAndRound
    // branch: CRT scale-and-round, then the plaintext-modulus NTT and slot
    // permutation that seal::BatchEncoder::decode performs, then one contiguous
    // copy of the `zpLabelCount` resulting scalars. Nothing else crosses the bus
    // and no seal::Plaintext is ever built.
    //
    // `out` must have room for zpLabelCount u64. Bit-identical to the host
    // routine.
    bool unwrapLabelsDevice(
        const ZpCrtContext& ctx,
        const DeviceBatch& labels,
        u64 chunkCount,
        u64 zpLabelCount,
        u64* out);

    // Same as unwrapLabelsDevice but leaves the scalars on the device. Nothing
    // crosses PCIe at all.
    DeviceScalarsPtr unwrapLabelsToDevice(
        const ZpCrtContext& ctx,
        const DeviceBatch& labels,
        u64 chunkCount,
        u64 zpLabelCount);

    // Same pipeline, but for labels that are still on the host. Pays an upload
    // in exchange for removing the per-chunk decode; used by the sender when the
    // keys were produced on the CPU.
    bool unwrapLabelsBatch(
        const ZpCrtContext& ctx,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        u64* out);

    // Public unscaled counterpart for host RNS labels: canonical CRT compose
    // modulo p, plaintext forward NTT, slot gather and one requested-scalar
    // download. Host SEAL contexts and BatchEncoder are never constructed.
    bool unwrapLabelsBatchUnscaled(
        const ZpCrtContext& ctx,
        const std::vector<RnsPoly>& labels,
        u64 chunkCount,
        u64 zpLabelCount,
        u64* out);

    // Device counterpart of wrapZpLabelsCrt: slot scatter, the inverse
    // plaintext-modulus NTT that seal::BatchEncoder::encode performs, and the
    // CRT lift, producing a device batch of ceil(labels.size() / N) ring
    // elements (padded up to `padChunks`). Only the scalars are uploaded, so the
    // 256 KiB-per-chunk host representation is never built.
    //
    // Bit-identical to wrapZpLabelsCrt followed by zero padding.
    DeviceBatchPtr wrapLabelsDevice(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u64 padChunks,
        bool garbledInput = false);

    // Same, for a caller whose scalars are already in device memory - the case a
    // GPU pipeline is in, where the previous stage produced x on the device.
    // Removes the only input-sized PCIe transfer a query makes.
    DeviceBatchPtr wrapDeviceLabels(
        const ZpCrtContext& ctx,
        const DeviceScalars& labels,
        u64 labelCount,
        bool multiplyByDelta,
        u64 padValue,
        u64 padChunks,
        bool garbledInput = false,
        ReceiverFirstQueryAllocations* firstQueryAllocations = nullptr,
        const void* firstQueryOwner = nullptr, u64 firstQuerySid = 0);

    // Prepare one setup key polynomial with the ordinary plaintext encoder and
    // CRT-lift arithmetic on GPU. Exactly one of a nonzero scalar, a full slot
    // span, or a nonzero three-delta pattern must be supplied. The required host
    // polynomial is fully downloaded before publication; failure preserves out.
    bool wrapSetupDeltaDevice(const ZpCrtContext& ctx, u64 delta,
        std::span<const u64> deltaSlots, const std::array<u64, 3>* garbledDeltas,
        RnsPoly& out);
    // Sender-only variant of the same constant/slot/garbled GPU arithmetic.
    // It publishes a synchronized coefficient-domain owner without the eager
    // host RnsPoly returned by wrapSetupDeltaDevice.
    DeviceBatchPtr wrapSetupDeltaResident(const ZpCrtContext& ctx, u64 delta,
        std::span<const u64> deltaSlots,
        const std::array<u64, 3>* garbledDeltas);

    // Copies a host scalar array to the device. Exists so a caller can place its
    // input where wrapDeviceLabels wants it; the protocol itself never calls it.
    DeviceScalarsPtr uploadScalars(std::span<const u64> src);

    // Exact cryptoTools AES-CTR u64 stream from a fresh PRNG(seed), reduced
    // modulo modulus on device. Synchronized before publication; no host array
    // is materialized. Null means unsupported input or a device failure.
    DeviceScalarsPtr sampleScalarsFromSeed(block seed, u64 count, u64 modulus);
}
