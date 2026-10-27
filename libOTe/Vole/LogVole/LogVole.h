#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "seal/seal.h"

#include <memory>
#include <array>
#include <optional>
#include <vector>

namespace osuCrypto::LogVole
{
    struct ZpHostContextCache;
    namespace gpu { class GpuPlainNtt; }

    // Public session identifier used by the low-level CI-VOLE API. The
    // libOTe-style wrappers below manage this counter automatically.
    using CivoleSid = u64;

    // CRT context for packing scalar Z_p labels into the LogVole ring.
    // The selected plaintext modulus may be smaller than the requested bit
    // count; call resolveCivoleModulus() or LogVoleSender::modulus() to learn
    // the concrete prime used by a session.
    struct ZpCrtContext
    {
        RingNttContext mRing;
        u32 mPlaintextModulusBits = 0;
        u64 mPlaintextModulus = 0;
        AlignedUnVec<u64> mPlaintextLiftModQj;
        // Production GPU contexts carry the exact audited modulus and lift
        // constants without constructing SEAL's host batching objects. CPU
        // fallback materializes those objects explicitly through this shared,
        // role-local owner; a null BatchEncoder must never select different
        // arithmetic or sampling semantics implicitly.
        bool mGpuLightweight = false;
        // A combined dynamic factory may retain the certified plaintext NTT
        // owner alongside the ring certificate. Both are immutable and
        // role-local; this is absent in the sequential and eager paths.
        std::shared_ptr<gpu::GpuPlainNtt> mNativePlainNtt;
        bool mNativeSealBundleCommitted = false;
        std::shared_ptr<ZpHostContextCache> mHostContextCache;
        std::shared_ptr<seal::SEALContext> mBatchingContext;

        // Constructing a BatchEncoder builds the slot permutation table and the
        // roots-of-unity vector, which is far more expensive than a single
        // encode. It is shared here because it is stateless for encode/decode.
        std::shared_ptr<seal::BatchEncoder> mBatchEncoder;
    };

    // Combined factory for callers that know both ring geometry and requested
    // plaintext width. The GPU path can publish both lightweight contexts
    // from one sealed device bundle; opt-out and eager paths use the existing
    // independent factories.
    bool makeNativeSealSetupContexts(const RingParams& ring,
        u32 plaintextModulusBits, RingNttContext& ringOut,
        ZpCrtContext& zpOut);

    struct CivoleParams
    {
        Params mLogVole;
    };

    // Which correctness mechanism a session runs, and therefore which RLWE
    // parameter set it needs. See Ct2SeedMode in LogVoleTypes.h.
    enum class CivoleSetting : u8
    {
        // GoldLabel golden seed. N = 8192, 4 x 55-bit limbs, g = 110.
        GoldenSeed = 0,
        // No golden seed, no rejection counters, nothing sent for ct2.
        // Uses N = 16384, 8 x 52-bit limbs, g = 208.
        NoGoldenSeed = 1
    };

    // Low-level CI-VOLE offline input for the sender. The scalar Delta is the
    // sender's global VOLE key, and mW is the requested output length.
    struct CivoleSenderOfflineInput
    {
        CivoleParams mParams;
        u64 mDelta = 0;
        u64 mW = 0;

        // Optional ring-periodic CRT key, one value per plaintext slot. When
        // supplied, mDelta must be zero. The caller owns this span until the
        // offline task completes. Used by LogVoleGarbledSender for three
        // independent deltas with zero-valued unused slots.
        std::span<const u64> mDeltaSlots;

        // Equivalent to repeating these three nonzero deltas through complete
        // groups of plaintext slots and zeroing the unused final slots. This
        // compact owned form lets GPU setup prepare the whole slot array.
        // Mutually exclusive with mDelta and mDeltaSlots.
        std::optional<std::array<u64, 3>> mGarbledDeltaPattern;
    };

    // Low-level CI-VOLE offline input for the receiver. mW is the agreed
    // output length and must match the sender's advertised length.
    struct CivoleReceiverOfflineInput
    {
        CivoleParams mParams;
        u64 mW = 0;
    };

    // Low-level reusable sender state for a fixed Delta and output length.
    // Each online SID can be used once.
    struct CivoleSenderState
    {
        CivoleParams mParams;
        u64 mModulus = 0;
        u64 mDelta = 0;
        u64 mW = 0;
        u32 mRingWidth = 0;
        SenderState mLogVoleState;

        bool mHasActiveSid = false;
        CivoleSid mActiveSid = 0;
        bool mKeyReleased = false;
        bool mReleaseIntUsed = false;
        AlignedUnVec<CivoleSid> mUsedSids;
        AlignedUnVec<u64> mReleasedKeys;
    };

    struct CivoleReceiverState
    {
        CivoleParams mParams;
        u64 mModulus = 0;
        u64 mW = 0;
        u32 mRingWidth = 0;
        ReceiverState mLogVoleState;
        // Optional receiver-owned first-query CUDA allocations prepared during
        // this same session's offline transport. The concrete CUDA type stays
        // private to the backend and is never shared with the sender.
        std::shared_ptr<void> mFirstQueryGpuAllocations;
        AlignedUnVec<CivoleSid> mUsedSids;
    };

    struct CivoleReleaseKOutput
    {
        CivoleSid mSid = 0;
        u64 mModulus = 0;
        AlignedUnVec<u64> mKeys;
    };

    struct CivoleSenderReleaseOutput
    {
        CivoleSid mSid = 0;
        CommunicationStats mComm;

        // Set when mKeepKeysOnDevice was requested and the CUDA backend handled
        // the query: the keys stay in device memory and CivoleSenderState's
        // mReleasedKeys stays empty. Concrete type is gpu::DeviceScalars.
        std::shared_ptr<void> mKeysDevice;
        u64 mKeysDeviceCount = 0;
    };

    struct CivoleSenderReleaseOptions
    {
        // Write the keys straight into this span instead of allocating and then
        // copying. Empty, or exactly the request size.
        std::span<u64> mKeysOut;

        // Leave the keys in device memory.
        bool mKeepKeysOnDevice = false;
    };

    struct CivoleReceiverSetXOutput
    {
        CivoleSid mSid = 0;
        u64 mModulus = 0;
        // No copy of the caller's x is kept here. It used to be mirrored into an
        // mValues field that nothing ever read, which cost a full n-word host copy
        // (134 MB at n = 2^24) on the receiver's critical path.
        AlignedUnVec<u64> mMacs;
        CommunicationStats mComm;

        // Set by civoleReceiverSetX when mKeepMacsOnDevice was requested: the
        // MACs are left in device memory and mMacs stays empty. The concrete
        // type is gpu::DeviceScalars. Use gpu::fetchScalars() to read them.
        std::shared_ptr<void> mMacsDevice;
        u64 mMacsDeviceCount = 0;
    };

    // Options for civoleReceiverSetX.
    struct CivoleReceiverSetXOptions
    {
        // Write the MACs straight into this span instead of allocating and then
        // copying. Must be either empty or exactly the request size. Avoids a
        // full-length host-to-host copy per query.
        std::span<u64> mMacsOut;

        // Leave the MACs in device memory. Only honoured when the CUDA backend
        // handled the query; otherwise the host path fills mMacs as usual.
        bool mKeepMacsOnDevice = false;

        // The receiver's x is already in device memory, as it is for a caller
        // whose previous pipeline stage ran on the GPU. Concrete type is
        // gpu::DeviceScalars, holding mXDeviceCount entries of Z_p. When set the
        // `x` span is not read and no input-sized transfer happens; the caller
        // is then responsible for the range check validateZpValues would do.
        std::shared_ptr<void> mXDevice;
        u64 mXDeviceCount = 0;

        // Pack each input three times into complete triples within each ring,
        // zeroing its final N % 3 slots. Used by the garbled-label API.
        bool mGarbledInput = false;
    };

}

namespace osuCrypto
{
    // Semi-honest LogVole chosen-input VOLE sender.
    //
    // For receiver input x and sender scalar Delta, send() outputs b such that
    // the receiver obtains a with a[i] = b[i] + x[i] * Delta mod p. The offline
    // phase fixes Delta and can be reused for sequential online calls of the
    // same configured size. Each online call consumes mNextSid, initialized to
    // zero by offline().
    class LogVoleSender : public TimerAdapter
    {
    public:
        enum class State
        {
            Default,
            Configured,
            Offline
        };

        LogVoleSender() = default;
        LogVoleSender(const LogVoleSender&) = delete;
        LogVoleSender& operator=(const LogVoleSender&) = delete;
        LogVoleSender(LogVoleSender&& other);
        LogVoleSender& operator=(LogVoleSender&& other);

        u64 mRequestSize = 0;
        u32 mPlaintextModulusBits = 55;
        u64 mModulus = 0;
        u64 mDelta = 0;
        u32 mNumThreads = 1;
        LogVole::CivoleSid mNextSid = 0;
        LogVole::CommunicationStats mLastOnlineComm;
        State mState = State::Default;
        LogVole::CivoleSetting mSetting = LogVole::CivoleSetting::GoldenSeed;
        LogVole::CivoleParams mParams;
        LogVole::CivoleSenderState mOfflineState;

        // Leave the keys in GPU memory instead of writing them to `b`, for
        // callers whose next step also runs on the GPU. After send(),
        // outputDevice() holds them. Ignored without the CUDA backend.
        bool mKeepOutputOnDevice = false;
        std::shared_ptr<void> mOutputDevice;
        u64 mOutputDeviceCount = 0;

        // Device-resident keys from the last send() when mKeepOutputOnDevice was
        // set. Concrete type is LogVole::gpu::DeviceScalars.
        const std::shared_ptr<void>& outputDevice() const { return mOutputDevice; }
        u64 outputDeviceCount() const { return mOutputDeviceCount; }

        // Select the number of VOLE outputs, requested plaintext modulus bit
        // count, worker thread count, and which correctness setting to run. The
        // actual prime p can be read with modulus() after configuration; a
        // setting that fixes p (NoGoldenSeed) overrides the requested bit count.
        void configure(
            u64 n,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed,
            LogVole::OnlineMode mode = LogVole::OnlineMode::Interactive);

        bool isConfigured() const { return mState != State::Default; }
        bool hasOffline() const { return mState == State::Offline; }
        u64 modulus() const { return mModulus; }
        // Diagnostic evidence for the SEAL context selected by configure().
        u64 configureCacheRunId() const { return mConfigureCacheRunId; }
        bool nativeSealBundleAtConfigure() const { return mNativeSealBundleAtConfigure; }
        LogVole::CivoleSetting setting() const { return mSetting; }
        LogVole::OnlineMode mode() const { return mParams.mLogVole.mOnlineMode; }

        // Run reusable offline setup for this sender's Delta.
        task<> offline(
            u64 delta,
            PRNG& prng,
            Socket& sock);

        // Online phase after offline(). Writes sender keys b.
        task<> send(
            span<u64> b,
            PRNG& prng,
            Socket& sock);

        // One-shot convenience entrypoint. If needed, this configures from
        // b.size() and runs offline(delta, sock) before the online send.
        task<> send(
            u64 delta,
            span<u64> b,
            PRNG& prng,
            Socket& sock);

        void clear();

    private:
        u64 mConfigureCacheRunId = 0;
        bool mNativeSealBundleAtConfigure = false;
    };

    // Semi-honest LogVole chosen-input VOLE receiver.
    //
    // The receiver supplies x and receives a, where a is correlated with the
    // sender output b and Delta as a[i] = b[i] + x[i] * Delta mod p.
    class LogVoleReceiver : public TimerAdapter
    {
    public:
        enum class State
        {
            Default,
            Configured,
            Offline
        };

        LogVoleReceiver() = default;
        LogVoleReceiver(const LogVoleReceiver&) = delete;
        LogVoleReceiver& operator=(const LogVoleReceiver&) = delete;
        LogVoleReceiver(LogVoleReceiver&& other);
        LogVoleReceiver& operator=(LogVoleReceiver&& other);

        u64 mRequestSize = 0;
        u32 mPlaintextModulusBits = 55;
        u64 mModulus = 0;
        u32 mNumThreads = 1;
        LogVole::CivoleSid mNextSid = 0;
        LogVole::CommunicationStats mLastOnlineComm;
        State mState = State::Default;
        LogVole::CivoleSetting mSetting = LogVole::CivoleSetting::GoldenSeed;
        LogVole::CivoleParams mParams;
        LogVole::CivoleReceiverState mOfflineState;
        std::shared_ptr<void> mOutputDevice;
        u64 mOutputDeviceCount = 0;

        // Select the number of VOLE outputs, requested plaintext modulus bit
        // count, worker thread count, and which correctness setting to run. Must
        // match the sender's setting and mode. NonInteractive requires
        // NoGoldenSeed. With a BufferingSocket, offline() imports reusable
        // public parameters and receive() completes locally; its buffered
        // outbound digest can be delivered to the sender later. Applications
        // must assign distinct SIDs across receivers sharing a public key.
        void configure(
            u64 n,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed,
            LogVole::OnlineMode mode = LogVole::OnlineMode::Interactive);

        // Leave the MACs in GPU memory instead of writing them to `a`, for
        // callers whose next step also runs on the GPU. After receive(),
        // outputDevice() holds them. Ignored when the CUDA backend is not in use.
        bool mKeepOutputOnDevice = false;

        // Take x from GPU memory instead of from the `x` span, for callers whose
        // previous step also ran on the GPU. Concrete type is
        // LogVole::gpu::DeviceScalars with mRequestSize entries; build one with
        // LogVole::gpu::uploadScalars or hand over a producer's own buffer. The
        // `x` argument of receive() is then only used for its size, and each
        // entry must already be in Z_p. Ignored without the CUDA backend.
        std::shared_ptr<void> mInputDevice;

        bool isConfigured() const { return mState != State::Default; }
        bool hasOffline() const { return mState == State::Offline; }
        u64 modulus() const { return mModulus; }
        // Diagnostic evidence for the SEAL context selected by configure().
        u64 configureCacheRunId() const { return mConfigureCacheRunId; }
        bool nativeSealBundleAtConfigure() const { return mNativeSealBundleAtConfigure; }
        LogVole::CivoleSetting setting() const { return mSetting; }
        LogVole::OnlineMode mode() const { return mParams.mLogVole.mOnlineMode; }

        // Device-resident MACs from the last receive() when mKeepOutputOnDevice
        // was set. The concrete type is LogVole::gpu::DeviceScalars.
        const std::shared_ptr<void>& outputDevice() const { return mOutputDevice; }
        u64 outputDeviceCount() const { return mOutputDeviceCount; }

        // Run reusable offline setup matching the sender's offline phase.
        task<> offline(Socket& sock);

        // Online phase. x must have the configured size and each x[i] must be
        // in Z_p. Writes receiver MACs a, unless mKeepOutputOnDevice is set.
        task<> receive(
            span<const u64> x,
            span<u64> a,
            PRNG& prng,
            Socket& sock);

        void clear();

    private:
        u64 mConfigureCacheRunId = 0;
        bool mNativeSealBundleAtConfigure = false;
    };
}

namespace osuCrypto::LogVole
{

    // Build default CI-VOLE parameters. These parameters target the LogVole
    // paper's Ring-LWE-style construction and use the requested worker count.
    bool makeDefaultCivoleParams(CivoleParams& out, u32 workerThreads = 1);

    // Parameters for CivoleSetting::NoGoldenSeed. The plaintext modulus is part
    // of the tuple (log p must match the limb size for Delta = q / p to hold),
    // so unlike makeDefaultCivoleParams this one fixes it.
    bool makeNoGoldenSeedCivoleParams(CivoleParams& out, u32 workerThreads = 1);

    bool makeCivoleParams(CivoleSetting setting, CivoleParams& out, u32 workerThreads = 1);

    // The plaintext modulus bit count a setting requires, or 0 when the setting
    // leaves it to the caller.
    u32 civoleSettingPlaintextModulusBits(CivoleSetting setting);

    bool resolveCivoleModulus(const CivoleParams& params, u64& out);

    u64 zpSlotCount(const ZpCrtContext& ctx);
    u64 zpRingLabelCount(const ZpCrtContext& ctx, u64 zpLabelCount);
    bool makeZpCrtContext(const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out);

    bool wrapZpBatchCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32 requestedWorkers,
        RnsPoly& out);

    bool wrapZpConstantCrt(
        const ZpCrtContext& ctx,
        u64 value,
        bool multiplyByDelta,
        u32 requestedWorkers,
        RnsPoly& out);

    bool wrapZpLabelsCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32 requestedWorkers,
        std::vector<RnsPoly>& out);

    bool unwrapRingLabelsCrt(
        const ZpCrtContext& ctx,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        bool scaleAndRound,
        u32 requestedWorkers,
        AlignedUnVec<u64>& out);

    // Low-level CI-VOLE state-machine API. Applications should normally prefer
    // osuCrypto::LogVoleSender and osuCrypto::LogVoleReceiver above.
    task<> civoleSenderOffline(
        const CivoleSenderOfflineInput& input,
        CivoleSenderState& state,
        PRNG& prng,
        Socket& sock);

    task<> civoleReceiverOffline(
        const CivoleReceiverOfflineInput& input,
        CivoleReceiverState& state,
        Socket& sock);

    bool civoleSenderReleaseK(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleReleaseKOutput& output);

    task<> civoleSenderRelease(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleSenderReleaseOutput& output,
        PRNG& prng,
        Socket& sock,
        CivoleSenderReleaseOptions options = {});



    task<> civoleReceiverSetX(
        CivoleReceiverState& state,
        CivoleSid sid,
        std::span<const u64> x,
        CivoleReceiverSetXOutput& output,
        PRNG& prng,
        Socket& sock,
        CivoleReceiverSetXOptions options = {});
}
