#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Aligned.h>

#include <algorithm>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    namespace gpu { class DeviceBatch; class RetainedPublicUniform; }

    template<typename T>
    using AlignedUnVec = AlignedUnVector<T>;

    template<typename T>
    void resizeZero(AlignedUnVec<T>& value, u64 size)
    {
        value.resize(static_cast<std::size_t>(size), AllocType::Zeroed);
    }

    template<typename T>
    void resizeFill(AlignedUnVec<T>& value, u64 size, const T& fill)
    {
        value.resize(static_cast<std::size_t>(size));
        std::fill(value.begin(), value.end(), fill);
    }

    template<typename T, typename It>
    void assignRange(AlignedUnVec<T>& value, It begin, It end)
    {
        const auto size = static_cast<std::size_t>(std::distance(begin, end));
        value.resize(size);
        std::copy(begin, end, value.begin());
    }

    template<typename T>
    void assignSpan(AlignedUnVec<T>& value, std::span<const T> input)
    {
        value.resize(input.size());
        std::copy(input.begin(), input.end(), value.begin());
    }

    template<typename T>
    void assignValues(AlignedUnVec<T>& value, std::initializer_list<T> input)
    {
        value.resize(input.size());
        std::copy(input.begin(), input.end(), value.begin());
    }

    template<typename L, typename R>
    bool rangesEqual(const L& lhs, const R& rhs)
    {
        return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
    }

    struct RingParams
    {
        u32 mPolyModulusDegree = 0;
        AlignedUnVec<int> mCoeffModulusBits;

        bool operator==(const RingParams& other) const
        {
            return mPolyModulusDegree == other.mPolyModulusDegree
                && mCoeffModulusBits.size() == other.mCoeffModulusBits.size()
                && std::equal(
                    mCoeffModulusBits.begin(),
                    mCoeffModulusBits.end(),
                    other.mCoeffModulusBits.begin());
        }

        bool operator!=(const RingParams& other) const
        {
            return !(*this == other);
        }
    };

    struct RnsPoly
    {
        AlignedUnVec<u64> mCoeffs;
    };

    struct RingTensor
    {
        u32 mRows = 0;
        u32 mCols = 0;
        std::vector<RnsPoly> mPolys;
    };

    inline u64 ringPolyCoeffCount(const RingParams& params)
    {
        return static_cast<u64>(params.mPolyModulusDegree) * params.mCoeffModulusBits.size();
    }

    inline u64 ringTensorSize(const RingTensor& tensor)
    {
        return static_cast<u64>(tensor.mRows) * tensor.mCols;
    }

    inline u64 ringTensorIndex(const RingTensor& tensor, u32 row, u32 col)
    {
        return static_cast<u64>(row) * tensor.mCols + col;
    }

    enum class ShrinkExpandMode : u8
    {
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
        Deterministic = 0,
#endif
        FullNoise = 1
    };

    struct ShrinkExpandParams
    {
        RingParams mRing;
        u32 mPlaintextModulusBits = 0;
        u32 mAlpha = 2;
        u32 mMu = 0;
        u32 mGadgetLogBase = 0;
        u32 mTau = 0;
        u32 mNumWorkerThreads = 1;
        bool mTruncateOneGadgetDigit = false;
        bool mLeafInputsAreGadget = false;
        ShrinkExpandMode mMode = ShrinkExpandMode::FullNoise;
        i64 mNoiseBound = 2;
    };

    // How the sender fixes the seed that the ct2 masks are derived from.
    //
    // GoldenSeed is the original GoldLabel behaviour: the sender draws seeds
    // until one makes *every* sampled ct2 coefficient land far enough from a
    // rounding boundary, then ships that seed. Correctness is then
    // deterministic, and the price is the grinding - each attempt is a full
    // recursive expansion plus a 128-bit CRT rounding check over every sampled
    // polynomial - and a Delta that has to keep the per-attempt acceptance
    // probability workable, so the budget degrades as the request grows.
    //
    // PublicSeed removes the golden seed. The seed is a public function of the
    // transcript, so there is nothing to grind, nothing to validate and nothing
    // to send; correctness instead rests on the random-oracle argument
    //
    //     2 * B * 2^lambda <= Delta_j = prod_{w != j} q_w
    //
    // i.e. a single sampled coefficient is bad with probability at most
    // 2^-lambda. validateNoGoldenSeedBudget checks exactly that, and refuses
    // parameters that do not have the headroom.
    enum class Ct2SeedMode : u8
    {
        GoldenSeed = 0,
        PublicSeed = 1
    };

    struct DigestTree;

    struct ShrinkExpandLacct
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RingTensor mCt;
    };

    // Internal immutable storage can defer a tensor's host representation.
    // Implementations must publish get() exactly once for concurrent readers,
    // retain the returned reference for their lifetime, and leave failed
    // materializations retryable. Encoded coefficients are the complete,
    // contiguous little-endian coefficient payload, without wire metadata,
    // and their span remains valid while the owner is retained.
    struct LazyRingTensorHostState
    {
        virtual ~LazyRingTensorHostState() = default;
        virtual const RingTensor& get() const = 0;
        // Optional export completes before returning; false permits get() fallback.
        virtual bool copyCoefficientsTo(std::span<u8>) const { return false; }
        virtual std::span<const u8> encodedCoefficients() const { return {}; }
    };

    struct LazyLacctHostState
    {
        virtual ~LazyLacctHostState() = default;
        virtual const ShrinkExpandLacct& get() const = 0;
        virtual bool copyCoefficientsTo(std::span<u8>) const { return false; }
        virtual std::span<const u8> encodedCoefficients() const { return {}; }
    };

    // Immutable first-layer LENC randomness retained by internal GPU setup.
    // Host access publishes stable snapshots without consuming protocol PRNG.
    struct LazyLencRandomizerState
    {
        virtual ~LazyLencRandomizerState() = default;
        virtual std::size_t count() const = 0;
        virtual bool matches(const RingParams& params) const = 0;
        virtual const std::vector<RnsPoly>& hostNtt() const = 0;
        virtual const std::vector<RnsPoly>& hostCoefficients() const = 0;
    };

    // Internal sender Root transport may keep r1 only in coefficient domain on
    // its GPU. Explicit host access reconstructs the exact sampled rows from
    // already-consumed seeds and never advances the protocol PRNG.
    struct LazyRootErrorHostState
    {
        virtual ~LazyRootErrorHostState() = default;
        virtual std::size_t count() const = 0;
        virtual bool matches(const RingParams& params) const = 0;
        virtual const std::vector<RnsPoly>& hostCoefficients() const = 0;
    };

    // A private sender uniform secret (Root skRRt or top HE sk1) may stay in
    // coefficient domain on its GPU. A declined consumer replays only the
    // already-consumed, row-ordered SEAL seeds, never the parent PRNG.
    struct LazyRootSecretHostState
    {
        virtual ~LazyRootSecretHostState() = default;
        virtual std::size_t count() const = 0;
        virtual bool matches(const RingParams& params) const = 0;
        virtual const std::vector<RnsPoly>& hostCoefficients() const = 0;
    };

    // A receiver normally consumes deterministic public A/B directly from
    // retained device owners. If a CPU fallback later needs them, publish one
    // complete immutable pair and keep it only for the lifetime of the state
    // (and its ordinary copies). Failure leaves the cache retryable.
    struct LazyPublicUniformHostState
    {
        virtual ~LazyPublicUniformHostState() = default;
        virtual bool get(
            std::shared_ptr<const std::vector<RnsPoly>>& publicA,
            std::shared_ptr<const std::vector<RnsPoly>>& publicB) const = 0;
    };

    // Internal sender setup can keep replicated seed-label polynomials on its
    // own GPU through LENC. A declined device consumer or explicit hostS()
    // request obtains the exact coefficient-domain batch once, without
    // repeating the parent PRNG draws or changing direct/public setup inputs.
    struct LazySeedLabelHostState
    {
        virtual ~LazySeedLabelHostState() = default;
        virtual std::size_t count() const = 0;
        virtual bool matches(const RingParams& params) const = 0;
        virtual const std::vector<RnsPoly>& hostCoefficients() const = 0;
    };

    struct ShrinkExpandSenderState
    {
        ShrinkExpandParams mParams;
        std::vector<RnsPoly> mS;
        std::shared_ptr<const LazySeedLabelHostState> mLazyS;
        std::vector<RnsPoly> mR;
        std::vector<RnsPoly> mSk1;
        // Selected internal setup retains the freshly sampled top HE key, or
        // its fixed child copy, through Ct1/recursive Root before publishing
        // independent mutable mSk1 vectors. Ordinary public setup is eager.
        std::shared_ptr<const gpu::DeviceBatch> mTopSk1Device;
        std::shared_ptr<const LazyRootSecretHostState> mLazyTopSk1;
        u64 mTopSk1OwnerRunId = 0;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicANtt;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicBNtt;
        // The default GPU sender owns immutable public operands on its own
        // device. Exact host owners are built only for a CPU path or an
        // explicit mutable host-state request.
        std::shared_ptr<const gpu::RetainedPublicUniform> mPublicANttDevice;
        std::shared_ptr<const gpu::RetainedPublicUniform> mPublicBNttDevice;
        std::shared_ptr<const LazyPublicUniformHostState> mLazyPublicUniformHosts;
        // Retained tokens were sampled during this sender's offline run;
        // online query scopes may use a different sid/run ID.
        u64 mPublicUniformRunId = 0;
        RingTensor mCt1;
        ShrinkExpandLacct mLacct;

        // Opaque device-side mirror of the offline tensors, filled in lazily by
        // the CUDA backend. Unused when the GPU backend is off.
        mutable std::shared_ptr<void> mGpuCache;

        // Explicit internal GPU views leave the bulk mutable vectors empty and
        // retain their shared backing here for CPU fallback. Ordinary
        // public offline inputs do not create these views. Before changing a
        // view's host polynomials, call materializeShrinkExpandHostState().
        std::shared_ptr<const ShrinkExpandSenderState> mSharedHostState;

        // The internal transport route retains completed device ciphertexts;
        // host getters materialize immutable snapshots only when requested.
        std::shared_ptr<const LazyRingTensorHostState> mLazyCt1;
        std::shared_ptr<const LazyLacctHostState> mLazyLacct;

        std::shared_ptr<const LazyLencRandomizerState> mLazyRandomizers;

        const std::vector<RnsPoly>& hostS() const { return mSharedHostState ? mSharedHostState->hostS() : mLazyS ? mLazyS->hostCoefficients() : mS; }
        const std::vector<RnsPoly>& hostSk1() const { return !mSk1.empty() ? mSk1 : mSharedHostState ? mSharedHostState->hostSk1() : mLazyTopSk1 ? mLazyTopSk1->hostCoefficients() : mSk1; }
        const std::vector<RnsPoly>& hostR() const { return mSharedHostState ? mSharedHostState->hostR() : mLazyRandomizers ? mLazyRandomizers->hostCoefficients() : mR; }
        const RingTensor& hostCt1() const { return mSharedHostState ? mSharedHostState->hostCt1() : mLazyCt1 ? mLazyCt1->get() : mCt1; }
        const ShrinkExpandLacct& hostLacct() const { return mSharedHostState ? mSharedHostState->hostLacct() : mLazyLacct ? mLazyLacct->get() : mLacct; }
    };

    struct ShrinkExpandReceiverState
    {
        ShrinkExpandParams mParams;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicANtt;
        std::shared_ptr<const std::vector<RnsPoly>> mPublicBNtt;
        // Internal transport setup can retain deterministic public operands on
        // the receiver device. Host owners stay empty until a CPU path or an
        // explicit materialization requests the exact snapshot.
        std::shared_ptr<const gpu::RetainedPublicUniform> mPublicANttDevice;
        std::shared_ptr<const gpu::RetainedPublicUniform> mPublicBNttDevice;
        std::shared_ptr<const LazyPublicUniformHostState> mLazyPublicUniformHosts;
        RingTensor mCt1;
        ShrinkExpandLacct mLacct;

        // Opaque device-side mirror of the offline tensors, filled in lazily by
        // the CUDA backend. Unused when the GPU backend is off.
        mutable std::shared_ptr<void> mGpuCache;

        // See the sender state: shared storage is immutable, with explicit
        // materialization restoring independent mutable public host tensors.
        std::shared_ptr<const ShrinkExpandReceiverState> mSharedHostState;

        // Ct1 is always returned in NTT domain, even when its retained input
        // was coefficient-domain wire storage. Host tensors remain immutable
        // until materializeShrinkExpandHostState() restores independent copies.
        std::shared_ptr<const LazyRingTensorHostState> mLazyCt1Ntt;
        std::shared_ptr<const LazyLacctHostState> mLazyLacct;

        const RingTensor& hostCt1() const { return mSharedHostState ? mSharedHostState->hostCt1() : mLazyCt1Ntt ? mLazyCt1Ntt->get() : mCt1; }
        const ShrinkExpandLacct& hostLacct() const { return mSharedHostState ? mSharedHostState->hostLacct() : mLazyLacct ? mLazyLacct->get() : mLacct; }
    };

    // Figure 10 of ePrint 2026/925. NonInteractive requires PublicSeed:
    // the receiver derives the root response locally and sends only its digest.
    enum class OnlineMode : u8
    {
        Interactive = 0,
        NonInteractive = 1
    };

    struct Params
    {
        ShrinkExpandParams mShrinkExpand;
        u32 mW = 0;
        u32 mGamma = 0;
        u64 mTotalLabelCount = 0;
        u64 mSessionId = 0;

        // Both parties must agree on this. makeChildParams copies it, so every
        // recursion level inherits the top-level choice.
        Ct2SeedMode mCt2SeedMode = Ct2SeedMode::GoldenSeed;
        OnlineMode mOnlineMode = OnlineMode::Interactive;

        // Required per-coefficient correctness margin for Ct2SeedMode::PublicSeed,
        // in bits: the setting is only accepted when a sampled ct2 coefficient is
        // bad with probability at most 2^-mCt2StatBits, i.e. when
        //     log2(2B) + mCt2StatBits <= log2(Delta_j)   for every limb j.
        // Unused by Ct2SeedMode::GoldenSeed, which rejects bad coefficients
        // instead of bounding them.
        u32 mCt2StatBits = 128;
    };

    struct SenderState
    {
        Params mParams;
        std::vector<RnsPoly> mSk1;
        ShrinkExpandSenderState mShrinkExpandState;
        // Recursive selected transport borrows the private top HE key on its
        // GPU. The const host view is exact; explicit materialization below
        // restores an independent mutable mSk1 at every level.
        const std::vector<RnsPoly>& hostSk1() const
        {
            return !mSk1.empty() ? mSk1 : mShrinkExpandState.hostSk1();
        }
        std::vector<RnsPoly> mRootSkRRt;
        std::shared_ptr<void> mRootSkRRtDevice;
        std::shared_ptr<const LazyRootSecretHostState> mLazyRootSkRRt;
        // Offline producer run, which can differ from a later online query SID.
        u64 mRootSkRRtOwnerRunId = 0;
        // Optional immutable NTT-domain device mirror of mRootSkRRt. The Root
        // response reads the same offline secret every query, so the operand
        // residency experiment can upload and transform it once. Typed as void
        // to keep CUDA types out of this header; the concrete type is
        // gpu::DeviceBatch.
        mutable std::shared_ptr<void> mRootSkRRtNttDevice;
        std::vector<RnsPoly> mRootR1Rt;
        // Internal transport setup keeps these sampled coefficient rows on the
        // Sender GPU until both CtR and TopCt have copied them. The public Root
        // API still populates mRootR1Rt eagerly; an internal caller may obtain
        // its exact host view through mLazyRootR1Rt when explicitly needed.
        std::shared_ptr<void> mRootR1RtDevice;
        std::shared_ptr<const LazyRootErrorHostState> mLazyRootR1Rt;
        u32 mRootRandomizerWidth = 0;
        mutable AlignedUnVec<u8> mGoldenSeed;
        // May be an empty lazy host mirror when mRootKPrimeRtDevice is a
        // synchronized GPU-generated key. CPU key derivation materializes it.
        mutable std::shared_ptr<RnsPoly> mRootKPrimeRt;
        // Coefficient-domain key retained from the Root sk' response calculation.
        // It can be the primary GPU-generated value or an optional host mirror.
        // Typed as void to keep CUDA types out of
        // this header; the concrete type is gpu::DeviceBatch. It is reusable
        // across GoldenSeed candidates because consumers D2D-copy before NTT.
        mutable std::shared_ptr<void> mRootKPrimeRtDevice;
        mutable std::shared_ptr<RnsPoly> mRootDPrimeRt;
        // Commitment to mRootDPrimeRt. Every recursion level derives ct2 seeds
        // from the same root digest, so hashing its 256 KiB coefficients once per
        // level needlessly starves the GPU between small launches.
        mutable block mRootDPrimeHash{};
        mutable bool mRootDPrimeHashValid = false;
        mutable std::shared_ptr<std::vector<RnsPoly>> mPrecomputedTbk;
        // When the GPU produced the keys they are left on the device and only
        // unwrapped from there, so mPrecomputedTbk stays empty. Typed as void to
        // keep the CUDA types out of this header; the concrete type is
        // gpu::DeviceBatch.
        mutable std::shared_ptr<void> mPrecomputedTbkDevice;
        mutable u64 mPrecomputedTbkCount = 0;
        std::unique_ptr<SenderState> mNextLevelState;
    };

    struct ReceiverState
    {
        Params mParams;
        ShrinkExpandReceiverState mShrinkExpandState;
        RingTensor mRootCtRRt;
        // Socket CtR stays in this receiver's owned coefficient-domain wire
        // segment until a GPU upload. get() provides a once-only CPU forward
        // NTT of the same bytes if the device path actually declines.
        std::shared_ptr<const LazyRingTensorHostState> mRootCtRWire;
        ShrinkExpandLacct mRootLacctLeft;
        // The socket decoder may retain Lacct in the process-owned wire Buffer.
        // GPU consumers upload its contiguous bytes; a declined path calls get().
        std::shared_ptr<const LazyRingTensorHostState> mRootLacctLeftWire;
        RingTensor mRootTopCt;
        // The socket decoder may retain TopCt in its process-owned wire Buffer
        // instead of scattering it into host polynomials. GPU consumers upload
        // this exact contiguous segment; a declined GPU path calls get().
        std::shared_ptr<const LazyRingTensorHostState> mRootTopCtWire;
        std::vector<RnsPoly> mRootPublicBStarNtt;
        // Internal TCP BStar remains in this receiver's owned NTT-domain
        // wire segment until a GPU upload or an exact lazy CPU fallback.
        std::shared_ptr<const LazyRingTensorHostState> mRootPublicBStarWire;
        u32 mRootRandomizerWidth = 0;
        mutable AlignedUnVec<u8> mGoldenSeed;
        mutable std::shared_ptr<RnsPoly> mRootDPrimeRt;
        mutable block mRootDPrimeHash{};
        mutable bool mRootDPrimeHashValid = false;
        // The three tensors above, uploaded once and kept in device memory for the
        // Root's device key derivation. They are offline constants, so this is
        // built on first use and reused for every query. Typed as void to keep the
        // CUDA types out of this header; the concrete type is a private cache
        // struct in LogVoleGpuProtocol.cpp.
        mutable std::shared_ptr<void> mRootGpuCache;
        std::unique_ptr<ReceiverState> mNextLevelState;
    };
}
