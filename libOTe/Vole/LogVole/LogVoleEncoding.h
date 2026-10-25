#pragma once

#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

#include <algorithm>
#include <span>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

namespace osuCrypto::LogVole
{
    struct Params;
    namespace detail
    {
        void* allocateSetupWireBytes(std::size_t bytes, std::size_t alignment);
        void deallocateSetupWireBytes(void* pointer) noexcept;

        template<typename T> struct SetupWireAllocator
        {
            using value_type = T;
            using propagate_on_container_move_assignment = std::true_type;
            using is_always_equal = std::true_type;
            template<typename U> struct rebind { using other = SetupWireAllocator<U>; };

            SetupWireAllocator() = default;
            template<typename U> SetupWireAllocator(const SetupWireAllocator<U>&) noexcept {}

            T* allocate(std::size_t count)
            {
                if (count > std::numeric_limits<std::size_t>::max() / sizeof(T))
                    throw std::bad_array_new_length();
                return static_cast<T*>(allocateSetupWireBytes(count * sizeof(T),
                    std::max<std::size_t>(gDefaultAlignment, alignof(T))));
            }
            void deallocate(T* pointer, std::size_t) noexcept { deallocateSetupWireBytes(pointer); }

            // Buffer's resize has always left new bytes uninitialized. Preserve
            // that behavior instead of std::vector's default value-initializing
            // memset; copies and explicit values use the ordinary construction.
            template<typename U> void construct(U* pointer) { ::new(static_cast<void*>(pointer)) U; }
            template<typename U, typename... Args> void construct(U* pointer, Args&&... args)
            { ::new(static_cast<void*>(pointer)) U(std::forward<Args>(args)...); }
            template<typename U> void destroy(U* pointer) { pointer->~U(); }
        };
        template<typename T, typename U>
        bool operator==(const SetupWireAllocator<T>&, const SetupWireAllocator<U>&) noexcept { return true; }
        template<typename T, typename U>
        bool operator!=(const SetupWireAllocator<T>&, const SetupWireAllocator<U>&) noexcept { return false; }
    }

    // A contiguous owning wire buffer. Large GPU buffers reuse page-aligned
    // host storage whose CUDA registration is retained after the first GPU
    // transfer; LV_GPU_SETUP_PINNED_WIRE=0 and pool allocation decline retain
    // ordinary aligned allocation. Copies always own independent storage.
    class Buffer : public std::vector<u8, detail::SetupWireAllocator<u8>>
    {
        using Base = std::vector<u8, detail::SetupWireAllocator<u8>>;
    public:
        using Base::Base;
        using element_type = u8;
        Buffer() = default;
        Buffer(const Buffer&) = default;
        Buffer(Buffer&&) noexcept = default;
        Buffer& operator=(const Buffer&) = default;
        Buffer& operator=(Buffer&&) noexcept = default;

        void resize(std::size_t size, AllocType type = AllocType::Uninitialized)
        {
            const auto oldSize = Base::size();
            Base::resize(size);
            if (type == AllocType::Zeroed && size > oldSize)
                std::memset(Base::data() + oldSize, 0, size - oldSize);
        }
        // AlignedUnVector::clear releases capacity as well as its logical size.
        void clear() noexcept { Base empty; Base::swap(empty); }
        span<u8> subspan(u64 offset) { return span<u8>(Base::data(), Base::size()).subspan(offset); }
        span<const u8> subspan(u64 offset) const
        { return span<const u8>(Base::data(), Base::size()).subspan(offset); }
        span<u8> subspan(u64 offset, std::size_t size)
        { return span<u8>(Base::data(), Base::size()).subspan(offset, size); }
        span<const u8> subspan(u64 offset, std::size_t size) const
        { return span<const u8>(Base::data(), Base::size()).subspan(offset, size); }
    };

    // Optional Linux allocation hint for large GPU protocol wire buffers.
    // Does not initialize, read, or change any payload bytes.
    void adviseGpuSetupWireBuffer(Buffer& buffer);

    struct PolyMessage
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        AlignedUnVec<u64> mCoeffs;
    };

    struct SeedMessage
    {
        AlignedUnVec<u8> mSeed;
    };

    struct RootOfflineMessage
    {
        RingParams mRing;
        u32 mTauHi = 0;
        u32 mGadgetLogBase = 0;
        u32 mPlaintextModulusBits = 0;
        u32 mLeftWidth = 0;
        u32 mRandomizerWidth = 0;
        RingTensor mCtR;
        ShrinkExpandLacct mLacctLeft;
        RingTensor mTopCt;
        std::vector<RnsPoly> mPublicBStarNtt;
        // The internal decoder can keep this NTT-domain batch as one owned
        // coefficient segment. Its count remains explicit while the eager
        // public vector is empty; public/direct messages use vector.size().
        u32 mPublicBStarCount = 0;
        // Internal sender transport may retain completed ciphertexts on its
        // own GPU until the independently owned wire buffer is populated.
        // Ordinary/public Root messages keep eager, mutable host tensors.
        std::shared_ptr<const LazyRingTensorHostState> mLazyCtR;
        std::shared_ptr<const LazyRingTensorHostState> mLazyLacctLeft;
        std::shared_ptr<const LazyRingTensorHostState> mLazyTopCt;
        std::shared_ptr<const LazyRingTensorHostState> mLazyPublicBStar;
        // Only the internal socket decoder sets these. They distinguish
        // owned, validated wire segments from sender-side deferred tensors;
        // public/direct messages continue to publish eager host tensors.
        std::shared_ptr<const LazyRingTensorHostState> mOwnedCtRWire;
        std::shared_ptr<const LazyRingTensorHostState> mOwnedLacctLeftWire;
        std::shared_ptr<const LazyRingTensorHostState> mOwnedTopCtWire;
        std::shared_ptr<const LazyRingTensorHostState> mOwnedPublicBStarWire;
    };

    struct RootDigestMessage
    {
        AlignedUnVec<u64> mDPrimeCoeffs;
    };

    struct RootResponseMessage
    {
        AlignedUnVec<u8> mSeed;
        AlignedUnVec<u64> mSkPrimeCoeffs;
    };

    Buffer encode(const KeyDeriveRequest& message);
    Buffer encode(const KeyDeriveResponse& message);
    Buffer encode(const ShrinkExpandOfflineMessage& message);
    Buffer encode(const ShrinkExpandOfflineMessage& message, u32 workers);
    // Borrow the completed sender tensors while producing independently owned
    // wire bytes. This avoids constructing a second mutable tensor package.
    Buffer encodeShrinkExpandOfflineState(const ShrinkExpandSenderState& state, u32 workers);
    Buffer encode(const PolyMessage& message);
    Buffer encode(const SeedMessage& message);
    Buffer encode(const RootOfflineMessage& message);
    Buffer encode(const RootOfflineMessage& message, u32 workers);
    // Internal single-use transport can reserve and pin its exact final wire
    // allocation while an earlier frame is in flight. The ordinary encode API
    // keeps allocating its own independent Buffer.
    std::size_t rootOfflineWireSize(const RootOfflineMessage& message);
    // Predict the terminal Root payload from valid sender parameters before
    // setup. Zero declines the early reservation; the completed message size
    // remains authoritative before encoding or transport.
    std::size_t forecastRootOfflineWireSize(const Params& params,
        bool leafInputsAreGadget) noexcept;
    Buffer encodeRootOfflineIntoBuffer(const RootOfflineMessage& message,
        Buffer&& reserved, u32 workers);
    // Opt-in final Root wire storage is still an ordinary owning Buffer and
    // can be moved into coproto. Only this one reservation asks the allocator
    // for CUDA page-locked pages; a decline returns the usual Buffer storage.
    Buffer reserveRootCudaWireBuffer(std::size_t bytes, u64 senderRunId,
        bool& cudaOwned, bool recordSelection = true);
    // Shrink the logical wire without reallocating or copying its CUDA-owned
    // pages. The owning pool also contracts the active provenance range.
    bool shrinkRootCudaWireBuffer(Buffer& reserved,
        std::size_t exactBytes) noexcept;
    bool isRootCudaWireHostRange(const void* pointer,
        std::size_t bytes) noexcept;
    void recordRootCudaWireDirectDownload(const void* pointer,
        std::size_t bytes, bool completed) noexcept;

    struct RootWireCudaAllocEvidence
    {
        u64 mSenderRunId = 0;
        u64 mWireBytes = 0;
        u64 mAllocationBeginNs = 0;
        u64 mAllocationEndNs = 0;
        u64 mAllocationCpuNs = 0;
        u64 mExpectedDirectDownloadBytes = 0;
        u64 mExpectedDirectDownloadCalls = 0;
        u64 mDirectDownloadBytes = 0;
        u64 mDirectDownloadCalls = 0;
        u64 mEarlyForecastBytes = 0;
        u64 mEarlyJoinWaitNs = 0;
        bool mRequested = false;
        bool mEligible = false;
        bool mSelected = false;
        bool mDeclined = false;
        bool mEarlyRequested = false;
        bool mEarlyEligible = false;
        bool mEarlyLaunched = false;
        bool mEarlyAdopted = false;
    };
    void resetRootWireCudaAllocEvidence(u64 senderRunId,
        bool requested) noexcept;
    void noteRootWireCudaAllocEligibility(u64 senderRunId,
        std::size_t wireBytes, bool eligible) noexcept;
    void noteRootWireCudaEarlyPlan(u64 senderRunId, bool requested,
        bool eligible, std::size_t forecastBytes, bool launched) noexcept;
    void noteRootWireCudaEarlyJoin(u64 senderRunId, u64 joinWaitNs,
        bool adopted) noexcept;
    void noteRootWireCudaExpectedDownloads(u64 senderRunId,
        const RootOfflineMessage& message);
    RootWireCudaAllocEvidence rootWireCudaAllocEvidenceSnapshot() noexcept;

    struct RootWirePinOverlapEvidence
    {
        u64 mSenderRunId = 0;
        u64 mWireBytes = 0;
        u64 mPinBeginNs = 0;
        u64 mPinEndNs = 0;
        u64 mPinCpuNs = 0;
        u64 mJoinWaitNs = 0;
        bool mRequested = false;
        bool mEligible = false;
        bool mLaunched = false;
        bool mAlreadyPinned = false;
        bool mPinSucceeded = false;
        bool mSelected = false;
    };
    // Snapshot is stable after LogVoleRingSender::offline completes. The run ID
    // prevents a caller from attributing a previous process-local setup to a
    // different offline run.
    RootWirePinOverlapEvidence rootWirePinOverlapEvidenceSnapshot();
    Buffer encode(const RootDigestMessage& message);
    Buffer encode(const RootResponseMessage& message);

    bool decode(std::span<const u8> payload, KeyDeriveRequest& message);
    bool decode(std::span<const u8> payload, KeyDeriveResponse& message);
    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message);
    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message, u32 workers);
    // Internal socket route. Validate dimensions and coefficient spans first,
    // then retain the received bytes without allocating host polynomials.
    bool decodeShrinkExpandOfflineForTransport(Buffer&& payload,
        ShrinkExpandOfflineMessage& message, u32 workers);
    bool decode(std::span<const u8> payload, PolyMessage& message);
    bool decode(std::span<const u8> payload, SeedMessage& message);
    bool decode(std::span<const u8> payload, RootOfflineMessage& message);
    bool decode(std::span<const u8> payload, RootOfflineMessage& message, u32 workers);
    // Internal socket route: retain the selected complete Root tensor segments
    // in the independently received Buffer until their first GPU or host consumer.
    bool decodeRootOfflineForTransport(Buffer&& payload,
        RootOfflineMessage& message, u32 workers);
    bool decode(std::span<const u8> payload, RootDigestMessage& message);
    bool decode(std::span<const u8> payload, RootResponseMessage& message);

    bool keyDerivePayloadSize(const RingParams& params, u32 tau, u64& out);
    bool shrinkExpandOfflinePayloadSize(const ShrinkExpandParams& params, u64& out);
    bool rootOfflinePayloadSize(const ShrinkExpandParams& params, u32 tauHi, u64& out);
    bool polyPayloadSize(const RingParams& params, u64& out);
    bool rootDigestPayloadSize(const RingParams& params, u64& out);
    bool rootResponsePayloadSize(const RingParams& params, u64& out);

    PolyMessage makePolyMessage(const RingParams& params, const RnsPoly& poly);
    bool readPolyMessage(const RingParams& params, PolyMessage& message, RnsPoly& out);
}
