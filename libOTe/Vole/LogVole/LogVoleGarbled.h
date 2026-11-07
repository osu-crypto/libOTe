#pragma once
#include "libOTe/Vole/LogVole/LogVoleIdentity.h"

#include "libOTe/Vole/LogVole/LogVole.h"

#include <array>

namespace osuCrypto::LogVole
{
    namespace gpu { class GpuStream; }
    // An additive label in Z_p^3, stored without truncation or hashing. This is
    // not an XOR/free-XOR block. The supported parameter sets target 128-bit
    // computational security under the existing semi-honest LogVole assumptions.
    using GarbledLabel = std::array<u64, 3>;

    struct GarbledLabelLayout
    {
        u64 mLabelCount = 0;
        u32 mSlotsPerRing = 0;

        GarbledLabelLayout() = default;
        GarbledLabelLayout(u64 labelCount, u32 slotsPerRing);
        u64 labelsPerRing() const { return mSlotsPerRing / 3; }
        u64 ringCount() const;
        u64 scalarCount() const;
        u64 scalarIndex(u64 label, u32 component = 0) const;
    };

    // Adjacent triples inside each ring, followed by N % 3 unused scalars.
    // Retaining this small padding lets the GPU publish labels directly from
    // CRT decoding. Device consumers use the same scalarIndex formula.
    // Pass the same batch to successive queries to reuse host output storage.
    // A batch being filled must not be read until its coroutine completes.
    struct GarbledLabelBatch
    {
        GarbledLabelLayout mLayout;
        u64 mModulus = 0;
        CivoleSid mSid = 0;
        CommunicationStats mComm;
        AlignedUnVec<u64> mScalars;
        std::shared_ptr<void> mDevice; // gpu::DeviceScalars, scalarCount() words

        u64 size() const { return mLayout.mLabelCount; }
        void wait(); // Complete device production without downloading.
        // Materialize device scalars on the caller's reusable reader stream.
        void fetch(gpu::GpuStream& stream);
        GarbledLabel label(u64 i) const;
        // Garbler helper: derive the label for a field value from its zero label.
        GarbledLabel labelForValue(u64 i, u64 value, const GarbledLabel& deltas) const;
    };
}

namespace osuCrypto
{
    class LogVoleGarbledSender
    {
    public:
        explicit LogVoleGarbledSender(LogVoleOptions options);
        const LogVoleOptions& options() const { return mOptions; }
        LogVoleGarbledSender(const LogVoleGarbledSender&) = delete;
        LogVoleGarbledSender& operator=(const LogVoleGarbledSender&) = delete;
        bool mKeepOutputOnDevice = false;

        // Samples three independent uniform nonzero deltas from this private
        // PRNG and CRT-encodes their repeating triple into the leaf key.
        task<> offline(macoro::thread_pool& executor, std::span<u8> setupResults, PRNG& prng, Socket& sock);
        task<> send(macoro::thread_pool& executor, std::span<LogVole::LheDecryptBuffer> buffers, std::span<LogVole::ZpDecodeBuffer> unwrapBuffers,
            LogVole::GarbledLabelBatch& zeroLabels, PRNG& prng, Socket& sock);

        u64 modulus() const { return mModulus; }
        // Numeric projection is diagnostic only, not globally unique.
        u64 configureCacheRunId() const { return mConfigureCacheRunId.mValue; }
        LogVole::ProtocolCacheRunId configureCacheIdentity() const { return mConfigureCacheRunId; }
        bool nativeSealBundleAtConfigure() const { return mNativeSealBundleAtConfigure; }
        const LogVole::GarbledLabel& deltas() const;
        const LogVole::GarbledLabelLayout& layout() const { return mLayout; }
        bool gpuSetupTopSk1Selected() const
        {
            return mState.mLogVoleState.mShrinkExpandState.mTopSk1Device != nullptr;
        }

    private:
        LogVoleOptions mOptions;
        std::shared_ptr<const LogVole::ZpCrtContext> mConfigureFactoryOwner;
        LogVole::CivoleParams mParams;
        LogVole::CivoleSenderState mState;
        LogVole::GarbledLabelLayout mLayout;
        LogVole::GarbledLabel mDeltas{};
        u64 mModulus = 0;
        LogVole::ProtocolCacheRunId mConfigureCacheRunId = 0;
        bool mNativeSealBundleAtConfigure = false;
        LogVole::CivoleSid mNextSid = 0;
        bool mHasOffline = false;
    };

    class LogVoleGarbledReceiver
    {
    public:
        explicit LogVoleGarbledReceiver(LogVoleOptions options);
        const LogVoleOptions& options() const { return mOptions; }
        LogVoleGarbledReceiver(const LogVoleGarbledReceiver&) = delete;
        LogVoleGarbledReceiver& operator=(const LogVoleGarbledReceiver&) = delete;
        bool mKeepOutputOnDevice = false;
        // Optional gpu::DeviceScalars containing exactly labelCount field
        // values. The caller guarantees each is < modulus(); pass an empty x
        // span to receive(). Production on another stream is ordered internally.
        std::shared_ptr<void> mInputDevice;

        task<> offline(Socket& sock);
        // a[i][j] = b[i][j] + x[i] * delta[j] mod p, j = 0,1,2.
        // For Boolean garbling each x[i] is a bit; field-valued inputs are also
        // supported. Host inputs are range-checked before a SID is consumed.
        task<> receive(macoro::thread_pool& executor, std::span<LogVole::LheDecryptBuffer> lheBuffers,
            std::span<LogVole::LencEvalBuffer> lencBuffers, std::span<LogVole::RootZetaBuffer> zetaBuffers, std::span<LogVole::ZpEncodeBuffer> wrapBuffers, std::span<LogVole::ZpDecodeBuffer> unwrapBuffers, span<const u64> x, LogVole::GarbledLabelBatch& labels,
            PRNG& prng, Socket& sock);
        u64 modulus() const { return mModulus; }
        // Numeric projection is diagnostic only, not globally unique.
        u64 configureCacheRunId() const { return mConfigureCacheRunId.mValue; }
        LogVole::ProtocolCacheRunId configureCacheIdentity() const { return mConfigureCacheRunId; }
        bool nativeSealBundleAtConfigure() const { return mNativeSealBundleAtConfigure; }
        const LogVole::GarbledLabelLayout& layout() const { return mLayout; }

    private:
        LogVoleOptions mOptions;
        std::shared_ptr<const LogVole::ZpCrtContext> mConfigureFactoryOwner;
        LogVole::CivoleParams mParams;
        LogVole::CivoleReceiverState mState;
        LogVole::GarbledLabelLayout mLayout;
        u64 mModulus = 0;
        LogVole::ProtocolCacheRunId mConfigureCacheRunId = 0;
        bool mNativeSealBundleAtConfigure = false;
        LogVole::CivoleSid mNextSid = 0;
        bool mHasOffline = false;
    };
}
