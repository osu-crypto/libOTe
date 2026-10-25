#pragma once

#include "libOTe/Vole/LogVole/LogVole.h"

#include <array>

namespace osuCrypto::LogVole
{
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
        void fetch(); // Materialize host scalars when output was kept on device.
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
        LogVoleGarbledSender() = default;
        LogVoleGarbledSender(const LogVoleGarbledSender&) = delete;
        LogVoleGarbledSender& operator=(const LogVoleGarbledSender&) = delete;
        bool mKeepOutputOnDevice = false;

        void configure(u64 labelCount, u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed);
        // Samples three independent uniform nonzero deltas from this private
        // PRNG and CRT-encodes their repeating triple into the leaf key.
        task<> offline(PRNG& prng, Socket& sock);
        task<> send(LogVole::GarbledLabelBatch& zeroLabels, PRNG& prng, Socket& sock);

        u64 modulus() const { return mModulus; }
        u64 configureCacheRunId() const { return mConfigureCacheRunId; }
        bool nativeSealBundleAtConfigure() const { return mNativeSealBundleAtConfigure; }
        const LogVole::GarbledLabel& deltas() const;
        const LogVole::GarbledLabelLayout& layout() const { return mLayout; }
        bool gpuSetupTopSk1Selected() const
        {
            return mState.mLogVoleState.mShrinkExpandState.mTopSk1Device != nullptr;
        }

    private:
        LogVole::CivoleParams mParams;
        LogVole::CivoleSenderState mState;
        LogVole::GarbledLabelLayout mLayout;
        LogVole::GarbledLabel mDeltas{};
        u64 mModulus = 0;
        u64 mConfigureCacheRunId = 0;
        bool mNativeSealBundleAtConfigure = false;
        LogVole::CivoleSid mNextSid = 0;
        bool mHasOffline = false;
    };

    class LogVoleGarbledReceiver
    {
    public:
        LogVoleGarbledReceiver() = default;
        LogVoleGarbledReceiver(const LogVoleGarbledReceiver&) = delete;
        LogVoleGarbledReceiver& operator=(const LogVoleGarbledReceiver&) = delete;
        bool mKeepOutputOnDevice = false;
        // Optional gpu::DeviceScalars containing exactly labelCount field
        // values. The caller guarantees each is < modulus(); pass an empty x
        // span to receive(). Production on another stream is ordered internally.
        std::shared_ptr<void> mInputDevice;

        void configure(u64 labelCount, u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed);
        task<> offline(Socket& sock);
        // a[i][j] = b[i][j] + x[i] * delta[j] mod p, j = 0,1,2.
        // For Boolean garbling each x[i] is a bit; field-valued inputs are also
        // supported. Host inputs are range-checked before a SID is consumed.
        task<> receive(span<const u64> x, LogVole::GarbledLabelBatch& labels,
            PRNG& prng, Socket& sock);
        u64 modulus() const { return mModulus; }
        u64 configureCacheRunId() const { return mConfigureCacheRunId; }
        bool nativeSealBundleAtConfigure() const { return mNativeSealBundleAtConfigure; }
        const LogVole::GarbledLabelLayout& layout() const { return mLayout; }

    private:
        LogVole::CivoleParams mParams;
        LogVole::CivoleReceiverState mState;
        LogVole::GarbledLabelLayout mLayout;
        u64 mModulus = 0;
        u64 mConfigureCacheRunId = 0;
        bool mNativeSealBundleAtConfigure = false;
        LogVole::CivoleSid mNextSid = 0;
        bool mHasOffline = false;
    };
}
