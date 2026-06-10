#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "seal/seal.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole
{
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
        std::shared_ptr<seal::SEALContext> mBatchingContext;
    };

    struct CivoleParams
    {
        Params mLogVole;
    };

    // Low-level CI-VOLE offline input for the sender. The scalar Delta is the
    // sender's global VOLE key, and mW is the requested output length.
    struct CivoleSenderOfflineInput
    {
        CivoleParams mParams;
        u64 mDelta = 0;
        u64 mW = 0;
    };

    struct CivoleReceiverOfflineInput
    {
        CivoleParams mParams;
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
    };

    struct CivoleReceiverSetXOutput
    {
        CivoleSid mSid = 0;
        u64 mModulus = 0;
        AlignedUnVec<u64> mValues;
        AlignedUnVec<u64> mMacs;
        CommunicationStats mComm;
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

        u64 mRequestSize = 0;
        u32 mPlaintextModulusBits = 55;
        u64 mModulus = 0;
        u64 mDelta = 0;
        u32 mNumThreads = 1;
        LogVole::CivoleSid mNextSid = 0;
        LogVole::CommunicationStats mLastOnlineComm;
        State mState = State::Default;
        LogVole::CivoleParams mParams;
        LogVole::CivoleSenderState mOfflineState;

        // Select the number of VOLE outputs, requested plaintext modulus bit
        // count, and worker thread count. The actual prime p can be read with
        // modulus() after configuration.
        void configure(
            u64 n,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1);

        bool isConfigured() const { return mState != State::Default; }
        bool hasOffline() const { return mState == State::Offline; }
        u64 modulus() const { return mModulus; }

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

        u64 mRequestSize = 0;
        u32 mPlaintextModulusBits = 55;
        u64 mModulus = 0;
        u32 mNumThreads = 1;
        LogVole::CivoleSid mNextSid = 0;
        LogVole::CommunicationStats mLastOnlineComm;
        State mState = State::Default;
        LogVole::CivoleParams mParams;
        LogVole::CivoleReceiverState mOfflineState;

        // Select the number of VOLE outputs, requested plaintext modulus bit
        // count, and worker thread count. The actual prime p can be read with
        // modulus() after configuration.
        void configure(
            u64 n,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1);

        bool isConfigured() const { return mState != State::Default; }
        bool hasOffline() const { return mState == State::Offline; }
        u64 modulus() const { return mModulus; }

        // Run reusable offline setup matching the sender's offline phase.
        task<> offline(Socket& sock);

        // Online phase. x must have the configured size and each x[i] must be
        // in Z_p. Writes receiver MACs a.
        task<> receive(
            span<const u64> x,
            span<u64> a,
            PRNG& prng,
            Socket& sock);

        void clear();
    };
}

namespace osuCrypto::LogVole
{

    // Build default CI-VOLE parameters. These parameters target the LogVole
    // paper's Ring-LWE-style construction and use the requested worker count.
    bool makeDefaultCivoleParams(CivoleParams& out, u32 workerThreads = 1);
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
        Socket& sock);

    task<> civoleReceiverSetX(
        CivoleReceiverState& state,
        CivoleSid sid,
        std::span<const u64> x,
        CivoleReceiverSetXOutput& output,
        PRNG& prng,
        Socket& sock);
}
