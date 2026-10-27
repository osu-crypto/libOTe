#include "libOTe/Vole/LogVole/LogVoleGarbled.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <stdexcept>

namespace osuCrypto::LogVole
{
    GarbledLabelLayout::GarbledLabelLayout(u64 count, u32 slots)
        : mLabelCount(count), mSlotsPerRing(slots)
    {
        if (!count || slots < 4 || (slots & (slots - 1)) ||
            ringCount() > std::numeric_limits<u32>::max() ||
            ringCount() > std::numeric_limits<std::size_t>::max() / sizeof(u64) / slots)
            throw std::invalid_argument("invalid garbled-label count or ring size");
    }

    u64 GarbledLabelLayout::ringCount() const
    {
        const u64 perRing = labelsPerRing();
        return perRing ? mLabelCount / perRing + (mLabelCount % perRing != 0) : 0;
    }

    u64 GarbledLabelLayout::scalarCount() const { return ringCount() * mSlotsPerRing; }

    u64 GarbledLabelLayout::scalarIndex(u64 label, u32 component) const
    {
        if (label >= mLabelCount || component >= 3 || !labelsPerRing())
            throw std::out_of_range("garbled-label index is out of range");
        return label / labelsPerRing() * mSlotsPerRing + label % labelsPerRing() * 3 + component;
    }

    void GarbledLabelBatch::wait()
    {
        if (!mDevice) return;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::waitScalars(*std::static_pointer_cast<gpu::DeviceScalars>(mDevice))) return;
#endif
        throw std::runtime_error("could not complete garbled labels on device");
    }

    void GarbledLabelBatch::fetch()
    {
        if (!mDevice) return;
#if defined(ENABLE_LOGVOLE_CUDA)
        mScalars.resize(mLayout.scalarCount());
        if (gpu::fetchScalars(*std::static_pointer_cast<gpu::DeviceScalars>(mDevice),
                {mScalars.data(), mScalars.size()})) return;
#endif
        throw std::runtime_error("could not fetch garbled labels from device");
    }

    GarbledLabel GarbledLabelBatch::label(u64 i) const
    {
        const u64 base = mLayout.scalarIndex(i);
        if (mScalars.size() != mLayout.scalarCount())
            throw std::logic_error("fetch garbled labels before reading them on the host");
        return {mScalars[base], mScalars[base + 1], mScalars[base + 2]};
    }

    GarbledLabel GarbledLabelBatch::labelForValue(u64 i, u64 value, const GarbledLabel& deltas) const
    {
        if (!mModulus || value >= mModulus ||
            std::any_of(deltas.begin(), deltas.end(), [&](u64 d) { return !d || d >= mModulus; }))
            throw std::invalid_argument("garbled-label field value or delta is invalid");
        auto result = label(i);
        const seal::Modulus p(mModulus);
        for (u32 j = 0; j < 3; ++j) result[j] = mulAddMod(value, deltas[j], result[j], p);
        return result;
    }

    namespace
    {
        void configureGarbled(u64 count, u32 threads, CivoleSetting setting,
            CivoleParams& params, GarbledLabelLayout& layout, u64& modulus,
            bool& nativeBundleCommitted)
        {
            CivoleParams next;
            ZpCrtContext selected{};
            if (!makeCivoleParams(setting, next, std::max(threads, 1u)) ||
                !makeZpCrtContext(next.mLogVole.mShrinkExpand.mRing,
                    next.mLogVole.mShrinkExpand.mPlaintextModulusBits, selected) ||
                selected.mPlaintextModulus <= (u64{1} << 43))
                throw std::invalid_argument("garbled labels require a supported 128-bit parameter set");
            GarbledLabelLayout shape(count, next.mLogVole.mShrinkExpand.mRing.mPolyModulusDegree);
            next.mLogVole.mTotalLabelCount = shape.scalarCount();
            const auto& shrink = next.mLogVole.mShrinkExpand;
            const u64 minimumWidth = shrink.mAlpha * (shrink.mTau - 1) * shrink.mRing.mCoeffModulusBits.size();
            next.mLogVole.mW = static_cast<u32>(std::max(shape.ringCount(), minimumWidth));
            // The ordinary offline path checks the final padded recursion as
            // well. Check the size-dependent NoGoldenSeed budget up front.
            if (!validateCt2SeedMode(next.mLogVole))
                throw std::invalid_argument("garbled-label size exceeds the selected correctness budget");
            params = std::move(next);
            layout = shape;
            modulus = selected.mPlaintextModulus;
            nativeBundleCommitted = selected.mNativeSealBundleCommitted;
        }

        std::array<u8, 32> garbledHeader(const GarbledLabelLayout& layout, u64 modulus)
        {
            const std::array<u64, 4> words{0x4c56474300000001ULL,
                layout.mLabelCount, layout.mSlotsPerRing, modulus};
            std::array<u8, 32> bytes{};
            for (u32 w = 0; w < words.size(); ++w)
                for (u32 b = 0; b < 8; ++b) bytes[8 * w + b] = static_cast<u8>(words[w] >> (8 * b));
            return bytes;
        }

        u64 sampleNonzero(PRNG& prng, u64 p)
        {
            const u64 range = p - 1, threshold = (u64{0} - range) % range;
            u64 sample;
            do { sample = prng.get<u64>(); } while (sample < threshold);
            return sample % range + 1;
        }

        GarbledLabelBatch outputBatch(const GarbledLabelLayout& shape, u64 modulus, CivoleSid sid)
        {
            GarbledLabelBatch out;
            out.mLayout = shape;
            out.mModulus = modulus;
            out.mSid = sid;
            return out;
        }
    }
}

namespace osuCrypto
{
    using namespace LogVole;

    void LogVoleGarbledSender::configure(u64 n, u32 threads, CivoleSetting setting)
    {
        const auto inheritedRun = currentProtocolCacheScope().mRunId;
        const auto configureRun = inheritedRun ? inheritedRun :
            allocateProtocolCacheRunId();
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Sender, configureRun);
        bool nativeBundleCommitted = false;
        configureGarbled(n, threads, setting, mParams, mLayout, mModulus,
            nativeBundleCommitted);
        mConfigureCacheRunId = configureRun;
        mNativeSealBundleAtConfigure = nativeBundleCommitted;
        mState = {};
        mDeltas = {};
        mNextSid = 0;
        mHasOffline = false;
    }

    const GarbledLabel& LogVoleGarbledSender::deltas() const
    {
        if (!mHasOffline) throw std::logic_error("garbled-label deltas require offline setup");
        return mDeltas;
    }

    task<> LogVoleGarbledSender::offline(PRNG& prng, Socket& sock)
    {
        if (!mLayout.mLabelCount) throw std::logic_error("configure the garbled-label sender first");
        auto meta = sock.fork();
        auto header = garbledHeader(mLayout, mModulus);
        co_await meta.send(coproto::copy(header));
        std::array<u8, 1> ack{};
        co_await meta.recv(ack);
        if (ack[0] != 1) throw std::invalid_argument("garbled-label configurations do not match");
        GarbledLabel deltas;
        for (auto& delta : deltas) delta = sampleNonzero(prng, mModulus);
        std::vector<u64> slots;
        CivoleSenderOfflineInput input;
        input.mParams = mParams;
        input.mW = mLayout.scalarCount();
        bool prepareDeltaOnDevice = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* deviceDelta = std::getenv("LV_GPU_SETUP_DELTA_DEVICE");
        prepareDeltaOnDevice = gpu::enabled() && (!deviceDelta || deviceDelta[0] != '0');
#endif
        if (prepareDeltaOnDevice) input.mGarbledDeltaPattern = deltas;
        else
        {
            slots.assign(mLayout.mSlotsPerRing, 0);
            for (u64 i = 0; i < mLayout.labelsPerRing() * 3; ++i) slots[i] = deltas[i % 3];
            input.mDeltaSlots = slots;
        }
        CivoleSenderState state;
        co_await civoleSenderOffline(input, state, prng, sock);
        mState = std::move(state);
        mDeltas = deltas;
        mNextSid = 0;
        mHasOffline = true;
    }

    task<> LogVoleGarbledSender::send(GarbledLabelBatch& labels, PRNG& prng, Socket& sock)
    {
        if (!mHasOffline || mNextSid == std::numeric_limits<CivoleSid>::max())
            throw std::logic_error("garbled-label sender has no available offline session");
        const auto sid = mNextSid++;
        auto next = outputBatch(mLayout, mModulus, sid);
        CivoleSenderReleaseOptions options;
        options.mKeepKeysOnDevice = mKeepOutputOnDevice;
        if (!mKeepOutputOnDevice)
        {
            next.mScalars = std::move(labels.mScalars);
            next.mScalars.resize(mLayout.scalarCount());
            options.mKeysOut = {next.mScalars.data(), next.mScalars.size()};
        }
        CivoleSenderReleaseOutput released;
        co_await civoleSenderRelease(mState, sid, released, prng, sock, options);
        next.mDevice = std::move(released.mKeysDevice);
        next.mComm = released.mComm;
        if (!next.mDevice && mKeepOutputOnDevice) next.mScalars = std::move(mState.mReleasedKeys);
        labels = std::move(next);
    }

    void LogVoleGarbledReceiver::configure(u64 n, u32 threads, CivoleSetting setting)
    {
        const auto inheritedRun = currentProtocolCacheScope().mRunId;
        const auto configureRun = inheritedRun ? inheritedRun :
            allocateProtocolCacheRunId();
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, configureRun);
        bool nativeBundleCommitted = false;
        configureGarbled(n, threads, setting, mParams, mLayout, mModulus,
            nativeBundleCommitted);
        mConfigureCacheRunId = configureRun;
        mNativeSealBundleAtConfigure = nativeBundleCommitted;
        mState = {};
        mInputDevice.reset();
        mNextSid = 0;
        mHasOffline = false;
    }

    task<> LogVoleGarbledReceiver::offline(Socket& sock)
    {
        if (!mLayout.mLabelCount) throw std::logic_error("configure the garbled-label receiver first");
        auto meta = sock.fork();
        std::array<u8, 32> header{};
        co_await meta.recv(header);
        const std::array<u8, 1> ack{static_cast<u8>(header == garbledHeader(mLayout, mModulus))};
        co_await meta.send(coproto::copy(ack));
        if (!ack[0]) throw std::invalid_argument("garbled-label configurations do not match");
        CivoleReceiverOfflineInput input;
        input.mParams = mParams;
        input.mW = mLayout.scalarCount();
        CivoleReceiverState state;
        co_await civoleReceiverOffline(input, state, sock);
        if (state.mW != mLayout.scalarCount()) throw std::invalid_argument("garbled-label width mismatch");
        mState = std::move(state);
        mNextSid = 0;
        mHasOffline = true;
    }

    task<> LogVoleGarbledReceiver::receive(span<const u64> x, GarbledLabelBatch& labels,
        PRNG& prng, Socket& sock)
    {
        if (!mHasOffline || mNextSid == std::numeric_limits<CivoleSid>::max())
            throw std::logic_error("garbled-label receiver has no available offline session");
        if (mInputDevice ? !x.empty() : x.size() != mLayout.mLabelCount)
            throw std::invalid_argument("garbled-label input size does not match configuration");
        if (!mInputDevice && std::any_of(x.begin(), x.end(), [&](u64 v) { return v >= mModulus; }))
            throw std::invalid_argument("garbled-label input is outside Z_p");
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mInputDevice && (!gpu::enabled() ||
            std::static_pointer_cast<gpu::DeviceScalars>(mInputDevice)->count() != mLayout.mLabelCount))
            throw std::invalid_argument("garbled-label device input has the wrong size or no GPU backend");
#else
        if (mInputDevice) throw std::invalid_argument("garbled-label device input requires CUDA");
#endif
        const auto sid = mNextSid++;
        auto next = outputBatch(mLayout, mModulus, sid);
        CivoleReceiverSetXOptions options;
        options.mGarbledInput = true;
        options.mKeepMacsOnDevice = mKeepOutputOnDevice;
        options.mXDevice = mInputDevice;
        options.mXDeviceCount = mInputDevice ? mLayout.mLabelCount : 0;
        if (!mKeepOutputOnDevice)
        {
            next.mScalars = std::move(labels.mScalars);
            next.mScalars.resize(mLayout.scalarCount());
            options.mMacsOut = {next.mScalars.data(), next.mScalars.size()};
        }
        CivoleReceiverSetXOutput received;
        co_await civoleReceiverSetX(mState, sid, x, received, prng, sock, options);
        next.mDevice = std::move(received.mMacsDevice);
        next.mComm = received.mComm;
        if (!next.mDevice && mKeepOutputOnDevice) next.mScalars = std::move(received.mMacs);
        labels = std::move(next);
    }
}
