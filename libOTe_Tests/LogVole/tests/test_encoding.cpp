#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/BufferingSocket.h"
#include "macoro/sync_wait.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    class ScopedEnvironmentValue
    {
    public:
        ScopedEnvironmentValue(const char* name, const char* value) : mName(name)
        {
            if (const char* old = std::getenv(name)) { mHadOld = true; mOld = old; }
            ::tests_libOTe::logvole_test::setEnvironment(name, value, 1);
        }
        ~ScopedEnvironmentValue()
        {
            if (mHadOld) ::tests_libOTe::logvole_test::setEnvironment(mName.c_str(), mOld.c_str(), 1);
            else ::tests_libOTe::logvole_test::unsetEnvironment(mName.c_str());
        }
    private:
        std::string mName, mOld;
        bool mHadOld = false;
    };

    KeyDeriveRequest make_keyderive_request()
    {
        KeyDeriveRequest message{};
        message.mPolyModulusDegree = 1024;
        message.mCoeffModulusCount = 2;
        message.mTau = 3;
        assignValues<std::uint64_t>(message.mDCoeffs, { 1, 2, 3, 4, 5 });
        return message;
    }

    KeyDeriveResponse make_keyderive_response()
    {
        KeyDeriveResponse message{};
        message.mPolyModulusDegree = 2048;
        message.mCoeffModulusCount = 3;
        message.mTau = 4;
        assignValues<std::uint64_t>(message.mMNttCoeffs, { 9, 8, 7, 6 });
        return message;
    }

    RingParams make_ring()
    {
        RingParams ring{};
        ring.mPolyModulusDegree = 8;
        assignValues<int>(ring.mCoeffModulusBits, { 30, 31 });
        return ring;
    }

    RnsPoly make_poly(const RingParams& ring, std::uint64_t seed)
    {
        RnsPoly poly{};
        poly.mCoeffs.resize(ringPolyCoeffCount(ring));
        for (std::size_t idx = 0; idx < poly.mCoeffs.size(); ++idx)
        {
            poly.mCoeffs[idx] = seed + static_cast<std::uint64_t>(idx * 17);
        }
        return poly;
    }

    RingTensor make_tensor(const RingParams& ring, std::uint32_t rows, std::uint32_t cols, std::uint64_t seed)
    {
        RingTensor tensor{};
        tensor.mRows = rows;
        tensor.mCols = cols;
        tensor.mPolys.reserve(static_cast<std::size_t>(rows) * cols);
        for (std::uint32_t idx = 0; idx < rows * cols; ++idx)
        {
            tensor.mPolys.push_back(make_poly(ring, seed + idx * 101));
        }
        return tensor;
    }

    void expect_poly_equal(const RnsPoly& lhs, const RnsPoly& rhs)
    {
        LOGVOLE_REQUIRE_EQ(lhs.mCoeffs.size(), rhs.mCoeffs.size());
        for (std::size_t idx = 0; idx < lhs.mCoeffs.size(); ++idx)
        {
            LOGVOLE_EXPECT_EQ(lhs.mCoeffs[idx], rhs.mCoeffs[idx]);
        }
    }

    void expect_tensor_equal(const RingTensor& lhs, const RingTensor& rhs)
    {
        LOGVOLE_EXPECT_EQ(lhs.mRows, rhs.mRows);
        LOGVOLE_EXPECT_EQ(lhs.mCols, rhs.mCols);
        LOGVOLE_REQUIRE_EQ(lhs.mPolys.size(), rhs.mPolys.size());
        for (std::size_t idx = 0; idx < lhs.mPolys.size(); ++idx)
        {
            expect_poly_equal(lhs.mPolys[idx], rhs.mPolys[idx]);
        }
    }

    void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t value)
    {
        for (std::uint32_t byte = 0; byte < sizeof(value); ++byte)
        {
            out.push_back(static_cast<std::uint8_t>((value >> (8u * byte)) & 0xFFu));
        }
    }

    void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t value)
    {
        for (std::uint32_t byte = 0; byte < sizeof(value); ++byte)
        {
            out.push_back(static_cast<std::uint8_t>((value >> (8u * byte)) & 0xFFu));
        }
    }

    void expect_bytes_equal(
        std::span<const std::uint8_t> actual,
        std::span<const std::uint8_t> expected)
    {
        LOGVOLE_REQUIRE_EQ(actual.size(), expected.size());
        const auto mismatch = std::mismatch(actual.begin(), actual.end(), expected.begin());
        if (mismatch.first != actual.end())
        {
            const auto idx = static_cast<std::size_t>(mismatch.first - actual.begin());
            LOGVOLE_EXPECT_EQ(*mismatch.first, *mismatch.second) << "byte idx " << idx;
        }
    }

    std::span<const std::uint8_t> as_span(const std::vector<std::uint8_t>& bytes)
    {
        return std::span<const std::uint8_t>(bytes.data(), bytes.size());
    }

    std::size_t expect_offline_tensor_wire(
        std::span<const std::uint8_t> wire,
        std::size_t offset,
        const RingTensor& tensor)
    {
        // Build the existing wire layout independently with scalar byte shifts.
        // This catches matching encoder/decoder bugs in the memcpy path.
        std::vector<std::uint8_t> expected;
        append_u32_le(expected, tensor.mRows);
        append_u32_le(expected, tensor.mCols);
        std::uint32_t coeffCount = 0;
        for (const auto& poly : tensor.mPolys)
            coeffCount += static_cast<std::uint32_t>(poly.mCoeffs.size());
        append_u32_le(expected, coeffCount);
        for (const auto& poly : tensor.mPolys)
            for (auto coeff : poly.mCoeffs)
                append_u64_le(expected, coeff);
        LOGVOLE_REQUIRE_TRUE(offset <= wire.size());
        LOGVOLE_REQUIRE_TRUE(expected.size() <= wire.size() - offset);
        expect_bytes_equal(wire.subspan(offset, expected.size()), as_span(expected));
        return offset + expected.size();
    }

    template<typename Message>
    void expect_offline_decode_boundaries(
        std::span<const std::uint8_t> wire,
        std::size_t firstTensorOffset)
    {
        // Each truncated prefix must be rejected, including partial vector
        // lengths and partial coefficient words at either end of a tensor.
        for (std::size_t size = 0; size < wire.size(); ++size)
        {
            Message decoded{};
            LOGVOLE_EXPECT_FALSE(decode(wire.first(size), decoded));
        }
        std::vector<std::uint8_t> unaligned(wire.size() + 1);
        std::copy(wire.begin(), wire.end(), unaligned.begin() + 1);
        Message decoded{};
        LOGVOLE_REQUIRE_TRUE(decode(as_span(unaligned).subspan(1), decoded));
        const auto reencoded = encode(decoded);
        expect_bytes_equal(reencoded, wire);

        std::vector<std::uint8_t> bad(wire.begin(), wire.end());
        bad.push_back(0);
        LOGVOLE_EXPECT_FALSE(decode(as_span(bad), decoded));
        bad.pop_back();
        const auto overwrite_u32 = [&](std::size_t offset, std::uint32_t value) {
            for (std::size_t byte = 0; byte < sizeof(value); ++byte)
                bad[offset + byte] = static_cast<std::uint8_t>(value >> (8u * byte));
        };

        // Ring dimension zero; both an empty shape and a huge tensor shape
        // inconsistent with the actual encoded coefficients; vector count
        // larger than the available bytes. All fail before coefficient access.
        overwrite_u32(0, 0);
        LOGVOLE_EXPECT_FALSE(decode(as_span(bad), decoded));
        std::copy(wire.begin(), wire.end(), bad.begin());
        overwrite_u32(firstTensorOffset, 0);
        LOGVOLE_EXPECT_FALSE(decode(as_span(bad), decoded));
        std::copy(wire.begin(), wire.end(), bad.begin());
        overwrite_u32(firstTensorOffset, std::numeric_limits<std::uint32_t>::max());
        overwrite_u32(firstTensorOffset + sizeof(std::uint32_t), 2);
        LOGVOLE_EXPECT_FALSE(decode(as_span(bad), decoded));
        std::copy(wire.begin(), wire.end(), bad.begin());
        overwrite_u32(firstTensorOffset + 2u * sizeof(std::uint32_t),
                      std::numeric_limits<std::uint32_t>::max());
        LOGVOLE_EXPECT_FALSE(decode(as_span(bad), decoded));
    }

    void append_ring_le(std::vector<std::uint8_t>& bytes, const RingParams& ring)
    {
        append_u32_le(bytes, ring.mPolyModulusDegree);
        append_u32_le(bytes, static_cast<std::uint32_t>(ring.mCoeffModulusBits.size()));
        for (auto bits : ring.mCoeffModulusBits)
        {
            bytes.push_back(static_cast<std::uint8_t>(bits));
            bytes.push_back(static_cast<std::uint8_t>(bits >> 8u));
        }
    }

    void append_batch_le(std::vector<std::uint8_t>& bytes, const std::vector<RnsPoly>& polys)
    {
        std::uint32_t count = 0;
        for (const auto& poly : polys) count += static_cast<std::uint32_t>(poly.mCoeffs.size());
        append_u32_le(bytes, count);
        for (const auto& poly : polys)
            for (auto value : poly.mCoeffs) append_u64_le(bytes, value);
    }

    void append_tensor_le(std::vector<std::uint8_t>& bytes, const RingTensor& tensor)
    {
        append_u32_le(bytes, tensor.mRows);
        append_u32_le(bytes, tensor.mCols);
        append_batch_le(bytes, tensor.mPolys);
    }

    std::vector<std::uint8_t> scalar_wire(const ShrinkExpandOfflineMessage& message)
    {
        std::vector<std::uint8_t> bytes;
        const auto& params = message.mParams;
        append_ring_le(bytes, params.mRing);
        for (auto value : { params.mPlaintextModulusBits, params.mAlpha, params.mMu,
                params.mGadgetLogBase, params.mTau }) append_u32_le(bytes, value);
        bytes.push_back(params.mTruncateOneGadgetDigit ? 1u : 0u);
        bytes.push_back(params.mLeafInputsAreGadget ? 1u : 0u);
        bytes.push_back(static_cast<std::uint8_t>(params.mMode));
        append_u64_le(bytes, static_cast<std::uint64_t>(params.mNoiseBound));
        append_tensor_le(bytes, message.mCt1);
        append_u32_le(bytes, message.mLacct.mWidthPadded);
        append_u32_le(bytes, message.mLacct.mLevels);
        append_tensor_le(bytes, message.mLacct.mCt);
        return bytes;
    }

    std::vector<std::uint8_t> scalar_wire(const RootOfflineMessage& message)
    {
        std::vector<std::uint8_t> bytes;
        append_ring_le(bytes, message.mRing);
        for (auto value : { message.mTauHi, message.mGadgetLogBase,
                message.mPlaintextModulusBits, message.mLeftWidth, message.mRandomizerWidth })
            append_u32_le(bytes, value);
        append_tensor_le(bytes, message.mCtR);
        append_u32_le(bytes, message.mLacctLeft.mWidthPadded);
        append_u32_le(bytes, message.mLacctLeft.mLevels);
        append_tensor_le(bytes, message.mLacctLeft.mCt);
        append_tensor_le(bytes, message.mTopCt);
        append_u32_le(bytes, static_cast<std::uint32_t>(message.mPublicBStarNtt.size()));
        append_batch_le(bytes, message.mPublicBStarNtt);
        return bytes;
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    // Exercise the actual device-to-wire copy contract with a CPU-generated
    // exact oracle. The owner publishes host data only if the direct copy is
    // declined, matching the production lazy ciphertext interface.
    class TestRootDeviceTensor final : public LazyRingTensorHostState
    {
    public:
        explicit TestRootDeviceTensor(RingTensor host, bool allowCopy = true)
            : mHost(std::move(host)), mAllowCopy(allowCopy)
        {
            std::vector<std::uint64_t> coefficients;
            for (const auto& poly : mHost.mPolys)
                coefficients.insert(coefficients.end(), poly.mCoeffs.begin(), poly.mCoeffs.end());
            mBytes = coefficients.size() * sizeof(std::uint64_t);
            void* allocation = gpu::gpuMalloc(mBytes);
            if (!allocation) throw std::runtime_error("Root wire test device allocation failed");
            mDevice = std::shared_ptr<void>(allocation, [](void* p) { gpu::gpuFree(p); });
            gpu::GpuStream stream;
            if (!stream.raw() || !gpu::uploadSetupWire(
                    mDevice.get(), coefficients.data(), mBytes, stream) || !stream.sync())
                throw std::runtime_error("Root wire test device upload failed");
        }

        const RingTensor& get() const override
        {
            ++mHostRequests;
            return mHost;
        }

        bool copyCoefficientsTo(std::span<std::uint8_t> destination) const override
        {
            ++mCopyRequests;
            if (!mAllowCopy || destination.size() != mBytes) return false;
            gpu::GpuStream stream;
            return stream.raw() && gpu::downloadSetupWire(
                destination.data(), mDevice.get(), mBytes, stream) && stream.sync();
        }

        std::size_t hostRequests() const { return mHostRequests; }
        std::size_t copyRequests() const { return mCopyRequests; }

    private:
        RingTensor mHost;
        std::shared_ptr<void> mDevice;
        std::size_t mBytes = 0;
        bool mAllowCopy = true;
        mutable std::size_t mHostRequests = 0;
        mutable std::size_t mCopyRequests = 0;
    };
#endif

    template<typename Message>
    void expect_large_parallel_wire(const Message& message, std::size_t firstTensorOffset,
        CpuBenchmarkContext& telemetry, bool expectParallel)
    {
        const auto expected = scalar_wire(message);
        LOGVOLE_REQUIRE_TRUE(expected.size() > (std::size_t(1) << 20));
        const auto serial = encode(message, 1);
        for (auto workers : { 0u, 1u, 8u })
        {
            telemetry.reset();
            const auto wire = encode(message, workers);
            expect_bytes_equal(wire, as_span(expected));
            expect_bytes_equal(wire, serial);
#if defined(__linux__)
            LOGVOLE_EXPECT_EQ(telemetry.mWorkersChecked.load() != 0, expectParallel && workers > 1);
#endif
            LOGVOLE_EXPECT_EQ(telemetry.mWorkerSlots.load(), 0u);
            // Decode an independently produced, deliberately unaligned wire,
            // rather than feeding the implementation its own encoded buffer.
            std::vector<std::uint8_t> unaligned(expected.size() + 1u, 0xA5);
            std::copy(expected.begin(), expected.end(), unaligned.begin() + 1);
            telemetry.reset();
            Message decoded{};
            LOGVOLE_REQUIRE_TRUE(decode(as_span(unaligned).subspan(1), decoded, workers));
#if defined(__linux__)
            LOGVOLE_EXPECT_EQ(telemetry.mWorkersChecked.load() != 0, expectParallel && workers > 1);
#endif
            LOGVOLE_EXPECT_EQ(telemetry.mWorkerSlots.load(), 0u);
            expect_bytes_equal(as_span(scalar_wire(decoded)), as_span(expected));
        }

        // A small selection covers headers, a partial count, a partial word,
        // the middle of a large body, and the final word. Avoid the quadratic
        // all-prefix test used for the intentionally tiny fixtures above.
        const auto body = firstTensorOffset + 3u * sizeof(std::uint32_t);
        for (auto size : { std::size_t(0), std::size_t(1), firstTensorOffset - 1u,
                firstTensorOffset + 8u, body - 1u, body + 7u,
                body + (std::size_t(1) << 20) - 1u, expected.size() / 2u,
                expected.size() - 1u })
        {
            Message decoded{};
            LOGVOLE_EXPECT_FALSE(decode(as_span(expected).first(size), decoded, 8));
        }
        const auto rejectMutation = [&](std::size_t offset, std::uint32_t value) {
            auto bad = expected;
            for (unsigned byte = 0; byte < 4; ++byte)
                bad[offset + byte] = static_cast<std::uint8_t>(value >> (8u * byte));
            Message decoded{};
            LOGVOLE_EXPECT_FALSE(decode(as_span(bad), decoded, 8));
        };
        rejectMutation(0, 0);
        rejectMutation(firstTensorOffset, 0);
        rejectMutation(firstTensorOffset, std::numeric_limits<std::uint32_t>::max());
        rejectMutation(firstTensorOffset + 8u, std::numeric_limits<std::uint32_t>::max());
        auto trailing = expected;
        trailing.push_back(0);
        Message decoded{};
        LOGVOLE_EXPECT_FALSE(decode(as_span(trailing), decoded, 8));
    }

    void expect_parallel_offline_codec(const oc::CLP& cmd)
    {
        bool haveGpu = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool previousGpu = gpu::enabled();
        struct RestoreGpu { bool mPrevious; ~RestoreGpu() { gpu::setEnabled(mPrevious); } } restoreGpu{ previousGpu };
        gpu::setEnabled(cmd.getOr("gpu", 0) != 0);
        haveGpu = gpu::enabled();
#else
        (void)cmd;
#endif
        ScopedEnvironmentValue parallelCodec("LV_GPU_SETUP_PARALLEL_CODEC", "1");
        ScopedProtocolCacheScope roleScope(ProtocolCacheRole::Unspecified, currentProtocolCacheScope().mRunId);
        CpuBenchmarkContext telemetry;
        telemetry.mWorkerLimit = 8;
#if defined(__linux__)
        cpu_set_t cpus;
        CPU_ZERO(&cpus);
        LOGVOLE_REQUIRE_EQ(sched_getaffinity(0, sizeof(cpus), &cpus), 0);
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
            if (CPU_ISSET(cpu, &cpus)) telemetry.mCpus.push_back(cpu);
#endif
        struct RestoreTelemetry
        {
            CpuBenchmarkContext* mPrevious;
            ~RestoreTelemetry() { tCpuBenchmarkContext = mPrevious; }
        } restoreTelemetry{ tCpuBenchmarkContext };
        tCpuBenchmarkContext = &telemetry;
        const char* nativeCodec = std::getenv("LV_SETUP_MEMCPY_CODEC");
        const bool expectParallel = haveGpu && std::endian::native == std::endian::little &&
            (!nativeCodec || nativeCodec[0] != '0') && telemetry.mCpus.size() > 1u;

        RingParams ring{};
        ring.mPolyModulusDegree = 8192;
        assignValues<int>(ring.mCoeffModulusBits, { 55, 54, 53, 52 });
        ShrinkExpandOfflineMessage shrink{};
        shrink.mParams.mRing = ring;
        shrink.mParams.mPlaintextModulusBits = 51;
        shrink.mParams.mAlpha = 2;
        shrink.mParams.mMu = 7;
        shrink.mParams.mGadgetLogBase = 107;
        shrink.mParams.mTau = 2;
        shrink.mParams.mNumWorkerThreads = 37; // Local scheduling is not a wire field.
        shrink.mParams.mTruncateOneGadgetDigit = true;
        shrink.mParams.mLeafInputsAreGadget = true;
        shrink.mParams.mMode = ShrinkExpandMode::FullNoise;
        shrink.mParams.mNoiseBound = -0x1234567;
        // Each batch is >1 MiB. Odd task counts exercise uneven worker
        // partitions and make swapped or repeated polynomial offsets visible.
        shrink.mCt1 = make_tensor(ring, 7, 1, 0xEFCDAB8967452301ull);
        shrink.mLacct.mWidthPadded = 8;
        shrink.mLacct.mLevels = 3;
        shrink.mLacct.mCt = make_tensor(ring, 5, 3, 0x8001020304050607ull);
        const auto ringHeader = 8u + 2u * ring.mCoeffModulusBits.size();
        expect_large_parallel_wire(shrink, ringHeader + 20u + 3u + 8u, telemetry, expectParallel);

        RootOfflineMessage root{};
        root.mRing = ring;
        root.mTauHi = 2;
        root.mGadgetLogBase = 107;
        root.mPlaintextModulusBits = 51;
        root.mLeftWidth = 7;
        root.mRandomizerWidth = 3;
        root.mCtR = std::move(shrink.mCt1);
        root.mLacctLeft = std::move(shrink.mLacct);
        root.mTopCt = make_tensor(ring, 9, 1, 0xFFEEDDCCBBAA9988ull);
        for (std::uint64_t i = 0; i < 5; ++i)
            root.mPublicBStarNtt.push_back(make_poly(ring, 0x9000000000000000ull + 1234567u * i));
        expect_large_parallel_wire(root, ringHeader + 20u, telemetry, expectParallel);
    }
}

void LogVole_Encoding_SingletonOfflinePayloadBound(const oc::CLP&)
{
    ShrinkExpandSenderOfflineInput input;
    input.mParams.mRing.mPolyModulusDegree = 1024;
    assignValues<int>(input.mParams.mRing.mCoeffModulusBits, {30, 30});
    input.mParams.mPlaintextModulusBits = 20;
    input.mParams.mMu = 1;
    input.mParams.mTau = 2;
    input.mParams.mGadgetLogBase = 20;
    RingNttContext ctx;
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(input.mParams.mRing, ctx));
    input.mS = {deriveUniformPolyFromNonce(ctx, 0x53494e474c4553ull, 0x57495245u, 0)};
    for (bool truncated : {false, true})
    {
        input.mParams.mTruncateOneGadgetDigit = truncated;
        oc::PRNG prng(oc::block(0x53494e474c4553ull, truncated));
        ShrinkExpandOfflineMessage message;
        ShrinkExpandSenderState sender;
        LOGVOLE_REQUIRE_TRUE(prepareShrinkExpandSenderOffline(input, prng, message, sender));
        LOGVOLE_REQUIRE_EQ(message.mLacct.mWidthPadded, 2u);
        LOGVOLE_REQUIRE_EQ(message.mLacct.mLevels, 1u);
        std::uint64_t bound = 0;
        LOGVOLE_REQUIRE_TRUE(shrinkExpandOfflinePayloadSize(input.mParams, bound));
        const auto bytes = encode(message);
        LOGVOLE_REQUIRE_TRUE(bytes.size() <= bound);
        ShrinkExpandOfflineMessage decoded;
        LOGVOLE_REQUIRE_TRUE(decode(bytes, decoded));
        ShrinkExpandReceiverOfflineInput receiverInput;
        receiverInput.mParams = input.mParams;
        ShrinkExpandReceiverState receiver;
        LOGVOLE_REQUIRE_TRUE(finalizeShrinkExpandReceiverOffline(
            receiverInput, std::move(decoded), receiver));
    }
}

void LogVole_Encoding_KeyDeriveRequestRoundTrip(const oc::CLP&)
{
    const auto message = make_keyderive_request();
    const auto encoded = encode(message);

    KeyDeriveRequest decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_TRUE(rangesEqual(decoded.mDCoeffs, message.mDCoeffs));
}

void LogVole_Encoding_KeyDeriveResponseRoundTrip(const oc::CLP&)
{
    const auto message = make_keyderive_response();
    const auto encoded = encode(message);

    KeyDeriveResponse decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_EQ(decoded.mPolyModulusDegree, message.mPolyModulusDegree);
    LOGVOLE_EXPECT_EQ(decoded.mCoeffModulusCount, message.mCoeffModulusCount);
    LOGVOLE_EXPECT_EQ(decoded.mTau, message.mTau);
    LOGVOLE_EXPECT_TRUE(rangesEqual(decoded.mMNttCoeffs, message.mMNttCoeffs));
}

void LogVole_Encoding_SeedMessageRoundTrip(const oc::CLP&)
{
    SeedMessage message{};
    assignValues<std::uint8_t>(message.mSeed, { 1, 3, 5, 7, 9, 11 });

    const auto encoded = encode(message);
    SeedMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decoded.mSeed, message.mSeed));

    SeedMessage empty{};
    LOGVOLE_EXPECT_FALSE(decode(std::span<const std::uint8_t>{}, empty));
}

void LogVole_Encoding_RootOfflineMessageRoundTrip(const oc::CLP&)
{
    const RingParams ring = make_ring();

    RootOfflineMessage message{};
    message.mRing = ring;
    message.mTauHi = 2;
    message.mGadgetLogBase = 7;
    message.mPlaintextModulusBits = 18;
    message.mLeftWidth = 4;
    message.mRandomizerWidth = 3;
    message.mCtR = make_tensor(ring, 4, 2, 1000);
    message.mLacctLeft.mWidthPadded = 8;
    message.mLacctLeft.mLevels = 3;
    message.mLacctLeft.mCt = make_tensor(ring, 3, 4, 2000);
    message.mTopCt = make_tensor(ring, 4, 5, 3000);
    message.mPublicBStarNtt = {
        make_poly(ring, 4000),
        make_poly(ring, 5000),
        make_poly(ring, 6000),
    };
    message.mCtR.mPolys.front().mCoeffs[0] = 0x0123456789ABCDEFull;
    message.mTopCt.mPolys.back().mCoeffs[1] = std::numeric_limits<std::uint64_t>::max();

    const auto encoded = encode(message);
    LOGVOLE_REQUIRE_EQ(rootOfflineWireSize(message), encoded.size());
    Buffer reserved(rootOfflineWireSize(message));
    const auto* const reservedPointer = reserved.data();
    const auto reservedEncoded = encodeRootOfflineIntoBuffer(
        message, std::move(reserved), 1u);
    LOGVOLE_REQUIRE_TRUE(reservedEncoded.data() == reservedPointer);
    expect_bytes_equal(reservedEncoded, encoded);
    bool cudaOwned = false;
    Buffer requestedRootWire = reserveRootCudaWireBuffer(
        encoded.size(), 987u, cudaOwned);
    const auto* const requestedPointer = requestedRootWire.data();
    LOGVOLE_REQUIRE_EQ(isRootCudaWireHostRange(requestedPointer,
        requestedRootWire.size()), cudaOwned);
    const auto requestedEncoded = encodeRootOfflineIntoBuffer(
        message, std::move(requestedRootWire), 1u);
    LOGVOLE_REQUIRE_TRUE(requestedEncoded.data() == requestedPointer);
    LOGVOLE_REQUIRE_EQ(isRootCudaWireHostRange(requestedEncoded.data(),
        requestedEncoded.size()), cudaOwned);
    expect_bytes_equal(requestedEncoded, encoded);
    bool rejectedWrongSize = false;
    try
    {
        Buffer wrongSize(encoded.size() - 1u);
        (void)encodeRootOfflineIntoBuffer(message, std::move(wrongSize), 1u);
    }
    catch (const std::invalid_argument&) { rejectedWrongSize = true; }
    LOGVOLE_REQUIRE_TRUE(rejectedWrongSize);
    RootOfflineMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));

    LOGVOLE_EXPECT_TRUE(decoded.mRing == message.mRing);
    LOGVOLE_EXPECT_EQ(decoded.mTauHi, message.mTauHi);
    LOGVOLE_EXPECT_EQ(decoded.mGadgetLogBase, message.mGadgetLogBase);
    LOGVOLE_EXPECT_EQ(decoded.mPlaintextModulusBits, message.mPlaintextModulusBits);
    LOGVOLE_EXPECT_EQ(decoded.mLeftWidth, message.mLeftWidth);
    LOGVOLE_EXPECT_EQ(decoded.mRandomizerWidth, message.mRandomizerWidth);
    expect_tensor_equal(decoded.mCtR, message.mCtR);
    LOGVOLE_EXPECT_EQ(decoded.mLacctLeft.mWidthPadded, message.mLacctLeft.mWidthPadded);
    LOGVOLE_EXPECT_EQ(decoded.mLacctLeft.mLevels, message.mLacctLeft.mLevels);
    expect_tensor_equal(decoded.mLacctLeft.mCt, message.mLacctLeft.mCt);
    expect_tensor_equal(decoded.mTopCt, message.mTopCt);
    LOGVOLE_REQUIRE_EQ(decoded.mPublicBStarNtt.size(), message.mPublicBStarNtt.size());
    LOGVOLE_EXPECT_EQ(decoded.mPublicBStarCount, message.mPublicBStarNtt.size());
    LOGVOLE_EXPECT_TRUE(!decoded.mOwnedPublicBStarWire && !decoded.mLazyPublicBStar);
    for (std::size_t idx = 0; idx < decoded.mPublicBStarNtt.size(); ++idx)
    {
        expect_poly_equal(decoded.mPublicBStarNtt[idx], message.mPublicBStarNtt[idx]);
    }

    const std::size_t firstTensorOffset =
        7u * sizeof(std::uint32_t) + ring.mCoeffModulusBits.size() * sizeof(std::uint16_t);
    auto offset = expect_offline_tensor_wire(encoded, firstTensorOffset, message.mCtR);
    offset = expect_offline_tensor_wire(encoded, offset + 2u * sizeof(std::uint32_t), message.mLacctLeft.mCt);
    offset = expect_offline_tensor_wire(encoded, offset, message.mTopCt);
    std::vector<std::uint8_t> expectedPublic;
    append_u32_le(expectedPublic, static_cast<std::uint32_t>(message.mPublicBStarNtt.size()));
    append_u32_le(expectedPublic, static_cast<std::uint32_t>(
        message.mPublicBStarNtt.size() * ringPolyCoeffCount(ring)));
    for (const auto& poly : message.mPublicBStarNtt)
        for (auto coeff : poly.mCoeffs)
            append_u64_le(expectedPublic, coeff);
    expect_bytes_equal(std::span<const std::uint8_t>(encoded).subspan(offset), as_span(expectedPublic));
    expect_offline_decode_boundaries<RootOfflineMessage>(encoded, firstTensorOffset);

    RootOfflineMessage empty{};
    empty.mRing = ring;
    LOGVOLE_REQUIRE_TRUE(decode(encode(empty), decoded));
    LOGVOLE_EXPECT_TRUE(decoded.mCtR.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(decoded.mLacctLeft.mCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(decoded.mTopCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(decoded.mPublicBStarNtt.empty());
}

void LogVole_Encoding_RootResidentWireExact(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (cmd.getOr("gpu", 0) == 0 || std::endian::native != std::endian::little) return;
    const bool previousGpu = gpu::enabled();
    struct RestoreGpu
    {
        bool previous;
        ~RestoreGpu() { gpu::setEnabled(previous); }
    } restore{previousGpu};
    gpu::setEnabled(true);

    const RingParams ring = make_ring();
    RootOfflineMessage eager{};
    eager.mRing = ring;
    eager.mTauHi = 2;
    eager.mGadgetLogBase = 7;
    eager.mPlaintextModulusBits = 18;
    eager.mLeftWidth = 3;
    eager.mRandomizerWidth = 2;
    eager.mCtR = make_tensor(ring, 3, 2, 0x1000);
    eager.mLacctLeft.mWidthPadded = 4;
    eager.mLacctLeft.mLevels = 2;
    eager.mLacctLeft.mCt = make_tensor(ring, 4, 3, 0x2000);
    eager.mTopCt = make_tensor(ring, 3, 4, 0x3000);
    eager.mPublicBStarNtt = { make_poly(ring, 0x4000), make_poly(ring, 0x5000) };
    eager.mCtR.mPolys.front().mCoeffs.front() = 0x0123456789ABCDEFull;
    eager.mTopCt.mPolys.back().mCoeffs.back() = std::numeric_limits<std::uint64_t>::max();
    const auto exact = scalar_wire(eager);
    expect_bytes_equal(encode(eager, 1), as_span(exact));

    RootOfflineMessage resident = eager;
    auto ctR = std::make_shared<TestRootDeviceTensor>(resident.mCtR);
    auto lacct = std::make_shared<TestRootDeviceTensor>(resident.mLacctLeft.mCt);
    auto topCt = std::make_shared<TestRootDeviceTensor>(resident.mTopCt);
    resident.mLazyCtR = ctR;
    resident.mLazyLacctLeft = lacct;
    resident.mLazyTopCt = topCt;
    resident.mCtR.mPolys.clear();
    resident.mLacctLeft.mCt.mPolys.clear();
    resident.mTopCt.mPolys.clear();
    for (auto workers : { 1u, 4u })
    {
        const auto wire = encode(resident, workers);
        expect_bytes_equal(wire, as_span(exact));
        RootOfflineMessage decoded{};
        LOGVOLE_REQUIRE_TRUE(decode(wire, decoded, workers));
        expect_tensor_equal(decoded.mCtR, eager.mCtR);
        expect_tensor_equal(decoded.mLacctLeft.mCt, eager.mLacctLeft.mCt);
        expect_tensor_equal(decoded.mTopCt, eager.mTopCt);
    }
    constexpr oc::u64 cudaWireTestRunId = 987u;
    resetRootWireCudaAllocEvidence(cudaWireTestRunId, true);
    noteRootWireCudaAllocEligibility(cudaWireTestRunId,
        rootOfflineWireSize(resident), true);
    noteRootWireCudaExpectedDownloads(cudaWireTestRunId, resident);
    bool cudaOwned = false;
    const std::size_t exactRootBytes = rootOfflineWireSize(resident);
    const std::size_t forecastRootBytes = exactRootBytes + 4096u;
    Buffer reserved = reserveRootCudaWireBuffer(
        forecastRootBytes, cudaWireTestRunId, cudaOwned);
    LOGVOLE_REQUIRE_TRUE(cudaOwned);
    const auto* const reservedPointer = reserved.data();
    LOGVOLE_REQUIRE_TRUE(isRootCudaWireHostRange(reservedPointer,
        forecastRootBytes));
    LOGVOLE_REQUIRE_TRUE(shrinkRootCudaWireBuffer(reserved,
        exactRootBytes));
    LOGVOLE_REQUIRE_TRUE(reserved.data() == reservedPointer);
    LOGVOLE_REQUIRE_EQ(reserved.size(), exactRootBytes);
    LOGVOLE_REQUIRE_TRUE(reserved.capacity() >= forecastRootBytes);
    LOGVOLE_REQUIRE_FALSE(isRootCudaWireHostRange(reservedPointer,
        forecastRootBytes));
    LOGVOLE_REQUIRE_TRUE(isRootCudaWireHostRange(reservedPointer,
        exactRootBytes));
    Buffer cudaWire = encodeRootOfflineIntoBuffer(resident,
        std::move(reserved), 4u);
    LOGVOLE_REQUIRE_TRUE(cudaWire.data() == reservedPointer);
    expect_bytes_equal(cudaWire, as_span(exact));
    const auto cudaEvidence = rootWireCudaAllocEvidenceSnapshot();
    LOGVOLE_REQUIRE_TRUE(cudaEvidence.mSelected);
    LOGVOLE_REQUIRE_EQ(cudaEvidence.mDirectDownloadCalls,
        cudaEvidence.mExpectedDirectDownloadCalls);
    LOGVOLE_REQUIRE_EQ(cudaEvidence.mDirectDownloadBytes,
        cudaEvidence.mExpectedDirectDownloadBytes);
    LOGVOLE_REQUIRE_EQ(cudaEvidence.mDirectDownloadCalls, 3u);
    coproto::BufferingSocket socket;
    macoro::sync_wait(socket.send(std::move(cudaWire)));
    macoro::sync_wait(socket.flush());
    LOGVOLE_REQUIRE_FALSE(isRootCudaWireHostRange(reservedPointer,
        exactRootBytes));
    bool reusedCudaOwned = false;
    Buffer reused = reserveRootCudaWireBuffer(forecastRootBytes,
        cudaWireTestRunId, reusedCudaOwned);
    LOGVOLE_REQUIRE_TRUE(reusedCudaOwned);
    LOGVOLE_REQUIRE_TRUE(reused.data() == reservedPointer);
    LOGVOLE_EXPECT_EQ(ctR->hostRequests(), 0u);
    LOGVOLE_EXPECT_EQ(lacct->hostRequests(), 0u);
    LOGVOLE_EXPECT_EQ(topCt->hostRequests(), 0u);
    // Two ordinary encodes plus the CUDA-owned reserved-buffer encode each
    // request one direct download from every lazy tensor.
    LOGVOLE_EXPECT_EQ(ctR->copyRequests(), 3u);
    LOGVOLE_EXPECT_EQ(lacct->copyRequests(), 3u);
    LOGVOLE_EXPECT_EQ(topCt->copyRequests(), 3u);

    // The socket decoder owns its exact received bytes and leaves all Root
    // tensors, including NTT-domain BStar, unsplit until their first consumer.
    ScopedEnvironmentValue encodedRoot("LV_GPU_SETUP_ROOT_ENCODED_RECEIVE", "1");
    ScopedEnvironmentValue encodedCtR("LV_GPU_SETUP_ROOT_CTR_ENCODED_RECEIVE", "1");
    ScopedEnvironmentValue encodedLacct("LV_GPU_SETUP_ROOT_LACCT_ENCODED_RECEIVE", "1");
    ScopedEnvironmentValue encodedBStar("LV_GPU_SETUP_ROOT_BSTAR_ENCODED_RECEIVE", "1");
    RootOfflineMessage retained{};
    auto received = encode(eager, 1);
    LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(std::move(received), retained, 4));
    LOGVOLE_REQUIRE_TRUE(retained.mOwnedCtRWire && retained.mLazyCtR);
    LOGVOLE_REQUIRE_TRUE(retained.mOwnedLacctLeftWire && retained.mLazyLacctLeft);
    LOGVOLE_REQUIRE_TRUE(retained.mOwnedTopCtWire && retained.mLazyTopCt);
    LOGVOLE_REQUIRE_TRUE(retained.mOwnedPublicBStarWire && retained.mLazyPublicBStar);
    LOGVOLE_EXPECT_TRUE(retained.mCtR.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mLacctLeft.mCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mTopCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mPublicBStarNtt.empty());

    LOGVOLE_EXPECT_EQ(retained.mPublicBStarCount, eager.mPublicBStarNtt.size());
    LOGVOLE_EXPECT_EQ(retained.mOwnedCtRWire->encodedCoefficients().size(),
        ringTensorSize(eager.mCtR) * ringPolyCoeffCount(ring) * sizeof(std::uint64_t));
    LOGVOLE_EXPECT_EQ(retained.mOwnedLacctLeftWire->encodedCoefficients().size(),
        ringTensorSize(eager.mLacctLeft.mCt) * ringPolyCoeffCount(ring) * sizeof(std::uint64_t));
    LOGVOLE_EXPECT_EQ(retained.mOwnedTopCtWire->encodedCoefficients().size(),
        ringTensorSize(eager.mTopCt) * ringPolyCoeffCount(ring) * sizeof(std::uint64_t));
    LOGVOLE_EXPECT_EQ(retained.mOwnedPublicBStarWire->encodedCoefficients().size(),
        eager.mPublicBStarNtt.size() * ringPolyCoeffCount(ring) * sizeof(std::uint64_t));
    expect_bytes_equal(encode(retained, 4), as_span(exact));
    LOGVOLE_EXPECT_TRUE(retained.mCtR.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mLacctLeft.mCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mTopCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mPublicBStarNtt.empty());
    expect_tensor_equal(retained.mOwnedCtRWire->get(), eager.mCtR);
    expect_tensor_equal(retained.mOwnedLacctLeftWire->get(), eager.mLacctLeft.mCt);
    expect_tensor_equal(retained.mOwnedTopCtWire->get(), eager.mTopCt);
    const auto& retainedBStar = retained.mOwnedPublicBStarWire->get().mPolys;
    LOGVOLE_REQUIRE_EQ(retainedBStar.size(), eager.mPublicBStarNtt.size());
    for (std::size_t i = 0; i < retainedBStar.size(); ++i)
        expect_poly_equal(retainedBStar[i], eager.mPublicBStarNtt[i]);
    RootOfflineMessage otherParty = eager;
    ++otherParty.mPublicBStarNtt.front().mCoeffs.front();
    RootOfflineMessage otherRetained{};
    auto otherWire = encode(otherParty, 1);
    LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(
        std::move(otherWire), otherRetained, 4));
    LOGVOLE_REQUIRE_TRUE(otherRetained.mOwnedPublicBStarWire);
    LOGVOLE_EXPECT_TRUE(otherRetained.mOwnedPublicBStarWire !=
        retained.mOwnedPublicBStarWire);
    LOGVOLE_EXPECT_TRUE(otherRetained.mOwnedPublicBStarWire->encodedCoefficients().data() !=
        retained.mOwnedPublicBStarWire->encodedCoefficients().data());
    const auto otherExact = scalar_wire(otherParty);
    expect_bytes_equal(encode(otherRetained, 4), as_span(otherExact));
    LOGVOLE_EXPECT_EQ(retainedBStar.front().mCoeffs.front(),
        eager.mPublicBStarNtt.front().mCoeffs.front());
    LOGVOLE_EXPECT_TRUE(retained.mCtR.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mLacctLeft.mCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mTopCt.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(retained.mPublicBStarNtt.empty());

    const std::size_t firstTensorOffset =
        7u * sizeof(std::uint32_t) + ring.mCoeffModulusBits.size() * sizeof(std::uint16_t);
    const auto ctROffset = firstTensorOffset;
    const auto lacctOffset = expect_offline_tensor_wire(as_span(exact), firstTensorOffset,
        eager.mCtR) + 2u * sizeof(std::uint32_t);
    const auto topCtOffset = expect_offline_tensor_wire(as_span(exact),
        lacctOffset, eager.mLacctLeft.mCt);
    const auto publicBStarOffset = expect_offline_tensor_wire(as_span(exact),
        topCtOffset, eager.mTopCt);
    const auto expectRejected = [&](Buffer&& malformed) {
        RootOfflineMessage eagerRejected{};
        LOGVOLE_EXPECT_FALSE(decode(malformed, eagerRejected, 4));
        const auto ctROwner = retained.mOwnedCtRWire;
        const auto lacctOwner = retained.mOwnedLacctLeftWire;
        const auto owner = retained.mOwnedTopCtWire;
        const auto publicBStarOwner = retained.mOwnedPublicBStarWire;
        LOGVOLE_EXPECT_FALSE(decodeRootOfflineForTransport(std::move(malformed), retained, 4));
        LOGVOLE_EXPECT_TRUE(retained.mOwnedCtRWire == ctROwner);
        LOGVOLE_EXPECT_TRUE(retained.mOwnedLacctLeftWire == lacctOwner);
        LOGVOLE_EXPECT_TRUE(retained.mOwnedTopCtWire == owner);
        LOGVOLE_EXPECT_TRUE(retained.mOwnedPublicBStarWire == publicBStarOwner);
    };
    auto impossibleCtRCount = encode(eager, 1);
    std::fill_n(impossibleCtRCount.begin() + ctROffset + 2u * sizeof(std::uint32_t),
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleCtRCount));
    auto impossibleCtRRows = encode(eager, 1);
    std::fill_n(impossibleCtRRows.begin() + ctROffset,
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleCtRRows));
    auto impossibleLacctCount = encode(eager, 1);
    std::fill_n(impossibleLacctCount.begin() + lacctOffset + 2u * sizeof(std::uint32_t),
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleLacctCount));
    auto impossibleLacctRows = encode(eager, 1);
    std::fill_n(impossibleLacctRows.begin() + lacctOffset,
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleLacctRows));
    auto impossibleCount = encode(eager, 1);
    std::fill_n(impossibleCount.begin() + topCtOffset + 2u * sizeof(std::uint32_t),
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleCount));
    auto impossibleBStarCount = encode(eager, 1);
    std::fill_n(impossibleBStarCount.begin() + publicBStarOffset,
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleBStarCount));
    auto impossibleBStarWords = encode(eager, 1);
    std::fill_n(impossibleBStarWords.begin() + publicBStarOffset + sizeof(std::uint32_t),
        sizeof(std::uint32_t), std::uint8_t{0xFF});
    expectRejected(std::move(impossibleBStarWords));
    auto truncated = encode(eager, 1);
    truncated.resize(truncated.size() - 1u);
    expectRejected(std::move(truncated));
    auto trailing = encode(eager, 1);
    trailing.push_back(0);
    expectRejected(std::move(trailing));

    // A direct/public decode remains eager even when its input was produced
    // by the same resident sender message.
    RootOfflineMessage direct{};
    LOGVOLE_REQUIRE_TRUE(decode(encode(eager, 1), direct, 4));
    LOGVOLE_EXPECT_TRUE(!direct.mCtR.mPolys.empty() && !direct.mOwnedCtRWire);
    LOGVOLE_EXPECT_TRUE(!direct.mLacctLeft.mCt.mPolys.empty() && !direct.mOwnedLacctLeftWire);
    LOGVOLE_EXPECT_TRUE(!direct.mTopCt.mPolys.empty() && !direct.mOwnedTopCtWire);
    LOGVOLE_EXPECT_TRUE(!direct.mPublicBStarNtt.empty() && !direct.mOwnedPublicBStarWire);
    RootOfflineMessage refreshed = retained;
    LOGVOLE_REQUIRE_TRUE(decode(encode(eager, 1), refreshed, 4));
    LOGVOLE_EXPECT_TRUE(!refreshed.mOwnedPublicBStarWire && !refreshed.mLazyPublicBStar);
    LOGVOLE_EXPECT_EQ(refreshed.mPublicBStarNtt.size(), eager.mPublicBStarNtt.size());
    expect_bytes_equal(encode(refreshed, 4), as_span(exact));
    {
        ScopedEnvironmentValue ctROptOut("LV_GPU_SETUP_ROOT_CTR_ENCODED_RECEIVE", "0");
        RootOfflineMessage stagedCtR{};
        auto stagedWire = encode(eager, 1);
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(std::move(stagedWire), stagedCtR, 4));
        LOGVOLE_EXPECT_TRUE(!stagedCtR.mCtR.mPolys.empty() && !stagedCtR.mOwnedCtRWire);
        LOGVOLE_EXPECT_TRUE(stagedCtR.mLacctLeft.mCt.mPolys.empty() && stagedCtR.mOwnedLacctLeftWire);
        LOGVOLE_EXPECT_TRUE(stagedCtR.mTopCt.mPolys.empty() && stagedCtR.mOwnedTopCtWire);
        expect_bytes_equal(encode(stagedCtR, 4), as_span(exact));
    }
    {
        ScopedEnvironmentValue lacctOptOut("LV_GPU_SETUP_ROOT_LACCT_ENCODED_RECEIVE", "0");
        RootOfflineMessage stagedLacct{};
        auto stagedWire = encode(eager, 1);
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(std::move(stagedWire), stagedLacct, 4));
        LOGVOLE_EXPECT_TRUE(!stagedLacct.mLacctLeft.mCt.mPolys.empty() &&
            !stagedLacct.mOwnedLacctLeftWire);
        LOGVOLE_EXPECT_TRUE(stagedLacct.mCtR.mPolys.empty() && stagedLacct.mOwnedCtRWire);
        LOGVOLE_EXPECT_TRUE(stagedLacct.mTopCt.mPolys.empty() && stagedLacct.mOwnedTopCtWire);
        expect_bytes_equal(encode(stagedLacct, 4), as_span(exact));
    }
    {
        ScopedEnvironmentValue bStarOptOut("LV_GPU_SETUP_ROOT_BSTAR_ENCODED_RECEIVE", "0");
        RootOfflineMessage stagedBStar{};
        auto stagedWire = encode(eager, 1);
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(std::move(stagedWire), stagedBStar, 4));
        LOGVOLE_EXPECT_TRUE(!stagedBStar.mPublicBStarNtt.empty() &&
            !stagedBStar.mOwnedPublicBStarWire);
        LOGVOLE_EXPECT_TRUE(stagedBStar.mCtR.mPolys.empty() && stagedBStar.mOwnedCtRWire);
        LOGVOLE_EXPECT_TRUE(stagedBStar.mLacctLeft.mCt.mPolys.empty() &&
            stagedBStar.mOwnedLacctLeftWire);
        LOGVOLE_EXPECT_TRUE(stagedBStar.mTopCt.mPolys.empty() && stagedBStar.mOwnedTopCtWire);
        expect_bytes_equal(encode(stagedBStar, 4), as_span(exact));
    }
    {
        ScopedEnvironmentValue optOut("LV_GPU_SETUP_ROOT_ENCODED_RECEIVE", "0");
        RootOfflineMessage staged{};
        auto stagedWire = encode(eager, 1);
        LOGVOLE_REQUIRE_TRUE(decodeRootOfflineForTransport(std::move(stagedWire), staged, 4));
        LOGVOLE_EXPECT_TRUE(!staged.mCtR.mPolys.empty() && !staged.mOwnedCtRWire);
        LOGVOLE_EXPECT_TRUE(!staged.mLacctLeft.mCt.mPolys.empty() && !staged.mOwnedLacctLeftWire);
        LOGVOLE_EXPECT_TRUE(!staged.mTopCt.mPolys.empty() && !staged.mOwnedTopCtWire);
        LOGVOLE_EXPECT_TRUE(!staged.mPublicBStarNtt.empty() && !staged.mOwnedPublicBStarWire);
        expect_bytes_equal(encode(staged, 4), as_span(exact));
    }

    auto declining = std::make_shared<TestRootDeviceTensor>(eager.mTopCt, false);
    resident.mLazyTopCt = declining;
    expect_bytes_equal(encode(resident, 1), as_span(exact));
    LOGVOLE_EXPECT_EQ(declining->copyRequests(), 1u);
    LOGVOLE_EXPECT_EQ(declining->hostRequests(), 1u);
#else
    (void)cmd;
#endif
}

void LogVole_Encoding_ShrinkExpandOfflineMessageDoesNotLeakNoiseRoot(const oc::CLP&)
{
    const RingParams ring = make_ring();

    ShrinkExpandOfflineMessage message{};
    message.mParams.mRing = ring;
    message.mParams.mPlaintextModulusBits = 18;
    message.mParams.mAlpha = 2;
    message.mParams.mMu = 3;
    message.mParams.mGadgetLogBase = 7;
    message.mParams.mTau = 2;
    message.mParams.mTruncateOneGadgetDigit = true;
    message.mParams.mLeafInputsAreGadget = true;
    message.mParams.mMode = ShrinkExpandMode::FullNoise;
    message.mParams.mNoiseBound = 5;
    message.mCt1 = make_tensor(ring, message.mParams.mMu, message.mParams.mTau, 7000);
    message.mLacct.mWidthPadded = 4;
    message.mLacct.mLevels = 2;
    message.mLacct.mCt = make_tensor(ring, 8, 4, 8000);
    message.mCt1.mPolys.front().mCoeffs[0] = 0x8000000000000000ull;
    message.mLacct.mCt.mPolys.back().mCoeffs[1] = 0x0123456789ABCDEFull;

    const auto encoded = encode(message);
    ShrinkExpandOfflineMessage decoded{};
    LOGVOLE_REQUIRE_TRUE(decode(encoded, decoded));

    LOGVOLE_EXPECT_TRUE(decoded.mParams.mRing == message.mParams.mRing);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mPlaintextModulusBits, message.mParams.mPlaintextModulusBits);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mAlpha, message.mParams.mAlpha);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mMu, message.mParams.mMu);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mGadgetLogBase, message.mParams.mGadgetLogBase);
    LOGVOLE_EXPECT_EQ(decoded.mParams.mTau, message.mParams.mTau);
    LOGVOLE_EXPECT_TRUE(decoded.mParams.mTruncateOneGadgetDigit);
    LOGVOLE_EXPECT_TRUE(decoded.mParams.mLeafInputsAreGadget);
    LOGVOLE_EXPECT_EQ(static_cast<std::uint8_t>(decoded.mParams.mMode), static_cast<std::uint8_t>(message.mParams.mMode));
    LOGVOLE_EXPECT_EQ(decoded.mParams.mNoiseBound, message.mParams.mNoiseBound);
    expect_tensor_equal(decoded.mCt1, message.mCt1);
    LOGVOLE_EXPECT_EQ(decoded.mLacct.mWidthPadded, message.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(decoded.mLacct.mLevels, message.mLacct.mLevels);
    expect_tensor_equal(decoded.mLacct.mCt, message.mLacct.mCt);

    const std::size_t firstTensorOffset =
        7u * sizeof(std::uint32_t) + ring.mCoeffModulusBits.size() * sizeof(std::uint16_t) +
        3u * sizeof(std::uint8_t) + sizeof(std::int64_t);
    auto offset = expect_offline_tensor_wire(encoded, firstTensorOffset, message.mCt1);
    offset = expect_offline_tensor_wire(encoded, offset + 2u * sizeof(std::uint32_t), message.mLacct.mCt);
    LOGVOLE_EXPECT_EQ(offset, encoded.size());
    expect_offline_decode_boundaries<ShrinkExpandOfflineMessage>(encoded, firstTensorOffset);

    ShrinkExpandOfflineMessage empty{};
    empty.mParams = message.mParams;
    LOGVOLE_REQUIRE_TRUE(decode(encode(empty), decoded));
    LOGVOLE_EXPECT_TRUE(decoded.mCt1.mPolys.empty());
    LOGVOLE_EXPECT_TRUE(decoded.mLacct.mCt.mPolys.empty());
}

void LogVole_Encoding_ShrinkExpandOfflineMessageRejectsInvalidMode(const oc::CLP&)
{
    const RingParams ring = make_ring();

    ShrinkExpandOfflineMessage message{};
    message.mParams.mRing = ring;
    message.mParams.mPlaintextModulusBits = 18;
    message.mParams.mAlpha = 2;
    message.mParams.mMu = 3;
    message.mParams.mGadgetLogBase = 7;
    message.mParams.mTau = 2;
    message.mParams.mTruncateOneGadgetDigit = true;
    message.mParams.mLeafInputsAreGadget = true;
    message.mParams.mMode = ShrinkExpandMode::FullNoise;
    message.mParams.mNoiseBound = 5;
    message.mCt1 = make_tensor(ring, message.mParams.mMu, message.mParams.mTau, 7000);
    message.mLacct.mWidthPadded = 4;
    message.mLacct.mLevels = 2;
    message.mLacct.mCt = make_tensor(ring, 8, 4, 8000);

    auto encoded = encode(message);
    const std::size_t ringParamsSize =
        sizeof(std::uint32_t) +
        sizeof(std::uint32_t) +
        ring.mCoeffModulusBits.size() * sizeof(std::uint16_t);
    const std::size_t modeOffset =
        ringParamsSize +
        5u * sizeof(std::uint32_t) +
        2u * sizeof(std::uint8_t);
    LOGVOLE_REQUIRE_LT(modeOffset, encoded.size());
    encoded[modeOffset] = 0xFF;

    ShrinkExpandOfflineMessage decoded{};
    LOGVOLE_EXPECT_FALSE(decode(encoded, decoded));
}

void LogVole_Encoding_ShrinkExpandOfflineMessageRejectsNoncanonicalBooleans(const oc::CLP&)
{
    const RingParams ring = make_ring();

    ShrinkExpandOfflineMessage message{};
    message.mParams.mRing = ring;
    message.mParams.mPlaintextModulusBits = 18;
    message.mParams.mAlpha = 2;
    message.mParams.mMu = 3;
    message.mParams.mGadgetLogBase = 7;
    message.mParams.mTau = 2;
    message.mParams.mTruncateOneGadgetDigit = true;
    message.mParams.mLeafInputsAreGadget = true;
    message.mParams.mMode = ShrinkExpandMode::FullNoise;
    message.mParams.mNoiseBound = 5;
    message.mCt1 = make_tensor(ring, message.mParams.mMu, message.mParams.mTau, 7000);
    message.mLacct.mWidthPadded = 4;
    message.mLacct.mLevels = 2;
    message.mLacct.mCt = make_tensor(ring, 8, 4, 8000);

    const auto encoded = encode(message);
    const std::size_t ringParamsSize =
        sizeof(std::uint32_t) +
        sizeof(std::uint32_t) +
        ring.mCoeffModulusBits.size() * sizeof(std::uint16_t);
    const std::size_t truncateOffset = ringParamsSize + 5u * sizeof(std::uint32_t);
    const std::size_t leafInputOffset = truncateOffset + sizeof(std::uint8_t);
    LOGVOLE_REQUIRE_LT(leafInputOffset, encoded.size());

    for (const auto offset : { truncateOffset, leafInputOffset })
    {
        auto malformed = encoded;
        malformed[offset] = 2;
        ShrinkExpandOfflineMessage decoded{};
        LOGVOLE_EXPECT_FALSE(decode(malformed, decoded));
    }
}

void LogVole_Encoding_RootDigestAndResponseRoundTrip(const oc::CLP&)
{
    // This literal is an external wire oracle, rather than an encode/decode
    // round trip where matching bugs could agree. It covers low bytes, carries,
    // a mixed-byte value, the high bit, and the full-width maximum.
    const std::array<std::uint8_t, 60> goldenDigestWire{
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };

    RootDigestMessage digest{};
    assignValues<std::uint64_t>(digest.mDPrimeCoeffs, {
        0,
        1,
        0xFF,
        0x100,
        0x0123456789ABCDEFull,
        0x8000000000000000ull,
        std::numeric_limits<std::uint64_t>::max(),
    });

    const auto encodedDigest = encode(digest);
    expect_bytes_equal(
        std::span<const std::uint8_t>(encodedDigest.data(), encodedDigest.size()),
        std::span<const std::uint8_t>(goldenDigestWire.data(), goldenDigestWire.size()));

    // Decoding a manually supplied legacy payload exercises fast-decoder /
    // legacy-encoder interoperability when the experiment is enabled.
    RootDigestMessage decodedDigest{};
    LOGVOLE_REQUIRE_TRUE(decode(
        std::span<const std::uint8_t>(goldenDigestWire.data(), goldenDigestWire.size()),
        decodedDigest));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decodedDigest.mDPrimeCoeffs, digest.mDPrimeCoeffs));

    RootResponseMessage response{};
    response.mSeed.resize(16);
    for (std::size_t idx = 0; idx < response.mSeed.size(); ++idx)
    {
        response.mSeed[idx] = static_cast<std::uint8_t>(0xA0u + idx);
    }
    response.mSkPrimeCoeffs = digest.mDPrimeCoeffs;

    std::vector<std::uint8_t> expectedResponse;
    expectedResponse.reserve(4u + response.mSeed.size() + goldenDigestWire.size());
    append_u32_le(expectedResponse, static_cast<std::uint32_t>(response.mSeed.size()));
    expectedResponse.insert(expectedResponse.end(), response.mSeed.begin(), response.mSeed.end());
    expectedResponse.insert(expectedResponse.end(), goldenDigestWire.begin(), goldenDigestWire.end());

    const auto encodedResponse = encode(response);
    expect_bytes_equal(
        std::span<const std::uint8_t>(encodedResponse.data(), encodedResponse.size()),
        as_span(expectedResponse));
    RootResponseMessage decodedResponse{};
    LOGVOLE_REQUIRE_TRUE(decode(as_span(expectedResponse), decodedResponse));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decodedResponse.mSeed, response.mSeed));
    LOGVOLE_EXPECT_TRUE(rangesEqual(decodedResponse.mSkPrimeCoeffs, response.mSkPrimeCoeffs));

    // PublicSeed has no seed bytes. Its coefficient count begins at byte four
    // and its coefficient body at byte eight; GoldenSeed's begin at 20 and 24.
    RootResponseMessage publicResponse{};
    publicResponse.mSkPrimeCoeffs = digest.mDPrimeCoeffs;
    std::vector<std::uint8_t> expectedPublicResponse(4u, 0);
    expectedPublicResponse.insert(
        expectedPublicResponse.end(), goldenDigestWire.begin(), goldenDigestWire.end());
    const auto encodedPublicResponse = encode(publicResponse);
    expect_bytes_equal(
        std::span<const std::uint8_t>(encodedPublicResponse.data(), encodedPublicResponse.size()),
        as_span(expectedPublicResponse));
    RootResponseMessage decodedPublicResponse{};
    LOGVOLE_REQUIRE_TRUE(decode(as_span(expectedPublicResponse), decodedPublicResponse));
    LOGVOLE_EXPECT_TRUE(decodedPublicResponse.mSeed.empty());
    LOGVOLE_EXPECT_TRUE(rangesEqual(
        decodedPublicResponse.mSkPrimeCoeffs, publicResponse.mSkPrimeCoeffs));

    // Exercise the production N=8192,rho=4 polynomial shape and compare every
    // encoded byte to an independent explicit little-endian reference.
    constexpr std::size_t productionCoeffCount = 8192u * 4u;
    RootDigestMessage productionDigest{};
    productionDigest.mDPrimeCoeffs.resize(productionCoeffCount);
    std::vector<std::uint8_t> expectedProductionDigest;
    expectedProductionDigest.reserve(4u + productionCoeffCount * sizeof(std::uint64_t));
    append_u32_le(expectedProductionDigest, static_cast<std::uint32_t>(productionCoeffCount));
    for (std::size_t idx = 0; idx < productionCoeffCount; ++idx)
    {
        const std::uint64_t value =
            0x8000000000000000ull |
            (0x9E3779B97F4A7C15ull * static_cast<std::uint64_t>(idx + 1u));
        productionDigest.mDPrimeCoeffs[idx] = value;
        append_u64_le(expectedProductionDigest, value);
    }

    const auto encodedProductionDigest = encode(productionDigest);
    LOGVOLE_EXPECT_EQ(encodedProductionDigest.size(), 262148u);
    expect_bytes_equal(
        std::span<const std::uint8_t>(
            encodedProductionDigest.data(), encodedProductionDigest.size()),
        as_span(expectedProductionDigest));
    RootDigestMessage decodedProductionDigest{};
    LOGVOLE_REQUIRE_TRUE(decode(as_span(expectedProductionDigest), decodedProductionDigest));
    LOGVOLE_EXPECT_TRUE(rangesEqual(
        decodedProductionDigest.mDPrimeCoeffs, productionDigest.mDPrimeCoeffs));

    RootResponseMessage productionResponse{};
    productionResponse.mSeed.resize(16);
    for (std::size_t idx = 0; idx < productionResponse.mSeed.size(); ++idx)
    {
        productionResponse.mSeed[idx] = static_cast<std::uint8_t>(idx);
    }
    productionResponse.mSkPrimeCoeffs = productionDigest.mDPrimeCoeffs;
    std::vector<std::uint8_t> expectedProductionResponse{
        0x10, 0x00, 0x00, 0x00,
    };
    expectedProductionResponse.reserve(4u + productionResponse.mSeed.size() + expectedProductionDigest.size());
    expectedProductionResponse.insert(
        expectedProductionResponse.end(),
        productionResponse.mSeed.begin(),
        productionResponse.mSeed.end());
    expectedProductionResponse.insert(
        expectedProductionResponse.end(),
        expectedProductionDigest.begin(),
        expectedProductionDigest.end());
    const auto encodedProductionResponse = encode(productionResponse);
    LOGVOLE_EXPECT_EQ(encodedProductionResponse.size(), 262168u);
    expect_bytes_equal(
        std::span<const std::uint8_t>(
            encodedProductionResponse.data(), encodedProductionResponse.size()),
        as_span(expectedProductionResponse));
    RootResponseMessage decodedProductionResponse{};
    LOGVOLE_REQUIRE_TRUE(decode(as_span(expectedProductionResponse), decodedProductionResponse));
    LOGVOLE_EXPECT_TRUE(rangesEqual(
        decodedProductionResponse.mSeed, productionResponse.mSeed));
    LOGVOLE_EXPECT_TRUE(rangesEqual(
        decodedProductionResponse.mSkPrimeCoeffs,
        productionResponse.mSkPrimeCoeffs));

    // The fast reader must preserve all legacy malformed-input decisions and
    // must reject impossible counts before multiplying or allocating.
    const auto expectBadDigest = [](const std::vector<std::uint8_t>& bytes) {
        RootDigestMessage decoded{};
        LOGVOLE_EXPECT_FALSE(decode(as_span(bytes), decoded));
    };
    expectBadDigest({});
    expectBadDigest({ 0x01, 0x00, 0x00 });
    expectBadDigest({ 0x00, 0x00, 0x00, 0x00 });
    expectBadDigest({ 0xFF, 0xFF, 0xFF, 0xFF });
    std::vector<std::uint8_t> truncatedDigest{ 0x01, 0x00, 0x00, 0x00 };
    truncatedDigest.resize(4u + 7u, 0xA5);
    expectBadDigest(truncatedDigest);
    std::vector<std::uint8_t> trailingDigest(
        goldenDigestWire.begin(), goldenDigestWire.end());
    trailingDigest.push_back(0x00);
    expectBadDigest(trailingDigest);

    const auto expectBadResponse = [](const std::vector<std::uint8_t>& bytes) {
        RootResponseMessage decoded{};
        LOGVOLE_EXPECT_FALSE(decode(as_span(bytes), decoded));
    };
    expectBadResponse({});
    expectBadResponse({ 0x10, 0x00, 0x00, 0x00, 0xAA, 0xBB });
    expectBadResponse({
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    });
    std::vector<std::uint8_t> truncatedResponse{
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    };
    truncatedResponse.resize(8u + 7u, 0x5A);
    expectBadResponse(truncatedResponse);
    auto trailingResponse = expectedResponse;
    trailingResponse.push_back(0x00);
    expectBadResponse(trailingResponse);

    RootDigestMessage emptyDigest{};
    LOGVOLE_EXPECT_FALSE(decode(encode(emptyDigest), emptyDigest));
}

void LogVole_Encoding_AllMessageRoundTrips(const oc::CLP& cmd)
{
    LogVole_Encoding_KeyDeriveRequestRoundTrip(cmd);
    LogVole_Encoding_KeyDeriveResponseRoundTrip(cmd);
    LogVole_Encoding_SeedMessageRoundTrip(cmd);
    LogVole_Encoding_ShrinkExpandOfflineMessageDoesNotLeakNoiseRoot(cmd);
    LogVole_Encoding_ShrinkExpandOfflineMessageRejectsInvalidMode(cmd);
    LogVole_Encoding_ShrinkExpandOfflineMessageRejectsNoncanonicalBooleans(cmd);
    LogVole_Encoding_RootOfflineMessageRoundTrip(cmd);
    LogVole_Encoding_RootResidentWireExact(cmd);
    LogVole_Encoding_RootDigestAndResponseRoundTrip(cmd);
    expect_parallel_offline_codec(cmd);
}

void LogVole_Encoding_PinnedWireBufferOwnership(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool previousGpu = gpu::enabled();
    struct RestoreGpu
    {
        bool mPrevious;
        ~RestoreGpu() { gpu::setEnabled(mPrevious); }
    } restoreGpu{previousGpu};
    gpu::setEnabled(cmd.getOr("gpu", 0) != 0);
    if (!gpu::enabled()) return;

    constexpr std::size_t bytes = std::size_t{1} << 20;
    ScopedEnvironmentValue pinned("LV_GPU_SETUP_PINNED_WIRE", "1");
    ScopedEnvironmentValue directDownload("LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD", "1");
    void* firstAllocation = nullptr;
    {
        Buffer buffer(bytes);
        firstAllocation = buffer.data();
        LOGVOLE_REQUIRE_TRUE(firstAllocation != nullptr);
        LOGVOLE_REQUIRE_EQ(reinterpret_cast<std::uintptr_t>(buffer.data()) % oc::gDefaultAlignment,
            std::uintptr_t{0});
        LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWireHostRange(buffer.data(), buffer.size()));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWireHostRange(buffer.data() + 31, buffer.size() - 31));
        LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWireHostRange(buffer.data() + buffer.size() - 1, 2));
        LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWirePinnedHostRange(buffer.data(), buffer.size()));

        gpu::GpuStream transferStream;
        LOGVOLE_REQUIRE_TRUE(transferStream.raw() != nullptr);
        struct DeviceAllocation
        {
            void* mPointer = nullptr;
            ~DeviceAllocation() { gpu::gpuFree(mPointer); }
        } device{gpu::gpuMalloc(bytes)};
        LOGVOLE_REQUIRE_TRUE(device.mPointer != nullptr);
        LOGVOLE_REQUIRE_TRUE(
            gpu::gpuMemsetZero(device.mPointer, bytes, transferStream.raw()));
        {
            // The opt-out keeps this fresh, active pool-owned destination
            // pageable and exercises the bounded staged D2H fallback.
            ScopedEnvironmentValue stagedDownload("LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD", "0");
            LOGVOLE_REQUIRE_TRUE(
                gpu::downloadSetupWire(buffer.data(), device.mPointer, bytes, transferStream));
            LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWirePinnedHostRange(buffer.data(), buffer.size()));
            LOGVOLE_EXPECT_EQ(buffer.front(), 0);
            LOGVOLE_EXPECT_EQ(buffer.back(), 0);
        }
        // The default registers that same active pool owner before D2H so CUDA
        // can fill the Buffer directly. Later H2D and repeated D2H retain the
        // exact byte and lifetime checks below.
        LOGVOLE_REQUIRE_TRUE(
            gpu::downloadSetupWire(buffer.data(), device.mPointer, bytes, transferStream));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWirePinnedHostRange(buffer.data(), buffer.size()));
        LOGVOLE_EXPECT_EQ(buffer.front(), 0);
        LOGVOLE_EXPECT_EQ(buffer.back(), 0);

        std::fill(buffer.begin(), buffer.end(), 0x3c);
        buffer.back() = 0xa7;
        LOGVOLE_REQUIRE_TRUE(
            gpu::uploadSetupWire(device.mPointer, buffer.data(), bytes, transferStream));
        LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWirePinnedHostRange(buffer.data(), buffer.size()));
        std::fill(buffer.begin(), buffer.end(), 0);
        LOGVOLE_REQUIRE_TRUE(
            gpu::downloadSetupWire(buffer.data(), device.mPointer, bytes, transferStream));
        LOGVOLE_EXPECT_EQ(buffer.front(), 0x3c);
        LOGVOLE_EXPECT_EQ(buffer.back(), 0xa7);

        bool pinnedRange = false;
        LOGVOLE_REQUIRE_TRUE(gpu::gpuTryPinSetupWireHostRange(
            buffer.data() + 31, buffer.size() - 31, pinnedRange));
        LOGVOLE_REQUIRE_TRUE(pinnedRange);
        LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWirePinnedHostRange(buffer.data(), buffer.size()));
        LOGVOLE_REQUIRE_TRUE(
            gpu::gpuIsSetupWirePinnedHostRange(buffer.data() + 31, buffer.size() - 31));
        pinnedRange = true;
        LOGVOLE_REQUIRE_TRUE(gpu::gpuTryPinSetupWireHostRange(
            buffer.data() + buffer.size() - 1, 2, pinnedRange));
        LOGVOLE_EXPECT_FALSE(pinnedRange);

        Buffer copied = buffer;
        LOGVOLE_REQUIRE_TRUE(copied.data() != buffer.data());
        LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWireHostRange(copied.data(), copied.size()));
        LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWirePinnedHostRange(copied.data(), copied.size()));
        LOGVOLE_REQUIRE_TRUE(std::equal(copied.begin(), copied.end(), buffer.begin()));
        LOGVOLE_EXPECT_EQ(copied.front(), 0x3c);
        LOGVOLE_EXPECT_EQ(copied.back(), 0xa7);
        pinnedRange = false;
        LOGVOLE_REQUIRE_TRUE(
            gpu::gpuTryPinSetupWireHostRange(copied.data(), copied.size(), pinnedRange));
        LOGVOLE_REQUIRE_TRUE(pinnedRange);

        Buffer moved = std::move(buffer);
        LOGVOLE_REQUIRE_TRUE(buffer.empty());
        LOGVOLE_REQUIRE_TRUE(moved.data() == firstAllocation);
        copied.clear();
        {
            // Deallocation follows pointer provenance even if rollback changes
            // after allocation.
            ScopedEnvironmentValue disabled("LV_GPU_SETUP_PINNED_WIRE", "0");
            moved.clear();
        }
        LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWireHostRange(firstAllocation, bytes));
    }

    Buffer reused(bytes);
    LOGVOLE_REQUIRE_TRUE(reused.data() == firstAllocation);
    LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWireHostRange(reused.data(), reused.size()));
    // Registration belongs to the allocation and persists while it is free.
    LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWirePinnedHostRange(reused.data(), reused.size()));
    std::fill(reused.begin(), reused.end(), 0x5a);
    reused.resize(bytes + 257u, oc::AllocType::Zeroed);
    LOGVOLE_REQUIRE_TRUE(std::all_of(reused.begin(), reused.begin() + bytes,
        [](std::uint8_t value) { return value == 0x5a; }));
    LOGVOLE_REQUIRE_TRUE(std::all_of(reused.begin() + bytes, reused.end(),
        [](std::uint8_t value) { return value == 0; }));
    LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWireHostRange(reused.data(), reused.size()));
    LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWirePinnedHostRange(reused.data(), reused.size()));
    bool resizedPinned = false;
    LOGVOLE_REQUIRE_TRUE(
        gpu::gpuTryPinSetupWireHostRange(reused.data(), reused.size(), resizedPinned));
    LOGVOLE_REQUIRE_TRUE(resizedPinned);
    LOGVOLE_REQUIRE_TRUE(gpu::gpuIsSetupWirePinnedHostRange(reused.data(), reused.size()));
    reused.clear();
    {
        ScopedEnvironmentValue disabled("LV_GPU_SETUP_PINNED_WIRE", "0");
        Buffer ordinary(bytes);
        LOGVOLE_REQUIRE_TRUE(ordinary.data() != nullptr);
        LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWireHostRange(ordinary.data(), ordinary.size()));
        LOGVOLE_EXPECT_FALSE(gpu::gpuIsSetupWirePinnedHostRange(ordinary.data(), ordinary.size()));
        bool ordinaryPinned = true;
        LOGVOLE_REQUIRE_TRUE(
            gpu::gpuTryPinSetupWireHostRange(ordinary.data(), ordinary.size(), ordinaryPinned));
        LOGVOLE_EXPECT_FALSE(ordinaryPinned);
    }
#else
    (void)cmd;
#endif
}
