#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleCpuScratch.h"
#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif

#include <algorithm>
#include <cmath>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#if defined(__linux__)
#include <sys/mman.h>
#endif

namespace osuCrypto::LogVole
{
    namespace detail
    {
        std::shared_ptr<WireMemoryPool> makeSetupWireMemory(std::size_t bytes, LogVoleWireOptions options, bool useGpu)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (bytes >= (std::size_t{1} << 20) && options.mPinned && useGpu)
                return std::make_shared<WireMemoryPool>();
#else
            (void)bytes;
#endif
            return {};
        }

        void* allocateSetupWireBytes(std::size_t bytes, std::size_t alignment,
            WireMemoryPool* memory)
        {
            if (!bytes) return nullptr;
            if (alignment < alignof(void*) || (alignment & (alignment - 1u)) ||
                alignment > std::numeric_limits<std::size_t>::max() - sizeof(void*) ||
                alignment > static_cast<std::size_t>(std::numeric_limits<int>::max()) - sizeof(void*) + 1u)
                throw std::bad_array_new_length();
            const std::size_t overhead = alignment - 1u + sizeof(void*);
            if (bytes > std::numeric_limits<std::size_t>::max() - overhead)
                throw std::bad_array_new_length();
#if defined(ENABLE_LOGVOLE_CUDA)
            if (memory && bytes >= (std::size_t{1} << 20) && alignment <= 4096)
            {

                if (void* pointer = memory->allocate(bytes, alignment))
                {
                    if (reinterpret_cast<std::uintptr_t>(pointer) % alignment == 0) return pointer;
                    (void)memory->release(pointer);
                }
            }
#else
            (void)memory;
#endif
            void* pointer = AlignedAllocator<u8>::aligned_malloc(bytes, alignment);
            if (!pointer) throw std::bad_alloc();
            return pointer;
        }

        void deallocateSetupWireBytes(void* pointer, WireMemoryPool* memory) noexcept
        {
            if (!pointer) return;
            if (memory && memory->release(pointer)) return;
            AlignedAllocator<u8>::aligned_free(pointer);
        }
    }

    void adviseGpuSetupWireBuffer(Buffer& buffer, const LogVoleWireOptions& options, bool useGpu)
    {
#if defined(__linux__) && defined(ENABLE_LOGVOLE_CUDA) && defined(MADV_HUGEPAGE)
        if (!options.mHugePages || !useGpu || buffer.size() < (std::size_t{8} << 20))
            return;
        if (buffer.memory() && buffer.memory()->contains(buffer.data(), buffer.size())) return;
        constexpr std::uintptr_t alignment = std::uintptr_t{2} << 20;
        const auto first = reinterpret_cast<std::uintptr_t>(buffer.data());
        if (first > std::numeric_limits<std::uintptr_t>::max() - buffer.size()) return;
        const auto last = first + buffer.size();
        const auto begin = (first + alignment - 1u) & ~(alignment - 1u);
        const auto end = last & ~(alignment - 1u);
        // Advise only complete, aligned regions owned by this allocation.
        // This is a hint: unsupported policies retain the original behavior.
        if (begin < end)
            (void)madvise(reinterpret_cast<void*>(begin), end - begin, MADV_HUGEPAGE);
#else
        (void)buffer;
#endif
    }

    namespace
    {
        static_assert(sizeof(u64) == 8);
        static_assert(std::is_trivially_copyable_v<u64>);

        // Root exchanges two full ring polynomials, and their generic scalar
        // little-endian codec is visible on the online critical path. Keep the
        // native object-representation copy on little-endian hosts; repeated
        // H200 A/B/A trials showed a consistent online win. Non-little-endian
        // hosts use the established byte-at-a-time path.
        constexpr bool setupMemcpyCodecEnabled()
        {
            return std::endian::native == std::endian::little;
        }

        u32 setupCodecWorkers(u32 requested, bool useGpu)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (useGpu)
                return std::max<u32>(1u, requested);
#endif
            return 1;
        }

        bool readU8(std::span<const u8> payload, u64& offset, u8& value)
        {
            if (offset + sizeof(u8) > payload.size())
            {
                return false;
            }

            value = payload[offset];
            offset += sizeof(u8);
            return true;
        }

        bool readU16(std::span<const u8> payload, u64& offset, u16& value)
        {
            if (offset + sizeof(u16) > payload.size())
            {
                return false;
            }

            value = static_cast<u16>(payload[offset]) |
                    static_cast<u16>(static_cast<u16>(payload[offset + 1]) << 8u);
            offset += sizeof(u16);
            return true;
        }

        bool readU32(std::span<const u8> payload, u64& offset, u32& value)
        {
            if (offset + sizeof(u32) > payload.size())
            {
                return false;
            }

            value = 0;
            for (u32 i = 0; i < sizeof(u32); ++i)
            {
                value |= static_cast<u32>(payload[offset + i]) << (8u * i);
            }
            offset += sizeof(u32);
            return true;
        }

        bool readU64(std::span<const u8> payload, u64& offset, u64& value)
        {
            if (offset + sizeof(u64) > payload.size())
            {
                return false;
            }

            value = 0;
            for (u32 i = 0; i < sizeof(u64); ++i)
            {
                value |= static_cast<u64>(payload[offset + i]) << (8u * i);
            }
            offset += sizeof(u64);
            return true;
        }

        bool readI64(std::span<const u8> payload, u64& offset, i64& value)
        {
            u64 unsignedValue = 0;
            if (!readU64(payload, offset, unsignedValue))
            {
                return false;
            }
            value = static_cast<i64>(unsignedValue);
            return true;
        }

        template<typename Vec>
        u32 checkedVectorSize(const Vec& values)
        {
            if (values.size() > std::numeric_limits<u32>::max())
            {
                throw std::length_error("LogVole vector is too large to encode");
            }
            return static_cast<u32>(values.size());
        }

        template<typename Vec>
        std::size_t u64VectorByteSize(const Vec& values)
        {
            checkedVectorSize(values);
            return sizeof(u32) + values.size() * sizeof(u64);
        }

        std::size_t ringBatchCoeffCount(const std::vector<RnsPoly>& polys)
        {
            std::size_t total = 0;
            for (const auto& poly : polys)
            {
                if (poly.mCoeffs.size() > std::numeric_limits<u32>::max() - total)
                {
                    throw std::length_error("LogVole ring batch is too large to encode");
                }
                total += poly.mCoeffs.size();
            }
            return total;
        }

        std::size_t ringBatchByteSize(const std::vector<RnsPoly>& polys)
        {
            const auto coeffCount = ringBatchCoeffCount(polys);
            return sizeof(u32) + coeffCount * sizeof(u64);
        }

        std::size_t ringParamsByteSize(const RingParams& params)
        {
            return sizeof(u32) + sizeof(u32) + params.mCoeffModulusBits.size() * sizeof(u16);
        }

        std::size_t paramsByteSize(const ShrinkExpandParams& params)
        {
            return ringParamsByteSize(params.mRing) +
                   5u * sizeof(u32) +
                   3u * sizeof(u8) +
                   sizeof(i64);
        }

        struct BufferWriter
        {
            Buffer mBuffer;
            std::size_t mOffset = 0;
            u32 mWorkers = 1;
            CpuBenchmarkState mCpuBenchmark;
            detail::CpuRowScratch* mCompute;

            explicit BufferWriter(std::size_t size, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark = {}, detail::CpuRowScratch* compute = nullptr)
                : mBuffer(size, options.mWire, useGpu, profile), mWorkers(setupCodecWorkers(workers, useGpu)), mCpuBenchmark(cpuBenchmark), mCompute(compute)
            {
                adviseGpuSetupWireBuffer(mBuffer, options.mWire, useGpu);
            }

            explicit BufferWriter(Buffer&& reserved, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark = {}, detail::CpuRowScratch* compute = nullptr)
                : mBuffer(std::move(reserved)), mWorkers(setupCodecWorkers(workers, useGpu)), mCpuBenchmark(cpuBenchmark), mCompute(compute)
            {
                adviseGpuSetupWireBuffer(mBuffer, options.mWire, useGpu);
            }

            void writeU8(u8 value)
            {
                mBuffer[mOffset++] = value;
            }

            void writeU16(u16 value)
            {
                mBuffer[mOffset++] = static_cast<u8>(value & 0xFFu);
                mBuffer[mOffset++] = static_cast<u8>((value >> 8u) & 0xFFu);
            }

            void writeU32(u32 value)
            {
                for (u32 i = 0; i < sizeof(u32); ++i)
                {
                    mBuffer[mOffset + i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
                }
                mOffset += sizeof(u32);
            }

            void writeU64(u64 value)
            {
                for (u32 i = 0; i < sizeof(u64); ++i)
                {
                    mBuffer[mOffset + i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
                }
                mOffset += sizeof(u64);
            }

            void writeI64(i64 value)
            {
                writeU64(static_cast<u64>(value));
            }

            void writeBytes(std::span<const u8> values)
            {
                std::copy(values.begin(), values.end(), mBuffer.begin() + static_cast<std::ptrdiff_t>(mOffset));
                mOffset += values.size();
            }

            template<typename Vec>
            void writeU64Vector(const Vec& values)
            {
                writeU32(checkedVectorSize(values));
                for (auto value : values)
                {
                    writeU64(static_cast<u64>(value));
                }
            }

            void writeNativeLittleEndianU64Vector(const AlignedUnVec<u64>& values)
            {
                writeU32(checkedVectorSize(values));
                const auto bytes = std::as_bytes(
                    std::span<const u64>(values.data(), values.size()));
                if (!bytes.empty())
                {
                    std::memcpy(mBuffer.data() + mOffset, bytes.data(), bytes.size());
                }
                mOffset += bytes.size();
            }

            void writeRingBatch(const std::vector<RnsPoly>& polys)
            {
                auto cpuBenchmark = mCpuBenchmark;
                writeU32(static_cast<u32>(ringBatchCoeffCount(polys)));
                constexpr bool nativeCopy = setupMemcpyCodecEnabled();
                if (mCompute && nativeCopy && mWorkers > 1 && polys.size() > 1 &&
                    ringBatchCoeffCount(polys) * sizeof(u64) >= (std::size_t(1) << 20))
                {
                    std::vector<std::size_t> offsets(polys.size() + 1, mOffset);
                    for (std::size_t i = 0; i < polys.size(); ++i)
                        offsets[i + 1] = offsets[i] + polys[i].mCoeffs.size() * sizeof(u64);
                    if (!mCompute->runBulk(polys.size(), mWorkers, [&](std::size_t i, CpuBenchmarkState& cpuBenchmark) {
                        const auto bytes = offsets[i + 1] - offsets[i];
                        if (bytes) std::memcpy(mBuffer.data() + offsets[i], polys[i].mCoeffs.data(), bytes);
                        return true;
                    }, cpuBenchmark)) throw std::runtime_error("parallel offline encoding failed");
                    mOffset = offsets.back();
                    return;
                }
                for (const auto& poly : polys)
                {
                    if (nativeCopy)
                    {
                        const auto bytes = poly.mCoeffs.size() * sizeof(u64);
                        if (bytes != 0)
                        {
                            std::memcpy(mBuffer.data() + mOffset, poly.mCoeffs.data(), bytes);
                        }
                        mOffset += bytes;
                    }
                    else
                    {
                        for (auto coeff : poly.mCoeffs)
                        {
                            writeU64(coeff);
                        }
                    }
                }
            }

            void writeRingParams(const RingParams& params)
            {
                writeU32(params.mPolyModulusDegree);
                writeU32(checkedVectorSize(params.mCoeffModulusBits));
                for (auto bits : params.mCoeffModulusBits)
                {
                    writeU16(static_cast<u16>(bits));
                }
            }

            void writeParams(const ShrinkExpandParams& params)
            {
                writeRingParams(params.mRing);
                writeU32(params.mPlaintextModulusBits);
                writeU32(params.mAlpha);
                writeU32(params.mMu);
                writeU32(params.mGadgetLogBase);
                writeU32(params.mTau);
                writeU8(static_cast<u8>(params.mTruncateOneGadgetDigit ? 1 : 0));
                writeU8(static_cast<u8>(params.mLeafInputsAreGadget ? 1 : 0));
                writeU8(static_cast<u8>(params.mMode));
                writeI64(params.mNoiseBound);
            }

            Buffer finish()
            {
                if (mOffset != mBuffer.size())
                {
                    throw std::logic_error("LogVole encoding size mismatch");
            }
                return std::move(mBuffer);
            }
        };

        bool readU16Vector(std::span<const u8> payload, u64& offset, AlignedUnVec<u16>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u16))
            {
                return false;
            }

            values.resize(count);
            for (u32 i = 0; i < count; ++i)
            {
                u16 value = 0;
                if (!readU16(payload, offset, value))
                {
                    return false;
                }
                values[i] = value;
            }
            return true;
        }

        bool readU64Vector(std::span<const u8> payload, u64& offset, AlignedUnVec<u64>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u64))
            {
                return false;
            }

            values.resize(count);
            for (u32 i = 0; i < count; ++i)
            {
                u64 value = 0;
                if (!readU64(payload, offset, value))
                {
                    return false;
                }
                values[i] = value;
            }
            return true;
        }

        bool readNativeLittleEndianU64Vector(
            std::span<const u8> payload,
            u64& offset,
            AlignedUnVec<u64>& values)
        {
            u32 count = 0;
            // Validate by division before forming count * sizeof(u64). Besides
            // rejecting truncated input, this proves the later byte count fits
            // in size_t because the complete payload already does.
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u64))
            {
                return false;
            }

            values.resize(count);
            const auto bytes = std::as_writable_bytes(
                std::span<u64>(values.data(), values.size()));
            if (!bytes.empty())
            {
                std::memcpy(
                    bytes.data(),
                    payload.data() + static_cast<std::size_t>(offset),
                    bytes.size());
            }
            offset += bytes.size();
            return true;
        }

        bool readOfflineRingBatch(
            std::span<const u8> payload,
            u64& offset,
            const RingParams& ring,
            u32 polyCount,
            std::vector<RnsPoly>& polys,
            u32 workers, bool useGpu, CpuBenchmarkState cpuBenchmark = {}, detail::CpuRowScratch* compute = nullptr)
        {
            const auto modulusCount = static_cast<u32>(ring.mCoeffModulusBits.size());
            if constexpr (!setupMemcpyCodecEnabled())
            {
                AlignedUnVec<u64> flat;
                return readU64Vector(payload, offset, flat) &&
                       unpackRingBatch(
                           polyCount, ring.mPolyModulusDegree, modulusCount, flat, polys);
            }

            u32 coeffCount = 0;
            if (!readU32(payload, offset, coeffCount) ||
                static_cast<u64>(coeffCount) > (payload.size() - offset) / sizeof(u64))
            {
                return false;
            }

            const u64 perPoly = static_cast<u64>(ring.mPolyModulusDegree) * modulusCount;
            // Check shape before allocation, and divide before multiplying so
            // hostile dimensions cannot overflow. Empty batches remain valid
            // with nonzero ring dimensions, as in unpackRingBatch.
            if (perPoly == 0 ||
                static_cast<u64>(polyCount) > static_cast<u64>(coeffCount) / perPoly ||
                static_cast<u64>(polyCount) * perPoly != coeffCount)
            {
                return false;
            }

            polys.resize(polyCount);
            const auto bytes = static_cast<std::size_t>(perPoly) * sizeof(u64);
            if (compute && setupCodecWorkers(workers, useGpu) > 1 && polyCount > 1 &&
                static_cast<std::size_t>(coeffCount) * sizeof(u64) >= (std::size_t(1) << 20))
            {
                if (!compute->runBulk(polyCount, setupCodecWorkers(workers, useGpu), [&](std::size_t i, CpuBenchmarkState& cpuBenchmark) {
                    auto& poly = polys[i];
                    poly.mCoeffs.resize(static_cast<std::size_t>(perPoly));
                    std::memcpy(poly.mCoeffs.data(), payload.data() + offset + i * bytes, bytes);
                    return true;
                }, cpuBenchmark)) return false;
                offset += static_cast<u64>(coeffCount) * sizeof(u64);
                return true;
            }
            for (auto& poly : polys)
            {
                poly.mCoeffs.resize(static_cast<std::size_t>(perPoly));
                const auto bytes = poly.mCoeffs.size() * sizeof(u64);
                // The wire fields need not be aligned. memcpy both handles
                // that and avoids a full flat-vector allocation/copy before
                // splitting the large offline payload into polynomials.
                std::memcpy(poly.mCoeffs.data(), payload.data() + offset, bytes);
                offset += bytes;
            }
            return true;
        }

        bool readOfflineRingTensor(
            std::span<const u8> payload,
            u64& offset,
            const RingParams& ring,
            RingTensor& tensor,
            u32 workers, bool useGpu, CpuBenchmarkState cpuBenchmark = {}, detail::CpuRowScratch* compute = nullptr)
        {
            if (!readU32(payload, offset, tensor.mRows) ||
                !readU32(payload, offset, tensor.mCols) ||
                (tensor.mRows != 0 &&
                 tensor.mCols > std::numeric_limits<u32>::max() / tensor.mRows))
            {
                return false;
            }
            return readOfflineRingBatch(
                payload, offset, ring, tensor.mRows * tensor.mCols, tensor.mPolys, workers, useGpu, cpuBenchmark, compute);
        }

        void writeRootU64Vector(BufferWriter& writer, const AlignedUnVec<u64>& values)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                writer.writeNativeLittleEndianU64Vector(values);
                return;
            }
            writer.writeU64Vector(values);
        }

        bool readRootU64Vector(
            std::span<const u8> payload,
            u64& offset,
            AlignedUnVec<u64>& values)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                return readNativeLittleEndianU64Vector(payload, offset, values);
            }
            return readU64Vector(payload, offset, values);
        }

        bool readRingParams(std::span<const u8> payload, u64& offset, RingParams& params)
        {
            AlignedUnVec<u16> coeffBits;
            if (!readU32(payload, offset, params.mPolyModulusDegree) ||
                !readU16Vector(payload, offset, coeffBits))
            {
                return false;
            }

            params.mCoeffModulusBits.resize(coeffBits.size());
            u64 idx = 0;
            for (auto bits : coeffBits)
            {
                params.mCoeffModulusBits[idx++] = static_cast<int>(bits);
            }
            return true;
        }

        template<typename Vec>
        Buffer encodeKeyDerive(
            u32 polyModulusDegree,
            u32 coeffModulusCount,
            u32 tau,
            const Vec& coeffs, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile)
        {
            BufferWriter writer(3u * sizeof(u32) + u64VectorByteSize(coeffs), 1, options, useGpu, profile);
            writer.writeU32(polyModulusDegree);
            writer.writeU32(coeffModulusCount);
            writer.writeU32(tau);
            writer.writeU64Vector(coeffs);
            return writer.finish();
        }

        bool decodeKeyDerive(
            std::span<const u8> payload,
            u32& polyModulusDegree,
            u32& coeffModulusCount,
            u32& tau,
            AlignedUnVec<u64>& coeffs)
        {
            u64 offset = 0;
            if (!readU32(payload, offset, polyModulusDegree) ||
                !readU32(payload, offset, coeffModulusCount) ||
                !readU32(payload, offset, tau) ||
                !readU64Vector(payload, offset, coeffs))
            {
                return false;
            }

            return offset == payload.size();
        }

        bool readShrinkExpandMode(u8 value, ShrinkExpandMode& mode)
        {
            switch (value)
            {
            case static_cast<u8>(ShrinkExpandMode::FullNoise):
                mode = ShrinkExpandMode::FullNoise;
                return true;
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
            case static_cast<u8>(ShrinkExpandMode::Deterministic):
                mode = ShrinkExpandMode::Deterministic;
                return true;
#endif
            default:
                return false;
            }
        }

        bool readParams(std::span<const u8> payload, u64& offset, ShrinkExpandParams& params)
        {
            u8 truncate = 0;
            u8 leafInputsAreGadget = 0;
            u8 mode = 0;
            if (!readRingParams(payload, offset, params.mRing) ||
                !readU32(payload, offset, params.mPlaintextModulusBits) ||
                !readU32(payload, offset, params.mAlpha) ||
                !readU32(payload, offset, params.mMu) ||
                !readU32(payload, offset, params.mGadgetLogBase) ||
                !readU32(payload, offset, params.mTau) ||
                !readU8(payload, offset, truncate) ||
                !readU8(payload, offset, leafInputsAreGadget) ||
                !readU8(payload, offset, mode) ||
                !readI64(payload, offset, params.mNoiseBound))
            {
                return false;
            }

            if (truncate > 1 || leafInputsAreGadget > 1)
                return false;

            params.mTruncateOneGadgetDigit = truncate != 0;
            params.mLeafInputsAreGadget = leafInputsAreGadget != 0;
            return readShrinkExpandMode(mode, params.mMode);
        }

		bool checkedAdd(u64 a, u64 b, u64& out)
		{
			if (a > std::numeric_limits<u64>::max() - b)
				return false;
			out = a + b;
			return true;
		}

		bool checkedMul(u64 a, u64 b, u64& out)
		{
			if (a != 0 && b > std::numeric_limits<u64>::max() / a)
				return false;
			out = a * b;
			return true;
		}

		bool nextPowerOfTwoAndLog(u32 value, u64& width, u64& levels)
		{
			if (value == 0)
				return false;
			// LENC pads a singleton with a zero leaf so its tree has an
			// internal digest node and one randomizer layer.
			width = 2;
			levels = 1;
			while (width < value)
			{
				if (width >= (u64(1) << 31))
					return false;
				width <<= 1;
				++levels;
			}
			return true;
		}

		bool ringCoeffByteSize(const RingParams& params, u64& out)
		{
			u64 count = 0;
			return params.mPolyModulusDegree != 0 &&
				!params.mCoeffModulusBits.empty() &&
				checkedMul(params.mPolyModulusDegree, params.mCoeffModulusBits.size(), count) &&
				checkedMul(count, sizeof(u64), out);
		}

		bool payloadFromPolyCount(u64 fixedBytes, u64 polyCount, const RingParams& params, u64& out)
		{
			u64 polyBytes = 0;
			u64 coeffBytes = 0;
			return ringCoeffByteSize(params, polyBytes) &&
				checkedMul(polyCount, polyBytes, coeffBytes) &&
				checkedAdd(fixedBytes, coeffBytes, out);
		}
    }

	bool keyDerivePayloadSize(const RingParams& params, u32 tau, u64& out)
	{
		return tau != 0 && payloadFromPolyCount(4u * sizeof(u32), tau, params, out);
	}

	bool polyPayloadSize(const RingParams& params, u64& out)
	{
		return payloadFromPolyCount(3u * sizeof(u32), 1, params, out);
	}

	bool rootDigestPayloadSize(const RingParams& params, u64& out)
	{
		return payloadFromPolyCount(sizeof(u32), 1, params, out);
	}

	bool rootResponsePayloadSize(const RingParams& params, u64& out)
	{
		constexpr u64 seedBytes = 16;
		return payloadFromPolyCount(2u * sizeof(u32) + seedBytes, 1, params, out);
	}

	bool shrinkExpandOfflinePayloadSize(const ShrinkExpandParams& params, u64& out)
	{
		u64 width = 0;
		u64 levels = 0;
		if (!nextPowerOfTwoAndLog(params.mMu, width, levels))
			return false;

		const u64 tauMax = static_cast<u64>(params.mTau) +
			(params.mTruncateOneGadgetDigit ? 1u : 0u);
		u64 ct1Polys = 0;
		u64 lacctPolys = 0;
		u64 temp = 0;
		u64 polyCount = 0;
		if (!checkedMul(params.mMu, params.mTau, ct1Polys) ||
			!checkedMul(levels, width, temp) ||
			!checkedMul(temp, 2u, temp) ||
			!checkedMul(temp, tauMax, lacctPolys) ||
			!checkedAdd(ct1Polys, lacctPolys, polyCount))
			return false;

		u64 ringParamsBytes = 0;
		if (!checkedMul(params.mRing.mCoeffModulusBits.size(), sizeof(u16), ringParamsBytes) ||
			!checkedAdd(ringParamsBytes, 8u, ringParamsBytes))
			return false;
		u64 fixedBytes = 0;
		if (!checkedAdd(
				ringParamsBytes,
				5u * sizeof(u32) + 3u * sizeof(u8) + sizeof(i64) + 32u,
				fixedBytes))
			return false;
		return payloadFromPolyCount(fixedBytes, polyCount, params.mRing, out);
	}

	bool rootOfflinePayloadSize(const ShrinkExpandParams& params, u32 tauHi, u64& out)
	{
		if (tauHi == 0 || params.mRing.mCoeffModulusBits.empty() ||
			params.mRing.mPolyModulusDegree == 0 || params.mGadgetLogBase == 0)
			return false;

		u64 leftWidth = 0;
		if (!checkedMul(tauHi, params.mRing.mCoeffModulusBits.size(), leftWidth) ||
			leftWidth == 0 || leftWidth > std::numeric_limits<u32>::max())
			return false;
		u64 width = 0;
		u64 levels = 0;
		if (!nextPowerOfTwoAndLog(static_cast<u32>(leftWidth), width, levels))
			return false;

		constexpr u64 statSec = 40;
		const u64 logN = static_cast<u64>(std::ceil(std::log2(static_cast<double>(params.mRing.mPolyModulusDegree))));
		const u64 slackNumerator = 2u * statSec + logN + 1u;
		const u64 slack = std::max<u64>(1, (slackNumerator + params.mGadgetLogBase - 1u) / params.mGadgetLogBase);
		const u64 randomizer = static_cast<u64>(params.mTau) + slack;

		u64 ctRPolys = 0;
		u64 lacctPolys = 0;
		u64 topPolys = 0;
		u64 temp = 0;
		u64 polyCount = 0;
		if (!checkedMul(leftWidth, tauHi, ctRPolys) ||
			!checkedMul(levels, width, temp) ||
			!checkedMul(temp, 2u, temp) ||
			!checkedMul(temp, static_cast<u64>(tauHi) + 1u, lacctPolys) ||
			!checkedAdd(tauHi, randomizer, temp) ||
			!checkedMul(leftWidth, temp, topPolys) ||
			!checkedAdd(ctRPolys, lacctPolys, polyCount) ||
			!checkedAdd(polyCount, topPolys, polyCount) ||
			!checkedAdd(polyCount, randomizer, polyCount))
			return false;

		u64 ringParamsBytes = 0;
		if (!checkedMul(params.mRing.mCoeffModulusBits.size(), sizeof(u16), ringParamsBytes) ||
			!checkedAdd(ringParamsBytes, 8u, ringParamsBytes))
			return false;
		u64 fixedBytes = 0;
		return checkedAdd(ringParamsBytes, 72u, fixedBytes) &&
			payloadFromPolyCount(fixedBytes, polyCount, params.mRing, out);
	}

    Buffer encode(const KeyDeriveRequest& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return encodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs, options, useGpu, profile);
    }

    Buffer encode(const KeyDeriveResponse& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return encodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs, options, useGpu, profile);
    }

    Buffer encode(const ShrinkExpandOfflineMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return encode(message, 1, options, useGpu, profile, cpuBenchmark);
    }

    static Buffer encodeShrinkExpandOfflineTensors(
        const ShrinkExpandParams& params,
        const RingTensor& ct1,
        const ShrinkExpandLacct& lacct,
        u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        HostStep phase(profile, "setup codec: encode shrink expand", &cpuBenchmark);
        BufferWriter writer(
            paramsByteSize(params) +
            2u * sizeof(u32) +
            ringBatchByteSize(ct1.mPolys) +
            4u * sizeof(u32) +
            ringBatchByteSize(lacct.mCt.mPolys), workers, options, useGpu, profile, cpuBenchmark, compute);
        writer.writeParams(params);
        writer.writeU32(ct1.mRows);
        writer.writeU32(ct1.mCols);
        writer.writeRingBatch(ct1.mPolys);
        writer.writeU32(lacct.mWidthPadded);
        writer.writeU32(lacct.mLevels);
        writer.writeU32(lacct.mCt.mRows);
        writer.writeU32(lacct.mCt.mCols);
        writer.writeRingBatch(lacct.mCt.mPolys);
        return writer.finish();
    }

    Buffer encode(const ShrinkExpandOfflineMessage& message, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        return encodeShrinkExpandOfflineTensors(message.mParams,
            message.mLazyCt1 ? message.mLazyCt1->get() : message.mCt1,
            message.mLazyLacct ? message.mLazyLacct->get() : message.mLacct, workers, options, useGpu, profile, cpuBenchmark, compute);
    }

    Buffer encodeShrinkExpandOfflineState(const ShrinkExpandSenderState& state, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        if (state.mSharedHostState)
            return encodeShrinkExpandOfflineState(*state.mSharedHostState, workers, options, useGpu, profile, cpuBenchmark);
        std::optional<detail::ShrinkExpandScratch::Lease> lease;
        if (useGpu && workers > 1) lease.emplace(detail::ShrinkExpandScratch::acquire(state.mCpuScratch));
        auto* compute = lease ? &lease->cpuRows() : nullptr;
        if ((!state.mLazyCt1 && !state.mLazyLacct) ||
            std::endian::native != std::endian::little)
            return encodeShrinkExpandOfflineTensors(state.mParams, state.hostCt1(), state.hostLacct(), workers, options, useGpu, profile, cpuBenchmark, compute);

        HostStep phase(profile, "setup codec: encode resident shrink expand", &cpuBenchmark);
        const u64 wordsPerPoly = ringPolyCoeffCount(state.mParams.mRing);
        const auto tensorWords = [&](const RingTensor& tensor) -> u32 {
            if (!wordsPerPoly || ringTensorSize(tensor) >
                std::numeric_limits<u32>::max() / wordsPerPoly)
                throw std::length_error("LogVole resident tensor is too large to encode");
            return static_cast<u32>(ringTensorSize(tensor) * wordsPerPoly);
        };
        const u32 ct1Words = tensorWords(state.mCt1);
        const u32 lacctWords = tensorWords(state.mLacct.mCt);
        BufferWriter writer(paramsByteSize(state.mParams) + 8u * sizeof(u32) +
            (static_cast<std::size_t>(ct1Words) + lacctWords) * sizeof(u64), workers, options, useGpu, profile, cpuBenchmark, compute);
        const auto writeTensor = [&](const RingTensor& tensor, u32 words,
                                     const auto& lazy, const auto& host) {
            const auto writeHost = [&](const RingTensor& materialized) {
                if (materialized.mRows != tensor.mRows || materialized.mCols != tensor.mCols ||
                    ringTensorSize(materialized) != materialized.mPolys.size() ||
                    !validateRingBatchShape(materialized.mPolys, state.mParams.mRing) ||
                    ringBatchCoeffCount(materialized.mPolys) != words)
                    throw std::invalid_argument("LogVole resident tensor host shape does not match wire metadata");
                writer.writeRingBatch(materialized.mPolys);
            };
            if (!lazy)
            {
                writeHost(tensor);
                return;
            }
            const auto start = writer.mOffset;
            writer.writeU32(words);
            const auto bytes = static_cast<std::size_t>(words) * sizeof(u64);
            if (lazy->copyCoefficientsTo(writer.mBuffer.wireView().subspan(writer.mOffset, bytes), options.mWire))
                writer.mOffset += bytes;
            else
            {
                writer.mOffset = start;
                writeHost(host());
            }
        };
        writer.writeParams(state.mParams);
        writer.writeU32(state.mCt1.mRows);
        writer.writeU32(state.mCt1.mCols);
        writeTensor(state.mCt1, ct1Words, state.mLazyCt1,
            [&]() -> const RingTensor& { return state.hostCt1(); });
        writer.writeU32(state.mLacct.mWidthPadded);
        writer.writeU32(state.mLacct.mLevels);
        writer.writeU32(state.mLacct.mCt.mRows);
        writer.writeU32(state.mLacct.mCt.mCols);
        writeTensor(state.mLacct.mCt, lacctWords, state.mLazyLacct,
            [&]() -> const RingTensor& { return state.hostLacct().mCt; });
        return writer.finish();
    }

    Buffer encode(const PolyMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        BufferWriter writer(2u * sizeof(u32) + u64VectorByteSize(message.mCoeffs), 1, options, useGpu, profile, cpuBenchmark);
        writer.writeU32(message.mPolyModulusDegree);
        writer.writeU32(message.mCoeffModulusCount);
        writer.writeU64Vector(message.mCoeffs);
        return writer.finish();
    }

    Buffer encode(const SeedMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        BufferWriter writer(message.mSeed.size(), 1, options, useGpu, profile, cpuBenchmark);
        writer.writeBytes(std::span<const u8>(message.mSeed.data(), message.mSeed.size()));
        return writer.finish();
    }

    Buffer encode(const RootOfflineMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return encode(message, 1, options, useGpu, profile, cpuBenchmark);
    }

    namespace
    {
        struct RootWireLayout
        {
            std::size_t mBytes = 0;
            std::size_t mWordsPerPoly = 0;
            u32 mPublicBStarCount = 0;
            bool mOwnedPublicBStar = false;
        };

        RootWireLayout rootWireLayout(const RootOfflineMessage& message)
        {
            RootWireLayout layout{};
            layout.mWordsPerPoly = ringPolyCoeffCount(message.mRing);
            const auto tensorWords = [&](const RingTensor& tensor) -> u32 {
                if (!layout.mWordsPerPoly || ringTensorSize(tensor) >
                    std::numeric_limits<u32>::max() / layout.mWordsPerPoly)
                    throw std::length_error("LogVole resident Root tensor is too large to encode");
                return static_cast<u32>(ringTensorSize(tensor) * layout.mWordsPerPoly);
            };
            const auto tensorBytes = [&](const RingTensor& tensor,
                                         const auto& lazy) -> std::size_t {
                return lazy ? sizeof(u32) + static_cast<std::size_t>(tensorWords(tensor)) * sizeof(u64)
                            : ringBatchByteSize(tensor.mPolys);
            };
            layout.mOwnedPublicBStar = message.mOwnedPublicBStarWire &&
                message.mOwnedPublicBStarWire == message.mLazyPublicBStar;
            if (message.mOwnedPublicBStarWire && !layout.mOwnedPublicBStar)
                throw std::invalid_argument("LogVole Root BStar wire owner does not match its lazy state");
            layout.mPublicBStarCount = layout.mOwnedPublicBStar
                ? message.mPublicBStarCount : checkedVectorSize(message.mPublicBStarNtt);
            if (layout.mOwnedPublicBStar &&
                (!layout.mWordsPerPoly ||
                 layout.mPublicBStarCount > std::numeric_limits<u32>::max() / layout.mWordsPerPoly ||
                 !message.mPublicBStarNtt.empty() ||
                 message.mOwnedPublicBStarWire->encodedCoefficients().size() !=
                    static_cast<std::size_t>(layout.mPublicBStarCount) *
                    layout.mWordsPerPoly * sizeof(u64)))
                throw std::invalid_argument("LogVole Root BStar wire shape does not match metadata");
            const auto publicBStarBytes = layout.mOwnedPublicBStar
                ? sizeof(u32) + static_cast<std::size_t>(layout.mPublicBStarCount) *
                    layout.mWordsPerPoly * sizeof(u64)
                : ringBatchByteSize(message.mPublicBStarNtt);
            layout.mBytes = ringParamsByteSize(message.mRing) +
                5u * sizeof(u32) + 2u * sizeof(u32) +
                tensorBytes(message.mCtR, message.mLazyCtR) +
                4u * sizeof(u32) +
                tensorBytes(message.mLacctLeft.mCt, message.mLazyLacctLeft) +
                2u * sizeof(u32) +
                tensorBytes(message.mTopCt, message.mLazyTopCt) +
                sizeof(u32) + publicBStarBytes;
            return layout;
        }
    }

    std::size_t rootOfflineWireSize(const RootOfflineMessage& message)
    {
        return rootWireLayout(message).mBytes;
    }

    Buffer encode(const RootOfflineMessage& message, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        return encodeRootOfflineIntoBuffer(message,
            Buffer(rootOfflineWireSize(message), options.mWire, useGpu, profile), workers, options, useGpu, profile, compute, cpuBenchmark);
    }

    Buffer encodeRootOfflineIntoBuffer(const RootOfflineMessage& message,
        Buffer&& reserved, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, detail::CpuRowScratch* compute, CpuBenchmarkState cpuBenchmark)
    {
        HostStep phase(profile, "setup codec: encode root", &cpuBenchmark);
        const auto layout = rootWireLayout(message);
        if (reserved.size() != layout.mBytes)
            throw std::invalid_argument("LogVole reserved Root wire size does not match message");
        const std::size_t wordsPerPoly = layout.mWordsPerPoly;
        const auto tensorWords = [&](const RingTensor& tensor) -> u32 {
            if (!wordsPerPoly || ringTensorSize(tensor) >
                std::numeric_limits<u32>::max() / wordsPerPoly)
                throw std::length_error("LogVole resident Root tensor is too large to encode");
            return static_cast<u32>(ringTensorSize(tensor) * wordsPerPoly);
        };
        const bool ownedPublicBStar = layout.mOwnedPublicBStar;
        const u32 publicBStarCount = layout.mPublicBStarCount;
        BufferWriter writer(std::move(reserved), workers, options, useGpu, profile, cpuBenchmark, compute);
        const auto writeTensor = [&](const RingTensor& tensor, const auto& lazy) {
            if (!lazy)
            {
                writer.writeRingBatch(tensor.mPolys);
                return;
            }
            const u32 words = tensorWords(tensor);
            const auto writeHost = [&] {
                const auto& host = lazy->get();
                if (host.mRows != tensor.mRows || host.mCols != tensor.mCols ||
                    ringTensorSize(host) != host.mPolys.size() ||
                    !validateRingBatchShape(host.mPolys, message.mRing) ||
                    ringBatchCoeffCount(host.mPolys) != words)
                    throw std::invalid_argument("LogVole resident Root tensor host shape does not match wire metadata");
                writer.writeRingBatch(host.mPolys);
            };
            if constexpr (std::endian::native != std::endian::little)
            {
                writeHost();
            }
            else
            {
                const auto start = writer.mOffset;
                writer.writeU32(words);
                const auto bytes = static_cast<std::size_t>(words) * sizeof(u64);
                if (lazy->copyCoefficientsTo(
                        writer.mBuffer.wireView().subspan(writer.mOffset, bytes), options.mWire))
                    writer.mOffset += bytes;
                else
                {
                    writer.mOffset = start;
                    writeHost();
                }
            }
        };
        writer.writeRingParams(message.mRing);
        writer.writeU32(message.mTauHi);
        writer.writeU32(message.mGadgetLogBase);
        writer.writeU32(message.mPlaintextModulusBits);
        writer.writeU32(message.mLeftWidth);
        writer.writeU32(message.mRandomizerWidth);
        writer.writeU32(message.mCtR.mRows);
        writer.writeU32(message.mCtR.mCols);
        writeTensor(message.mCtR, message.mLazyCtR);
        writer.writeU32(message.mLacctLeft.mWidthPadded);
        writer.writeU32(message.mLacctLeft.mLevels);
        writer.writeU32(message.mLacctLeft.mCt.mRows);
        writer.writeU32(message.mLacctLeft.mCt.mCols);
        writeTensor(message.mLacctLeft.mCt, message.mLazyLacctLeft);
        writer.writeU32(message.mTopCt.mRows);
        writer.writeU32(message.mTopCt.mCols);
        writeTensor(message.mTopCt, message.mLazyTopCt);
        writer.writeU32(publicBStarCount);
        if (!ownedPublicBStar)
            writer.writeRingBatch(message.mPublicBStarNtt);
        else
        {
            const auto words = static_cast<u32>(publicBStarCount * wordsPerPoly);
            const auto start = writer.mOffset;
            writer.writeU32(words);
            const auto bytes = static_cast<std::size_t>(words) * sizeof(u64);
            if (std::endian::native == std::endian::little &&
                message.mOwnedPublicBStarWire->copyCoefficientsTo(
                    writer.mBuffer.wireView().subspan(writer.mOffset, bytes), options.mWire))
                writer.mOffset += bytes;
            else
            {
                writer.mOffset = start;
                const auto& host = message.mLazyPublicBStar->get();
                if (host.mRows != publicBStarCount || host.mCols != 1 ||
                    host.mPolys.size() != publicBStarCount ||
                    !validateRingBatchShape(host.mPolys, message.mRing) ||
                    ringBatchCoeffCount(host.mPolys) != words)
                    throw std::invalid_argument("LogVole resident Root BStar host shape does not match wire metadata");
                writer.writeRingBatch(host.mPolys);
            }
        }
        return writer.finish();
    }

    Buffer encode(const RootDigestMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        BufferWriter writer(u64VectorByteSize(message.mDPrimeCoeffs), 1, options, useGpu, profile, cpuBenchmark);
        writeRootU64Vector(writer, message.mDPrimeCoeffs);
        return writer.finish();
    }

    Buffer encode(const RootResponseMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        BufferWriter writer(
            sizeof(u32) +
            message.mSeed.size() +
            u64VectorByteSize(message.mSkPrimeCoeffs), 1, options, useGpu, profile, cpuBenchmark);
        writer.writeU32(checkedVectorSize(message.mSeed));
        writer.writeBytes(std::span<const u8>(message.mSeed.data(), message.mSeed.size()));
        writeRootU64Vector(writer, message.mSkPrimeCoeffs);
        return writer.finish();
    }

    bool decode(std::span<const u8> payload, KeyDeriveRequest& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return decodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    bool decode(std::span<const u8> payload, KeyDeriveResponse& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return decodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return decode(payload, message, 1, options, useGpu, profile, cpuBenchmark);
    }

    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        HostStep phase(profile, "setup codec: decode shrink expand", &cpuBenchmark);
        message.mLazyCt1.reset();
        message.mLazyLacct.reset();
        u64 offset = 0;
        if (!readParams(payload, offset, message.mParams) ||
            !readOfflineRingTensor(payload, offset, message.mParams.mRing, message.mCt1, workers, useGpu, cpuBenchmark, compute) ||
            !readU32(payload, offset, message.mLacct.mWidthPadded) ||
            !readU32(payload, offset, message.mLacct.mLevels) ||
            !readOfflineRingTensor(payload, offset, message.mParams.mRing, message.mLacct.mCt, workers, useGpu, cpuBenchmark, compute) ||
            offset != payload.size())
        {
            return false;
        }
        return true;
    }

    namespace
    {
        class EncodedTensorHostState final : public LazyRingTensorHostState
        {
        public:
            EncodedTensorHostState(std::shared_ptr<const Buffer> payload,
                std::size_t offset, std::size_t bytes, u32 rows, u32 cols, std::size_t words, std::shared_ptr<HostStepProfiler> profile)
                : mPayload(std::move(payload)), mOffset(offset), mBytes(bytes), mPolyWords(words), mProfile(std::move(profile))
            {
                mHost.mRows = rows;
                mHost.mCols = cols;
            }
            ConstWireView encodedCoefficients() const override
            {
                return mPayload->wireView().subspan(mOffset, mBytes);
            }
            bool copyCoefficientsTo(WireView destination, const LogVoleWireOptions&) const override
            {
                if (destination.size() != mBytes) return false;
                std::memmove(destination.data(), mPayload->data() + mOffset, mBytes);
                return true;
            }
            const RingTensor& get() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep phase(mProfile.get(), "setup codec: deferred tensor materialization");
                    std::vector<RnsPoly> polys(static_cast<std::size_t>(mHost.mRows) * mHost.mCols);
                    const auto bytes = mPolyWords * sizeof(u64);
                    for (std::size_t i = 0; i < polys.size(); ++i)
                    {
                        polys[i].mCoeffs.resize(mPolyWords);
                        std::memcpy(polys[i].mCoeffs.data(), mPayload->data() + mOffset + i * bytes, bytes);
                    }
                    mHost.mPolys = std::move(polys);
                });
                return mHost;
            }
        private:
            std::shared_ptr<const Buffer> mPayload;
            std::size_t mOffset, mBytes, mPolyWords;
            const std::shared_ptr<HostStepProfiler> mProfile;
            mutable std::once_flag mOnce;
            mutable RingTensor mHost;
        };
    }

    bool decodeShrinkExpandOfflineForTransport(Buffer&& payload,
        ShrinkExpandOfflineMessage& message, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, const std::shared_ptr<HostStepProfiler>& profileOwner, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        auto* profile = profileOwner.get();
        bool enabled = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        enabled = useGpu;
#endif
        if (!enabled || std::endian::native != std::endian::little)
            return decode(payload, message, workers, options, useGpu, profile, cpuBenchmark, compute);

        HostStep phase(profile, "setup codec: retain encoded shrink expand", &cpuBenchmark);
        ShrinkExpandOfflineMessage next{};
        u64 offset = 0;
        if (!readParams(payload, offset, next.mParams) || !validateShrinkExpandParams(next.mParams))
            return false;
        const u64 words = ringPolyCoeffCount(next.mParams.mRing);
        struct Segment { std::size_t offset = 0, bytes = 0; } ct1, lacct;
        const auto readTensor = [&](RingTensor& tensor, Segment& segment) {
            u32 coeffCount = 0;
            if (!readU32(payload, offset, tensor.mRows) ||
                !readU32(payload, offset, tensor.mCols) ||
                !readU32(payload, offset, coeffCount) || !words ||
                !tensor.mRows || !tensor.mCols ||
                ringTensorSize(tensor) > static_cast<u64>(coeffCount) / words ||
                ringTensorSize(tensor) * words != coeffCount ||
                coeffCount > (payload.size() - offset) / sizeof(u64)) return false;
            segment.offset = offset;
            segment.bytes = static_cast<std::size_t>(coeffCount) * sizeof(u64);
            offset += segment.bytes;
            return true;
        };
        if (!readTensor(next.mCt1, ct1) ||
            !readU32(payload, offset, next.mLacct.mWidthPadded) ||
            !readU32(payload, offset, next.mLacct.mLevels) ||
            !readTensor(next.mLacct.mCt, lacct) || offset != payload.size() ||
            next.mCt1.mRows != next.mParams.mMu || next.mCt1.mCols != next.mParams.mTau ||
            !next.mLacct.mWidthPadded || !next.mLacct.mLevels ||
            static_cast<u64>(next.mLacct.mLevels) * next.mLacct.mWidthPadded != next.mLacct.mCt.mRows)
            return false;

        auto owner = std::make_shared<const Buffer>(std::move(payload));
        next.mLazyCt1 = std::make_shared<EncodedTensorHostState>(owner,
            ct1.offset, ct1.bytes, next.mCt1.mRows, next.mCt1.mCols, words, profileOwner);
        auto lazyLacct = std::make_shared<EncodedTensorHostState>(std::move(owner),
            lacct.offset, lacct.bytes, next.mLacct.mCt.mRows, next.mLacct.mCt.mCols, words, profileOwner);
        next.mLazyLacct = detail::makeLazyLacctHostState(next.mLacct, std::move(lazyLacct));
        message = std::move(next);
        return true;
    }

    bool decode(std::span<const u8> payload, PolyMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        u64 offset = 0;
        if (!readU32(payload, offset, message.mPolyModulusDegree) ||
            !readU32(payload, offset, message.mCoeffModulusCount) ||
            !readU64Vector(payload, offset, message.mCoeffs))
        {
            return false;
        }
        return offset == payload.size();
    }

    bool decode(std::span<const u8> payload, SeedMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        if (payload.empty())
        {
            return false;
        }

        assignRange(message.mSeed, payload.begin(), payload.end());
        return true;
    }

    bool decode(std::span<const u8> payload, RootOfflineMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        return decode(payload, message, 1, options, useGpu, profile, cpuBenchmark);
    }

    bool decode(std::span<const u8> payload, RootOfflineMessage& message, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        HostStep phase(profile, "setup codec: decode root", &cpuBenchmark);
        u64 offset = 0;
        u32 publicBStarCount = 0;

        if (!readRingParams(payload, offset, message.mRing) ||
            !readU32(payload, offset, message.mTauHi) ||
            !readU32(payload, offset, message.mGadgetLogBase) ||
            !readU32(payload, offset, message.mPlaintextModulusBits) ||
            !readU32(payload, offset, message.mLeftWidth) ||
            !readU32(payload, offset, message.mRandomizerWidth) ||
            !readOfflineRingTensor(payload, offset, message.mRing, message.mCtR, workers, useGpu, cpuBenchmark, compute) ||
            !readU32(payload, offset, message.mLacctLeft.mWidthPadded) ||
            !readU32(payload, offset, message.mLacctLeft.mLevels) ||
            !readOfflineRingTensor(payload, offset, message.mRing, message.mLacctLeft.mCt, workers, useGpu, cpuBenchmark, compute) ||
            !readOfflineRingTensor(payload, offset, message.mRing, message.mTopCt, workers, useGpu, cpuBenchmark, compute) ||
            !readU32(payload, offset, publicBStarCount) ||
            !readOfflineRingBatch(
                payload, offset, message.mRing, publicBStarCount, message.mPublicBStarNtt, workers, useGpu, cpuBenchmark, compute) ||
            offset != payload.size())
        {
            return false;
        }

        message.mLazyCtR.reset();
        message.mLazyLacctLeft.reset();
        message.mLazyTopCt.reset();
        message.mLazyPublicBStar.reset();
        message.mOwnedCtRWire.reset();
        message.mOwnedLacctLeftWire.reset();
        message.mOwnedTopCtWire.reset();
        message.mOwnedPublicBStarWire.reset();
        message.mPublicBStarCount = publicBStarCount;
        return true;
    }

    bool decodeRootOfflineForTransport(Buffer&& payload,
        RootOfflineMessage& message, u32 workers, const LogVoleEncodingOptions& options, bool useGpu, const std::shared_ptr<HostStepProfiler>& profileOwner, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* compute)
    {
        auto* profile = profileOwner.get();
        bool enabled = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        enabled = useGpu;
#endif
        if (!enabled || std::endian::native != std::endian::little)
            return decode(payload, message, workers, options, useGpu, profile, cpuBenchmark, compute);

        HostStep phase(profile, "setup codec: retain encoded root tensors", &cpuBenchmark);
        RootOfflineMessage next{};
        u64 offset = 0;
        u32 publicBStarCount = 0;
        struct Segment { std::size_t offset = 0, bytes = 0; } ctR, lacct, topCt, publicBStar;
        const auto readOwnedTensor = [&](RingTensor& tensor, Segment& segment) {
            u32 coeffCount = 0;
            if (!readU32(payload, offset, tensor.mRows) ||
                !readU32(payload, offset, tensor.mCols) ||
                (tensor.mRows != 0 &&
                 tensor.mCols > std::numeric_limits<u32>::max() / tensor.mRows) ||
                !readU32(payload, offset, coeffCount) ||
                static_cast<u64>(coeffCount) > (payload.size() - offset) / sizeof(u64))
                return false;

            // Match readOfflineRingBatch's shape check before retaining any
            // bytes. Division avoids overflow for adversarial wire dimensions.
            const u64 words = ringPolyCoeffCount(next.mRing);
            const u64 polys = ringTensorSize(tensor);
            if (!words || polys > static_cast<u64>(coeffCount) / words ||
                polys * words != coeffCount)
                return false;
            segment.offset = static_cast<std::size_t>(offset);
            segment.bytes = static_cast<std::size_t>(coeffCount) * sizeof(u64);
            offset += segment.bytes;
            return true;
        };
        const auto readOwnedPublicBStar = [&](u32 count, Segment& segment) {
            u32 coeffCount = 0;
            if (!readU32(payload, offset, coeffCount) ||
                static_cast<u64>(coeffCount) > (payload.size() - offset) / sizeof(u64))
                return false;
            const u64 words = ringPolyCoeffCount(next.mRing);
            if (!words || static_cast<u64>(count) > static_cast<u64>(coeffCount) / words ||
                static_cast<u64>(count) * words != coeffCount)
                return false;
            segment.offset = static_cast<std::size_t>(offset);
            segment.bytes = static_cast<std::size_t>(coeffCount) * sizeof(u64);
            offset += segment.bytes;
            return true;
        };
        if (!readRingParams(payload, offset, next.mRing) ||
            !readU32(payload, offset, next.mTauHi) ||
            !readU32(payload, offset, next.mGadgetLogBase) ||
            !readU32(payload, offset, next.mPlaintextModulusBits) ||
            !readU32(payload, offset, next.mLeftWidth) ||
            !readU32(payload, offset, next.mRandomizerWidth) ||
            !readOwnedTensor(next.mCtR, ctR) ||
            !readU32(payload, offset, next.mLacctLeft.mWidthPadded) ||
            !readU32(payload, offset, next.mLacctLeft.mLevels) ||
            !readOwnedTensor(next.mLacctLeft.mCt, lacct) ||
            !readOwnedTensor(next.mTopCt, topCt) ||
            !readU32(payload, offset, publicBStarCount) ||
            !readOwnedPublicBStar(publicBStarCount, publicBStar) ||
            offset != payload.size())
            return false;

        auto owner = std::make_shared<const Buffer>(std::move(payload));
        const auto words = static_cast<std::size_t>(ringPolyCoeffCount(next.mRing));
        next.mLazyCtR = std::make_shared<EncodedTensorHostState>(owner,
            ctR.offset, ctR.bytes, next.mCtR.mRows, next.mCtR.mCols, words, profileOwner);
        next.mOwnedCtRWire = next.mLazyCtR;
        next.mLazyLacctLeft = std::make_shared<EncodedTensorHostState>(owner,
            lacct.offset, lacct.bytes, next.mLacctLeft.mCt.mRows,
            next.mLacctLeft.mCt.mCols, words, profileOwner);
        next.mOwnedLacctLeftWire = next.mLazyLacctLeft;
        next.mLazyTopCt = std::make_shared<EncodedTensorHostState>(owner,
            topCt.offset, topCt.bytes, next.mTopCt.mRows, next.mTopCt.mCols,
            words, profileOwner);
        next.mOwnedTopCtWire = next.mLazyTopCt;
        next.mPublicBStarCount = publicBStarCount;
        next.mLazyPublicBStar = std::make_shared<EncodedTensorHostState>(
            std::move(owner), publicBStar.offset, publicBStar.bytes,
            publicBStarCount, 1u, words, profileOwner);
        next.mOwnedPublicBStarWire = next.mLazyPublicBStar;
        message = std::move(next);
        return true;
    }

    bool decode(std::span<const u8> payload, RootDigestMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        u64 offset = 0;
        if (!readRootU64Vector(payload, offset, message.mDPrimeCoeffs) ||
            offset != payload.size() ||
            message.mDPrimeCoeffs.empty())
        {
            return false;
        }
        return true;
    }

    bool decode(std::span<const u8> payload, RootResponseMessage& message, const LogVoleEncodingOptions& options, bool useGpu, HostStepProfiler* profile, CpuBenchmarkState cpuBenchmark)
    {
        u64 offset = 0;
        u32 seedSize = 0;
        if (!readU32(payload, offset, seedSize) ||
            offset + seedSize > payload.size())
        {
            return false;
        }

        assignRange(
            message.mSeed,
            payload.begin() + static_cast<std::ptrdiff_t>(offset),
            payload.begin() + static_cast<std::ptrdiff_t>(offset + seedSize));
        offset += seedSize;

        // An empty seed is the Ct2SeedMode::PublicSeed encoding: there is no seed
        // on the wire because the receiver derives it from the transcript. The
        // receiver rejects an empty seed when its own mode says it should have
        // received one, so this stays unambiguous.
        if (!readRootU64Vector(payload, offset, message.mSkPrimeCoeffs) ||
            offset != payload.size() ||
            message.mSkPrimeCoeffs.empty())
        {
            return false;
        }
        return true;
    }

    PolyMessage makePolyMessage(const RingParams& params, const RnsPoly& poly)
    {
        PolyMessage message{};
        message.mPolyModulusDegree = params.mPolyModulusDegree;
        message.mCoeffModulusCount = static_cast<u32>(params.mCoeffModulusBits.size());
        message.mCoeffs = poly.mCoeffs;
        return message;
    }

    bool readPolyMessage(const RingParams& params, PolyMessage& message, RnsPoly& out)
    {
        if (message.mPolyModulusDegree != params.mPolyModulusDegree ||
            message.mCoeffModulusCount != params.mCoeffModulusBits.size() ||
            message.mCoeffs.size() != static_cast<std::size_t>(ringPolyCoeffCount(params)))
        {
            return false;
        }

        out.mCoeffs = std::move(message.mCoeffs);
        return true;
    }
}
