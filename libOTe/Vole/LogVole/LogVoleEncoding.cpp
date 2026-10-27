#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include <cuda_runtime_api.h>
#endif

#include <algorithm>
#include <cmath>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>
#if defined(__linux__)
#include <sys/mman.h>
#endif

namespace osuCrypto::LogVole
{
    namespace
    {
        std::mutex rootCudaWireEvidenceMutex;
        RootWireCudaAllocEvidence lastRootCudaWireEvidence{};

        u64 rootCudaWireSteadyNs()
        {
            return static_cast<u64>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        thread_local bool requestRootCudaWireAllocation = false;
        thread_local u64 rootCudaWireAllocationRunId = 0;

        // CUDA-owned Root wire pages are local to this sender process. The
        // vector allocator remains responsible for their lifetime; released
        // blocks may be reused but are never freed while coproto or TCP owns
        // the moved Buffer. The process-local pool is deliberately immortal.
        struct RootCudaWirePool
        {
            struct Block
            {
                void* mPointer = nullptr;
                std::size_t mCapacity = 0;
                std::size_t mActiveBytes = 0;
                u64 mOwnerRunId = 0;
            };

            std::map<std::size_t, std::vector<Block*>> mFree;
            std::unordered_map<void*, std::unique_ptr<Block>> mBlocks;
            std::map<std::uintptr_t, Block*> mActive;
            std::mutex mMutex;

            Block* findActiveLocked(const void* pointer,
                std::size_t bytes) const noexcept
            {
                if (!pointer || !bytes) return nullptr;
                const auto address = reinterpret_cast<std::uintptr_t>(pointer);
                auto it = mActive.upper_bound(address);
                if (it == mActive.begin()) return nullptr;
                --it;
                Block* const block = it->second;
                const auto offset = address - it->first;
                if (offset >= block->mActiveBytes ||
                    bytes > block->mActiveBytes - offset)
                    return nullptr;
                return block;
            }

            void* allocate(std::size_t bytes, std::size_t alignment,
                u64 ownerRunId) noexcept
            {
                if (!bytes || alignment > 4096u) return nullptr;
                try
                {
                    std::lock_guard lock(mMutex);
                    auto it = mFree.lower_bound(bytes);
                    while (it != mFree.end() && it->second.empty()) ++it;
                    const auto largestReusable = bytes <=
                        std::numeric_limits<std::size_t>::max() / 2u
                        ? 2u * bytes : std::numeric_limits<std::size_t>::max();
                    if (it != mFree.end() && it->first <= largestReusable)
                    {
                        Block* const block = it->second.back();
                        const auto [activeIt, activeInserted] = mActive.emplace(
                            reinterpret_cast<std::uintptr_t>(
                                block->mPointer), block);
                        (void)activeIt;
                        if (!activeInserted) return nullptr;
                        block->mActiveBytes = bytes;
                        block->mOwnerRunId = ownerRunId;
                        it->second.pop_back();
                        return block->mPointer;
                    }
                }
                catch (...) { return nullptr; }

                void* pointer = nullptr;
                const auto error = cudaHostAlloc(&pointer, bytes,
                    cudaHostAllocPortable);
                if (error != cudaSuccess)
                {
                    const auto pending = cudaPeekAtLastError();
                    if (pending == error) (void)cudaGetLastError();
                    return nullptr;
                }
                if (reinterpret_cast<std::uintptr_t>(pointer) % alignment)
                {
                    (void)cudaFreeHost(pointer);
                    return nullptr;
                }
                try
                {
                    auto block = std::make_unique<Block>(Block{
                        pointer, bytes, bytes, ownerRunId});
                    std::lock_guard lock(mMutex);
                    auto [it, inserted] = mBlocks.emplace(pointer,
                        std::move(block));
                    if (!inserted)
                    {
                        (void)cudaFreeHost(pointer);
                        return nullptr;
                    }
                    try
                    {
                        const auto [activeIt, activeInserted] = mActive.emplace(
                            reinterpret_cast<std::uintptr_t>(pointer),
                            it->second.get());
                        (void)activeIt;
                        if (!activeInserted)
                            throw std::runtime_error("Root CUDA wire range already active");
                    }
                    catch (...)
                    {
                        mBlocks.erase(it);
                        throw;
                    }
                    return pointer;
                }
                catch (...)
                {
                    (void)cudaFreeHost(pointer);
                    return nullptr;
                }
            }

            bool releaseKnown(void* pointer) noexcept
            {
                if (!pointer) return false;
                try
                {
                    std::lock_guard lock(mMutex);
                    auto it = mBlocks.find(pointer);
                    if (it == mBlocks.end()) return false;
                    if (mActive.erase(reinterpret_cast<std::uintptr_t>(pointer)))
                    {
                        Block* const block = it->second.get();
                        block->mActiveBytes = 0;
                        block->mOwnerRunId = 0;
                        try { mFree[block->mCapacity].push_back(block); }
                        catch (...) { /* Retain ownership without reuse. */ }
                    }
                    return true;
                }
                catch (...) { return true; }
            }

            bool contains(const void* pointer, std::size_t bytes) noexcept
            {
                try
                {
                    std::lock_guard lock(mMutex);
                    return findActiveLocked(pointer, bytes) != nullptr;
                }
                catch (...) { return false; }
            }

            bool contractActive(void* pointer, std::size_t oldBytes,
                std::size_t exactBytes) noexcept
            {
                if (!pointer || !exactBytes || exactBytes > oldBytes)
                    return false;
                try
                {
                    std::lock_guard lock(mMutex);
                    auto it = mActive.find(
                        reinterpret_cast<std::uintptr_t>(pointer));
                    if (it == mActive.end() ||
                        it->second->mActiveBytes != oldBytes)
                        return false;
                    it->second->mActiveBytes = exactBytes;
                    return true;
                }
                catch (...) { return false; }
            }

            u64 ownerRunId(const void* pointer,
                std::size_t bytes) noexcept
            {
                try
                {
                    std::lock_guard lock(mMutex);
                    Block* const block = findActiveLocked(pointer, bytes);
                    return block ? block->mOwnerRunId : 0;
                }
                catch (...) { return 0; }
            }
        };

        RootCudaWirePool& rootCudaWirePool()
        {
            static RootCudaWirePool* pool = new RootCudaWirePool();
            return *pool;
        }
#endif
    }

    namespace detail
    {
        void* allocateSetupWireBytes(std::size_t bytes, std::size_t alignment)
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
            if (requestRootCudaWireAllocation && gpu::enabled())
            {
                HostStep cudaAllocationStep("setup: CUDA-owned Root wire allocation");
                if (void* pointer = rootCudaWirePool().allocate(bytes,
                        alignment, rootCudaWireAllocationRunId))
                    return pointer;
            }
            const char* pinned = std::getenv("LV_GPU_SETUP_PINNED_WIRE");
            if (bytes >= (std::size_t{1} << 20) && alignment <= 4096 &&
                (!pinned || pinned[0] != '0') && gpu::enabled())
            {
                HostStep allocationStep("setup: reusable wire allocation");
                if (void* pointer = gpu::gpuTryAllocateSetupWireHost(bytes))
                {
                    if (reinterpret_cast<std::uintptr_t>(pointer) % alignment == 0) return pointer;
                    (void)gpu::gpuReleaseSetupWireHost(pointer);
                }
            }
#endif
            void* pointer = AlignedAllocator<u8>::aligned_malloc(bytes, alignment);
            if (!pointer) throw std::bad_alloc();
            return pointer;
        }

        void deallocateSetupWireBytes(void* pointer) noexcept
        {
            if (!pointer) return;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (rootCudaWirePool().releaseKnown(pointer)) return;
            // Allocation provenance, not the current runtime flag, determines
            // the matching release. Rollback may change while buffers survive.
            if (gpu::gpuReleaseSetupWireHost(pointer)) return;
#endif
            AlignedAllocator<u8>::aligned_free(pointer);
        }
    }

    void resetRootWireCudaAllocEvidence(u64 senderRunId,
        bool requested) noexcept
    {
        try
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            lastRootCudaWireEvidence = {};
            lastRootCudaWireEvidence.mSenderRunId = senderRunId;
            lastRootCudaWireEvidence.mRequested = requested;
        }
        catch (...) {}
    }

    void noteRootWireCudaAllocEligibility(u64 senderRunId,
        std::size_t wireBytes, bool eligible) noexcept
    {
        try
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            if (lastRootCudaWireEvidence.mSenderRunId != senderRunId) return;
            lastRootCudaWireEvidence.mWireBytes = static_cast<u64>(wireBytes);
            lastRootCudaWireEvidence.mEligible = eligible;
        }
        catch (...) {}
    }

    void noteRootWireCudaEarlyPlan(u64 senderRunId, bool requested,
        bool eligible, std::size_t forecastBytes, bool launched) noexcept
    {
        try
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            if (lastRootCudaWireEvidence.mSenderRunId != senderRunId) return;
            lastRootCudaWireEvidence.mEarlyRequested = requested;
            lastRootCudaWireEvidence.mEarlyEligible = eligible;
            lastRootCudaWireEvidence.mEarlyForecastBytes =
                static_cast<u64>(forecastBytes);
            lastRootCudaWireEvidence.mEarlyLaunched = launched;
        }
        catch (...) {}
    }

    void noteRootWireCudaEarlyJoin(u64 senderRunId, u64 joinWaitNs,
        bool adopted) noexcept
    {
        try
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            if (lastRootCudaWireEvidence.mSenderRunId != senderRunId) return;
            lastRootCudaWireEvidence.mEarlyJoinWaitNs = joinWaitNs;
            lastRootCudaWireEvidence.mEarlyAdopted = adopted;
            if (adopted)
            {
                lastRootCudaWireEvidence.mSelected = true;
                lastRootCudaWireEvidence.mDeclined = false;
            }
        }
        catch (...) {}
    }

    RootWireCudaAllocEvidence rootWireCudaAllocEvidenceSnapshot() noexcept
    {
        try
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            return lastRootCudaWireEvidence;
        }
        catch (...) { return {}; }
    }

    bool isRootCudaWireHostRange(const void* pointer,
        std::size_t bytes) noexcept
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        return rootCudaWirePool().contains(pointer, bytes);
#else
        (void)pointer;
        (void)bytes;
        return false;
#endif
    }

    void recordRootCudaWireDirectDownload(const void* pointer,
        std::size_t bytes, bool completed) noexcept
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!completed || !bytes) return;
        const u64 ownerRunId = rootCudaWirePool().ownerRunId(pointer, bytes);
        if (!ownerRunId) return;
        try
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            if (lastRootCudaWireEvidence.mSenderRunId != ownerRunId ||
                lastRootCudaWireEvidence.mDirectDownloadBytes >
                    std::numeric_limits<u64>::max() - bytes)
                return;
            lastRootCudaWireEvidence.mDirectDownloadBytes +=
                static_cast<u64>(bytes);
            ++lastRootCudaWireEvidence.mDirectDownloadCalls;
        }
        catch (...) {}
#else
        (void)pointer;
        (void)bytes;
        (void)completed;
#endif
    }

    Buffer reserveRootCudaWireBuffer(std::size_t bytes, u64 senderRunId,
        bool& cudaOwned, bool recordSelection)
    {
        cudaOwned = false;
        const u64 wallBegin = rootCudaWireSteadyNs();
        const u64 cpuBegin = cpuBenchmarkThreadNs();
        Buffer reserved;
#if defined(ENABLE_LOGVOLE_CUDA)
        struct RequestScope
        {
            bool mPreviousRequest = requestRootCudaWireAllocation;
            u64 mPreviousRunId = rootCudaWireAllocationRunId;
            explicit RequestScope(u64 runId)
            {
                requestRootCudaWireAllocation = true;
                rootCudaWireAllocationRunId = runId;
            }
            ~RequestScope()
            {
                requestRootCudaWireAllocation = mPreviousRequest;
                rootCudaWireAllocationRunId = mPreviousRunId;
            }
        } request(senderRunId);
#else
        (void)senderRunId;
#endif
        reserved.resize(bytes);
        cudaOwned = isRootCudaWireHostRange(reserved.data(), reserved.size());
        const u64 cpuElapsed = cpuBenchmarkThreadNs() - cpuBegin;
        const u64 wallEnd = rootCudaWireSteadyNs();
        {
            std::lock_guard lock(rootCudaWireEvidenceMutex);
            if (lastRootCudaWireEvidence.mSenderRunId == senderRunId)
            {
                lastRootCudaWireEvidence.mAllocationBeginNs = wallBegin;
                lastRootCudaWireEvidence.mAllocationEndNs = wallEnd;
                lastRootCudaWireEvidence.mAllocationCpuNs = cpuElapsed;
                if (recordSelection)
                {
                    lastRootCudaWireEvidence.mSelected = cudaOwned;
                    lastRootCudaWireEvidence.mDeclined =
                        lastRootCudaWireEvidence.mEligible && !cudaOwned;
                }
            }
        }
        return reserved;
    }

    bool shrinkRootCudaWireBuffer(Buffer& reserved,
        std::size_t exactBytes) noexcept
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!exactBytes || exactBytes > reserved.size() ||
            !isRootCudaWireHostRange(reserved.data(), reserved.size()))
            return false;
        const std::size_t oldBytes = reserved.size();
        if (!rootCudaWirePool().contractActive(reserved.data(),
                oldBytes, exactBytes)) return false;
        try { reserved.resize(exactBytes); }
        catch (...) { return false; }
        return reserved.size() == exactBytes &&
            isRootCudaWireHostRange(reserved.data(), exactBytes);
#else
        (void)reserved;
        (void)exactBytes;
        return false;
#endif
    }

    void adviseGpuSetupWireBuffer(Buffer& buffer)
    {
#if defined(__linux__) && defined(ENABLE_LOGVOLE_CUDA) && defined(MADV_HUGEPAGE)
        const char* flag = std::getenv("LV_GPU_SETUP_WIRE_HUGE_PAGES");
        if ((flag && flag[0] == '0') || !gpu::enabled() || buffer.size() < (std::size_t{8} << 20))
            return;
        if (gpu::gpuIsSetupWireHostRange(buffer.data(), buffer.size()) ||
            isRootCudaWireHostRange(buffer.data(), buffer.size())) return;
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
        // H200 A/B/A trials showed a consistent online win. This switch is
        // independent of the offline codec below. Non-little-endian hosts use
        // the established byte-at-a-time path.
        bool rootU64MemcpyCodecEnabled()
        {
            static const bool on = [] {
                const char* value = std::getenv("LV_ROOT_U64_MEMCPY_CODEC");
                return !(value && value[0] == '0');
            }();
            return on;
        }

        bool setupMemcpyCodecEnabled()
        {
            if constexpr (std::endian::native != std::endian::little)
            {
                return false;
            }
            static const bool on = [] {
                const char* value = std::getenv("LV_SETUP_MEMCPY_CODEC");
                return !(value && value[0] == '0');
            }();
            return on;
        }

        u32 setupCodecWorkers(u32 requested)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_PARALLEL_CODEC");
            if (gpu::enabled() && (!value || value[0] != '0'))
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

            explicit BufferWriter(std::size_t size, u32 workers = 1)
                : mBuffer(size), mWorkers(setupCodecWorkers(workers))
            {
                adviseGpuSetupWireBuffer(mBuffer);
            }

            explicit BufferWriter(Buffer&& reserved, u32 workers = 1)
                : mBuffer(std::move(reserved)), mWorkers(setupCodecWorkers(workers))
            {
                adviseGpuSetupWireBuffer(mBuffer);
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
                writeU32(static_cast<u32>(ringBatchCoeffCount(polys)));
                const bool nativeCopy = setupMemcpyCodecEnabled();
                if (nativeCopy && mWorkers > 1 && polys.size() > 1 &&
                    ringBatchCoeffCount(polys) * sizeof(u64) >= (std::size_t(1) << 20))
                {
                    std::vector<std::size_t> offsets(polys.size() + 1, mOffset);
                    for (std::size_t i = 0; i < polys.size(); ++i)
                        offsets[i + 1] = offsets[i] + polys[i].mCoeffs.size() * sizeof(u64);
                    if (!detail::runParallelTasks(polys.size(), mWorkers, [&](std::size_t i) {
                        const auto bytes = offsets[i + 1] - offsets[i];
                        if (bytes) std::memcpy(mBuffer.data() + offsets[i], polys[i].mCoeffs.data(), bytes);
                        return true;
                    })) throw std::runtime_error("parallel offline encoding failed");
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
            u32 workers = 1)
        {
            const auto modulusCount = static_cast<u32>(ring.mCoeffModulusBits.size());
            if (!setupMemcpyCodecEnabled())
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
            if (setupCodecWorkers(workers) > 1 && polyCount > 1 &&
                static_cast<std::size_t>(coeffCount) * sizeof(u64) >= (std::size_t(1) << 20))
            {
                if (!detail::runParallelTasks(polyCount, setupCodecWorkers(workers), [&](std::size_t i) {
                    auto& poly = polys[i];
                    poly.mCoeffs.resize(static_cast<std::size_t>(perPoly));
                    std::memcpy(poly.mCoeffs.data(), payload.data() + offset + i * bytes, bytes);
                    return true;
                })) return false;
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
            u32 workers = 1)
        {
            if (!readU32(payload, offset, tensor.mRows) ||
                !readU32(payload, offset, tensor.mCols) ||
                (tensor.mRows != 0 &&
                 tensor.mCols > std::numeric_limits<u32>::max() / tensor.mRows))
            {
                return false;
            }
            return readOfflineRingBatch(
                payload, offset, ring, tensor.mRows * tensor.mCols, tensor.mPolys, workers);
        }

        void writeRootU64Vector(BufferWriter& writer, const AlignedUnVec<u64>& values)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                if (rootU64MemcpyCodecEnabled())
                {
                    writer.writeNativeLittleEndianU64Vector(values);
                    return;
                }
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
                if (rootU64MemcpyCodecEnabled())
                {
                    return readNativeLittleEndianU64Vector(payload, offset, values);
                }
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
            const Vec& coeffs)
        {
            BufferWriter writer(3u * sizeof(u32) + u64VectorByteSize(coeffs));
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

    Buffer encode(const KeyDeriveRequest& message)
    {
        return encodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    Buffer encode(const KeyDeriveResponse& message)
    {
        return encodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    Buffer encode(const ShrinkExpandOfflineMessage& message)
    {
        return encode(message, 1);
    }

    static Buffer encodeShrinkExpandOfflineTensors(
        const ShrinkExpandParams& params,
        const RingTensor& ct1,
        const ShrinkExpandLacct& lacct,
        u32 workers)
    {
        HostStep phase("setup codec: encode shrink expand");
        BufferWriter writer(
            paramsByteSize(params) +
            2u * sizeof(u32) +
            ringBatchByteSize(ct1.mPolys) +
            4u * sizeof(u32) +
            ringBatchByteSize(lacct.mCt.mPolys), workers);
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

    Buffer encode(const ShrinkExpandOfflineMessage& message, u32 workers)
    {
        return encodeShrinkExpandOfflineTensors(message.mParams,
            message.mLazyCt1 ? message.mLazyCt1->get() : message.mCt1,
            message.mLazyLacct ? message.mLazyLacct->get() : message.mLacct, workers);
    }

    Buffer encodeShrinkExpandOfflineState(const ShrinkExpandSenderState& state, u32 workers)
    {
        if (state.mSharedHostState)
            return encodeShrinkExpandOfflineState(*state.mSharedHostState, workers);
        if ((!state.mLazyCt1 && !state.mLazyLacct) ||
            std::endian::native != std::endian::little)
            return encodeShrinkExpandOfflineTensors(state.mParams, state.hostCt1(), state.hostLacct(), workers);

        HostStep phase("setup codec: encode resident shrink expand");
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
            (static_cast<std::size_t>(ct1Words) + lacctWords) * sizeof(u64), workers);
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
            if (lazy->copyCoefficientsTo(std::span<u8>(writer.mBuffer.data() + writer.mOffset, bytes)))
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

    Buffer encode(const PolyMessage& message)
    {
        BufferWriter writer(2u * sizeof(u32) + u64VectorByteSize(message.mCoeffs));
        writer.writeU32(message.mPolyModulusDegree);
        writer.writeU32(message.mCoeffModulusCount);
        writer.writeU64Vector(message.mCoeffs);
        return writer.finish();
    }

    Buffer encode(const SeedMessage& message)
    {
        BufferWriter writer(message.mSeed.size());
        writer.writeBytes(std::span<const u8>(message.mSeed.data(), message.mSeed.size()));
        return writer.finish();
    }

    Buffer encode(const RootOfflineMessage& message)
    {
        return encode(message, 1);
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

    void noteRootWireCudaExpectedDownloads(u64 senderRunId,
        const RootOfflineMessage& message)
    {
        const auto layout = rootWireLayout(message);
        u64 expectedBytes = 0;
        u64 expectedCalls = 0;
        const auto addTensor = [&](const RingTensor& tensor,
                                   const auto& lazy) {
            if (!lazy) return;
            const u64 bytes = static_cast<u64>(ringTensorSize(tensor)) *
                layout.mWordsPerPoly * sizeof(u64);
            if (!bytes) return;
            if (expectedBytes > std::numeric_limits<u64>::max() - bytes)
                throw std::length_error("LogVole Root lazy wire downloads are too large");
            expectedBytes += bytes;
            ++expectedCalls;
        };
        addTensor(message.mCtR, message.mLazyCtR);
        addTensor(message.mLacctLeft.mCt, message.mLazyLacctLeft);
        addTensor(message.mTopCt, message.mLazyTopCt);
        std::lock_guard lock(rootCudaWireEvidenceMutex);
        if (lastRootCudaWireEvidence.mSenderRunId != senderRunId) return;
        lastRootCudaWireEvidence.mExpectedDirectDownloadBytes = expectedBytes;
        lastRootCudaWireEvidence.mExpectedDirectDownloadCalls = expectedCalls;
    }

    Buffer encode(const RootOfflineMessage& message, u32 workers)
    {
        return encodeRootOfflineIntoBuffer(message,
            Buffer(rootOfflineWireSize(message)), workers);
    }

    Buffer encodeRootOfflineIntoBuffer(const RootOfflineMessage& message,
        Buffer&& reserved, u32 workers)
    {
        HostStep phase("setup codec: encode root");
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
        BufferWriter writer(std::move(reserved), workers);
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
                        std::span<u8>(writer.mBuffer.data() + writer.mOffset, bytes)))
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
                    std::span<u8>(writer.mBuffer.data() + writer.mOffset, bytes)))
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

    Buffer encode(const RootDigestMessage& message)
    {
        BufferWriter writer(u64VectorByteSize(message.mDPrimeCoeffs));
        writeRootU64Vector(writer, message.mDPrimeCoeffs);
        return writer.finish();
    }

    Buffer encode(const RootResponseMessage& message)
    {
        BufferWriter writer(
            sizeof(u32) +
            message.mSeed.size() +
            u64VectorByteSize(message.mSkPrimeCoeffs));
        writer.writeU32(checkedVectorSize(message.mSeed));
        writer.writeBytes(std::span<const u8>(message.mSeed.data(), message.mSeed.size()));
        writeRootU64Vector(writer, message.mSkPrimeCoeffs);
        return writer.finish();
    }

    bool decode(std::span<const u8> payload, KeyDeriveRequest& message)
    {
        return decodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    bool decode(std::span<const u8> payload, KeyDeriveResponse& message)
    {
        return decodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message)
    {
        return decode(payload, message, 1);
    }

    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message, u32 workers)
    {
        HostStep phase("setup codec: decode shrink expand");
        message.mLazyCt1.reset();
        message.mLazyLacct.reset();
        u64 offset = 0;
        if (!readParams(payload, offset, message.mParams) ||
            !readOfflineRingTensor(payload, offset, message.mParams.mRing, message.mCt1, workers) ||
            !readU32(payload, offset, message.mLacct.mWidthPadded) ||
            !readU32(payload, offset, message.mLacct.mLevels) ||
            !readOfflineRingTensor(payload, offset, message.mParams.mRing, message.mLacct.mCt, workers) ||
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
                std::size_t offset, std::size_t bytes, u32 rows, u32 cols, std::size_t words)
                : mPayload(std::move(payload)), mOffset(offset), mBytes(bytes), mPolyWords(words)
            {
                mHost.mRows = rows;
                mHost.mCols = cols;
            }
            std::span<const u8> encodedCoefficients() const override
            {
                return { mPayload->data() + mOffset, mBytes };
            }
            bool copyCoefficientsTo(std::span<u8> destination) const override
            {
                if (destination.size() != mBytes) return false;
                std::memmove(destination.data(), mPayload->data() + mOffset, mBytes);
                return true;
            }
            const RingTensor& get() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep phase("setup codec: deferred tensor materialization");
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
            mutable std::once_flag mOnce;
            mutable RingTensor mHost;
        };
    }

    bool decodeShrinkExpandOfflineForTransport(Buffer&& payload,
        ShrinkExpandOfflineMessage& message, u32 workers)
    {
        bool enabled = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        const char* flag = std::getenv("LV_GPU_SETUP_ENCODED_RECEIVE");
        enabled = gpu::enabled() && (!flag || flag[0] != '0');
#endif
        if (!enabled || std::endian::native != std::endian::little)
            return decode(payload, message, workers);

        HostStep phase("setup codec: retain encoded shrink expand");
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
            ct1.offset, ct1.bytes, next.mCt1.mRows, next.mCt1.mCols, words);
        auto lazyLacct = std::make_shared<EncodedTensorHostState>(std::move(owner),
            lacct.offset, lacct.bytes, next.mLacct.mCt.mRows, next.mLacct.mCt.mCols, words);
        next.mLazyLacct = detail::makeLazyLacctHostState(next.mLacct, std::move(lazyLacct));
        message = std::move(next);
        return true;
    }

    bool decode(std::span<const u8> payload, PolyMessage& message)
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

    bool decode(std::span<const u8> payload, SeedMessage& message)
    {
        if (payload.empty())
        {
            return false;
        }

        assignRange(message.mSeed, payload.begin(), payload.end());
        return true;
    }

    bool decode(std::span<const u8> payload, RootOfflineMessage& message)
    {
        return decode(payload, message, 1);
    }

    bool decode(std::span<const u8> payload, RootOfflineMessage& message, u32 workers)
    {
        HostStep phase("setup codec: decode root");
        u64 offset = 0;
        u32 publicBStarCount = 0;

        if (!readRingParams(payload, offset, message.mRing) ||
            !readU32(payload, offset, message.mTauHi) ||
            !readU32(payload, offset, message.mGadgetLogBase) ||
            !readU32(payload, offset, message.mPlaintextModulusBits) ||
            !readU32(payload, offset, message.mLeftWidth) ||
            !readU32(payload, offset, message.mRandomizerWidth) ||
            !readOfflineRingTensor(payload, offset, message.mRing, message.mCtR, workers) ||
            !readU32(payload, offset, message.mLacctLeft.mWidthPadded) ||
            !readU32(payload, offset, message.mLacctLeft.mLevels) ||
            !readOfflineRingTensor(payload, offset, message.mRing, message.mLacctLeft.mCt, workers) ||
            !readOfflineRingTensor(payload, offset, message.mRing, message.mTopCt, workers) ||
            !readU32(payload, offset, publicBStarCount) ||
            !readOfflineRingBatch(
                payload, offset, message.mRing, publicBStarCount, message.mPublicBStarNtt, workers) ||
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
        RootOfflineMessage& message, u32 workers)
    {
        bool enabled = false;
        bool retainCtR = false;
        bool retainLacct = false;
        bool retainPublicBStar = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        const char* flag = std::getenv("LV_GPU_SETUP_ROOT_ENCODED_RECEIVE");
        enabled = gpu::enabled() && (!flag || flag[0] != '0');
        const char* ctRFlag = std::getenv("LV_GPU_SETUP_ROOT_CTR_ENCODED_RECEIVE");
        retainCtR = !ctRFlag || ctRFlag[0] != '0';
        const char* lacctFlag = std::getenv("LV_GPU_SETUP_ROOT_LACCT_ENCODED_RECEIVE");
        retainLacct = !lacctFlag || lacctFlag[0] != '0';
        const char* publicBStarFlag = std::getenv("LV_GPU_SETUP_ROOT_BSTAR_ENCODED_RECEIVE");
        retainPublicBStar = !publicBStarFlag || publicBStarFlag[0] != '0';
#endif
        if (!enabled || std::endian::native != std::endian::little)
            return decode(payload, message, workers);

        HostStep phase("setup codec: retain encoded root tensors");
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
            !(retainCtR
                ? readOwnedTensor(next.mCtR, ctR)
                : readOfflineRingTensor(payload, offset, next.mRing, next.mCtR, workers)) ||
            !readU32(payload, offset, next.mLacctLeft.mWidthPadded) ||
            !readU32(payload, offset, next.mLacctLeft.mLevels) ||
            !(retainLacct
                ? readOwnedTensor(next.mLacctLeft.mCt, lacct)
                : readOfflineRingTensor(payload, offset, next.mRing, next.mLacctLeft.mCt, workers)) ||
            !readOwnedTensor(next.mTopCt, topCt) ||
            !readU32(payload, offset, publicBStarCount) ||
            !(retainPublicBStar
                ? readOwnedPublicBStar(publicBStarCount, publicBStar)
                : readOfflineRingBatch(payload, offset, next.mRing, publicBStarCount,
                    next.mPublicBStarNtt, workers)) ||
            offset != payload.size())
            return false;

        auto owner = std::make_shared<const Buffer>(std::move(payload));
        const auto words = static_cast<std::size_t>(ringPolyCoeffCount(next.mRing));
        if (retainCtR)
        {
            next.mLazyCtR = std::make_shared<EncodedTensorHostState>(owner,
                ctR.offset, ctR.bytes, next.mCtR.mRows, next.mCtR.mCols, words);
            next.mOwnedCtRWire = next.mLazyCtR;
        }
        if (retainLacct)
        {
            next.mLazyLacctLeft = std::make_shared<EncodedTensorHostState>(owner,
                lacct.offset, lacct.bytes, next.mLacctLeft.mCt.mRows,
                next.mLacctLeft.mCt.mCols, words);
            next.mOwnedLacctLeftWire = next.mLazyLacctLeft;
        }
        next.mLazyTopCt = std::make_shared<EncodedTensorHostState>(owner,
            topCt.offset, topCt.bytes, next.mTopCt.mRows, next.mTopCt.mCols,
            words);
        next.mOwnedTopCtWire = next.mLazyTopCt;
        next.mPublicBStarCount = publicBStarCount;
        if (retainPublicBStar)
        {
            next.mLazyPublicBStar = std::make_shared<EncodedTensorHostState>(
                std::move(owner), publicBStar.offset, publicBStar.bytes,
                publicBStarCount, 1u, words);
            next.mOwnedPublicBStarWire = next.mLazyPublicBStar;
        }
        message = std::move(next);
        return true;
    }

    bool decode(std::span<const u8> payload, RootDigestMessage& message)
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

    bool decode(std::span<const u8> payload, RootResponseMessage& message)
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
