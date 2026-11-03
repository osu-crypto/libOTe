#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

namespace osuCrypto::LogVole::gpu
{
    class OwnedGpuStream;
    class OwnedGpuBuffer;

    // Pinned host storage with no global pool or registry. The enclosing stream
    // owner must finish DMA before replacement/destruction. Exported host views
    // may retain this object after their completed download.
    class PinnedHostBuffer
    {
    public:
        PinnedHostBuffer() = default;
        explicit PinnedHostBuffer(std::size_t bytes);
        ~PinnedHostBuffer();
        PinnedHostBuffer(PinnedHostBuffer&& other) noexcept;
        PinnedHostBuffer& operator=(PinnedHostBuffer&& other) noexcept;
        PinnedHostBuffer(const PinnedHostBuffer&) = delete;
        PinnedHostBuffer& operator=(const PinnedHostBuffer&) = delete;
        void* data() const noexcept { return mData; }
        std::size_t size() const noexcept { return mBytes; }
        void reset() noexcept;
    private:
        void* mData = nullptr;
        std::size_t mBytes = 0;
    };

    // Explicit allocation domain. It owns a private CUDA pool and its host
    // free lists; no process-wide allocator or current-stream state is used.
    // Streams retain this owner; buffers retain both their allocation stream
    // and their last-use stream, including handoffs to another private pool.
    // Construct and destroy all owners within the application's CUDA lifetime,
    // before main returns. This includes any exported buffers.
    class GpuMemoryPool
    {
    public:
        explicit GpuMemoryPool(int device);
        ~GpuMemoryPool();
        GpuMemoryPool(const GpuMemoryPool&) = delete;
        GpuMemoryPool& operator=(const GpuMemoryPool&) = delete;

        int device() const noexcept;
        // Releases only cached allocations, ordered after their last use.
        // Active buffers and streams remain valid. Reports CUDA failures.
        void trim();

    private:
        friend class OwnedGpuStream;
        friend class OwnedGpuBuffer;
        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    // A session owns its reusable streams explicitly. An exported buffer can
    // extend a stream's lifetime without retaining the session or its caches.
    class OwnedGpuStream
    {
    public:
        explicit OwnedGpuStream(std::shared_ptr<GpuMemoryPool> memory);
        // Transfers an exclusively owned stream on successful construction.
        // Used while migrating existing stream owners to the explicit domain.
        OwnedGpuStream(std::shared_ptr<GpuMemoryPool> memory, void* adoptedStream);
        ~OwnedGpuStream();
        OwnedGpuStream(const OwnedGpuStream&) = delete;
        OwnedGpuStream& operator=(const OwnedGpuStream&) = delete;

        void* raw() const noexcept { return mStream; }
        const std::shared_ptr<GpuMemoryPool>& memory() const noexcept { return mMemory; }
        void synchronize() const;

    private:
        friend class OwnedGpuBuffer;
        std::shared_ptr<GpuMemoryPool> mMemory;
        void* mStream = nullptr;
        std::uint64_t mId = 0;
    };

    class OwnedGpuBuffer
    {
    public:
        OwnedGpuBuffer() = default;
        // The owning device must be current when allocating, handing off or
        // releasing buffers, just as it must be for submitting their kernels.
        // A session establishes that device at each host execution boundary.
        OwnedGpuBuffer(std::shared_ptr<OwnedGpuStream> stream, std::size_t bytes);
        ~OwnedGpuBuffer();
        OwnedGpuBuffer(OwnedGpuBuffer&& other) noexcept;
        OwnedGpuBuffer& operator=(OwnedGpuBuffer&& other) noexcept;
        OwnedGpuBuffer(const OwnedGpuBuffer&) = delete;
        OwnedGpuBuffer& operator=(const OwnedGpuBuffer&) = delete;

        void* data() const noexcept { return mData; }
        std::size_t size() const noexcept { return mBytes; }
        const std::shared_ptr<OwnedGpuStream>& stream() const noexcept { return mStream; }
        explicit operator bool() const noexcept { return mData != nullptr; }
        void reset() noexcept;

        // Exclusive stream handoff: orders subsequent use on next after all
        // preceding use on the current stream. Callers must not enqueue further
        // use on the old stream. Raw pointers do not transfer this ownership.
        // Streams may belong to different pools on the same device. Storage
        // always returns to its original pool, ordered after the final use.
        void handoff(const std::shared_ptr<OwnedGpuStream>& next);

    private:
        std::shared_ptr<OwnedGpuStream> mAllocationStream;
        std::shared_ptr<OwnedGpuStream> mStream;
        void* mData = nullptr;
        std::size_t mBytes = 0;
    };
}
