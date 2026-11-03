#include "libOTe/Vole/LogVole/cuda/LogVoleGpuMemory.h"
#include <cuda_runtime_api.h>
#include <array>
#include <bit>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        void requireCuda(cudaError_t error, const char* operation)
        {
            if (error != cudaSuccess)
                throw std::runtime_error(std::string(operation) + ": " + cudaGetErrorString(error));
        }

        // Destruction cannot report an exception. Do not silently continue after
        // failing to establish the completion needed to release device storage.
        void cleanupCuda(cudaError_t error) noexcept
        {
            if (error != cudaSuccess) std::terminate();
        }

        class DeviceScope
        {
            int mPrevious;
            bool mChanged;
        public:
            explicit DeviceScope(int device)
            {
                requireCuda(cudaGetDevice(&mPrevious), "cudaGetDevice");
                mChanged = device != mPrevious;
                if (mChanged) requireCuda(cudaSetDevice(device), "cudaSetDevice");
            }
            ~DeviceScope() { if (mChanged) cleanupCuda(cudaSetDevice(mPrevious)); }
        };

        cudaStream_t native(void* stream) noexcept { return static_cast<cudaStream_t>(stream); }
    }

    struct GpuMemoryPool::Impl
    {
        static constexpr unsigned kBuckets = std::numeric_limits<std::size_t>::digits;
        struct Block
        {
            void* pointer;
            std::uint64_t streamId;
            cudaEvent_t ready;
        };
        int device;
        cudaMemPool_t pool = nullptr;
        cudaStream_t cleanupStream = nullptr;
        std::mutex mutex;
        std::array<std::vector<Block>, kBuckets> free;
        std::vector<cudaEvent_t> events;
        std::uint64_t nextStreamId = 1;

        explicit Impl(int device_) : device(device_)
        {
            DeviceScope scope(device);
            cudaMemPoolProps props{};
            props.allocType = cudaMemAllocationTypePinned;
            props.location.type = cudaMemLocationTypeDevice;
            props.location.id = device;
            requireCuda(cudaMemPoolCreate(&pool, &props), "cudaMemPoolCreate");
            try
            {
                std::uint64_t threshold = std::numeric_limits<std::uint64_t>::max();
                requireCuda(cudaMemPoolSetAttribute(pool, cudaMemPoolAttrReleaseThreshold,
                    &threshold), "cudaMemPoolSetAttribute");
                requireCuda(cudaStreamCreateWithFlags(&cleanupStream, cudaStreamNonBlocking),
                    "cudaStreamCreateWithFlags");
            }
            catch (...)
            {
                cleanupCuda(cudaMemPoolDestroy(pool));
                throw;
            }
        }

        // mutex is held by the caller. An event is reused only after its
        // previous record has been captured by every required stream wait.
        cudaEvent_t takeEvent()
        {
            if (!events.empty())
            {
                auto event = events.back();
                events.pop_back();
                return event;
            }
            cudaEvent_t event = nullptr;
            requireCuda(cudaEventCreateWithFlags(&event, cudaEventDisableTiming), "cudaEventCreate");
            return event;
        }

        void returnEvent(cudaEvent_t event) noexcept
        {
            if (!event) return;
            try { events.push_back(event); }
            catch (...) { cleanupCuda(cudaEventDestroy(event)); }
        }

        static unsigned bucket(std::size_t bytes)
        {
            const auto result = static_cast<unsigned>(std::bit_width(bytes - 1));
            if (result >= kBuckets) throw std::length_error("CUDA allocation size overflow");
            return result < 12 ? 12 : result;
        }

        void* allocate(std::size_t bytes, cudaStream_t stream, std::uint64_t id)
        {
            if (!bytes) return nullptr;
            const auto b = bucket(bytes);
            std::lock_guard lock(mutex);
            auto& list = free[b];
            for (std::size_t i = list.size(); i-- > 0;)
            {
                if (list[i].streamId == id)
                {
                    auto block = list[i];
                    list[i] = list.back();
                    list.pop_back();
                    returnEvent(block.ready);
                    return block.pointer;
                }
            }
            if (!list.empty())
            {
                // Leave the block owned by the list if the dependency fails.
                auto block = list.back();
                requireCuda(cudaStreamWaitEvent(stream, block.ready, 0), "cudaStreamWaitEvent");
                list.pop_back();
                returnEvent(block.ready);
                return block.pointer;
            }
            void* pointer = nullptr;
            requireCuda(cudaMallocFromPoolAsync(&pointer, std::size_t(1) << b, pool, stream),
                "cudaMallocFromPoolAsync");
            return pointer;
        }

        void release(void* pointer, std::size_t bytes, cudaStream_t stream, std::uint64_t id) noexcept
        {
            if (!pointer) return;
            std::lock_guard lock(mutex);
            cudaEvent_t event = nullptr;
            try
            {
                event = takeEvent();
                requireCuda(cudaEventRecord(event, stream), "cudaEventRecord");
                free[bucket(bytes)].push_back({pointer, id, event});
            }
            catch (...)
            {
                // Allocation bookkeeping can fail independently of CUDA. Queue
                // the actual release behind the last use instead of leaking.
                cleanupCuda(cudaFreeAsync(pointer, stream));
                if (event) cleanupCuda(cudaEventDestroy(event));
            }
        }

        void trim()
        {
            DeviceScope scope(device);
            std::lock_guard lock(mutex);
            for (auto& list : free)
            {
                while (!list.empty())
                {
                    auto block = list.back();
                    requireCuda(cudaStreamWaitEvent(cleanupStream, block.ready, 0), "trim wait");
                    requireCuda(cudaFreeAsync(block.pointer, cleanupStream), "trim free");
                    list.pop_back();
                    returnEvent(block.ready);
                }
            }
            requireCuda(cudaStreamSynchronize(cleanupStream), "trim synchronize");
            requireCuda(cudaMemPoolTrimTo(pool, 0), "cudaMemPoolTrimTo");
        }

        ~Impl()
        {
            // Every stream retains this pool, so all producer streams have
            // drained before the last pool owner can reach this destructor.
            try { trim(); }
            catch (...) { std::terminate(); }
            DeviceScope scope(device);
            for (auto event : events) cleanupCuda(cudaEventDestroy(event));
            cleanupCuda(cudaStreamDestroy(cleanupStream));
            cleanupCuda(cudaMemPoolDestroy(pool));
        }
    };

    GpuMemoryPool::GpuMemoryPool(int device) : mImpl(std::make_unique<Impl>(device)) {}
    GpuMemoryPool::~GpuMemoryPool() = default;
    int GpuMemoryPool::device() const noexcept { return mImpl->device; }
    void GpuMemoryPool::trim() { mImpl->trim(); }

    OwnedGpuStream::OwnedGpuStream(std::shared_ptr<GpuMemoryPool> memory)
        : OwnedGpuStream(std::move(memory), nullptr) {}

    OwnedGpuStream::OwnedGpuStream(std::shared_ptr<GpuMemoryPool> memory, void* adoptedStream)
        : mMemory(std::move(memory))
    {
        if (!mMemory) throw std::invalid_argument("CUDA stream requires a memory owner");
        DeviceScope scope(mMemory->device());
        auto& pool = *mMemory->mImpl;
        std::lock_guard lock(pool.mutex);
        if (!pool.nextStreamId) throw std::overflow_error("CUDA stream identity exhausted");
        mId = pool.nextStreamId++;
        cudaStream_t stream = native(adoptedStream);
        if (!stream)
            requireCuda(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreate");
        mStream = stream;
    }

    OwnedGpuStream::~OwnedGpuStream()
    {
        if (!mStream) return;
        DeviceScope scope(mMemory->device());
        cleanupCuda(cudaStreamSynchronize(native(mStream)));
        cleanupCuda(cudaStreamDestroy(native(mStream)));
    }

    void OwnedGpuStream::synchronize() const
    {
        requireCuda(cudaStreamSynchronize(native(mStream)), "cudaStreamSynchronize");
    }

    OwnedGpuBuffer::OwnedGpuBuffer(std::shared_ptr<OwnedGpuStream> stream, std::size_t bytes)
        : mAllocationStream(stream), mStream(std::move(stream)), mBytes(bytes)
    {
        if (!mStream) throw std::invalid_argument("CUDA buffer requires a stream owner");
        mData = mStream->mMemory->mImpl->allocate(bytes, native(mStream->raw()), mStream->mId);
    }

    OwnedGpuBuffer::~OwnedGpuBuffer() { reset(); }
    OwnedGpuBuffer::OwnedGpuBuffer(OwnedGpuBuffer&& other) noexcept
        : mAllocationStream(std::move(other.mAllocationStream)),
          mStream(std::move(other.mStream)), mData(std::exchange(other.mData, nullptr)),
          mBytes(std::exchange(other.mBytes, 0)) {}

    OwnedGpuBuffer& OwnedGpuBuffer::operator=(OwnedGpuBuffer&& other) noexcept
    {
        if (this == &other) return *this;
        reset();
        mAllocationStream = std::move(other.mAllocationStream);
        mStream = std::move(other.mStream);
        mData = std::exchange(other.mData, nullptr);
        mBytes = std::exchange(other.mBytes, 0);
        return *this;
    }

    void OwnedGpuBuffer::reset() noexcept
    {
        if (mData)
        {
            // Return storage to its allocation domain only after the final
            // consumer. This queues a dependency, not a host/device-wide wait.
            try { handoff(mAllocationStream); }
            catch (...) { std::terminate(); }
            mAllocationStream->mMemory->mImpl->release(mData, mBytes,
                native(mAllocationStream->raw()), mAllocationStream->mId);
        }
        mData = nullptr;
        mBytes = 0;
        mStream.reset();
        mAllocationStream.reset();
    }

    void OwnedGpuBuffer::handoff(const std::shared_ptr<OwnedGpuStream>& next)
    {
        if (!next || !mStream || next->mMemory->device() != mAllocationStream->mMemory->device())
            throw std::invalid_argument("CUDA handoff requires streams on the same device");
        if (next == mStream) return;
        auto& pool = *mAllocationStream->mMemory->mImpl;
        {
            std::lock_guard lock(pool.mutex);
            auto event = pool.takeEvent();
            try
            {
                requireCuda(cudaEventRecord(event, native(mStream->raw())), "handoff record");
                requireCuda(cudaStreamWaitEvent(native(next->raw()), event, 0), "handoff wait");
            }
            catch (...)
            {
                pool.returnEvent(event);
                throw;
            }
            pool.returnEvent(event);
        }
        // Drop the old owner outside the allocator lock: it may drain/destroy
        // that stream. Never synchronize the device as a whole.
        mStream = next;
    }
}
