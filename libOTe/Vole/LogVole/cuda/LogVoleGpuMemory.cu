#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"

#include <cuda_runtime.h>
#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        unsigned memoryBucket(std::size_t bytes)
        {
            unsigned bucket = 12;
            while (bucket < 63 && (std::size_t{1} << bucket) < bytes) ++bucket;
            return bucket;
        }

        struct StreamUse
        {
            void* mStream = nullptr;
            std::weak_ptr<void> mLease;
            bool mTracked = false;

            bool live() const { return !mTracked || !mLease.expired(); }
        };

        StreamUse streamUse(void* stream, const std::shared_ptr<void>& lease)
        {
            return {stream, lease, static_cast<bool>(lease)};
        }
    }

    struct DeviceMemoryPool::Impl
    {
        struct Dependency
        {
            StreamUse mUse;
            cudaEvent_t mEvent = nullptr;
        };
        struct Cached
        {
            void* mPointer = nullptr;
            std::vector<Dependency> mDependencies;
        };
        struct Allocation
        {
            unsigned mBucket = 0;
            std::vector<StreamUse> mUses;
            bool mUntracked = false;
        };

        mutable std::mutex mMutex;
        std::array<std::vector<Cached>, 64> mFree;
        std::unordered_map<void*, Allocation> mActive;
        std::vector<cudaEvent_t> mEvents;
        std::vector<Cached> mQuarantined;
        cudaMemPool_t mPool = nullptr;
        bool mPoolAttempted = false;
        MemoryPoolStats mStats;

        cudaEvent_t event()
        {
            if (!mEvents.empty())
            {
                auto result = mEvents.back();
                mEvents.pop_back();
                return result;
            }
            cudaEvent_t result = nullptr;
            if (cudaEventCreateWithFlags(&result, cudaEventDisableTiming) != cudaSuccess)
                return nullptr;
            return result;
        }

        void use(Allocation& allocation, const StreamUse& use)
        {
            for (auto& prior : allocation.mUses)
                if (prior.mStream == use.mStream)
                {
                    if (!prior.live()) prior = use;
                    return;
                }
            allocation.mUses.push_back(use);
        }

        ~Impl()
        {
            // All allocation owners retain this pool. Cached dependencies may
            // still belong to a different execution's consumer stream.
            for (auto& [pointer, allocation] : mActive)
            {
                if (allocation.mUntracked) (void)cudaDeviceSynchronize();
                for (const auto& use : allocation.mUses)
                {
                    auto lease = use.mLease.lock();
                    if (use.mTracked && !lease) continue;
                    (void)cudaStreamSynchronize(static_cast<cudaStream_t>(use.mStream));
                }
                (void)cudaFree(pointer);
            }
            for (auto& bucket : mFree)
                for (auto& block : bucket)
                {
                    for (auto& dependency : block.mDependencies)
                    {
                        if (dependency.mEvent)
                        {
                            (void)cudaEventSynchronize(dependency.mEvent);
                            (void)cudaEventDestroy(dependency.mEvent);
                        }
                    }
                    (void)cudaFree(block.mPointer);
                }
            for (auto event : mEvents) (void)cudaEventDestroy(event);
            for (auto& block : mQuarantined)
            {
                (void)cudaDeviceSynchronize();
                for (const auto& dependency : block.mDependencies)
                    if (dependency.mEvent) (void)cudaEventDestroy(dependency.mEvent);
                (void)cudaFree(block.mPointer);
            }
            if (mPool) (void)cudaMemPoolDestroy(mPool);
        }
    };

    DeviceMemoryPool::DeviceMemoryPool() : mImpl(std::make_unique<Impl>()) {}
    DeviceMemoryPool::~DeviceMemoryPool() = default;

    void* DeviceMemoryPool::allocate(std::size_t bytes, void* rawStream, const std::shared_ptr<void>& streamLease)
    {
        if (!bytes || bytes > (std::size_t{1} << 62)) return nullptr;
        auto& state = *mImpl;
        std::lock_guard<std::mutex> lock(state.mMutex);
        auto use = streamUse(rawStream, streamLease);
        auto lease = use.mLease.lock();
        if (use.mTracked && !lease) use = {};
        const auto stream = static_cast<cudaStream_t>(use.mStream);
        const auto bucket = memoryBucket(bytes);
        auto& available = state.mFree[bucket];
        void* pointer = nullptr;
        if (!available.empty())
        {
            auto selected = available.end() - 1;
            for (auto it = available.begin(); it != available.end(); ++it)
                if (it->mDependencies.size() == 1 &&
                    it->mDependencies[0].mUse.mStream == use.mStream)
                {
                    selected = it;
                    break;
                }
            auto block = std::move(*selected);
            available.erase(selected);
            bool ready = true;
            for (auto& dependency : block.mDependencies)
            {
                auto priorLease = dependency.mUse.mLease.lock();
                if (dependency.mEvent &&
                    !(dependency.mUse.mStream == use.mStream && dependency.mUse.mTracked && use.mTracked) &&
                    (!dependency.mUse.mTracked || priorLease))
                    ready = cudaStreamWaitEvent(stream, dependency.mEvent, 0) == cudaSuccess && ready;
            }
            if (!ready)
            {
                // A failed dependency cannot make its allocation reusable.
                if (cudaDeviceSynchronize() != cudaSuccess)
                {
                    state.mQuarantined.push_back(std::move(block));
                    return nullptr;
                }
            }
            for (auto& dependency : block.mDependencies)
                if (dependency.mEvent) state.mEvents.push_back(dependency.mEvent);
            pointer = block.mPointer;
            ++state.mStats.mCacheHits;
        }
        else
        {
            if (!state.mPoolAttempted)
            {
                state.mPoolAttempted = true;
                int device = 0;
                cudaMemPoolProps properties{};
                properties.allocType = cudaMemAllocationTypePinned;
                properties.location.type = cudaMemLocationTypeDevice;
                if (cudaGetDevice(&device) == cudaSuccess)
                {
                    properties.location.id = device;
                    if (cudaMemPoolCreate(&state.mPool, &properties) == cudaSuccess)
                    {
                        std::uint64_t threshold = std::numeric_limits<std::uint64_t>::max();
                        (void)cudaMemPoolSetAttribute(state.mPool, cudaMemPoolAttrReleaseThreshold, &threshold);
                    }
                    else (void)cudaGetLastError();
                }
            }
            const auto capacity = std::size_t{1} << bucket;
            auto error = state.mPool
                ? cudaMallocFromPoolAsync(&pointer, capacity, state.mPool, stream)
                : cudaMalloc(&pointer, capacity);
            if (error != cudaSuccess) return nullptr;
            ++state.mStats.mAllocations;
        }
        state.mActive.emplace(pointer, Impl::Allocation{bucket, {use}});
        return pointer;
    }

    void DeviceMemoryPool::use(void* pointer)
    {
        if (!pointer) return;
        std::lock_guard<std::mutex> lock(mImpl->mMutex);
        auto found = mImpl->mActive.find(pointer);
        if (found != mImpl->mActive.end() && !found->second.mUntracked)
        {
            found->second.mUntracked = true;
            ++mImpl->mStats.mUntrackedUses;
        }
    }

    void DeviceMemoryPool::use(void* pointer, void* stream, const std::shared_ptr<void>& lease)
    {
        if (!pointer) return;
        std::lock_guard<std::mutex> lock(mImpl->mMutex);
        auto found = mImpl->mActive.find(pointer);
        if (found != mImpl->mActive.end()) mImpl->use(found->second, streamUse(stream, lease));
    }

    void DeviceMemoryPool::release(void* pointer) noexcept
    {
        if (!pointer) return;
        try
        {
            auto& state = *mImpl;
            std::lock_guard<std::mutex> lock(state.mMutex);
            auto found = state.mActive.find(pointer);
            if (found == state.mActive.end()) return;
            if (found->second.mUntracked && cudaDeviceSynchronize() != cudaSuccess) return;
            Impl::Cached block{pointer, {}};
            block.mDependencies.reserve(found->second.mUses.size());
            auto& free = state.mFree[found->second.mBucket];
            free.reserve(free.size() + 1);
            if (!found->second.mUntracked)
            {
                for (const auto& use : found->second.mUses)
                {
                    auto lease = use.mLease.lock();
                    if (use.mTracked && !lease) continue; // Stream destruction drains its work.
                    auto event = state.event();
                    if (!event || cudaEventRecord(event, static_cast<cudaStream_t>(use.mStream)) != cudaSuccess)
                    {
                        if (event) state.mEvents.push_back(event);
                        if (cudaStreamSynchronize(static_cast<cudaStream_t>(use.mStream)) != cudaSuccess)
                            return; // Keep the active allocation quarantined until teardown.
                    }
                    else block.mDependencies.push_back({use, event});
                }
            }
            free.push_back(std::move(block));
            state.mActive.erase(found);
            ++state.mStats.mReleases;
        }
        catch (...) { /* Retain allocations on bookkeeping failure. */ }
    }

    MemoryPoolStats DeviceMemoryPool::stats() const
    {
        std::lock_guard<std::mutex> lock(mImpl->mMutex);
        return mImpl->mStats;
    }

    struct PinnedMemoryPool::Impl
    {
        mutable std::mutex mMutex;
        std::array<std::vector<void*>, 64> mFree;
        std::unordered_map<void*, unsigned> mActive;
        MemoryPoolStats mStats;
        ~Impl()
        {
            for (auto& bucket : mFree) for (auto pointer : bucket) (void)cudaFreeHost(pointer);
            for (auto& entry : mActive) (void)cudaFreeHost(entry.first);
        }
    };

    PinnedMemoryPool::PinnedMemoryPool() : mImpl(std::make_unique<Impl>()) {}
    PinnedMemoryPool::~PinnedMemoryPool() = default;

    void* PinnedMemoryPool::allocate(std::size_t bytes)
    {
        if (!bytes || bytes > (std::size_t{1} << 62)) return nullptr;
        std::lock_guard<std::mutex> lock(mImpl->mMutex);
        const auto bucket = memoryBucket(bytes);
        auto& available = mImpl->mFree[bucket];
        void* pointer = nullptr;
        if (!available.empty())
        {
            pointer = available.back();
            available.pop_back();
            ++mImpl->mStats.mCacheHits;
        }
        else
        {
            if (cudaHostAlloc(&pointer, std::size_t{1} << bucket, cudaHostAllocPortable) != cudaSuccess)
                return nullptr;
            ++mImpl->mStats.mAllocations;
        }
        mImpl->mActive.emplace(pointer, bucket);
        return pointer;
    }

    void PinnedMemoryPool::release(void* pointer) noexcept
    {
        if (!pointer) return;
        try
        {
            std::lock_guard<std::mutex> lock(mImpl->mMutex);
            auto found = mImpl->mActive.find(pointer);
            if (found == mImpl->mActive.end()) return;
            mImpl->mFree[found->second].push_back(pointer);
            mImpl->mActive.erase(found);
            ++mImpl->mStats.mReleases;
        }
        catch (...) {}
    }

    MemoryPoolStats PinnedMemoryPool::stats() const
    {
        std::lock_guard<std::mutex> lock(mImpl->mMutex);
        return mImpl->mStats;
    }
}
