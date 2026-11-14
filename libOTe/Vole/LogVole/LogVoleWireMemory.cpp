#include "libOTe/Vole/LogVole/LogVoleWireMemory.h"
#include "libOTe/config.h"
#include <cstdlib>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <unordered_map>
#include <vector>
#if defined(_MSC_VER)
#include <malloc.h>
#endif
#if defined(ENABLE_LOGVOLE_CUDA)
#include <cuda_runtime_api.h>
#endif

namespace osuCrypto::LogVole
{
    struct WireMemoryPool::Impl
    {
        static constexpr std::size_t pageAlignment = 4096;
        enum class PinState { Unregistered, Registered, Declined };
        struct Block
        {
            void* pointer = nullptr;
            std::size_t capacity = 0, activeBytes = 0;
            PinState pinState = PinState::Unregistered;
            ~Block()
            {
                if (!pointer) return;
#if defined(ENABLE_LOGVOLE_CUDA)
                if (pinState == PinState::Registered &&
                    cudaHostUnregister(pointer) != cudaSuccess) std::terminate();
#endif
#if defined(_MSC_VER)
                _aligned_free(pointer);
#else
                std::free(pointer);
#endif
            }
        };
        mutable std::mutex mutex;
        std::map<std::size_t, std::vector<Block*>> free;
        std::unordered_map<void*, std::unique_ptr<Block>> blocks;
        std::map<std::uintptr_t, Block*> active;

        Block* find(const void* pointer, std::size_t bytes) const noexcept
        {
            if (!pointer || !bytes) return nullptr;
            const auto address = reinterpret_cast<std::uintptr_t>(pointer);
            auto it = active.upper_bound(address);
            if (it == active.begin()) return nullptr;
            --it;
            const auto offset = address - it->first;
            return offset < it->second->activeBytes && bytes <= it->second->activeBytes - offset
                ? it->second : nullptr;
        }
    };

    WireMemoryPool::WireMemoryPool() : mImpl(std::make_unique<Impl>()) {}
    WireMemoryPool::~WireMemoryPool() = default;

    void* WireMemoryPool::allocate(std::size_t bytes, std::size_t alignment) noexcept
    {
        constexpr auto page = Impl::pageAlignment;
        if (!bytes || !alignment || (alignment & (alignment - 1)) || alignment > page ||
            bytes > std::numeric_limits<std::size_t>::max() - (page - 1)) return nullptr;
        const auto capacity = (bytes + page - 1) & ~(page - 1);
        try
        {
            std::lock_guard lock(mImpl->mutex);
            auto it = mImpl->free.lower_bound(capacity);
            while (it != mImpl->free.end() && it->second.empty()) ++it;
            const auto limit = capacity <= std::numeric_limits<std::size_t>::max() / 2
                ? 2 * capacity : std::numeric_limits<std::size_t>::max();
            if (it != mImpl->free.end() && it->first <= limit)
            {
                auto* block = it->second.back();
                if (!mImpl->active.emplace(reinterpret_cast<std::uintptr_t>(block->pointer), block).second)
                    return nullptr;
                block->activeBytes = bytes;

                it->second.pop_back();
                return block->pointer;
            }
            auto block = std::make_unique<Impl::Block>();
            block->capacity = capacity;
            block->activeBytes = bytes;

#if defined(_MSC_VER)
            block->pointer = _aligned_malloc(capacity, page);
#else
            block->pointer = std::aligned_alloc(page, capacity);
#endif
            if (!block->pointer || reinterpret_cast<std::uintptr_t>(block->pointer) % alignment)
                return nullptr;
            void* pointer = block->pointer;
            auto [owned, inserted] = mImpl->blocks.emplace(pointer, std::move(block));
            if (!inserted) return nullptr;
            try
            {
                if (mImpl->active.emplace(reinterpret_cast<std::uintptr_t>(pointer), owned->second.get()).second)
                    return pointer;
            }
            catch (...) { mImpl->blocks.erase(owned); throw; }
            mImpl->blocks.erase(owned);
        }
        catch (...) {}
        return nullptr;
    }

    bool WireMemoryPool::release(void* pointer) noexcept
    {
        if (!pointer) return false;
        std::lock_guard lock(mImpl->mutex);
        auto it = mImpl->blocks.find(pointer);
        if (it == mImpl->blocks.end()) return false;
        auto& block = *it->second;
        if (mImpl->active.erase(reinterpret_cast<std::uintptr_t>(pointer)))
        {
            block.activeBytes = 0;

            try { mImpl->free[block.capacity].push_back(&block); }
            catch (...) { /* Still owned; trim/destruction will release it. */ }
        }
        return true;
    }

    bool WireMemoryPool::contains(const void* pointer, std::size_t bytes) const noexcept
    {
        std::lock_guard lock(mImpl->mutex);
        return mImpl->find(pointer, bytes) != nullptr;
    }
    bool WireMemoryPool::isPinned(const void* pointer, std::size_t bytes) const noexcept
    {
        std::lock_guard lock(mImpl->mutex);
        const auto* block = mImpl->find(pointer, bytes);
        return block && block->pinState == Impl::PinState::Registered;
    }
    bool WireMemoryPool::pin(const void* pointer, std::size_t bytes, bool& pinned) noexcept
    {
        pinned = false;
        std::lock_guard lock(mImpl->mutex);
        auto* block = mImpl->find(pointer, bytes);
        if (!block) return true;
        if (block->pinState == Impl::PinState::Registered)
        { pinned = true; return true; }
        if (block->pinState == Impl::PinState::Declined) return true;
#if defined(ENABLE_LOGVOLE_CUDA)
        const auto error = cudaHostRegister(block->pointer, block->capacity, cudaHostRegisterPortable);
        if (error == cudaSuccess)
        { block->pinState = Impl::PinState::Registered; pinned = true; return true; }
        if (error != cudaErrorInvalidValue && error != cudaErrorMemoryAllocation &&
            error != cudaErrorHostMemoryAlreadyRegistered && error != cudaErrorNotSupported &&
            error != cudaErrorInsufficientDriver && error != cudaErrorNoDevice && error != cudaErrorOperatingSystem)
            return false;
        const auto pending = cudaPeekAtLastError();
        if (pending == error) (void)cudaGetLastError();
        else if (pending != cudaSuccess) return false;
#endif
        block->pinState = Impl::PinState::Declined;
        return true;
    }
    void WireMemoryPool::trim()
    {
        std::lock_guard lock(mImpl->mutex);
        mImpl->free.clear();
        for (auto it = mImpl->blocks.begin(); it != mImpl->blocks.end();)
            if (!it->second->activeBytes) it = mImpl->blocks.erase(it);
            else ++it;
    }
}
