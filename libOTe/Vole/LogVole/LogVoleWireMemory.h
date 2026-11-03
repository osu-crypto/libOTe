#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>

namespace osuCrypto::LogVole
{
    // An explicitly owned allocation/registration domain for protocol wire
    // buffers. A Buffer retains its pool; callers may share a pool across
    // buffers to reuse pages and their CUDA registration. No global registry.
    // Every transfer must finish before releasing its active allocation.
    class WireMemoryPool
    {
    public:
        WireMemoryPool();
        ~WireMemoryPool();
        WireMemoryPool(const WireMemoryPool&) = delete;
        WireMemoryPool& operator=(const WireMemoryPool&) = delete;
        void* allocate(std::size_t bytes, std::size_t alignment,
            bool cudaOwned = false, std::uint64_t runId = 0) noexcept;
        bool release(void* pointer) noexcept;
        bool contains(const void* pointer, std::size_t bytes) const noexcept;
        bool isPinned(const void* pointer, std::size_t bytes) const noexcept;
        bool isCudaOwned(const void* pointer, std::size_t bytes) const noexcept;
        std::uint64_t ownerRunId(const void* pointer, std::size_t bytes) const noexcept;
        // An unknown range or a benign registration decline succeeds with
        // pinned=false, so the caller can use bounded transfer staging.
        bool pin(const void* pointer, std::size_t bytes, bool& pinned) noexcept;
        bool contract(void* pointer, std::size_t oldBytes, std::size_t bytes) noexcept;
        void trim();
    private:
        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    // Borrowed bytes and their allocation provenance. This does not extend the
    // Buffer's lifetime: the Buffer must stay alive and unchanged through the
    // synchronous transfer, or until an explicitly joined registration worker
    // finishes. Subviews preserve provenance without a lookup or allocation.
    template<typename T> struct BasicWireView : std::span<T>
    {
        using Base = std::span<T>;
        WireMemoryPool* mMemory = nullptr;
        BasicWireView() = default;
        BasicWireView(Base bytes, WireMemoryPool* memory = nullptr)
            : Base(bytes), mMemory(memory) {}
        BasicWireView(T* data, std::size_t size, WireMemoryPool* memory = nullptr)
            : Base(data, size), mMemory(memory) {}
        template<typename U> requires(std::is_convertible_v<U(*)[], T(*)[]>)
        BasicWireView(const BasicWireView<U>& other)
            : Base(other.data(), other.size()), mMemory(other.mMemory) {}
        BasicWireView subspan(std::size_t offset, std::size_t size = std::dynamic_extent) const
        { return {Base::subspan(offset, size), mMemory}; }
    };
    using WireView = BasicWireView<std::uint8_t>;
    using ConstWireView = BasicWireView<const std::uint8_t>;
}
