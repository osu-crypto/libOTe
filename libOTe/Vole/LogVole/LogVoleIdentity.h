#pragma once
#include "cryptoTools/Common/Defines.h"
#include <atomic>
#include <memory>
#include <functional>
#include <ostream>

namespace osuCrypto::LogVole
{
    class ProtocolCacheService;
    // Host-only allocator-qualified ID. Copies are two words, with no refcount
    // traffic in polynomial/cache lookups. The containing operation or retained
    // record must keep serviceOwner() alive for the whole use of this view.
    struct ProtocolCacheRunId
    {
        const ProtocolCacheService* mService = nullptr;
        u64 mValue = 0;
        ProtocolCacheRunId() = default;
        ProtocolCacheRunId(std::nullptr_t) {}
        explicit operator bool() const noexcept { return mValue != 0; }
        bool operator==(const ProtocolCacheRunId&) const = default;
        bool operator==(std::nullptr_t) const noexcept { return mValue == 0; }
        std::shared_ptr<const ProtocolCacheService> serviceOwner() const;
        std::size_t hash() const noexcept
        {
            return std::hash<const void*>{}(mService) ^ (std::hash<u64>{}(mValue) + 0x9e3779b9u);
        }
    private:
        friend class ProtocolCacheService;
        ProtocolCacheRunId(const ProtocolCacheService* service, u64 value)
            : mService(service), mValue(value) {}
    };

    inline std::ostream& operator<<(std::ostream& out, ProtocolCacheRunId id)
    { return out << id.mService << ':' << id.mValue; }

    // One explicit allocation domain per shared cache/resource owner. It never
    // stores a current session; independent services may both allocate value 1.
    class ProtocolCacheService : public std::enable_shared_from_this<ProtocolCacheService>
    {
        mutable std::atomic<u64> mNextId{1};
        ProtocolCacheService() = default;
    public:
        static std::shared_ptr<ProtocolCacheService> create()
        { return std::shared_ptr<ProtocolCacheService>(new ProtocolCacheService); }
        ProtocolCacheService(const ProtocolCacheService&) = delete;
        ProtocolCacheService& operator=(const ProtocolCacheService&) = delete;
        ProtocolCacheRunId allocate() const { return qualify(mNextId.fetch_add(1, std::memory_order_relaxed)); }
        // Existing online query SID bindings use this explicit numeric mapping.
        // This does not allocate a session and preserves the old numeric value.
        ProtocolCacheRunId qualify(u64 value) const { return value ? ProtocolCacheRunId(this, value) : ProtocolCacheRunId{}; }
    };
    inline std::shared_ptr<const ProtocolCacheService> ProtocolCacheRunId::serviceOwner() const
    { return mService ? mService->shared_from_this() : nullptr; }
}
