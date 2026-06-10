#pragma once

#include <cryptoTools/Common/Defines.h>

#include <atomic>

namespace osuCrypto::LogVole
{
    enum class ProtocolCacheRole : u8
    {
        Unspecified = 0,
        Sender = 1,
        Receiver = 2
    };

    struct ProtocolCacheScope
    {
        u64 mRunId = 0;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
    };

    inline std::atomic<u64> gProtocolCacheRunCounter{ 1 };
    inline thread_local ProtocolCacheScope tProtocolCacheScope{};

    inline u64 allocateProtocolCacheRunId()
    {
        return gProtocolCacheRunCounter.fetch_add(1, std::memory_order_relaxed);
    }

    inline ProtocolCacheScope currentProtocolCacheScope()
    {
        return tProtocolCacheScope;
    }

    inline void setProtocolCacheScope(ProtocolCacheRole role, u64 runId)
    {
        tProtocolCacheScope.mRole = role;
        tProtocolCacheScope.mRunId = runId;
    }

    class ScopedProtocolCacheScope
    {
    public:
        ScopedProtocolCacheScope(ProtocolCacheRole role, u64 runId)
            : mPrevious(tProtocolCacheScope)
        {
            setProtocolCacheScope(role, runId);
        }

        ScopedProtocolCacheScope(ProtocolCacheScope scope)
            : mPrevious(tProtocolCacheScope)
        {
            tProtocolCacheScope = scope;
        }

        ScopedProtocolCacheScope(const ScopedProtocolCacheScope&) = delete;
        ScopedProtocolCacheScope& operator=(const ScopedProtocolCacheScope&) = delete;

        ~ScopedProtocolCacheScope()
        {
            tProtocolCacheScope = mPrevious;
        }

    private:
        ProtocolCacheScope mPrevious{};
    };
}
