#pragma once

#include <atomic>
#include <cstdint>

namespace logvole
{
    enum class protocol_cache_role : std::uint8_t
    {
        unspecified = 0u,
        sender = 1u,
        receiver = 2u
    };

    struct protocol_cache_scope
    {
        std::uint64_t run_id = 0u;
        protocol_cache_role role = protocol_cache_role::unspecified;
    };

    inline std::atomic<std::uint64_t> g_protocol_cache_run_counter{ 1u };
    inline thread_local protocol_cache_scope g_protocol_cache_scope{};

    inline std::uint64_t allocate_protocol_cache_run_id()
    {
        return g_protocol_cache_run_counter.fetch_add(1u, std::memory_order_relaxed);
    }

    inline protocol_cache_scope current_protocol_cache_scope()
    {
        return g_protocol_cache_scope;
    }

    inline void set_protocol_cache_scope(protocol_cache_role role, std::uint64_t run_id)
    {
        g_protocol_cache_scope.role = role;
        g_protocol_cache_scope.run_id = run_id;
    }

    inline void clear_protocol_cache_scope()
    {
        g_protocol_cache_scope = protocol_cache_scope{};
    }

    class scoped_protocol_cache_scope
    {
    public:
        scoped_protocol_cache_scope(protocol_cache_role role, std::uint64_t run_id) : previous_(g_protocol_cache_scope)
        {
            set_protocol_cache_scope(role, run_id);
        }

        ~scoped_protocol_cache_scope()
        {
            g_protocol_cache_scope = previous_;
        }

        scoped_protocol_cache_scope(const scoped_protocol_cache_scope &) = delete;
        scoped_protocol_cache_scope &operator=(const scoped_protocol_cache_scope &) = delete;
        scoped_protocol_cache_scope(scoped_protocol_cache_scope &&) = delete;
        scoped_protocol_cache_scope &operator=(scoped_protocol_cache_scope &&) = delete;

    private:
        protocol_cache_scope previous_{};
    };

} // namespace logvole
