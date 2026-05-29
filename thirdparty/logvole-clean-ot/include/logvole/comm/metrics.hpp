#pragma once

#include <cstdint>

namespace logvole::comm
{
    struct comm_counters
    {
        std::uint64_t frames_s2r_sent = 0;
        std::uint64_t frames_s2r_recv = 0;
        std::uint64_t frames_r2s_sent = 0;
        std::uint64_t frames_r2s_recv = 0;

        std::uint64_t wire_bytes_s2r_sent = 0;
        std::uint64_t wire_bytes_s2r_recv = 0;
        std::uint64_t wire_bytes_r2s_sent = 0;
        std::uint64_t wire_bytes_r2s_recv = 0;

        std::uint64_t payload_bytes_s2r_sent = 0;
        std::uint64_t payload_bytes_s2r_recv = 0;
        std::uint64_t payload_bytes_r2s_sent = 0;
        std::uint64_t payload_bytes_r2s_recv = 0;

        std::uint64_t rounds_completed = 0;

        std::uint64_t bits_s2r_sent() const
        {
            return wire_bytes_s2r_sent * 8;
        }

        std::uint64_t bits_r2s_sent() const
        {
            return wire_bytes_r2s_sent * 8;
        }
    };

} // namespace logvole::comm
