#pragma once

#include <cstddef>
#include <cstdint>

namespace logvole::comm
{
    struct message_envelope
    {
        std::uint32_t protocol_id = 0;
        std::uint16_t version = 0;
        std::uint64_t session_id = 0;
        std::uint32_t round_index = 0;
        std::uint64_t sequence_number = 0;
        std::uint32_t payload_type = 0;
        std::uint32_t payload_size = 0;
        std::uint32_t payload_crc = 0;
    };

    constexpr std::size_t envelope_wire_size = sizeof(std::uint32_t) + sizeof(std::uint16_t) + sizeof(std::uint64_t) +
                                               sizeof(std::uint32_t) + sizeof(std::uint64_t) + sizeof(std::uint32_t) +
                                               sizeof(std::uint32_t) + sizeof(std::uint32_t);

} // namespace logvole::comm
