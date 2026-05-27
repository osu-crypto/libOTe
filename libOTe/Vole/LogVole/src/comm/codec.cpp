#include "loglabel/comm/codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace loglabel::comm
{
    namespace
    {
        void append_u16(byte_buffer &buffer, std::uint16_t value)
        {
            buffer.push_back(static_cast<std::uint8_t>(value & 0xFFu));
            buffer.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
        }

        void append_u32(byte_buffer &buffer, std::uint32_t value)
        {
            for (int i = 0; i < 4; ++i)
            {
                buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
            }
        }

        void append_u64(byte_buffer &buffer, std::uint64_t value)
        {
            for (int i = 0; i < 8; ++i)
            {
                buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
            }
        }

        protocol_result<std::uint16_t> read_u16(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 2 > buffer.size())
            {
                return protocol_result<std::uint16_t>::failure(
                    protocol_errc::decode_validation_failure, "frame underflow reading uint16");
            }

            std::uint16_t value = static_cast<std::uint16_t>(buffer[offset]) |
                                  (static_cast<std::uint16_t>(buffer[offset + 1]) << 8u);
            offset += 2;
            return protocol_result<std::uint16_t>::success(value);
        }

        protocol_result<std::uint32_t> read_u32(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 4 > buffer.size())
            {
                return protocol_result<std::uint32_t>::failure(
                    protocol_errc::decode_validation_failure, "frame underflow reading uint32");
            }

            std::uint32_t value = 0;
            for (int i = 0; i < 4; ++i)
            {
                value |= static_cast<std::uint32_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
            }
            offset += 4;
            return protocol_result<std::uint32_t>::success(value);
        }

        protocol_result<std::uint64_t> read_u64(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 8 > buffer.size())
            {
                return protocol_result<std::uint64_t>::failure(
                    protocol_errc::decode_validation_failure, "frame underflow reading uint64");
            }

            std::uint64_t value = 0;
            for (int i = 0; i < 8; ++i)
            {
                value |= static_cast<std::uint64_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
            }
            offset += 8;
            return protocol_result<std::uint64_t>::success(value);
        }

        const std::array<std::uint32_t, 256> &crc_table()
        {
            static const std::array<std::uint32_t, 256> table = [] {
                std::array<std::uint32_t, 256> t{};
                for (std::uint32_t i = 0; i < 256; ++i)
                {
                    std::uint32_t c = i;
                    for (int j = 0; j < 8; ++j)
                    {
                        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1u)) : (c >> 1u);
                    }
                    t[i] = c;
                }
                return t;
            }();
            return table;
        }
    } // namespace

    std::uint32_t crc32(const std::uint8_t *data, std::size_t length)
    {
        if (length == 0 || data == nullptr)
        {
            return 0;
        }

        std::uint32_t crc = 0xFFFFFFFFu;
        const auto &table = crc_table();
        for (std::size_t i = 0; i < length; ++i)
        {
            const auto idx = static_cast<std::uint8_t>((crc ^ data[i]) & 0xFFu);
            crc = table[idx] ^ (crc >> 8u);
        }
        return crc ^ 0xFFFFFFFFu;
    }

    protocol_result<byte_buffer> serialize_frame(const message_envelope &envelope, const byte_buffer &payload)
    {
        if (payload.size() > std::numeric_limits<std::uint32_t>::max())
        {
            return protocol_result<byte_buffer>::failure(
                protocol_errc::config_error, "payload too large for 32-bit payload size");
        }

        if (envelope.payload_size != payload.size())
        {
            return protocol_result<byte_buffer>::failure(
                protocol_errc::config_error, "envelope payload_size does not match payload bytes");
        }

        byte_buffer frame;
        frame.reserve(envelope_wire_size + payload.size());

        append_u32(frame, envelope.protocol_id);
        append_u16(frame, envelope.version);
        append_u64(frame, envelope.session_id);
        append_u32(frame, envelope.round_index);
        append_u64(frame, envelope.sequence_number);
        append_u32(frame, envelope.payload_type);
        append_u32(frame, envelope.payload_size);
        append_u32(frame, envelope.payload_crc);

        frame.insert(frame.end(), payload.begin(), payload.end());
        return protocol_result<byte_buffer>::success(std::move(frame));
    }

    protocol_result<std::pair<message_envelope, byte_buffer>> deserialize_frame(const byte_buffer &frame)
    {
        if (frame.size() < envelope_wire_size)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                protocol_errc::decode_validation_failure, "frame too short for envelope");
        }

        std::size_t offset = 0;
        message_envelope envelope{};

        auto protocol_id = read_u32(frame, offset);
        if (!protocol_id)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(protocol_id.error(), protocol_id.message());
        }
        envelope.protocol_id = protocol_id.value();

        auto version = read_u16(frame, offset);
        if (!version)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(version.error(), version.message());
        }
        envelope.version = version.value();

        auto session_id = read_u64(frame, offset);
        if (!session_id)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                session_id.error(), session_id.message());
        }
        envelope.session_id = session_id.value();

        auto round_index = read_u32(frame, offset);
        if (!round_index)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                round_index.error(), round_index.message());
        }
        envelope.round_index = round_index.value();

        auto sequence_number = read_u64(frame, offset);
        if (!sequence_number)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                sequence_number.error(), sequence_number.message());
        }
        envelope.sequence_number = sequence_number.value();

        auto payload_type = read_u32(frame, offset);
        if (!payload_type)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                payload_type.error(), payload_type.message());
        }
        envelope.payload_type = payload_type.value();

        auto payload_size = read_u32(frame, offset);
        if (!payload_size)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                payload_size.error(), payload_size.message());
        }
        envelope.payload_size = payload_size.value();

        auto payload_crc = read_u32(frame, offset);
        if (!payload_crc)
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                payload_crc.error(), payload_crc.message());
        }
        envelope.payload_crc = payload_crc.value();

        if (offset + envelope.payload_size != frame.size())
        {
            return protocol_result<std::pair<message_envelope, byte_buffer>>::failure(
                protocol_errc::decode_validation_failure, "frame payload size mismatch");
        }

        byte_buffer payload;
        payload.insert(payload.end(), frame.begin() + static_cast<std::ptrdiff_t>(offset), frame.end());

        return protocol_result<std::pair<message_envelope, byte_buffer>>::success(
            std::make_pair(envelope, std::move(payload)));
    }

} // namespace loglabel::comm
