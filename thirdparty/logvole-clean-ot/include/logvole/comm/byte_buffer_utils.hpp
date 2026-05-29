#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>
#include "logvole/comm/codec.hpp"

namespace logvole::comm::detail
{
    inline void append_u8(byte_buffer &buffer, std::uint8_t value)
    {
        buffer.push_back(value);
    }

    inline void append_u16(byte_buffer &buffer, std::uint16_t value)
    {
        buffer.push_back(static_cast<std::uint8_t>(value & 0xFFu));
        buffer.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
    }

    inline void append_u32(byte_buffer &buffer, std::uint32_t value)
    {
        for (int i = 0; i < 4; ++i)
        {
            buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
        }
    }

    inline void append_u64(byte_buffer &buffer, std::uint64_t value)
    {
        for (int i = 0; i < 8; ++i)
        {
            buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
        }
    }

    inline protocol_result<std::uint8_t> read_u8(const byte_buffer &buffer, std::size_t &offset)
    {
        if (offset + 1u > buffer.size())
        {
            return protocol_result<std::uint8_t>::failure(
                protocol_errc::decode_validation_failure, "payload underflow while reading uint8");
        }
        return protocol_result<std::uint8_t>::success(buffer[offset++]);
    }

    inline protocol_result<std::uint16_t> read_u16(const byte_buffer &buffer, std::size_t &offset)
    {
        if (offset + 2u > buffer.size())
        {
            return protocol_result<std::uint16_t>::failure(
                protocol_errc::decode_validation_failure, "payload underflow while reading uint16");
        }

        const std::uint16_t value =
            static_cast<std::uint16_t>(buffer[offset]) | (static_cast<std::uint16_t>(buffer[offset + 1u]) << 8u);
        offset += 2u;
        return protocol_result<std::uint16_t>::success(value);
    }

    inline protocol_result<std::uint32_t> read_u32(const byte_buffer &buffer, std::size_t &offset)
    {
        if (offset + 4u > buffer.size())
        {
            return protocol_result<std::uint32_t>::failure(
                protocol_errc::decode_validation_failure, "payload underflow while reading uint32");
        }

        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i)
        {
            value |= static_cast<std::uint32_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
        }
        offset += 4u;
        return protocol_result<std::uint32_t>::success(value);
    }

    inline protocol_result<std::uint64_t> read_u64(const byte_buffer &buffer, std::size_t &offset)
    {
        if (offset + 8u > buffer.size())
        {
            return protocol_result<std::uint64_t>::failure(
                protocol_errc::decode_validation_failure, "payload underflow while reading uint64");
        }

        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
        {
            value |= static_cast<std::uint64_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
        }
        offset += 8u;
        return protocol_result<std::uint64_t>::success(value);
    }

    inline protocol_result<void> append_u16_vector(byte_buffer &buffer, const std::vector<std::uint16_t> &values)
    {
        if (values.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return protocol_result<void>::failure(protocol_errc::config_error, "uint16 vector too large");
        }

        append_u32(buffer, static_cast<std::uint32_t>(values.size()));
        for (std::uint16_t value : values)
        {
            append_u16(buffer, value);
        }
        return protocol_result<void>::success();
    }

    inline protocol_result<void> append_u64_vector(byte_buffer &buffer, const std::vector<std::uint64_t> &values)
    {
        if (values.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return protocol_result<void>::failure(protocol_errc::config_error, "uint64 vector too large");
        }

        append_u32(buffer, static_cast<std::uint32_t>(values.size()));

        if (!values.empty())
        {
            const std::size_t byte_size = values.size() * sizeof(std::uint64_t);
            const std::size_t old_size = buffer.size();
            buffer.resize(old_size + byte_size);
            std::memcpy(buffer.data() + old_size, values.data(), byte_size);
        }
        return protocol_result<void>::success();
    }

    inline protocol_result<std::vector<std::uint16_t>> read_u16_vector(const byte_buffer &buffer, std::size_t &offset)
    {
        auto size_result = read_u32(buffer, offset);
        if (!size_result)
        {
            return protocol_result<std::vector<std::uint16_t>>::failure(size_result.error(), size_result.message());
        }

        std::vector<std::uint16_t> out;
        out.reserve(size_result.value());
        for (std::size_t i = 0; i < size_result.value(); ++i)
        {
            auto value = read_u16(buffer, offset);
            if (!value)
            {
                return protocol_result<std::vector<std::uint16_t>>::failure(value.error(), value.message());
            }
            out.push_back(value.value());
        }

        return protocol_result<std::vector<std::uint16_t>>::success(std::move(out));
    }

    inline protocol_result<std::vector<std::uint64_t>> read_u64_vector(const byte_buffer &buffer, std::size_t &offset)
    {
        auto size_result = read_u32(buffer, offset);
        if (!size_result)
        {
            return protocol_result<std::vector<std::uint64_t>>::failure(size_result.error(), size_result.message());
        }

        const std::size_t count = size_result.value();
        std::vector<std::uint64_t> out;

        if (count > 0)
        {
            const std::size_t byte_size = count * sizeof(std::uint64_t);
            if (offset + byte_size > buffer.size())
            {
                return protocol_result<std::vector<std::uint64_t>>::failure(
                    protocol_errc::decode_validation_failure, "payload underflow while reading uint64 array");
            }
            out.resize(count);
            std::memcpy(out.data(), buffer.data() + offset, byte_size);
            offset += byte_size;
        }

        return protocol_result<std::vector<std::uint64_t>>::success(std::move(out));
    }

} // namespace logvole::comm::detail
