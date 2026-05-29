#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace logvole::comm
{
    enum class role_t
    {
        sender,
        receiver
    };

    constexpr role_t opposite_role(role_t role)
    {
        return role == role_t::sender ? role_t::receiver : role_t::sender;
    }

    enum class transport_kind
    {
        in_memory,
        uds,
        tcp
    };

    enum class protocol_errc
    {
        ok = 0,
        invalid_state_transition,
        flow_violation,
        decode_validation_failure,
        unsupported_protocol_version,
        timeout,
        io_error,
        unsupported_transport,
        config_error,
        handler_error
    };

    inline const char *to_string(protocol_errc err)
    {
        switch (err)
        {
        case protocol_errc::ok:
            return "ok";
        case protocol_errc::invalid_state_transition:
            return "invalid_state_transition";
        case protocol_errc::flow_violation:
            return "flow_violation";
        case protocol_errc::decode_validation_failure:
            return "decode_validation_failure";
        case protocol_errc::unsupported_protocol_version:
            return "unsupported_protocol_version";
        case protocol_errc::timeout:
            return "timeout";
        case protocol_errc::io_error:
            return "io_error";
        case protocol_errc::unsupported_transport:
            return "unsupported_transport";
        case protocol_errc::config_error:
            return "config_error";
        case protocol_errc::handler_error:
            return "handler_error";
        default:
            return "unknown";
        }
    }

    template <typename T>
    class protocol_result
    {
    public:
        static protocol_result success(T value)
        {
            protocol_result result;
            result.ok_ = true;
            result.value_.emplace(std::move(value));
            return result;
        }

        static protocol_result failure(protocol_errc error, std::string message = {})
        {
            protocol_result result;
            result.ok_ = false;
            result.error_ = error;
            result.message_ = std::move(message);
            return result;
        }

        explicit operator bool() const
        {
            return ok_;
        }

        bool ok() const
        {
            return ok_;
        }

        T &value()
        {
            return *value_;
        }

        const T &value() const
        {
            return *value_;
        }

        protocol_errc error() const
        {
            return error_;
        }

        const std::string &message() const
        {
            return message_;
        }

    private:
        protocol_result() = default;

        bool ok_ = false;
        protocol_errc error_ = protocol_errc::ok;
        std::optional<T> value_;
        std::string message_;
    };

    template <>
    class protocol_result<void>
    {
    public:
        static protocol_result success()
        {
            protocol_result result;
            result.ok_ = true;
            return result;
        }

        static protocol_result failure(protocol_errc error, std::string message = {})
        {
            protocol_result result;
            result.ok_ = false;
            result.error_ = error;
            result.message_ = std::move(message);
            return result;
        }

        explicit operator bool() const
        {
            return ok_;
        }

        bool ok() const
        {
            return ok_;
        }

        protocol_errc error() const
        {
            return error_;
        }

        const std::string &message() const
        {
            return message_;
        }

    private:
        protocol_result() = default;

        bool ok_ = false;
        protocol_errc error_ = protocol_errc::ok;
        std::string message_;
    };

    template <typename T>
    struct is_protocol_result : std::false_type
    {};

    template <typename T>
    struct is_protocol_result<protocol_result<T>> : std::true_type
    {};

    template <typename T>
    inline constexpr bool is_protocol_result_v = is_protocol_result<T>::value;

} // namespace logvole::comm
