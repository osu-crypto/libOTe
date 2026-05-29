#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "logvole/civole_protocol.hpp"

using namespace logvole;
using namespace logvole::comm;

namespace
{
    constexpr std::uint32_t k_protocol_id = 0xC170u;
    constexpr std::uint16_t k_protocol_version = 1u;
    constexpr std::uint64_t k_offline_session_id = 1u;
    constexpr std::uint64_t k_online_session_id = 2u;
    constexpr std::size_t k_example_w = 16u;
    constexpr civole_sid k_example_sid = 42u;

    struct options
    {
        std::string role;
        std::string host = "127.0.0.1";
        std::uint16_t port = 29090u;
        bool show_help = false;
    };

    void print_usage(const char *argv0)
    {
        std::cerr << "Usage:\n"
                  << "  " << argv0 << " --role receiver [--host 127.0.0.1] [--port 29090]\n"
                  << "  " << argv0 << " --role sender   [--host 127.0.0.1] [--port 29090]\n\n"
                  << "Start the receiver first. The example uses port for offl and port+1 for setx/release.\n";
    }

    bool parse_uint16(const std::string &text, std::uint16_t &out)
    {
        try
        {
            std::size_t consumed = 0u;
            const unsigned long value = std::stoul(text, &consumed, 10);
            if (consumed != text.size() || value > std::numeric_limits<std::uint16_t>::max())
            {
                return false;
            }
            out = static_cast<std::uint16_t>(value);
            return true;
        }
        catch (const std::exception &)
        {
            return false;
        }
    }

    bool parse_args(int argc, char **argv, options &out)
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h")
            {
                out.show_help = true;
                return true;
            }

            auto require_value = [&](std::string &value) -> bool {
                if (i + 1 >= argc)
                {
                    return false;
                }
                value = argv[++i];
                return true;
            };

            if (arg == "--role")
            {
                if (!require_value(out.role))
                {
                    return false;
                }
            }
            else if (arg.rfind("--role=", 0) == 0)
            {
                out.role = arg.substr(7);
            }
            else if (arg == "--host")
            {
                if (!require_value(out.host))
                {
                    return false;
                }
            }
            else if (arg.rfind("--host=", 0) == 0)
            {
                out.host = arg.substr(7);
            }
            else if (arg == "--port")
            {
                std::string port_text;
                if (!require_value(port_text) || !parse_uint16(port_text, out.port))
                {
                    return false;
                }
            }
            else if (arg.rfind("--port=", 0) == 0)
            {
                if (!parse_uint16(arg.substr(7), out.port))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return (out.role == "sender" || out.role == "receiver") && out.port < std::numeric_limits<std::uint16_t>::max();
    }

    protocol_result<any_channel> make_tcp_role_channel(
        role_t role, bool server, const std::string &host, std::uint16_t port, std::uint64_t session_id)
    {
        channel_config config{};
        config.kind = transport_kind::tcp;
        config.role = role;
        config.protocol_id = k_protocol_id;
        config.version = k_protocol_version;
        config.session_id = session_id;
        config.recv_timeout = std::chrono::milliseconds(600000);
        config.max_frame_size = 256u * 1024u * 1024u;
        config.tcp.host = host;
        config.tcp.port = port;
        config.tcp.server = server;
        return make_channel(config);
    }

    std::vector<std::uint64_t> make_example_x(std::size_t w, std::uint64_t modulus)
    {
        std::vector<std::uint64_t> x(w);
        for (std::size_t i = 0; i < x.size(); ++i)
        {
            x[i] = static_cast<std::uint64_t>((3u * i + 5u) % modulus);
        }
        return x;
    }

    int print_error(const std::string &label, const std::string &message)
    {
        std::cerr << label << " failed: " << message << "\n";
        return 1;
    }

    int run_receiver(const options &opts)
    {
        auto params_result = make_default_civole_params(1u);
        if (!params_result)
        {
            return print_error("make_default_civole_params", params_result.message());
        }
        civole_params params = std::move(params_result.value());

        auto modulus_result = resolve_civole_modulus(params);
        if (!modulus_result)
        {
            return print_error("resolve_civole_modulus", modulus_result.message());
        }
        const std::uint64_t p = modulus_result.value();
        const std::uint16_t online_port = static_cast<std::uint16_t>(opts.port + 1u);

        logvole_seal_backend backend{};

        std::cout << "receiver: listening for offl on " << opts.host << ":" << opts.port << std::endl;
        auto offl_channel = make_tcp_role_channel(role_t::receiver, true, opts.host, opts.port, k_offline_session_id);
        if (!offl_channel)
        {
            return print_error("receiver offl channel", offl_channel.message());
        }

        civole_receiver_offl_input offl_input{};
        offl_input.params = params;
        auto offl = run_civole_receiver_offl(std::move(offl_channel.value()), offl_input, backend);
        if (!offl)
        {
            return print_error("receiver offl", offl.message());
        }

        std::vector<std::uint64_t> x = make_example_x(k_example_w, p);
        std::cout << "receiver: offl complete; listening for setx_int on " << opts.host << ":" << online_port
                  << std::endl;
        auto online_channel =
            make_tcp_role_channel(role_t::receiver, true, opts.host, online_port, k_online_session_id);
        if (!online_channel)
        {
            return print_error("receiver online channel", online_channel.message());
        }

        auto setx = run_civole_receiver_setx_int(
            std::move(online_channel.value()), offl.value().state, k_example_sid, x, backend);
        if (!setx)
        {
            return print_error("receiver setx_int", setx.message());
        }

        std::cout << "receiver: setx_int produced " << setx.value().macs.size() << " macs modulo "
                  << setx.value().modulus << "." << std::endl;
        return 0;
    }

    int run_sender(const options &opts)
    {
        auto params_result = make_default_civole_params(1u);
        if (!params_result)
        {
            return print_error("make_default_civole_params", params_result.message());
        }
        civole_params params = std::move(params_result.value());

        auto modulus_result = resolve_civole_modulus(params);
        if (!modulus_result)
        {
            return print_error("resolve_civole_modulus", modulus_result.message());
        }
        const std::uint64_t p = modulus_result.value();
        const std::uint64_t delta = 7u % p;
        const std::uint16_t online_port = static_cast<std::uint16_t>(opts.port + 1u);

        logvole_seal_backend backend{};

        std::cout << "sender: connecting for offl to " << opts.host << ":" << opts.port << std::endl;
        auto offl_channel = make_tcp_role_channel(role_t::sender, false, opts.host, opts.port, k_offline_session_id);
        if (!offl_channel)
        {
            return print_error("sender offl channel", offl_channel.message());
        }

        civole_sender_offl_input offl_input{};
        offl_input.params = params;
        offl_input.delta = delta;
        offl_input.w = k_example_w;
        auto offl = run_civole_sender_offl(std::move(offl_channel.value()), offl_input, backend);
        if (!offl)
        {
            return print_error("sender offl", offl.message());
        }

        auto releasek = run_civole_sender_releasek_int(offl.value().state, k_example_sid, backend);
        if (!releasek)
        {
            return print_error("sender releasek_int", releasek.message());
        }

        std::cout << "sender: releasek_int produced " << releasek.value().keys.size()
                  << " keys; connecting for release_int to " << opts.host << ":" << online_port << std::endl;
        auto online_channel = make_tcp_role_channel(role_t::sender, false, opts.host, online_port, k_online_session_id);
        if (!online_channel)
        {
            return print_error("sender online channel", online_channel.message());
        }

        auto release = run_civole_sender_release_int(
            std::move(online_channel.value()), offl.value().state, k_example_sid, backend);
        if (!release)
        {
            return print_error("sender release_int", release.message());
        }

        std::cout << "sender: release_int complete for " << k_example_w << " Zp values modulo " << p << "."
                  << std::endl;
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    options opts{};
    if (!parse_args(argc, argv, opts))
    {
        print_usage(argv[0]);
        return 1;
    }
    if (opts.show_help)
    {
        print_usage(argv[0]);
        return 0;
    }

    if (opts.role == "receiver")
    {
        return run_receiver(opts);
    }
    return run_sender(opts);
}
