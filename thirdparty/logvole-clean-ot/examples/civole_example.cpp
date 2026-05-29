#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>
#include "logvole/civole_protocol.hpp"

using namespace logvole;
using namespace logvole::comm;

int main()
{
    auto params_result = make_default_civole_params(1u);
    if (!params_result)
    {
        std::cerr << params_result.message() << "\n";
        return 1;
    }
    civole_params params = std::move(params_result.value());

    auto modulus_result = resolve_civole_modulus(params);
    if (!modulus_result)
    {
        std::cerr << modulus_result.message() << "\n";
        return 1;
    }
    const std::uint64_t p = modulus_result.value();

    constexpr std::size_t w = 16u;
    constexpr civole_sid sid = 42u;
    const std::uint64_t delta = 7u % p;
    std::vector<std::uint64_t> x(w);
    for (std::size_t i = 0; i < x.size(); ++i)
    {
        x[i] = static_cast<std::uint64_t>((3u * i + 5u) % p);
    }

    auto offl_channels = make_in_memory_channel_pair(0xC170u, 1u, 1u, std::chrono::milliseconds(600000));
    if (!offl_channels)
    {
        std::cerr << offl_channels.message() << "\n";
        return 1;
    }

    logvole_seal_backend sender_backend{};
    logvole_seal_backend receiver_backend{};
    auto channels = std::move(offl_channels.value());

    auto sender_offl = protocol_result<civole_sender_offl_output>::failure(protocol_errc::io_error, "not run");
    auto receiver_offl = protocol_result<civole_receiver_offl_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_offl_thread([&]() mutable {
        civole_receiver_offl_input input{};
        input.params = params;
        receiver_offl = run_civole_receiver_offl(std::move(channels.second), input, receiver_backend);
    });
    std::thread sender_offl_thread([&]() mutable {
        civole_sender_offl_input input{};
        input.params = params;
        input.delta = delta;
        input.w = w;
        sender_offl = run_civole_sender_offl(std::move(channels.first), input, sender_backend);
    });
    sender_offl_thread.join();
    receiver_offl_thread.join();

    if (!sender_offl || !receiver_offl)
    {
        std::cerr << "offl failed: " << sender_offl.message() << " / " << receiver_offl.message() << "\n";
        return 1;
    }

    auto releasek = run_civole_sender_releasek_int(sender_offl.value().state, sid, sender_backend);
    if (!releasek)
    {
        std::cerr << releasek.message() << "\n";
        return 1;
    }

    auto online_channels = make_in_memory_channel_pair(0xC170u, 1u, 2u, std::chrono::milliseconds(600000));
    if (!online_channels)
    {
        std::cerr << online_channels.message() << "\n";
        return 1;
    }
    auto online_pair = std::move(online_channels.value());

    auto sender_release =
        protocol_result<civole_sender_release_output>::failure(protocol_errc::io_error, "not run");
    auto receiver_setx = protocol_result<civole_receiver_setx_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_online_thread([&]() mutable {
        receiver_setx = run_civole_receiver_setx_int(
            std::move(online_pair.second), receiver_offl.value().state, sid, x, receiver_backend);
    });
    std::thread sender_online_thread([&]() mutable {
        sender_release = run_civole_sender_release_int(
            std::move(online_pair.first), sender_offl.value().state, sid, sender_backend);
    });
    sender_online_thread.join();
    receiver_online_thread.join();

    if (!sender_release || !receiver_setx)
    {
        std::cerr << "online failed: " << sender_release.message() << " / " << receiver_setx.message() << "\n";
        return 1;
    }

    for (std::size_t i = 0; i < w; ++i)
    {
        const std::uint64_t expected =
            (releasek.value().keys[i] + static_cast<unsigned __int128>(x[i]) * delta) % p;
        if (receiver_setx.value().macs[i] != expected)
        {
            std::cerr << "VOLE invariant failed at " << i << "\n";
            return 1;
        }
    }

    std::cout << "CI-VOLE relation holds for " << w << " Zp values modulo " << p << ".\n";
    return 0;
}
